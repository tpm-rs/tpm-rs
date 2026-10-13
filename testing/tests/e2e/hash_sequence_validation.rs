//! Hash sequence validation: handles, hierarchies, hash algorithms, authorization, trailing bytes
//! and slot limits.

use crate::_common::{
    RespHeader, base_attrs, create_primary_with_auth_in, event_sequence_complete,
    execute_tpm_command_auto_pw_unwrap, execute_tpm_command_via_run, execute_tpm_command_via_send,
    execute_tpm_command_with_corrupted_bytes_via_send, execute_tpm_command_with_extra_bytes,
    execute_tpm_command_with_trailing, execute_with_password_sessions, hmac_template, leak_bytes,
    pw, rc_at, sequence_complete, sequence_update, start_hash_sequence, start_sequence,
    start_sequence_alg,
};
use tpm2::commands::{
    EventSequenceComplete, HMACStart, Hash, HashSequenceStart, SequenceComplete, SequenceUpdate,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bMaxBuffer, Tpm2bNonce, TpmaSession, TpmiAlgHash, TpmsAuthCommand,
    Unmarshal, *,
};
use tpm2_simulator::create_simulator;

/// TPM2_SequenceComplete with an invalid hierarchy fails with exactly TPM_RC_VALUE on the hierarchy parameter
#[test]
fn complete_invalid_hierarchy_response_code() {
    let mut sim = create_simulator!();

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_handles = execute_tpm_command_via_run(&mut sim, &start_cmd, &[]).unwrap();

    let complete_cmd = SequenceComplete {
        sequence_handle: start_handles.sequence_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle(0x80000000), // invalid hierarchy handle
    };

    let res = execute_tpm_command_via_run(&mut sim, &complete_cmd, &[pw()]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(2)).get())
    );
}

/// TPM2_SequenceComplete with hierarchy 0x00000000 fails
#[test]
fn complete_rejects_invalid_hierarchy() {
    let mut sim = create_simulator!();

    // 1. Start sequence
    let handle = start_sequence_alg(&mut sim, TpmiAlgHash::Sha256);

    // 2. Complete sequence with invalid hierarchy (e.g. 0x00000000 is not a valid hierarchy)
    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&[]).unwrap(),
        hierarchy: Handle(0x00000000),
    };
    let res = execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd);
    assert!(res.is_err());
}

/// TPM2_SequenceComplete with trailing bytes fails with TPM_RC_SIZE
#[test]
fn complete_rejects_trailing_bytes() {
    let mut sim = create_simulator!();

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_handles = execute_tpm_command_via_run(&mut sim, &start_cmd, &[]).unwrap();

    let complete_cmd = SequenceComplete {
        sequence_handle: start_handles.sequence_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };

    let res = execute_tpm_command_with_extra_bytes(&mut sim, &complete_cmd, &[pw()]);
    assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
}

/// SequenceUpdate/Complete with invalid sequence handles or an invalid hierarchy fail with the right codes.
#[test]
fn invalid_sequence_and_hierarchy_handles() {
    let mut sim = create_simulator!();

    // Start a valid sequence to have a reference handle
    let seq_handle = start_sequence(&mut sim, Some(TpmiAlgHash::Sha256));

    // 1. SequenceUpdate with invalid sequence handle
    let invalid_handle = Handle(seq_handle.0 + 1);
    let update_cmd = SequenceUpdate {
        sequence_handle: invalid_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };
    let update_res = execute_tpm_command_via_send(&mut sim, &update_cmd, &[]);
    assert_eq!(update_res.unwrap_err(), TpmRc::REFERENCE_H0.get());

    // 2. SequenceComplete with invalid sequence handle
    let complete_cmd = SequenceComplete {
        sequence_handle: invalid_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_res = execute_tpm_command_via_send(&mut sim, &complete_cmd, &[]);
    assert_eq!(complete_res.unwrap_err(), TpmRc::REFERENCE_H0.get());

    // 3. SequenceComplete with invalid hierarchy (hierarchy is the second parameter)
    let complete_cmd_invalid_hier = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle(0), // Invalid hierarchy
    };
    let complete_res2 = execute_tpm_command_via_send(&mut sim, &complete_cmd_invalid_hier, &[pw()]);
    assert_eq!(
        complete_res2.unwrap_err(),
        TpmRc::VALUE.with(Position::parameter(2)).get()
    );

    // 4. Complete sequence successfully
    let complete_cmd_valid = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_res_ok = execute_tpm_command_via_send(&mut sim, &complete_cmd_valid, &[pw()]);
    assert!(complete_res_ok.is_ok());

    // 5. SequenceUpdate reuse
    let update_cmd_valid = SequenceUpdate {
        sequence_handle: seq_handle,
        ..update_cmd
    };
    let update_res2 = execute_tpm_command_via_send(&mut sim, &update_cmd_valid, &[pw()]);
    assert_eq!(update_res2.unwrap_err(), TpmRc::REFERENCE_H0.get());

    // 6. SequenceComplete reuse
    let complete_res_reuse = execute_tpm_command_via_send(&mut sim, &complete_cmd_valid, &[pw()]);
    assert_eq!(complete_res_reuse.unwrap_err(), TpmRc::REFERENCE_H0.get());
}

/// Sequences are not limited to 4096 bytes, event sequences report every implemented hash,
/// HMAC_Start checks `restricted` before `sign`, and HashSequenceStart reports RC_P2.
#[test]
fn long_data_event_banks_and_start_error_order() {
    let mut sim = create_simulator!();

    // > 4096 bytes across SequenceUpdate calls.
    let chunk: &'static [u8] = leak_bytes(&[0x5a; 1024]);
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    for _ in 0..6 {
        sequence_update(&mut sim, seq, chunk).expect("long sequences must be accepted");
    }
    sequence_complete(&mut sim, seq, b"", Handle::RH_NULL).unwrap();

    // Event sequence: SHA-1, SHA-256, SHA-384 and SHA-512 digests.
    let ev = start_hash_sequence(&mut sim, None);
    assert_eq!(
        event_sequence_complete(&mut sim, Handle::RH_NULL, ev, b"event").unwrap(),
        4
    );

    // HMAC_Start with a restricted, non-signing key -> ATTRIBUTES (restricted first).
    let key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        hmac_template(
            base_attrs() | TpmaObject::RESTRICTED | TpmaObject::DECRYPT,
            Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
                hash_alg: TpmiAlgHash::Sha256,
                kdf: Some(TpmiAlgKdf::Kdf1Sp800_108),
            })),
        ),
        b"",
    );
    let start = HMACStart {
        handle: key,
        auth: Tpm2bAuth::default(),
        hash_alg: None,
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &start, 1, &[]).unwrap_err(),
        rc_at(TpmRc::ATTRIBUTES, Position::handle(1))
    );
}

/// SequenceUpdate/SequenceComplete on a non-existent sequence handle fail with TPM_RC_REFERENCE_H0
#[test]
fn rejects_unloaded_sequence_handle() {
    let mut sim = create_simulator!();

    let invalid_handle = Handle(0x8000000F);

    // Update with invalid handle
    let update_cmd = SequenceUpdate {
        sequence_handle: invalid_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };
    let res_update = execute_tpm_command_auto_pw_unwrap(&mut sim, &update_cmd);
    assert_eq!(res_update.err(), Some(TpmRc::REFERENCE_H0.get()));

    // Complete with invalid handle
    let complete_cmd = SequenceComplete {
        sequence_handle: invalid_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let res_complete = execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd);
    assert_eq!(res_complete.err(), Some(TpmRc::REFERENCE_H0.get()));
}

/// SequenceUpdate/SequenceComplete on a completed sequence fail with TPM_RC_REFERENCE_H0
#[test]
fn rejects_use_after_complete() {
    let mut sim = create_simulator!();

    let handle = start_sequence_alg(&mut sim, TpmiAlgHash::Sha256);

    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd).unwrap();

    // Now try to update it again. Should fail with TpmRc::REFERENCE_H0.
    let update_cmd = SequenceUpdate {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"more data").unwrap(),
    };
    let res = execute_tpm_command_auto_pw_unwrap(&mut sim, &update_cmd);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));

    // Now try to complete it again. Should fail with TpmRc::REFERENCE_H0.
    let res_complete = execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd);
    assert_eq!(res_complete.err(), Some(TpmRc::REFERENCE_H0.get()));
}

/// SequenceUpdate/SequenceComplete reject a wrong password (BAD_AUTH + S1) and accept the right one.
#[test]
fn sequence_auth_value_enforced() {
    let mut sim = create_simulator!();

    // 1. HashSequenceStart with a non-empty authorization value.
    let sequence_auth = b"SecretAuthPassword123";
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::from_bytes(sequence_auth).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp_handles = execute_tpm_command_via_send(&mut sim, &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    // 2. SequenceUpdate with a session containing the WRONG password.
    // The implementation MUST reject this with TPM_RC_BAD_AUTH for session 1 (0x9A2).
    let wrong_auth_session = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"WrongPassword123").unwrap(),
    };

    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };
    let update_res_wrong =
        execute_tpm_command_via_send(&mut sim, &update_cmd, &[wrong_auth_session]);
    assert_eq!(update_res_wrong.unwrap_err(), 0x9A2);

    // 3. SequenceUpdate with the CORRECT password -> should succeed.
    let correct_auth_session = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(sequence_auth).unwrap(),
    };
    let update_res_correct =
        execute_tpm_command_via_send(&mut sim, &update_cmd, &[correct_auth_session]);
    assert!(update_res_correct.is_ok());

    // 4. SequenceComplete with a session containing the WRONG password -> should fail.
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_res_wrong =
        execute_tpm_command_via_send(&mut sim, &complete_cmd, &[wrong_auth_session]);
    assert_eq!(complete_res_wrong.unwrap_err(), 0x9A2);

    // 5. SequenceComplete with the CORRECT password -> should succeed.
    let complete_res_correct =
        execute_tpm_command_via_send(&mut sim, &complete_cmd, &[correct_auth_session]);
    assert!(complete_res_correct.is_ok());
}

/// HashSequenceStart with an unimplemented hash (SM3-256) is `TPM_RC_HASH + RC_P2`.
#[test]
fn sm3_hash_alg_returns_hash_p2() {
    let mut sim = create_simulator!();
    // Raw parameters: auth (empty TPM2B) || hashAlg = TPM_ALG_SM3_256 (0x0012).
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x8001u16.to_be_bytes()); // TPM_ST_NO_SESSIONS
    buf.extend_from_slice(&14u32.to_be_bytes());
    buf.extend_from_slice(&0x0000_0186u32.to_be_bytes()); // TPM_CC_HashSequenceStart
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0x0012u16.to_be_bytes());
    let mut rsp = [0u8; 64];
    sim.transact(&buf, &mut rsp).unwrap();
    let mut slice = &rsp[..];
    let rc = RespHeader::unmarshal(&mut slice).unwrap().rc;
    assert_eq!(rc, rc_at(TpmRc::HASH, Position::parameter(2)));
}

/// The number of concurrently active sequences is limited; once the limit is reached,
/// `TPM2_HashSequenceStart` fails with `TPM_RC_OBJECT_MEMORY` until a sequence completes.
#[test]
fn start_object_memory_limit() {
    let mut sim = create_simulator!();

    // Start sequences until the TPM runs out of sequence slots.
    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let mut handles = Vec::new();
    let limit_rc = loop {
        assert!(handles.len() < 64, "sequence limit never reached");
        match execute_tpm_command_auto_pw_unwrap(&mut sim, &start_cmd) {
            Ok(start_resp_handles) => handles.push(start_resp_handles.sequence_handle),
            Err(rc) => break rc,
        }
    };
    assert!(!handles.is_empty());

    // Starting one more sequence fails with TpmRc::OBJECT_MEMORY.
    assert_eq!(limit_rc, TpmRc::OBJECT_MEMORY.get());

    // Complete one sequence to free up a slot.
    let handle_to_complete = handles.pop().unwrap();
    let complete_cmd = SequenceComplete {
        sequence_handle: handle_to_complete,
        buffer: Tpm2bMaxBuffer::from_bytes(&[]).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd).unwrap();

    // Now starting a new sequence should succeed.
    let start_resp_handles = execute_tpm_command_auto_pw_unwrap(&mut sim, &start_cmd).unwrap();
    let new_handle = start_resp_handles.sequence_handle;
    assert!((new_handle.0 as u16) != 0);
}

/// TPM2_HashSequenceStart with trailing bytes fails with TPM_RC_SIZE
#[test]
fn start_rejects_trailing_bytes() {
    let mut sim = create_simulator!();

    let cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let res = execute_tpm_command_with_extra_bytes(&mut sim, &cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
}

/// Hash sequences work for SHA-1/256/384/512 and an invalid hashAlg fails with TPM_RC_HASH + P2.
#[test]
fn supported_algorithms_and_invalid_hash() {
    let mut sim = create_simulator!();

    let test_cases = [
        (TpmiAlgHash::Sha1, 20),
        (TpmiAlgHash::Sha256, 32),
        (TpmiAlgHash::Sha384, 48),
        (TpmiAlgHash::Sha512, 64),
    ];

    for (alg, expected_len) in test_cases {
        let seq_handle = start_sequence(&mut sim, Some(alg));

        let complete_cmd = SequenceComplete {
            sequence_handle: seq_handle,
            buffer: Tpm2bMaxBuffer::from_bytes(b"test").unwrap(),
            hierarchy: Handle::RH_NULL,
        };
        let complete_resp = execute_tpm_command_via_send(&mut sim, &complete_cmd, &[pw()]).unwrap();
        assert_eq!(complete_resp.result.get_size() as usize, expected_len);
    }

    // Invalid hash algorithm
    let invalid_start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_res = execute_tpm_command_with_corrupted_bytes_via_send(
        &mut sim,
        &invalid_start_cmd,
        &[],
        |buf| {
            buf[2..4].copy_from_slice(&0u16.to_be_bytes());
        },
    );
    assert_eq!(
        start_res.unwrap_err(),
        TpmRc::HASH.with(Position::parameter(2)).get()
    );
}

/// Hash, HashSequenceStart, SequenceUpdate, SequenceComplete and EventSequenceComplete reject trailing bytes with TPM_RC_SIZE.
#[test]
fn trailing_bytes_return_size() {
    let mut sim = create_simulator!();

    // 1. Hash command with trailing bytes
    let hash_cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"Helloooo").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_tpm_command_with_trailing(&mut sim, &hash_cmd, &[]);
    assert_eq!(res, Err(TpmRc::SIZE.get()));

    // 2. HashSequenceStart command with trailing bytes
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res2 = execute_tpm_command_with_trailing(&mut sim, &start_cmd, &[]);
    assert_eq!(res2, Err(TpmRc::SIZE.get()));

    // 3. SequenceUpdate command with trailing bytes
    let seq_handle = start_sequence(&mut sim, Some(TpmiAlgHash::Sha256));

    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };
    let res3 = execute_tpm_command_with_trailing(&mut sim, &update_cmd, &[pw()]);
    assert_eq!(res3, Err(TpmRc::SIZE.get()));

    // 4. SequenceComplete command with trailing bytes
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let res4 = execute_tpm_command_with_trailing(&mut sim, &complete_cmd, &[pw()]);
    assert_eq!(res4, Err(TpmRc::SIZE.get()));

    // 5. EventSequenceComplete command with trailing bytes
    let event_seq_handle = start_sequence(&mut sim, None);

    let event_complete_cmd = EventSequenceComplete {
        pcr_handle: Handle::RH_NULL,
        sequence_handle: event_seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
    };
    let res5 = execute_tpm_command_with_trailing(&mut sim, &event_complete_cmd, &[pw(), pw()]);
    assert_eq!(res5, Err(TpmRc::SIZE.get()));
}

/// TPM2_SequenceUpdate with trailing bytes fails with TPM_RC_SIZE
#[test]
fn update_rejects_trailing_bytes() {
    let mut sim = create_simulator!();

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_handles = execute_tpm_command_via_run(&mut sim, &start_cmd, &[]).unwrap();

    let update_cmd = SequenceUpdate {
        sequence_handle: start_handles.sequence_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };

    let res = execute_tpm_command_with_extra_bytes(&mut sim, &update_cmd, &[pw()]);
    assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
}
