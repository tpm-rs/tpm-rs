//! HMAC sequences (HMAC_Start / SequenceUpdate / SequenceComplete): key checks, results, auth and
//! slot limits.

use crate::_common::*;
#[allow(deprecated)]
use tpm2::commands::Sign;
use tpm2::commands::{
    CreatePrimary, EvictControl, FlushContext, HMAC, HMACStart, ReadPublic, SequenceComplete,
    SequenceUpdate,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bMaxBuffer,
    Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmlPcrSelection, TpmsSensitiveCreate,
    TpmtKeyedHashScheme, TpmtPublic, TpmtSigScheme, TpmtTkHashcheck, *,
};
use tpm2_simulator::create_simulator;

/// Starting more than the maximum concurrent HMAC sequences fails with TPM_RC_OBJECT_MEMORY until one completes.
///
/// 1. Starting multiple concurrent HMAC sequences.
#[test]
fn concurrent_sequences_object_memory() {
    let mut sim = create_simulator!();

    let key_handle = make_keyed_hash_key(&mut sim, b"hmac_key_bytes");

    let start_cmd = HMACStart {
        handle: key_handle,
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let mut handles = Vec::new();
    // Start up to MAX_ACTIVE_SEQUENCES concurrent HMAC sequences
    for _ in 0..MAX_ACTIVE_SEQUENCES {
        let resp_h =
            execute_tpm_command_mapping_parse_errors(&mut sim, &start_cmd, &[pw()]).unwrap();
        handles.push(resp_h.sequence_handle);
    }

    // Try starting one more, should fail with TPM_RC_OBJECT_MEMORY (0x902)
    let start_res = execute_tpm_command_mapping_parse_errors(&mut sim, &start_cmd, &[pw()]);
    assert!(start_res.is_err());
    let rc = start_res.unwrap_err();
    assert_eq!(rc & 0xFF, 0x02);

    // Complete one sequence
    let complete_cmd = SequenceComplete {
        sequence_handle: handles[0],
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command_mapping_parse_errors(&mut sim, &complete_cmd, &[pw()]).unwrap();

    // Now starting another one should succeed
    let start_res_ok = execute_tpm_command_mapping_parse_errors(&mut sim, &start_cmd, &[pw()]);
    assert!(start_res_ok.is_ok());
}

/// An HMAC sequence accepts more than 4096 bytes without TPM_RC_MEMORY.
#[test]
fn data_beyond_4096_bytes_accepted() {
    let mut sim = create_simulator!();
    let key_handle = create_keyed_hash_key(&mut sim, b"keyauth", b"key");

    let auths = [password_auth(b"keyauth")];
    let start_cmd = HMACStart {
        handle: key_handle,
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_rsp = execute_tpm_command(&mut sim, &start_cmd, &auths).unwrap();
    let seq_handle = start_rsp.sequence_handle;

    // The sequence has an empty authValue; SequenceUpdate/SequenceComplete require USER
    // authorization of the sequence handle (C: TPM_RC_AUTH_MISSING without a session).
    let seq_auths = [password_auth(b"")];

    // Send 4 chunks of 1024 bytes (total 4096 bytes)
    let chunk_1024 = vec![0u8; 1024];
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&chunk_1024).unwrap(),
    };
    for _ in 0..4 {
        execute_tpm_command(&mut sim, &update_cmd, &seq_auths).unwrap();
    }

    // C has no limit on the total length of a sequence (the data is consumed by the running
    // hash), so going past 4096 bytes must still succeed (no TPM_RC_MEMORY).
    let update_cmd_more = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&[0]).unwrap(),
    };
    execute_tpm_command(&mut sim, &update_cmd_more, &seq_auths).unwrap();

    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command(&mut sim, &complete_cmd, &seq_auths).unwrap();
}

/// Authorized HMAC_Start on a keyed-hash data object (not an HMAC key) fails with TPM_RC_KEY + H1.
///
/// `TPM2_HMAC_Start`, correctly authorized, on a loaded object that is not an HMAC signing key
/// fails with `TPM_RC_KEY + H1`.
#[test]
fn hmac_start_non_hmac_keyedhash_returns_key_h1() {
    let mut sim = create_simulator!();

    // A loaded keyed-hash data object (neither sign nor decrypt) with authValue "password".
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(b"password").unwrap(),
            data: Tpm2bSensitiveData::from_bytes(b"data").unwrap(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::USER_WITH_AUTH
                | TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let created = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    let cmd = HMACStart {
        handle: created.object_handle,
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    // Password session with the object's authValue.
    let err_code = execute_with_password_sessions(&mut sim, &cmd, 1, b"password")
        .expect_err("HMAC_Start on a non-signing object must fail");
    assert_eq!(err_code, TpmRc::KEY.with(Position::handle(1)).get());
}

/// HMAC_Start on a restricted non-signing key reports ATTRIBUTES before KEY.
///
/// Same ordering requirement as above, from the second MAC_Start finding.
#[test]
fn hmac_start_restricted_checked_before_sign() {
    let mut sim = create_simulator!();
    // Restricted and non-signing: ATTRIBUTES (restricted) before KEY (sign).
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

/// HMAC_Start reports attribute errors (restricted: ATTRIBUTES + H1) before an incompatible
/// hashAlg (VALUE + P2).
///
/// This TPM implements `TPM2_HMAC_Start` (no CMAC), whose reference order (`HMAC_Start.c`) is:
/// key type, `restricted`, `sign`, then the hash selection. A restricted HMAC key with a
/// mismatching `hashAlg` therefore reports `TPM_RC_ATTRIBUTES + RC_H1`, while an unrestricted
/// signing key with the same `hashAlg` reports `TPM_RC_VALUE + RC_P2`.
#[test]
fn hmac_start_attributes_checked_before_hash() {
    let mut sim = create_simulator!();
    let key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        hmac_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    // Restricted + mismatching hash: attribute error first.
    let restricted = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        hmac_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT | TpmaObject::RESTRICTED,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let start = HMACStart {
        handle: Handle::default(),
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha1),
    };
    for (handle, expected) in [
        (key, rc_at(TpmRc::VALUE, Position::parameter(2))),
        (restricted, rc_at(TpmRc::ATTRIBUTES, Position::handle(1))),
    ] {
        assert_eq!(
            execute_with_password_sessions(&mut sim, &HMACStart { handle, ..start }, 1, &[])
                .unwrap_err(),
            expected
        );
    }
}

/// HMAC_Start on an unloaded transient handle fails with TPM_RC_REFERENCE_H0.
///
/// `TPM2_HMAC_Start` on a transient handle that is not loaded fails with
/// `TPM_RC_REFERENCE_H0`.
#[test]
fn hmac_start_unloaded_key_returns_reference_h0() {
    let mut sim = create_simulator!();

    let cmd = HMACStart {
        handle: Handle(0x80000001),
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let err_code = execute_with_password_sessions(&mut sim, &cmd, 0, &[])
        .expect_err("HMAC_Start on a missing object must fail");
    assert_eq!(err_code, TpmRc::REFERENCE_H0.get());
}

/// HMAC_Start works on a persistent HMAC key; Sign with a mismatched ECDSA inScheme fails with TPM_RC_SCHEME.
#[test]
#[allow(deprecated)]
fn persistent_hmac_key_starts_sequence() {
    let mut sim = create_simulator!();
    let persistent_handle = Handle(0x81000003);
    let key_bytes = b"persistent_key_bytes_secret_12";
    let transient_handle = create_keyed_hash_key(&mut sim, b"keyauth", key_bytes);

    let evict_cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: transient_handle,
        persistent_handle,
    };
    let evict_auths = [password_auth(b"")];
    execute_tpm_command(&mut sim, &evict_cmd, &evict_auths).unwrap();

    // Unload the transient copy.
    let flush_cmd = FlushContext {
        flush_handle: transient_handle,
    };
    execute_tpm_command(&mut sim, &flush_cmd, &[]).unwrap();

    let rp_cmd = ReadPublic {
        object_handle: transient_handle,
    };
    let res = execute_tpm_command(&mut sim, &rp_cmd, &[]);
    assert_eq!(res.unwrap_err(), TpmRc::REFERENCE_H0.get());

    let rp_cmd_p = ReadPublic {
        object_handle: persistent_handle,
    };
    let rp_resp = execute_tpm_command(&mut sim, &rp_cmd_p, &[]).unwrap();
    assert!(!rp_resp.name.get_buffer().is_empty());

    let mac_cmd = HMAC {
        handle: persistent_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"hello world").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let key_auths = [password_auth(b"keyauth")];
    let mac_resp = execute_tpm_command(&mut sim, &mac_cmd, &key_auths).unwrap();
    assert_eq!(
        mac_resp.out_hmac.get_buffer(),
        hmac_sha256_single(key_bytes, b"hello world")
    );

    let hmac_start_cmd = HMACStart {
        handle: persistent_handle,
        auth: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_start_rsp = execute_tpm_command(&mut sim, &hmac_start_cmd, &key_auths).unwrap();
    let seq_handle = hmac_start_rsp.sequence_handle;

    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command(&mut sim, &complete_cmd, &[password_auth(b"seqauth")]).unwrap();

    let sign_cmd = Sign {
        key_handle: persistent_handle,
        digest: Tpm2bDigest::from_bytes(&[0; 32]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let res = execute_tpm_command(&mut sim, &sign_cmd, &key_auths);
    // CryptSelectSignScheme: an ECDSA inScheme doesn't match the key's HMAC scheme ->
    // TPM_RCS_SCHEME + RC_Sign_inScheme (Sign.c).
    assert_eq!(
        res.unwrap_err(),
        TpmRc::SCHEME.with(Position::parameter(2)).get()
    );

    let evict_cmd_p = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: persistent_handle,
        ..evict_cmd
    };
    execute_tpm_command(&mut sim, &evict_cmd_p, &evict_auths).unwrap();
}

/// HMAC sequence handles need USER auth (AUTH_MISSING/BAD_AUTH), reject ReadPublic (SEQUENCE) and misuse (MODE).
#[test]
fn sequence_auth_and_read_public_rejected() {
    let mut sim = create_simulator!();
    let key_handle = create_keyed_hash_key(&mut sim, b"keyauth", b"key");

    let auths = [password_auth(b"keyauth")];
    let start_cmd = HMACStart {
        handle: key_handle,
        auth: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_rsp = execute_tpm_command(&mut sim, &start_cmd, &auths).unwrap();
    let seq_handle = start_rsp.sequence_handle;

    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
    };

    let res = execute_tpm_command(&mut sim, &update_cmd, &[]);
    assert_eq!(res.unwrap_err(), TpmRc::AUTH_MISSING.get());

    let res = execute_tpm_command(&mut sim, &update_cmd, &[password_auth(b"wrongauth")]);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::BAD_AUTH.with(Position::session(1)).get()
    );

    let rp_cmd = ReadPublic {
        object_handle: seq_handle,
    };
    let res = execute_tpm_command(&mut sim, &rp_cmd, &[]);
    // C: ReadPublic of a sequence object returns bare TPM_RC_SEQUENCE (0x103), ReadPublic.c:22.
    assert_eq!(res.unwrap_err(), TpmRc::SEQUENCE.get());

    let mac_cmd = HMAC {
        handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = execute_tpm_command(&mut sim, &mac_cmd, &[]);
    assert_eq!(res.unwrap_err(), TpmRc::AUTH_MISSING.get());

    let bad_update_cmd = SequenceUpdate {
        sequence_handle: key_handle,
        ..update_cmd
    };
    let res = execute_tpm_command(&mut sim, &bad_update_cmd, &auths);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::MODE.with(Position::handle(1)).get()
    );

    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command(&mut sim, &complete_cmd, &[password_auth(b"seqauth")]).unwrap();
}

/// HMAC sequence over split chunks matches the client HMAC; feeding more than 4096 bytes is accepted.
///
/// 3. Performing HMAC update with very large data buffers or split chunks.
#[test]
fn split_and_large_updates() {
    let mut sim = create_simulator!();

    let key_bytes: &'static [u8] = b"hmac_key_bytes";
    let key_handle = make_keyed_hash_key(&mut sim, key_bytes);

    let start_cmd = HMACStart {
        handle: key_handle,
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_rsp =
        execute_tpm_command_mapping_parse_errors(&mut sim, &start_cmd, &[pw()]).unwrap();
    let seq_handle = start_rsp.sequence_handle;

    // Update with 10 split chunks of 100 bytes each
    let chunk = [0x55u8; 100];
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&chunk).unwrap(),
    };
    for _ in 0..10 {
        execute_tpm_command_mapping_parse_errors(&mut sim, &update_cmd, &[pw()]).unwrap();
    }

    // Complete sequence
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp =
        execute_tpm_command_mapping_parse_errors(&mut sim, &complete_cmd, &[pw()]).unwrap();

    // Verify HMAC output against the client-side HMAC
    let combined_data = vec![0x55u8; 1000];
    assert_eq!(
        complete_resp.result.get_buffer(),
        expected_hmac(key_bytes, &combined_data)
    );

    // Test buffer limits: feed more than 4096 bytes into a sequence.
    let start_rsp_2 =
        execute_tpm_command_mapping_parse_errors(&mut sim, &start_cmd, &[pw()]).unwrap();
    let seq_handle_2 = start_rsp_2.sequence_handle;

    // Fill to 4096 bytes
    let large_chunk = [0xaa; 1024];
    let update_cmd_large = SequenceUpdate {
        sequence_handle: seq_handle_2,
        buffer: Tpm2bMaxBuffer::from_bytes(&large_chunk).unwrap(),
    };
    for _ in 0..4 {
        execute_tpm_command_mapping_parse_errors(&mut sim, &update_cmd_large, &[pw()]).unwrap();
    }

    // Update 1 more byte. C streams sequence data into the hash state with no length limit
    // (SequenceUpdate.c has no TPM_RC_MEMORY path), so this succeeds.
    let update_cmd_one = SequenceUpdate {
        sequence_handle: seq_handle_2,
        buffer: Tpm2bMaxBuffer::from_bytes(&[1]).unwrap(),
    };
    let update_res = execute_tpm_command_mapping_parse_errors(&mut sim, &update_cmd_one, &[pw()]);
    assert!(update_res.is_ok());

    // Clean up sequence 2
    let complete_cmd_2 = SequenceComplete {
        sequence_handle: seq_handle_2,
        ..complete_cmd
    };
    execute_tpm_command_mapping_parse_errors(&mut sim, &complete_cmd_2, &[pw()]).unwrap();
}

/// An HMAC sequence fed in chunks yields the same HMAC as a one-shot client computation.
#[test]
fn split_chunks_match_hmac() {
    let mut sim = create_simulator!();
    let key_bytes = b"another_secret_key_bytes_56789";
    let key_handle = create_keyed_hash_key(&mut sim, b"keyauth", key_bytes);

    let auths = [password_auth(b"keyauth")];
    let start_cmd = HMACStart {
        handle: key_handle,
        auth: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_rsp = execute_tpm_command(&mut sim, &start_cmd, &auths).unwrap();
    let seq_handle = start_rsp.sequence_handle;

    let seq_auths = [password_auth(b"seqauth")];

    let chunk1 = b"Hello, ";
    let chunk2 = b"this is a stress test for ";
    let chunk3 = b"HMAC sequence updates!";

    for chunk in [&chunk1[..], &chunk2[..], &chunk3[..]] {
        let update_cmd = SequenceUpdate {
            sequence_handle: seq_handle,
            buffer: Tpm2bMaxBuffer::from_bytes(chunk).unwrap(),
        };
        execute_tpm_command(&mut sim, &update_cmd, &seq_auths).unwrap();
    }

    let final_chunk = b" End of sequence.";
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(final_chunk).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command(&mut sim, &complete_cmd, &seq_auths).unwrap();

    let mut full_data = Vec::new();
    full_data.extend_from_slice(chunk1);
    full_data.extend_from_slice(chunk2);
    full_data.extend_from_slice(chunk3);
    full_data.extend_from_slice(final_chunk);

    assert_eq!(
        complete_resp.result.get_buffer(),
        hmac_sha256_single(key_bytes, &full_data)
    );
}

/// SequenceUpdate / SequenceComplete with a wrong sequence password fail with TPM_RC_BAD_AUTH.
///
/// 2. Using invalid session attributes or unauthorized commands.
#[test]
fn wrong_password_rejected() {
    let mut sim = create_simulator!();

    let key_handle = make_keyed_hash_key(&mut sim, b"hmac_key_bytes");

    let seq_auth: &'static [u8] = b"SeqPassword123";
    let start_cmd = HMACStart {
        handle: key_handle,
        auth: Tpm2bAuth::from_bytes(seq_auth).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_rsp =
        execute_tpm_command_mapping_parse_errors(&mut sim, &start_cmd, &[pw()]).unwrap();
    let seq_handle = start_rsp.sequence_handle;

    // Try updating sequence with WRONG password session
    let wrong_auth = pw_with(b"WrongPassword123");
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };
    let update_res = execute_tpm_command_mapping_parse_errors(&mut sim, &update_cmd, &[wrong_auth]);
    assert_eq!(update_res.err(), Some(0x9A2)); // TPM_RC_BAD_AUTH for session 1

    // Update with CORRECT password session
    let correct_auth = pw_with(seq_auth);
    let update_res_ok =
        execute_tpm_command_mapping_parse_errors(&mut sim, &update_cmd, &[correct_auth]);
    assert!(update_res_ok.is_ok());

    // Try completing sequence with WRONG password session
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_res =
        execute_tpm_command_mapping_parse_errors(&mut sim, &complete_cmd, &[wrong_auth]);
    assert_eq!(complete_res.err(), Some(0x9A2));

    // Complete with CORRECT password session
    let complete_res_ok =
        execute_tpm_command_mapping_parse_errors(&mut sim, &complete_cmd, &[correct_auth]);
    assert!(complete_res_ok.is_ok());
}
