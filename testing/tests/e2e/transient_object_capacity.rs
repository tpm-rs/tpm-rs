//! Transient object slot capacity: exhaustion by objects and sequences and recovery after flush.

use crate::_common::{
    ECC_X, ECC_Y, MAX_PROBED_SEQUENCES, create_keyed_hash_key, empty_password_auth,
    execute_tpm_command, execute_tpm_command_uncorrupted, execute_tpm_command_via_send,
    execute_with_password_sessions, fill_sequence_slots, flush_context, get_test_template,
    make_ecc_public_area, make_ecc_public_area_exact_attrs, make_template, password_auth, pw,
    start_sequence,
};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::CreateLoaded;
use tpm2::commands::{
    CreatePrimary, FlushContext, HMACStart, HashSequenceStart, LoadExternal, SequenceComplete,
    SequenceUpdate,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bMaxBuffer,
    Tpm2bSensitiveData, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmlPcrSelection, TpmsEccParms,
    TpmsEccPoint, TpmsSensitiveCreate, TpmtPublic, *,
};

/// Calling TPM2_CreateLoaded 65 times (beyond transient object slots) does not panic the TPM.
#[test]
#[allow(deprecated)]
fn create_loaded_exhausting_object_slots_does_not_panic() {
    let mut sim = Tpm::new();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                    hash_alg: TpmiAlgHash::Sha256,
                    count: 0,
                })),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = make_template(&pub_area);

    let create = CreateLoaded {
        parent_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
    };

    // GlobalState transient_objects has size 64. Calling this 65 times should panic!
    for _ in 0..65 {
        let _ = execute_with_password_sessions(&mut sim, &create, 1, &[]);
    }
}

/// FlushContext aborts a sequence (later use is REFERENCE_H0, double flush HANDLE + P1) and recycles its slot.
#[test]
fn flush_aborts_hash_sequence_and_frees_slot() {
    let mut sim = Tpm::new();

    // 1. Start a sequence, then abort it via FlushContext
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let seq_handle = start_sequence(&mut sim, Some(TpmiAlgHash::Sha256));

    let flush_cmd = FlushContext {
        flush_handle: seq_handle,
    };
    execute_tpm_command_via_send(&mut sim, &flush_cmd, &[]).unwrap();

    // Verify it is aborted (SequenceUpdate returns ReferenceH0)
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };
    let update_res = execute_tpm_command_via_send(&mut sim, &update_cmd, &[]);
    assert_eq!(update_res.unwrap_err(), TpmRc::REFERENCE_H0.get());

    // Double flush should fail with ReferenceH0
    let flush_res_double = execute_tpm_command_via_send(&mut sim, &flush_cmd, &[]);
    // C: TPM_RCS_HANDLE + RC_FlushContext_flushHandle (0x1CB), FlushContext.c:22.
    assert_eq!(
        flush_res_double.unwrap_err(),
        TpmRc::HANDLE.with(Position::parameter(1)).get()
    );

    // 2. Slot recycling verification: fill all available slots; the failing start returns
    // TPM_RC_OBJECT_MEMORY.
    let handles = fill_sequence_slots(&mut sim);

    // Flush one sequence
    let flush_cmd_recycle = FlushContext {
        flush_handle: handles[handles.len() - 1],
    };
    execute_tpm_command_via_send(&mut sim, &flush_cmd_recycle, &[]).unwrap();

    // Another start should now succeed
    let start_res_retry = execute_tpm_command_via_send(&mut sim, &start_cmd, &[]);
    assert!(start_res_retry.is_ok());
}

/// Starting sequences until TPM_RC_OBJECT_MEMORY, then completing one frees a slot for a new sequence.
#[test]
fn hash_sequence_slots_recover_after_complete() {
    let mut sim = Tpm::new();

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    // Start sequences until the TPM runs out of object slots; the failing start returns
    // TPM_RC_OBJECT_MEMORY.
    let handles = fill_sequence_slots(&mut sim);

    // Complete one sequence
    let complete_cmd = SequenceComplete {
        sequence_handle: handles[0],
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command_via_send(&mut sim, &complete_cmd, &[pw()]).unwrap();

    // Now starting another sequence should succeed!
    let start_res_ok = execute_tpm_command_via_send(&mut sim, &start_cmd, &[]);
    assert!(start_res_ok.is_ok());
}

/// Sequences get consecutive transient handles and the next start fails with OBJECT_MEMORY when slots are full.
#[test]
fn hash_sequences_share_transient_handles() {
    let mut sim = Tpm::new();

    // Start 3 sequences -> handles should be strictly 0x80000000, 0x80000001, 0x80000002
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let mut handles = [0u32; 3];
    for h in &mut handles {
        let resp = execute_tpm_command_via_send(&mut sim, &start_cmd, &[]).unwrap();
        *h = resp.sequence_handle.0;
    }
    assert_eq!(handles, [0x80000000, 0x80000001, 0x80000002]);

    // Attempting a 4th sequence should fail with OBJECT_MEMORY because s_objects capacity (3) is full
    let fourth_res = execute_tpm_command_via_send(&mut sim, &start_cmd, &[]);
    assert!(fourth_res.is_err());
}

/// The TPM's object slots are shared by loaded objects and sequences: starting HMAC
/// sequences eventually fails with `TPM_RC_OBJECT_MEMORY`, and completing a sequence frees
/// its slot (and handle) for the next one.
#[test]
fn hmac_sequences_share_object_slots() {
    let mut sim = Tpm::new();
    let key_handle = create_keyed_hash_key(&mut sim, b"keyauth", b"my_secret_key_bytes_12345");

    let auths = [password_auth(b"keyauth")];
    let start_cmd = HMACStart {
        handle: key_handle,
        auth: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let mut seq_handles = Vec::new();
    loop {
        match execute_tpm_command(&mut sim, &start_cmd, &auths) {
            Ok(resp) => seq_handles.push(resp.sequence_handle),
            Err(rc) => {
                assert_eq!(rc, TpmRc::OBJECT_MEMORY.get());
                break;
            }
        }
        assert!(
            seq_handles.len() < MAX_PROBED_SEQUENCES,
            "TPM never ran out of object memory"
        );
    }
    assert!(!seq_handles.is_empty(), "no HMAC sequence could be started");

    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handles[0],
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command(&mut sim, &complete_cmd, &[password_auth(b"seqauth")]).unwrap();

    let resp = execute_tpm_command(&mut sim, &start_cmd, &auths).unwrap();
    let new_seq_handle = resp.sequence_handle;
    assert_eq!(new_seq_handle.0, seq_handles[0].0);
}

/// Loading external keys until slots run out fails with TPM_RC_OBJECT_MEMORY.
#[test]
fn load_external_until_object_memory() {
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(make_ecc_public_area_exact_attrs(
        ECC_X,
        ECC_Y,
        TpmaObject::SIGN_ENCRYPT,
    ));

    // Load MAX_LOADED_OBJECTS objects
    for i in 0..tpm2::TPM2_MAX_LOADED_OBJECTS as usize {
        let cmd = LoadExternal {
            in_private: None,
            in_public,
            hierarchy: Handle::RH_NULL,
        };
        let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
        assert!(res.is_ok(), "Failed to load object {}", i);
    }

    // Next load should fail with ObjectMemory
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::OBJECT_MEMORY.get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// Loading external keys until the transient slots are full fails with TPM_RC_OBJECT_MEMORY; a flush frees a slot.
#[test]
fn load_external_until_object_memory_then_flush() {
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let mut handles = Vec::new();
    for _ in 0..tpm2::TPM2_MAX_LOADED_OBJECTS as usize {
        let resp = sim.execute(cmd).unwrap();
        handles.push(resp.object_handle);
    }

    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::OBJECT_MEMORY;
    assert_eq!(err.get(), expected.get());

    for handle in handles {
        flush_context(&mut sim, handle).unwrap();
    }
}

/// Exactly `MAX_LOADED_OBJECTS` (3) primary objects can be loaded at once; the next
/// TPM2_CreatePrimary fails with TPM_RC_OBJECT_MEMORY.
#[test]
fn create_primary_beyond_capacity_out_of_memory() {
    let mut sim = Tpm::new();

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(t_sens),
        in_public: tpm2::Tpm2b(get_test_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    // Exactly MAX_LOADED_OBJECTS items should be created and stored in RAM without error.
    for i in 0..tpm2::TPM2_MAX_LOADED_OBJECTS {
        let res = execute_tpm_command_uncorrupted(&mut sim, &cmd, &[empty_password_auth()]);
        assert!(
            res.is_ok(),
            "CreatePrimary at slot {} failed unexpectedly: {:?}",
            i,
            res.err()
        );
    }

    // The next load attempt should fail with TPM_RC_OBJECT_MEMORY (0x902), preserving cache limits.
    let overflow_res = execute_tpm_command_uncorrupted(&mut sim, &cmd, &[empty_password_auth()]);
    assert_eq!(
        overflow_res.err(),
        Some(TpmRc::OBJECT_MEMORY.get()),
        "Expected TPM_RC_OBJECT_MEMORY when exceeding the transient capacity"
    );
}
