//! TPM2_ContextSave / TPM2_ContextLoad validation: handle types, integrity coverage, keystream
//! reuse and reset/restart invalidation.

use crate::_common::{
    CC_CONTEXT_SAVE, ST_NO_SESSIONS, TPM_SU_CLEAR, TPM_SU_STATE, build_raw_cmd, context_load,
    context_save, context_save_raw, create_keyed_hash_object_with_attrs, create_storage_primary_in,
    create_test_keys, execute_with_password_sessions, flush_context, flush_rc, mssim_rc_of, nv_off,
    nv_on, rc_h, rc_p, shutdown_and_start_clear, start_session_raw,
};
#[allow(deprecated)]
use tpm2::commands::{ContextLoad, ContextSave, CreateLoaded};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmaObject, TpmsContextData, Unmarshal};
use tpm2_simulator::create_simulator;

/// stClear object contexts do not load after TPM Restart and no object context loads after TPM Reset (TPM_RC_INTEGRITY)
///
/// Object contexts are bound to the TPM state they were saved in: the context of an
/// `stClear` object must not load after a TPM Restart (clear count changed), and the
/// context of any object must not load after a TPM Reset (total reset count changed).
///
/// The white-box original changed `clear_count` / `total_reset_count` directly; here
/// the counters are changed through `TPM2_Shutdown` + power cycle + `TPM2_Startup`.
#[test]
fn context_load_rejects_after_restart_or_reset() {
    let mut sim = create_simulator!();

    let st_clear_handle = create_keyed_hash_object_with_attrs(&mut sim, TpmaObject::ST_CLEAR);
    let st_clear_context = context_save(&mut sim, st_clear_handle);
    // stClear objects are saved with the TRANSIENT_STCLEAR handle (0x80000002).
    assert_eq!(st_clear_context.saved_handle.0, 0x80000002);

    let handle = create_keyed_hash_object_with_attrs(&mut sim, TpmaObject::default());
    let context = context_save(&mut sim, handle);

    // 1. A TPM Restart changes the clear count, which invalidates the ST_CLEAR context.
    shutdown_and_start_clear(&mut sim, TPM_SU_STATE);
    assert_eq!(
        context_load(&mut sim, st_clear_context),
        // C: TPM_RCS_INTEGRITY + RC_ContextLoad_context (0x1DF), ContextLoad.c:76.
        Err(TpmRc::INTEGRITY.with(Position::parameter(1)).get()),
        "ST_CLEAR context must fail when clear_count increments"
    );
    // The non-stClear object context survives the restart.
    let loaded = context_load(&mut sim, context).expect("context must survive a TPM Restart");
    flush_context(&mut sim, loaded).unwrap();

    // 2. A TPM Reset changes the total reset count: must fail with INTEGRITY.
    shutdown_and_start_clear(&mut sim, TPM_SU_CLEAR);
    assert_eq!(
        context_load(&mut sim, context),
        // C: TPM_RCS_INTEGRITY + RC_ContextLoad_context (0x1DF), ContextLoad.c:76.
        Err(TpmRc::INTEGRITY.with(Position::parameter(1)).get()),
        "Context must fail when total_reset_count increments"
    );
}

/// TPM2_ContextLoad of a context with a tampered integrity HMAC fails with TPM_RC_INTEGRITY + P1
#[test]
fn context_load_rejects_tampered_integrity() {
    let mut sim = create_simulator!();
    let handle = create_keyed_hash_object_with_attrs(&mut sim, TpmaObject::default());

    let mut tampered_context = context_save(&mut sim, handle);
    tampered_context.saved_handle.0 ^= 0x01; // Tamper with the handle

    // C: TPM_RCS_INTEGRITY + RC_ContextLoad_context (0x1DF), ContextLoad.c:76.
    assert_eq!(
        context_load(&mut sim, tampered_context),
        Err(TpmRc::INTEGRITY.with(Position::parameter(1)).get()),
        "HMAC check should fail!"
    );
}

/// TPM2_ContextLoad rejects a context whose sequence, savedHandle or hierarchy was modified
#[test]
#[allow(deprecated)]
fn context_load_rejects_tampered_sequence_handle_hierarchy() {
    let mut sim = create_simulator!();
    let (in_sensitive, in_public) = create_test_keys();
    let cmd = CreateLoaded {
        parent_handle: tpm2::Handle(0x40000001),
        in_sensitive,
        in_public,
    };
    let resp_handles = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();
    let created_handle = resp_handles.object_handle;

    let save_cmd = ContextSave {
        save_handle: created_handle,
    };
    let save_resp = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]).unwrap();

    flush_context(&mut sim, created_handle).unwrap();

    // 1. Mutate sequence
    let mut mutated_seq = save_resp.context;
    mutated_seq.sequence = mutated_seq.sequence.wrapping_add(1);
    let load_cmd = ContextLoad {
        context: mutated_seq,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]);
    assert!(res.is_err(), "MAC check failed to catch mutated sequence!");

    // 2. Mutate saved_handle
    let mut mutated_handle = save_resp.context;
    mutated_handle.saved_handle.0 ^= 1;
    let load_cmd = ContextLoad {
        context: mutated_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]);
    assert!(
        res.is_err(),
        "MAC check failed to catch mutated saved_handle!"
    );

    // 3. Mutate hierarchy
    let mut mutated_hierarchy = save_resp.context;
    mutated_hierarchy.hierarchy.0 ^= 1;
    let load_cmd = ContextLoad {
        context: mutated_hierarchy,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]);
    assert!(res.is_err(), "MAC check failed to catch mutated hierarchy!");
}

/// Two context saves of the same object produce different encrypted blobs (no keystream reuse)
#[test]
#[allow(deprecated)]
fn context_save_uses_fresh_keystream() {
    let mut sim = create_simulator!();
    let (in_sensitive, in_public) = create_test_keys();
    let cmd = CreateLoaded {
        parent_handle: tpm2::Handle(0x40000001),
        in_sensitive,
        in_public,
    };
    let resp_handles = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();
    let created_handle = resp_handles.object_handle;

    let save_cmd = ContextSave {
        save_handle: created_handle,
    };

    let save_resp1 = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]).unwrap();
    let save_resp2 = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]).unwrap();

    let ctx1 = save_resp1.context;
    let ctx2 = save_resp2.context;

    assert_eq!(ctx1.saved_handle, ctx2.saved_handle);
    assert_ne!(ctx1.sequence, ctx2.sequence, "Sequence should increment!");

    // The encrypted part must be different, avoiding keystream reuse

    let mut u1 = ctx1.context_blob.get_buffer();
    let tpms_ctx1 = TpmsContextData::unmarshal(&mut u1).unwrap();
    let mut u2 = ctx2.context_blob.get_buffer();
    let tpms_ctx2 = TpmsContextData::unmarshal(&mut u2).unwrap();
    assert_ne!(
        tpms_ctx1.encrypted.get_buffer(),
        tpms_ctx2.encrypted.get_buffer(),
        "ContextSave encrypted payload is identical! Keystream/IV reuse detected!"
    );
}

/// ContextSave validates saveHandle as TPMI_DH_CONTEXT (VALUE + H1) and the session type byte (HANDLE + H1); FlushContext error positions.
///
/// `TPM2_ContextSave` validates `saveHandle` as a `TPMI_DH_CONTEXT` (`TPM_RC_VALUE + RC_H1`)
/// and checks the session type of session handles; `TPM2_FlushContext` positions its errors.
#[test]
fn save_handle_type_and_session_type() {
    let mut sim = create_simulator!();
    for handle in [0x8100_0099u32, 0x4000_0005, 0x4000_0001, 0x0100_0001] {
        assert_eq!(
            context_save_raw(&mut sim, handle),
            Err(rc_h(TpmRc::VALUE, 1)),
            "handle {handle:#x}"
        );
    }
    // Unloaded session / transient handles.
    assert_eq!(
        context_save_raw(&mut sim, 0x0200_0007),
        Err(TpmRc::REFERENCE_H0.get())
    );
    assert_eq!(
        context_save_raw(&mut sim, 0x8000_0007),
        Err(TpmRc::REFERENCE_H0.get())
    );
    // A loaded policy session referenced with the HMAC type byte: TPM_RC_HANDLE + RC_H1.
    let p = start_session_raw(&mut sim, 1);
    assert_eq!(
        context_save_raw(&mut sim, 0x0200_0000 | (p & 0x00FF_FFFF)),
        Err(rc_h(TpmRc::HANDLE, 1))
    );
    assert!(context_save_raw(&mut sim, p).is_ok());

    assert_eq!(flush_rc(&mut sim, 0x8000_0009), rc_p(TpmRc::HANDLE, 1));
    assert_eq!(flush_rc(&mut sim, 0x4000_0001), rc_p(TpmRc::VALUE, 1));
}

/// ContextSave of a permanent handle (RH_OWNER) fails
#[test]
fn save_permanent_handle_rejected() {
    let mut sim = create_simulator!();

    let save_cmd = ContextSave {
        save_handle: Handle(0x40000001), // TPM_RH_OWNER
    };
    let res = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]);
    assert!(res.is_err(), "Context save on permanent handle should fail");
}

/// ContextSave reports TPM_RC_SIZE for trailing bytes before the orderly / NV-unavailable check.
///
/// `TPM2_ContextSave` performs `RETURN_IF_ORDERLY` only after the parameter checks: trailing
/// bytes are `TPM_RC_SIZE` even when NV is unavailable in an orderly state.
#[test]
fn trailing_bytes_checked_before_orderly() {
    let mut sim = create_simulator!();
    let key = create_storage_primary_in(&mut sim, Handle::RH_OWNER);
    // TPM2_Shutdown(CLEAR) makes the state orderly; the TPM keeps executing commands.
    let shutdown = build_raw_cmd(ST_NO_SESSIONS, 0x145, &[], None, &0u16.to_be_bytes());
    assert_eq!(mssim_rc_of(&mut sim, &shutdown), 0);
    nv_off(&mut sim);
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_CONTEXT_SAVE, &[key.0], None, &[0x00]);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::SIZE.get());
    // Without trailing bytes the orderly check applies.
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_CONTEXT_SAVE, &[key.0], None, &[]);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::NV_UNAVAILABLE.get());
    nv_on(&mut sim);
}
