//! Handles of persistent objects and later transient handles in the same command: a transient
//! handle must reference a loaded object (TPM 2.0 Part 3, "Handle Area Validation": "If the
//! handle references a transient object, the handle shall reference a loaded object
//! (`TPM_RC_REFERENCE_H0` + N ...)"), even when the reference has put the per-command RAM copy of
//! an earlier persistent handle into that object slot.

use crate::_common::{
    ST_SESSIONS, build_raw_cmd, create_ecc_parent_key, evict_control, flush_context, mssim_rc_of,
};
use testing::tpm::Tpm;
use tpm2::Handle;

/// `TPM_RC_REFERENCE_H1`.
const RC_REFERENCE_H1: u32 = 0x911;
/// An empty password session (`TPM_RS_PW`, no nonce, continueSession, empty password).
const PW_SESSION: &[u8] = &[0x40, 0, 0, 0x09, 0, 0, 0x01, 0, 0];

/// A persistent copy of an ECC storage key at `0x81000100`, with no object loaded at
/// `0x80000000`.
fn persistent_key_and_free_slot() -> Tpm {
    let mut tpm = Tpm::new();
    let key = create_ecc_parent_key(&mut tpm);
    assert_eq!(key, Handle(0x8000_0000));
    evict_control(&mut tpm, Handle(0x4000_0001), key, Handle(0x8100_0100)).unwrap();
    flush_context(&mut tpm, key).unwrap();
    tpm
}

/// TPM2_Duplicate(persistent, 0x80000000) with nothing loaded at 0x80000000 reports the unloaded
/// second handle (TPM_RC_REFERENCE_H1), although the persistent object's RAM copy may occupy
/// that slot during the command.
#[test]
fn duplicate_with_unloaded_new_parent_is_reference_error() {
    let mut tpm = persistent_key_and_free_slot();
    // encryptionKeyIn (empty), symmetricAlg TPM_ALG_NULL.
    let cmd = build_raw_cmd(
        ST_SESSIONS,
        0x14B,
        &[0x8100_0100, 0x8000_0000],
        Some(PW_SESSION),
        &[0, 0, 0x00, 0x10],
    );
    assert_eq!(mssim_rc_of(&mut tpm, &cmd), RC_REFERENCE_H1);
}

/// TPM2_ObjectChangeAuth(persistent, 0x80000000) with nothing loaded at 0x80000000 is
/// TPM_RC_REFERENCE_H1.
#[test]
fn object_change_auth_with_unloaded_parent_is_reference_error() {
    let mut tpm = persistent_key_and_free_slot();
    let cmd = build_raw_cmd(
        ST_SESSIONS,
        0x150,
        &[0x8100_0100, 0x8000_0000],
        Some(PW_SESSION),
        &[0, 0],
    );
    assert_eq!(mssim_rc_of(&mut tpm, &cmd), RC_REFERENCE_H1);
}
