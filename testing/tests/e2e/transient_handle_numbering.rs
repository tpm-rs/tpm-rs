//! Handles of objects created by a command that references a persistent object.
//!
//! The values of transient handles are implementation-specific (TPM 2.0 Part 1, "Transient
//! Object Handles": "The TPM assigns Object handles when an Object is loaded"); `tpm-rs` numbers
//! them like the TCG reference, where each persistent object referenced by the command occupies
//! the lowest free object slot for the duration of the command (`ObjectLoadEvict`), so the new
//! object gets the next free one. `TPM2_GetCapability(TPM_CAP_HANDLES)` then lists the same
//! handles in every implementation.

use crate::_common::{
    create, create_ecc_parent_key, create_primary_handle, ecc_sign_template, evict_control,
    execute_with_password_sessions, flush_context, hmac_key_template, load, loaded_handles,
};
use testing::tpm::Tpm;
use tpm2::commands::HMACStart;
use tpm2::{Handle, Tpm2bAuth, TpmaObject, TpmiAlgHash};

/// The owner persistent handle the tests use.
const PERSISTENT: Handle = Handle(0x8100_0100);

/// `TPM2_HMAC_Start` with the persistent key `key`; returns the sequence handle.
fn hmac_start(tpm: &mut Tpm, key: Handle) -> Handle {
    let cmd = HMACStart {
        handle: key,
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    execute_with_password_sessions(tpm, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("TPM2_HMAC_Start failed: {rc:#x}"))
        .sequence_handle
}

/// An HMAC key made persistent at [`PERSISTENT`]; its transient copy stays loaded at
/// `0x80000000` unless `flush` is set.
fn persistent_hmac_key(tpm: &mut Tpm, flush: bool) {
    let key = create_primary_handle(tpm, hmac_key_template(TpmiAlgHash::Sha256));
    assert_eq!(key, Handle(0x8000_0000));
    evict_control(tpm, Handle::RH_OWNER, key, PERSISTENT).unwrap();
    if flush {
        flush_context(tpm, key).unwrap();
    }
}

/// With nothing else loaded, the persistent key's copy takes `0x80000000` during
/// `TPM2_HMAC_Start`, so the sequence gets `0x80000001`.
#[test]
fn hmac_sequence_of_persistent_key_skips_the_copy_slot() {
    let mut tpm = Tpm::new();
    persistent_hmac_key(&mut tpm, true);
    let sequence = hmac_start(&mut tpm, PERSISTENT);
    assert_eq!(sequence, Handle(0x8000_0001));
    assert_eq!(loaded_handles(&mut tpm, 0x8000_0000), [0x8000_0001]);
}

/// With the transient key still at `0x80000000`, the copy takes `0x80000001` and the sequence
/// `0x80000002`; GetCapability(TPM_CAP_HANDLES) starting at the sequence lists only it.
#[test]
fn hmac_sequence_after_loaded_object_and_copy_slot() {
    let mut tpm = Tpm::new();
    persistent_hmac_key(&mut tpm, false);
    let sequence = hmac_start(&mut tpm, PERSISTENT);
    assert_eq!(sequence, Handle(0x8000_0002));
    assert_eq!(
        loaded_handles(&mut tpm, 0x8000_0000),
        [0x8000_0000, 0x8000_0002]
    );
    assert_eq!(loaded_handles(&mut tpm, 0x8000_0001), [0x8000_0002]);
    // Once the slot of the copy is free again, it is used by the next object.
    flush_context(&mut tpm, Handle(0x8000_0000)).unwrap();
    let next = hmac_start(&mut tpm, PERSISTENT);
    assert_eq!(next, Handle(0x8000_0001));
}

/// `TPM2_Load` under a persistent parent: the parent's copy takes the lowest free slot, so the
/// child gets the next one, and the copy's slot is free again after the command.
#[test]
fn child_of_persistent_parent_skips_the_copy_slot() {
    let mut tpm = Tpm::new();
    let parent = create_ecc_parent_key(&mut tpm);
    assert_eq!(parent, Handle(0x8000_0000));
    evict_control(&mut tpm, Handle::RH_OWNER, parent, PERSISTENT).unwrap();
    flush_context(&mut tpm, parent).unwrap();

    let template = ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    let child = create(&mut tpm, PERSISTENT, template, b"", b"").unwrap();
    let first = load(&mut tpm, PERSISTENT, child.out_private, child.out_public).unwrap();
    assert_eq!(first, Handle(0x8000_0001));
    // `0x80000000` is free again; the copy takes it, so the second child gets `0x80000002`.
    let second = load(&mut tpm, PERSISTENT, child.out_private, child.out_public).unwrap();
    assert_eq!(second, Handle(0x8000_0002));
    assert_eq!(
        loaded_handles(&mut tpm, 0x8000_0000),
        [0x8000_0001, 0x8000_0002]
    );
}
