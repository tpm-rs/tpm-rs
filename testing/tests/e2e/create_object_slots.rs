//! TPM2_Create and object slots: the command needs a free object slot as scratch memory for the
//! new object (TPM 2.0 Part 3, "Response Code Details", TPM_RC_OBJECT_MEMORY: "the TPM
//! implementation is allowed to use object slots for other reasons"), as in the reference
//! (`TPM2_Create()`: `FindEmptyObjectSlot(NULL)`, else TPM_RC_OBJECT_MEMORY), including the slot a
//! persistent parent occupies in RAM for the duration of the command.

use crate::_common::{
    create, create_ecc_parent_key, evict_control, flush_context, get_ecc_signing_key_template,
};
use testing::tpm::Tpm;
use tpm2::Handle;

/// `TPM_RC_OBJECT_MEMORY`.
const RC_OBJECT_MEMORY: u32 = 0x902;
/// `TPM_RH_OWNER`.
const OWNER: Handle = Handle(0x4000_0001);

/// With every object slot occupied by loaded objects, TPM2_Create has no scratch slot and fails
/// with TPM_RC_OBJECT_MEMORY; after a flush it succeeds.
#[test]
fn create_without_a_free_slot_returns_object_memory() {
    let mut tpm = Tpm::new();
    let parent = create_ecc_parent_key(&mut tpm);
    let second = create_ecc_parent_key(&mut tpm);
    let third = create_ecc_parent_key(&mut tpm);
    assert_eq!(
        create(&mut tpm, parent, get_ecc_signing_key_template(), b"", b"").err(),
        Some(RC_OBJECT_MEMORY)
    );
    flush_context(&mut tpm, third).unwrap();
    create(&mut tpm, parent, get_ecc_signing_key_template(), b"", b"").unwrap();
    let _ = second;
}

/// A persistent parent is copied into an object slot for the duration of the command, so with
/// two loaded objects TPM2_Create under a persistent parent has no scratch slot left
/// (TPM_RC_OBJECT_MEMORY), while TPM2_Create under a loaded (transient) parent still succeeds.
#[test]
fn create_under_persistent_parent_needs_two_free_slots() {
    let mut tpm = Tpm::new();
    let parent = create_ecc_parent_key(&mut tpm);
    let persistent = Handle(0x8100_0101);
    evict_control(&mut tpm, OWNER, parent, persistent).unwrap();
    let _other = create_ecc_parent_key(&mut tpm);
    create(&mut tpm, parent, get_ecc_signing_key_template(), b"", b"").unwrap();
    assert_eq!(
        create(
            &mut tpm,
            persistent,
            get_ecc_signing_key_template(),
            b"",
            b""
        )
        .err(),
        Some(RC_OBJECT_MEMORY)
    );
    flush_context(&mut tpm, parent).unwrap();
    create(
        &mut tpm,
        persistent,
        get_ecc_signing_key_template(),
        b"",
        b"",
    )
    .unwrap();
    evict_control(&mut tpm, OWNER, persistent, persistent).unwrap();
}
