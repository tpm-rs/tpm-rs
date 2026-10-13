//! Sequence object handles are rejected by commands that need a regular object.

use crate::_common::*;
use tpm2::commands::*;
use tpm2::errors::TpmRc;
use tpm2::*;
use tpm2_simulator::{SimulatorPlatformSignal, create_simulator};

/// EvictControl (ATTRIBUTES+H2), ObjectChangeAuth and CreateLoaded (TYPE+H1) reject sequence objects.
///
/// sequence-object-handle-validation-and-error-code-discrepancies
#[test]
#[allow(deprecated)]
fn evict_change_auth_create_loaded_reject_sequence_handles() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let seq = hash_sequence_start(&mut sim);

    // EvictControl: sequence objects are temporary -> ATTRIBUTES + RC_H2.
    assert_eq!(
        evict_control(&mut sim, Handle::RH_OWNER, seq, Handle(0x8100_0100)).unwrap_err(),
        rc_h(TpmRc::ATTRIBUTES, 2)
    );

    // ObjectChangeAuth on a sequence object -> TYPE + RC_H1.
    let rc = command_rc(
        &mut sim,
        &ObjectChangeAuth {
            object_handle: seq,
            parent_handle: srk,
            new_auth: Tpm2bAuth::default(),
        },
        1,
    );
    assert_eq!(rc, rc_h(TpmRc::TYPE, 1));

    // CreateLoaded with a sequence parent -> TYPE + RC_H1 (not REFERENCE_H0).
    let rc = command_rc(
        &mut sim,
        &CreateLoaded {
            parent_handle: seq,
            in_sensitive: sensitive_create(&[], &[]),
            in_public: make_template(&ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty())),
        },
        1,
    );
    assert_eq!(rc, rc_h(TpmRc::TYPE, 1));
}

/// Load with a sequence parent fails; EvictControl checks NV availability before persisting anything.
///
/// sequence-object-handle-resolution-and-evictcontrol-external-object-bugs
#[test]
fn load_under_sequence_parent_and_evict_without_nv() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let seq = hash_sequence_start(&mut sim);

    assert_eq!(
        read_public(&mut sim, seq).unwrap_err(),
        rc0(TpmRc::SEQUENCE)
    );
    assert_eq!(
        evict_control(&mut sim, Handle::RH_OWNER, seq, Handle(0x8100_0101)).unwrap_err(),
        rc_h(TpmRc::ATTRIBUTES, 2)
    );
    // Load with a sequence parent.
    let child = create(
        &mut sim,
        srk,
        sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        b"x",
    )
    .unwrap();
    assert_eq!(
        load(&mut sim, seq, child.out_private, child.out_public).unwrap_err(),
        rc_h(TpmRc::TYPE, 1)
    );

    // EvictControl must check NV availability before it mutates NV.
    let (obj, _) = create_and_load(
        &mut sim,
        srk,
        ecc_sign_template(
            TpmiAlgHash::Sha256,
            TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
        ),
        &[],
        &[],
    );
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(
        evict_control(&mut sim, Handle::RH_OWNER, obj, Handle(0x8100_0102)).unwrap_err(),
        rc0(TpmRc::NV_UNAVAILABLE)
    );
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    assert!(
        read_public(&mut sim, Handle(0x8100_0102)).is_err(),
        "the object must not have been persisted"
    );
}

/// ReadPublic/Unseal/MakeCredential/ActivateCredential/Create/Load reject sequence handles with the C error codes and positions.
///
/// read-public-and-object-handlers-sequence-handle-error-discrepancies
#[test]
fn object_commands_reject_sequence_handles() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let seq = hash_sequence_start(&mut sim);

    // ReadPublic: sequence -> TPM_RC_SEQUENCE, TPM_RH_NULL -> VALUE + RC_H1.
    assert_eq!(
        read_public(&mut sim, seq).unwrap_err(),
        rc0(TpmRc::SEQUENCE)
    );
    assert_eq!(
        read_public(&mut sim, Handle::RH_NULL).unwrap_err(),
        rc_h(TpmRc::VALUE, 1)
    );

    // Unseal: a sequence object is not a KEYEDHASH object.
    let rc = command_rc(&mut sim, &Unseal { item_handle: seq }, 1);
    assert_eq!(rc, rc_h(TpmRc::TYPE, 1));

    // MakeCredential: a sequence object is not an asymmetric key.
    let rc = command_rc(
        &mut sim,
        &MakeCredential {
            handle: seq,
            credential: Tpm2bDigest::from_bytes(&[1; 16]).unwrap(),
            object_name: Tpm2bName::from_bytes(&[0, 0x0b, 1, 2, 3]).unwrap(),
        },
        0,
    );
    assert_eq!(rc, rc_h(TpmRc::TYPE, 1));

    // ActivateCredential: keyHandle is a sequence object.
    let rc = command_rc(
        &mut sim,
        &ActivateCredential {
            activate_handle: srk,
            key_handle: seq,
            credential_blob: Tpm2bIdObject::default(),
            secret: Tpm2bEncryptedSecret::default(),
        },
        2,
    );
    assert_eq!(rc, rc_h(TpmRc::TYPE, 2));

    // Create / Load: a sequence object is never a parent.
    let rc = create(
        &mut sim,
        seq,
        ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, rc_h(TpmRc::TYPE, 1));
}

/// ReadPublic on a hash sequence handle fails with TPM_RC_SEQUENCE (no public area).
///
/// tpm2-readpublic-returns-tpm-rc-reference-h0
#[test]
fn read_public_rejects_sequence_object() {
    let mut sim = create_simulator!();
    let seq = hash_sequence_start(&mut sim);
    // C ReadPublic.c: a sequence object has no public area.
    assert_eq!(
        read_public(&mut sim, seq).unwrap_err(),
        rc0(TpmRc::SEQUENCE)
    );
}
