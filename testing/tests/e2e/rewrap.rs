//! TPM2_Rewrap: re-wrapping duplication blobs between parents and blob validation.

use crate::_common::*;
use tpm2::commands::Rewrap;
use tpm2::errors::TpmRc;
use tpm2::{Handle, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bPrivate, *};
use tpm2_simulator::create_simulator;

/// Rewrap to an ECC/NULL parent produces a fresh seed that imports and loads; max-size unwrapped duplicate is VALUE+P1.
///
/// tpm2-rewrap-reuses-old-protection-seed-instead
#[test]
fn fresh_seed_for_new_parent() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let ecc_parent = try_create_primary_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    )
    .unwrap()
    .0;
    let (obj, obj_rsp) = create_and_load(
        &mut sim,
        srk,
        duplicable_sign_template(TpmiAlgHash::Sha256),
        &[],
        &[],
    );
    let name = read_public(&mut sim, obj).unwrap().name;

    // Unwrapped duplicate -> Rewrap to an ECC parent (fresh ECDH seed) -> Import -> Load.
    let dup = duplicate(&mut sim, obj, Handle::RH_NULL, None).unwrap();
    let wrapped = rewrap(
        &mut sim,
        Handle::RH_NULL,
        ecc_parent,
        dup.duplicate,
        name,
        Tpm2bEncryptedSecret::default(),
    )
    .expect("Rewrap to an ECC parent");
    assert!(wrapped.out_sym_seed.get_size() > 0);
    let private = import(
        &mut sim,
        ecc_parent,
        obj_rsp.out_public,
        wrapped.out_duplicate,
        wrapped.out_sym_seed,
    )
    .expect("Import of a rewrapped duplicate");
    load(&mut sim, ecc_parent, private, obj_rsp.out_public).unwrap();

    // ECC old parent: unwrap and wrap again to a NULL parent.
    let back = rewrap(
        &mut sim,
        ecc_parent,
        Handle::RH_NULL,
        wrapped.out_duplicate,
        name,
        wrapped.out_sym_seed,
    )
    .expect("Rewrap from an ECC parent");
    assert_eq!(back.out_duplicate.get_buffer(), dup.duplicate.get_buffer());

    // A maximum-size unwrapped duplicate can not get an outer wrapper: VALUE + RC_P1 (no panic).
    let big = vec![0x42u8; Tpm2bPrivate::CAP];
    assert_eq!(
        rewrap(
            &mut sim,
            Handle::RH_NULL,
            ecc_parent,
            Tpm2bPrivate::from_bytes(leak_bytes(&big)).unwrap(),
            name,
            Tpm2bEncryptedSecret::default(),
        )
        .unwrap_err(),
        rc_p(TpmRc::VALUE, 1)
    );
}

/// Rewrap reports truncated (INSUFFICIENT), corrupted (INTEGRITY) and overflowing (VALUE) inDuplicate at RC_P1.
///
/// tpm2-rewrap-unwrap-outer-and-overflow-missing-rc-p1-error-positions
#[test]
fn malformed_duplicate_error_positions() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    let parent = try_create_primary_in(
        &mut sim,
        Handle::RH_OWNER,
        rsa_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    )
    .unwrap()
    .0;
    let (obj, _) = create_and_load(
        &mut sim,
        srk,
        duplicable_sign_template(TpmiAlgHash::Sha256),
        &[],
        &[],
    );
    let name = read_public(&mut sim, obj).unwrap().name;
    let dup = duplicate(&mut sim, obj, parent, None).unwrap();

    // Truncated inDuplicate -> INSUFFICIENT + RC_P1.
    assert_eq!(
        rewrap(
            &mut sim,
            parent,
            Handle::RH_NULL,
            Tpm2bPrivate::from_bytes(&[0]).unwrap(),
            name,
            dup.out_sym_seed,
        )
        .unwrap_err(),
        rc_p(TpmRc::INSUFFICIENT, 1)
    );
    // Corrupted integrity -> INTEGRITY + RC_P1.
    let mut blob = dup.duplicate.get_buffer().to_vec();
    blob[3] ^= 1;
    assert_eq!(
        rewrap(
            &mut sim,
            parent,
            Handle::RH_NULL,
            Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
            name,
            dup.out_sym_seed,
        )
        .unwrap_err(),
        rc_p(TpmRc::INTEGRITY, 1)
    );
    // Output overflow -> VALUE + RC_P1.
    let big = vec![0x42u8; Tpm2bPrivate::CAP];
    assert_eq!(
        rewrap(
            &mut sim,
            Handle::RH_NULL,
            parent,
            Tpm2bPrivate::from_bytes(leak_bytes(&big)).unwrap(),
            name,
            Tpm2bEncryptedSecret::default(),
        )
        .unwrap_err(),
        rc_p(TpmRc::VALUE, 1)
    );
}

/// Rewrap with NULL old and new parents returns the input blob and an empty seed.
#[test]
fn null_parents_pass_blob_through() {
    let mut sim = create_simulator!();

    let test_blob = [1, 2, 3, 4, 5, 6, 7, 8];
    let cmd = Rewrap {
        old_parent: Handle::RH_NULL,
        new_parent: Handle::RH_NULL,
        in_duplicate: Tpm2bPrivate::from_bytes(&test_blob).unwrap(),
        name: Tpm2bName::default(),
        in_sym_seed: Tpm2bEncryptedSecret::default(),
    };

    let resp = execute_with_password_sessions(&mut sim, &cmd, 1, &[])
        .expect("Rewrap with null parents failed");

    assert_eq!(resp.out_duplicate.get_buffer(), &test_blob);
    assert_eq!(resp.out_sym_seed.get_size(), 0);
}

/// Rewrap with a non-empty inSymSeed and NULL oldParent fails.
#[test]
fn seed_with_null_old_parent_rejected() {
    let mut sim = create_simulator!();

    // Non-empty in_sym_seed with RHNull old_parent must return handle error
    let cmd = Rewrap {
        old_parent: Handle::RH_NULL,
        new_parent: Handle::RH_NULL,
        in_duplicate: Tpm2bPrivate::default(),
        name: Tpm2bName::default(),
        in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&[1u8; 16]).unwrap(),
    };

    let err = execute_with_password_sessions(&mut sim, &cmd, 1, &[])
        .map(|_| ())
        .expect_err("Rewrap should fail when in_sym_seed is non-empty for null old_parent");

    assert_ne!(err, 0);
}
