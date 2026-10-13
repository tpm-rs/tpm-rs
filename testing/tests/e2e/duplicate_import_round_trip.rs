//! Duplicate -> Import -> Load round trips over key types, name algorithms and wrapper algorithms.

use crate::_common::{
    AES128_CFB, AES256_CFB, create_srk, create_unwrap, dup_import_load, dup_policy, dup_sign_attrs,
    ecc_public_with_policy, flush_context, load_with_name, rsa_dup_target, rsa_public,
    storage_attrs, try_create_owner_primary,
};
use testing::tpm::Tpm;
use tpm2::commands::responses::Create as CreateRsp;
use tpm2::{TpmEccCurve, TpmaObject, TpmiAlgHash};

/// Duplicate -> Import -> Load over parent/target nameAlgs, inner wrappers and parent symmetric algorithms.
///
/// Duplicate → Import → Load round trips over parent nameAlgs, target
/// nameAlgs, inner wrapper algorithms and parent symmetric algorithms.
///
/// The white-box original also covered storage parents with a NULL symmetric
/// algorithm, which cannot be created through the command interface; AES-256
/// parents are covered instead.
#[test]
fn hash_and_symmetric_algorithm_matrix() {
    let mut sim = Tpm::new();
    let srk = create_srk(&mut sim);

    let hash_algos = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
    ];
    let sym_algos = [None, Some(AES128_CFB), Some(AES256_CFB)];

    // Target signing keys (created once; loaded under the SRK for every combination).
    let targets: Vec<(TpmiAlgHash, CreateRsp<'static>)> = [TpmiAlgHash::Sha1, TpmiAlgHash::Sha256]
        .into_iter()
        .map(|h| {
            (
                h,
                create_unwrap(&mut sim, srk, rsa_dup_target(h, TpmaObject::empty()), &[]),
            )
        })
        .collect();

    for &parent_hash in &hash_algos {
        for parent_sym in [AES128_CFB, AES256_CFB] {
            // 1. A parent storage key with parent_hash and parent_sym
            let (parent, _) = try_create_owner_primary(
                &mut sim,
                rsa_public(parent_hash, storage_attrs(), &[], Some(parent_sym)),
            )
            .unwrap();

            for (target_hash, target) in &targets {
                // 2. Load the target signing key with target_hash
                let (target_handle, target_name) =
                    load_with_name(&mut sim, srk, target.out_private, target.out_public).unwrap();

                for &sym_alg in &sym_algos {
                    // 3-5. Duplicate, Import and Load
                    dup_import_load(
                        &mut sim,
                        target_handle,
                        target.out_public,
                        &target_name,
                        *target_hash,
                        parent,
                        sym_alg,
                        &format!(
                            "parent_hash={parent_hash:?}, parent_sym={parent_sym:?}, \
                             target_hash={target_hash:?}, sym_alg={sym_alg:?}"
                        ),
                    );
                }
                flush_context(&mut sim, target_handle).unwrap();
            }
            flush_context(&mut sim, parent).unwrap();
        }
    }
}

/// Duplicate -> Import -> Load over RSA / P-256 / BN P-256 parents (all nameAlgs) and RSA / ECC targets.
///
/// Duplicate → Import → Load round trips over RSA / NIST P-256 / BN P-256
/// storage parents (with every parent nameAlg) and RSA / ECC targets.
#[test]
fn parent_and_target_key_type_matrix() {
    let mut sim = Tpm::new();
    let srk = create_srk(&mut sim);

    #[derive(Clone, Copy, Debug)]
    enum KeyGenType {
        Rsa,
        Ecc(TpmEccCurve),
    }

    let parent_types = [
        KeyGenType::Rsa,
        KeyGenType::Ecc(TpmEccCurve::NistP256),
        KeyGenType::Ecc(TpmEccCurve::BNP256),
    ];
    let hash_algos = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
    ];

    // Target signing keys (created once; loaded under the SRK for every combination).
    let targets = [
        (
            KeyGenType::Rsa,
            create_unwrap(
                &mut sim,
                srk,
                rsa_dup_target(TpmiAlgHash::Sha256, TpmaObject::empty()),
                &[],
            ),
        ),
        (
            KeyGenType::Ecc(TpmEccCurve::NistP256),
            create_unwrap(
                &mut sim,
                srk,
                ecc_public_with_policy(
                    TpmiAlgHash::Sha256,
                    dup_sign_attrs(TpmaObject::empty()),
                    dup_policy(TpmiAlgHash::Sha256),
                    TpmEccCurve::NistP256,
                    None,
                ),
                &[],
            ),
        ),
    ];

    for &parent_type in &parent_types {
        for &parent_hash in &hash_algos {
            // 1. Create parent storage key
            let parent_public = match parent_type {
                KeyGenType::Rsa => rsa_public(parent_hash, storage_attrs(), &[], Some(AES128_CFB)),
                KeyGenType::Ecc(curve) => ecc_public_with_policy(
                    parent_hash,
                    storage_attrs(),
                    &[],
                    curve,
                    Some(AES128_CFB),
                ),
            };
            let (parent, _) =
                try_create_owner_primary(&mut sim, parent_public).unwrap_or_else(|e| {
                    panic!("CreatePrimary failed for parent_type={parent_type:?}, error={e:08X}")
                });

            for (target_type, target) in &targets {
                // 2. Load target signing key
                let (target_handle, target_name) =
                    load_with_name(&mut sim, srk, target.out_private, target.out_public).unwrap();

                // 3-5. Duplicate, Import and Load
                dup_import_load(
                    &mut sim,
                    target_handle,
                    target.out_public,
                    &target_name,
                    TpmiAlgHash::Sha256,
                    parent,
                    None,
                    &format!(
                        "parent_type={parent_type:?}, target_type={target_type:?}, \
                         parent_hash={parent_hash:?}"
                    ),
                );
                flush_context(&mut sim, target_handle).unwrap();
            }
            flush_context(&mut sim, parent).unwrap();
        }
    }
}

/// Duplicate -> Import -> Load round trip of an RSA signing key under an RSA storage parent.
///
/// Duplicate → Import → Load round trip of an RSA signing key under an RSA
/// storage parent.
#[test]
fn rsa_signing_key_round_trip() {
    let mut sim = Tpm::new();

    // 1. A valid storage key (parent)
    let parent = create_srk(&mut sim);

    // 2. A target signing key
    let target = create_unwrap(
        &mut sim,
        parent,
        rsa_dup_target(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    );
    let (target_handle, target_name) =
        load_with_name(&mut sim, parent, target.out_private, target.out_public).unwrap();

    // 3-5. Duplicate, Import and Load
    dup_import_load(
        &mut sim,
        target_handle,
        target.out_public,
        &target_name,
        TpmiAlgHash::Sha256,
        parent,
        None,
        "integration flow",
    );
}
