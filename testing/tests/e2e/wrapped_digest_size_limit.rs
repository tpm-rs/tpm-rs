//! The integrity digests that `TPM2_Load`, `TPM2_Import` and `TPM2_Rewrap` unmarshal from a
//! private or duplicated blob (`integrityOuter`, and `integrityInner` of an inner wrapper) are
//! `TPM2B_DIGEST`s: TPM 2.0 Part 2, Table "Definition of TPM2B_DIGEST Structure", "buffer\[size\]
//! {:sizeof(TPMU_HA)}", so a *size* larger than the largest implemented digest (64 octets, or
//! 48 without SHA-512) is `TPM_RC_SIZE` ("the value of a size parameter is larger or smaller than
//! allowed", Part 2, "Unmarshaling Errors"), even if fewer octets follow (the limit is on the
//! *size* field, before the buffer octets are needed: `TPM_RC_INSUFFICIENT` only for a *size*
//! within the limit). Regression: the limit was 64 octets in every build, so without SHA-512 a
//! *size* of 49 to 64 octets was `TPM_RC_INSUFFICIENT` or reached the integrity check.

use crate::_common::{
    AES128_CFB, STRONGEST_DIGEST_SIZE, STRONGEST_HASH_ALG, command_rc, create, create_and_load,
    duplicable_sign_template, duplicate_alg, import, leak_bytes, load, owner_srk, rc_p,
    read_public, rewrap, rsa_storage_template_with, try_create_primary_in,
};
use testing::tpm::Tpm;
use tpm2::commands::Import;
use tpm2::errors::TpmRc;
use tpm2::{Handle, Tpm2bData, Tpm2bEncryptedSecret, Tpm2bPrivate, TpmaObject, TpmiAlgHash};

/// A blob that starts with a `TPM2B_DIGEST` of `size` octets followed by `following` octets.
fn digest_prefixed(size: usize, following: usize) -> Vec<u8> {
    let mut blob = (size as u16).to_be_bytes().to_vec();
    blob.resize(2 + following, 0x5A);
    blob
}

/// An outer-wrapped duplicate setup: a storage parent (SHA-256), a duplicable key (with the
/// strongest hash as nameAlg) and its duplicate for that parent (whose `outSymSeed` is valid).
struct Duplicated {
    parent: Handle,
    object_public: tpm2::Tpm2bPublic<'static>,
    name: tpm2::Tpm2bName<'static>,
    seed: Tpm2bEncryptedSecret<'static>,
}

fn duplicated(sim: &mut Tpm) -> Duplicated {
    let srk = owner_srk(sim);
    let parent = try_create_primary_in(
        sim,
        Handle::RH_OWNER,
        rsa_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    )
    .unwrap()
    .0;
    let (obj, obj_rsp) = create_and_load(
        sim,
        srk,
        duplicable_sign_template(STRONGEST_HASH_ALG),
        &[],
        &[],
    );
    let name = read_public(sim, obj).unwrap().name;
    let dup = duplicate_alg(sim, obj, parent, None, STRONGEST_HASH_ALG).unwrap();
    Duplicated {
        parent,
        object_public: obj_rsp.out_public,
        name,
        seed: dup.out_sym_seed,
    }
}

/// `TPM2_Load`: an `integrityOuter` *size* one octet above the largest digest is
/// `TPM_RC_SIZE + RC_Load_inPrivate`, whether or not that many octets follow; at the limit, the
/// digest is unmarshaled and fails the integrity check.
#[test]
fn load_outer_integrity_larger_than_largest_digest_is_size_error() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let key = create(
        &mut sim,
        srk,
        rsa_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    )
    .expect("Create");
    let load_rc = |sim: &mut Tpm, blob: Vec<u8>| {
        load(
            sim,
            srk,
            Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
            key.out_public,
        )
        .unwrap_err()
    };
    for following in [8, STRONGEST_DIGEST_SIZE + 1 + 32] {
        assert_eq!(
            load_rc(
                &mut sim,
                digest_prefixed(STRONGEST_DIGEST_SIZE + 1, following)
            ),
            rc_p(TpmRc::SIZE, 1),
            "size {} with {following} octets following",
            STRONGEST_DIGEST_SIZE + 1
        );
    }
    assert_eq!(
        load_rc(
            &mut sim,
            digest_prefixed(STRONGEST_DIGEST_SIZE, STRONGEST_DIGEST_SIZE + 32)
        ),
        rc_p(TpmRc::INTEGRITY, 1)
    );
}

/// `TPM2_Import`: an outer wrapper's `integrityOuter` *size* one octet above the largest digest
/// is `TPM_RC_SIZE + RC_Import_duplicate`, whether or not that many octets follow.
#[test]
fn import_outer_integrity_larger_than_largest_digest_is_size_error() {
    let mut sim = Tpm::new();
    let dup = duplicated(&mut sim);
    for following in [8, STRONGEST_DIGEST_SIZE + 1 + 32] {
        let blob = digest_prefixed(STRONGEST_DIGEST_SIZE + 1, following);
        assert_eq!(
            import(
                &mut sim,
                dup.parent,
                dup.object_public,
                Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
                dup.seed,
            )
            .unwrap_err(),
            rc_p(TpmRc::SIZE, 3),
            "{following} octets following"
        );
    }
}

/// `TPM2_Import`: an inner wrapper's `integrityInner` *size* one octet above the largest digest
/// is `TPM_RC_SIZE + RC_Import_duplicate`, whether or not that many octets follow; at the limit,
/// the digest is unmarshaled and fails the integrity check.
#[test]
fn import_inner_integrity_larger_than_largest_digest_is_size_error() {
    let mut sim = Tpm::new();
    let dup = duplicated(&mut sim);
    let key = [0x24u8; 16];
    let inner_import = |sim: &mut Tpm, plain: Vec<u8>| {
        let mut blob = plain;
        crate::_common::aes128_cfb_zero_iv_encrypt(&key, &mut blob);
        command_rc(
            sim,
            &Import {
                parent_handle: dup.parent,
                encryption_key: Tpm2bData::from_bytes(leak_bytes(&key)).unwrap(),
                object_public: dup.object_public,
                duplicate: Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
                in_sym_seed: Tpm2bEncryptedSecret::default(),
                symmetric_alg: Some(AES128_CFB),
            },
            1,
        )
    };
    for following in [8, STRONGEST_DIGEST_SIZE + 1 + 32] {
        assert_eq!(
            inner_import(
                &mut sim,
                digest_prefixed(STRONGEST_DIGEST_SIZE + 1, following)
            ),
            rc_p(TpmRc::SIZE, 3),
            "{following} octets following"
        );
    }
    assert_eq!(
        inner_import(
            &mut sim,
            digest_prefixed(STRONGEST_DIGEST_SIZE, STRONGEST_DIGEST_SIZE + 8)
        ),
        rc_p(TpmRc::INTEGRITY, 3)
    );
}

/// `TPM2_Rewrap`: an `integrityOuter` *size* of `inDuplicate` one octet above the largest digest
/// is `TPM_RC_SIZE + RC_Rewrap_inDuplicate`, whether or not that many octets follow.
#[test]
fn rewrap_outer_integrity_larger_than_largest_digest_is_size_error() {
    let mut sim = Tpm::new();
    let dup = duplicated(&mut sim);
    for following in [8, STRONGEST_DIGEST_SIZE + 1 + 32] {
        let blob = digest_prefixed(STRONGEST_DIGEST_SIZE + 1, following);
        assert_eq!(
            rewrap(
                &mut sim,
                dup.parent,
                Handle::RH_NULL,
                Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
                dup.name,
                dup.seed,
            )
            .unwrap_err(),
            rc_p(TpmRc::SIZE, 1),
            "{following} octets following"
        );
    }
}
