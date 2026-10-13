//! Encoding of sensitive areas and private blobs: seed sizes and authValue padding.

use crate::_common::*;
use tpm2::*;
use tpm2_simulator::create_simulator;

/// TPM2B_PRIVATE layout (encrypted sensitive size and auth padding) round-trips (delegates to crypto_blobs helper).
///
/// tpm2b-private-encrypted-sensitive-size-and-auth-padding-bug
#[test]
fn private_area_format_round_trip() {
    crate::_common::private_area_format_round_trip();
}

/// A SHA-512 KEYEDHASH object keeps its 64-byte seed; MarshalSensitive pads empty authValue to the digest size.
///
/// parent-seed-truncation-trailing-zero-strip-and-stclear-omission
#[test]
fn sha512_keyedhash_seed_and_auth_padding() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    // A SHA-512 KEYEDHASH object: its 64-byte seedValue must survive creation and loading.
    let mut t = sealed_template(TpmiAlgHash::Sha512, TpmaObject::empty());
    t.auth_policy = dup_policy_digest_for(TpmiAlgHash::Sha512);
    let (obj, rsp) = create_and_load(&mut sim, srk, t, &[], b"data");
    let dup = duplicate_with_policy(&mut sim, obj, TpmiAlgHash::Sha512);
    let sensitive = parse_plain_duplicate(dup.duplicate.get_buffer());
    assert_eq!(sensitive.seed_value.get_size(), 64, "seedValue truncated");
    let unique = match rsp.out_public.0.parms_and_id {
        PublicParmsAndId::KeyedHash(_, u) => u.get_buffer().to_vec(),
        _ => unreachable!(),
    };
    assert_eq!(
        hash_parts(
            TpmiAlgHash::Sha512,
            &[sensitive.seed_value.get_buffer(), b"data"]
        ),
        unique
    );
    // MarshalSensitive pads the (empty) authValue to the nameAlg digest size.
    assert_eq!(sensitive.auth_value.get_size(), 64);
}

/// A SHA-384 SYMCIPHER key keeps its 48-byte seedValue; non-parent asymmetric keys drop it (checked via plain Duplicate).
///
/// transient-object-seed-truncation-to-32-bytes-and-zero-stripping
#[test]
fn symcipher_seed_kept_and_asymmetric_seed_dropped() {
    let mut sim = create_simulator!();
    let srk = owner_srk(&mut sim);
    // SHA-384 SYMCIPHER key: its 48-byte seedValue must be kept in full.
    let mut t = sym_template_with(TpmiAlgHash::Sha384, TpmaObject::empty());
    t.auth_policy = dup_policy_digest_for(TpmiAlgHash::Sha384);
    let (obj, rsp) = create_and_load(&mut sim, srk, t, b"pw", &[]);
    let dup = duplicate_with_policy(&mut sim, obj, TpmiAlgHash::Sha384);
    let sensitive = parse_plain_duplicate(dup.duplicate.get_buffer());
    assert_eq!(sensitive.seed_value.get_size(), 48, "seedValue truncated");
    let key = match sensitive.sensitive {
        TpmuSensitiveComposite::Sym(k) => k.get_buffer().to_vec(),
        _ => panic!("not a symmetric key"),
    };
    let unique = match rsp.out_public.0.parms_and_id {
        PublicParmsAndId::Sym(_, u) => u.get_buffer().to_vec(),
        _ => unreachable!(),
    };
    assert_eq!(
        hash_parts(
            TpmiAlgHash::Sha384,
            &[sensitive.seed_value.get_buffer(), &key]
        ),
        unique
    );

    // C CryptCreateObject drops the seedValue of non-parent asymmetric keys.
    let (signer, _) = create_and_load(
        &mut sim,
        srk,
        duplicable_sign_template(TpmiAlgHash::Sha256),
        &[],
        &[],
    );
    let dup = duplicate(&mut sim, signer, Handle::RH_NULL, None).unwrap();
    assert_eq!(
        parse_plain_duplicate(dup.duplicate.get_buffer())
            .seed_value
            .get_size(),
        0
    );
}
