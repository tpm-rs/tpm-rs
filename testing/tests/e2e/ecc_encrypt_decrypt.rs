//! TPM2_ECC_Encrypt and TPM2_ECC_Decrypt: Part 1's ECC encryption with KDF2 (checked against a
//! client-side implementation in both directions), the KDF scheme selection and the validation
//! of the key, `C1` and `C3`.

// A build with only one of the two commands does not use every import.
#![cfg_attr(
    not(all(feature = "cc-ecc-encrypt", feature = "cc-ecc-decrypt")),
    allow(unused_imports)
)]

use crate::_common::{
    AES128_CFB, client_ecc_key, create_primary_returning_public, ecc_decrypt_reference,
    ecc_encrypt_reference, ecc_point_bytes, ecc_point_from_bytes, ecc_public,
    execute_with_password_sessions, flush_handle, load_external_ecc_key_on, load_public_only,
    rc_at, rc_bare, rsa_public_with_symmetric, sdo_user,
};
use testing::tpm::Tpm;
use tpm2::commands::{ECCDecrypt, ECCEncrypt};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bDigest, Tpm2bEccPoint, Tpm2bMaxBuffer, TpmEccCurve, TpmaObject,
    TpmiAlgHash, TpmtKdfScheme, TpmtPublic,
};

/// The curves of the default profile.
const CURVES: [TpmEccCurve; 5] = [
    TpmEccCurve::NistP224,
    TpmEccCurve::NistP256,
    TpmEccCurve::NistP384,
    TpmEccCurve::NistP521,
    TpmEccCurve::BNP256,
];

/// An ECC key template on `curve` with attributes `attrs`.
fn key_template(curve: TpmEccCurve, attrs: TpmaObject) -> TpmtPublic<'static> {
    let mut public = ecc_public(attrs, None, None);
    if let PublicParmsAndId::Ecc(parms, _) = &mut public.parms_and_id {
        parms.curve_id = curve;
    }
    public
}

/// The KDF2 scheme with `hash`.
fn kdf2(hash: TpmiAlgHash) -> Option<TpmtKdfScheme> {
    Some(TpmtKdfScheme::Kdf2(hash))
}

/// The output of TPM2_ECC_Encrypt: `(C1, C2, C3)`.
type Ciphertext = (Vec<u8>, Vec<u8>, Vec<u8>);

/// TPM2_ECC_Encrypt; returns `(C1, C2, C3)`.
#[cfg(feature = "cc-ecc-encrypt")]
fn encrypt(
    sim: &mut Tpm,
    key: Handle,
    plain_text: &[u8],
    scheme: Option<TpmtKdfScheme>,
) -> Result<Ciphertext, u32> {
    let plain_text = crate::_common::leak_bytes(plain_text);
    let rsp = execute_with_password_sessions(
        sim,
        &ECCEncrypt {
            key_handle: key,
            plain_text: Tpm2bMaxBuffer::from_bytes(plain_text).unwrap(),
            in_scheme: scheme,
        },
        0,
        &[],
    )?;
    Ok((
        ecc_point_bytes(&rsp.c1.0),
        rsp.c2.get_buffer().to_vec(),
        rsp.c3.get_buffer().to_vec(),
    ))
}

/// TPM2_ECC_Decrypt; returns the plaintext.
#[cfg(feature = "cc-ecc-decrypt")]
fn decrypt(
    sim: &mut Tpm,
    key: Handle,
    c1: Tpm2bEccPoint<'static>,
    c2: &[u8],
    c3: &[u8],
    scheme: Option<TpmtKdfScheme>,
) -> Result<Vec<u8>, u32> {
    let rsp = execute_with_password_sessions(
        sim,
        &ECCDecrypt {
            key_handle: key,
            c1,
            c2: Tpm2bMaxBuffer::from_bytes(crate::_common::leak_bytes(c2)).unwrap(),
            c3: Tpm2bDigest::from_bytes(crate::_common::leak_bytes(c3)).unwrap(),
            in_scheme: scheme,
        },
        1,
        &[],
    )?;
    Ok(rsp.plain_text.get_buffer().to_vec())
}

/// TPM2_ECC_Encrypt follows Part 1 (`C2 := M ⊕ KDF2(x2 || y2)`, `C3 := H(x2 || M || y2)` with
/// `(x2, y2) := [k]P_B`): the client decrypts it with the private key, for several curves,
/// hashes and plaintext lengths (including the empty plaintext).
#[cfg(feature = "cc-ecc-encrypt")]
#[test]
fn encrypt_matches_client_decryption() {
    let mut sim = Tpm::new();
    for curve in [
        TpmEccCurve::NistP224,
        TpmEccCurve::NistP256,
        TpmEccCurve::NistP384,
        TpmEccCurve::NistP521,
    ] {
        let (key, d, _) = load_external_ecc_key_on(
            &mut sim,
            curve,
            TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
            None,
        );
        for (hash, len) in [
            (TpmiAlgHash::Sha256, 0),
            (TpmiAlgHash::Sha256, 1),
            (TpmiAlgHash::Sha384, 33),
            (TpmiAlgHash::Sha1, 100),
            (TpmiAlgHash::Sha256, 1024),
        ] {
            let m: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let (c1, c2, c3) = encrypt(&mut sim, key, &m, kdf2(hash)).unwrap();
            assert_eq!(c2.len(), m.len());
            assert_eq!(c3.len(), hash.digest_size());
            assert_eq!(
                ecc_decrypt_reference(curve, hash, &d, &c1, &c2, &c3),
                Some(m),
                "{curve:?} {hash:?} {len}"
            );
        }
        flush_handle(&mut sim, key);
    }
}

/// TPM2_ECC_Decrypt follows Part 1: it decrypts what the client encrypts for the key's public
/// point, for several curves and hashes.
#[cfg(feature = "cc-ecc-decrypt")]
#[test]
fn decrypt_matches_client_encryption() {
    let mut sim = Tpm::new();
    for curve in [
        TpmEccCurve::NistP224,
        TpmEccCurve::NistP256,
        TpmEccCurve::NistP384,
        TpmEccCurve::NistP521,
    ] {
        let (key, public) = create_primary_returning_public(
            &mut sim,
            key_template(curve, TpmaObject::DECRYPT | sdo_user()),
            &[],
        );
        let PublicParmsAndId::Ecc(_, pb) = public.parms_and_id else {
            unreachable!()
        };
        let pb = ecc_point_bytes(&pb);
        for (hash, len) in [(TpmiAlgHash::Sha256, 0), (TpmiAlgHash::Sha384, 77)] {
            let (k, _) = client_ecc_key(curve);
            let m: Vec<u8> = (0..len).map(|i| i as u8 ^ 0x5A).collect();
            let (c1, c2, c3) = ecc_encrypt_reference(curve, hash, &pb, &k, &m);
            assert_eq!(
                decrypt(
                    &mut sim,
                    key,
                    ecc_point_from_bytes(&c1),
                    &c2,
                    &c3,
                    kdf2(hash)
                ),
                Ok(m),
                "{curve:?} {hash:?}"
            );
        }
        flush_handle(&mut sim, key);
    }
}

/// What TPM2_ECC_Encrypt produces, TPM2_ECC_Decrypt recovers with the same key, on every
/// curve; each encryption uses a new ephemeral key.
#[cfg(all(feature = "cc-ecc-encrypt", feature = "cc-ecc-decrypt"))]
#[test]
fn encrypt_decrypt_round_trip_on_each_curve() {
    let mut sim = Tpm::new();
    for curve in CURVES {
        let (key, _) = create_primary_returning_public(
            &mut sim,
            key_template(curve, TpmaObject::DECRYPT | sdo_user()),
            &[],
        );
        let m = b"ECC encryption round trip";
        let first = encrypt(&mut sim, key, m, kdf2(TpmiAlgHash::Sha256)).unwrap();
        let second = encrypt(&mut sim, key, m, kdf2(TpmiAlgHash::Sha256)).unwrap();
        assert_ne!(first.0, second.0, "{curve:?}");
        let (c1, c2, c3) = first;
        assert_eq!(
            decrypt(
                &mut sim,
                key,
                ecc_point_from_bytes(&c1),
                &c2,
                &c3,
                kdf2(TpmiAlgHash::Sha256)
            ),
            Ok(m.to_vec()),
            "{curve:?}"
        );
        flush_handle(&mut sim, key);
    }
}

/// TPM2_ECC_Encrypt does not check the key's attributes: it works with a signing key and with a
/// public-only key, but a non-ECC key fails with TPM_RC_KEY + H1.
#[cfg(feature = "cc-ecc-encrypt")]
#[test]
fn encrypt_key_requirements() {
    let mut sim = Tpm::new();
    let (signing, public) = create_primary_returning_public(
        &mut sim,
        ecc_public(TpmaObject::SIGN_ENCRYPT | sdo_user(), None, None),
        &[],
    );
    encrypt(&mut sim, signing, b"m", kdf2(TpmiAlgHash::Sha256)).unwrap();
    let public_only = Handle(load_public_only(&mut sim, &public));
    encrypt(&mut sim, public_only, b"m", kdf2(TpmiAlgHash::Sha256)).unwrap();
    let (rsa, _) = create_primary_returning_public(
        &mut sim,
        rsa_public_with_symmetric(TpmaObject::DECRYPT | sdo_user(), None),
        &[],
    );
    assert_eq!(
        encrypt(&mut sim, rsa, b"m", kdf2(TpmiAlgHash::Sha256)),
        Err(rc_at(TpmRc::KEY, Position::handle(1)))
    );
}

/// Only KDF2 is supported: TPM2_ECC_Encrypt with `inScheme` `TPM_ALG_NULL` (and a key whose
/// `kdf` is `TPM_ALG_NULL`), MGF1, KDF1_SP800_56A or KDF1_SP800_108 fails with a bare
/// TPM_RC_SCHEME.
#[cfg(feature = "cc-ecc-encrypt")]
#[test]
fn encrypt_rejects_schemes_other_than_kdf2() {
    let mut sim = Tpm::new();
    let (key, _) = create_primary_returning_public(
        &mut sim,
        ecc_public(TpmaObject::DECRYPT | sdo_user(), None, None),
        &[],
    );
    for scheme in [
        None,
        Some(TpmtKdfScheme::Mgf1(TpmiAlgHash::Sha256)),
        Some(TpmtKdfScheme::Kdf1Sp800_56a(TpmiAlgHash::Sha256)),
        Some(TpmtKdfScheme::Kdf1Sp800_108(TpmiAlgHash::Sha256)),
    ] {
        assert_eq!(
            encrypt(&mut sim, key, b"m", scheme),
            Err(rc_bare(TpmRc::SCHEME)),
            "{scheme:?}"
        );
    }
}

/// TPM2_ECC_Decrypt needs an ECC key (TPM_RC_KEY + H1) with `restricted` CLEAR and `decrypt`
/// SET (TPM_RC_ATTRIBUTES + H1).
#[cfg(feature = "cc-ecc-decrypt")]
#[test]
fn decrypt_rejects_unsuitable_keys() {
    let mut sim = Tpm::new();
    let (rsa, _) = create_primary_returning_public(
        &mut sim,
        rsa_public_with_symmetric(TpmaObject::DECRYPT | sdo_user(), None),
        &[],
    );
    let (restricted, public) = create_primary_returning_public(
        &mut sim,
        ecc_public(
            TpmaObject::DECRYPT | TpmaObject::RESTRICTED | sdo_user(),
            Some(AES128_CFB),
            None,
        ),
        &[],
    );
    let (signing, _) = create_primary_returning_public(
        &mut sim,
        ecc_public(TpmaObject::SIGN_ENCRYPT | sdo_user(), None, None),
        &[],
    );
    let PublicParmsAndId::Ecc(_, point) = public.parms_and_id else {
        unreachable!()
    };
    let c1 = tpm2::Tpm2b(point);
    for (key, rc) in [
        (rsa, TpmRc::KEY),
        (restricted, TpmRc::ATTRIBUTES),
        (signing, TpmRc::ATTRIBUTES),
    ] {
        assert_eq!(
            decrypt(&mut sim, key, c1, b"x", &[0; 32], kdf2(TpmiAlgHash::Sha256)),
            Err(rc_at(rc, Position::handle(1)))
        );
    }
}

/// TPM2_ECC_Decrypt rejects a `C1` that is not on the curve of the key with TPM_RC_ECC_POINT +
/// P1, before the KDF scheme (`TPM_ALG_NULL`: a bare TPM_RC_SCHEME) is checked.
#[cfg(feature = "cc-ecc-decrypt")]
#[test]
fn decrypt_rejects_c1_not_on_curve() {
    let mut sim = Tpm::new();
    let (key, public) = create_primary_returning_public(
        &mut sim,
        ecc_public(TpmaObject::DECRYPT | sdo_user(), None, None),
        &[],
    );
    let PublicParmsAndId::Ecc(_, point) = public.parms_and_id else {
        unreachable!()
    };
    let mut bad = ecc_point_bytes(&point);
    bad[40] ^= 0x01;
    for scheme in [kdf2(TpmiAlgHash::Sha256), None] {
        assert_eq!(
            decrypt(
                &mut sim,
                key,
                ecc_point_from_bytes(&bad),
                b"x",
                &[0; 32],
                scheme
            ),
            Err(rc_at(TpmRc::ECC_POINT, Position::parameter(1))),
            "{scheme:?}"
        );
    }
    // With a valid C1, `TPM_ALG_NULL` is a bare TPM_RC_SCHEME.
    assert_eq!(
        decrypt(&mut sim, key, tpm2::Tpm2b(point), b"x", &[0; 32], None),
        Err(rc_bare(TpmRc::SCHEME))
    );
}

/// TPM2_ECC_Decrypt fails with a bare TPM_RC_VALUE when `C3` does not match the recovered
/// plaintext: a modified `C2`, a modified `C3`, a truncated `C3`, or another hash.
#[cfg(all(feature = "cc-ecc-encrypt", feature = "cc-ecc-decrypt"))]
#[test]
fn decrypt_rejects_integrity_mismatch() {
    let mut sim = Tpm::new();
    let (key, _) = create_primary_returning_public(
        &mut sim,
        ecc_public(TpmaObject::DECRYPT | sdo_user(), None, None),
        &[],
    );
    let (c1, c2, c3) = encrypt(&mut sim, key, b"integrity", kdf2(TpmiAlgHash::Sha256)).unwrap();
    let c1 = ecc_point_from_bytes(&c1);
    let mut bad_c2 = c2.clone();
    bad_c2[0] ^= 1;
    let mut bad_c3 = c3.clone();
    bad_c3[31] ^= 1;
    let value = Err(rc_bare(TpmRc::VALUE));
    let sha256 = kdf2(TpmiAlgHash::Sha256);
    assert_eq!(decrypt(&mut sim, key, c1, &bad_c2, &c3, sha256), value);
    assert_eq!(decrypt(&mut sim, key, c1, &c2, &bad_c3, sha256), value);
    assert_eq!(decrypt(&mut sim, key, c1, &c2, &c3[..31], sha256), value);
    assert_eq!(
        decrypt(&mut sim, key, c1, &c2, &c3, kdf2(TpmiAlgHash::Sha384)),
        value
    );
    assert_eq!(
        decrypt(&mut sim, key, c1, &c2, &c3, sha256),
        Ok(b"integrity".to_vec())
    );
}
