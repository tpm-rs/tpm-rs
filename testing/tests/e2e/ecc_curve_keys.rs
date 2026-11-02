//! Keys on the optional ECC curves NIST P-192, BN P-638 and SM2 P-256: TPM2_CreatePrimary,
//! TPM2_Create, TPM2_Load and TPM2_CreateLoaded of signing, decryption and storage keys (public
//! points of the curve's coordinate size, on the curve), TPM2_LoadExternal of client-generated
//! keys, and the validation of loaded public points and private keys.

use crate::_common::{
    AES128_CFB, OPTIONAL_ECC_CURVES, base_attrs, client_curve, create,
    create_primary_returning_public, ecc_curve_public, ecc_curve_template, ecc_signature_parts,
    load, load_external_ecc, make_template, rc_bare, rc_p, run, sign,
};
use testing::tpm::Tpm;
#[allow(deprecated)] // TPM2_CreateLoaded is deprecated upstream, but the TPM implements it.
use tpm2::commands::{CreateLoaded, ReadPublic};
use tpm2::errors::TpmRc;
use tpm2::{TpmEccCurve, TpmaObject, TpmiAlgHash, TpmtEccScheme, TpmtPublic};

/// An ECDSA-SHA256 signing key template on `curve`.
fn signing_template(curve: TpmEccCurve) -> TpmtPublic<'static> {
    ecc_curve_template(
        curve,
        base_attrs() | TpmaObject::SIGN_ENCRYPT,
        Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
    )
}

/// An unrestricted decryption (key agreement) key template on `curve`.
fn decrypt_template(curve: TpmEccCurve) -> TpmtPublic<'static> {
    ecc_curve_template(curve, base_attrs() | TpmaObject::DECRYPT, None)
}

/// A storage (restricted decryption, AES-128-CFB) key template on `curve`.
fn storage_template(curve: TpmEccCurve) -> TpmtPublic<'static> {
    let mut template = ecc_curve_template(
        curve,
        base_attrs() | TpmaObject::DECRYPT | TpmaObject::RESTRICTED,
        None,
    );
    if let tpm2::PublicParmsAndId::Ecc(parms, _) = &mut template.parms_and_id {
        parms.symmetric = Some(AES128_CFB);
    }
    template
}

/// Asserts that the public point of `public` has the coordinate size of `curve` and is on it.
fn assert_point_on_curve(curve: TpmEccCurve, public: &TpmtPublic<'_>) {
    let c = client_curve(curve as u16);
    let (x, y) = c.public_point(public);
    assert!(
        c.contains(&x, &y),
        "public point of a {curve:?} key is not on the curve"
    );
}

/// TPM2_CreatePrimary creates signing, decryption and storage keys on every optional curve, each
/// with a public point of the curve's coordinate size on the curve.
#[test]
fn primary_keys_have_points_on_the_curve() {
    let mut sim = Tpm::new();
    for &curve in OPTIONAL_ECC_CURVES {
        for template in [
            signing_template(curve),
            decrypt_template(curve),
            storage_template(curve),
        ] {
            let (handle, public) = create_primary_returning_public(&mut sim, template, b"");
            assert_point_on_curve(curve, &public);
            sim.execute(tpm2::commands::FlushContext {
                flush_handle: handle,
            })
            .expect("FlushContext");
        }
    }
}

/// TPM2_Create and TPM2_Load of signing and decryption keys under a storage key on the same
/// curve, and TPM2_CreateLoaded of the same templates, produce keys whose loaded public areas
/// (TPM2_ReadPublic) are the created ones, with points on the curve.
#[test]
#[allow(deprecated)] // TPM2_CreateLoaded is deprecated upstream, but the TPM implements it.
fn child_keys_create_load_and_create_loaded() {
    let mut sim = Tpm::new();
    for &curve in OPTIONAL_ECC_CURVES {
        let (parent, _) = create_primary_returning_public(&mut sim, storage_template(curve), b"");
        for template in [signing_template(curve), decrypt_template(curve)] {
            let created = create(&mut sim, parent, template, b"", b"")
                .unwrap_or_else(|rc| panic!("Create on {curve:?}: {rc:#x}"));
            assert_point_on_curve(curve, &created.out_public.0);
            let child = load(&mut sim, parent, created.out_private, created.out_public)
                .unwrap_or_else(|rc| panic!("Load on {curve:?}: {rc:#x}"));
            let read = sim
                .execute(ReadPublic {
                    object_handle: child,
                })
                .unwrap();
            assert_eq!(read.out_public.0, created.out_public.0);
            sim.execute(tpm2::commands::FlushContext {
                flush_handle: child,
            })
            .unwrap();

            let loaded = run(
                &mut sim,
                &CreateLoaded {
                    parent_handle: parent,
                    in_public: make_template(&template),
                    ..Default::default()
                },
                1,
            )
            .unwrap_or_else(|rc| panic!("CreateLoaded on {curve:?}: {rc:#x}"));
            assert_point_on_curve(curve, &loaded.out_public.0);
            let read = sim
                .execute(ReadPublic {
                    object_handle: loaded.object_handle,
                })
                .unwrap();
            assert_eq!(read.out_public.0, loaded.out_public.0);
            assert_eq!(read.name, loaded.name);
            sim.execute(tpm2::commands::FlushContext {
                flush_handle: loaded.object_handle,
            })
            .unwrap();
        }
        sim.execute(tpm2::commands::FlushContext {
            flush_handle: parent,
        })
        .unwrap();
    }
}

/// TPM2_LoadExternal of a client-generated private key with its public point: the TPM's ECDSA
/// signatures verify client-side with the client's public point.
#[test]
#[allow(deprecated)] // TPM2_Sign is deprecated upstream, but the TPM implements it.
fn load_external_private_key_signs_for_the_client_public_key() {
    let mut sim = Tpm::new();
    for &curve in OPTIONAL_ECC_CURVES {
        let c = client_curve(curve as u16);
        let (d, q) = c.key_pair();
        let public = ecc_curve_public(
            curve,
            TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
            &c.coordinate(&q.0),
            &c.coordinate(&q.1),
        );
        let key = load_external_ecc(&mut sim, public, Some(&c.coordinate(&d)))
            .unwrap_or_else(|rc| panic!("LoadExternal on {curve:?}: {rc:#x}"));
        let digest: &'static [u8] = &[0x5A; 32];
        let signature = sign(&mut sim, key, b"", digest, None).expect("Sign");
        let (hash, r, s) = ecc_signature_parts(&signature);
        assert_eq!(hash, TpmiAlgHash::Sha256);
        assert!(c.ecdsa_verify(&q, digest, &r, &s), "signature on {curve:?}");
        sim.execute(tpm2::commands::FlushContext { flush_handle: key })
            .unwrap();
    }
}

/// TPM2_LoadExternal of a public key alone rejects a point that is not on the curve and a
/// coordinate that is not below the field prime with `TPM_RC_ECC_POINT + RC_P2`, and a
/// coordinate shorter than the curve's coordinate size with `TPM_RC_KEY + RC_P2`; the valid point
/// loads.
#[test]
fn load_external_validates_public_points() {
    let mut sim = Tpm::new();
    for &curve in OPTIONAL_ECC_CURVES {
        let c = client_curve(curve as u16);
        let (_, q) = c.key_pair();
        let x = c.coordinate(&q.0);
        let y = c.coordinate(&q.1);
        let public = |x: &[u8], y: &[u8]| {
            ecc_curve_public(
                curve,
                TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
                Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                x,
                y,
            )
        };

        // y + 1 is not on the curve (only y and p - y are).
        let y_plus_one = c.coordinate(&((&q.1 + 1u32) % &c.p));
        assert_eq!(
            load_external_ecc(&mut sim, public(&x, &y_plus_one), None).err(),
            Some(rc_p(TpmRc::ECC_POINT, 2)),
            "point off {curve:?}"
        );
        // x + p and y + p have the same residues but are not field elements (SP 800-56A
        // 5.6.2.3.3 step 2); they fit the coordinate size on BN P-638.
        if let Some(x_plus_p) = c.plus_p(&q.0) {
            assert_eq!(
                load_external_ecc(&mut sim, public(&x_plus_p, &y), None).err(),
                Some(rc_p(TpmRc::ECC_POINT, 2)),
                "x + p on {curve:?}"
            );
        }
        if let Some(y_plus_p) = c.plus_p(&q.1) {
            assert_eq!(
                load_external_ecc(&mut sim, public(&x, &y_plus_p), None).err(),
                Some(rc_p(TpmRc::ECC_POINT, 2)),
                "y + p on {curve:?}"
            );
        }
        // y = p (a coordinate that is not below p).
        assert_eq!(
            load_external_ecc(&mut sim, public(&x, &c.coordinate(&c.p)), None).err(),
            Some(rc_p(TpmRc::ECC_POINT, 2)),
            "y = p on {curve:?}"
        );
        // A coordinate one byte short of the coordinate size.
        assert_eq!(
            load_external_ecc(&mut sim, public(&x[1..], &y), None).err(),
            Some(rc_p(TpmRc::KEY, 2)),
            "short x on {curve:?}"
        );

        let key = load_external_ecc(&mut sim, public(&x, &y), None)
            .unwrap_or_else(|rc| panic!("valid point on {curve:?}: {rc:#x}"));
        sim.execute(tpm2::commands::FlushContext { flush_handle: key })
            .unwrap();
    }
}

/// TPM2_LoadExternal with a private key checks `0 < d < n` (`TPM_RC_KEY_SIZE`) and that the
/// public point is `[d]G` (`TPM_RC_BINDING`).
#[test]
fn load_external_validates_private_keys() {
    let mut sim = Tpm::new();
    for &curve in OPTIONAL_ECC_CURVES {
        let c = client_curve(curve as u16);
        let (d, q) = c.key_pair();
        let public = ecc_curve_public(
            curve,
            TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
            &c.coordinate(&q.0),
            &c.coordinate(&q.1),
        );
        for bad in [rsa::BigUint::from(0u32), c.n.clone()] {
            assert_eq!(
                load_external_ecc(&mut sim, public, Some(&c.coordinate(&bad))).err(),
                Some(rc_bare(TpmRc::KEY_SIZE)),
                "d = {bad:x} on {curve:?}"
            );
        }
        let other = (&d + 1u32) % &c.n;
        assert_eq!(
            load_external_ecc(&mut sim, public, Some(&c.coordinate(&other))).err(),
            Some(rc_bare(TpmRc::BINDING)),
            "unrelated d on {curve:?}"
        );
    }
}
