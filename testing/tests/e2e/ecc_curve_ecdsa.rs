//! ECDSA on the optional ECC curves NIST P-192, BN P-638 and SM2 P-256: TPM2_Sign signatures
//! verify with TPM2_VerifySignature and with the independent client-side ECDSA of
//! `_common::ClientCurve`, client-side signatures verify on the TPM, and tampered signatures fail
//! with `TPM_RC_SIGNATURE`.

use crate::_common::{
    OPTIONAL_ECC_CURVES, base_attrs, client_curve, create_primary_returning_public,
    ecc_curve_public, ecc_curve_template, ecc_signature_parts, leak_bytes, load_external_ecc, rc_p,
    sha256, sign, verify_signature,
};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;
use tpm2::{
    Tpm2bEccParameter, TpmaObject, TpmiAlgHash, TpmsSignatureEcc, TpmtEccScheme, TpmtSigScheme,
    TpmtSignature,
};

/// `signature` with `r` or `s` (selected by `in_s`) replaced by `value`.
fn with_component(
    signature: &TpmtSignature<'static>,
    in_s: bool,
    value: Vec<u8>,
) -> TpmtSignature<'static> {
    let TpmtSignature::Ecdsa(sig) = signature else {
        panic!("not an ECDSA signature");
    };
    let value = Tpm2bEccParameter::from_bytes(leak_bytes(&value)).unwrap();
    let mut sig: TpmsSignatureEcc<'static> = *sig;
    if in_s {
        sig.signature_s = value;
    } else {
        sig.signature_r = value;
    }
    TpmtSignature::Ecdsa(sig)
}

/// The ECDSA signatures of a TPM-generated key on every optional curve have `r` and `s` of the
/// order's size, verify with TPM2_VerifySignature and client-side, and fail on the TPM
/// (`TPM_RC_SIGNATURE + RC_P2`) and client-side when `s` or the digest is changed.
#[test]
#[allow(deprecated)] // TPM2_Sign/TPM2_VerifySignature are deprecated upstream.
fn tpm_signatures_verify_on_tpm_and_client() {
    let mut sim = Tpm::new();
    for &curve in OPTIONAL_ECC_CURVES {
        let c = client_curve(curve as u16);
        let template = ecc_curve_template(
            curve,
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        );
        let (key, public) = create_primary_returning_public(&mut sim, template, b"");
        let q = c.public_point(&public);
        let digest = leak_bytes(&sha256(&[b"ECDSA on an optional curve"]));
        let signature = sign(&mut sim, key, b"", digest, None).expect("Sign");
        let (hash, r, s) = ecc_signature_parts(&signature);
        assert_eq!(hash, TpmiAlgHash::Sha256);
        assert_eq!(r.len(), c.n_len(), "size of r on {curve:?}");
        assert_eq!(s.len(), c.n_len(), "size of s on {curve:?}");
        assert!(
            c.ecdsa_verify(&q, digest, &r, &s),
            "client verification on {curve:?}"
        );
        verify_signature(&mut sim, key, digest, signature)
            .unwrap_or_else(|rc| panic!("VerifySignature on {curve:?}: {rc:#x}"));

        let mut bad_s = s.clone();
        *bad_s.last_mut().unwrap() ^= 1;
        assert!(!c.ecdsa_verify(&q, digest, &r, &bad_s));
        assert_eq!(
            verify_signature(
                &mut sim,
                key,
                digest,
                with_component(&signature, true, bad_s)
            )
            .err(),
            Some(rc_p(TpmRc::SIGNATURE, 2)),
            "tampered s on {curve:?}"
        );
        let other_digest = leak_bytes(&sha256(&[b"another message"]));
        assert!(!c.ecdsa_verify(&q, other_digest, &r, &s));
        assert_eq!(
            verify_signature(&mut sim, key, other_digest, signature).err(),
            Some(rc_p(TpmRc::SIGNATURE, 2)),
            "other digest on {curve:?}"
        );
        sim.execute(tpm2::commands::FlushContext { flush_handle: key })
            .unwrap();
    }
}

/// Client-side ECDSA signatures with a client-generated key verify with TPM2_VerifySignature on
/// the public key loaded by TPM2_LoadExternal; `r = 0` and `s = n` fail with
/// `TPM_RC_SIGNATURE + RC_P2`.
#[test]
#[allow(deprecated)] // TPM2_VerifySignature is deprecated upstream.
fn client_signatures_verify_on_tpm() {
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
        let key = load_external_ecc(&mut sim, public, None)
            .unwrap_or_else(|rc| panic!("LoadExternal on {curve:?}: {rc:#x}"));
        let digest = leak_bytes(&sha256(&[b"signed by the client"]));
        let (r, s) = c.ecdsa_sign(&d, digest);
        let signature = TpmtSignature::Ecdsa(c.signature_ecc(TpmiAlgHash::Sha256, &r, &s));
        verify_signature(&mut sim, key, digest, signature)
            .unwrap_or_else(|rc| panic!("VerifySignature on {curve:?}: {rc:#x}"));

        let zero_r = with_component(&signature, false, vec![0; c.n_len()]);
        assert_eq!(
            verify_signature(&mut sim, key, digest, zero_r).err(),
            Some(rc_p(TpmRc::SIGNATURE, 2)),
            "r = 0 on {curve:?}"
        );
        let n_s = with_component(&signature, true, c.n.to_bytes_be());
        assert_eq!(
            verify_signature(&mut sim, key, digest, n_s).err(),
            Some(rc_p(TpmRc::SIGNATURE, 2)),
            "s = n on {curve:?}"
        );
        sim.execute(tpm2::commands::FlushContext { flush_handle: key })
            .unwrap();
    }
}

/// A key without a scheme on an optional curve signs with an explicit ECDSA scheme of another
/// hash (SHA-384, whose digest is longer than the P-192 and SM2 P-256 orders and is truncated),
/// and the signature verifies client-side.
#[test]
#[allow(deprecated)] // TPM2_Sign is deprecated upstream, but the TPM implements it.
fn key_without_scheme_signs_with_another_hash() {
    let mut sim = Tpm::new();
    for &curve in OPTIONAL_ECC_CURVES {
        let c = client_curve(curve as u16);
        let template = ecc_curve_template(curve, base_attrs() | TpmaObject::SIGN_ENCRYPT, None);
        let (key, public) = create_primary_returning_public(&mut sim, template, b"");
        let q = c.public_point(&public);
        let digest: &'static [u8] = &[0xA7; 48];
        let signature = sign(
            &mut sim,
            key,
            b"",
            digest,
            Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha384)),
        )
        .expect("Sign");
        let (hash, r, s) = ecc_signature_parts(&signature);
        assert_eq!(hash, TpmiAlgHash::Sha384);
        assert!(c.ecdsa_verify(&q, digest, &r, &s), "signature on {curve:?}");
        verify_signature(&mut sim, key, digest, signature)
            .unwrap_or_else(|rc| panic!("VerifySignature on {curve:?}: {rc:#x}"));
        sim.execute(tpm2::commands::FlushContext { flush_handle: key })
            .unwrap();
    }
}
