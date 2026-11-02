//! SM2 signatures (`TPM_ALG_SM2`, TPM 2.0 Part 1, "SM2 Digital Signature Algorithm"; the TPM signs
//! the given digest `e` directly, `Z_A` is the caller's): `TPM_CAP_ALGS`, TPM2_Sign and
//! TPM2_VerifySignature with SM2 keys on SM2 P-256 and NIST P-256 (checked against the
//! independent client-side SM2 of `_common::ClientCurve`), tampered signatures, scheme
//! mismatches, a TPM2_Quote signed with SM2, TPM2_PolicySigned with an SM2 authorization and
//! TPM2_IncrementalSelfTest of SM2.

#[cfg(feature = "sm2")]
use crate::_common::{
    CAP_ALGS, base_attrs, client_curve, create_primary_returning_public, ecc_curve_public,
    ecc_curve_template, ecc_signature_parts, get_cap, incremental_self_test, leak_bytes,
    load_external_ecc, marshal_to_vec, policy_get_digest, policy_signed, quote, rc_p,
    read_public_name, sha256, sign, start_policy_session, verify_signature,
};
#[cfg(feature = "sm2")]
use testing::tpm::Tpm;
#[cfg(feature = "sm2")]
use tpm2::commands::{GetTestResult, SelfTest};
#[cfg(feature = "sm2")]
use tpm2::errors::TpmRc;
#[cfg(feature = "sm2")]
use tpm2::{
    Alg, Tpm2bEccParameter, TpmCc, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmtEccScheme,
    TpmtSigScheme, TpmtSignature,
};

/// The curves the SM2 tests use: SM2 P-256 (with `ecc_curve_sm2_p256`) and NIST P-256 (SM2 is
/// not tied to a curve).
#[cfg(feature = "sm2")]
const SM2_CURVES: &[TpmEccCurve] = &[
    #[cfg(feature = "ecc_curve_sm2_p256")]
    TpmEccCurve::SM2P256,
    TpmEccCurve::NistP256,
];

/// An SM2-SHA256 signing key template on `curve` (`extra` added to the default attributes).
#[cfg(feature = "sm2")]
fn sm2_template(curve: TpmEccCurve, extra: TpmaObject) -> tpm2::TpmtPublic<'static> {
    ecc_curve_template(
        curve,
        base_attrs() | TpmaObject::SIGN_ENCRYPT | extra,
        Some(TpmtEccScheme::Sm2(TpmiAlgHash::Sha256)),
    )
}

/// `signature` (SM2) with the last byte of `r` flipped.
#[cfg(feature = "sm2")]
fn tampered(signature: &TpmtSignature<'static>) -> TpmtSignature<'static> {
    let TpmtSignature::Sm2(sig) = signature else {
        panic!("not an SM2 signature: {signature:?}");
    };
    let mut r = sig.signature_r.get_buffer().to_vec();
    *r.last_mut().unwrap() ^= 1;
    let mut sig = *sig;
    sig.signature_r = Tpm2bEccParameter::from_bytes(leak_bytes(&r)).unwrap();
    TpmtSignature::Sm2(sig)
}

/// `TPM_CAP_ALGS` reports `TPM_ALG_SM2` as an asymmetric signing method (asymmetric, signing,
/// method).
#[cfg(feature = "sm2")]
#[test]
fn algorithm_capability_lists_sm2() {
    let mut sim = Tpm::new();
    let (_, data) = get_cap(&mut sim, CAP_ALGS, u32::from(Alg::SM2.id()), 1).unwrap();
    assert_eq!(u32::from_be_bytes(data[0..4].try_into().unwrap()), 1);
    assert_eq!(u16::from_be_bytes([data[4], data[5]]), Alg::SM2.id());
    let attributes = u32::from_be_bytes(data[6..10].try_into().unwrap());
    assert_eq!(attributes, (1 << 0) | (1 << 8) | (1 << 10));
}

/// SM2 signatures of TPM-generated keys on SM2 P-256 and NIST P-256 (with the key's scheme and
/// with an explicit SM2-SHA384 scheme on a key without a scheme) verify client-side and with
/// TPM2_VerifySignature; a tampered `r` or another digest fails with
/// `TPM_RC_SIGNATURE + RC_P2`.
#[cfg(feature = "sm2")]
#[test]
#[allow(deprecated)] // TPM2_Sign/TPM2_VerifySignature are deprecated upstream.
fn tpm_signatures_verify_on_tpm_and_client() {
    let mut sim = Tpm::new();
    for &curve in SM2_CURVES {
        let c = client_curve(curve as u16);
        for (template, in_scheme, hash) in [
            (
                sm2_template(curve, TpmaObject::empty()),
                None,
                TpmiAlgHash::Sha256,
            ),
            (
                ecc_curve_template(curve, base_attrs() | TpmaObject::SIGN_ENCRYPT, None),
                Some(TpmtSigScheme::Sm2(TpmiAlgHash::Sha384)),
                TpmiAlgHash::Sha384,
            ),
        ] {
            let (key, public) = create_primary_returning_public(&mut sim, template, b"");
            let q = c.public_point(&public);
            let digest = leak_bytes(&crate::_common::compute_hash(hash, &[b"SM2 message"]));
            let signature = sign(&mut sim, key, b"", digest, in_scheme).expect("Sign");
            assert!(matches!(signature, TpmtSignature::Sm2(_)), "{signature:?}");
            let (sig_hash, r, s) = ecc_signature_parts(&signature);
            assert_eq!(sig_hash, hash);
            assert_eq!(r.len(), 32, "size of r");
            assert_eq!(s.len(), 32, "size of s");
            assert!(
                c.sm2_verify(&q, digest, &r, &s),
                "client verification on {curve:?}"
            );
            verify_signature(&mut sim, key, digest, signature)
                .unwrap_or_else(|rc| panic!("VerifySignature on {curve:?}: {rc:#x}"));
            assert_eq!(
                verify_signature(&mut sim, key, digest, tampered(&signature)).err(),
                Some(rc_p(TpmRc::SIGNATURE, 2)),
                "tampered r on {curve:?}"
            );
            let other = leak_bytes(&crate::_common::compute_hash(hash, &[b"other"]));
            assert_eq!(
                verify_signature(&mut sim, key, other, signature).err(),
                Some(rc_p(TpmRc::SIGNATURE, 2)),
                "other digest on {curve:?}"
            );
            sim.execute(tpm2::commands::FlushContext { flush_handle: key })
                .unwrap();
        }
    }
}

/// Client-side SM2 signatures with a client-generated key verify with TPM2_VerifySignature on the
/// public key loaded by TPM2_LoadExternal, with and without an SM2 scheme in the public area.
#[cfg(feature = "sm2")]
#[test]
#[allow(deprecated)] // TPM2_VerifySignature is deprecated upstream.
fn client_signatures_verify_on_tpm() {
    let mut sim = Tpm::new();
    for &curve in SM2_CURVES {
        let c = client_curve(curve as u16);
        let (d, q) = c.key_pair();
        for scheme in [Some(TpmtEccScheme::Sm2(TpmiAlgHash::Sha256)), None] {
            let public = ecc_curve_public(
                curve,
                TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
                scheme,
                &c.coordinate(&q.0),
                &c.coordinate(&q.1),
            );
            let key = load_external_ecc(&mut sim, public, None)
                .unwrap_or_else(|rc| panic!("LoadExternal on {curve:?}: {rc:#x}"));
            let digest = leak_bytes(&sha256(&[b"signed by the client with SM2"]));
            let (r, s) = c.sm2_sign(&d, digest);
            let signature = TpmtSignature::Sm2(c.signature_ecc(TpmiAlgHash::Sha256, &r, &s));
            verify_signature(&mut sim, key, digest, signature)
                .unwrap_or_else(|rc| panic!("VerifySignature on {curve:?}: {rc:#x}"));
            assert_eq!(
                verify_signature(&mut sim, key, digest, tampered(&signature)).err(),
                Some(rc_p(TpmRc::SIGNATURE, 2))
            );
            sim.execute(tpm2::commands::FlushContext { flush_handle: key })
                .unwrap();
        }
    }
}

/// TPM2_Sign with an SM2 key and an ECDSA `inScheme`, or with an ECDSA key and an SM2
/// `inScheme`, fails with `TPM_RC_SCHEME + RC_P2`; an SM2 key does not verify an ECDSA
/// signature of its own (`TPM_RC_SCHEME + RC_P2`).
#[cfg(feature = "sm2")]
#[test]
#[allow(deprecated)] // TPM2_Sign/TPM2_VerifySignature are deprecated upstream.
fn scheme_mismatches_are_rejected() {
    let mut sim = Tpm::new();
    let digest = leak_bytes(&sha256(&[b"scheme mismatch"]));
    let (sm2_key, _) = create_primary_returning_public(
        &mut sim,
        sm2_template(TpmEccCurve::NistP256, TpmaObject::empty()),
        b"",
    );
    assert_eq!(
        sign(
            &mut sim,
            sm2_key,
            b"",
            digest,
            Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256))
        )
        .err(),
        Some(rc_p(TpmRc::SCHEME, 2))
    );
    let (ecdsa_key, _) = create_primary_returning_public(
        &mut sim,
        ecc_curve_template(
            TpmEccCurve::NistP256,
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    assert_eq!(
        sign(
            &mut sim,
            ecdsa_key,
            b"",
            digest,
            Some(TpmtSigScheme::Sm2(TpmiAlgHash::Sha256))
        )
        .err(),
        Some(rc_p(TpmRc::SCHEME, 2))
    );
    let ecdsa_signature = sign(&mut sim, ecdsa_key, b"", digest, None).unwrap();
    let TpmtSignature::Ecdsa(ecdsa) = ecdsa_signature else {
        panic!("not ECDSA")
    };
    // The ECDSA signature relabeled as SM2 does not verify as SM2.
    assert_eq!(
        verify_signature(&mut sim, ecdsa_key, digest, TpmtSignature::Sm2(ecdsa)).err(),
        Some(rc_p(TpmRc::SIGNATURE, 2))
    );
}

/// A restricted SM2 signing key signs a TPM2_Quote; the signature over the SHA-256 digest of
/// the `quoted` structure verifies client-side and with TPM2_VerifySignature.
#[cfg(feature = "sm2")]
#[test]
#[allow(deprecated)] // TPM2_VerifySignature is deprecated upstream.
fn quote_signed_with_sm2_verifies() {
    let mut sim = Tpm::new();
    for &curve in SM2_CURVES {
        let c = client_curve(curve as u16);
        let (key, public) = create_primary_returning_public(
            &mut sim,
            sm2_template(curve, TpmaObject::RESTRICTED),
            b"",
        );
        let rsp = quote(&mut sim, key, None).expect("Quote");
        let signature = rsp.signature.expect("signature");
        assert!(matches!(signature, TpmtSignature::Sm2(_)), "{signature:?}");
        let digest = leak_bytes(&sha256(&[&marshal_to_vec(&rsp.quoted.0)]));
        let (_, r, s) = ecc_signature_parts(&signature);
        assert!(c.sm2_verify(&c.public_point(&public), digest, &r, &s));
        verify_signature(&mut sim, key, digest, signature)
            .unwrap_or_else(|rc| panic!("VerifySignature of the quote on {curve:?}: {rc:#x}"));
        sim.execute(tpm2::commands::FlushContext { flush_handle: key })
            .unwrap();
    }
}

/// TPM2_PolicySigned accepts a client-side SM2 signature of `aHash` (here
/// `SHA-256(nonceTPM || expiration)` with empty cpHashA and policyRef) by a key loaded with
/// TPM2_LoadExternal and extends the policy digest with `TPM_CC_PolicySigned || authName`; a
/// tampered signature fails with `TPM_RC_SIGNATURE + RC_P5`.
#[cfg(feature = "sm2")]
#[test]
fn policy_signed_accepts_an_sm2_authorization() {
    let mut sim = Tpm::new();
    for &curve in SM2_CURVES {
        let c = client_curve(curve as u16);
        let (d, q) = c.key_pair();
        let public = ecc_curve_public(
            curve,
            TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            Some(TpmtEccScheme::Sm2(TpmiAlgHash::Sha256)),
            &c.coordinate(&q.0),
            &c.coordinate(&q.1),
        );
        let key = load_external_ecc(&mut sim, public, None).expect("LoadExternal");
        let name = read_public_name(&mut sim, key);
        let session = start_policy_session(&mut sim).session_handle;
        let a_hash = sha256(&[&0i32.to_be_bytes()]);
        let (r, s) = c.sm2_sign(&d, &a_hash);
        let auth = TpmtSignature::Sm2(c.signature_ecc(TpmiAlgHash::Sha256, &r, &s));

        assert_eq!(
            policy_signed(&mut sim, key, session, tampered(&auth)).err(),
            Some(rc_p(TpmRc::SIGNATURE, 5))
        );
        policy_signed(&mut sim, key, session, auth)
            .unwrap_or_else(|rc| panic!("PolicySigned on {curve:?}: {rc:#x}"));
        let update = sha256(&[
            &[0u8; 32],
            &TpmCc::PolicySigned.code().to_be_bytes(),
            name.get_buffer(),
        ]);
        assert_eq!(policy_get_digest(&mut sim, session), sha256(&[&update]));
        sim.execute(tpm2::commands::FlushContext {
            flush_handle: session,
        })
        .unwrap();
        sim.execute(tpm2::commands::FlushContext { flush_handle: key })
            .unwrap();
    }
}

/// SM2 has no self test (as in the references): TPM2_IncrementalSelfTest of SM2 succeeds and
/// leaves it off the `toDoList`, and after TPM2_SelfTest, TPM2_GetTestResult succeeds and an SM2
/// signature still verifies.
#[cfg(feature = "sm2")]
#[test]
#[allow(deprecated)] // TPM2_Sign/TPM2_VerifySignature are deprecated upstream.
fn incremental_self_test_of_sm2() {
    let mut sim = Tpm::new();
    let to_do = incremental_self_test(&mut sim, &[]).expect("IncrementalSelfTest");
    assert!(!to_do.contains(&Alg::SM2), "{to_do:?}");
    let after = incremental_self_test(&mut sim, &[Alg::SM2]).expect("IncrementalSelfTest(SM2)");
    assert!(!after.contains(&Alg::SM2), "{after:?}");
    sim.execute(SelfTest { full_test: true }).expect("SelfTest");
    let rsp = sim.execute(GetTestResult {}).expect("GetTestResult");
    assert_eq!(rsp.test_result, Ok(()));

    let (key, _) = create_primary_returning_public(
        &mut sim,
        sm2_template(TpmEccCurve::NistP256, TpmaObject::empty()),
        b"",
    );
    let digest = leak_bytes(&sha256(&[b"after the self test"]));
    let signature = sign(&mut sim, key, b"", digest, None).expect("Sign");
    verify_signature(&mut sim, key, digest, signature).expect("VerifySignature");
}

/// Without the `sm2` feature, `TPM_CAP_ALGS` does not report `TPM_ALG_SM2`, and TPM2_Sign
/// with an SM2 `inScheme` (sent as patched raw bytes, since the scheme does not marshal without
/// the feature) fails with `TPM_RC_SCHEME + RC_P2`.
#[cfg(not(feature = "sm2"))]
#[test]
#[allow(deprecated)] // TPM2_Sign is deprecated upstream, but the TPM implements it.
fn capability_and_sign_omit_sm2_without_the_feature() {
    use crate::_common::{
        CAP_ALGS, base_attrs, create_primary_returning_public, ecc_curve_template,
        execute_with_corrupted_bytes_status, get_cap, rc_p,
    };
    use tpm2::{Handle, Tpm2bDigest, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmtEccScheme};

    let mut sim = testing::tpm::Tpm::new();
    let (_, data) = get_cap(&mut sim, CAP_ALGS, 0x001b, 1).unwrap();
    let count = u32::from_be_bytes(data[0..4].try_into().unwrap());
    if count > 0 {
        assert_ne!(
            u16::from_be_bytes([data[4], data[5]]),
            0x001b,
            "TPM_ALG_SM2 listed"
        );
    }

    let (key, _) = create_primary_returning_public(
        &mut sim,
        ecc_curve_template(
            TpmEccCurve::NistP256,
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let cmd = tpm2::commands::Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap(),
        in_scheme: Some(tpm2::TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
        validation: tpm2::TpmtTkHashcheck::new(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    // Parameters: digest (2 + 32 bytes), then the inScheme algorithm (TPM_ALG_ECDSA).
    let rc = execute_with_corrupted_bytes_status(&mut sim, &cmd, 1, &[], |params| {
        assert_eq!(params[34..36], [0x00, 0x18]);
        params[34..36].copy_from_slice(&0x001bu16.to_be_bytes());
    })
    .err();
    assert_eq!(rc, Some(rc_p(tpm2::errors::TpmRc::SCHEME, 2)));
}
