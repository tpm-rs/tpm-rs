//! EC-Schnorr signatures (`TPM_ALG_ECSCHNORR`, TPM 2.0 Part 1, "EC Schnorr":
//! `r = TRUNC(H(FE2BS(xE) || P), n)`, `s = k + r*d mod n`): `TPM_CAP_ALGS`, TPM2_Sign and
//! TPM2_VerifySignature on NIST P-256 and the optional curves (checked against the independent
//! client-side EC-Schnorr of `_common::ClientCurve`), tampered signatures, scheme mismatches, a
//! TPM2_Certify signed with EC-Schnorr, TPM2_PolicySigned with an EC-Schnorr authorization and
//! the EC-Schnorr self test.

#[cfg(feature = "ecschnorr")]
use crate::_common::{
    CAP_ALGS, OPTIONAL_ECC_CURVES, base_attrs, client_curve, compute_hash,
    create_primary_returning_public, ecc_curve_public, ecc_curve_template, ecc_signature_parts,
    get_cap, incremental_self_test, leak_bytes, load_external_ecc, marshal_to_vec,
    policy_get_digest, policy_signed, rc_p, read_public_name, run, sha256, sign,
    start_policy_session, verify_signature,
};
#[cfg(feature = "ecschnorr")]
use testing::tpm::Tpm;
#[cfg(feature = "ecschnorr")]
use tpm2::commands::{Certify, GetTestResult, SelfTest};
#[cfg(feature = "ecschnorr")]
use tpm2::errors::TpmRc;
#[cfg(feature = "ecschnorr")]
use tpm2::{
    Alg, Tpm2bData, Tpm2bEccParameter, TpmCc, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmtEccScheme,
    TpmtSigScheme, TpmtSignature,
};

/// The curves the EC-Schnorr tests use: NIST P-256 and the optional curves of this build.
#[cfg(feature = "ecschnorr")]
fn schnorr_curves() -> Vec<TpmEccCurve> {
    let mut curves = vec![TpmEccCurve::NistP256];
    curves.extend_from_slice(OPTIONAL_ECC_CURVES);
    curves
}

/// An EC-Schnorr-SHA256 signing key template on `curve` (`extra` added to the default
/// attributes).
#[cfg(feature = "ecschnorr")]
fn schnorr_template(curve: TpmEccCurve, extra: TpmaObject) -> tpm2::TpmtPublic<'static> {
    ecc_curve_template(
        curve,
        base_attrs() | TpmaObject::SIGN_ENCRYPT | extra,
        Some(TpmtEccScheme::Ecschnorr(TpmiAlgHash::Sha256)),
    )
}

/// `signature` (EC-Schnorr) with the last byte of `s` flipped.
#[cfg(feature = "ecschnorr")]
fn tampered(signature: &TpmtSignature<'static>) -> TpmtSignature<'static> {
    let TpmtSignature::Ecschnorr(sig) = signature else {
        panic!("not an EC-Schnorr signature: {signature:?}");
    };
    let mut s = sig.signature_s.get_buffer().to_vec();
    *s.last_mut().unwrap() ^= 1;
    let mut sig = *sig;
    sig.signature_s = Tpm2bEccParameter::from_bytes(leak_bytes(&s)).unwrap();
    TpmtSignature::Ecschnorr(sig)
}

/// `TPM_CAP_ALGS` reports `TPM_ALG_ECSCHNORR` as an asymmetric signing algorithm (asymmetric,
/// signing).
#[cfg(feature = "ecschnorr")]
#[test]
fn algorithm_capability_lists_ecschnorr() {
    let mut sim = Tpm::new();
    let (_, data) = get_cap(&mut sim, CAP_ALGS, u32::from(Alg::ECSCHNORR.id()), 1).unwrap();
    assert_eq!(u32::from_be_bytes(data[0..4].try_into().unwrap()), 1);
    assert_eq!(u16::from_be_bytes([data[4], data[5]]), Alg::ECSCHNORR.id());
    let attributes = u32::from_be_bytes(data[6..10].try_into().unwrap());
    assert_eq!(attributes, (1 << 0) | (1 << 8));
}

/// EC-Schnorr signatures of TPM-generated keys (with the key's SHA-256 scheme and with an
/// explicit EC-Schnorr-SHA384 scheme on a key without a scheme) have `r` and `s` of the order's
/// size, verify client-side and with TPM2_VerifySignature, and fail with
/// `TPM_RC_SIGNATURE + RC_P2` when `s` or the digest is changed.
#[cfg(feature = "ecschnorr")]
#[test]
#[allow(deprecated)] // TPM2_Sign/TPM2_VerifySignature are deprecated upstream.
fn tpm_signatures_verify_on_tpm_and_client() {
    let mut sim = Tpm::new();
    for curve in schnorr_curves() {
        let c = client_curve(curve as u16);
        for (template, in_scheme, hash) in [
            (
                schnorr_template(curve, TpmaObject::empty()),
                None,
                TpmiAlgHash::Sha256,
            ),
            (
                ecc_curve_template(curve, base_attrs() | TpmaObject::SIGN_ENCRYPT, None),
                Some(TpmtSigScheme::Ecschnorr(TpmiAlgHash::Sha384)),
                TpmiAlgHash::Sha384,
            ),
        ] {
            let (key, public) = create_primary_returning_public(&mut sim, template, b"");
            let q = c.public_point(&public);
            let digest = leak_bytes(&compute_hash(hash, &[b"EC-Schnorr message"]));
            let signature = sign(&mut sim, key, b"", digest, in_scheme).expect("Sign");
            assert!(
                matches!(signature, TpmtSignature::Ecschnorr(_)),
                "{signature:?}"
            );
            let (sig_hash, r, s) = ecc_signature_parts(&signature);
            assert_eq!(sig_hash, hash);
            assert_eq!(r.len(), c.n_len(), "size of r on {curve:?}");
            assert_eq!(s.len(), c.n_len(), "size of s on {curve:?}");
            assert!(
                c.schnorr_verify(hash, &q, digest, &r, &s),
                "client verification on {curve:?} with {hash:?}"
            );
            verify_signature(&mut sim, key, digest, signature)
                .unwrap_or_else(|rc| panic!("VerifySignature on {curve:?}: {rc:#x}"));
            assert_eq!(
                verify_signature(&mut sim, key, digest, tampered(&signature)).err(),
                Some(rc_p(TpmRc::SIGNATURE, 2)),
                "tampered s on {curve:?}"
            );
            let other = leak_bytes(&compute_hash(hash, &[b"other"]));
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

/// Client-side EC-Schnorr signatures with a client-generated key verify with
/// TPM2_VerifySignature on the public key loaded by TPM2_LoadExternal.
#[cfg(feature = "ecschnorr")]
#[test]
#[allow(deprecated)] // TPM2_VerifySignature is deprecated upstream.
fn client_signatures_verify_on_tpm() {
    let mut sim = Tpm::new();
    for curve in schnorr_curves() {
        let c = client_curve(curve as u16);
        let (d, q) = c.key_pair();
        let public = ecc_curve_public(
            curve,
            TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            Some(TpmtEccScheme::Ecschnorr(TpmiAlgHash::Sha256)),
            &c.coordinate(&q.0),
            &c.coordinate(&q.1),
        );
        let key = load_external_ecc(&mut sim, public, None)
            .unwrap_or_else(|rc| panic!("LoadExternal on {curve:?}: {rc:#x}"));
        let digest = leak_bytes(&sha256(&[b"signed by the client with EC-Schnorr"]));
        let (r, s) = c.schnorr_sign(TpmiAlgHash::Sha256, &d, digest);
        let signature = TpmtSignature::Ecschnorr(c.signature_ecc(TpmiAlgHash::Sha256, &r, &s));
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

/// TPM2_Sign with an EC-Schnorr key and an ECDSA `inScheme`, or with an ECDSA key and an
/// EC-Schnorr `inScheme`, fails with `TPM_RC_SCHEME + RC_P2`; an ECDSA signature relabeled as
/// EC-Schnorr does not verify (`TPM_RC_SIGNATURE + RC_P2`).
#[cfg(feature = "ecschnorr")]
#[test]
#[allow(deprecated)] // TPM2_Sign/TPM2_VerifySignature are deprecated upstream.
fn scheme_mismatches_are_rejected() {
    let mut sim = Tpm::new();
    let digest = leak_bytes(&sha256(&[b"scheme mismatch"]));
    let (schnorr_key, _) = create_primary_returning_public(
        &mut sim,
        schnorr_template(TpmEccCurve::NistP256, TpmaObject::empty()),
        b"",
    );
    assert_eq!(
        sign(
            &mut sim,
            schnorr_key,
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
            Some(TpmtSigScheme::Ecschnorr(TpmiAlgHash::Sha256))
        )
        .err(),
        Some(rc_p(TpmRc::SCHEME, 2))
    );
    let TpmtSignature::Ecdsa(ecdsa) = sign(&mut sim, ecdsa_key, b"", digest, None).unwrap() else {
        panic!("not ECDSA")
    };
    assert_eq!(
        verify_signature(&mut sim, ecdsa_key, digest, TpmtSignature::Ecschnorr(ecdsa)).err(),
        Some(rc_p(TpmRc::SIGNATURE, 2))
    );
}

/// A restricted EC-Schnorr signing key certifies itself with TPM2_Certify; the signature over
/// the SHA-256 digest of `certifyInfo` verifies client-side and with TPM2_VerifySignature.
#[cfg(feature = "ecschnorr")]
#[test]
#[allow(deprecated)] // TPM2_VerifySignature is deprecated upstream.
fn certify_signed_with_ecschnorr_verifies() {
    let mut sim = Tpm::new();
    for curve in schnorr_curves() {
        let c = client_curve(curve as u16);
        let (key, public) = create_primary_returning_public(
            &mut sim,
            schnorr_template(curve, TpmaObject::RESTRICTED),
            b"",
        );
        let rsp = run(
            &mut sim,
            &Certify {
                object_handle: key,
                sign_handle: key,
                qualifying_data: Tpm2bData::from_bytes(b"certify").unwrap(),
                in_scheme: None,
            },
            2,
        )
        .unwrap_or_else(|rc| panic!("Certify on {curve:?}: {rc:#x}"));
        let signature = rsp.signature.expect("signature");
        assert!(
            matches!(signature, TpmtSignature::Ecschnorr(_)),
            "{signature:?}"
        );
        let digest = leak_bytes(&sha256(&[&marshal_to_vec(&rsp.certify_info.0)]));
        let (_, r, s) = ecc_signature_parts(&signature);
        assert!(c.schnorr_verify(
            TpmiAlgHash::Sha256,
            &c.public_point(&public),
            digest,
            &r,
            &s
        ));
        verify_signature(&mut sim, key, digest, signature)
            .unwrap_or_else(|rc| panic!("VerifySignature of certifyInfo on {curve:?}: {rc:#x}"));
        sim.execute(tpm2::commands::FlushContext { flush_handle: key })
            .unwrap();
    }
}

/// TPM2_PolicySigned accepts a client-side EC-Schnorr signature of `aHash` (here
/// `SHA-256(nonceTPM || expiration)` with empty cpHashA and policyRef) by a key loaded with
/// TPM2_LoadExternal and extends the policy digest with `TPM_CC_PolicySigned || authName`; a
/// tampered signature fails with `TPM_RC_SIGNATURE + RC_P5`.
#[cfg(feature = "ecschnorr")]
#[test]
fn policy_signed_accepts_an_ecschnorr_authorization() {
    let mut sim = Tpm::new();
    for curve in schnorr_curves() {
        let c = client_curve(curve as u16);
        let (d, q) = c.key_pair();
        let public = ecc_curve_public(
            curve,
            TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            Some(TpmtEccScheme::Ecschnorr(TpmiAlgHash::Sha256)),
            &c.coordinate(&q.0),
            &c.coordinate(&q.1),
        );
        let key = load_external_ecc(&mut sim, public, None).expect("LoadExternal");
        let name = read_public_name(&mut sim, key);
        let session = start_policy_session(&mut sim).session_handle;
        let a_hash = sha256(&[&0i32.to_be_bytes()]);
        let (r, s) = c.schnorr_sign(TpmiAlgHash::Sha256, &d, &a_hash);
        let auth = TpmtSignature::Ecschnorr(c.signature_ecc(TpmiAlgHash::Sha256, &r, &s));

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

/// EC-Schnorr needs a test after `_TPM_Init`: it is on the `toDoList` until
/// TPM2_IncrementalSelfTest tests it (a known-answer verification, then a sign/verify), after
/// which TPM2_GetTestResult still reports `TPM_RC_NEEDS_TEST` for the other algorithms until
/// TPM2_SelfTest completes every test.
#[cfg(feature = "ecschnorr")]
#[test]
fn incremental_self_test_of_ecschnorr() {
    let mut sim = Tpm::new();
    let to_do = incremental_self_test(&mut sim, &[]).expect("IncrementalSelfTest");
    assert!(to_do.contains(&Alg::ECSCHNORR), "{to_do:?}");
    let after =
        incremental_self_test(&mut sim, &[Alg::ECSCHNORR]).expect("IncrementalSelfTest(ECSCHNORR)");
    assert!(!after.contains(&Alg::ECSCHNORR), "{after:?}");
    assert!(after.len() < to_do.len());
    let rsp = sim.execute(GetTestResult {}).expect("GetTestResult");
    assert_eq!(rsp.test_result, Err(TpmRc::NEEDS_TEST));
    sim.execute(SelfTest { full_test: false })
        .expect("SelfTest");
    let rsp = sim.execute(GetTestResult {}).expect("GetTestResult");
    assert_eq!(rsp.test_result, Ok(()));
}

/// The first EC-Schnorr signature after `_TPM_Init` runs the EC-Schnorr self test on demand
/// (which draws random values from the DRBG), so ECSCHNORR leaves the `toDoList`.
#[cfg(feature = "ecschnorr")]
#[test]
#[allow(deprecated)] // TPM2_Sign is deprecated upstream, but the TPM implements it.
fn first_ecschnorr_signature_tests_ecschnorr() {
    let mut sim = Tpm::new();
    let (key, _) = create_primary_returning_public(
        &mut sim,
        schnorr_template(TpmEccCurve::NistP256, TpmaObject::empty()),
        b"",
    );
    let digest = leak_bytes(&sha256(&[b"first EC-Schnorr signature"]));
    sign(&mut sim, key, b"", digest, None).expect("Sign");
    let to_do = incremental_self_test(&mut sim, &[]).expect("IncrementalSelfTest");
    assert!(!to_do.contains(&Alg::ECSCHNORR), "{to_do:?}");
}

/// Without the `ecschnorr` feature, `TPM_CAP_ALGS` does not report `TPM_ALG_ECSCHNORR`, and TPM2_Sign
/// with an EC-Schnorr `inScheme` (sent as patched raw bytes, since the scheme does not marshal without
/// the feature) fails with `TPM_RC_SCHEME + RC_P2`.
#[cfg(not(feature = "ecschnorr"))]
#[test]
#[allow(deprecated)] // TPM2_Sign is deprecated upstream, but the TPM implements it.
fn capability_and_sign_omit_ecschnorr_without_the_feature() {
    use crate::_common::{
        CAP_ALGS, base_attrs, create_primary_returning_public, ecc_curve_template,
        execute_with_corrupted_bytes_status, get_cap, rc_p,
    };
    use tpm2::{Handle, Tpm2bDigest, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmtEccScheme};

    let mut sim = testing::tpm::Tpm::new();
    let (_, data) = get_cap(&mut sim, CAP_ALGS, 0x001c, 1).unwrap();
    let count = u32::from_be_bytes(data[0..4].try_into().unwrap());
    if count > 0 {
        assert_ne!(
            u16::from_be_bytes([data[4], data[5]]),
            0x001c,
            "TPM_ALG_ECSCHNORR listed"
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
        params[34..36].copy_from_slice(&0x001cu16.to_be_bytes());
    })
    .err();
    assert_eq!(rc, Some(rc_p(tpm2::errors::TpmRc::SCHEME, 2)));
}
