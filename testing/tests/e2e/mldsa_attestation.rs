//! Attestation with ML-DSA signing keys (TPM 2.0 v185): TPM2_Certify, TPM2_CertifyCreation,
//! TPM2_Quote, TPM2_GetTime, TPM2_GetSessionAuditDigest, TPM2_GetCommandAuditDigest and
//! TPM2_NV_Certify sign the whole marshalled `TPMS_ATTEST` with pure ML-DSA and an empty context
//! (verified client-side with FIPS 204), accept an inScheme of TPM_ALG_NULL or TPM_ALG_MLDSA and
//! reject other schemes; the PCR digest of a quote and the NV digest of TPM2_NV_Certify use the
//! signing key's nameAlg (errata). HashML-DSA attestation keys are tested with the `hash_mldsa`
//! feature only.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{
    Certify, CertifyCreation, GetCommandAuditDigest, GetSessionAuditDigest, GetTime, Quote,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bData, TpmSt, TpmaNv, TpmiAlgHash, TpmiMldsaParms, TpmlPcrSelection, TpmsAttest,
    TpmtPublic, TpmtSigScheme, TpmtSignature, TpmuAttest,
};

/// Qualifying data of every attestation in this file.
const QUALIFYING_DATA: &[u8] = b"pqc-attestation";

/// Verifies that `signature` is a pure ML-DSA signature (empty context) of the marshalled
/// `attest` by the ML-DSA key `public`, of the parameter set's signature size, and that a
/// modified attestation does not verify.
fn assert_mldsa_attestation(
    public: &TpmtPublic<'_>,
    attest: &TpmsAttest<'_>,
    signature: &Option<TpmtSignature<'_>>,
) {
    let (parameter_set, public_key) = mldsa_public_key(public);
    let signature = mldsa_signature_bytes(signature.as_ref().expect("no signature"));
    assert_eq!(signature.len(), parameter_set.signature_bytes());
    let message = marshal_to_vec(attest);
    assert!(
        mldsa_client_verify(parameter_set, &public_key, &message, &signature),
        "{parameter_set:?}: attestation signature does not verify"
    );
    let mut modified = message.clone();
    *modified.last_mut().unwrap() ^= 1;
    assert!(!mldsa_client_verify(
        parameter_set,
        &public_key,
        &modified,
        &signature
    ));
    assert_eq!(attest.extra_data.get_buffer(), QUALIFYING_DATA);
}

/// Creates a primary ML-DSA key from `template`; returns its handle and public area.
fn mldsa_key(sim: &mut Tpm, template: TpmtPublic<'static>) -> (Handle, TpmtPublic<'static>) {
    create_primary_returning_public(sim, template, &[])
}

/// TPM2_Certify with `sign_handle` certifying `object_handle`.
fn certify(
    sim: &mut Tpm,
    object_handle: Handle,
    sign_handle: Handle,
    in_scheme: Option<TpmtSigScheme>,
) -> Result<(TpmsAttest<'static>, Option<TpmtSignature<'static>>), u32> {
    execute_with_password_sessions(
        sim,
        &Certify {
            object_handle,
            sign_handle,
            qualifying_data: Tpm2bData::from_bytes(QUALIFYING_DATA).unwrap(),
            in_scheme,
        },
        2,
        &[],
    )
    .map(|rsp| (rsp.certify_info.0, rsp.signature))
}

/// TPM2_Certify with an ML-DSA key of every parameter set (inScheme TPM_ALG_NULL and
/// TPM_ALG_MLDSA) returns a pure ML-DSA signature of the attestation structure.
#[test]
fn certify_signs_with_pure_mldsa() {
    let mut sim = Tpm::new();
    for parameter_set in MLDSA_PARAMETER_SETS {
        let (key, public) = mldsa_key(&mut sim, mldsa_signing_public(parameter_set));
        for in_scheme in [None, Some(TpmtSigScheme::Mldsa)] {
            let (attest, signature) = certify(&mut sim, key, key, in_scheme)
                .unwrap_or_else(|rc| panic!("{parameter_set:?} {in_scheme:?}: {rc:#x}"));
            assert_eq!(attest.attested_type(), TpmSt::ATTEST_CERTIFY);
            assert_mldsa_attestation(&public, &attest, &signature);
        }
        flush_context(&mut sim, key).unwrap();
    }
}

/// TPM2_Certify with an ML-DSA key and an inScheme of another algorithm (ECDSA, RSASSA) fails
/// with TPM_RC_SCHEME + P2.
#[test]
fn certify_rejects_other_schemes() {
    let mut sim = Tpm::new();
    let (key, _) = mldsa_key(&mut sim, mldsa_signing_public(TpmiMldsaParms::Mldsa44));
    for in_scheme in [
        TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256),
        TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256),
    ] {
        assert_eq!(
            certify(&mut sim, key, key, Some(in_scheme)).map(|_| ()),
            Err(TpmRc::SCHEME.with(Position::parameter(2)).get()),
            "{in_scheme:?}"
        );
    }
}

/// A restricted ML-DSA key (an attestation key) certifies another object.
#[test]
fn restricted_key_certifies_other_object() {
    let mut sim = Tpm::new();
    let (key, public) = mldsa_key(&mut sim, mldsa_attestation_public(TpmiMldsaParms::Mldsa65));
    let (object, _) =
        create_primary_returning_public(&mut sim, mlkem_or_ecc_object_template(), &[]);
    let (attest, signature) = certify(&mut sim, object, key, None).unwrap();
    let TpmuAttest::Certify(info) = attest.attested else {
        panic!("not a certify attestation");
    };
    assert_eq!(info.name, read_public_name(&mut sim, object));
    assert_mldsa_attestation(&public, &attest, &signature);
}

/// An object to certify: an ECC signing key.
fn mlkem_or_ecc_object_template() -> TpmtPublic<'static> {
    ecc_template(
        base_attrs() | tpm2::TpmaObject::SIGN_ENCRYPT,
        Some(tpm2::TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
    )
}

/// TPM2_Quote with a restricted ML-DSA key whose nameAlg is SHA-384 signs the attestation
/// with pure ML-DSA, and its pcrDigest is the SHA-384 digest (the key's nameAlg) of the selected
/// SHA-256 PCR values.
#[test]
fn quote_signs_with_pure_mldsa_and_name_alg_pcr_digest() {
    let mut sim = Tpm::new();
    let mut template = mldsa_attestation_public(TpmiMldsaParms::Mldsa44);
    template.name_alg = Some(TpmiAlgHash::Sha384);
    let (key, public) = mldsa_key(&mut sim, template);
    let pcr_select = pcr_selections(TpmiAlgHash::Sha256, &[1, 2]);
    let rsp = execute_with_password_sessions(
        &mut sim,
        &Quote {
            sign_handle: key,
            qualifying_data: Tpm2bData::from_bytes(QUALIFYING_DATA).unwrap(),
            in_scheme: None,
            pcr_select,
        },
        1,
        &[],
    )
    .unwrap();
    let attest = rsp.quoted.0;
    assert_mldsa_attestation(&public, &attest, &rsp.signature);
    let TpmuAttest::Quote(info) = attest.attested else {
        panic!("not a quote");
    };
    // PCRs 1 and 2 of the SHA-256 bank are all zero after TPM2_Startup.
    assert_eq!(
        info.pcr_digest.get_buffer(),
        compute_hash(TpmiAlgHash::Sha384, &[&[0u8; 64]]).as_slice()
    );
}

/// TPM2_Quote with an ML-DSA key and an ECDSA inScheme fails with TPM_RC_SCHEME + P2.
#[test]
fn quote_rejects_other_schemes() {
    let mut sim = Tpm::new();
    let (key, _) = mldsa_key(&mut sim, mldsa_attestation_public(TpmiMldsaParms::Mldsa44));
    let rc = execute_with_password_sessions(
        &mut sim,
        &Quote {
            sign_handle: key,
            qualifying_data: Tpm2bData::default(),
            in_scheme: Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
            pcr_select: TpmlPcrSelection::default(),
        },
        1,
        &[],
    )
    .map(|_| ());
    assert_eq!(rc, Err(TpmRc::SCHEME.with(Position::parameter(2)).get()));
}

/// TPM2_GetTime with an ML-DSA key signs the time attestation with pure ML-DSA.
#[test]
fn get_time_signs_with_pure_mldsa() {
    let mut sim = Tpm::new();
    let (key, public) = mldsa_key(&mut sim, mldsa_signing_public(TpmiMldsaParms::Mldsa65));
    let rsp = execute_with_password_sessions(
        &mut sim,
        &GetTime {
            privacy_admin_handle: Handle::RH_ENDORSEMENT,
            sign_handle: key,
            qualifying_data: Tpm2bData::from_bytes(QUALIFYING_DATA).unwrap(),
            in_scheme: Some(TpmtSigScheme::Mldsa),
        },
        2,
        &[],
    )
    .unwrap();
    assert_eq!(rsp.time_info.0.attested_type(), TpmSt::ATTEST_TIME);
    assert_mldsa_attestation(&public, &rsp.time_info.0, &rsp.signature);
}

/// TPM2_GetSessionAuditDigest and TPM2_GetCommandAuditDigest with an ML-DSA key sign their
/// audit attestations with pure ML-DSA.
#[test]
fn audit_digests_sign_with_pure_mldsa() {
    let mut sim = Tpm::new();
    let (key, public) = mldsa_key(&mut sim, mldsa_signing_public(TpmiMldsaParms::Mldsa44));
    // An HMAC session that audited one command (continueSession | audit).
    let mut session = start_hmac_session(&mut sim);
    audited_get_capability(&mut sim, &mut session, 0x81);
    let rsp = execute_with_password_sessions(
        &mut sim,
        &GetSessionAuditDigest {
            privacy_admin_handle: Handle::RH_ENDORSEMENT,
            sign_handle: key,
            session_handle: session.session_handle,
            qualifying_data: Tpm2bData::from_bytes(QUALIFYING_DATA).unwrap(),
            in_scheme: None,
        },
        2,
        &[],
    )
    .unwrap();
    assert_eq!(
        rsp.audit_info.0.attested_type(),
        TpmSt::ATTEST_SESSION_AUDIT
    );
    assert_mldsa_attestation(&public, &rsp.audit_info.0, &rsp.signature);

    let rsp = execute_with_password_sessions(
        &mut sim,
        &GetCommandAuditDigest {
            privacy_handle: Handle::RH_ENDORSEMENT,
            sign_handle: key,
            qualifying_data: Tpm2bData::from_bytes(QUALIFYING_DATA).unwrap(),
            in_scheme: None,
        },
        2,
        &[],
    )
    .unwrap();
    assert_eq!(
        rsp.audit_info.0.attested_type(),
        TpmSt::ATTEST_COMMAND_AUDIT
    );
    assert_mldsa_attestation(&public, &rsp.audit_info.0, &rsp.signature);
}

/// TPM2_CertifyCreation with an ML-DSA key signs the creation attestation with pure ML-DSA.
#[test]
fn certify_creation_signs_with_pure_mldsa() {
    let mut sim = Tpm::new();
    let (key, public) = mldsa_key(&mut sim, mldsa_signing_public(TpmiMldsaParms::Mldsa44));
    let (_, created) = try_create_primary_in(
        &mut sim,
        Handle::RH_OWNER,
        mlkem_or_ecc_object_template(),
        &[],
    )
    .unwrap();
    let rsp = execute_with_password_sessions(
        &mut sim,
        &CertifyCreation {
            sign_handle: key,
            object_handle: created.object_handle,
            qualifying_data: Tpm2bData::from_bytes(QUALIFYING_DATA).unwrap(),
            creation_hash: created.creation_hash,
            in_scheme: None,
            creation_ticket: created.creation_ticket,
        },
        1,
        &[],
    )
    .unwrap();
    assert_eq!(rsp.certify_info.0.attested_type(), TpmSt::ATTEST_CREATION);
    assert_mldsa_attestation(&public, &rsp.certify_info.0, &rsp.signature);
}

/// TPM2_NV_Certify with an ML-DSA key whose nameAlg is SHA-384 signs the NV attestation with
/// pure ML-DSA, both for the contents (TPM_ST_ATTEST_NV) and for the digest of the whole index
/// (TPM_ST_ATTEST_NV_DIGEST, whose nvDigest is the SHA-384 digest of the contents).
#[test]
fn nv_certify_signs_with_pure_mldsa_and_name_alg_digest() {
    let mut sim = Tpm::new();
    let mut template = mldsa_signing_public(TpmiMldsaParms::Mldsa44);
    template.name_alg = Some(TpmiAlgHash::Sha384);
    let (key, public) = mldsa_key(&mut sim, template);
    let index = 0x0150_0020;
    let contents = b"post-quantum nv";
    define_nv(
        &mut sim,
        index,
        TpmaNv::AUTHWRITE | TpmaNv::AUTHREAD,
        contents.len() as u16,
    );
    nv_write(&mut sim, Handle(index), contents).unwrap();

    let attest = |sim: &mut Tpm, size: u16| {
        execute_with_password_sessions(
            sim,
            &tpm2::commands::NVCertify {
                sign_handle: key,
                auth_handle: Handle(index),
                nv_index: Handle(index),
                qualifying_data: Tpm2bData::from_bytes(QUALIFYING_DATA).unwrap(),
                in_scheme: None,
                size,
                offset: 0,
            },
            2,
            &[],
        )
        .unwrap()
    };
    let rsp = attest(&mut sim, contents.len() as u16);
    assert_mldsa_attestation(&public, &rsp.certify_info.0, &rsp.signature);
    let TpmuAttest::Nv(info) = rsp.certify_info.0.attested else {
        panic!("not an NV attestation");
    };
    assert_eq!(info.nv_contents.get_buffer(), contents);

    let rsp = attest(&mut sim, 0);
    assert_mldsa_attestation(&public, &rsp.certify_info.0, &rsp.signature);
    let TpmuAttest::NvDigest(info) = rsp.certify_info.0.attested else {
        panic!("not an NV digest attestation");
    };
    assert_eq!(
        info.nv_digest.get_buffer(),
        compute_hash(TpmiAlgHash::Sha384, &[contents]).as_slice()
    );
}

/// TPM2_Certify with a HashML-DSA key signs the digest of the attestation structure (computed
/// with the key's hash algorithm) with HashML-DSA and an empty context.
#[cfg(feature = "hash_mldsa")]
#[test]
fn certify_signs_with_hash_mldsa() {
    use tpm2::{PublicParmsAndId, Tpm2bDigest, Tpm2bPublicKeyMldsa, TpmsHashMldsaParms};
    let mut sim = Tpm::new();
    for (parameter_set, hash_alg) in [
        (TpmiMldsaParms::Mldsa44, TpmiAlgHash::Sha256),
        (TpmiMldsaParms::Mldsa87, TpmiAlgHash::Sha384),
    ] {
        let template = TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: base_attrs() | tpm2::TpmaObject::SIGN_ENCRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::HashMldsa(
                TpmsHashMldsaParms {
                    parameter_set,
                    hash_alg,
                },
                Tpm2bPublicKeyMldsa::default(),
            ),
        };
        let (key, public) = mldsa_key(&mut sim, template);
        let (attest, signature) = certify(&mut sim, key, key, None).unwrap();
        let Some(TpmtSignature::HashMldsa(signature)) = signature else {
            panic!("not a HashML-DSA signature: {signature:?}");
        };
        assert_eq!(signature.hash, hash_alg);
        let (_, public_key) = mldsa_public_key(&public);
        let digest = compute_hash(hash_alg, &[&marshal_to_vec(&attest)]);
        let mu = hash_mldsa_mu(&public_key, hash_alg, &digest);
        assert!(mldsa_client_verify_mu(
            parameter_set,
            &public_key,
            &mu,
            signature.sig.get_buffer()
        ));
        flush_context(&mut sim, key).unwrap();
    }
}
