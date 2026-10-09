use crate::test_utils::marshal_to_slice;
use tpm2::errors::TpmRc;

use crate::test_utils::{
    CmdHeader, RespHeader, execute_get_capability, execute_get_session_audit_digest,
    execute_with_corrupted_bytes_status, execute_with_hmac_sessions_raw,
    execute_with_hmac_sessions_status, execute_with_password_sessions,
    execute_with_password_sessions_status, flush_context, start_auth_session,
};
use tpm2::Marshal;
use tpm2::Unmarshal;
use tpm2::commands::{
    Certify, CertifyHandles, Command, CreatePrimary, CreatePrimaryHandles, GetCapability,
    GetSessionAuditDigest, GetSessionAuditDigestHandles,
};
use tpm2::{Handle, TpmCap, TpmCc, TpmEccCurve, TpmPt, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bNonce,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject, TpmaSession, TpmiAlgHash, TpmiRsaKeyBits,
    TpmiStCommandTag, TpmsAuthCommand, TpmsEccParms, TpmsEccPoint, TpmsRsaParms,
    TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtSigScheme,
};
use tpm2_simulator::{Simulator, create_simulator};

// =========================================================================
// Helpers
// =========================================================================

fn execute_raw_transact(tpm: &mut Simulator<'_>, cmd_bytes: &[u8]) -> Result<(), u32> {
    let mut resp_buffer = [0u8; 4096];
    tpm.transact(cmd_bytes, &mut resp_buffer).unwrap();

    let mut slice = &resp_buffer[..];
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }
    Ok(())
}

fn create_signing_key_ecc(
    sim: &mut Simulator<'_>,
    auth: &[u8],
) -> (Handle, tpm2::Tpm2bName<'static>) {
    create_signing_key_ecc_with_unique(sim, auth, 0)
}

fn create_signing_key_ecc_with_unique(
    sim: &mut Simulator<'_>,
    auth: &[u8],
    unique: u8,
) -> (Handle, tpm2::Tpm2bName<'static>) {
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(&[unique; 32]))
                    .unwrap(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let mut user_auth = Tpm2bAuth::default();
    if !auth.is_empty() {
        user_auth = Tpm2bAuth::from_bytes(auth).unwrap();
    }

    let sensitive_create = TpmsSensitiveCreate {
        user_auth,
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[])
            .expect("could not generate ECC signing key");

    (rsp_handles.object_handle, rsp.name)
}

fn create_non_signing_key_rsa(sim: &mut Simulator<'_>) -> (Handle, tpm2::Tpm2bName<'static>) {
    // A key without SIGN_ENCRYPT, e.g. DECRYPT only
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[])
            .expect("could not generate RSA non-signing key");

    (rsp_handles.object_handle, rsp.name)
}

// =========================================================================
// GetCapability Tests
// =========================================================================

#[test]
fn test_get_capability_unknown_capability() {
    let mut sim = create_simulator!();

    // Use an unsupported capability tag (e.g. 0x9999)
    let get_cmd = GetCapability {
        capability: TpmCap::Algs,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };

    let resp = execute_with_corrupted_bytes_status(&mut sim, &get_cmd, (), 0, &[], |buf| {
        buf[0..4].copy_from_slice(&0x9999u32.to_be_bytes());
    });
    // Invalid capability fails unmarshalling with TPM_RC_VALUE + TPM_RC_P + TPM_RC_1
    assert_eq!(
        resp.err(),
        Some(
            TpmRc::VALUE
                .with(tpm2::errors::Position::parameter(1))
                .get()
        )
    );
}

#[test]
fn test_get_capability_property_count_zero() {
    let mut sim = create_simulator!();

    let get_cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 0,
    };

    let mut resp_buffer = [0u8; 4096];
    let (get_resp, _) = execute_get_capability(&mut sim, &get_cmd, (), 0, &[], &mut resp_buffer)
        .expect("property_count = 0 should succeed and return more_data = YES per TPM 2.0 Spec");
    assert!(get_resp.more_data);
}

#[test]
fn test_get_capability_property_count_huge() {
    let mut sim = create_simulator!();

    let get_cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: u32::MAX,
    };

    let mut resp_buffer = [0u8; 4096];
    let (rsp, _) = execute_get_capability(&mut sim, &get_cmd, (), 0, &[], &mut resp_buffer)
        .expect("Should handle property_count = u32::MAX gracefully");
    // It should have returned properties without panicking
    assert!(!rsp.more_data);
}

#[test]
fn test_get_capability_with_trailing_garbage() {
    let mut sim = create_simulator!();

    // Marshal GetCapability
    let get_cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };

    let mut cmd_bytes = [0u8; 100];
    let header = CmdHeader {
        tag: TpmiStCommandTag::NoSessions,
        size: 0,
        code: TpmCc::GetCapability,
    };

    let mut written = header.marshal((&mut cmd_bytes[0..10]).try_into().unwrap());
    written += marshal_to_slice(&(get_cmd), &mut cmd_bytes[written..]);

    // Add 1 extra byte of garbage
    cmd_bytes[written] = 0xAA;
    written += 1;

    // Update size in header
    let mut size_bytes = [0u8; 4];
    size_bytes.copy_from_slice(&(written as u32).to_be_bytes());
    cmd_bytes[2..6].copy_from_slice(&size_bytes);

    let resp = execute_raw_transact(&mut sim, &cmd_bytes[..written]);
    // Expect TPM_RC_SIZE (0x95)
    assert_eq!(resp.err(), Some(0x95));
}

// =========================================================================
// GetSessionAuditDigest Tests
// =========================================================================

#[test]
fn test_get_session_audit_digest_invalid_privacy_admin() {
    let mut sim = create_simulator!();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    // Start a session to audit
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Use invalid privacy admin handle (e.g. transient 0x80000000)
    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle(0x80000000),
        sign_handle: ak_handle,
        session_handle: sess.session_handle,
    };

    let resp =
        execute_with_password_sessions_status(&mut sim, &get_audit_cmd, get_audit_handles, 2, &[]);
    // SPEC EXPECTS: TPM_RC_VALUE for handle 1 (0x184)
    assert_eq!(resp.err(), Some(0x184));

    flush_context(&mut sim, ak_handle).unwrap();
}

#[test]
fn test_get_session_audit_digest_non_existent_signer() {
    let mut sim = create_simulator!();

    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Use non-existent sign key handle 0x80ffffff
    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle(0x8000000E),
        session_handle: sess.session_handle,
    };

    let resp =
        execute_with_password_sessions_status(&mut sim, &get_audit_cmd, get_audit_handles, 2, &[]);
    // SPEC EXPECTS: TPM_RC_REFERENCE_Hx for invalid transient sign_handle (ReferenceH1 = 2321)
    assert_eq!(resp.err(), Some(2321));
}

#[test]
fn test_get_session_audit_digest_incorrect_signer_type() {
    let mut sim = create_simulator!();
    // Create a key that is NOT a signing key (e.g. DECRYPT only)
    let (non_sign_handle, _) = create_non_signing_key_rsa(&mut sim);

    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: non_sign_handle,
        session_handle: sess.session_handle,
    };

    let resp =
        execute_with_password_sessions_status(&mut sim, &get_audit_cmd, get_audit_handles, 2, &[]);
    assert!(resp.is_err());

    flush_context(&mut sim, non_sign_handle).unwrap();
}

#[test]
fn test_get_session_audit_digest_non_existent_session() {
    let mut sim = create_simulator!();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Use non-existent session handle 0x0200000e
    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: ak_handle,
        session_handle: Handle(0x0200000e),
    };

    let resp =
        execute_with_password_sessions_status(&mut sim, &get_audit_cmd, get_audit_handles, 2, &[]);
    // C EntityGetLoadStatus: an unloaded HMAC session handle yields
    // TPM_RC_REFERENCE_H0 + 2 (0x912) for the third handle (Entity.c:146-149).
    assert_eq!(resp.err(), Some(0x912));

    flush_context(&mut sim, ak_handle).unwrap();
}

#[test]
fn test_get_session_audit_digest_missing_auth() {
    let mut sim = create_simulator!();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: ak_handle,
        session_handle: sess.session_handle,
    };

    // Provide only 1 authorization session instead of 2
    let resp =
        execute_with_password_sessions_status(&mut sim, &get_audit_cmd, get_audit_handles, 1, &[]);
    // Expect TPM_RC_AUTH_MISSING (0x125)
    assert_eq!(resp.err(), Some(0x125));

    flush_context(&mut sim, ak_handle).unwrap();
}

// =========================================================================
// Certify Tests
// =========================================================================

#[test]
fn test_certify_non_existent_object() {
    let mut sim = create_simulator!();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    let certify_cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Use non-existent object handle 0x80ffffff (handle 1)
    let certify_handles = CertifyHandles {
        object_handle: Handle(0x8000000E),
        sign_handle: ak_handle,
    };

    let resp =
        execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles, 2, &[]);
    // SPEC EXPECTS: TPM_RC_REFERENCE_Hx for invalid transient object_handle (ReferenceH0 = 2320)
    assert_eq!(resp.err(), Some(2320));

    flush_context(&mut sim, ak_handle).unwrap();
}

#[test]
fn test_certify_non_existent_signer() {
    let mut sim = create_simulator!();
    let (obj_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    let certify_cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Use non-existent sign handle 0x8000000E (handle 2)
    let certify_handles = CertifyHandles {
        object_handle: obj_handle,
        sign_handle: Handle(0x8000000E),
    };

    let resp =
        execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles, 2, &[]);
    // SPEC EXPECTS: TPM_RC_REFERENCE_Hx for invalid transient sign_handle (ReferenceH1 = 2321)
    assert_eq!(resp.err(), Some(2321));

    flush_context(&mut sim, obj_handle).unwrap();
}

#[test]
fn test_certify_incorrect_signer_type() {
    let mut sim = create_simulator!();
    let (obj_handle, _) = create_signing_key_ecc(&mut sim, &[]);
    let (non_sign_handle, _) = create_non_signing_key_rsa(&mut sim);

    let certify_cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let certify_handles = CertifyHandles {
        object_handle: obj_handle,
        sign_handle: non_sign_handle,
    };

    let resp =
        execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles, 2, &[]);
    assert!(resp.is_err());

    flush_context(&mut sim, obj_handle).unwrap();
    flush_context(&mut sim, non_sign_handle).unwrap();
}

#[test]
fn test_certify_missing_auth() {
    let mut sim = create_simulator!();
    let (obj_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 0);
    let (ak_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 1);

    let certify_cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let certify_handles = CertifyHandles {
        object_handle: obj_handle,
        sign_handle: ak_handle,
    };

    // Provide only 1 authorization session instead of 2
    let resp =
        execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles, 1, &[]);
    // Expect TPM_RC_AUTH_MISSING (0x125)
    assert_eq!(resp.err(), Some(0x125));

    flush_context(&mut sim, obj_handle).unwrap();
    flush_context(&mut sim, ak_handle).unwrap();
}

// =========================================================================
// Unexpected Signature Scheme Tests
// =========================================================================

#[test]
fn test_certify_scheme_mismatch_ecc_with_rsa_scheme() {
    let mut sim = create_simulator!();
    let (obj_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 0);
    let (ak_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 1);

    // Signer key is ECC (ECDSA), but we request RSASSA signature scheme!
    let certify_cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
    };

    let certify_handles = CertifyHandles {
        object_handle: obj_handle,
        sign_handle: ak_handle,
    };

    let resp =
        execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles, 2, &[]);
    assert!(resp.is_err());
    let err = resp.err().unwrap();
    // TPM_RC_SCHEME + RC_Certify_inScheme (P2).
    assert_eq!(err, 0x2D2);

    flush_context(&mut sim, obj_handle).unwrap();
    flush_context(&mut sim, ak_handle).unwrap();
}

// =========================================================================
// M1 Remediation Stress Tests
// =========================================================================

fn extend_audit_digest_local(
    current_digest: &mut [u8; 32],
    cmd_code: TpmCc,
    handle_names: &[&[u8]],
    cmd_params: &[u8],
    resp_params: &[u8],
) {
    use sha2::Digest as _;
    // cpHash
    let mut cp_hasher = sha2::Sha256::new();
    cp_hasher.update(cmd_code.code().to_be_bytes());
    for name in handle_names {
        cp_hasher.update(name);
    }
    cp_hasher.update(cmd_params);
    let cp_hash = cp_hasher.finalize();

    // rpHash
    let mut rp_hasher = sha2::Sha256::new();
    rp_hasher.update(0u32.to_be_bytes()); // responseCode = TPM_RC_SUCCESS (0)
    rp_hasher.update(cmd_code.code().to_be_bytes());
    rp_hasher.update(resp_params);
    let rp_hash = rp_hasher.finalize();

    // extend digest: digest = SHA256(digest || cpHash || rpHash)
    let mut extend_hasher = sha2::Sha256::new();
    extend_hasher.update(current_digest.as_slice());
    extend_hasher.update(cp_hash.as_slice());
    extend_hasher.update(rp_hash.as_slice());
    current_digest.copy_from_slice(&extend_hasher.finalize());
}

#[test]
fn test_audit_reset_behavior() {
    let mut sim = create_simulator!();

    // Create the AK for audit signing
    let (ak_handle, _ak_name) = create_signing_key_ecc(&mut sim, &[]);

    // 1. Start audit session
    let mut sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Set AUDIT attribute
    sess.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;

    // 2. Run a command with audit session (should initialize and extend audit digest)
    let get_cmd_1 = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };
    let mut sessions = [sess.clone()];
    let (_get_rsp_1, _) =
        execute_with_hmac_sessions_raw(&mut sim, &get_cmd_1, (), &[], &mut sessions, &[&[]])
            .unwrap();
    sess = sessions[0].clone();

    // Verify audit digest is non-zero
    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: ak_handle,
        session_handle: sess.session_handle,
    };
    let mut resp_buffer_1 = [0u8; 4096];
    let (get_audit_rsp_1, _) = execute_get_session_audit_digest(
        &mut sim,
        &get_audit_cmd,
        get_audit_handles,
        2,
        &[],
        &mut resp_buffer_1,
    )
    .unwrap();
    let attest_1 = get_audit_rsp_1.audit_info.0;
    let aud_info_1 = match attest_1.attested {
        tpm2::TpmuAttest::SessionAudit(info) => info,
        _ => panic!("Expected SessionAudit"),
    };
    let digest_1 = aud_info_1.session_digest.get_buffer().to_vec();
    assert_ne!(digest_1, vec![0u8; 32]);

    // 3. Run a second command with audit session, but WITHOUT AUDIT_RESET attribute.
    // It should extend the digest further.
    let get_cmd_2 = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::LEVEL),
        property_count: 1,
    };
    let mut sessions = [sess.clone()];
    let (_get_rsp_2, _) =
        execute_with_hmac_sessions_raw(&mut sim, &get_cmd_2, (), &[], &mut sessions, &[&[]])
            .unwrap();
    sess = sessions[0].clone();

    let mut resp_buffer_2 = [0u8; 4096];
    let (get_audit_rsp_2, _) = execute_get_session_audit_digest(
        &mut sim,
        &get_audit_cmd,
        get_audit_handles,
        2,
        &[],
        &mut resp_buffer_2,
    )
    .unwrap();
    let attest_2 = get_audit_rsp_2.audit_info.0;
    let aud_info_2 = match attest_2.attested {
        tpm2::TpmuAttest::SessionAudit(info) => info,
        _ => panic!("Expected SessionAudit"),
    };
    let digest_2 = aud_info_2.session_digest.get_buffer().to_vec();
    assert_ne!(digest_2, vec![0u8; 32]);
    assert_ne!(digest_2, digest_1);

    // 4. Run a third command WITH AUDIT_RESET attribute (0x04) set in attributes.
    // The TPM should reset the session's audit digest to zero, then extend it with only the third command.
    sess.attributes = TpmaSession::AUDIT | TpmaSession::AUDIT_RESET | TpmaSession::CONTINUE_SESSION;
    let mut sessions = [sess.clone()];
    let (get_rsp_3_bytes, _) =
        execute_with_hmac_sessions_raw(&mut sim, &get_cmd_2, (), &[], &mut sessions, &[&[]])
            .unwrap();
    sess = sessions[0].clone();

    let mut resp_buffer_3 = [0u8; 4096];
    let (get_audit_rsp_3, _) = execute_get_session_audit_digest(
        &mut sim,
        &get_audit_cmd,
        get_audit_handles,
        2,
        &[],
        &mut resp_buffer_3,
    )
    .unwrap();
    let attest_3 = get_audit_rsp_3.audit_info.0;
    let aud_info_3 = match attest_3.attested {
        tpm2::TpmuAttest::SessionAudit(info) => info,
        _ => panic!("Expected SessionAudit"),
    };
    let digest_3 = aud_info_3.session_digest.get_buffer().to_vec();
    assert_ne!(digest_3, vec![0u8; 32]);

    // The digest should be different from digest_2 because of the reset.
    assert_ne!(digest_3, digest_2);

    // Let's manually compute what digest_3 should be.
    // Since it was reset, digest_3 should be equal to the extension of a zero digest with command 3.
    let mut expected_digest_3 = [0u8; 32];

    let mut cmd_buf = [0u8; 512];
    let cmd_len = marshal_to_slice(&get_cmd_2, &mut cmd_buf);

    extend_audit_digest_local(
        &mut expected_digest_3,
        GetCapability::CMD_CODE,
        &[],
        &cmd_buf[..cmd_len],
        &get_rsp_3_bytes,
    );

    assert_eq!(digest_3.as_slice(), expected_digest_3.as_slice());

    // 5. Run a fourth command WITHOUT AUDIT_RESET attribute (0x04) set in attributes.
    // The TPM should extend expected_digest_3.
    sess.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;
    let mut sessions = [sess.clone()];
    let (get_rsp_4_bytes, _) =
        execute_with_hmac_sessions_raw(&mut sim, &get_cmd_2, (), &[], &mut sessions, &[&[]])
            .unwrap();
    let _final_sess = sessions[0].clone();

    let mut resp_buffer_4 = [0u8; 4096];
    let (get_audit_rsp_4, _) = execute_get_session_audit_digest(
        &mut sim,
        &get_audit_cmd,
        get_audit_handles,
        2,
        &[],
        &mut resp_buffer_4,
    )
    .unwrap();
    let attest_4 = get_audit_rsp_4.audit_info.0;
    let aud_info_4 = match attest_4.attested {
        tpm2::TpmuAttest::SessionAudit(info) => info,
        _ => panic!("Expected SessionAudit"),
    };
    let digest_4 = aud_info_4.session_digest.get_buffer().to_vec();
    assert_ne!(digest_4, vec![0u8; 32]);
    assert_ne!(digest_4, digest_3);

    // Compute expected digest 4:
    let mut expected_digest_4 = expected_digest_3;
    let mut cmd_buf_4 = [0u8; 512];
    let cmd_len_4 = marshal_to_slice(&get_cmd_2, &mut cmd_buf_4);

    extend_audit_digest_local(
        &mut expected_digest_4,
        GetCapability::CMD_CODE,
        &[],
        &cmd_buf_4[..cmd_len_4],
        &get_rsp_4_bytes,
    );

    assert_eq!(digest_4.as_slice(), expected_digest_4.as_slice());

    flush_context(&mut sim, ak_handle).unwrap();
}

#[test]
fn test_get_session_audit_digest_parameter_errors() {
    let mut sim = create_simulator!();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: ak_handle,
        session_handle: sess.session_handle,
    };

    // Construct raw transaction bytes:
    let mut cmd_buffer = [0u8; 4096];
    let mut cmd_header = CmdHeader {
        tag: TpmiStCommandTag::Sessions,
        size: 0,
        code: TpmCc::GetSessionAuditDigest,
    };
    let mut written = cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());
    written += marshal_to_slice(&(get_audit_handles), &mut cmd_buffer[written..]);

    // 2 password sessions
    let auth_cmd = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_buffer = [0u8; 1024];
    let mut auth_written = 0;
    for _ in 0..2 {
        auth_written += marshal_to_slice(&(auth_cmd), &mut auth_buffer[auth_written..]);
    }
    written += marshal_to_slice(&(auth_written as u32), &mut cmd_buffer[written..]);
    cmd_buffer[written..written + auth_written].copy_from_slice(&auth_buffer[..auth_written]);
    written += auth_written;

    // Parameters:
    // qualifying_data: size 67 (exceeds max size 66), followed by 67 bytes of zero
    let size_67 = 67u16;
    written += marshal_to_slice(&(size_67), &mut cmd_buffer[written..]);
    cmd_buffer[written..written + 67].fill(0);
    written += 67;
    // in_scheme: Null
    let in_scheme: Option<TpmtSigScheme> = None;
    written += marshal_to_slice(&(in_scheme), &mut cmd_buffer[written..]);

    // Update size in header
    cmd_header.size = written as u32;
    let mut header_buf = [0u8; 10];
    cmd_header.marshal(&mut header_buf);
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    // Transact
    let mut resp_buffer = [0u8; 4096];
    sim.transact(&cmd_buffer[..written], &mut resp_buffer)
        .unwrap();

    let mut slice = &resp_buffer[..];
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();

    assert_eq!(resp_header.rc, 0x1D5); // TPM_RC_SIZE + TPM_RC_P + TPM_RC_1 (0x1D5) because parameter 1 unmarshal failed

    flush_context(&mut sim, ak_handle).unwrap();
}

#[test]
fn test_get_session_audit_digest_scheme_mismatch() {
    let mut sim = create_simulator!();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    let mut sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    sess.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;

    let get_cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };
    let mut sessions = [sess.clone()];
    execute_with_hmac_sessions_status(&mut sim, &get_cmd, (), &[], &mut sessions, &[&[]]).unwrap();
    let sess = &sessions[0];

    // Signer key is ECC (ECDSA), but we request RSASSA signature scheme!
    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
    };

    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: ak_handle,
        session_handle: sess.session_handle,
    };

    let resp =
        execute_with_password_sessions_status(&mut sim, &get_audit_cmd, get_audit_handles, 2, &[]);
    assert!(resp.is_err());
    let err = resp.err().unwrap();
    // Signer key scheme mismatch.
    // TPM_RC_SCHEME + RC_GetSessionAuditDigest_inScheme (P2).
    assert_eq!(err, 0x2D2);

    flush_context(&mut sim, ak_handle).unwrap();
}

#[test]
fn test_certify_parameter_errors() {
    let mut sim = create_simulator!();
    let (obj_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 0);
    let (ak_handle, _) = create_signing_key_ecc_with_unique(&mut sim, &[], 1);

    let certify_handles = CertifyHandles {
        object_handle: obj_handle,
        sign_handle: ak_handle,
    };

    // Construct raw transaction bytes:
    let mut cmd_buffer = [0u8; 4096];
    let mut cmd_header = CmdHeader {
        tag: TpmiStCommandTag::Sessions,
        size: 0,
        code: TpmCc::Certify,
    };
    let mut written = cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());
    written += marshal_to_slice(&(certify_handles), &mut cmd_buffer[written..]);

    // 2 password sessions
    let auth_cmd = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_buffer = [0u8; 1024];
    let mut auth_written = 0;
    for _ in 0..2 {
        auth_written += marshal_to_slice(&(auth_cmd), &mut auth_buffer[auth_written..]);
    }
    written += marshal_to_slice(&(auth_written as u32), &mut cmd_buffer[written..]);
    cmd_buffer[written..written + auth_written].copy_from_slice(&auth_buffer[..auth_written]);
    written += auth_written;

    // Parameters:
    // qualifying_data: size 67 (exceeds max size 66), followed by 67 bytes of zero
    let size_67 = 67u16;
    written += marshal_to_slice(&(size_67), &mut cmd_buffer[written..]);
    cmd_buffer[written..written + 67].fill(0);
    written += 67;
    // in_scheme: Null
    let in_scheme: Option<TpmtSigScheme> = None;
    written += marshal_to_slice(&(in_scheme), &mut cmd_buffer[written..]);

    // Update size in header
    cmd_header.size = written as u32;
    let mut header_buf = [0u8; 10];
    cmd_header.marshal(&mut header_buf);
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    // Transact
    let mut resp_buffer = [0u8; 4096];
    sim.transact(&cmd_buffer[..written], &mut resp_buffer)
        .unwrap();

    let mut slice = &resp_buffer[..];
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();

    assert_eq!(resp_header.rc, 0x1D5); // TPM_RC_SIZE + TPM_RC_P + TPM_RC_1 (0x1D5) because parameter 1 unmarshal failed

    flush_context(&mut sim, obj_handle).unwrap();
    flush_context(&mut sim, ak_handle).unwrap();
}
