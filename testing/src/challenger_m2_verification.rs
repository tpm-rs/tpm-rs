use crate::test_utils::*;
use sha2::{Digest, Sha256};
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, PolicyAuthorize, PolicyAuthorizeHandles, PolicyGetDigest,
    PolicyGetDigestHandles, PolicySecret, PolicySecretHandles, Sign, SignHandles, StartAuthSession,
    StartAuthSessionHandles, VerifySignature, VerifySignatureHandles,
};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve, TpmSe};
use tpm2_simulator::{Simulator, create_simulator};

fn create_signing_key(sim: &mut Simulator<'_>) -> (Handle, Tpm2bName<'static>) {
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(ecc_parms, tpm2::TpmsEccPoint::default()),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_primary = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &create_primary, create_handles, 1, &[])
            .expect("could not call TPM2_CreatePrimary");
    (rsp_handles.object_handle, rsp.name)
}

#[test]
fn test_session_expiration_enforced() {
    let mut sim = create_simulator!();

    // 1. Start Policy session
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (start_rsp, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // 2. Call PolicySecret with expiration = -1 (which sets the timeout to 1 second)
    let policy_secret = PolicySecret {
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: -1, // 1 second timeout
    };
    let policy_secret_handles = PolicySecretHandles {
        auth_handle: Handle::RH_OWNER,
        policy_session: session_handle,
    };
    let _ = execute_with_password_sessions(&mut sim, &policy_secret, policy_secret_handles, 1, &[])
        .expect("PolicySecret failed");

    // Immediately the policy should still be valid. Let's verify by calling PolicyGetDigest
    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: session_handle,
    };
    assert!(
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).is_ok()
    );

    // 3. Wait for 1.5 seconds so that the session expires
    std::thread::sleep(std::time::Duration::from_millis(1500));

    // 4. Repeat PolicySecret with the same 1-second expiration. It should return
    // an error due to session expiration. (C PolicyOR does not check the
    // session timeout at all; it would fail with VALUE+P1 because the current
    // digest is not in the list. PolicySecret's expiration is checked against
    // the session start time: EXPIRED+P4, Policy_spt.c:36-39.)
    // With nonceTPM present, C measures the expiration from the session start
    // time (Policy_spt.c ComputeAuthTimeout); with an empty nonce it would be
    // relative to the current second and not reliably expired.
    let policy_secret = PolicySecret {
        nonce_tpm: start_rsp.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: -1,
    };
    let policy_secret_handles = PolicySecretHandles {
        auth_handle: Handle::RH_OWNER,
        policy_session: session_handle,
    };
    let res =
        execute_with_password_sessions(&mut sim, &policy_secret, policy_secret_handles, 1, &[]);
    assert!(
        res.is_err(),
        "Expected command to fail on expired session, but it succeeded!"
    );
    let err_code = res.err().unwrap();
    // TPM_RC_EXPIRED is 0x00000023, combined with session/parameter positions.
    // Let's verify that the base error code is EXPIRED (0x23).
    assert_eq!(
        err_code & 0x3F,
        0x23,
        "Expected expired error 0x23, got {:x}",
        err_code
    );
}

#[test]
fn test_ticket_forgery_fails() {
    let mut sim = create_simulator!();
    let (sk, sk_name) = create_signing_key(&mut sim);

    // Start a Policy session
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // Get the current policy digest (which is all zeros initially)
    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: session_handle,
    };
    let (digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();
    let approved_policy = digest_rsp.policy_digest;

    // 1. Try to use PolicyAuthorize with a forged ticket under NULL hierarchy
    // A forged ticket will have hierarchy RHNull, but random/guessed digest.
    let forged_ticket = TpmtTkVerified::Verified(
        Handle::RH_NULL,
        Tpm2bDigest::from_bytes(&[0xAA; 32]).unwrap(),
    );

    let policy_auth_cmd = PolicyAuthorize {
        approved_policy,
        policy_ref: Tpm2bNonce::default(),
        key_sign: sk_name,
        check_ticket: forged_ticket,
    };
    let policy_auth_handles = PolicyAuthorizeHandles {
        policy_session: session_handle,
    };

    let res =
        execute_with_password_sessions(&mut sim, &policy_auth_cmd, policy_auth_handles, 0, &[]);
    assert!(
        res.is_err(),
        "PolicyAuthorize should fail with a forged ticket!"
    );
    let err_code = res.err().unwrap();
    // Expected value error (0x04 or format-1 version)
    assert_eq!(
        err_code & 0x3F,
        0x04,
        "Expected value error 0x04, got {:x}",
        err_code
    );

    // 2. Try to use PolicyAuthorize with a forged ticket under Owner hierarchy
    let forged_owner_ticket = TpmtTkVerified::Verified(
        Handle::RH_OWNER,
        Tpm2bDigest::from_bytes(&[0xBB; 32]).unwrap(),
    );
    let policy_auth_cmd_owner = PolicyAuthorize {
        approved_policy,
        policy_ref: Tpm2bNonce::default(),
        key_sign: sk_name,
        check_ticket: forged_owner_ticket,
    };
    let res_owner = execute_with_password_sessions(
        &mut sim,
        &policy_auth_cmd_owner,
        policy_auth_handles,
        0,
        &[],
    );
    assert!(
        res_owner.is_err(),
        "PolicyAuthorize should fail with forged ticket under Owner hierarchy!"
    );

    // Cleanup keys
    flush_context(&mut sim, sk).unwrap();
}

#[test]
fn test_verify_signature_to_policy_authorize() {
    let mut sim = create_simulator!();
    let (sk, sk_name) = create_signing_key(&mut sim);

    // 1. Start Policy session to get the approved policy digest
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // Get policy digest
    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: session_handle,
    };
    let (digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();
    let approved_policy = digest_rsp.policy_digest;

    // 2. Compute aHash = hash(approvedPolicy || policyRef)
    // Here policyRef is empty.
    let mut hasher = Sha256::new();
    hasher.update(approved_policy.get_buffer());
    // policyRef is empty, so nothing to update for policyRef
    let a_hash = hasher.finalize();

    // 3. Sign the aHash using Sign command on the signing key
    let sign_cmd = Sign {
        digest: Tpm2bDigest::from_bytes(&a_hash).unwrap(),
        in_scheme: Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let (sign_resp, _) = execute_sign(
        &mut sim,
        &sign_cmd,
        SignHandles { key_handle: sk },
        1,
        &[],
        &mut resp_buffer,
    )
    .expect("Sign failed");

    // 4. Verify signature on the TPM to generate the validation ticket
    let verify_cmd = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&a_hash).unwrap(),
        signature: sign_resp.signature,
    };
    let verify_handles = VerifySignatureHandles { key_handle: sk };
    let (verify_resp, _) =
        execute_with_password_sessions(&mut sim, &verify_cmd, verify_handles, 0, &[])
            .expect("VerifySignature failed");

    assert_eq!(verify_resp.validation.tag(), 0x8022); // TPM_ST_VERIFIED

    // 5. Execute PolicyAuthorize command with the computed ticket
    let policy_auth_cmd = PolicyAuthorize {
        approved_policy,
        policy_ref: Tpm2bNonce::default(),
        key_sign: sk_name,
        check_ticket: verify_resp.validation,
    };
    let policy_auth_handles = PolicyAuthorizeHandles {
        policy_session: session_handle,
    };
    let res =
        execute_with_password_sessions(&mut sim, &policy_auth_cmd, policy_auth_handles, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyAuthorize failed with valid VerifySignature ticket: {:?}",
        res.err()
    );

    // 6. Verify that the session policy digest was updated correctly:
    // digest_new = hash(digest_old=0 || TPM_CC_PolicyAuthorize || keySign || policyRef)
    let (final_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_authorize(
        policy_auth_cmd.key_sign.get_buffer(),
        policy_auth_cmd.policy_ref.get_buffer(),
    );
    assert_eq!(
        pol.policy_digest,
        final_digest_rsp.policy_digest.get_buffer()
    );

    // Cleanup keys
    flush_context(&mut sim, sk).unwrap();
}
