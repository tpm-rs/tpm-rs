//! TPM2_PolicyAuthorize: verification ticket checks and approved policy handling.

use crate::_common::*;
use sha2::{Digest, Sha256};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{PolicyAuthorize, PolicyGetDigest, Sign, StartAuthSession, VerifySignature};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, Handle, Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmSe, TpmiAlgHash, TpmtSigScheme,
    TpmtTkHashcheck, TpmtTkVerified, *,
};

/// PolicyAuthorize with forged verification tickets (NULL and owner hierarchy) fails.
#[test]
fn forged_ticket_rejected() {
    let mut sim = Tpm::new();
    let (sk, sk_name) = create_signing_key(&mut sim);

    // Start a Policy session
    let start_auth = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_rsp_handles = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // Get the current policy digest (which is all zeros initially)
    let get_digest = PolicyGetDigest {
        policy_session: session_handle,
    };
    let digest_rsp = execute_with_password_sessions(&mut sim, &get_digest, 0, &[]).unwrap();
    let approved_policy = digest_rsp.policy_digest;

    // 1. Try to use PolicyAuthorize with a forged ticket under NULL hierarchy
    // A forged ticket will have hierarchy RHNull, but random/guessed digest.
    let forged_ticket = TpmtTkVerified::Verified(
        Handle::RH_NULL,
        Tpm2bDigest::from_bytes(&[0xAA; 32]).unwrap(),
    );

    let policy_auth_cmd = PolicyAuthorize {
        policy_session: session_handle,
        approved_policy,
        policy_ref: Tpm2bNonce::default(),
        key_sign: sk_name,
        check_ticket: forged_ticket,
    };

    let res = execute_with_password_sessions(&mut sim, &policy_auth_cmd, 0, &[]);
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
        policy_session: session_handle,
        approved_policy,
        policy_ref: Tpm2bNonce::default(),
        key_sign: sk_name,
        check_ticket: forged_owner_ticket,
    };
    let res_owner = execute_with_password_sessions(&mut sim, &policy_auth_cmd_owner, 0, &[]);
    assert!(
        res_owner.is_err(),
        "PolicyAuthorize should fail with forged ticket under Owner hierarchy!"
    );

    // Cleanup keys
    flush_context(&mut sim, sk).unwrap();
}

/// PolicyAuthorize with a ticket for an invalid hierarchy (RH_PW) is TPM_RC_VALUE + RC_P4
#[test]
fn invalid_ticket_hierarchy_rejected() {
    let mut sim = Tpm::new();
    let session = policy_session(&mut sim);

    // Use a ticket with an invalid hierarchy (e.g. 0x40000009 - RH_PW)
    let check_ticket = TpmtTkVerified::Verified(
        Handle(0x40000009),
        Tpm2bDigest::from_bytes(&[0; 32]).unwrap(),
    );

    let key_sign_bytes = [[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat();
    let cmd = PolicyAuthorize {
        policy_session: session,
        approved_policy: Tpm2bDigest::from_bytes(&[0; 32]).unwrap(),
        policy_ref: Tpm2bNonce::default(),
        key_sign: Tpm2bName::from_bytes(leak_bytes(&key_sign_bytes)).unwrap(),
        check_ticket,
    };

    let err_val = execute_with_password_sessions(&mut sim, &cmd, 0, &[])
        .expect_err("PolicyAuthorize must fail");
    // Expecting 0x04C4 (value_for(Position::parameter(4)))
    assert_eq!(err_val, 0x04C4, "got {err_val:#x}");
}

/// PolicyAuthorize with a forged TPM_RH_NULL verification ticket is rejected with TPM_RC_VALUE
#[test]
fn null_hierarchy_ticket_rejected() {
    let mut sim = Tpm::new();

    // The initial policy digest of the session is all zeros.
    let session = start_policy_session(&mut sim);

    let approved_policy = Tpm2bDigest::from_bytes(&[0; 32]).unwrap();
    let policy_ref = Tpm2bNonce::from_bytes(&[5, 6, 7, 8]).unwrap();

    let mut key_sign_bytes = [0u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    key_sign_bytes[2..34].copy_from_slice(&[0x11; 32]);
    let key_sign = Tpm2bName::from_bytes(&key_sign_bytes).unwrap();

    // Normally we need a signature from key_sign. But we use a ticket with RH_NULL (0x40000007).
    // An attacker assumes the proof for RH_NULL is empty.
    // The HMAC is computed over: 0x8022 (2 bytes) || aHash (32 bytes) || keySign name (34 bytes)
    // aHash = SHA256(approvedPolicy || policyRef)
    let mut a_hash_input = approved_policy.get_buffer().to_vec();
    a_hash_input.extend_from_slice(policy_ref.get_buffer());
    let a_hash = sha256_bytes(&a_hash_input);

    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&0x8022u16.to_be_bytes());
    hmac_input.extend_from_slice(&a_hash);
    hmac_input.extend_from_slice(key_sign.get_buffer());

    // HMAC calculated using an empty key
    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let computed_hmac = tpm2::crypto::hmac(
        CLIENT_CRYPTO,
        TpmiAlgHash::Sha256,
        &[],
        &hmac_input,
        &mut hmac_buf,
    )
    .unwrap();

    let check_ticket = TpmtTkVerified::Verified(
        Handle(0x40000007),
        Tpm2bDigest::from_bytes(leak_bytes(computed_hmac.digest())).unwrap(),
    );

    let cmd = PolicyAuthorize {
        policy_session: session.session_handle,
        approved_policy,
        policy_ref,
        key_sign,
        check_ticket,
    };

    // Execute PolicyAuthorize. It should fail because the ticket uses an empty key but the TPM uses the random null_proof!
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]).map(|_| ());
    assert!(
        res.is_err(),
        "Expected PolicyAuthorize to fail with forged RH_NULL ticket, but it succeeded!"
    );
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE.with(Position::parameter(4)).get()
    );
}

/// TPM2_PolicyAuthorize with an empty ticket digest fails with TPM_RC_VALUE + P4
#[test]
fn policy_authorize_rejects_empty_ticket_digest() {
    let mut sim = Tpm::new();

    // 1. Start a policy session
    let (session, _) = start_policy(&mut sim, TpmSe::Policy);
    let approved_policy = policy_get_digest(&mut sim, session);

    // 2. Prepare ticket inputs with an empty (invalid) ticket digest
    let check_ticket = TpmtTkVerified::Verified(Handle(0x4000000C), Tpm2bDigest::default());

    // Calling PolicyAuthorize with a wrong ticket should fail with value_for(Parameter, Pos4)
    let res = policy_authorize(
        &mut sim,
        session,
        &approved_policy,
        &[],
        dummy_key_sign(),
        check_ticket,
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(4)).get())
    );
}

/// TPM2_PolicyAuthorize rejects a ticket forged for TPM_RH_NULL with an empty-key HMAC (TPM_RC_VALUE)
#[test]
fn policy_authorize_rejects_forged_null_hierarchy_ticket() {
    let mut sim = Tpm::new();

    // Let's use a dummy authority key name (it does not even need to exist!)
    let key_name: Vec<u8> = [0u8, 11].into_iter().chain(1..=32).collect();

    let approved_policy = [0u8; 32];
    let policy_ref = [8u8; 16];
    // aHash = SHA256(approvedPolicy || policyRef)
    let ahash_digest = sha256(&[&approved_policy, &policy_ref]);

    // Forge the ticket with RHNull (0x40000007) and an HMAC with an empty key
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&0x8022u16.to_be_bytes()); // tag
    hmac_input.extend_from_slice(&ahash_digest); // digest
    hmac_input.extend_from_slice(&key_name); // keyName
    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let hmac_digest = tpm2::crypto::hmac(
        CLIENT_CRYPTO,
        TpmiAlgHash::Sha256,
        &[],
        &hmac_input,
        &mut hmac_buf,
    )
    .unwrap();
    let ticket = TpmtTkVerified::Verified(
        Handle::RH_NULL,
        Tpm2bDigest::from_bytes(leak_bytes(hmac_digest.digest())).unwrap(),
    );

    // Start a real policy session
    let (session, _) = start_policy(&mut sim, TpmSe::Policy);

    // Call PolicyAuthorize on this session
    let res = policy_authorize(
        &mut sim,
        session,
        &approved_policy,
        &policy_ref,
        Tpm2bName::from_bytes(leak_bytes(&key_name)).unwrap(),
        ticket,
    );
    let err = res.expect_err(
        "Expected PolicyAuthorize to fail with forged RHNull ticket, but it succeeded!",
    );
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(4)).get());
}

/// TPM2_PolicyAuthorize with a ticket naming an invalid hierarchy fails with TPM_RC_VALUE on checkTicket
#[test]
fn policy_authorize_rejects_invalid_ticket_hierarchy() {
    let mut sim = Tpm::new();
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let approved_policy = Tpm2bDigest::from_bytes(&[0x00; 32]).unwrap();
    let key_sign = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();

    let cmd = PolicyAuthorize {
        policy_session: sess.session_handle,
        approved_policy,
        policy_ref: Tpm2bNonce::default(),
        key_sign,
        check_ticket: TpmtTkVerified::Verified(Handle(0x1234), Tpm2bDigest::default()),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    // Expected value error: value_for(Position::parameter(4))
    // 0x04C4 = 0x0004 (Value) + 0x0080 (Format 1) + 0x0040 (Parameter) + 0x0400 (Pos4)
    assert_eq!(
        res.err(),
        Some(0x04C4),
        "PolicyAuthorize with invalid hierarchy should fail with TPM_RC_VALUE on parameter 4"
    );
}

/// TPM2_PolicyAuthorize with keySign naming an unknown hash alg (0xFFFF) fails with TPM_RC_HASH
#[test]
fn policy_authorize_rejects_key_sign_unknown_hash() {
    let mut sim = Tpm::new();

    // 1. Start a trial session
    let (session, _) = start_policy(&mut sim, TpmSe::Trial);

    // 2. Call PolicyAuthorize with invalid hash alg in key_sign (e.g. 0xFFFF)
    let mut key_sign_bad_hash = [0u8; 34];
    key_sign_bad_hash[0..2].copy_from_slice(&0xFFFFu16.to_be_bytes());
    let res = policy_authorize(
        &mut sim,
        session,
        &[],
        &[],
        Tpm2bName::from_bytes(leak_bytes(&key_sign_bad_hash)).unwrap(),
        TpmtTkVerified::default(),
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::HASH.with(Position::parameter(3)).get())
    );
}

/// TPM2_PolicyAuthorize with a keySign shorter than 2 bytes or with a wrong digest length fails with TPM_RC_SIZE
#[test]
fn policy_authorize_rejects_malformed_key_sign_size() {
    let mut sim = Tpm::new();

    // 1. Start a trial session
    let (session, _) = start_policy(&mut sim, TpmSe::Trial);

    // 2. Call PolicyAuthorize with key_sign size < 2
    let res = policy_authorize(
        &mut sim,
        session,
        &[],
        &[],
        Tpm2bName::from_bytes(&[0]).unwrap(),
        TpmtTkVerified::default(),
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(Position::parameter(3)).get())
    );

    // 3. Call PolicyAuthorize with key_sign size not matching digest size of its hash algorithm
    // SHA256 requires 32 bytes digest, but key_sign total size is 10 (8 bytes digest)
    let mut key_sign_mismatched = [0u8; 10];
    key_sign_mismatched[0..2].copy_from_slice(&0x000Bu16.to_be_bytes());
    let res2 = policy_authorize(
        &mut sim,
        session,
        &[],
        &[],
        Tpm2bName::from_bytes(leak_bytes(&key_sign_mismatched)).unwrap(),
        TpmtTkVerified::default(),
    );
    assert_eq!(
        res2.err(),
        Some(TpmRc::SIZE.with(Position::parameter(3)).get())
    );
}

/// TPM2_PolicyAuthorize with an approvedPolicy different from the session digest fails with TPM_RC_VALUE + P1
#[test]
fn policy_authorize_rejects_mismatched_approved_policy() {
    let mut sim = Tpm::new();

    // 1. Start a policy session and advance its digest
    let (session, _) = start_policy(&mut sim, TpmSe::Policy);
    policy_command_code_get_random(&mut sim, session);

    // 2. Prepare ticket inputs with a MISMATCHED approvedPolicy (e.g. all 0xEE)
    let check_ticket = TpmtTkVerified::Verified(Handle(0x4000000C), Tpm2bDigest::default());

    // Calling PolicyAuthorize with mismatched approved_policy should return value_for(Parameter, Pos1)
    let res = policy_authorize(
        &mut sim,
        session,
        &[0xEE; 32],
        &[],
        dummy_key_sign(),
        check_ticket,
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}

/// TPM2_PolicyAuthorize with a tampered ticket HMAC fails with TPM_RC_VALUE + P4
#[test]
fn policy_authorize_rejects_tampered_ticket_hmac() {
    let mut sim = Tpm::new();

    // 1. Start a policy session and get the current policy digest (all zeros)
    let (session, _) = start_policy(&mut sim, TpmSe::Policy);
    let approved_policy = policy_get_digest(&mut sim, session);

    // 2. Prepare ticket inputs with a WRONG/tampered HMAC digest
    let check_ticket = TpmtTkVerified::Verified(
        Handle(0x4000000C),
        Tpm2bDigest::from_bytes(&[0x99; 32]).unwrap(),
    );

    // Calling PolicyAuthorize with wrong ticket HMAC should fail with value_for(Parameter, Pos4)
    let res = policy_authorize(
        &mut sim,
        session,
        &approved_policy,
        &[],
        dummy_key_sign(),
        check_ticket,
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(4)).get())
    );
}

/// TPM2_PolicyAuthorize succeeds on a session whose PolicySigned timeout has passed (policy commands do not check the timeout)
#[test]
fn policy_authorize_succeeds_on_timed_out_session() {
    let mut sim = Tpm::new();
    let (key, key_name) = create_signing_key_name_bytes(&mut sim);

    // Start policy session
    let (session, nonce_tpm) = start_policy(&mut sim, TpmSe::Policy);

    // Set a timeout on the session using PolicySigned first (expiration = 1 s)
    let expiration: i32 = 1;
    let digest = policy_signed_digest(nonce_tpm.get_buffer(), expiration);
    let auth = sign_pss(&mut sim, key, &digest);
    let res = policy_signed_with_nonce(&mut sim, key, session, nonce_tpm, expiration, auth);
    assert!(res.is_ok(), "PolicySigned failed: {:?}", res.err());

    // Fetch the updated policy digest of the session
    let current_policy_digest = policy_get_digest(&mut sim, session);

    // Generate the ticket using this updated policy digest
    let pa_policy_ref = [8u8; 16];
    let ahash_digest = sha256(&[&current_policy_digest, &pa_policy_ref]);
    let signature = sign_pss(&mut sim, key, &ahash_digest);
    let ticket = verify_signature_unwrap(&mut sim, key, &ahash_digest, signature);

    // Let the session timeout pass
    sleep(std::time::Duration::from_millis(1100));

    // As in C, policy commands never check the session timeout (only CheckPolicyAuthSession does
    // when the session authorizes a command), so PolicyAuthorize succeeds on the expired session.
    let res2 = policy_authorize(
        &mut sim,
        session,
        &current_policy_digest,
        &pa_policy_ref,
        Tpm2bName::from_bytes(leak_bytes(&key_name)).unwrap(),
        ticket,
    );
    assert!(res2.is_ok(), "PolicyAuthorize failed: {:?}", res2.err());
}

/// TPM2_PolicyAuthorize on a trial session skips the ticket check and resets/extends the digest with keySign and policyRef
#[test]
fn policy_authorize_trial_session_updates_digest() {
    let mut sim = Tpm::new();

    // 1. Start a trial session and advance its digest
    let (session, _) = start_policy(&mut sim, TpmSe::Trial);
    policy_command_code_get_random(&mut sim, session);
    let approved_policy = policy_get_digest(&mut sim, session);

    // 2. Call PolicyAuthorize on Trial session (no ticket validation)
    let key_sign = dummy_key_sign();
    let policy_ref = [7u8; 8];
    let res = policy_authorize(
        &mut sim,
        session,
        &approved_policy,
        &policy_ref,
        key_sign,
        TpmtTkVerified::default(),
    );
    assert!(res.is_ok(), "PolicyAuthorize failed: {:?}", res.err());

    // 3. Verify updated digest
    // digest1 = SHA256(ZeroDigest || TPM_CC_PolicyAuthorize || key_sign)
    // expected = SHA256(digest1 || policy_ref)
    let digest1 = sha256(&[
        &[0u8; 32],
        &0x0000016Au32.to_be_bytes(),
        key_sign.get_buffer(),
    ]);
    let expected_digest = sha256(&[&digest1, &policy_ref]);
    assert_eq!(policy_get_digest(&mut sim, session), expected_digest);
}

/// TPM2_PolicyAuthorize succeeds with a TPM2_VerifySignature ticket over aHash(approvedPolicy||policyRef)
#[test]
fn policy_authorize_with_verify_signature_ticket() {
    let mut sim = Tpm::new();
    let (key, key_name) = create_signing_key_name_bytes(&mut sim);

    // 1. Compute approvedPolicy and policyRef digest (aHash)
    // For a brand new session, policy_digest is all zeros
    let approved_policy = [0u8; 32];
    let policy_ref = [8u8; 16];
    // aHash = SHA256(approvedPolicy || policyRef)
    let ahash_digest = sha256(&[&approved_policy, &policy_ref]);

    // 2. Sign aHash
    let signature = sign_pss(&mut sim, key, &ahash_digest);

    // 3. Call VerifySignature to get a ticket
    let ticket = verify_signature_unwrap(&mut sim, key, &ahash_digest, signature);

    // 4. Start a real policy session
    let (session, _) = start_policy(&mut sim, TpmSe::Policy);

    // 5. Call PolicyAuthorize on this session
    let res = policy_authorize(
        &mut sim,
        session,
        &approved_policy,
        &policy_ref,
        Tpm2bName::from_bytes(leak_bytes(&key_name)).unwrap(),
        ticket,
    );
    assert!(res.is_ok(), "PolicyAuthorize failed with {:?}", res.err());
}

/// Sign aHash, VerifySignature to get a ticket, and PolicyAuthorize accepts it.
#[allow(deprecated)]
#[test]
fn verify_signature_ticket_authorizes_policy() {
    let mut sim = Tpm::new();
    let (sk, sk_name) = create_signing_key(&mut sim);

    // 1. Start Policy session to get the approved policy digest
    let start_auth = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_rsp_handles = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // Get policy digest
    let get_digest = PolicyGetDigest {
        policy_session: session_handle,
    };
    let digest_rsp = execute_with_password_sessions(&mut sim, &get_digest, 0, &[]).unwrap();
    let approved_policy = digest_rsp.policy_digest;

    // 2. Compute aHash = hash(approvedPolicy || policyRef)
    // Here policyRef is empty.
    let mut hasher = Sha256::new();
    hasher.update(approved_policy.get_buffer());
    // policyRef is empty, so nothing to update for policyRef
    let a_hash = hasher.finalize();

    // 3. Sign the aHash using Sign command on the signing key
    let sign_cmd = Sign {
        key_handle: sk,
        digest: Tpm2bDigest::from_bytes(&a_hash).unwrap(),
        in_scheme: Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let sign_resp =
        execute_sign(&mut sim, &sign_cmd, 1, &[], &mut resp_buffer).expect("Sign failed");

    // 4. Verify signature on the TPM to generate the validation ticket
    let verify_cmd = VerifySignature {
        key_handle: sk,
        digest: Tpm2bDigest::from_bytes(&a_hash).unwrap(),
        signature: sign_resp.signature,
    };
    let verify_resp = execute_with_password_sessions(&mut sim, &verify_cmd, 0, &[])
        .expect("VerifySignature failed");

    assert_eq!(verify_resp.validation.tag(), 0x8022); // TPM_ST_VERIFIED

    // 5. Execute PolicyAuthorize command with the computed ticket
    let policy_auth_cmd = PolicyAuthorize {
        policy_session: session_handle,
        approved_policy,
        policy_ref: Tpm2bNonce::default(),
        key_sign: sk_name,
        check_ticket: verify_resp.validation,
    };
    let res = execute_with_password_sessions(&mut sim, &policy_auth_cmd, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyAuthorize failed with valid VerifySignature ticket: {:?}",
        res.err()
    );

    // 6. Verify that the session policy digest was updated correctly:
    // digest_new = hash(digest_old=0 || TPM_CC_PolicyAuthorize || keySign || policyRef)
    let final_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest, 0, &[]).unwrap();

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

/// PolicyAuthorize accepts a VerifySignature ticket for aHash and rejects it for a different policy
#[allow(deprecated)]
#[test]
fn verify_signature_ticket_binding() {
    let mut sim = Tpm::new();

    // Create a key in Owner hierarchy
    let (key_handle, key_name) = create_ecc_key(&mut sim);

    let approved_policy = Tpm2bDigest::from_bytes(&[0; 32]).unwrap();
    let policy_ref = Tpm2bNonce::from_bytes(&[5, 6, 7, 8]).unwrap();

    // 1. We compute aHash = SHA256(approvedPolicy || policyRef)
    let mut a_hash_input = approved_policy.get_buffer().to_vec();
    a_hash_input.extend_from_slice(policy_ref.get_buffer());
    let a_hash = sha256_bytes(&a_hash_input);

    // 2. We sign aHash using our ECC key
    let signature = sign_unwrap(
        &mut sim,
        key_handle,
        &a_hash,
        TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256),
    );

    // 3. Call VerifySignature to get a verification ticket
    let vs_cmd = VerifySignature {
        key_handle,
        digest: Tpm2bDigest::from_bytes(&a_hash).unwrap(),
        signature,
    };
    let vs_rsp = execute_with_password_sessions(&mut sim, &vs_cmd, 0, &[]).unwrap();

    // Verify the ticket returned by VerifySignature
    let check_ticket = vs_rsp.validation;
    assert_eq!(check_ticket.tag(), 0x8022);
    assert_eq!(check_ticket.hierarchy().0, 0x40000001); // RH_OWNER

    // 4. Set up the policy session and call PolicyAuthorize
    let session = start_policy_session(&mut sim);
    let cmd = PolicyAuthorize {
        policy_session: session.session_handle,
        approved_policy,
        policy_ref,
        key_sign: key_name,
        check_ticket,
    };

    // 5. This command SHOULD succeed because VerifySignature correctly computes the HMAC ticket.
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]).map(|_| ());
    assert!(
        res.is_ok(),
        "Expected PolicyAuthorize to succeed, but it failed: {:?}",
        res.err()
    );
}
