//! TPM2_PolicyNameHash and TPM2_PolicyTemplate digest updates and session checks.

use crate::_common::*;
use tpm2::commands::{PolicyGetDigest, PolicyNameHash, PolicyTemplate, StartAuthSession};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bDigest, Tpm2bNonce, TpmCc, TpmSe, TpmiAlgHash};
use tpm2_simulator::create_simulator;

/// PolicyNameHash on an HMAC session is rejected
#[test]
fn hmac_session_rejected() {
    let mut sim = create_simulator!();

    // Start an HMAC session via StartAuthSession
    let session_handle =
        start_session_with_nonce(&mut sim, TpmSe::HMAC, TpmiAlgHash::Sha256, &[1; 32]);

    let res = execute_with_password_sessions(
        &mut sim,
        &PolicyNameHash {
            policy_session: session_handle,
            name_hash: Tpm2bDigest::from_bytes(&[0x42u8; 32]).unwrap(),
        },
        0,
        &[],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );
}

/// PolicyNameHash in a trial session updates the digest to H(0 || TPM_CC_PolicyNameHash || nameHash)
#[test]
fn name_hash_updates_digest() {
    let mut sim = create_simulator!();

    // Start a SHA256 trial policy session via StartAuthSession
    let policy_session_handle =
        start_session_with_nonce(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256, &[1; 32]);

    // Send TPM2_PolicyNameHash with a test 32-byte nameHash
    let name_hash_bytes = [0x42u8; 32];
    let res = execute_with_password_sessions(
        &mut sim,
        &PolicyNameHash {
            policy_session: policy_session_handle,
            name_hash: Tpm2bDigest::from_bytes(&name_hash_bytes).unwrap(),
        },
        0,
        &[],
    );
    assert!(
        res.is_ok(),
        "Expected TPM2_PolicyNameHash to succeed, but failed with rc: {:?}",
        res.err()
    );

    // Invoke PolicyGetDigest to verify the resulting digest
    let policy_digest = policy_get_digest_checked(&mut sim, policy_session_handle);

    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(&[0u8; 32]);
    data_to_hash.extend_from_slice(&(TpmCc::PolicyNameHash.code()).to_be_bytes());
    data_to_hash.extend_from_slice(&name_hash_bytes);
    let digest = hash_bytes(TpmiAlgHash::Sha256, &data_to_hash);

    assert_eq!(policy_digest, digest);
}

/// PolicyTemplate extends the policy digest with H(0[32] || TPM_CC_PolicyTemplate || templateHash).
///
/// `TPM2_PolicyTemplate` extends the policy digest with
/// `H(0[32] || TPM_CC_PolicyTemplate || templateHash)`.
#[test]
fn policy_template_extends_digest() {
    let mut sim = create_simulator!();

    // 1. Start a policy session
    let session_rsp = execute_with_password_sessions(
        &mut sim,
        &StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[1u8; 32]).unwrap(),
            encrypted_salt: Default::default(),
            session_type: TpmSe::Policy,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        },
        0,
        &[],
    )
    .expect("StartAuthSession failed");
    let session_handle = session_rsp.session_handle;

    // 2. Define a template hash
    let template_hash = [0x5au8; 32];
    execute_with_password_sessions(
        &mut sim,
        &PolicyTemplate {
            policy_session: session_handle,
            template_hash: Tpm2bDigest::from_bytes(&template_hash).unwrap(),
        },
        0,
        &[],
    )
    .expect("PolicyTemplate command failed");

    // 3. Compute expected policy digest: Sha256(0[32] || TPM_CC_PolicyTemplate || template_hash)
    let mut hasher = tpm2::crypto::HashStream::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256).unwrap();
    hasher.update(&[0u8; 32]).unwrap();
    hasher
        .update(&TpmCc::PolicyTemplate.code().to_be_bytes())
        .unwrap();
    hasher.update(&template_hash).unwrap();
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let expected_digest = hasher.finalize(&mut out).unwrap().digest().to_vec();

    // 4. Query policy digest with PolicyGetDigest
    let digest_resp = execute_with_password_sessions(
        &mut sim,
        &PolicyGetDigest {
            policy_session: session_handle,
        },
        0,
        &[],
    )
    .expect("PolicyGetDigest failed");

    assert_eq!(
        digest_resp.policy_digest.get_buffer(),
        expected_digest.as_slice()
    );
}
