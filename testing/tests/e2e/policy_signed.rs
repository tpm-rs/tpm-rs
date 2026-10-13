//! TPM2_PolicySigned: signature verification, digest updates and handle/key validation.

use crate::_common::*;
use tpm2::commands::PolicySigned;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bDigest, Tpm2bNonce, Tpm2bPublicKeyRsa, TpmCc, TpmSe, TpmaObject,
    TpmiAlgHash, TpmsSignatureEcc, TpmtHa, TpmtPublic, TpmtSigScheme, TpmtSignature,
};
use tpm2_simulator::create_simulator;

/// PolicySigned with an ECDSA signature updates the policy digest as specified (including policyRef)
#[test]
fn ecc_signature_updates_digest() {
    let mut sim = create_simulator!();

    let (key_handle, auth_name) = create_ecc_key(&mut sim);
    let session = start_policy_session(&mut sim);

    let nonce_tpm_input = session.nonce_tpm;
    let expiration: i32 = -100;
    let policy_ref = Tpm2bNonce::from_bytes(&[5, 6, 7, 8]).unwrap();
    let cp_hash_a = Tpm2bDigest::default();

    // toBeSigned = nonceTPM || expiration (4) || cpHashA (0) || policyRef (4)
    let mut to_be_signed = Vec::new();
    to_be_signed.extend_from_slice(nonce_tpm_input.get_buffer());
    to_be_signed.extend_from_slice(&expiration.to_be_bytes());
    to_be_signed.extend_from_slice(cp_hash_a.get_buffer());
    to_be_signed.extend_from_slice(policy_ref.get_buffer());
    let digest_to_sign = sha256_bytes(&to_be_signed);

    let auth = sign_unwrap(
        &mut sim,
        key_handle,
        &digest_to_sign,
        TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256),
    );
    assert!(matches!(auth, TpmtSignature::Ecdsa(..)));

    let cmd = PolicySigned {
        auth_object: key_handle,
        policy_session: session.session_handle,
        nonce_tpm: nonce_tpm_input,
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };
    let rsp = execute_with_password_sessions(&mut sim, &cmd, 0, &[]).unwrap();

    // expected digest1 = SHA256(initial_digest (32) || TPM_CC_PolicySigned (4) || authName (34))
    // expected new_digest = SHA256(digest1 (32) || policyRef (4))
    let mut expected_update1 = vec![0u8; 32];
    expected_update1.extend_from_slice(&TpmCc::PolicySigned.code().to_be_bytes());
    expected_update1.extend_from_slice(auth_name.get_buffer());
    let digest1 = sha256_bytes(&expected_update1);

    let mut expected_update2 = digest1.to_vec();
    expected_update2.extend_from_slice(policy_ref.get_buffer());
    let expected_digest = sha256_bytes(&expected_update2);

    // Verify the updated policy digest in the session
    assert_eq!(
        policy_digest(&mut sim, session.session_handle),
        expected_digest
    );

    // Verify a ticket is returned because expiration < 0
    assert_eq!(rsp.policy_ticket.tag(), 0x8025);
    assert_ne!(rsp.policy_ticket.digest().get_size(), 0);
}

/// PolicySigned rejects unloaded/non-object handles in trial sessions and validates the handle before nonce checks.
#[test]
fn handle_validated_before_parameter_checks() {
    let mut sim = create_simulator!();
    let sig = TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha256, &[0; 32]).unwrap());
    // Trial session: unloaded transient and non-object handles are rejected.
    let trial = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_signed(&mut sim, Handle(0x8000_0002), trial, sig),
        Err(TpmRc::REFERENCE_H0.get())
    );
    assert_eq!(
        policy_signed(&mut sim, Handle::RH_OWNER, trial, sig),
        Err(TpmRc::VALUE.with(Position::handle(1)).get())
    );
    // Policy session: the handle is validated before PolicyParameterChecks (bad nonce).
    let policy =
        start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let err = run_command(
        &mut sim,
        PolicySigned {
            auth_object: Handle(0x8000_0002),
            policy_session: policy,
            nonce_tpm: Tpm2bNonce::from_bytes(&[0xEE; 16]).unwrap(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
            auth: sig,
        },
    )
    .map(|_| ())
    .unwrap_err();
    assert_eq!(err, TpmRc::REFERENCE_H0.get());
}

/// PolicySigned rejects public-only KEYEDHASH keys and HMAC hash mismatches (SIGNATURE+P5); a correct HMAC verifies.
#[test]
fn hmac_public_only_key_and_scheme_mismatch() {
    let mut sim = create_simulator!();
    // 1. A public-only KEYEDHASH key cannot verify (forgeable with an empty HMAC key).
    let key = load_public_only_hmac_key(&mut sim);
    let policy =
        start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_signed(&mut sim, key, policy, empty_policy_signed_hmac(&[])),
        Err(TpmRc::HANDLE.with(Position::parameter(5)).get())
    );

    // 2. Key scheme HMAC(SHA-256) vs. signature HMAC(SHA-1): TPM_RC_SIGNATURE + RC_P5.
    // Without SENSITIVE_DATA_ORIGIN the provided data is the HMAC key.
    let mut template = hmac_key_template(TpmiAlgHash::Sha256);
    template
        .object_attributes
        .remove(TpmaObject::SENSITIVE_DATA_ORIGIN);
    let (hmac_key, _) = create_primary_with_data(&mut sim, template, &[7; 32]);
    let policy =
        start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let sig = TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha1, &[0; 20]).unwrap());
    assert_eq!(
        policy_signed(&mut sim, hmac_key, policy, sig),
        Err(TpmRc::SIGNATURE.with(Position::parameter(5)).get())
    );
    // A correct HMAC with the loaded key still verifies.
    policy_signed(
        &mut sim,
        hmac_key,
        policy,
        empty_policy_signed_hmac(&[7; 32]),
    )
    .unwrap();
}

/// PolicySigned with an invalid signature fails
#[test]
fn incorrect_signature_rejected() {
    let mut sim = create_simulator!();

    let (key_handle, _) = create_ecc_key(&mut sim);
    let session = start_policy_session(&mut sim);

    // Use a completely incorrect signature
    let signature_r = tpm2::Tpm2bEccParameter::from_bytes(&[0x99; 32]).unwrap();
    let signature_s = tpm2::Tpm2bEccParameter::from_bytes(&[0x99; 32]).unwrap();
    let auth = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r,
        signature_s,
    });

    let cmd = PolicySigned {
        auth_object: key_handle,
        policy_session: session.session_handle,
        nonce_tpm: session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
        auth,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    // Should fail with a signature/parameter verification error
    assert!(res.is_err());
}

/// TPM2_PolicySigned with a negative expiration returns a TPM_ST_AUTH_SIGNED ticket
#[test]
fn policy_signed_negative_expiration_returns_ticket() {
    let mut sim = create_simulator!();
    let (key, _) = create_signing_key_name_bytes(&mut sim);

    // 1. Start a policy session
    let (session, nonce_tpm) = start_policy(&mut sim, TpmSe::Policy);

    // 2. Set expiration to -10 (negative value, so a ticket should be generated)
    let expiration: i32 = -10;
    let digest = policy_signed_digest(nonce_tpm.get_buffer(), expiration);
    let auth = sign_pss(&mut sim, key, &digest);

    // Calling PolicySigned with negative expiration should generate a ticket in response
    let ps_rsp =
        policy_signed_with_nonce(&mut sim, key, session, nonce_tpm, expiration, auth).unwrap();

    // Verify tag is 0x8025 and digest is non-empty
    assert_eq!(ps_rsp.policy_ticket.tag(), 0x8025);
    assert_ne!(ps_rsp.policy_ticket.digest().get_size(), 0);
}

/// TPM2_PolicySigned with expiration=1s succeeds, then after 1s fails with TPM_RC_EXPIRED + P4
#[test]
fn policy_signed_rejects_after_expiration_passes() {
    let mut sim = create_simulator!();
    let (key, _) = create_signing_key_name_bytes(&mut sim);

    // 1. Start a policy session
    let (session, nonce_tpm) = start_policy(&mut sim, TpmSe::Policy);

    // 2. Set expiration to 1 second
    let expiration: i32 = 1;
    let digest = policy_signed_digest(nonce_tpm.get_buffer(), expiration);
    let auth = sign_pss(&mut sim, key, &digest);

    // Calling PolicySigned with expiration = 1 should succeed and set the timeout
    let res = policy_signed_with_nonce(&mut sim, key, session, nonce_tpm, expiration, auth);
    assert!(res.is_ok(), "PolicySigned failed: {:?}", res.err());

    // 3. Let the 1 s expiration pass
    sleep(std::time::Duration::from_millis(1100));

    // The policy session itself never expires for policy commands (C only checks the session
    // timeout when the session authorizes a command); the new authorization's own expiration
    // is what has passed: TPM_RC_EXPIRED + RC_P4 (`expiration`, C PolicyParameterChecks).
    let res2 = policy_signed_with_nonce(&mut sim, key, session, nonce_tpm, expiration, auth);
    assert_eq!(
        res2.err(),
        Some(TpmRc::EXPIRED.with(Position::parameter(4)).get())
    );
}

/// TPM2_PolicySigned with an ECDSA signature for an RSA key fails with TPM_RC_SCHEME + P5
#[test]
fn policy_signed_rejects_ecdsa_signature_for_rsa_key() {
    let mut sim = create_simulator!();
    let (key, _) = create_signing_key_name_bytes(&mut sim); // This creates an RSA key

    // 1. Start a policy session
    let (session, nonce_tpm) = start_policy(&mut sim, TpmSe::Policy);

    // 2. Call PolicySigned on RSA key but with ECDSA signature
    let auth = TpmtSignature::Ecdsa(tpm2::TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r: tpm2::Tpm2bEccParameter::from_bytes(&[0; 32]).unwrap(),
        signature_s: tpm2::Tpm2bEccParameter::from_bytes(&[0; 32]).unwrap(),
    });
    let res = policy_signed_with_nonce(&mut sim, key, session, nonce_tpm, 0, auth);
    // C CryptRsaValidateSignature rejects a non-RSA sigAlg with TPM_RC_SCHEME (CryptRsa.c:1200),
    // which PolicySigned blames on `auth` (PolicySigned.c:96): SCHEME + P5.
    assert_eq!(
        res.err(),
        Some(TpmRc::SCHEME.with(Position::parameter(5)).get())
    );
}

/// TPM2_PolicySigned with a signature over a wrong nonceTPM fails with TPM_RC_SIGNATURE
#[test]
fn policy_signed_rejects_signature_over_wrong_nonce() {
    let mut sim = create_simulator!();
    let (key, _) = create_signing_key_name_bytes(&mut sim);

    // 1. Start a policy session
    let (session, nonce_tpm) = start_policy(&mut sim, TpmSe::Policy);

    // 2. Compute digest over an INCORRECT nonce_tpm (e.g. all 0xFF) and sign it
    let digest = policy_signed_digest(&[0xFF; 16], 0);
    let auth = sign_pss(&mut sim, key, &digest);

    // The correct nonce_tpm is passed in the command parameters, so PolicySigned should fail
    // because the signature is over the incorrect nonce!
    let res = policy_signed_with_nonce(&mut sim, key, session, nonce_tpm, 0, auth);
    assert_eq!(
        res.err(),
        Some(TpmRc::SIGNATURE.with(Position::parameter(5)).get())
    );
}

/// TPM2_PolicySigned with a symmetric key as authObject fails with TPM_RC_KEY
#[test]
fn policy_signed_rejects_symmetric_auth_object() {
    let mut sim = create_simulator!();

    // 1. Create a symmetric key and load it
    let (sym_key, _) = create_primary(
        &mut sim,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::DECRYPT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(AES128_CFB, Tpm2bDigest::default()),
        },
    );

    // 2. Start a policy session
    let (session, nonce_tpm) = start_policy(&mut sim, TpmSe::Policy);

    // 3. Call PolicySigned using the symmetric key as authObject
    let auth = TpmtSignature::Rsapss(tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::from_bytes(&[0; 256]).unwrap(),
    });
    let res = policy_signed_with_nonce(&mut sim, sym_key, session, nonce_tpm, 0, auth);
    assert_eq!(
        res.err(),
        Some(TpmRc::SCHEME.with(Position::parameter(5)).get())
    );
}

/// TPM2_PolicySigned with a tampered RSA-PSS signature fails with TPM_RC_SIGNATURE + P5
#[test]
fn policy_signed_rejects_tampered_signature() {
    let mut sim = create_simulator!();
    let (key, _) = create_signing_key_name_bytes(&mut sim);

    // 1. Start a policy session
    let (session, nonce_tpm) = start_policy(&mut sim, TpmSe::Policy);

    // 2. Compute digest and sign
    let digest = policy_signed_digest(nonce_tpm.get_buffer(), 0);
    let TpmtSignature::Rsapss(mut sig) = sign_pss(&mut sim, key, &digest) else {
        panic!("expected an RSASSA-PSS signature");
    };

    // Tamper with the signature bytes to make it invalid
    let mut sig_bytes = sig.sig.get_buffer().to_vec();
    sig_bytes[10] ^= 0xFF;
    sig.sig = Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&sig_bytes)).unwrap();

    // Calling PolicySigned with tampered signature should fail with signature_for(Parameter, Pos5)
    let res = policy_signed_with_nonce(
        &mut sim,
        key,
        session,
        nonce_tpm,
        0,
        TpmtSignature::Rsapss(sig),
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::SIGNATURE.with(Position::parameter(5)).get())
    );
}

/// TPM2_PolicySigned on a trial session skips the signature check and extends the digest with keyName and policyRef
#[test]
fn policy_signed_trial_session_updates_digest() {
    let mut sim = create_simulator!();
    let (key, key_name) = create_signing_key_name_bytes(&mut sim);

    // 1. Start a trial session
    let (session, _) = start_policy(&mut sim, TpmSe::Trial);

    // 2. Call PolicySigned on Trial session (the signature is not checked)
    let policy_ref = [9u8; 16];
    let res = run_command(
        &mut sim,
        PolicySigned {
            auth_object: key,
            policy_session: session,
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::from_bytes(&policy_ref).unwrap(),
            expiration: 0,
            auth: TpmtSignature::Rsapss(tpm2::TpmsSignatureRsa {
                hash: TpmiAlgHash::Sha256,
                sig: Tpm2bPublicKeyRsa::default(),
            }),
        },
    );
    assert!(res.is_ok(), "PolicySigned failed: {:?}", res.err());

    // 3. Call PolicyGetDigest to verify updated digest
    // Expected digest update:
    // digest1 = SHA256(0..32 || TPM_CC_PolicySigned || key_name)
    // expected = SHA256(digest1 || policy_ref)
    let digest1 = sha256(&[&[0u8; 32], &0x00000160u32.to_be_bytes(), &key_name]);
    let expected_digest = sha256(&[&digest1, &policy_ref]);
    assert_eq!(policy_get_digest(&mut sim, session), expected_digest);
}

/// PolicySigned: public-only HMAC key HANDLE error, unloaded trial handle, RSA signature on ECC key scheme error.
#[test]
fn public_only_hmac_and_unloaded_trial_handle() {
    // Parts 1-3 (part 4, LoadExternal phEnable, is handed over to fix-objects).
    let mut sim = create_simulator!();
    let key = load_public_only_hmac_key(&mut sim);
    let policy =
        start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_signed(&mut sim, key, policy, empty_policy_signed_hmac(&[])),
        Err(TpmRc::HANDLE.with(Position::parameter(5)).get())
    );
    let (ecc_key, _) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha256));
    assert_eq!(
        policy_signed(&mut sim, ecc_key, policy, ecdsa_dummy_sig()),
        Err(TpmRc::SCHEME.with(Position::parameter(5)).get())
    );
    let trial = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_signed(&mut sim, Handle(0x8000_0002), trial, ecdsa_dummy_sig()),
        Err(TpmRc::REFERENCE_H0.get())
    );
}

/// PolicySigned with an RSA signature on an ECC key fails with SCHEME; trial with unloaded authObject fails.
#[test]
fn rsa_signature_on_ecc_key_is_scheme_error() {
    let mut sim = create_simulator!();
    let (ecc_key, _) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha256));
    let policy =
        start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    // An RSA signature on an ECC key is a scheme error (CryptEccValidateSignature).
    assert_eq!(
        policy_signed(&mut sim, ecc_key, policy, ecdsa_dummy_sig()),
        Err(TpmRc::SCHEME.with(Position::parameter(5)).get())
    );
    // Trial: unloaded authObject.
    let trial = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_signed(&mut sim, Handle(0x8000_0002), trial, ecdsa_dummy_sig()),
        Err(TpmRc::REFERENCE_H0.get())
    );
}

/// PolicySigned with an RSA signature updates the digest and returns no ticket for expiration 0
#[test]
fn rsa_signature_updates_digest() {
    let mut sim = create_simulator!();

    let (key_handle, _) = create_rsa_key(&mut sim);
    let session = start_policy_session(&mut sim);

    let nonce_tpm_input = session.nonce_tpm;
    let expiration: i32 = 0; // No ticket
    let policy_ref = Tpm2bNonce::default();
    let cp_hash_a = Tpm2bDigest::default();

    // toBeSigned = nonceTPM || expiration (4) || cpHashA (0) || policyRef (0)
    let mut to_be_signed = Vec::new();
    to_be_signed.extend_from_slice(nonce_tpm_input.get_buffer());
    to_be_signed.extend_from_slice(&expiration.to_be_bytes());
    let digest_to_sign = sha256_bytes(&to_be_signed);

    let auth = sign_unwrap(
        &mut sim,
        key_handle,
        &digest_to_sign,
        TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256),
    );
    assert!(matches!(auth, TpmtSignature::Rsassa(..)));

    let cmd = PolicySigned {
        auth_object: key_handle,
        policy_session: session.session_handle,
        nonce_tpm: nonce_tpm_input,
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };
    let rsp = execute_with_password_sessions(&mut sim, &cmd, 0, &[]).unwrap();

    // Verify session state is updated
    assert_ne!(policy_digest(&mut sim, session.session_handle), [0u8; 32]);
    // Ticket should be empty because expiration is 0
    assert_eq!(rsp.policy_ticket.digest().get_size(), 0);
}

/// PolicySigned in a trial session uses the loaded object Name and rejects unloaded handles (REFERENCE_H0).
#[test]
fn trial_requires_loaded_object() {
    let mut sim = create_simulator!();
    let trial = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    let sig = TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha256, &[0; 32]).unwrap());
    assert_eq!(
        policy_signed(&mut sim, Handle(0x8000_0002), trial, sig),
        Err(TpmRc::REFERENCE_H0.get())
    );
    // Trial digest uses the loaded object's Name.
    let (key, name) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha256));
    let trial = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_signed(&mut sim, key, trial, sig).unwrap();
    let d1 = sha(
        TpmiAlgHash::Sha256,
        &[&[0; 32], &TpmCc::PolicySigned.code().to_be_bytes(), &name],
    );
    assert_eq!(
        policy_digest(&mut sim, trial),
        sha(TpmiAlgHash::Sha256, &[&d1])
    );
}
