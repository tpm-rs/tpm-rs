//! TPM2_PolicyCommandCode: digest updates, conflicting codes and session checks.

use crate::_common::*;
use tpm2::commands::{PolicyCommandCode, PolicyGetDigest, StartAuthSession, *};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bEncryptedSecret, Tpm2bNonce, TpmCc, TpmSe, TpmaObject, TpmiAlgHash, *,
};
use tpm2_simulator::create_simulator;

/// PolicyCommandCode: unloaded session REFERENCE_H0, HMAC session rejected, digest update, conflicting second code TPM_RC_POLICY_CC
#[test]
fn command_code_digest_and_handle_errors() {
    let mut sim = create_simulator!();

    // 1. Session not found -> returns TpmRc::HANDLE (0x80)
    // 0x03000009 is a valid TPMI_SH_POLICY value that is not loaded: C EntityGetLoadStatus
    // returns TPM_RC_REFERENCE_H0.
    let res = policy_command_code(&mut sim, Handle(0x03000009), TpmCc::Duplicate);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));

    // 2. Create an HMAC session instead of Policy session and check handle error
    let hmac_session = start_session_handle(&mut sim, TpmSe::HMAC);
    let res = policy_command_code(&mut sim, hmac_session, TpmCc::Duplicate);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );

    // 3. Create a valid Policy session.
    let policy_session = start_session_handle(&mut sim, TpmSe::Policy);

    // 4. Unsupported command code (e.g. TpmCc::PPCommands) -> returns TpmRc::POLICY_CC (0x120)
    let res = policy_command_code(&mut sim, policy_session, TpmCc::PPCommands);
    // C TPM2_PolicyCommandCode: TPM_RCS_POLICY_CC + RC_PolicyCommandCode_code (+P1).
    assert_eq!(
        res.err(),
        Some(TpmRc::POLICY_CC.with(Position::parameter(1)).get())
    );

    // 5. Valid command code (e.g. TpmCc::Duplicate) -> returns Ok(())
    let res = policy_command_code(&mut sim, policy_session, TpmCc::Duplicate);
    assert!(res.is_ok());

    // Verify policy_digest updated (PolicyCommandCode extends it with the command code)
    let digest = try_policy_get_digest(&mut sim, policy_session).unwrap();
    assert_ne!(digest, [0u8; 32]);
    assert_eq!(
        digest,
        expected_command_code_digest(&[0u8; 32], TpmCc::Duplicate)
    );

    // 6. Calling again with a different command code (e.g. TpmCc::Import) -> returns TpmRc::VALUE (0x44)
    let res = policy_command_code(&mut sim, policy_session, TpmCc::Import);
    // C TPM2_PolicyCommandCode: TPM_RCS_VALUE + RC_PolicyCommandCode_code (+P1).
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}

/// A second, different PolicyCommandCode fails with VALUE+P1.
#[test]
fn conflicting_code_is_value_error() {
    // Part 4 (policy_command_code); parts 1-3 are engine checks handed over to fix-sessions.
    let mut sim = create_simulator!();
    let s = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_command_code(&mut sim, s, TpmCc::NVRead).unwrap();
    assert_eq!(
        policy_command_code(&mut sim, s, TpmCc::NVWrite),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}

/// PolicyCommandCode with a conflicting code reports VALUE+P1 before other errors.
#[test]
fn conflicting_code_reported_first() {
    let mut sim = create_simulator!();
    let unimplemented = TpmCc::new(0x0000_FFFF);

    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_command_code(&mut sim, s, unimplemented),
        Err(TpmRc::POLICY_CC.with(Position::parameter(1)).get())
    );

    // A conflicting command code is reported first (TPM_RCS_VALUE + RC_P1).
    policy_command_code(&mut sim, s, TpmCc::Sign).unwrap();
    assert_eq!(
        policy_command_code(&mut sim, s, unimplemented),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
    assert_eq!(
        policy_command_code(&mut sim, s, TpmCc::Unseal),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}

/// PolicyCommandCode(TPM_CC_Load) extends the policy digest with TPM_CC_PolicyCommandCode || TPM_CC_Load.
///
/// `TPM2_PolicyCommandCode(TPM_CC_Load)` extends the policy digest with
/// `TPM_CC_PolicyCommandCode || TPM_CC_Load`.
#[test]
fn policy_command_code_extends_digest() {
    let mut sim = create_simulator!();

    // 1. Start a policy session
    let resp_handles = exec_command(
        &mut sim,
        &StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Policy,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        },
        &[],
    )
    .expect("StartAuthSession failed");
    let session_handle = resp_handles.session_handle;

    // 2. Call PolicyCommandCode with TpmCc::Load (supported command)
    exec_command(
        &mut sim,
        &PolicyCommandCode {
            policy_session: session_handle,
            code: TpmCc::Load,
        },
        &[],
    )
    .expect("PolicyCommandCode failed");

    // 3. Call PolicyGetDigest to verify the updated digest
    let digest_resp = exec_command(
        &mut sim,
        &PolicyGetDigest {
            policy_session: session_handle,
        },
        &[],
    )
    .expect("PolicyGetDigest failed");

    // Policy digest should be computed as: SHA256(initial_digest || PolicyCommandCode || Load)
    // Initial digest is 32 bytes of 0s.
    let expected_digest = digest_parts(
        TpmiAlgHash::Sha256,
        &[
            &[0u8; 32],
            &TpmCc::PolicyCommandCode.code().to_be_bytes(),
            &TpmCc::Load.code().to_be_bytes(),
        ],
    );
    assert_eq!(digest_resp.policy_digest.get_buffer(), expected_digest);
}

/// PolicyGetDigest: unloaded session REFERENCE_H0, HMAC session rejected, returns the PolicyCommandCode digest
#[test]
fn policy_get_digest_errors_and_value() {
    let mut sim = create_simulator!();

    // 1. Session not found -> returns TpmRc::HANDLE
    // 0x03000009 is a valid TPMI_SH_POLICY value that is not loaded: C EntityGetLoadStatus
    // returns TPM_RC_REFERENCE_H0.
    let res = try_policy_get_digest(&mut sim, Handle(0x03000009));
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));

    // 2. Create an HMAC session instead of Policy session and check handle error
    let hmac_session = start_session_handle(&mut sim, TpmSe::HMAC);
    let res = try_policy_get_digest(&mut sim, hmac_session);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );

    // 3. A fresh Policy session reports the all-zero initial digest.
    let policy_session = start_session_handle(&mut sim, TpmSe::Policy);
    let res = try_policy_get_digest(&mut sim, policy_session);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), [0u8; 32]);

    // 4. After updating the session's digest, PolicyGetDigest returns the updated value.
    policy_command_code(&mut sim, policy_session, TpmCc::Duplicate).unwrap();
    let digest = try_policy_get_digest(&mut sim, policy_session).unwrap();
    assert_eq!(
        digest,
        expected_command_code_digest(&[0u8; 32], TpmCc::Duplicate)
    );
}

/// PolicyCommandCode works on a trial session, but a trial session in a session area fails with TPM_RC_ATTRIBUTES + S1.
///
/// `TPM2_PolicyCommandCode` works on a trial session, but a trial session can
/// never appear in a command's session area (`TPM_RC_ATTRIBUTES` + RC_S1).
#[test]
fn trial_session_cannot_authorize() {
    let mut sim = create_simulator!();

    // 1. Create a transient target key to use for a command
    let srk = create_srk(&mut sim);
    let target = create_unwrap(
        &mut sim,
        srk,
        rsa_dup_target(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    );
    let (target_handle, _) =
        load_with_name(&mut sim, srk, target.out_private, target.out_public).unwrap();

    // 2. Start a trial policy session
    let resp_handles = exec_command(
        &mut sim,
        &StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        },
        &[],
    )
    .unwrap();
    let session_handle = resp_handles.session_handle;

    // 3. Execute PolicyCommandCode on Trial session (should succeed)
    let res = exec_command(
        &mut sim,
        &PolicyCommandCode {
            policy_session: session_handle,
            code: TpmCc::Duplicate,
        },
        &[],
    );
    assert!(res.is_ok());

    // 4. Try to use the trial session to authorize a Duplicate command. A trial session can never
    //    appear in the session area (C ParseSessionBuffer): TPM_RC_ATTRIBUTES + RC_S1.
    let auth = TpmsAuthCommand {
        session_handle,
        nonce: Tpm2bNonce::from_bytes(&[2; 32]).unwrap(),
        session_attributes: TpmaSession(1), // continueSession
        hmac: Tpm2bAuth::default(),
    };
    let res = exec_command(
        &mut sim,
        &Duplicate {
            object_handle: target_handle,
            new_parent_handle: Handle::RH_NULL,
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: None,
        },
        &[auth],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::session(1)).get())
    );
}

/// PolicyCommandCode rejects unimplemented codes (TPM_RC_POLICY_CC) and a code different from the one already set (TPM_RC_VALUE).
///
/// `TPM2_PolicyCommandCode` rejects unimplemented command codes
/// (`TPM_RC_POLICY_CC`) and a code different from one already set
/// (`TPM_RC_VALUE`).
#[test]
fn unsupported_or_conflicting_code_rejected() {
    let mut sim = create_simulator!();

    let resp_handles = exec_command(
        &mut sim,
        &StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Policy,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        },
        &[],
    )
    .unwrap();

    // 1. Call PolicyCommandCode with unsupported code (TpmCc::PPCommands)
    let res = exec_command(
        &mut sim,
        &PolicyCommandCode {
            policy_session: resp_handles.session_handle,
            code: TpmCc::PPCommands,
        },
        &[],
    );
    // C PolicyCommandCode.c: TPM_RCS_POLICY_CC + RC_PolicyCommandCode_code (P1).
    assert_eq!(
        res.err(),
        Some(TpmRc::POLICY_CC.with(Position::parameter(1)).get())
    );

    // 2. Call PolicyCommandCode with supported code (TpmCc::Load) -> should succeed
    exec_command(
        &mut sim,
        &PolicyCommandCode {
            policy_session: resp_handles.session_handle,
            code: TpmCc::Load,
        },
        &[],
    )
    .unwrap();

    // 3. Call PolicyCommandCode with a different code (TpmCc::Import) -> should fail with Value
    let res = exec_command(
        &mut sim,
        &PolicyCommandCode {
            policy_session: resp_handles.session_handle,
            code: TpmCc::Import,
        },
        &[],
    );
    // C PolicyCommandCode.c: TPM_RCS_VALUE + RC_PolicyCommandCode_code (P1).
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}
