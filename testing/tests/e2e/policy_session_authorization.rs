//! Authorizing commands with policy sessions: policy digest mismatches, empty policies and expired
//! sessions.

use crate::_common::*;
use tpm2::TpmSe;

/// PolicyCommandCode mismatch and policy command on an expired session scenarios.
///
/// policy-session-timeout-expiration-and-command-code-error-discrepancies
#[test]
fn command_code_mismatch_and_expired_policy_command() {
    let mut sim = new_sim();
    policy_command_on_expired_session_scenario(&mut sim);
    policy_cc_mismatch_scenario(&mut sim);
}

/// Objects with empty authPolicy fail with POLICY_FAIL; hierarchies with empty authPolicy fail with AUTH_UNAVAILABLE.
///
/// verify-session-hmacs-empty-auth-policy-returns-auth-unavailable-instead-of-policy-fail
/// (handed over by fix-auth)
#[test]
fn empty_auth_policy_object_vs_hierarchy() {
    let mut sim = new_sim();
    let key = create_primary_ecc(&mut sim);
    let mut p = start_session(&mut sim, TpmSe::Policy, false);
    // Objects always have a policy available (even an empty one), so the digest comparison fails.
    let rc = exec(
        &mut sim,
        CC_ENCRYPT_DECRYPT,
        &[key],
        &mut [SessUse::hmac(&mut p, ATTR_CONT, &[])],
        &[0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_POLICY_FAIL));
    // A hierarchy with an empty authPolicy has no policy available.
    let rc = exec(
        &mut sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut p, ATTR_CONT, &[])],
        &create_primary_params(),
        1,
    )
    .rc;
    assert_eq!(rc, RC_AUTH_UNAVAILABLE);
}

/// A policy session used only for encryption is verified by HMAC alone; its policy assertions are not evaluated.
///
/// unassociated-session-policy-and-empty-hmac-bugs (part 2, handed over by fix-auth)
#[test]
fn encrypt_only_policy_session_skips_assertions() {
    let mut sim = new_sim();
    // A policy session that only encrypts is verified by its HMAC alone; its policy assertions
    // (here: a locality the command is not sent from) are not evaluated.
    let mut p = start_session(&mut sim, TpmSe::Policy, true);
    let rc = policy_cmd(&mut sim, CC_POLICY_LOCALITY, p.handle, &[0x08]);
    assert_eq!(rc, 0);
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(&mut p, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &8u16.to_be_bytes(),
        0,
    )
    .rc;
    assert_eq!(rc, 0);
}

/// Expired policy session and PolicyCommandCode mismatch scenarios report the C error codes and order.
///
/// verify-session-hmacs-policy-cc-expired-flush-and-order-bugs
#[test]
fn expired_session_and_command_code_mismatch() {
    let mut sim = new_sim();
    policy_cc_mismatch_scenario(&mut sim);
    expired_policy_session_scenario(&mut sim);
}

/// Policy commands on an expired policy session report EXPIRED with the right handle position.
///
/// validate-policy-session-erroneous-expiration-and-handle-error-codes
#[test]
fn policy_command_on_expired_session() {
    let mut sim = new_sim();
    policy_command_on_expired_session_scenario(&mut sim);
}

/// PolicySecret with a policy lacking PolicyPassword/AuthValue is MODE; expired sessions are reported only when the policy matches.
///
/// tpm2-policysecret-auth-mode-bypass-and-policy-session-validation-bugs
#[test]
fn policy_secret_mode_and_expired_session() {
    let mut sim = new_sim();
    set_owner_policy(&mut sim, &JUNK_DIGEST, &[]);
    let mut p1 = start_session(&mut sim, TpmSe::Policy, false);
    let p2 = start_session(&mut sim, TpmSe::Policy, false);

    // P1 has neither PolicyPassword nor PolicyAuthValue, so it cannot prove knowledge of the
    // owner authValue for TPM2_PolicySecret: TPM_RC_MODE (before the digest comparison).
    let rc = exec(
        &mut sim,
        CC_POLICY_SECRET,
        &[RH_OWNER, p2.handle],
        &mut [SessUse::hmac(&mut p1, ATTR_CONT, &[])],
        &policy_secret_params(&[], 0),
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_MODE));
    flush(&mut sim, p1.handle);
    flush(&mut sim, p2.handle);

    // Expired policy sessions are reported (not flushed), and only once the policy matches.
    expired_policy_session_scenario(&mut sim);
}
