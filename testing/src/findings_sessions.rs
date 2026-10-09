//! End-to-end regression tests for the `sessions` findings in command-handlers.toml.
//!
//! Owned by the `fix-sessions` worker; add submodules under `findings_sessions/` if this grows.
//!
//! The tests build commands byte-by-byte (see [`helpers`]) so that they can exercise malformed
//! headers, unusual session areas and exact response codes, while still talking to the simulator
//! purely through its command interface.

#![allow(unused_imports)]

pub(crate) mod helpers;

use helpers::*;
use std::time::Duration;
use tpm2::TpmSe;

/// Fixed policy digest used where any non-empty `authPolicy` will do.
const JUNK_DIGEST: [u8; 32] = [0x11; 32];

// parameter-decryption-executed-before-session-hmac-verification
#[test]
fn parameter_decryption_executed_before_session_hmac_verification() {
    let mut sim = new_sim();
    let mut s = start_session(&mut sim, TpmSe::HMAC, true);

    // A malformed (1-byte) encrypted first parameter together with a wrong HMAC: the
    // authorization failure must be reported, not the decryption error.
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[]).bad_hmac()],
        &[0x00],
        0,
    )
    .rc;
    // TPM_RH_OWNER is DA-exempt, so the HMAC failure is TPM_RC_BAD_AUTH (C IncrementLockout).
    assert_eq!(rc, rc_s1(RC_BAD_AUTH));

    // With a correct HMAC the decryption errors carry the session position and use the C codes.
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[])],
        &[0x00],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_INSUFFICIENT));
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[])],
        &[0x00, 0x05, 0x01],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_SIZE));
}

// session-area-validation-omissions-wrong-error-codes
#[test]
fn session_area_validation_omissions_wrong_error_codes() {
    let mut sim = new_sim();
    let get_random = 8u16.to_be_bytes();

    // A password session that does not authorize any handle.
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::pw(&[])],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_HANDLE));

    // A trial policy session can never appear in the session area.
    // (Used to authorize a handle, so no other attribute rule applies first.)
    let mut trial = start_session(&mut sim, TpmSe::Trial, false);
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut trial, ATTR_CONT, &[])],
        &[0x00, 0x00],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_ATTRIBUTES));

    // A non-authorization session must be an audit, encrypt or decrypt session.
    let mut s = start_session(&mut sim, TpmSe::HMAC, false);
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(&mut s, ATTR_CONT, &[])],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_ATTRIBUTES));
}

// session-area-validation-omissions-wrong-error-codes: ordering of the unassociated-session
// attribute check (reported by triage, #135). C `RetrieveSessionData` checks every session's
// decrypt/encrypt symmetric algorithm before `ParseSessionBuffer` rejects a plain unassociated
// session.
#[test]
fn session_area_validation_omissions_symmetric_checked_first() {
    let mut sim = new_sim();
    let mut s1 = start_session(&mut sim, TpmSe::HMAC, false);
    let mut s2 = start_session(&mut sim, TpmSe::HMAC, false);
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [
            SessUse::hmac(&mut s1, ATTR_CONT | ATTR_DECRYPT, &[]),
            SessUse::hmac(&mut s2, ATTR_CONT, &[]),
        ],
        &[0x00, 0x00],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_SYMMETRIC));
}

// tpm2-policysecret-auth-mode-bypass-and-policy-session-validation-bugs
#[test]
fn tpm2_policysecret_auth_mode_bypass_and_policy_session_validation_bugs() {
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

// parameter-encryption-decryption-command-table-discrepancies
#[test]
fn parameter_encryption_decryption_command_table_discrepancies() {
    let mut sim = new_sim();
    let mut s = start_session(&mut sim, TpmSe::HMAC, true);

    // ENCRYPT_2: TPM2_PolicyGetDigest.
    let p = start_session(&mut sim, TpmSe::Policy, false);
    let r = exec(
        &mut sim,
        CC_POLICY_GET_DIGEST,
        &[p.handle],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &[],
        0,
    );
    assert_eq!(r.rc, 0);

    // DECRYPT_2: TPM2_HashSequenceStart (auth is a TPM2B).
    let mut params = vec![0x00, 0x04, 1, 2, 3, 4];
    params.extend_from_slice(&ALG_SHA256.to_be_bytes());
    let r = exec(
        &mut sim,
        CC_HASH_SEQUENCE_START,
        &[],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[])],
        &params,
        1,
    );
    assert_eq!(r.rc, 0);

    // TPM2_EncryptDecrypt has no DECRYPT_2 (its first parameter is a TPMI_YES_NO).
    let key = create_primary_ecc(&mut sim);
    let rc = exec(
        &mut sim,
        CC_ENCRYPT_DECRYPT,
        &[key],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[])],
        &[0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_ATTRIBUTES));
}

// policy-session-zeroed-on-command-error-and-premature-exclusive-audit-clear
#[test]
fn policy_session_zeroed_on_command_error_and_premature_exclusive_audit_clear() {
    let mut sim = new_sim();

    // 1. A failing command leaves the policy sessions it used untouched.
    let mut p = start_session(&mut sim, TpmSe::Policy, true);
    assert_eq!(policy_command_code(&mut sim, p.handle, CC_GET_RANDOM), 0);
    let digest = policy_get_digest(&mut sim, p.handle);
    assert_ne!(digest, vec![0u8; 32]);
    // TPM2_LoadExternal with a malformed inPrivate fails inside the command handler.
    let mut params = vec![0x00, 0x02, 0xFF, 0xFF, 0x00, 0x00];
    params.extend_from_slice(&RH_NULL.to_be_bytes());
    let rc = exec(
        &mut sim,
        CC_LOAD_EXTERNAL,
        &[],
        &mut [SessUse::hmac(&mut p, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &params,
        1,
    )
    .rc;
    assert_ne!(rc, 0);
    assert_eq!(policy_get_digest(&mut sim, p.handle), digest);

    // 2. A failing TPM_ST_NO_SESSIONS command does not end audit exclusivity.
    let mut a = start_session(&mut sim, TpmSe::HMAC, false);
    let get_random = 8u16.to_be_bytes();
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(&mut a, ATTR_CONT | ATTR_AUDIT, &[])],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, 0);
    let rc = rc_of(&transact(
        &mut sim,
        &build(ST_NO_SESSIONS, CC_READ_PUBLIC, &[0x80FF_FFFF], None, &[]),
    ));
    assert_ne!(rc, 0);
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(
            &mut a,
            ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_EXCLUSIVE,
            &[],
        )],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, 0, "audit session should still be exclusive");

    // 3. A successful command resets every continued policy session in the session area, even
    //    one that only encrypts.
    let mut p = start_session(&mut sim, TpmSe::Policy, true);
    assert_eq!(policy_command_code(&mut sim, p.handle, CC_GET_RANDOM), 0);
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(&mut p, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, 0);
    assert_eq!(policy_get_digest(&mut sim, p.handle), vec![0u8; 32]);
}

// execcommand-header-size-and-session-unmarshal-error-bugs
#[test]
fn execcommand_header_size_and_session_unmarshal_error_bugs() {
    let mut sim = new_sim();
    let get_random = build(
        ST_NO_SESSIONS,
        CC_GET_RANDOM,
        &[],
        None,
        &8u16.to_be_bytes(),
    );
    assert_eq!(rc_of(&transact(&mut sim, &get_random)), 0);

    // Truncated header fields: TPM_RC_INSUFFICIENT; bad tag: TPM_RC_BAD_TAG.
    assert_eq!(rc_of(&transact(&mut sim, &[0x80])), RC_INSUFFICIENT);
    assert_eq!(
        rc_of(&transact(&mut sim, &[0x80, 0x01, 0, 0, 0])),
        RC_INSUFFICIENT
    );
    assert_eq!(rc_of(&transact(&mut sim, &[0x12, 0x34])), RC_BAD_TAG);
    let mut short = get_random[..8].to_vec();
    short[2..6].copy_from_slice(&8u32.to_be_bytes());
    assert_eq!(rc_of(&transact(&mut sim, &short)), RC_INSUFFICIENT);

    // commandSize must equal the number of received bytes.
    let mut bigger = get_random.clone();
    bigger[2..6].copy_from_slice(&13u32.to_be_bytes());
    assert_eq!(rc_of(&transact(&mut sim, &bigger)), RC_COMMAND_SIZE);
    let mut trailing = get_random.clone();
    trailing.extend_from_slice(&[0, 0]);
    assert_eq!(rc_of(&transact(&mut sim, &trailing)), RC_COMMAND_SIZE);

    // TPM_ST_SESSIONS with an authorization area smaller than one session.
    let cmd = build(
        ST_SESSIONS,
        CC_GET_RANDOM,
        &[],
        Some(&[]),
        &8u16.to_be_bytes(),
    );
    assert_eq!(rc_of(&transact(&mut sim, &cmd)), RC_SIZE);

    // Session commands accept the same parameter sizes as commands without sessions: a large
    // (malformed) TPM2_LoadExternal reaches the command handler instead of a bare TPM_RC_SIZE.
    let mut s = start_session(&mut sim, TpmSe::HMAC, false);
    let mut params = vec![];
    params.extend_from_slice(&1198u16.to_be_bytes());
    params.extend_from_slice(&[0xFF; 1198]);
    params.extend_from_slice(&[0x00, 0x00]);
    params.extend_from_slice(&RH_NULL.to_be_bytes());
    let rc = exec(
        &mut sim,
        CC_LOAD_EXTERNAL,
        &[],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_AUDIT, &[])],
        &params,
        1,
    )
    .rc;
    assert_ne!(rc, 0);
    assert_ne!(rc, RC_SIZE, "large session command rejected by the engine");
}

// verify-session-hmacs-check-nv-written-missing-rc-s-and-encrypt-decrypt-command-table
#[test]
fn verify_session_hmacs_check_nv_written_missing_rc_s_and_encrypt_decrypt_command_table() {
    let mut sim = new_sim();
    check_nv_written_on_non_nv_entity(&mut sim);

    // The command tables: TPM2_PolicyGetDigest allows an encrypt session.
    let mut s = start_session(&mut sim, TpmSe::HMAC, true);
    let p = start_session(&mut sim, TpmSe::Policy, false);
    let r = exec(
        &mut sim,
        CC_POLICY_GET_DIGEST,
        &[p.handle],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &[],
        0,
    );
    assert_eq!(r.rc, 0);
}

// verify-session-hmacs-check-nv-written-omits-session-position (handed over by fix-auth)
#[test]
fn verify_session_hmacs_check_nv_written_omits_session_position() {
    let mut sim = new_sim();
    check_nv_written_on_non_nv_entity(&mut sim);
}

// verify-session-hmacs-policy-cc-expired-flush-and-order-bugs
#[test]
fn verify_session_hmacs_policy_cc_expired_flush_and_order_bugs() {
    let mut sim = new_sim();
    policy_cc_mismatch_scenario(&mut sim);
    expired_policy_session_scenario(&mut sim);
}

// validate-policy-session-erroneous-expiration-and-handle-error-codes
#[test]
fn validate_policy_session_erroneous_expiration_and_handle_error_codes() {
    let mut sim = new_sim();
    policy_command_on_expired_session_scenario(&mut sim);
}

// session-area-unmarshal-and-attribute-validation-discrepancies
#[test]
fn session_area_unmarshal_and_attribute_validation_discrepancies() {
    let mut sim = new_sim();

    // authorizationSize < 9.
    let cmd = build(
        ST_SESSIONS,
        CC_GET_RANDOM,
        &[],
        Some(&[]),
        &8u16.to_be_bytes(),
    );
    assert_eq!(rc_of(&transact(&mut sim, &cmd)), RC_SIZE);

    // A password session must have an empty nonce.
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::pw(&[]).with_nonce(&[1, 2, 3, 4])],
        &[0x00, 0x00],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_NONCE));

    // Handle errors are reported before session-attribute errors.
    // TPM2_EncryptDecrypt on an unloaded key with a password session that (illegally) has
    // ENCRYPT set: C reports TPM_RC_REFERENCE_H0 (EntityGetLoadStatus) before looking at the
    // session area.
    let rc = exec(
        &mut sim,
        CC_ENCRYPT_DECRYPT,
        &[0x8000_0001],
        &mut [SessUse::pw(&[]).with_attrs(ATTR_CONT | ATTR_ENCRYPT)],
        &[0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00],
        0,
    )
    .rc;
    assert_eq!(rc, RC_REFERENCE_H0);
}

// build-response-sessions-strips-encrypt-decrypt-attributes-and-corrupts-response-hmacs
#[test]
fn build_response_sessions_strips_encrypt_decrypt_attributes_and_corrupts_response_hmacs() {
    let mut sim = new_sim();
    let mut s = start_session(&mut sim, TpmSe::HMAC, true);
    let r = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &8u16.to_be_bytes(),
        0,
    );
    assert_eq!(r.rc, 0);
    assert_eq!(r.session_attrs, vec![ATTR_CONT | ATTR_ENCRYPT]);
    // The response HMAC covers the attribute byte as returned.
    assert!(r.response_hmac_ok);

    let mut params = vec![0x00, 0x04, 1, 2, 3, 4];
    params.extend_from_slice(&ALG_SHA256.to_be_bytes());
    let r = exec(
        &mut sim,
        CC_HASH_SEQUENCE_START,
        &[],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[])],
        &params,
        1,
    );
    assert_eq!(r.rc, 0);
    assert_eq!(r.session_attrs, vec![ATTR_CONT | ATTR_DECRYPT]);
    assert!(r.response_hmac_ok);
}

// policy-session-timeout-expiration-and-command-code-error-discrepancies
#[test]
fn policy_session_timeout_expiration_and_command_code_error_discrepancies() {
    let mut sim = new_sim();
    policy_command_on_expired_session_scenario(&mut sim);
    policy_cc_mismatch_scenario(&mut sim);
}

// verify-session-hmacs-empty-auth-policy-returns-auth-unavailable-instead-of-policy-fail
// (handed over by fix-auth)
#[test]
fn verify_session_hmacs_empty_auth_policy_returns_auth_unavailable_instead_of_policy_fail() {
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

// unassociated-session-policy-and-empty-hmac-bugs (part 2, handed over by fix-auth)
#[test]
fn unassociated_session_policy_and_empty_hmac_bugs() {
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

// verify-session-hmacs-strips-trailing-zeros-on-hmac-and-checks-auth-before-cphash (part 2) and
// policy-password-non-empty-response-hmac-and-policy-check-order (part 2), handed over by
// fix-auth: cpHash is checked before the password.
#[test]
fn verify_session_hmacs_strips_trailing_zeros_on_hmac_and_checks_auth_before_cphash() {
    let mut sim = new_sim();
    let cp_hash = [0x33u8; 32];
    let mut cp_hash_param = vec![0x00, 0x20];
    cp_hash_param.extend_from_slice(&cp_hash);
    let digest = trial_digest(&mut sim, |sim, t| {
        assert_eq!(policy_cmd(sim, CC_POLICY_CP_HASH, t, &cp_hash_param), 0);
        assert_eq!(policy_cmd(sim, CC_POLICY_PASSWORD, t, &[]), 0);
    });
    set_owner_policy(&mut sim, &digest, &[]);
    let mut p = start_session(&mut sim, TpmSe::Policy, false);
    assert_eq!(
        policy_cmd(&mut sim, CC_POLICY_CP_HASH, p.handle, &cp_hash_param),
        0
    );
    assert_eq!(policy_cmd(&mut sim, CC_POLICY_PASSWORD, p.handle, &[]), 0);
    let rc = exec(
        &mut sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::policy_password(&mut p, b"wrong")],
        &create_primary_params(),
        1,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_POLICY_FAIL));
}

// policy-password-non-empty-response-hmac-and-policy-check-order (part 1)
#[test]
fn policy_password_non_empty_response_hmac_and_policy_check_order() {
    let mut sim = new_sim();
    // Give the owner a non-empty authValue so a response HMAC would have a non-empty key.
    let mut new_auth = vec![0x00, 0x02];
    new_auth.extend_from_slice(b"pw");
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::pw(&[])],
        &new_auth,
        0,
    )
    .rc;
    assert_eq!(rc, 0);

    let digest = trial_digest(&mut sim, |sim, t| {
        assert_eq!(policy_cmd(sim, CC_POLICY_PASSWORD, t, &[]), 0);
    });
    set_owner_policy(&mut sim, &digest, b"pw");
    let mut p = start_session(&mut sim, TpmSe::Policy, false);
    assert_eq!(policy_cmd(&mut sim, CC_POLICY_PASSWORD, p.handle, &[]), 0);
    let r = exec(
        &mut sim,
        CC_SET_PRIMARY_POLICY,
        &[RH_OWNER],
        &mut [SessUse::policy_password(&mut p, b"pw")],
        &set_primary_policy_params(&digest),
        0,
    );
    assert_eq!(r.rc, 0);
    assert_eq!(r.session_hmacs, vec![Vec::<u8>::new()]);
}

/// Sets the owner policy to `TPM2_PolicyNvWritten(YES)` and uses a satisfying policy session to
/// authorize the owner hierarchy (not an NV index): `TPM_RC_POLICY_FAIL + RC_S1`.
fn check_nv_written_on_non_nv_entity(sim: &mut Sim) {
    let digest = trial_digest(sim, |sim, t| {
        assert_eq!(policy_cmd(sim, CC_POLICY_NV_WRITTEN, t, &[0x01]), 0);
    });
    set_owner_policy(sim, &digest, &[]);
    let mut p = start_session(sim, TpmSe::Policy, false);
    assert_eq!(policy_cmd(sim, CC_POLICY_NV_WRITTEN, p.handle, &[0x01]), 0);
    let rc = exec(
        sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut p, ATTR_CONT, &[])],
        &create_primary_params(),
        1,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_POLICY_FAIL));
}

/// A policy session bound to another command code: `TPM_RC_POLICY_CC + RC_S1`.
fn policy_cc_mismatch_scenario(sim: &mut Sim) {
    let digest = trial_digest(sim, |sim, t| {
        assert_eq!(policy_command_code(sim, t, CC_NV_DEFINE_SPACE), 0);
    });
    set_owner_policy(sim, &digest, &[]);
    let mut p = start_session(sim, TpmSe::Policy, false);
    assert_eq!(policy_command_code(sim, p.handle, CC_NV_DEFINE_SPACE), 0);
    let rc = exec(
        sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut p, ATTR_CONT, &[])],
        &create_primary_params(),
        1,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_POLICY_CC));
}

/// Policy sessions with an expired timeout:
/// - when the policy matches, authorization fails with `TPM_RC_EXPIRED + RC_S1` and the session
///   stays loaded (it can still be restarted);
/// - when the policy does not match, the digest mismatch is reported first.
fn expired_policy_session_scenario(sim: &mut Sim) {
    let digest = trial_digest(sim, |sim, t| {
        assert_eq!(policy_secret(sim, t, &[], 0), 0);
    });
    set_owner_policy(sim, &digest, &[]);
    let mut p1 = start_session(sim, TpmSe::Policy, false);
    let mut p2 = start_session(sim, TpmSe::Policy, false);
    let nonce1 = p1.nonce_tpm.clone();
    let nonce2 = p2.nonce_tpm.clone();
    assert_eq!(policy_secret(sim, p1.handle, &nonce1, 1), 0);
    assert_eq!(policy_secret(sim, p2.handle, &nonce2, 1), 0);
    std::thread::sleep(Duration::from_millis(1500));

    let rc = exec(
        sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut p1, ATTR_CONT, &[])],
        &create_primary_params(),
        1,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_EXPIRED));
    assert_eq!(policy_cmd(sim, CC_POLICY_RESTART, p1.handle, &[]), 0);

    set_owner_policy(sim, &JUNK_DIGEST, &[]);
    let rc = exec(
        sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut p2, ATTR_CONT, &[])],
        &create_primary_params(),
        1,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_POLICY_FAIL));
}

/// Policy commands keep working on a policy session whose timeout has passed; expiration is
/// only enforced when the session authorizes a command.
fn policy_command_on_expired_session_scenario(sim: &mut Sim) {
    let p = start_session(sim, TpmSe::Policy, false);
    let nonce = p.nonce_tpm.clone();
    assert_eq!(policy_secret(sim, p.handle, &nonce, 1), 0);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(policy_cmd(sim, CC_POLICY_AUTH_VALUE, p.handle, &[]), 0);
    let r = transact(
        sim,
        &build(ST_NO_SESSIONS, CC_POLICY_GET_DIGEST, &[p.handle], None, &[]),
    );
    assert_eq!(rc_of(&r), 0);
}

// session-handle-resolution-reference-s0-h0-and-duplicate-bugs (items 1, 2, 4, 5; handed over by
// fix-attest)
#[test]
fn session_handle_resolution_reference_s0_h0_and_duplicate_bugs() {
    let mut sim = new_sim();
    let get_random = 8u16.to_be_bytes();

    // An unloaded session: TPM_RC_REFERENCE_S0.
    let mut ghost = Sess {
        handle: 0x0200_0005,
        nonce_tpm: vec![0; 16],
        session_key: vec![],
    };
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(&mut ghost, ATTR_CONT | ATTR_AUDIT, &[])],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, RC_REFERENCE_S0);

    // A loaded HMAC session referenced with the policy-session handle type: TPM_RC_HANDLE.
    let s = start_session(&mut sim, TpmSe::HMAC, false);
    let mut wrong_type = Sess {
        handle: (s.handle & 0x00FF_FFFF) | 0x0300_0000,
        ..s.clone()
    };
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(&mut wrong_type, ATTR_CONT | ATTR_AUDIT, &[])],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_HANDLE));

    // The same session twice in the session area: TPM_RC_HANDLE + RC_S2.
    let mut a = s.clone();
    let mut b = s.clone();
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [
            SessUse::hmac(&mut a, ATTR_CONT | ATTR_AUDIT, &[]),
            SessUse::hmac(&mut b, ATTR_CONT | ATTR_AUDIT, &[]),
        ],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, RC_HANDLE | 0xA00);

    // A session named in the handle area may also be used in the session area.
    let mut p = start_session(&mut sim, TpmSe::Policy, true);
    let p_handle = p.handle;
    let r = exec(
        &mut sim,
        CC_POLICY_GET_DIGEST,
        &[p_handle],
        &mut [SessUse::hmac(&mut p, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &[],
        0,
    );
    assert_eq!(r.rc, 0);
}
