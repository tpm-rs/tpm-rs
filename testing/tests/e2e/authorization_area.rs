//! Command header and authorization-area parsing: sizes, tags, session counts and the order of
//! authorization errors.

use crate::_common::{
    ATTR_AUDIT, ATTR_CONT, ATTR_CONTINUE, ATTR_ENCRYPT, AuthEntry, CC_ENCRYPT_DECRYPT,
    CC_GET_RANDOM, CC_HIERARCHY_CHANGE_AUTH, CC_LOAD_EXTERNAL, RC_AUTH_MISSING, RC_BAD_AUTH_S1,
    RC_BAD_TAG, RC_COMMAND_SIZE, RC_INSUFFICIENT, RC_NONCE, RC_REFERENCE_H0, RC_SIZE, RC_SUCCESS,
    RC_VALUE_H1, RH_NULL, RH_OWNER, ST_NO_SESSIONS, ST_SESSIONS, SessUse, build, create_sealed,
    exec, new_sim, raw_entry, rc_of, rc_s1, send_rc_with_auth_entries, start_session,
    start_session_of_type, tpm2b_params, transact,
};
use testing::tpm::Tpm;
use tpm2::{Handle, TpmCc, TpmSe, TpmaObject};

/// authorizationSize < 9, password nonce non-empty, handle errors (REFERENCE_H0) before session attribute errors.
#[test]
fn auth_size_nonce_and_handle_error_order() {
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

/// Handles requiring authorization need a session even with an empty authValue; one session per authorized handle (PCR_Allocate, Certify)
///
/// A handle that requires authorization always needs a session, even when its authValue is
/// empty (C `CheckAuthNoSession()` and the handle loop of `ParseSessionBuffer()`), and
/// `TPM2_PCR_Allocate` requires authorization of `TPM_RH_PLATFORM`.
#[test]
fn authorization_requires_session_even_with_empty_auth() {
    let mut sim = Tpm::new();

    // No session area at all, empty ownerAuth.
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[],
        &tpm2b_params(b""),
    );
    assert_eq!(code, RC_AUTH_MISSING);

    // TPM2_PCR_Allocate: platform authorization is required and a password session is
    // associated with the platform handle.
    let allocation = [
        0u8, 0, 0, 1, // count
        0x00, 0x0B, // SHA-256
        3, 0xFF, 0xFF, 0xFF, // all 24 PCRs
    ];
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::PCRAllocate,
        &[Handle::RH_PLATFORM.0],
        &[],
        &allocation,
    );
    assert_eq!(code, RC_AUTH_MISSING);
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::PCRAllocate,
        &[Handle::RH_PLATFORM.0],
        &[AuthEntry::pw(&[])],
        &allocation,
    );
    assert_eq!(code, RC_SUCCESS);

    // Fewer sessions than authorized handles: TPM2_Certify authorizes both objectHandle and
    // signHandle, even if signHandle is TPM_RH_NULL.
    let item = create_sealed(
        &mut sim,
        TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        b"",
        &[],
    );
    let mut certify_params = tpm2b_params(&[]);
    certify_params.extend_from_slice(&0x0010u16.to_be_bytes()); // TPM_ALG_NULL scheme
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::Certify,
        &[item, Handle::RH_NULL.0],
        &[AuthEntry::pw(&[])],
        &certify_params,
    );
    assert_eq!(code, RC_AUTH_MISSING);

    // The same with two real (loaded, non-NULL) entities: the single session authorizes only
    // objectHandle, so signHandle has no authorization (C `ParseSessionBuffer()` handle loop).
    let signer = create_sealed(
        &mut sim,
        TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        b"signer",
        &[],
    );
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::Certify,
        &[item, signer],
        &[AuthEntry::pw(&[])],
        &certify_params,
    );
    assert_eq!(code, RC_AUTH_MISSING);
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::ActivateCredential,
        &[item, signer],
        &[AuthEntry::pw(&[])],
        &[0, 0, 0, 0],
    );
    assert_eq!(code, RC_AUTH_MISSING);
}

/// Truncated header INSUFFICIENT, bad tag BAD_TAG, commandSize mismatch, short auth area, large session commands reach handler.
#[test]
fn command_header_and_auth_area_sizes() {
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

/// TPM2_PCR_Allocate checks password and HMAC sessions against platformAuth (HANDLE_1_USER)
///
/// `TPM2_PCR_Allocate` is a `HANDLE_1_USER` command (the duplicate finding owned by fix-capctx).
#[test]
fn pcr_allocate_requires_platform_auth() {
    let mut sim = Tpm::new();
    let allocation = [0u8, 0, 0, 1, 0x00, 0x0B, 3, 0xFF, 0xFF, 0xFF];

    // A password session is associated with (and checked against) platformAuth.
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_PLATFORM.0],
        &[AuthEntry::pw(&[])],
        &tpm2b_params(b"platform"),
    );
    assert_eq!(code, RC_SUCCESS);
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::PCRAllocate,
        &[Handle::RH_PLATFORM.0],
        &[AuthEntry::pw(b"wrong")],
        &allocation,
    );
    assert_eq!(code, RC_BAD_AUTH_S1);

    // An HMAC session must prove knowledge of platformAuth too.
    let session = start_session_of_type(&mut sim, TpmSe::HMAC);
    let auth = raw_entry(&session, ATTR_CONTINUE, &[0x55; 32]);
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::PCRAllocate,
        &[Handle::RH_PLATFORM.0],
        &[auth],
        &allocation,
    );
    assert_eq!(code, RC_BAD_AUTH_S1);

    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::PCRAllocate,
        &[Handle::RH_PLATFORM.0],
        &[AuthEntry::pw(b"platform")],
        &allocation,
    );
    assert_eq!(code, RC_SUCCESS);
}

/// Invalid handles are reported before a missing `authorizationSize`, as the C reference parses
/// and validates the handle area before it unmarshals the authorization area: a `TPM_ST_SESSIONS`
/// command that ends after its handle area fails with the handle's error, not with
/// `TPM_RC_INSUFFICIENT` (found by differential fuzzing).
#[test]
fn invalid_handle_is_reported_before_missing_authorization_size() {
    const CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
    const CC_CONTEXT_SAVE: u32 = 0x0000_0162;
    let mut sim = new_sim();
    // `TPM2_NV_DefineSpace` with `authHandle` 0 (not a `TPMI_RH_PROVISION`) and nothing after it.
    let cmd = [0x80, 0x02, 0, 0, 0, 14, 0, 0, 0x01, 0x2A, 0, 0, 0, 0];
    assert_eq!(
        cmd,
        build(ST_SESSIONS, CC_NV_DEFINE_SPACE, &[0], None, &[]).as_slice()
    );
    assert_eq!(rc_of(&transact(&mut sim, &cmd)), RC_VALUE_H1);
    // With a valid handle the missing `authorizationSize` is reported.
    let cmd = build(ST_SESSIONS, CC_NV_DEFINE_SPACE, &[RH_OWNER], None, &[]);
    assert_eq!(rc_of(&transact(&mut sim, &cmd)), RC_INSUFFICIENT);
    // The same for a command that does not allow sessions: `TPM2_ContextSave` of the owner
    // hierarchy (not a `TPMI_DH_CONTEXT`).
    let cmd = build(ST_SESSIONS, CC_CONTEXT_SAVE, &[RH_OWNER], None, &[]);
    assert_eq!(rc_of(&transact(&mut sim, &cmd)), RC_VALUE_H1);
}

/// Each session is checked as it is unmarshaled: an unloaded first session is
/// `TPM_RC_REFERENCE_S0` even though the second session would not unmarshal. TPM 2.0 Part 3,
/// "Session Area Validation": "The TPM will unmarshal the authorization sessions and perform the
/// following validations: [...] If the session is not loaded, the TPM will return the warning
/// `TPM_RC_REFERENCE_S0` + N where N is the number of the session." The specification does not
/// order the sessions' checks against each other; this follows the TCG reference
/// (`RetrieveSessionData()`). Found by differential fuzzing.
#[test]
fn unloaded_session_reported_before_later_sessions_are_unmarshaled() {
    let mut tpm = testing::tpm::Tpm::new();
    let steps: [(&str, u32); 2] = [
        (
            concat!(
                "800200000043000001314000000100000009400000090000010000000400000000001a0023000b000300720000000600",
                "80004300100003001000000000000000000000",
            ),
            0x000,
        ),
        (
            concat!(
                "800200000083000001538000000000000039020000000000000000000000aa104151c3dbab3ddfeea52fd338f4188118",
                "8200205d2e90f619f1ee886d62b1f8c308963b69d031efb905ad43000000340015000a70407373773072640000000773",
                "656372657473000e0008000b0000045200000010000000000000000080800102000100",
            ),
            0x918,
        ),
    ];
    for (i, (cmd, rc)) in steps.into_iter().enumerate() {
        let rsp = tpm.send_command(0, &crate::_common::hex_checked(cmd));
        assert_eq!(
            u32::from_be_bytes(rsp[6..10].try_into().unwrap()),
            rc,
            "step {i}: {rsp:02x?}"
        );
    }
}

/// Handles are unmarshaled one after the other: a first handle outside its interface type is
/// `TPM_RC_VALUE + H1` even when the second handle is missing (which would be
/// `TPM_RC_INSUFFICIENT + H2`). TPM 2.0 Part 3, "Handle Area Validation": "1. The TPM shall
/// successfully unmarshal the number of handles required by the command and validate that the
/// value of the handle is consistent with the command syntax. If not, the TPM shall return
/// `TPM_RC_VALUE`." Found by differential fuzzing.
#[test]
fn invalid_first_handle_reported_before_missing_second_handle() {
    let mut sim = new_sim();
    // `TPM2_NV_UndefineSpaceSpecial(nvIndex = 0, <platform missing>)`.
    let cmd = [0x80, 0x02, 0, 0, 0, 14, 0, 0, 0x01, 0x1F, 0, 0, 0, 0];
    assert_eq!(rc_of(&transact(&mut sim, &cmd)), RC_VALUE_H1);
    // With a valid first handle the missing second one is reported.
    let cmd = [0x80, 0x02, 0, 0, 0, 14, 0, 0, 0x01, 0x1F, 0x01, 0, 0, 0];
    assert_eq!(rc_of(&transact(&mut sim, &cmd)), 0x29A);
}

/// A command larger than the TPM's `MAX_COMMAND_SIZE` (`4096 - 0x80` octets, the value reported
/// as `TPM_PT_MAX_COMMAND_SIZE`) is `TPM_RC_COMMAND_SIZE`, before its handles or sessions are
/// examined. TPM 2.0 Part 2, `TPM_PT_MAX_COMMAND_SIZE`: "the maximum value for *commandSize* in a
/// command"; Part 3, "Command Header Validation": "2. The TPM shall successfully unmarshal a
/// UINT32 as the *commandSize*. [...] (`TPM_RC_COMMAND_SIZE`)." The specification does not name
/// the response code for a *commandSize* above the maximum; this follows the TCG reference
/// (`TPM_RC_COMMAND_SIZE`, checked together with the received size). Found by differential
/// fuzzing.
#[test]
fn command_larger_than_max_command_size_rejected() {
    let mut sim = new_sim();
    for (len, expected) in [(4096 - 0x80 + 1, 0x142), (4096, 0x142)] {
        // `TPM2_NV_UndefineSpaceSpecial` with an invalid handle and padding.
        let mut cmd = vec![0x80, 0x02, 0, 0, 0, 0, 0, 0, 0x01, 0x1F, 0, 0, 0, 0];
        cmd.resize(len, 0);
        cmd[2..6].copy_from_slice(&(len as u32).to_be_bytes());
        assert_eq!(rc_of(&transact(&mut sim, &cmd)), expected, "{len} octets");
    }
}

/// `auditExclusive` or `auditReset` without `audit` is `TPM_RC_ATTRIBUTES` at the session, before
/// any later session is unmarshaled. TPM 2.0 Part 2, Table "Definition of (UINT8) TPMA_SESSION
/// Bits": "This setting is only allowed if the *audit* attribute is SET (TPM_RC_ATTRIBUTES)."
/// (Both references needed a `bug-fix-session-audit-attribute-dependency` patch.) Found by
/// differential fuzzing.
#[test]
fn audit_reset_without_audit_rejected() {
    let mut sim = new_sim();
    // `TPM2_StartAuthSession(TPM_RH_NULL, TPM_RH_NULL)`: unsalted, unbound HMAC session, NULL
    // symmetric, SHA-256.
    let mut start = vec![
        0x80, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0x76, 0x40, 0, 0, 7, 0x40, 0, 0, 7,
    ];
    start.extend_from_slice(&[0, 16]);
    start.extend_from_slice(&[0x11; 16]);
    start.extend_from_slice(&[0, 0, 0x00, 0, 0x10, 0, 0x0B]);
    let len = start.len() as u32;
    start[2..6].copy_from_slice(&len.to_be_bytes());
    let rsp = transact(&mut sim, &start);
    assert_eq!(rc_of(&rsp), 0, "{rsp:02x?}");
    let session = &rsp[10..14];
    for attrs in [0x04u8, 0x02, 0x06] {
        // `TPM2_GetRandom(8)` with the session (auditReset/auditExclusive, no audit), then a
        // second session that would not unmarshal.
        let mut cmd = vec![0x80, 0x02, 0, 0, 0, 0, 0, 0, 0x01, 0x7B];
        let mut area = session.to_vec();
        area.extend_from_slice(&[0, 0, attrs, 0, 0]);
        area.extend_from_slice(&[0, 0, 0xAA, 0x10]);
        cmd.extend_from_slice(&(area.len() as u32).to_be_bytes());
        cmd.extend_from_slice(&area);
        cmd.extend_from_slice(&[0, 8]);
        let len = cmd.len() as u32;
        cmd[2..6].copy_from_slice(&len.to_be_bytes());
        // `TPM_RC_ATTRIBUTES + TPM_RC_S + TPM_RC_1`.
        assert_eq!(
            rc_of(&transact(&mut sim, &cmd)),
            0x982,
            "attributes {attrs:#x}"
        );
    }
}
