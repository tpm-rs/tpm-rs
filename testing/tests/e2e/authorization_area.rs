//! Command header and authorization-area parsing: sizes, tags, session counts and the order of
//! authorization errors.

use crate::_common::{
    ATTR_AUDIT, ATTR_CONT, ATTR_CONTINUE, ATTR_ENCRYPT, AuthEntry, CC_ENCRYPT_DECRYPT,
    CC_GET_RANDOM, CC_HIERARCHY_CHANGE_AUTH, CC_LOAD_EXTERNAL, RC_AUTH_MISSING, RC_BAD_AUTH_S1,
    RC_BAD_TAG, RC_COMMAND_SIZE, RC_INSUFFICIENT, RC_NONCE, RC_REFERENCE_H0, RC_SIZE, RC_SUCCESS,
    RH_NULL, RH_OWNER, ST_NO_SESSIONS, ST_SESSIONS, SessUse, build, create_sealed, exec, new_sim,
    raw_entry, rc_of, rc_s1, send_rc_with_auth_entries, start_session, start_session_of_type,
    tpm2b_params, transact,
};
use tpm2::{Handle, TpmCc, TpmSe, TpmaObject};
use tpm2_simulator::create_simulator;

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
    let mut sim = create_simulator!();

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
    let mut sim = create_simulator!();
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
