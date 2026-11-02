//! The vendor-specific permanent authorization handle `TPM_RH_AUTH_00`
//! (`VENDOR_PERMANENT_AUTH_HANDLE`, `tpm2-engine`'s `vendor-permanent-auth`; Part 1, "Permanent
//! Resource Handles (MSO=40)"). With the feature it is a permanent handle of the endorsement
//! hierarchy whose authValue is the platform's unique value (the byte-reversed "not really
//! unique" string of the C references' `_plat__GetUnique(1, ...)`); without it (like the C
//! references' upstream `VENDOR_PERMANENT_AUTH_ENABLED NO`) it is a valid `TPMI_DH_ENTITY`
//! value that references no entity (`TPM_RC_VALUE`) and is not reported as a handle.
//!
//! The feature is on by default in `tpm2-engine` and `tpm2-simulator` but off in `testing`'s
//! differential targets, and another crate of a build may turn it on, so the tests branch on
//! `tpm2_engine::VENDOR_PERMANENT_AUTH` (the feature as built) and skip the half that does not
//! apply.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bDigest, Tpm2bNonce, TpmSe, TpmiAlgHash, commands::PolicySecret};
use tpm2_engine::VENDOR_PERMANENT_AUTH;

/// `TPM_CC_StartAuthSession`.
const CC_START_AUTH_SESSION: u32 = 0x0000_0176;

/// Returns whether `TPM_CAP_HANDLES` lists `TPM_RH_AUTH_00` among the permanent handles.
fn auth_00_is_listed(sim: &mut Tpm) -> bool {
    let (handles, more) = cap_handles(sim, 0x4000_0000, 64).unwrap();
    assert!(!more);
    handles.contains(&Handle::RH_AUTH_00.0)
}

/// Sends `TPM2_StartAuthSession(TPM_RH_NULL, bind)` for an unsalted HMAC session with a
/// 16-octet nonceCaller and SHA-256; returns the response code.
fn start_bound_session_rc(sim: &mut Tpm, bind: u32) -> u32 {
    let mut params = 16u16.to_be_bytes().to_vec();
    params.extend_from_slice(&[0x33; 16]);
    params.extend_from_slice(&0u16.to_be_bytes()); // encryptedSalt
    params.push(0x00); // TPM_SE_HMAC
    params.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric: TPM_ALG_NULL
    params.extend_from_slice(&0x000Bu16.to_be_bytes()); // authHash: SHA-256
    let cmd = build(
        ST_NO_SESSIONS,
        CC_START_AUTH_SESSION,
        &[0x4000_0007, bind],
        None,
        &params,
    );
    mssim_rc_of(sim, &cmd)
}

/// Without the feature, `TPM_RH_AUTH_00` is not a permanent handle of this TPM: it is not
/// listed by `TPM_CAP_HANDLES`, cannot authorize TPM2_PolicySecret (`TPM_RC_VALUE` + H1) and
/// cannot be the bind entity of a session (`TPM_RC_VALUE` + H2).
#[test]
fn auth_00_is_not_implemented_without_feature() {
    if VENDOR_PERMANENT_AUTH {
        return;
    }
    let mut sim = Tpm::new();
    assert!(!auth_00_is_listed(&mut sim));
    let session = start_session_raw(&mut sim, 1);
    let cmd = build_raw_cmd(
        ST_SESSIONS,
        CC_POLICY_SECRET,
        &[Handle::RH_AUTH_00.0, session],
        Some(&PW_SESSION),
        &policy_secret_default_params(),
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), RC_VALUE_H1);
    assert_eq!(
        start_bound_session_rc(&mut sim, Handle::RH_AUTH_00.0),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );
}

/// The other vendor authorization handles (`TPM_RH_AUTH_01..TPM_RH_AUTH_FF`) are valid
/// `TPMI_DH_ENTITY` values that reference no entity on this TPM (`TPM_RC_VALUE` + H1).
#[test]
fn other_vendor_auth_handles_reference_nothing() {
    let mut sim = Tpm::new();
    let session = start_session_raw(&mut sim, 1);
    for handle in [Handle::RH_AUTH_00.0 + 1, Handle::RH_AUTH_FF.0] {
        let cmd = build_raw_cmd(
            ST_SESSIONS,
            CC_POLICY_SECRET,
            &[handle, session],
            Some(&PW_SESSION),
            &policy_secret_default_params(),
        );
        assert_eq!(mssim_rc_of(&mut sim, &cmd), RC_VALUE_H1, "{handle:#x}");
    }
}

/// With the feature, `TPM2_GetCapability(TPM_CAP_HANDLES)` lists `TPM_RH_AUTH_00` among the
/// permanent handles, and the platform unique value (`_plat__GetUnique(1, ...)` of the
/// references: their "not really unique" string, byte reversed) authorizes it in
/// TPM2_PolicySecret.
#[test]
fn auth_00_is_authorized_by_platform_unique_value() {
    if !VENDOR_PERMANENT_AUTH {
        return;
    }
    let mut sim = Tpm::new();
    assert!(auth_00_is_listed(&mut sim));
    let unique = b"euqinu laer A .eulav euqinu a yllaer ton si sihT";
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let cmd = PolicySecret {
        auth_handle: Handle::RH_AUTH_00,
        policy_session: session.session_handle,
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, unique)
        .expect("TPM2_PolicySecret with TPM_RH_AUTH_00 must succeed");
    assert!(execute_with_password_sessions(&mut sim, &cmd, 1, b"wrong").is_err());
}

/// With the feature, `TPM_RH_AUTH_00` can be the bind entity of a session, and it belongs to
/// the endorsement hierarchy: while `ehEnable` is CLEAR it is `TPM_RC_HIERARCHY`.
#[test]
fn auth_00_binds_sessions_and_follows_endorsement_hierarchy() {
    if !VENDOR_PERMANENT_AUTH {
        return;
    }
    let mut sim = Tpm::new();
    assert_eq!(start_bound_session_rc(&mut sim, Handle::RH_AUTH_00.0), 0);
    set_hierarchy_enabled(&mut sim, Handle::RH_ENDORSEMENT, false);
    assert_eq!(
        start_bound_session_rc(&mut sim, Handle::RH_AUTH_00.0),
        TpmRc::HIERARCHY.with(Position::handle(2)).get()
    );
}
