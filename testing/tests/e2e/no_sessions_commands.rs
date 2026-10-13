//! Commands that take no sessions reject an authorization area with TPM_RC_AUTH_CONTEXT.

use crate::_common::{
    PW_SESSION_CONTINUE as PW_SESSION, build_raw_cmd as build_cmd,
    context_save_raw as context_save, create_storage_primary_in as create_primary,
    flush_rc as flush, mssim_rc_of as rc_of, start_session_raw as start_session, *,
};
use tpm2::errors::TpmRc;
use tpm2::*;
use tpm2_simulator::{SimulatorPlatformSignal, create_simulator};

/// TPM_RC_AUTH_CONTEXT is reported before the session area is unmarshaled, including truncated and audit-only sessions.
///
/// `TPM_RC_AUTH_CONTEXT` is reported before the session area is unmarshaled.
#[test]
fn auth_context_before_session_unmarshal() {
    let mut sim = create_simulator!();
    // A truncated TPMS_AUTH_COMMAND (sane authorizationSize) still yields AUTH_CONTEXT.
    let mut bad_session = PW_SESSION.to_vec();
    bad_session[5] = 0x10; // nonce size 0x0010 with no nonce bytes
    let cmd = build_cmd(
        ST_SESSIONS,
        CC_FLUSH_CONTEXT,
        &[],
        Some(&bad_session),
        &0x8000_0000u32.to_be_bytes(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::AUTH_CONTEXT.get());
    // An HMAC session used only for audit is rejected as well.
    let s = start_session(&mut sim, 0);
    let mut audit = s.to_be_bytes().to_vec();
    audit.extend_from_slice(&[0, 0, 0x81, 0, 0]);
    let cmd = build_cmd(
        ST_SESSIONS,
        CC_FLUSH_CONTEXT,
        &[],
        Some(&audit),
        &s.to_be_bytes(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::AUTH_CONTEXT.get());
}

/// NO_SESSIONS commands reject a session area with TPM_RC_AUTH_CONTEXT; FlushContext ignores the session type byte; object contexts start at sequence 1.
///
/// `NO_SESSIONS` commands reject a session area with `TPM_RC_AUTH_CONTEXT`; `TPM2_FlushContext`
/// ignores the session type byte; object context sequence numbers start at 1.
#[test]
fn session_area_rejected_and_flush_handle_aliases() {
    let mut sim = create_simulator!();

    let key = create_primary(&mut sim, Handle::RH_OWNER);
    let cmd = build_cmd(
        ST_SESSIONS,
        CC_FLUSH_CONTEXT,
        &[],
        Some(&PW_SESSION),
        &key.0.to_be_bytes(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::AUTH_CONTEXT.get());
    let cmd = build_cmd(
        ST_SESSIONS,
        CC_CONTEXT_SAVE,
        &[key.0],
        Some(&PW_SESSION),
        &[],
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::AUTH_CONTEXT.get());
    // Once started, Startup is rejected before its handles/sessions are looked at.
    let cmd = build_cmd(ST_SESSIONS, CC_STARTUP, &[], Some(&PW_SESSION), &[0, 0]);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::INITIALIZE.get());

    // The first saved object context has sequence 1.
    let ctx = context_save(&mut sim, key.0).unwrap();
    assert_eq!(context_sequence(&ctx), 1);
    let cmd = build_cmd(ST_SESSIONS, CC_CONTEXT_LOAD, &[], Some(&PW_SESSION), &ctx);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::AUTH_CONTEXT.get());

    // Flushing the policy session 0x03xxxxxx via its 0x02xxxxxx alias.
    let p = start_session(&mut sim, 1);
    assert_eq!(p >> 24, 0x03);
    assert_eq!(flush(&mut sim, 0x0200_0000 | (p & 0x00FF_FFFF)), 0);
    assert!(session_handles(&mut sim, false).is_empty());
    // ... and a saved HMAC session via its 0x03xxxxxx alias.
    let h = start_session(&mut sim, 0);
    context_save(&mut sim, h).unwrap();
    assert_eq!(flush(&mut sim, 0x0300_0000 | (h & 0x00FF_FFFF)), 0);
    assert!(session_handles(&mut sim, true).is_empty());
}

/// TPM2_Startup with a session area fails with TPM_RC_AUTH_CONTEXT and is not executed.
///
/// `TPM2_Startup` with a session area is `TPM_RC_AUTH_CONTEXT` (and is not executed).
#[test]
fn startup_with_sessions_not_executed() {
    let mut sim = create_simulator!();
    sim.signal_platform(SimulatorPlatformSignal::PowerOff, NO_STREAM)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn, NO_STREAM)
        .unwrap();
    nv_on(&mut sim);
    let cmd = build_cmd(ST_SESSIONS, CC_STARTUP, &[], Some(&PW_SESSION), &[0, 0]);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::AUTH_CONTEXT.get());
    // The TPM is still not started: a plain Startup succeeds.
    let cmd = build_cmd(ST_NO_SESSIONS, CC_STARTUP, &[], None, &[0, 0]);
    assert_eq!(rc_of(&mut sim, &cmd), 0);
}
