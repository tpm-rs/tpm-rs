//! Session lifecycle: starting, using and flushing HMAC/policy sessions.

use crate::_common::{
    create_primary_key, execute_with_hmac_sessions, flush_context, start_auth_session,
};
use testing::tpm::Tpm;
use tpm2::commands::ReadPublic;
use tpm2::{Handle, TpmSe, TpmiAlgHash};

/// Flushing an already flushed session fails.
#[test]
fn double_flush_fails() {
    let mut sim = Tpm::new();
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    flush_context(&mut sim, sess.session_handle).unwrap();
    let _ = flush_context(&mut sim, sess.session_handle).unwrap_err();
}

/// FlushContext succeeds on a loaded HMAC session.
#[test]
fn flush_context_removes_session() {
    let mut sim = Tpm::new();
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    flush_context(&mut sim, sess.session_handle).unwrap();
}

/// FlushContext of an unloaded session handle fails with TPM_RC_HANDLE + P1.
#[test]
fn flush_unloaded_session_returns_handle_p1() {
    let mut sim = Tpm::new();
    let err = flush_context(&mut sim, Handle(0x0200003f)).unwrap_err();
    // C FlushContext.c: flushHandle is a parameter, so an unloaded session
    // returns TPM_RCS_HANDLE + RC_FlushContext_flushHandle (HANDLE+P1, 0x1CB).
    assert_eq!(err, 0x1cb);
}

/// Using a flushed session in a command fails with TPM_RC_REFERENCE_S0.
#[test]
fn flushed_session_use_returns_reference_s0() {
    let mut sim = Tpm::new();
    let object_handle = create_primary_key(&mut sim);
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    flush_context(&mut sim, sess.session_handle).unwrap();
    let read_cmd = ReadPublic { object_handle };
    let err = match execute_with_hmac_sessions(&mut sim, &read_cmd, &[], &mut [sess], &[&[]]) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // C RetrieveSessionData: a session handle that is not loaded returns
    // TPM_RC_REFERENCE_S0 (0x918), not HANDLE+S1.
    assert_eq!(err, 0x918);
}

/// A new HMAC session can be started after flushing the previous one.
#[test]
fn session_restarts_after_flush() {
    let mut sim = Tpm::new();
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    flush_context(&mut sim, sess.session_handle).unwrap();
    let _sess2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

/// Three HMAC sessions can be started and loaded at the same time.
#[test]
fn three_sessions_coexist() {
    let mut sim = Tpm::new();
    let _sess1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let _sess2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let _sess3 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}
