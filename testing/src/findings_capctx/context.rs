//! Regression tests for the context management findings (`TPM2_ContextSave`,
//! `TPM2_ContextLoad`, `TPM2_FlushContext`).

use super::*;
use crate::findings_sessions::helpers as sh;

const CC_CONTEXT_SAVE: u32 = 0x162;
const CC_CONTEXT_LOAD: u32 = 0x161;
const CC_FLUSH_CONTEXT: u32 = 0x165;
const CC_STARTUP: u32 = 0x144;
const CC_POLICY_TEMPLATE: u32 = 0x190;
const CC_POLICY_CP_HASH: u32 = 0x16E;

/// `TPM2_ContextSave(handle)`; returns the marshaled `TPMS_CONTEXT` on success.
fn context_save(sim: &mut Simulator<'_>, handle: u32) -> Result<Vec<u8>, u32> {
    let cmd = build_cmd(ST_NO_SESSIONS, CC_CONTEXT_SAVE, &[handle], None, &[]);
    let (rc, resp) = send(sim, &cmd);
    if rc != 0 {
        return Err(rc);
    }
    Ok(resp[10..].to_vec())
}

/// `TPM2_ContextLoad(context)`; returns the loaded handle on success.
fn context_load(sim: &mut Simulator<'_>, context: &[u8]) -> Result<u32, u32> {
    let cmd = build_cmd(ST_NO_SESSIONS, CC_CONTEXT_LOAD, &[], None, context);
    let (rc, resp) = send(sim, &cmd);
    if rc != 0 {
        return Err(rc);
    }
    Ok(u32::from_be_bytes(resp[10..14].try_into().unwrap()))
}

/// `TPM2_FlushContext(handle)`.
fn flush(sim: &mut Simulator<'_>, handle: u32) -> u32 {
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_FLUSH_CONTEXT,
        &[],
        None,
        &handle.to_be_bytes(),
    );
    rc_of(sim, &cmd)
}

/// Returns the `sequence` of a marshaled `TPMS_CONTEXT`.
fn context_sequence(context: &[u8]) -> u64 {
    u64::from_be_bytes(context[0..8].try_into().unwrap())
}

/// Returns the loaded / saved session handles reported by `TPM_CAP_HANDLES`.
fn session_handles(sim: &mut Simulator<'_>, saved: bool) -> Vec<u32> {
    let property = if saved { 0x0300_0000 } else { 0x0200_0000 };
    let (_, data) = super::capability::get_cap(sim, 1, property, 64).unwrap();
    let n = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    (0..n)
        .map(|i| u32::from_be_bytes(data[4 + 4 * i..8 + 4 * i].try_into().unwrap()))
        .collect()
}

/// Only the latest saved context of a currently saved session can be loaded (no replay, no
/// reload after a flush), errors carry `RC_P1`, and the `TPM2_PolicyTemplate` state survives a
/// save/load cycle.
#[test]
fn tpm2_contextload_session_replay_and_error_code_bugs() {
    let mut sim = create_simulator!();
    let s = start_session(&mut sim, 0);

    let ctx1 = context_save(&mut sim, s).unwrap();
    assert_eq!(context_load(&mut sim, &ctx1), Ok(s));
    let ctx2 = context_save(&mut sim, s).unwrap();
    // Replaying the older context is rejected.
    assert_eq!(context_load(&mut sim, &ctx1), Err(rc_p(TpmRc::HANDLE, 1)));
    assert_eq!(context_load(&mut sim, &ctx2), Ok(s));
    // Loading a context of a session that is currently loaded is rejected.
    assert_eq!(context_load(&mut sim, &ctx2), Err(rc_p(TpmRc::HANDLE, 1)));

    // A saved session that was flushed cannot be loaded again.
    let ctx3 = context_save(&mut sim, s).unwrap();
    assert_eq!(flush(&mut sim, s), 0);
    assert_eq!(context_load(&mut sim, &ctx3), Err(rc_p(TpmRc::HANDLE, 1)));

    // A corrupted integrity value: TPM_RC_INTEGRITY + RC_P1.
    let t = start_session(&mut sim, 0);
    let ctx = context_save(&mut sim, t).unwrap();
    let mut bad = ctx.clone();
    bad[16 + 2 + 2] ^= 0xFF; // first byte of the integrity digest
    assert_eq!(context_load(&mut sim, &bad), Err(rc_p(TpmRc::INTEGRITY, 1)));
    assert_eq!(context_load(&mut sim, &ctx), Ok(t));

    // isTemplateHashDefined is part of the saved session context.
    let p = start_session(&mut sim, 1);
    let mut digest = 32u16.to_be_bytes().to_vec();
    digest.extend_from_slice(&[0x5A; 32]);
    let cmd = build_cmd(ST_NO_SESSIONS, CC_POLICY_TEMPLATE, &[p], None, &digest);
    assert_eq!(rc_of(&mut sim, &cmd), 0);
    let ctx = context_save(&mut sim, p).unwrap();
    assert_eq!(context_load(&mut sim, &ctx), Ok(p));
    let mut cp = 32u16.to_be_bytes().to_vec();
    cp.extend_from_slice(&[0x77; 32]);
    let cmd = build_cmd(ST_NO_SESSIONS, CC_POLICY_CP_HASH, &[p], None, &cp);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::CPHASH.get());
}

/// Saving the exclusive audit session keeps it exclusive; saved sessions are tracked beyond
/// `MAX_LOADED_SESSIONS`; `TPM2_FlushContext` reports `TPM_RC_HANDLE + RC_P1`.
#[test]
fn tpm2_flushcontext_and_contextsave_exclusive_audit_and_handle_bugs() {
    let mut sim = create_simulator!();

    // 1. Exclusive audit survives ContextSave/ContextLoad.
    let mut a = sh::start_session(&mut sim, TpmSe::HMAC, false);
    let get_random = 8u16.to_be_bytes();
    let rc = sh::exec(
        &mut sim,
        sh::CC_GET_RANDOM,
        &[],
        &mut [sh::SessUse::hmac(
            &mut a,
            sh::ATTR_CONT | sh::ATTR_AUDIT,
            &[],
        )],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, 0);
    let ctx = context_save(&mut sim, a.handle).unwrap();
    assert_eq!(context_load(&mut sim, &ctx), Ok(a.handle));
    let rc = sh::exec(
        &mut sim,
        sh::CC_GET_RANDOM,
        &[],
        &mut [sh::SessUse::hmac(
            &mut a,
            sh::ATTR_CONT | sh::ATTR_AUDIT | sh::ATTR_AUDIT_EXCLUSIVE,
            &[],
        )],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(
        rc, 0,
        "audit session must still be exclusive after save/load"
    );
    assert_eq!(flush(&mut sim, a.handle), 0);

    // 2. More saved sessions than MAX_LOADED_SESSIONS are tracked and can be flushed.
    let mut saved = Vec::new();
    for _ in 0..5 {
        let h = start_session(&mut sim, 0);
        context_save(&mut sim, h).unwrap();
        saved.push(h);
    }
    let reported = session_handles(&mut sim, true);
    for h in &saved {
        assert!(
            reported.contains(&(0x0200_0000 | (h & 0x00FF_FFFF))),
            "saved session {h:#x} not reported"
        );
    }
    for h in &saved {
        assert_eq!(flush(&mut sim, *h), 0, "flush {h:#x}");
    }
    assert!(session_handles(&mut sim, true).is_empty());

    // 3. Unloaded transient object / unknown session: TPM_RC_HANDLE + RC_P1.
    assert_eq!(flush(&mut sim, 0x8000_0005), rc_p(TpmRc::HANDLE, 1));
    assert_eq!(flush(&mut sim, 0x0200_0010), rc_p(TpmRc::HANDLE, 1));
}

/// `NO_SESSIONS` commands reject a session area with `TPM_RC_AUTH_CONTEXT`; `TPM2_FlushContext`
/// ignores the session type byte; object context sequence numbers start at 1.
#[test]
fn no_sessions_commands_missing_auth_context_and_flush_context_session_type_bugs() {
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

/// `TPM2_Startup` with a session area is `TPM_RC_AUTH_CONTEXT` (and is not executed).
#[test]
fn no_sessions_commands_missing_auth_context_startup() {
    let mut sim = create_simulator!();
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    nv_on(&mut sim);
    let cmd = build_cmd(ST_SESSIONS, CC_STARTUP, &[], Some(&PW_SESSION), &[0, 0]);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::AUTH_CONTEXT.get());
    // The TPM is still not started: a plain Startup succeeds.
    let cmd = build_cmd(ST_NO_SESSIONS, CC_STARTUP, &[], None, &[0, 0]);
    assert_eq!(rc_of(&mut sim, &cmd), 0);
}

/// The session context gap is enforced: once the context counter has advanced 64K times past
/// the oldest saved session, saving another session fails with `TPM_RC_CONTEXT_GAP`, and
/// loading anything but the oldest context into the last free slot fails too.
#[test]
fn contextsave_contextload_integrity_fingerprint_and_gap_bugs() {
    let mut sim = create_simulator!();
    let oldest = start_session(&mut sim, 0);
    let oldest_ctx = context_save(&mut sim, oldest).unwrap();
    let b = start_session(&mut sim, 0);
    let mut last_ctx = None;
    let mut gap_hit = false;
    for _ in 0..70_000 {
        match context_save(&mut sim, b) {
            Ok(ctx) => {
                assert_eq!(context_load(&mut sim, &ctx), Ok(b));
                last_ctx = Some(ctx);
            }
            Err(rc) => {
                assert_eq!(rc, TpmRc::CONTEXT_GAP.get());
                gap_hit = true;
                break;
            }
        }
    }
    assert!(gap_hit, "TPM_RC_CONTEXT_GAP never reported");
    let last = last_ctx.unwrap();
    assert!(context_sequence(&last) - context_sequence(&oldest_ctx) <= 0x1_0000);

    // Loading the oldest context resolves the gap; afterwards b can be saved again.
    assert_eq!(context_load(&mut sim, &oldest_ctx), Ok(oldest));
    assert!(context_save(&mut sim, b).is_ok());
}

/// `TPM2_ContextSave` validates `saveHandle` as a `TPMI_DH_CONTEXT` (`TPM_RC_VALUE + RC_H1`)
/// and checks the session type of session handles; `TPM2_FlushContext` positions its errors.
#[test]
fn context_save_and_flush_context_handle_validation_and_session_masking_bugs() {
    let mut sim = create_simulator!();
    for handle in [0x8100_0099u32, 0x4000_0005, 0x4000_0001, 0x0100_0001] {
        assert_eq!(
            context_save(&mut sim, handle),
            Err(rc_h(TpmRc::VALUE, 1)),
            "handle {handle:#x}"
        );
    }
    // Unloaded session / transient handles.
    assert_eq!(
        context_save(&mut sim, 0x0200_0007),
        Err(TpmRc::REFERENCE_H0.get())
    );
    assert_eq!(
        context_save(&mut sim, 0x8000_0007),
        Err(TpmRc::REFERENCE_H0.get())
    );
    // A loaded policy session referenced with the HMAC type byte: TPM_RC_HANDLE + RC_H1.
    let p = start_session(&mut sim, 1);
    assert_eq!(
        context_save(&mut sim, 0x0200_0000 | (p & 0x00FF_FFFF)),
        Err(rc_h(TpmRc::HANDLE, 1))
    );
    assert!(context_save(&mut sim, p).is_ok());

    assert_eq!(flush(&mut sim, 0x8000_0009), rc_p(TpmRc::HANDLE, 1));
    assert_eq!(flush(&mut sim, 0x4000_0001), rc_p(TpmRc::VALUE, 1));
}

/// `TPM2_ContextSave` performs `RETURN_IF_ORDERLY` only after the parameter checks: trailing
/// bytes are `TPM_RC_SIZE` even when NV is unavailable in an orderly state.
#[test]
fn context_save_nv_clear_orderly_executed_before_handle_and_parameter_validation() {
    let mut sim = create_simulator!();
    let key = create_primary(&mut sim, Handle::RH_OWNER);
    // TPM2_Shutdown(CLEAR) makes the state orderly; the TPM keeps executing commands.
    let shutdown = build_cmd(ST_NO_SESSIONS, 0x145, &[], None, &0u16.to_be_bytes());
    assert_eq!(rc_of(&mut sim, &shutdown), 0);
    nv_off(&mut sim);
    let cmd = build_cmd(ST_NO_SESSIONS, CC_CONTEXT_SAVE, &[key.0], None, &[0x00]);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::SIZE.get());
    // Without trailing bytes the orderly check applies.
    let cmd = build_cmd(ST_NO_SESSIONS, CC_CONTEXT_SAVE, &[key.0], None, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::NV_UNAVAILABLE.get());
    nv_on(&mut sim);
}

/// `TPM2_FlushContext`: positioned `TPM_RC_HANDLE`, session type byte ignored, no sessions.
#[test]
fn flush_context_unloaded_transient_success_and_session_upper_byte() {
    let mut sim = create_simulator!();
    assert_eq!(flush(&mut sim, 0x8000_0001), rc_p(TpmRc::HANDLE, 1));
    assert_eq!(flush(&mut sim, 0x0300_0001), rc_p(TpmRc::HANDLE, 1));

    let h = start_session(&mut sim, 0);
    assert_eq!(flush(&mut sim, 0x0300_0000 | (h & 0x00FF_FFFF)), 0);
    assert!(session_handles(&mut sim, false).is_empty());

    let cmd = build_cmd(
        ST_SESSIONS,
        CC_FLUSH_CONTEXT,
        &[],
        Some(&PW_SESSION),
        &0x8000_0000u32.to_be_bytes(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::AUTH_CONTEXT.get());
}

/// `TPM_RC_AUTH_CONTEXT` is reported before the session area is unmarshaled.
#[test]
fn no_sessions_commands_accept_sessions_instead_of_auth_context() {
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
