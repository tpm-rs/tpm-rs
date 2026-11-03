//! TPM2_ContextSave / TPM2_ContextLoad of sessions: context gap, replay protection and saved-
//! session tracking.

use crate::_common::{
    ATTR_AUDIT, ATTR_AUDIT_EXCLUSIVE, ATTR_AUDIT_RESET, ATTR_CONT, CC_GET_RANDOM,
    CC_POLICY_CP_HASH, CC_POLICY_TEMPLATE, ST_NO_SESSIONS, SessUse, audited_get_capability,
    build_raw_cmd, context_load_raw, context_save_raw, context_sequence, cp_hash,
    create_primary_key, exec, execute_with_hmac_sessions, execute_with_password_sessions, flush_rc,
    loaded_sessions, marshal_to_vec, mssim_rc_of, rc_p, session_audit_digest, session_handles,
    sha256, sign_cmd_and_handles, start_auth_session, start_hmac_session, start_session,
    start_session_raw,
};
use testing::tpm::Tpm;
use tpm2::commands::{ContextSave, GetCapability};
use tpm2::errors::TpmRc;
use tpm2::{Handle, TpmCap, TpmCc, TpmPt, TpmSe, TpmaSession, TpmiAlgHash};

/// After the context counter advances 64K past the oldest saved session, saving fails with TPM_RC_CONTEXT_GAP until the oldest is loaded.
///
/// The session context gap is enforced: once the context counter has advanced 64K times past
/// the oldest saved session, saving another session fails with `TPM_RC_CONTEXT_GAP`, and
/// loading anything but the oldest context into the last free slot fails too.
#[test]
fn context_gap_enforced() {
    let mut sim = Tpm::new();
    let oldest = start_session_raw(&mut sim, 0);
    let oldest_ctx = context_save_raw(&mut sim, oldest).unwrap();
    let b = start_session_raw(&mut sim, 0);
    let mut last_ctx = None;
    let mut gap_hit = false;
    for _ in 0..70_000 {
        match context_save_raw(&mut sim, b) {
            Ok(ctx) => {
                assert_eq!(context_load_raw(&mut sim, &ctx), Ok(b));
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
    assert_eq!(context_load_raw(&mut sim, &oldest_ctx), Ok(oldest));
    assert!(context_save_raw(&mut sim, b).is_ok());
}

/// Saving the exclusive audit session keeps it exclusive; more than MAX_LOADED_SESSIONS saved sessions are tracked; FlushContext reports HANDLE + P1.
///
/// Saving the exclusive audit session keeps it exclusive; saved sessions are tracked beyond
/// `MAX_LOADED_SESSIONS`; `TPM2_FlushContext` reports `TPM_RC_HANDLE + RC_P1`.
#[test]
fn exclusive_audit_and_saved_session_tracking() {
    let mut sim = Tpm::new();

    // 1. Exclusive audit survives ContextSave/ContextLoad.
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
    let ctx = context_save_raw(&mut sim, a.handle).unwrap();
    assert_eq!(context_load_raw(&mut sim, &ctx), Ok(a.handle));
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
    assert_eq!(
        rc, 0,
        "audit session must still be exclusive after save/load"
    );
    assert_eq!(flush_rc(&mut sim, a.handle), 0);

    // 2. More saved sessions than MAX_LOADED_SESSIONS are tracked and can be flushed.
    let mut saved = Vec::new();
    for _ in 0..5 {
        let h = start_session_raw(&mut sim, 0);
        context_save_raw(&mut sim, h).unwrap();
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
        assert_eq!(flush_rc(&mut sim, *h), 0, "flush {h:#x}");
    }
    assert!(session_handles(&mut sim, true).is_empty());

    // 3. Unloaded transient object / unknown session: TPM_RC_HANDLE + RC_P1.
    assert_eq!(
        flush_rc(&mut sim, Handle::TRANSIENT_LAST.0),
        rc_p(TpmRc::HANDLE, 1)
    );
    assert_eq!(flush_rc(&mut sim, 0x0200_0010), rc_p(TpmRc::HANDLE, 1));
}

/// ContextSave of a policy session succeeds and removes it from the loaded-session RAM.
#[test]
fn saved_session_leaves_ram() {
    let mut sim = Tpm::new();

    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap_or_else(|rc| panic!("StartAuthSession failed: {rc:#x}"));
    let session_handle = session.session_handle;
    assert!(loaded_sessions(&mut sim).contains(&session_handle.0));

    // ContextSave command
    let save_cmd = ContextSave {
        save_handle: session_handle,
    };
    let rsp_parsed = execute_with_password_sessions(&mut sim, &save_cmd, 0, &[])
        .unwrap_or_else(|rc| panic!("ContextSave failed: {rc:#x}"));

    assert_eq!(rsp_parsed.context.saved_handle, session_handle);
    assert_eq!(rsp_parsed.context.hierarchy, Handle::RH_NULL);

    // Verify session is flushed from active RAM
    assert!(!loaded_sessions(&mut sim).contains(&session_handle.0));
}

/// Only the latest saved context of a saved session loads (no replay, no reload after flush); errors carry P1; PolicyTemplate state survives.
///
/// Only the latest saved context of a currently saved session can be loaded (no replay, no
/// reload after a flush), errors carry `RC_P1`, and the `TPM2_PolicyTemplate` state survives a
/// save/load cycle.
#[test]
fn stale_replayed_and_flushed_contexts_rejected() {
    let mut sim = Tpm::new();
    let s = start_session_raw(&mut sim, 0);

    let ctx1 = context_save_raw(&mut sim, s).unwrap();
    assert_eq!(context_load_raw(&mut sim, &ctx1), Ok(s));
    let ctx2 = context_save_raw(&mut sim, s).unwrap();
    // Replaying the older context is rejected.
    assert_eq!(
        context_load_raw(&mut sim, &ctx1),
        Err(rc_p(TpmRc::HANDLE, 1))
    );
    assert_eq!(context_load_raw(&mut sim, &ctx2), Ok(s));
    // Loading a context of a session that is currently loaded is rejected.
    assert_eq!(
        context_load_raw(&mut sim, &ctx2),
        Err(rc_p(TpmRc::HANDLE, 1))
    );

    // A saved session that was flushed cannot be loaded again.
    let ctx3 = context_save_raw(&mut sim, s).unwrap();
    assert_eq!(flush_rc(&mut sim, s), 0);
    assert_eq!(
        context_load_raw(&mut sim, &ctx3),
        Err(rc_p(TpmRc::HANDLE, 1))
    );

    // A corrupted integrity value: TPM_RC_INTEGRITY + RC_P1.
    let t = start_session_raw(&mut sim, 0);
    let ctx = context_save_raw(&mut sim, t).unwrap();
    let mut bad = ctx.clone();
    bad[16 + 2 + 2] ^= 0xFF; // first byte of the integrity digest
    assert_eq!(
        context_load_raw(&mut sim, &bad),
        Err(rc_p(TpmRc::INTEGRITY, 1))
    );
    assert_eq!(context_load_raw(&mut sim, &ctx), Ok(t));

    // isTemplateHashDefined is part of the saved session context.
    let p = start_session_raw(&mut sim, 1);
    let mut digest = 32u16.to_be_bytes().to_vec();
    digest.extend_from_slice(&[0x5A; 32]);
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_POLICY_TEMPLATE, &[p], None, &digest);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), 0);
    let ctx = context_save_raw(&mut sim, p).unwrap();
    assert_eq!(context_load_raw(&mut sim, &ctx), Ok(p));
    let mut cp = 32u16.to_be_bytes().to_vec();
    cp.extend_from_slice(&[0x77; 32]);
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_POLICY_CP_HASH, &[p], None, &cp);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::CPHASH.get());
}

/// A reloaded HMAC session uses the nonceCaller and cpHash of each command, not saved copies.
///
/// After `TPM2_ContextSave`/`TPM2_ContextLoad`, a session still authorizes commands with
/// verified response HMACs over the new command's nonceCaller (Part 1, "Session Nonces": "For a
/// response, the TPM uses the last nonceCaller"), and its audit digest still chains as
/// `H(auditDigest || cpHash || rpHash)` with the cpHash of the audited command. Like the C
/// references, whose `SESSION` keeps neither (`s_nonceCaller[]` and the command's cpHash are
/// per-command globals), the saved context holds only nonceTPM, the session key and the
/// audit digest.
#[test]
fn reloaded_session_uses_per_command_nonce_caller_and_cp_hash() {
    let mut sim = Tpm::new();
    let key = create_primary_key(&mut sim);

    // Authorization: the response HMAC is verified by `execute_with_hmac_sessions`.
    let mut sessions = [start_hmac_session(&mut sim)];
    sessions[0].attributes = TpmaSession::CONTINUE_SESSION;
    execute_with_hmac_sessions(
        &mut sim,
        &sign_cmd_and_handles(key),
        &[],
        &mut sessions,
        &[&[]],
    )
    .unwrap_or_else(|rc| panic!("Sign before ContextSave failed: {rc:#x}"));
    let handle = sessions[0].session_handle.0;
    let ctx = context_save_raw(&mut sim, handle).unwrap();
    assert_eq!(context_load_raw(&mut sim, &ctx), Ok(handle));
    execute_with_hmac_sessions(
        &mut sim,
        &sign_cmd_and_handles(key),
        &[],
        &mut sessions,
        &[&[]],
    )
    .unwrap_or_else(|rc| panic!("Sign after ContextLoad failed: {rc:#x}"));

    // Audit: the digest chain continues across the save/load with the next command's cpHash.
    let params = marshal_to_vec(&GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    });
    let cp = cp_hash(TpmCc::GetCapability, &[], &params);
    let rp = |resp_params: &[u8]| {
        sha256(&[
            &0u32.to_be_bytes(),
            &TpmCc::GetCapability.code().to_be_bytes(),
            resp_params,
        ])
    };
    let session = &mut sessions[0];
    let (rp1, _) =
        audited_get_capability(&mut sim, session, ATTR_AUDIT | ATTR_AUDIT_RESET | ATTR_CONT);
    let digest_1 = sha256(&[&[0u8; 32], &cp, &rp(&rp1)]);
    assert_eq!(session_audit_digest(&mut sim, handle), digest_1);
    let ctx = context_save_raw(&mut sim, handle).unwrap();
    assert_eq!(context_load_raw(&mut sim, &ctx), Ok(handle));
    let (rp2, _) = audited_get_capability(&mut sim, session, ATTR_AUDIT | ATTR_CONT);
    let digest_2 = sha256(&[&digest_1, &cp, &rp(&rp2)]);
    assert_eq!(session_audit_digest(&mut sim, handle), digest_2);
}
