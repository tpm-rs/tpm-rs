//! Validation of session handles in the handle and authorization areas.

use crate::_common::{
    ATTR_AUDIT, ATTR_CONT, ATTR_ENCRYPT, CC_GET_RANDOM, CC_GET_SESSION_AUDIT_DIGEST,
    CC_POLICY_GET_DIGEST, CC_POLICY_NV, CC_POLICY_RESTART, CC_POLICY_SECRET, CC_POLICY_SIGNED,
    RC_HANDLE, RC_REFERENCE_S0, ST_NO_SESSIONS, Sess, SessUse, build_pw_cmd, build_raw_cmd,
    create_storage_primary_in, exec, mssim_rc_of, new_sim, policy_secret_default_params, rc_h,
    rc_s1, start_session, start_session_raw,
};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;
use tpm2::{Handle, TpmSe};

/// Session handles in the handle area: unloaded slots are `TPM_RC_REFERENCE_H0 + i`, wrong types
/// `TPM_RC_VALUE` (unmarshal) or `TPM_RC_HANDLE` (session of the other type).
#[test]
fn policy_session_handle_errors() {
    let mut sim = Tpm::new();
    let p = start_session_raw(&mut sim, 1);
    let h = start_session_raw(&mut sim, 0);
    let pslot = p & 0x00FF_FFFF;
    let hslot = h & 0x00FF_FFFF;

    // Unloaded policy session at handle 1 / 2 / 3.
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_GET_DIGEST,
        &[0x0300_0005],
        None,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H0.get());
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SECRET,
        &[Handle::RH_OWNER.0, 0x0300_0005],
        None,
        &policy_secret_default_params(),
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H1.get());
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_NV,
        &[Handle::RH_OWNER.0, 0x0100_0000, 0x0300_0005],
        None,
        &[],
    );
    let rc = mssim_rc_of(&mut sim, &cmd);
    // The NV Index (handle 2) is checked before handle 3.
    assert_eq!(rc, rc_h(TpmRc::HANDLE, 2));

    // Non-policy handle types: TPM_RC_VALUE at the handle position (also for PolicyRestart and
    // handle 2 of PolicySecret).
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_POLICY_RESTART, &[0x0200_0005], None, &[]);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SECRET,
        &[Handle::RH_OWNER.0, h],
        None,
        &policy_secret_default_params(),
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 2));

    // A policy handle naming the slot of a loaded HMAC session: TPM_RC_HANDLE.
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_GET_DIGEST,
        &[0x0300_0000 | hslot],
        None,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 1));
    // The real policy handle works.
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_POLICY_GET_DIGEST, &[p], None, &[]);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), 0);

    // GetSessionAuditDigest: sessionHandle is a TPMI_SH_HMAC.
    let gsad = |session: u32| {
        build_pw_cmd(
            CC_GET_SESSION_AUDIT_DIGEST,
            &[Handle::RH_ENDORSEMENT.0, Handle::RH_NULL.0, session],
            2,
            &[0, 0, 0x00, 0x10],
        )
    };
    assert_eq!(mssim_rc_of(&mut sim, &gsad(p)), rc_h(TpmRc::VALUE, 3));
    assert_eq!(
        mssim_rc_of(&mut sim, &gsad(0x0200_0000 | 0x30)),
        TpmRc::REFERENCE_H2.get()
    );
    assert_eq!(
        mssim_rc_of(&mut sim, &gsad(0x0200_0000 | pslot)),
        rc_h(TpmRc::HANDLE, 3)
    );
}

/// Same mapping for the policy-session handle (`validate_policy_session`-equivalent checks).
#[test]
fn policy_signed_auth_object_checked_first() {
    let mut sim = Tpm::new();
    let h = start_session_raw(&mut sim, 0);
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SIGNED,
        &[Handle::RH_NULL.0, h],
        None,
        &[],
    );
    // authObject (handle 1) is validated first: TPM_RH_NULL is not a TPMI_DH_OBJECT.
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    let key = create_storage_primary_in(&mut sim, Handle::RH_OWNER);
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_POLICY_SIGNED, &[key.0, h], None, &[]);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 2));
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SIGNED,
        &[key.0, 0x0300_0009],
        None,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H1.get());
}

/// Unloaded session REFERENCE_S0, wrong session handle type HANDLE, duplicate session HANDLE+S2, handle-area session reuse.
///
/// session-handle-resolution-reference-s0-h0-and-duplicate-bugs (items 1, 2, 4, 5; handed over by
/// fix-attest)
#[test]
fn session_handle_resolution_and_duplicates() {
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

/// Session handles in the handle area resolve by slot (`TPM_RC_REFERENCE_H0 + i` vs
/// `TPM_RC_HANDLE`).
#[test]
fn session_handle_resolved_by_slot() {
    let mut sim = Tpm::new();
    let h = start_session_raw(&mut sim, 0);
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_GET_DIGEST,
        &[0x0300_0000 | (h & 0x00FF_FFFF)],
        None,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 1));
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_GET_DIGEST,
        &[0x0300_0011],
        None,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H0.get());
}

/// Unloaded policy-session handles return `TPM_RC_REFERENCE_H0 + i`.
#[test]
fn unloaded_policy_session_returns_reference_h0() {
    let mut sim = Tpm::new();
    for cc in [0x16Cu32, 0x16B, 0x18C, 0x189] {
        let cmd = build_raw_cmd(ST_NO_SESSIONS, cc, &[0x0300_0003], None, &[0, 0, 0, 0]);
        assert_eq!(
            mssim_rc_of(&mut sim, &cmd),
            TpmRc::REFERENCE_H0.get(),
            "cc {cc:#x}"
        );
    }
}
