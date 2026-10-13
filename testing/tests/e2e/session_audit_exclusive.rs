//! Exclusive audit sessions: auditExclusive semantics and handover between sessions.

use crate::_common::{
    ATTR_AUDIT, ATTR_AUDIT_EXCLUSIVE, ATTR_AUDIT_RESET, ATTR_CONT, CC_CONTEXT_SAVE,
    CC_FLUSH_CONTEXT, CC_GET_CAPABILITY, CC_HIERARCHY_CHANGE_AUTH, GET_CAP_PARAMS, RC_ATTRIBUTES,
    RC_EXCLUSIVE, RH_OWNER, ST_NO_SESSIONS, SessUse, audit_exclusive_rc, audited_get_capability,
    base_attributes, build, create_primary_with_auth, exec, exec_pws, flush_context,
    get_cap_params, get_cap_with, hmac_session, is_exclusive, make_exclusive, new_sim, rc_of,
    rc_s1, rsassa_signer_template, session_audit_info, sha256, start_hmac_session, start_session,
    transact,
};
use testing::tpm::Tpm;
use tpm2::commands::{GetCapability, GetSessionAuditDigest};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bData, Tpm2bDigest, TpmCap, TpmEccCurve, TpmPt, TpmSe,
    TpmaObject, TpmiAlgHash, TpmsEccParms, TpmsEccPoint, TpmtEccScheme, TpmtPublic,
};

/// auditExclusive fails with TPM_RC_EXCLUSIVE on a non-exclusive session and succeeds on the exclusive one.
///
/// 3. Exclusivity Gating
#[test]
fn audit_exclusive_attribute_gating() {
    let mut sim = Tpm::new();
    let mut s1 = hmac_session(&mut sim);
    let mut s2 = hmac_session(&mut sim);

    // Session 1: audit session, initialized (first-use done)
    assert_eq!(
        get_cap_with(&mut sim, &mut s1, ATTR_CONT | ATTR_AUDIT).rc,
        0
    );
    // Session 2: exclusive, initialized (first-use done)
    assert_eq!(
        get_cap_with(&mut sim, &mut s2, ATTR_CONT | ATTR_AUDIT).rc,
        0
    );

    // A. Command with Session 1 (AUDIT_EXCLUSIVE set -> continueSession | audit | auditExclusive = 0x83)
    // Should fail with TPM_RC_EXCLUSIVE (0x121)
    let res_1 = get_cap_with(
        &mut sim,
        &mut s1,
        ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_EXCLUSIVE,
    );
    assert_eq!(res_1.rc, RC_EXCLUSIVE);

    // B. Command with Session 2 (AUDIT_EXCLUSIVE set)
    // Should succeed
    let res_2 = get_cap_with(
        &mut sim,
        &mut s2,
        ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_EXCLUSIVE,
    );
    assert_eq!(res_2.rc, 0);
    assert_ne!(res_2.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);
}

/// An auditReset command moves exclusivity to the new session and resets its digest to H(0 || cpHash || rpHash).
///
/// 1. Audit Reset Handover with Existing Exclusive Session
#[test]
fn audit_reset_hands_over_exclusivity() {
    let mut sim = Tpm::new();
    let mut s1 = hmac_session(&mut sim);
    let mut s2 = hmac_session(&mut sim);

    // Session 2: audit session, initialized (first-use done).
    let r = get_cap_with(&mut sim, &mut s2, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0);
    // Session 1: audit session, initialized, and now the exclusive one.
    let r = get_cap_with(&mut sim, &mut s1, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0);
    assert_ne!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);

    // Command with Session 2, AUDIT_RESET set
    let r = get_cap_with(&mut sim, &mut s2, ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_RESET);
    assert_eq!(r.rc, 0, "Command failed");
    assert!(r.response_hmac_ok);

    // Verify exclusivity successfully hands over to Session 2
    assert_ne!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);
    let probe = get_cap_with(
        &mut sim,
        &mut s1,
        ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_EXCLUSIVE,
    );
    assert_eq!(probe.rc, RC_EXCLUSIVE);

    // Verify Session 2's audit digest is reset: it only covers the auditReset command,
    // digest = H(0...0 || cpHash || rpHash).
    let cc = CC_GET_CAPABILITY.to_be_bytes();
    let cp_hash = sha256(&[&cc, &get_cap_params()]);
    let rp_hash = sha256(&[&0u32.to_be_bytes(), &cc, &r.params]);
    let expected = sha256(&[&[0u8; 32], &cp_hash, &rp_hash]);
    let (exclusive, digest) = session_audit_info(&mut sim, s2.handle);
    assert!(exclusive);
    assert_eq!(digest, expected);
}

/// Case 1: Verification of Response Session Attributes (auditExclusive and
/// audit bits): exclusivity is established by an audit session, handed over to
/// another audit session, and lost by the first one.
#[test]
fn exclusive_bit_handed_over_between_sessions() {
    let mut sim = Tpm::new();

    let mut s1 = start_hmac_session(&mut sim);
    let mut s2 = start_hmac_session(&mut sim);

    // A. Session 1 with AUDIT | AUDIT_RESET | CONTINUE (0x85) -> should establish exclusivity
    let (_, attrs_1) = audited_get_capability(&mut sim, &mut s1, 0x85);
    assert_eq!(
        attrs_1 & 0x80,
        0x80,
        "Expected audit bit to be set in response"
    );
    assert_eq!(
        attrs_1 & 0x02,
        0x02,
        "Expected auditExclusive bit to be set in response"
    );
    assert_eq!(
        attrs_1 & 0x04,
        0x04,
        "Expected auditReset bit to be set in response because the digest was reset"
    );

    // B. Session 2 with AUDIT | AUDIT_RESET (0x85) -> exclusivity hands over to Session 2
    let (_, attrs_2) = audited_get_capability(&mut sim, &mut s2, 0x85);
    assert_eq!(attrs_2 & 0x80, 0x80);
    assert_eq!(attrs_2 & 0x02, 0x02);

    // C. Execute command using Session 1 with just AUDIT (0x81) -> exclusivity is lost for
    //    Session 1
    let (_, attrs_1_again) = audited_get_capability(&mut sim, &mut s1, 0x81);
    assert_eq!(attrs_1_again & 0x80, 0x80);
    assert_eq!(
        attrs_1_again & 0x02,
        0,
        "Expected auditExclusive to be cleared since exclusivity was lost"
    );
}

/// Audit exclusivity hand-over/loss across sessions, two audit sessions rejected, non-audit session TPM_RC_TYPE, privacyAdminHandle restricted to endorsement.
#[test]
fn exclusivity_tracking_and_privacy_handle() {
    let mut sim = Tpm::new();

    // ==========================================
    // 1. GetCapability Handles with property_count = 0
    // ==========================================
    // Load a transient object
    let obj = create_primary_with_auth(
        &mut sim,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: base_attributes() | TpmaObject::SIGN_ENCRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                TpmsEccParms {
                    symmetric: None,
                    scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                TpmsEccPoint::default(),
            ),
        },
        &[],
    );

    // GetCapability with Handles, property_count = 0 (should succeed per TPM (2 as u16) Spec Section 30.1)
    let cmd = GetCapability {
        capability: TpmCap::Handles,
        property: 0x80000000,
        property_count: 0,
    };
    assert!(sim.execute(cmd).is_ok());
    flush_context(&mut sim, obj).unwrap();

    // ==========================================
    // 2. Session exclusivity tracking
    // ==========================================
    let mut s1 = hmac_session(&mut sim);
    let mut s2 = hmac_session(&mut sim);

    // 2.1 Execute command with Session 1 (AUDIT set) -> sets exclusivity
    let r = get_cap_with(&mut sim, &mut s1, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0);
    assert_ne!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);

    // 2.2 Execute command with Session 2 (AUDIT set) -> changes exclusivity
    let r = get_cap_with(&mut sim, &mut s2, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0);
    assert_ne!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);
    assert!(!is_exclusive(&mut sim, &mut s1));

    // 2.3 Execute command with Session 1 and Session 2 (both AUDIT set) -> fails with
    // TPM_RC_ATTRIBUTES on session 2 (0xA82)
    let r = exec(
        &mut sim,
        CC_GET_CAPABILITY,
        &[],
        &mut [
            SessUse::hmac(&mut s1, ATTR_CONT | ATTR_AUDIT, &[]),
            SessUse::hmac(&mut s2, ATTR_CONT | ATTR_AUDIT, &[]),
        ],
        &get_cap_params(),
        0,
    );
    assert_eq!(r.rc, 0xA82);
    // exclusivity remains session_handle_2 because command failed validation before state update
    assert!(is_exclusive(&mut sim, &mut s2));

    // 2.4 Execute command with Session 1 (AUDIT and AUDIT_RESET set) -> regain exclusivity
    let r = get_cap_with(&mut sim, &mut s1, ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_RESET);
    assert_eq!(r.rc, 0);
    assert_ne!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);
    assert!(!is_exclusive(&mut sim, &mut s2));

    // 2.5 Execute command WITHOUT sessions (or not audit session) -> exclusivity lost
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };
    sim.execute(cmd).unwrap();
    assert!(!is_exclusive(&mut sim, &mut s1));

    // 2.6 Regain exclusivity with Session 1 (AUDIT and AUDIT_RESET set)
    let r = get_cap_with(&mut sim, &mut s1, ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_RESET);
    assert_eq!(r.rc, 0);
    assert_ne!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);

    // 2.7 Session completion (continueSession = 0) -> session removed
    let r = get_cap_with(&mut sim, &mut s1, ATTR_AUDIT);
    assert_eq!(r.rc, 0);
    assert!(
        flush_context(&mut sim, Handle(s1.handle)).is_err(),
        "session should have been removed"
    );

    // A new session regains exclusivity
    let mut s1 = hmac_session(&mut sim);
    let r = get_cap_with(&mut sim, &mut s1, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0);
    assert_ne!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);

    // 2.8 Session flush (flush context) -> session removed
    flush_context(&mut sim, Handle(s1.handle)).unwrap();
    assert!(flush_context(&mut sim, Handle(s1.handle)).is_err());
    assert!(!is_exclusive(&mut sim, &mut s2));

    // ==========================================
    // 3. Non-audit sessions return TPM_RC_TYPE
    // ==========================================
    // Create an active session, but do NOT run any command with it as AUDIT.
    let s3 = hmac_session(&mut sim);
    let signer_handle = create_primary_with_auth(&mut sim, rsassa_signer_template(), &[]);

    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        ..Default::default()
    };
    let get_audit_cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: signer_handle,
        session_handle: Handle(s3.handle),
        ..get_audit_cmd
    };
    let res = exec_pws(&mut sim, &get_audit_cmd, &[&[], &[]]);
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(3)).get()));
    flush_context(&mut sim, Handle(s3.handle)).unwrap();

    // ==========================================
    // 4. privacy_admin_handle validation restricts to endorsement/null hierarchies
    // ==========================================
    // Prepare a valid audit session (with audit digest initialized)
    let mut s4 = hmac_session(&mut sim);
    assert_eq!(
        get_cap_with(&mut sim, &mut s4, ATTR_CONT | ATTR_AUDIT).rc,
        0
    );

    let invalid_handles = [
        Handle::RH_OWNER,
        Handle::RH_PLATFORM,
        Handle::RH_LOCKOUT,
        Handle::RH_NULL,
    ];
    for &h in &invalid_handles {
        let get_audit_cmd = GetSessionAuditDigest {
            privacy_admin_handle: h,
            sign_handle: signer_handle,
            session_handle: Handle(s4.handle),
            ..get_audit_cmd
        };
        let res = exec_pws(&mut sim, &get_audit_cmd, &[&[], &[]]);
        assert_eq!(
            res.err(),
            Some(TpmRc::VALUE.with(Position::handle(1)).get()),
            "Expected handle {:?} to be rejected with TPM_RC_VALUE at Pos1",
            h
        );
    }

    // Verify valid handle: only RHEndorsement is allowed by TPMI_RH_ENDORSEMENT (non-nullable)
    let valid_handles = [Handle::RH_ENDORSEMENT];
    for &h in &valid_handles {
        let get_audit_cmd = GetSessionAuditDigest {
            privacy_admin_handle: h,
            sign_handle: signer_handle,
            session_handle: Handle(s4.handle),
            ..get_audit_cmd
        };
        let res = exec_pws(&mut sim, &get_audit_cmd, &[&[], &[]]);
        assert!(
            res.is_ok(),
            "Expected handle {:?} to be accepted, but got: {:?}",
            h,
            res.err()
        );
    }
}

/// FlushContext and ContextSave without sessions do not clear exclusivity.
///
/// Case 2: Preservation of Exclusivity on Excluded Commands without Sessions
#[test]
fn kept_on_flush_and_context_save() {
    let mut sim = new_sim();
    let mut sess = start_session(&mut sim, TpmSe::HMAC, false);

    // 2A. FlushContext without sessions (Tag 0x8001)
    make_exclusive(&mut sim, &mut sess);
    // FlushContext for non-existent transient handle 0x80000000
    let request_flush = build(
        ST_NO_SESSIONS,
        CC_FLUSH_CONTEXT,
        &[],
        None,
        &0x8000_0000u32.to_be_bytes(),
    );
    transact(&mut sim, &request_flush);
    // Exclusivity must be preserved because FlushContext is excluded
    assert_eq!(audit_exclusive_rc(&mut sim, &mut sess), 0);

    // 2B. ContextSave without sessions
    make_exclusive(&mut sim, &mut sess);
    // ContextSave for non-existent handle 0x80000000
    let request_save = build(ST_NO_SESSIONS, CC_CONTEXT_SAVE, &[0x8000_0000], None, &[]);
    transact(&mut sim, &request_save);
    assert_eq!(audit_exclusive_rc(&mut sim, &mut sess), 0);
}

/// A command with sessions but no audit session clears exclusivity.
///
/// 4. Exclusivity Loss when using a Non-Audit Session
#[test]
fn lost_on_command_without_audit_session() {
    let mut sim = Tpm::new();
    let mut s2 = hmac_session(&mut sim);

    // Session 2: exclusive, initialized (first-use done)
    let r = get_cap_with(&mut sim, &mut s2, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0);
    assert_ne!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);

    // Command with a non-audit authorization session. In C a session that authorizes no handle
    // must be an audit/encrypt/decrypt session (TPM_RC_ATTRIBUTES + S1 otherwise,
    // SessionProcess.c:1705-1712), so a plain HMAC session can't be sent with GetCapability.
    // Use HierarchyChangeAuth(RH_OWNER, unchanged empty auth) authorized by a password session
    // instead: the command carries sessions but no audit session, which clears the exclusive
    // audit session (C UpdateAuditSessionStatus, SessionProcess.c:1993-1996).
    let r = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::pw(&[])],
        &[0, 0],
        0,
    );
    assert_eq!(r.rc, 0, "Command failed");

    // Verify exclusivity is lost
    let probe = get_cap_with(
        &mut sim,
        &mut s2,
        ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_EXCLUSIVE,
    );
    assert_eq!(probe.rc, RC_EXCLUSIVE);
}

/// A command without sessions (TPM_ST_NO_SESSIONS) clears exclusivity.
///
/// Case 1: Exclusivity Loss on Command without Sessions (Tag 0x8001)
#[test]
fn lost_on_command_without_sessions() {
    let mut sim = new_sim();
    let mut sess = start_session(&mut sim, TpmSe::HMAC, false);
    make_exclusive(&mut sim, &mut sess);

    // Command without session (Tag 0x8001), cc is GetCapability
    let cmd = build(
        ST_NO_SESSIONS,
        CC_GET_CAPABILITY,
        &[],
        None,
        &GET_CAP_PARAMS,
    );
    assert_eq!(rc_of(&transact(&mut sim, &cmd)), 0);

    // Exclusivity must be lost
    assert_eq!(
        audit_exclusive_rc(&mut sim, &mut sess),
        TpmRc::EXCLUSIVE.get()
    );
}

/// Using a different audit session clears the exclusive audit session.
///
/// 2. Exclusivity Loss when using a Non-Exclusive Session
#[test]
fn lost_on_other_audit_session() {
    let mut sim = Tpm::new();
    let mut s1 = hmac_session(&mut sim);
    let mut s2 = hmac_session(&mut sim);

    // Session 1: audit session, initialized (first-use done)
    assert_eq!(
        get_cap_with(&mut sim, &mut s1, ATTR_CONT | ATTR_AUDIT).rc,
        0
    );
    // Session 2: exclusive, initialized (first-use done)
    let r = get_cap_with(&mut sim, &mut s2, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0);
    assert_ne!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);

    // Command with Session 1, no first-use, no auditReset (attribute 0x81)
    let r = get_cap_with(&mut sim, &mut s1, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0, "Command failed");
    assert_eq!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);

    // Verify exclusivity is lost: neither session is the exclusive audit session.
    for s in [&mut s1, &mut s2] {
        let probe = get_cap_with(&mut sim, s, ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_EXCLUSIVE);
        assert_eq!(probe.rc, RC_EXCLUSIVE);
    }
}

/// The exclusive audit session stays exclusive when used again without auditExclusive.
///
/// 2. If a session is the exclusive audit session, and it is used in a command
///    as an audit session without auditExclusive set, it retains its exclusivity (spec requirement Part 1, 19.3).
#[test]
fn session_audit_exclusive_retained_without_audit_exclusive() {
    let mut sim = Tpm::new();
    let mut s = start_session(&mut sim, TpmSe::HMAC, false);

    // First use: the session becomes the exclusive audit session.
    let r = get_cap_with(&mut sim, &mut s, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0);
    assert_ne!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);

    // Used again as an audit session, without auditExclusive.
    let r = get_cap_with(&mut sim, &mut s, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0, "Command failed");

    // Under correct spec behavior, it MUST retain exclusivity since it was used in the command as an audit session
    assert_ne!(
        r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE,
        0,
        "Exclusive audit session should retain exclusivity."
    );
    let probe = get_cap_with(
        &mut sim,
        &mut s,
        ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_EXCLUSIVE,
    );
    assert_eq!(
        probe.rc, 0,
        "Exclusive audit session should retain exclusivity."
    );
}

/// An audit session becomes the exclusive audit session on first use.
///
/// 1. On first use of an audit session, the session unconditionally becomes
///    the exclusive audit session (spec requirement Part 1, 19.3).
#[test]
fn session_audit_first_use_becomes_exclusive() {
    let mut sim = Tpm::new();
    let mut s = start_session(&mut sim, TpmSe::HMAC, false);

    let r = get_cap_with(&mut sim, &mut s, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0, "Command failed");
    assert!(r.response_hmac_ok);

    // Under correct spec behavior, the session MUST become exclusive on first use
    assert_ne!(
        r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE,
        0,
        "Session should be exclusive on first use."
    );
    let probe = get_cap_with(
        &mut sim,
        &mut s,
        ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_EXCLUSIVE,
    );
    assert_eq!(probe.rc, 0, "Session should be exclusive on first use.");
}

/// A policy session with the audit attribute fails with TPM_RC_ATTRIBUTES + S1.
///
/// 3. Policy session used with AUDIT attribute must fail with attributes_for error.
#[test]
fn session_audit_rejects_policy_session() {
    let mut sim = Tpm::new();
    let mut s = start_session(&mut sim, TpmSe::Policy, false);

    let r = get_cap_with(&mut sim, &mut s, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(
        r.rc,
        rc_s1(RC_ATTRIBUTES),
        "Expected policy session auditing to fail with attributes_for error"
    );
}
