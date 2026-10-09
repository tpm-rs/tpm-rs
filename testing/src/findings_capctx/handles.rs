//! Regression tests for the command dispatch / handle validation findings
//! (`validate_command_handles`, persistent object loading, `NO_SESSIONS` ordering).

use super::*;

const CC_CREATE_PRIMARY: u32 = 0x131;
const CC_EVICT_CONTROL: u32 = 0x120;
const CC_HIERARCHY_CONTROL: u32 = 0x121;
const CC_CLOCK_SET: u32 = 0x128;
const CC_NV_DEFINE_SPACE: u32 = 0x12A;
const CC_POLICY_SECRET: u32 = 0x151;
const CC_POLICY_SIGNED: u32 = 0x160;
const CC_POLICY_NV: u32 = 0x149;
const CC_POLICY_RESTART: u32 = 0x180;
const CC_POLICY_GET_DIGEST: u32 = 0x189;
const CC_GET_SESSION_AUDIT_DIGEST: u32 = 0x14D;
const CC_GET_TIME: u32 = 0x14C;
const CC_REWRAP: u32 = 0x152;
const CC_COMMIT: u32 = 0x18B;
const CC_SIGN: u32 = 0x15D;
const CC_READ_PUBLIC: u32 = 0x173;
const CC_START_AUTH_SESSION: u32 = 0x176;

/// `TPM2_ReadPublic(handle)` (no sessions); returns the response code.
fn read_public(sim: &mut Simulator<'_>, handle: u32) -> u32 {
    rc_of(
        sim,
        &build_cmd(ST_NO_SESSIONS, CC_READ_PUBLIC, &[handle], None, &[]),
    )
}

/// Parameters of `TPM2_PolicySecret` (empty nonce, cpHash, policyRef; expiration 0).
fn policy_secret_params() -> Vec<u8> {
    vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// A no-session command naming a disabled hierarchy reports `TPM_RC_HIERARCHY + RC_H1`, and an
/// unloaded second handle `TPM_RC_REFERENCE_H1`, before `TPM_RC_AUTH_MISSING`.
#[test]
fn no_sessions_check_unauthorized_handles_executes_before_validate_command_handles() {
    let mut sim = create_simulator!();

    // EvictControl(owner, unloaded transient object): handle 2 is checked first.
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_EVICT_CONTROL,
        &[Handle::RH_OWNER.0, 0x8000_0001],
        None,
        &0x8100_0001u32.to_be_bytes(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H1.get());

    // CreatePrimary(owner) while the storage hierarchy is disabled.
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_CREATE_PRIMARY,
        &[Handle::RH_OWNER.0],
        None,
        &[],
    );
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::HIERARCHY, 1));
    // Still enabled hierarchies get AUTH_MISSING.
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_CREATE_PRIMARY,
        &[Handle::RH_PLATFORM.0],
        None,
        &[],
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::AUTH_MISSING.get());
}

/// Unrecognized permanent handles carry their own position, and `TPM_RH_AUTH_00` belongs to the
/// endorsement hierarchy.
#[test]
fn validate_command_handles_permanent_handle_off_by_one_and_vendor_permanent_eh_enable() {
    let mut sim = create_simulator!();
    let p = start_session(&mut sim, 1);
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SECRET,
        &[0x4000_0005, p],
        None,
        &policy_secret_params(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));

    set_hierarchy_enabled(&mut sim, Handle::RH_ENDORSEMENT, false);
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SECRET,
        &[Handle::RH_AUTH_00.0, p],
        None,
        &policy_secret_params(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::HIERARCHY, 1));
}

/// Handles of `ClockSet`, `NV_DefineSpace`, `Commit`, `Rewrap`, `GetTime` and `ContextSave` are
/// validated (with the right position) before authorization.
#[test]
fn validate_command_handles_off_by_one_position_and_missing_commands() {
    let mut sim = create_simulator!();

    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_CLOCK_SET,
        &[0x8000_0000],
        None,
        &0u64.to_be_bytes(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_NV_DEFINE_SPACE,
        &[0x8000_0000],
        None,
        &[],
    );
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    // TPMI_RH_PROVISION / TPMI_RH_ENDORSEMENT: other hierarchies are invalid values.
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_CLOCK_SET,
        &[Handle::RH_ENDORSEMENT.0],
        None,
        &0u64.to_be_bytes(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_GET_TIME,
        &[Handle::RH_OWNER.0, Handle::RH_NULL.0],
        None,
        &[],
    );
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));

    // Unloaded objects: TPM_RC_REFERENCE_Hx.
    let cmd = build_pw_cmd(CC_COMMIT, &[0x8000_00F0], 1, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H0.get());
    let cmd = build_pw_cmd(CC_REWRAP, &[0x8000_0007, Handle::RH_NULL.0], 1, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H0.get());
    let cmd = build_pw_cmd(
        CC_GET_TIME,
        &[Handle::RH_ENDORSEMENT.0, 0x8000_0007],
        2,
        &[],
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H1.get());

    // ContextSave of an invalid permanent handle: TPM_RC_VALUE + RC_H1.
    let cmd = build_cmd(ST_NO_SESSIONS, 0x162, &[0x4000_0005], None, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
}

/// Session handles in the handle area: unloaded slots are `TPM_RC_REFERENCE_H0 + i`, wrong types
/// `TPM_RC_VALUE` (unmarshal) or `TPM_RC_HANDLE` (session of the other type).
#[test]
fn validate_command_handles_session_handle_validation_and_error_code_bugs() {
    let mut sim = create_simulator!();
    let p = start_session(&mut sim, 1);
    let h = start_session(&mut sim, 0);
    let pslot = p & 0x00FF_FFFF;
    let hslot = h & 0x00FF_FFFF;

    // Unloaded policy session at handle 1 / 2 / 3.
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_GET_DIGEST,
        &[0x0300_0005],
        None,
        &[],
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H0.get());
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SECRET,
        &[Handle::RH_OWNER.0, 0x0300_0005],
        None,
        &policy_secret_params(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H1.get());
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_NV,
        &[Handle::RH_OWNER.0, 0x0100_0000, 0x0300_0005],
        None,
        &[],
    );
    let rc = rc_of(&mut sim, &cmd);
    // The NV Index (handle 2) is checked before handle 3.
    assert_eq!(rc, rc_h(TpmRc::HANDLE, 2));

    // Non-policy handle types: TPM_RC_VALUE at the handle position (also for PolicyRestart and
    // handle 2 of PolicySecret).
    let cmd = build_cmd(ST_NO_SESSIONS, CC_POLICY_RESTART, &[0x0200_0005], None, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SECRET,
        &[Handle::RH_OWNER.0, h],
        None,
        &policy_secret_params(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 2));

    // A policy handle naming the slot of a loaded HMAC session: TPM_RC_HANDLE.
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_GET_DIGEST,
        &[0x0300_0000 | hslot],
        None,
        &[],
    );
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 1));
    // The real policy handle works.
    let cmd = build_cmd(ST_NO_SESSIONS, CC_POLICY_GET_DIGEST, &[p], None, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), 0);

    // GetSessionAuditDigest: sessionHandle is a TPMI_SH_HMAC.
    let gsad = |session: u32| {
        build_pw_cmd(
            CC_GET_SESSION_AUDIT_DIGEST,
            &[Handle::RH_ENDORSEMENT.0, Handle::RH_NULL.0, session],
            2,
            &[0, 0, 0x00, 0x10],
        )
    };
    assert_eq!(rc_of(&mut sim, &gsad(p)), rc_h(TpmRc::VALUE, 3));
    assert_eq!(
        rc_of(&mut sim, &gsad(0x0200_0000 | 0x30)),
        TpmRc::REFERENCE_H2.get()
    );
    assert_eq!(
        rc_of(&mut sim, &gsad(0x0200_0000 | pslot)),
        rc_h(TpmRc::HANDLE, 3)
    );
}

/// Same mapping for the policy-session handle (`validate_policy_session`-equivalent checks).
#[test]
fn validate_policy_session_erroneous_expiration_and_handle_error_codes() {
    let mut sim = create_simulator!();
    let h = start_session(&mut sim, 0);
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SIGNED,
        &[Handle::RH_NULL.0, h],
        None,
        &[],
    );
    // authObject (handle 1) is validated first: TPM_RH_NULL is not a TPMI_DH_OBJECT.
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    let key = create_primary(&mut sim, Handle::RH_OWNER);
    let cmd = build_cmd(ST_NO_SESSIONS, CC_POLICY_SIGNED, &[key.0, h], None, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 2));
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SIGNED,
        &[key.0, 0x0300_0009],
        None,
        &[],
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H1.get());
}

/// `TPM2_PolicySigned`'s `authObject` is a `TPMI_DH_OBJECT`, also for trial sessions.
#[test]
fn expects_object_handle_spurious_ecc_parameters_and_missing_policy_signed() {
    let mut sim = create_simulator!();
    let trial = {
        let mut params = Vec::new();
        params.extend_from_slice(&32u16.to_be_bytes());
        params.extend_from_slice(&[0x11; 32]);
        params.extend_from_slice(&0u16.to_be_bytes());
        params.push(0x03); // TPM_SE_TRIAL
        params.extend_from_slice(&0x0010u16.to_be_bytes());
        params.extend_from_slice(&0x000Bu16.to_be_bytes());
        let cmd = build_cmd(
            ST_NO_SESSIONS,
            CC_START_AUTH_SESSION,
            &[Handle::RH_NULL.0, Handle::RH_NULL.0],
            None,
            &params,
        );
        let (rc, resp) = send(&mut sim, &cmd);
        assert_eq!(rc, 0);
        u32::from_be_bytes(resp[10..14].try_into().unwrap())
    };
    for (auth_object, expected) in [
        (0x8000_0099u32, TpmRc::REFERENCE_H0.get()),
        (0x8100_0099, rc_h(TpmRc::HANDLE, 1)),
        (Handle::RH_OWNER.0, rc_h(TpmRc::VALUE, 1)),
        (0x0000_0000, rc_h(TpmRc::VALUE, 1)),
    ] {
        let cmd = build_cmd(
            ST_NO_SESSIONS,
            CC_POLICY_SIGNED,
            &[auth_object, trial],
            None,
            &[],
        );
        assert_eq!(
            rc_of(&mut sim, &cmd),
            expected,
            "authObject {auth_object:#x}"
        );
    }
}

/// A trial `TPM2_PolicySigned` on an unloaded object no longer hashes a 4-byte fallback Name
/// into the policy digest, and objects of a disabled hierarchy look undefined.
#[test]
fn handle_name_and_handle_auth_disabled_hierarchy_and_unloaded_fallback_bugs() {
    let mut sim = create_simulator!();
    let key = create_primary(&mut sim, Handle::RH_OWNER);
    evict(&mut sim, Handle::RH_OWNER, key, 0x8100_0010);
    let p = start_session(&mut sim, 1);
    // PolicySecret with a persistent authHandle of a disabled hierarchy: TPM_RC_HANDLE.
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SECRET,
        &[0x8100_0010, p],
        None,
        &policy_secret_params(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 1));
    assert_eq!(read_public(&mut sim, 0x8100_0010), rc_h(TpmRc::HANDLE, 1));
}

/// Undefined persistent handles and persistent handles of a disabled hierarchy are
/// `TPM_RC_HANDLE + RC_Hx` (not `TPM_RC_REFERENCE_Hx` / `TPM_RC_HIERARCHY`).
#[test]
fn persistent_object_handle_validation_error_code_discrepancies() {
    let mut sim = create_simulator!();
    let cmd = build_pw_cmd(CC_SIGN, &[0x8100_0099], 1, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 1));
    let cmd = build_pw_cmd(CC_EVICT_CONTROL, &[Handle::RH_OWNER.0, 0x8100_0099], 1, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 2));

    let key = create_primary(&mut sim, Handle::RH_OWNER);
    evict(&mut sim, Handle::RH_OWNER, key, 0x8100_0001);
    assert_eq!(read_public(&mut sim, 0x8100_0001), 0);
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let cmd = build_pw_cmd(CC_SIGN, &[0x8100_0001], 1, &[]);
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 1));
    assert_eq!(read_public(&mut sim, 0x8100_0001), rc_h(TpmRc::HANDLE, 1));
}

/// Platform persistent handles above `0x8180_FFFF` are valid.
#[test]
fn platform_persistent_handle_range_truncated_at_0x8180ffff() {
    let mut sim = create_simulator!();
    let key = create_primary(&mut sim, Handle::RH_PLATFORM);
    evict(&mut sim, Handle::RH_PLATFORM, key, 0x8181_0000);
    assert_eq!(read_public(&mut sim, 0x8181_0000), 0);
    let s = {
        let cmd = build_pw_cmd(CC_SIGN, &[0x8181_0000], 1, &[]);
        rc_of(&mut sim, &cmd)
    };
    assert_ne!(s, rc_h(TpmRc::VALUE, 1));
}

/// A persistent object needs a free object slot (`TPM_RC_OBJECT_MEMORY`), and the hierarchy of a
/// persistent handle is checked by its handle range.
#[test]
fn object_load_evict_persistent_handles_ignore_transient_slot_capacity() {
    let mut sim = create_simulator!();
    let key = create_primary(&mut sim, Handle::RH_OWNER);
    evict(&mut sim, Handle::RH_OWNER, key, 0x8100_0003);
    // Fill every object slot.
    let mut loaded = vec![key];
    loop {
        let cmd = CreatePrimary {
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: Tpm2b(ecc_storage_template()),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let handles = CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        };
        match execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]) {
            Ok((_, h)) => loaded.push(h.object_handle),
            Err(rc) => {
                assert_eq!(rc, TpmRc::OBJECT_MEMORY.get());
                break;
            }
        }
        assert!(loaded.len() <= 64, "object memory never exhausted");
    }
    assert_eq!(
        read_public(&mut sim, 0x8100_0003),
        TpmRc::OBJECT_MEMORY.get()
    );
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        0x165,
        &[],
        None,
        &loaded.pop().unwrap().0.to_be_bytes(),
    );
    assert_eq!(rc_of(&mut sim, &cmd), 0);
    assert_eq!(read_public(&mut sim, 0x8100_0003), 0);
    for h in loaded {
        let cmd = build_cmd(ST_NO_SESSIONS, 0x165, &[], None, &h.0.to_be_bytes());
        assert_eq!(rc_of(&mut sim, &cmd), 0);
    }

    // A platform persistent handle while phEnable is clear: TPM_RC_HANDLE + RC_H1.
    let pkey = create_primary(&mut sim, Handle::RH_PLATFORM);
    evict(&mut sim, Handle::RH_PLATFORM, pkey, 0x8180_0001);
    assert_eq!(read_public(&mut sim, 0x8180_0001), 0);
    let mut params = Handle::RH_PLATFORM.0.to_be_bytes().to_vec();
    params.push(0);
    let cmd = build_pw_cmd(CC_HIERARCHY_CONTROL, &[Handle::RH_PLATFORM.0], 1, &params);
    assert_eq!(rc_of(&mut sim, &cmd), 0);
    assert_eq!(read_public(&mut sim, 0x8180_0001), rc_h(TpmRc::HANDLE, 1));
}

/// `TPM2_HierarchyControl` parameters are validated by the handler after authorization, in
/// parameter order.
#[test]
fn hierarchy_control_parameter_validation_order_and_underflow_error_loss() {
    let mut sim = create_simulator!();
    // Both parameters invalid: `enable` (parameter 1) is reported.
    let mut params = 0x4000_0005u32.to_be_bytes().to_vec();
    params.push(2);
    let cmd = build_pw_cmd(CC_HIERARCHY_CONTROL, &[Handle::RH_PLATFORM.0], 1, &params);
    assert_eq!(rc_of(&mut sim, &cmd), rc_p(TpmRc::VALUE, 1));
    // Without a session, the missing authorization is reported before any parameter error.
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_HIERARCHY_CONTROL,
        &[Handle::RH_PLATFORM.0],
        None,
        &params,
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::AUTH_MISSING.get());
}

/// Unloaded policy-session handles return `TPM_RC_REFERENCE_H0 + i`.
#[test]
fn startauthsession_and_policycommandcode_session_parsing_and_error_bugs() {
    let mut sim = create_simulator!();
    for cc in [0x16Cu32, 0x16B, 0x18C, 0x189] {
        let cmd = build_cmd(ST_NO_SESSIONS, cc, &[0x0300_0003], None, &[0, 0, 0, 0]);
        assert_eq!(
            rc_of(&mut sim, &cmd),
            TpmRc::REFERENCE_H0.get(),
            "cc {cc:#x}"
        );
    }
}

/// Session handles in the handle area resolve by slot (`TPM_RC_REFERENCE_H0 + i` vs
/// `TPM_RC_HANDLE`).
#[test]
fn session_handle_resolution_reference_s0_h0_and_duplicate_bugs() {
    let mut sim = create_simulator!();
    let h = start_session(&mut sim, 0);
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_GET_DIGEST,
        &[0x0300_0000 | (h & 0x00FF_FFFF)],
        None,
        &[],
    );
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 1));
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_GET_DIGEST,
        &[0x0300_0011],
        None,
        &[],
    );
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H0.get());
}
