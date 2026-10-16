//! Generic handle-area validation: disabled hierarchies, unloaded handles and handle error
//! positions across commands.

use crate::_common::{
    CC_CLOCK_SET, CC_COMMIT, CC_CREATE_PRIMARY, CC_EVICT_CONTROL, CC_GET_TIME, CC_NV_DEFINE_SPACE,
    CC_POLICY_SECRET, CC_POLICY_SIGNED, CC_REWRAP, CC_START_AUTH_SESSION, ST_NO_SESSIONS,
    build_pw_cmd, build_raw_cmd, create_storage_primary_in, evict, mssim_rc_of,
    policy_secret_default_params, rc_h, read_public_rc, send_with_rc, set_hierarchy_enabled,
    start_session_raw,
};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;
use tpm2::*;

/// A trial `TPM2_PolicySigned` on an unloaded object no longer hashes a 4-byte fallback Name
/// into the policy digest, and objects of a disabled hierarchy look undefined.
#[test]
fn disabled_hierarchy_objects_look_undefined() {
    let mut sim = Tpm::new();
    let key = create_storage_primary_in(&mut sim, Handle::RH_OWNER);
    evict(&mut sim, Handle::RH_OWNER, key, 0x8100_0010);
    let p = start_session_raw(&mut sim, 1);
    // PolicySecret with a persistent authHandle of a disabled hierarchy: TPM_RC_HANDLE.
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SECRET,
        &[0x8100_0010, p],
        None,
        &policy_secret_default_params(),
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::HANDLE, 1));
    assert_eq!(
        read_public_rc(&mut sim, 0x8100_0010),
        rc_h(TpmRc::HANDLE, 1)
    );
}

/// A no-session command naming a disabled hierarchy reports `TPM_RC_HIERARCHY + RC_H1`, and an
/// unloaded second handle `TPM_RC_REFERENCE_H1`, before `TPM_RC_AUTH_MISSING`.
#[test]
fn handle_errors_precede_auth_missing() {
    let mut sim = Tpm::new();

    // EvictControl(owner, unloaded transient object): handle 2 is checked first.
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_EVICT_CONTROL,
        &[Handle::RH_OWNER.0, 0x8000_0001],
        None,
        &0x8100_0001u32.to_be_bytes(),
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H1.get());

    // CreatePrimary(owner) while the storage hierarchy is disabled.
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_CREATE_PRIMARY,
        &[Handle::RH_OWNER.0],
        None,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::HIERARCHY, 1));
    // Still enabled hierarchies get AUTH_MISSING.
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_CREATE_PRIMARY,
        &[Handle::RH_PLATFORM.0],
        None,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::AUTH_MISSING.get());
}

/// Handles of `ClockSet`, `NV_DefineSpace`, `Commit`, `Rewrap`, `GetTime` and `ContextSave` are
/// validated (with the right position) before authorization.
#[test]
fn handle_positions_for_less_common_commands() {
    let mut sim = Tpm::new();

    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_CLOCK_SET,
        &[0x8000_0000],
        None,
        &0u64.to_be_bytes(),
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_NV_DEFINE_SPACE,
        &[0x8000_0000],
        None,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    // TPMI_RH_PROVISION / TPMI_RH_ENDORSEMENT: other hierarchies are invalid values.
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_CLOCK_SET,
        &[Handle::RH_ENDORSEMENT.0],
        None,
        &0u64.to_be_bytes(),
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_GET_TIME,
        &[Handle::RH_OWNER.0, Handle::RH_NULL.0],
        None,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));

    // Unloaded objects: TPM_RC_REFERENCE_Hx.
    let cmd = build_pw_cmd(CC_COMMIT, &[Handle::TRANSIENT_LAST.0], 1, &[]);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H0.get());
    let cmd = build_pw_cmd(
        CC_REWRAP,
        &[Handle::TRANSIENT_LAST.0, Handle::RH_NULL.0],
        1,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H0.get());
    let cmd = build_pw_cmd(
        CC_GET_TIME,
        &[Handle::RH_ENDORSEMENT.0, Handle::TRANSIENT_LAST.0],
        2,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H1.get());

    // ContextSave of an invalid permanent handle: TPM_RC_VALUE + RC_H1.
    let cmd = build_raw_cmd(ST_NO_SESSIONS, 0x162, &[0x4000_0005], None, &[]);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
}

/// Unrecognized permanent handles carry their own position, and `TPM_RH_AUTH_00` belongs to the
/// endorsement hierarchy.
#[test]
fn permanent_handle_positions_and_auth_00_hierarchy() {
    let mut sim = Tpm::new();
    let p = start_session_raw(&mut sim, 1);
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SECRET,
        &[0x4000_0005, p],
        None,
        &policy_secret_default_params(),
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));

    set_hierarchy_enabled(&mut sim, Handle::RH_ENDORSEMENT, false);
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_SECRET,
        &[Handle::RH_AUTH_00.0, p],
        None,
        &policy_secret_default_params(),
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_h(TpmRc::HIERARCHY, 1));
}

/// `TPM2_PolicySigned`'s `authObject` is a `TPMI_DH_OBJECT`, also for trial sessions.
#[test]
fn policy_signed_auth_object_must_be_object() {
    let mut sim = Tpm::new();
    let trial = {
        let mut params = Vec::new();
        params.extend_from_slice(&32u16.to_be_bytes());
        params.extend_from_slice(&[0x11; 32]);
        params.extend_from_slice(&0u16.to_be_bytes());
        params.push(0x03); // TPM_SE_TRIAL
        params.extend_from_slice(&0x0010u16.to_be_bytes());
        params.extend_from_slice(&0x000Bu16.to_be_bytes());
        let cmd = build_raw_cmd(
            ST_NO_SESSIONS,
            CC_START_AUTH_SESSION,
            &[Handle::RH_NULL.0, Handle::RH_NULL.0],
            None,
            &params,
        );
        let (rc, resp) = send_with_rc(&mut sim, &cmd);
        assert_eq!(rc, 0);
        u32::from_be_bytes(resp[10..14].try_into().unwrap())
    };
    for (auth_object, expected) in [
        (Handle::TRANSIENT_LAST.0, TpmRc::REFERENCE_H0.get()),
        // Above TRANSIENT_LAST: not a TPMI_DH_OBJECT value.
        (Handle::TRANSIENT_LAST.0 + 1, rc_h(TpmRc::VALUE, 1)),
        (0x8000_0099, rc_h(TpmRc::VALUE, 1)),
        (0x8100_0099, rc_h(TpmRc::HANDLE, 1)),
        (Handle::RH_OWNER.0, rc_h(TpmRc::VALUE, 1)),
        (0x0000_0000, rc_h(TpmRc::VALUE, 1)),
    ] {
        let cmd = build_raw_cmd(
            ST_NO_SESSIONS,
            CC_POLICY_SIGNED,
            &[auth_object, trial],
            None,
            &[],
        );
        assert_eq!(
            mssim_rc_of(&mut sim, &cmd),
            expected,
            "authObject {auth_object:#x}"
        );
    }
}

/// Every handle is type-checked before any is checked for presence, as the C reference
/// unmarshals the whole handle area (`ParseHandleBuffer`) before `EntityGetLoadStatus`: an
/// invalid second handle is reported before an unloaded first one (found by differential
/// fuzzing).
#[test]
fn invalid_handle_type_is_reported_before_unloaded_handle() {
    const CC_CERTIFY_CREATION: u32 = 0x0000_014A;
    const ST_SESSIONS: u16 = 0x8002;
    let mut sim = Tpm::new();
    // `TPM2_CertifyCreation(signHandle = unloaded 0x80000000, objectHandle = 0)`, without an
    // authorization area.
    let cmd = build_raw_cmd(
        ST_SESSIONS,
        CC_CERTIFY_CREATION,
        &[0x8000_0000, 0],
        None,
        &[],
    );
    // `TPM_RC_VALUE + TPM_RC_H + TPM_RC_2`.
    assert_eq!(mssim_rc_of(&mut sim, &cmd), 0x284);
    // With a valid second handle type, the unloaded first handle is reported.
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_CERTIFY_CREATION,
        &[0x8000_0000, 0x8000_0001],
        None,
        &[],
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H0.get());
}

/// Every handle is unmarshaled as the interface type of its position (Part 3) before any entity
/// is looked up, so a value outside the type is `TPM_RC_VALUE` at the first such position,
/// whatever the later handles are (found by differential fuzzing; the TCG reference needed
/// `bug-fix` patches for `TPM2_CreateLoaded` and `TPM2_RSA_Decrypt`).
#[test]
fn handles_outside_their_interface_type_are_value_errors() {
    const TPM_RC_VALUE_H1: u32 = 0x184;
    let cases: [(&str, &[u8]); 9] = [
        // TPM2_NV_Read(authHandle = TPM_RS_PW, nvIndex = 0): TPMI_RH_NV_AUTH.
        (
            "NV_Read",
            &[
                0x80, 0x02, 0, 0, 0, 0x12, 0, 0, 0x01, 0x4E, 0x40, 0, 0, 0x09, 0, 0, 0, 0,
            ],
        ),
        // TPM2_PolicySecret(authHandle = 0x0B000000, policySession = 0): TPMI_DH_ENTITY.
        (
            "PolicySecret",
            &[
                0x80, 0x02, 0, 0, 0, 0x12, 0, 0, 0x01, 0x51, 0x0B, 0, 0, 0, 0, 0, 0, 0,
            ],
        ),
        // TPM2_NV_ReadPublic(0x81800000): TPMI_RH_NV_INDEX.
        (
            "NV_ReadPublic",
            &[
                0x80, 0x01, 0, 0, 0, 0x0E, 0, 0, 0x01, 0x69, 0x81, 0x80, 0, 0,
            ],
        ),
        // TPM2_CreateLoaded(parentHandle = TPM_RS_PW, 0, an NV Index, TPM_RH_AUTH_00,
        // TPM_RH_LOCKOUT): TPMI_DH_PARENT.
        (
            "CreateLoaded(TPM_RS_PW)",
            &[
                0x80, 0x01, 0, 0, 0, 0x0E, 0, 0, 0x01, 0x91, 0x40, 0, 0, 0x09,
            ],
        ),
        (
            "CreateLoaded(0)",
            &[0x80, 0x01, 0, 0, 0, 0x0E, 0, 0, 0x01, 0x91, 0, 0, 0, 0],
        ),
        (
            "CreateLoaded(NV)",
            &[0x80, 0x01, 0, 0, 0, 0x0E, 0, 0, 0x01, 0x91, 0x01, 0, 0, 0],
        ),
        (
            "CreateLoaded(TPM_RH_AUTH_00)",
            &[
                0x80, 0x01, 0, 0, 0, 0x0E, 0, 0, 0x01, 0x91, 0x40, 0, 0, 0x10,
            ],
        ),
        (
            "CreateLoaded(TPM_RH_LOCKOUT)",
            &[
                0x80, 0x01, 0, 0, 0, 0x0E, 0, 0, 0x01, 0x91, 0x40, 0, 0, 0x0A,
            ],
        ),
        // TPM2_RSA_Decrypt(keyHandle = TPM_RH_NULL): TPMI_DH_OBJECT without '+'.
        (
            "RSA_Decrypt",
            &[
                0x80, 0x01, 0, 0, 0, 0x0E, 0, 0, 0x01, 0x59, 0x40, 0, 0, 0x07,
            ],
        ),
    ];
    let mut sim = Tpm::new();
    for (name, cmd) in cases {
        assert_eq!(mssim_rc_of(&mut sim, cmd), TPM_RC_VALUE_H1, "{name}");
    }
}

/// External (`0x11xxxxxx`) and permanent (`0x12xxxxxx`) NV Indexes are valid `TPMI_RH_NV_INDEX`
/// values (TPM 2.0 Part 2, Table "Definition of (TPM_HANDLE) TPMI_RH_NV_INDEX Type":
/// "{EXTERNAL_NV_FIRST:EXTERNAL_NV_LAST} | range of external NV Indexes" and
/// "{PERMANENT_NV_FIRST:PERMANENT_NV_LAST} | range of permanent NV Indexes"), so they pass handle
/// unmarshaling; this TPM does not implement them, so their load status check fails with
/// `TPM_RC_VALUE` at their position, in handle order after the earlier handles.
#[test]
fn external_and_permanent_nv_indexes_are_unmarshaled_but_not_implemented() {
    const CC_NV_WRITE_LOCK: u32 = 0x0000_0138;
    const CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
    let mut sim = crate::_common::Tpm::new();
    // An undefined NV Index as authHandle is reported first.
    let cmd = crate::_common::build(
        0x8002,
        CC_NV_WRITE_LOCK,
        &[0x0100_0000, 0x1100_7100],
        Some(&crate::_common::PW_SESSION),
        &[],
    );
    assert_eq!(
        crate::_common::rc_of(&sim.send_command(0, &cmd)),
        rc_h(TpmRc::HANDLE, 1)
    );
    let cmd = crate::_common::build(
        0x8002,
        CC_NV_WRITE_LOCK,
        &[Handle::RH_OWNER.0, 0x1100_7100],
        Some(&crate::_common::PW_SESSION),
        &[],
    );
    assert_eq!(
        crate::_common::rc_of(&sim.send_command(0, &cmd)),
        rc_h(TpmRc::VALUE, 2)
    );
    let cmd = crate::_common::build(0x8001, CC_NV_READ_PUBLIC, &[0x1200_0001], None, &[]);
    assert_eq!(
        crate::_common::rc_of(&sim.send_command(0, &cmd)),
        rc_h(TpmRc::VALUE, 1)
    );
}
