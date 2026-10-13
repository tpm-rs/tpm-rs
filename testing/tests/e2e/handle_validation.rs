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
    let cmd = build_pw_cmd(CC_COMMIT, &[0x8000_000F], 1, &[]);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H0.get());
    let cmd = build_pw_cmd(CC_REWRAP, &[0x8000_0007, Handle::RH_NULL.0], 1, &[]);
    assert_eq!(mssim_rc_of(&mut sim, &cmd), TpmRc::REFERENCE_H0.get());
    let cmd = build_pw_cmd(
        CC_GET_TIME,
        &[Handle::RH_ENDORSEMENT.0, 0x8000_0007],
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
        (0x8000_000Fu32, TpmRc::REFERENCE_H0.get()),
        // Above TRANSIENT_LAST: not a TPMI_DH_OBJECT value.
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
