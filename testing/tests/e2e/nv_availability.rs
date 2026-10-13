//! Behaviour of NV-dependent commands (NV space, hierarchy changes, Clear, ChangeEPS/PPS) while NV
//! is unavailable.

use crate::_common::{
    define_nv_with_policy_unwrap as define, exec_with_empty_passwords as pw,
    policy_command_code_active as policy_command_code, power_cycle_with as power_cycle,
    start_session_active as start_session, *,
};
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::{SimulatorPlatformSignal, create_simulator};

/// HierarchyChangeAuth/ClearControl need NV for every hierarchy without changing state; disableClear survives TPM Reset.
///
/// HierarchyChangeAuth / ClearControl check NV availability for every hierarchy, and
/// disableClear persists across TPM Reset.
#[test]
fn change_auth_and_clear_control_need_nv_and_persist() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    for h in [Handle::RH_OWNER, Handle::RH_ENDORSEMENT, Handle::RH_LOCKOUT] {
        assert_eq!(
            hierarchy_change_auth(&mut sim, h, &[], b"new"),
            Err(nv_unavailable()),
            "{h:?}"
        );
    }
    assert_eq!(
        clear_control(&mut sim, Handle::RH_LOCKOUT, true),
        Err(nv_unavailable())
    );
    nv_on(&mut sim);
    // The failed attempt must not have changed the owner auth.
    hierarchy_change_auth(&mut sim, Handle::RH_OWNER, &[], b"o").unwrap();

    clear_control(&mut sim, Handle::RH_LOCKOUT, true).unwrap();
    assert_eq!(power_cycle(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    assert_eq!(
        clear(&mut sim, Handle::RH_LOCKOUT),
        Err(TpmRc::DISABLED.get()),
        "disableClear lost across TPM Reset"
    );
    clear_control(&mut sim, Handle::RH_PLATFORM, false).unwrap();
    clear(&mut sim, Handle::RH_LOCKOUT).unwrap();
}

/// NV_ChangeAuth with NV off succeeds when authValue is unchanged and fails with TPM_RC_NV_UNAVAILABLE when it changes
///
/// NV_ChangeAuth needs NV only when the authValue actually changes (C `NvWriteIndexAuth` ->
/// `NvConditionallyWrite`).
#[test]
fn change_auth_needs_nv_only_when_auth_changes() {
    let mut sim = create_simulator!();
    let index = 0x0150_0703;
    define_change_auth_index(&mut sim, index, 8);
    let name = nv_index_name(&mut sim, index);
    sim.signal_platform(SimulatorPlatformSignal::NvOff, NO_STREAM)
        .unwrap();

    // Same (empty) authValue: nothing to write.
    let mut session = start_session(&mut sim, TpmSe::Policy);
    policy_command_code(&mut sim, &session, TpmCc::NVChangeAuth);
    with_session(
        &mut sim,
        &change_auth_cmd(Handle(index), &[]),
        &[&name],
        &mut session,
    )
    .expect("NV_ChangeAuth without a change must not need NV");

    // A new authValue must be written to NV.
    policy_command_code(&mut sim, &session, TpmCc::NVChangeAuth);
    let rc = with_session(
        &mut sim,
        &change_auth_cmd(Handle(index), b"new"),
        &[&name],
        &mut session,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::NV_UNAVAILABLE.get());
}

/// ChangeEPS, ChangePPS and Clear fail with NV_UNAVAILABLE while NV is off.
///
/// ChangeEPS / ChangePPS / Clear check NV availability unconditionally.
#[test]
fn change_eps_change_pps_and_clear_need_nv() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    let rc = execute_with_password_sessions(
        &mut sim,
        &ChangeEPS {
            auth_handle: Handle::RH_PLATFORM,
        },
        1,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, nv_unavailable());
    let rc = execute_with_password_sessions(
        &mut sim,
        &ChangePPS {
            auth_handle: Handle::RH_PLATFORM,
        },
        1,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, nv_unavailable());
    assert_eq!(clear(&mut sim, Handle::RH_PLATFORM), Err(nv_unavailable()));
}

/// NV_DefineSpace/Write/UndefineSpace with NV unavailable fail with TPM_RC_NV_UNAVAILABLE and change nothing
#[test]
fn define_write_undefine_fail_when_nv_off() {
    let mut sim = create_simulator!();
    let index = 0x0150_0701;
    define(&mut sim, index, OWNER_RW, 8, &[]);
    owner_write(&mut sim, index, 0, &[1; 8]).unwrap();

    sim.signal_platform(SimulatorPlatformSignal::NvOff, NO_STREAM)
        .unwrap();
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0702, OWNER_RW, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::NV_UNAVAILABLE.get());
    assert_eq!(
        owner_write(&mut sim, index, 0, &[2; 8]).unwrap_err(),
        TpmRc::NV_UNAVAILABLE.get()
    );
    assert_eq!(
        pw(
            &mut sim,
            &NVUndefineSpace {
                auth_handle: Handle::RH_OWNER,
                nv_index: Handle(index)
            },
            1
        )
        .unwrap_err(),
        TpmRc::NV_UNAVAILABLE.get()
    );
    sim.signal_platform(SimulatorPlatformSignal::NvOn, NO_STREAM)
        .unwrap();

    // Nothing was changed while NV was unavailable.
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, index, 0, 8).unwrap(),
        vec![1; 8]
    );
}

/// HierarchyChangeAuth fails with NV_UNAVAILABLE even when the orderly state is already cleared.
///
/// The persistent NV-mutating hierarchy commands use RETURN_IF_NV_IS_NOT_AVAILABLE, which
/// fails even after the orderly state has already been cleared.
#[test]
fn hierarchy_change_auth_needs_nv_when_not_orderly() {
    let mut sim = create_simulator!();
    // The orderly state is SU_NONE after Startup, so RETURN_IF_ORDERLY alone never fails here.
    nv_off(&mut sim);
    assert_eq!(
        hierarchy_change_auth(&mut sim, Handle::RH_PLATFORM, &[], b"pp"),
        Err(nv_unavailable())
    );
    let rc = execute_with_password_sessions(
        &mut sim,
        &SetPrimaryPolicy {
            auth_handle: Handle::RH_PLATFORM,
            auth_policy: Tpm2bDigest::from_bytes(&[0x22; 32]).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        1,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, nv_unavailable());
}

/// SetPrimaryPolicy for the endorsement hierarchy needs NV; IncrementalSelfTest rejects ALG_NULL but accepts XOR.
#[test]
fn set_primary_policy_endorsement_needs_nv() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    set_primary_policy_nv_off_check(&mut sim, Handle::RH_ENDORSEMENT);
    nv_on(&mut sim);
    // IncrementalSelfTest: TPM_ALG_NULL is not implemented, TPM_ALG_XOR is.
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::NULL]),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
    incremental_self_test(&mut sim, &[Alg::XOR]).expect("XOR rejected");
}

/// SetPrimaryPolicy for TPM_RH_LOCKOUT fails with NV_UNAVAILABLE while NV is off.
#[test]
fn set_primary_policy_lockout_needs_nv() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    set_primary_policy_nv_off_check(&mut sim, Handle::RH_LOCKOUT);
}

/// SetPrimaryPolicy for TPM_RH_OWNER fails with NV_UNAVAILABLE while NV is off.
#[test]
fn set_primary_policy_owner_needs_nv() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    set_primary_policy_nv_off_check(&mut sim, Handle::RH_OWNER);
}
