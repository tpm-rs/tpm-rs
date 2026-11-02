//! TPM2_PP_Commands and the list of commands that require Physical Presence
//! (TPM_CAP_PP_COMMANDS): the manufacture default, setting and clearing gatable commands,
//! the Physical Presence check of platform authorizations (password, HMAC and policy), and
//! persistence across power cycles.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{ClearControl, GetCapability, PPCommands, SetPrimaryPolicy};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, TpmCap, TpmCc, TpmSe, TpmaSession, TpmiAlgHash,
    TpmlCc, TpmsAuthCommand, TpmsCapabilityData,
};

/// `TPM2_GetCapability(TPM_CAP_PP_COMMANDS, property, count)`: the listed commands and
/// `moreData`.
fn pp_commands_cap(tpm: &mut Tpm, property: u32, count: u32) -> (Vec<TpmCc>, bool) {
    let rsp = tpm
        .execute(GetCapability {
            capability: TpmCap::PPCommands,
            property,
            property_count: count,
        })
        .expect("TPM2_GetCapability failed");
    match rsp.capability_data {
        TpmsCapabilityData::PPCommands(list) => (list.as_slice().to_vec(), rsp.more_data),
        other => panic!("unexpected capability data: {other:?}"),
    }
}

/// The whole list of commands that require Physical Presence.
fn pp_list(tpm: &mut Tpm) -> Vec<TpmCc> {
    pp_commands_cap(tpm, TpmCc::FIRST.code(), 256).0
}

/// A `TPM2_PP_Commands(TPM_RH_PLATFORM, set, clear)` command.
fn pp_commands(set: &[TpmCc], clear: &[TpmCc]) -> PPCommands {
    PPCommands {
        auth: Handle::RH_PLATFORM,
        set_list: TpmlCc::from_slice(set).unwrap(),
        clear_list: TpmlCc::from_slice(clear).unwrap(),
    }
}

/// Runs TPM2_PP_Commands with the (empty) platform password while Physical Presence is
/// asserted, and deasserts it again.
fn pp_commands_with_pp(tpm: &mut Tpm, set: &[TpmCc], clear: &[TpmCc]) {
    tpm.signal_platform(SimulatorPlatformSignal::PhysicalPresenceOn)
        .unwrap();
    execute_with_password_sessions(tpm, &pp_commands(set, clear), 1, &[])
        .expect("TPM2_PP_Commands failed");
    tpm.signal_platform(SimulatorPlatformSignal::PhysicalPresenceOff)
        .unwrap();
}

/// `TPM2_ClearControl(auth, disable = NO)` with an empty password; returns its response code.
fn clear_control_rc(tpm: &mut Tpm, auth: Handle, password: &[u8]) -> Result<(), u32> {
    execute_with_password_sessions(
        tpm,
        &ClearControl {
            auth,
            disable: false,
        },
        1,
        password,
    )
    .map(|_| ())
}

/// After manufacture, TPM2_PP_Commands is the only command that requires Physical Presence.
#[test]
fn manufacture_list_holds_only_pp_commands() {
    let mut tpm = Tpm::new();
    assert_eq!(pp_list(&mut tpm), [TpmCc::PPCommands]);
    // A list starting after it is empty; a zero count reports moreData.
    assert_eq!(
        pp_commands_cap(&mut tpm, TpmCc::PPCommands.code() + 1, 256),
        (vec![], false)
    );
    assert_eq!(pp_commands_cap(&mut tpm, 0, 0), (vec![], true));
}

/// TPM2_PP_Commands itself requires Physical Presence: without it, `TPM_RC_PP` (session 1),
/// checked before the password (even a wrong one).
#[test]
fn requires_physical_presence() {
    let mut tpm = Tpm::new();
    let cmd = pp_commands(&[TpmCc::ClearControl], &[]);
    assert_eq!(
        execute_with_password_sessions(&mut tpm, &cmd, 1, &[]).unwrap_err(),
        TpmRc::PP.with(Position::session(1)).get()
    );
    assert_eq!(
        execute_with_password_sessions(&mut tpm, &cmd, 1, b"wrong").unwrap_err(),
        TpmRc::PP.with(Position::session(1)).get()
    );
    assert_eq!(pp_list(&mut tpm), [TpmCc::PPCommands]);

    // With Physical Presence, a wrong password fails as usual.
    tpm.signal_platform(SimulatorPlatformSignal::PhysicalPresenceOn)
        .unwrap();
    assert_eq!(
        execute_with_password_sessions(&mut tpm, &cmd, 1, b"wrong").unwrap_err(),
        TpmRc::BAD_AUTH.with(Position::session(1)).get()
    );
}

/// TPM2_PP_Commands takes only `TPM_RH_PLATFORM` (`TPMI_RH_PLATFORM`): `TPM_RC_VALUE` (handle 1)
/// for the owner.
#[test]
fn requires_platform_handle() {
    let mut tpm = Tpm::new();
    let mut cmd = pp_commands(&[], &[]);
    cmd.auth = Handle::RH_OWNER;
    assert_eq!(
        execute_with_password_sessions(&mut tpm, &cmd, 1, &[]).unwrap_err(),
        TpmRc::VALUE.with(Position::handle(1)).get()
    );
}

/// The set list adds gatable implemented commands; other commands (not gatable, or not
/// implemented) are discarded, TPM2_PP_Commands cannot be cleared, and a command in both lists
/// ends up cleared.
#[test]
fn set_and_clear_lists() {
    let mut tpm = Tpm::new();
    pp_commands_with_pp(
        &mut tpm,
        &[
            TpmCc::ClearControl,
            TpmCc::Clear,
            TpmCc::GetRandom,         // not gatable
            TpmCc::FieldUpgradeStart, // not implemented
            TpmCc::HierarchyChangeAuth,
        ],
        &[TpmCc::PPCommands, TpmCc::HierarchyChangeAuth],
    );
    assert_eq!(
        pp_list(&mut tpm),
        [TpmCc::Clear, TpmCc::ClearControl, TpmCc::PPCommands]
    );

    // The list starting at a property, limited by the count.
    assert_eq!(
        pp_commands_cap(&mut tpm, TpmCc::Clear.code(), 1),
        (vec![TpmCc::Clear], true)
    );
    assert_eq!(
        pp_commands_cap(&mut tpm, TpmCc::Clear.code() + 1, 256),
        (vec![TpmCc::ClearControl, TpmCc::PPCommands], false)
    );

    pp_commands_with_pp(&mut tpm, &[], &[TpmCc::Clear]);
    assert_eq!(pp_list(&mut tpm), [TpmCc::ClearControl, TpmCc::PPCommands]);
}

/// A command on the list requires Physical Presence with platform authorization only: the
/// platform fails with `TPM_RC_PP` without it, and lockout authorization needs none.
#[test]
fn listed_command_requires_physical_presence_for_platform_auth() {
    let mut tpm = Tpm::new();
    pp_commands_with_pp(&mut tpm, &[TpmCc::ClearControl], &[]);

    assert_eq!(
        clear_control_rc(&mut tpm, Handle::RH_PLATFORM, &[]),
        Err(TpmRc::PP.with(Position::session(1)).get())
    );
    // `disable = NO` with lockout authorization is `TPM_RC_AUTH_FAIL` (not a PP error).
    assert_eq!(
        clear_control_rc(&mut tpm, Handle::RH_LOCKOUT, &[]),
        Err(TpmRc::AUTH_FAIL.get())
    );

    tpm.signal_platform(SimulatorPlatformSignal::PhysicalPresenceOn)
        .unwrap();
    assert_eq!(clear_control_rc(&mut tpm, Handle::RH_PLATFORM, &[]), Ok(()));
}

/// Physical Presence is also required for an HMAC session or a policy session (platformPolicy)
/// authorizing a listed command with `TPM_RH_PLATFORM`.
#[test]
fn hmac_and_policy_authorizations_require_physical_presence() {
    let mut tpm = Tpm::new();
    pp_commands_with_pp(&mut tpm, &[TpmCc::ClearControl], &[]);

    let mut hmac = hmac_session(&mut tpm);
    let mut uses = [SessUse::hmac(&mut hmac, ATTR_CONT, &[])];
    let rsp = exec(
        &mut tpm,
        TpmCc::ClearControl.code(),
        &[Handle::RH_PLATFORM.0],
        &mut uses,
        &[0],
        0,
    );
    assert_eq!(rsp.rc, TpmRc::PP.with(Position::session(1)).get());

    // platformPolicy: the empty-digest policy of a fresh SHA-256 session.
    execute_with_password_sessions(
        &mut tpm,
        &SetPrimaryPolicy {
            auth_handle: Handle::RH_PLATFORM,
            auth_policy: Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        1,
        &[],
    )
    .unwrap();
    let policy = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);
    let auth = TpmsAuthCommand {
        session_handle: policy,
        nonce: Tpm2bNonce::from_bytes(&[0x22; 16]).unwrap(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };
    let cmd = ClearControl {
        auth: Handle::RH_PLATFORM,
        disable: false,
    };
    assert_eq!(
        exec_command(&mut tpm, &cmd, &[auth]).map(|_| ()),
        Err(TpmRc::PP.with(Position::session(1)).get())
    );
    tpm.signal_platform(SimulatorPlatformSignal::PhysicalPresenceOn)
        .unwrap();
    assert_eq!(exec_command(&mut tpm, &cmd, &[auth]).map(|_| ()), Ok(()));
}

/// The list is persistent: it survives power cycles (TPM Reset).
#[test]
fn list_survives_power_cycle() {
    let mut tpm = Tpm::new();
    pp_commands_with_pp(&mut tpm, &[TpmCc::ClearControl, TpmCc::Clear], &[]);
    tpm.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    power_on_start_up(&mut tpm);
    assert_eq!(
        pp_list(&mut tpm),
        [TpmCc::Clear, TpmCc::ClearControl, TpmCc::PPCommands]
    );
}

/// TPM2_PP_Commands updates NV: `TPM_RC_NV_UNAVAILABLE` while NV is unavailable.
#[test]
fn needs_nv() {
    let mut tpm = Tpm::new();
    tpm.signal_platform(SimulatorPlatformSignal::PhysicalPresenceOn)
        .unwrap();
    tpm.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(
        execute_with_password_sessions(&mut tpm, &pp_commands(&[TpmCc::Clear], &[]), 1, &[])
            .unwrap_err(),
        TpmRc::NV_UNAVAILABLE.get()
    );
    tpm.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    assert_eq!(pp_list(&mut tpm), [TpmCc::PPCommands]);
}

/// A TPML_CC with more than MAX_CAP_CC entries is `TPM_RC_SIZE` at its parameter.
#[test]
fn oversized_list_is_rejected() {
    let mut tpm = Tpm::new();
    tpm.signal_platform(SimulatorPlatformSignal::PhysicalPresenceOn)
        .unwrap();
    let max_cap_cc = tpm2::TPM2_MAX_CAP_CC as u32;
    let mut params = Vec::new();
    params.extend_from_slice(&0u32.to_be_bytes()); // setList: empty
    params.extend_from_slice(&(max_cap_cc + 1).to_be_bytes()); // clearList: too long
    for _ in 0..=max_cap_cc {
        params.extend_from_slice(&TpmCc::Clear.code().to_be_bytes());
    }
    let cmd = build_pw_cmd(
        TpmCc::PPCommands.code(),
        &[Handle::RH_PLATFORM.0],
        1,
        &params,
    );
    assert_eq!(
        send_rc(&mut tpm, &cmd),
        TpmRc::SIZE.with(Position::parameter(2)).get()
    );
}

/// TPM2_SetAlgorithmSet (handle `TPMI_RH_PLATFORM`) can be gated with Physical Presence.
#[cfg(feature = "cc-set-algorithm-set")]
#[test]
fn set_algorithm_set_can_be_gated() {
    let mut tpm = Tpm::new();
    pp_commands_with_pp(&mut tpm, &[TpmCc::SetAlgorithmSet], &[]);
    assert_eq!(
        pp_list(&mut tpm),
        [TpmCc::PPCommands, TpmCc::SetAlgorithmSet]
    );
    let cmd = tpm2::commands::SetAlgorithmSet {
        auth_handle: Handle::RH_PLATFORM,
        algorithm_set: 1,
    };
    assert_eq!(
        execute_with_password_sessions(&mut tpm, &cmd, 1, &[]).unwrap_err(),
        TpmRc::PP.with(Position::session(1)).get()
    );
}
