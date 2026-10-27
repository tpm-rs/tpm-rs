//! The Nuvoton vendor commands `NTC2_PreConfig` (`0x20000211`), `NTC2_LockPreConfig`
//! (`0x20000212`) and `NTC2_GetConfig` (`0x20000213`) as emulated by `ibmswtpm2` (not in the
//! TPM 2.0 specification), implemented in the `ibmswtpm2` profile (`tpm2-impl`'s
//! `ntc2-vendor-commands`): the initial configuration, setting and locking it, its RAM-only
//! lifetime (kept across power cycles and TPM Resets, reset with a new TPM), the
//! `NO_SESSIONS` attribute and the parameter checks. Without the profile feature the three
//! command codes are not implemented.

use crate::_common::{
    CAP_COMMANDS, PW_SESSION_CONTINUE, RC_INSUFFICIENT, RC_SIZE, ST_NO_SESSIONS, ST_SESSIONS,
    SimulatorPlatformSignal, build_raw_cmd, get_cap, power_cycle_with, send_raw,
};
use testing::tpm::Tpm;

/// `NTC2_CC_PreConfig`.
const CC_NTC2_PRE_CONFIG: u32 = 0x2000_0211;
/// `NTC2_CC_LockPreConfig`.
const CC_NTC2_LOCK_PRE_CONFIG: u32 = 0x2000_0212;
/// `NTC2_CC_GetConfig`.
const CC_NTC2_GET_CONFIG: u32 = 0x2000_0213;
/// `TPM_RC_COMMAND_CODE`.
const RC_COMMAND_CODE: u32 = 0x143;
/// `TPM_RC_DISABLED`.
const RC_DISABLED: u32 = 0x120;
/// `TPM_RC_AUTH_CONTEXT`.
const RC_AUTH_CONTEXT: u32 = 0x145;
/// `TPM_RC_P + TPM_RC_1`.
const P1: u32 = 0x140;
/// `TPM_SU_CLEAR`.
const SU_CLEAR: u16 = 0;
/// `TPM_SU_STATE`.
const SU_STATE: u16 = 1;

/// The configuration of a new TPM (`ntc2state` in `ibmswtpm2`'s `ntc2.c`): `i2cLoc1_2`,
/// `i2cLoc3_4`, `AltCfg` 0x13, `Direction` 0, `PullUp`, `PushPull`, `CFG_A`..`CFG_J` all
/// 0xFF, `IsValid` 0xAA and `IsLocked` 0xFF.
const INITIAL_CONFIG: [u8; 18] = [
    0xff, 0xff, 0x13, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xaa, 0xff,
];

/// A configuration to set, with `IsLocked` = 0xAA (which `NTC2_PreConfig` ignores) and an
/// invalid `IsValid` (which it does not check).
const NEW_CONFIG: [u8; 18] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x55, 0xaa,
];

/// [`NEW_CONFIG`] as stored: `IsLocked` forced to 0xFF.
fn stored(config: [u8; 18]) -> [u8; 18] {
    let mut c = config;
    c[17] = 0xff;
    c
}

/// Sends the vendor command `cc` without sessions and returns the response.
fn ntc2(sim: &mut Tpm, cc: u32, params: &[u8]) -> Vec<u8> {
    send_raw(sim, &build_raw_cmd(ST_NO_SESSIONS, cc, &[], None, params))
}

/// The response code of a response.
fn rc(rsp: &[u8]) -> u32 {
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

/// `NTC2_GetConfig`: the current configuration.
fn get_config(sim: &mut Tpm) -> Vec<u8> {
    let rsp = ntc2(sim, CC_NTC2_GET_CONFIG, &[]);
    assert_eq!(rc(&rsp), 0, "NTC2_GetConfig failed");
    rsp[10..].to_vec()
}

/// Without the ibmswtpm2 profile the NTC2 command codes are not implemented
///
/// Outside the `ibmswtpm2` profile every `NTC2_*` command fails with `TPM_RC_COMMAND_CODE`
/// (the profile itself is covered by the other tests of this file).
#[test]
fn commands_are_unimplemented_without_profile() {
    if tpm2_impl::NTC2_VENDOR_COMMANDS {
        return;
    }
    let mut sim = Tpm::new();
    for (cc, params) in [
        (CC_NTC2_PRE_CONFIG, &NEW_CONFIG[..]),
        (CC_NTC2_LOCK_PRE_CONFIG, &[][..]),
        (CC_NTC2_GET_CONFIG, &[][..]),
    ] {
        assert_eq!(
            rc(&ntc2(&mut sim, cc, params)),
            RC_COMMAND_CODE,
            "cc {cc:#x}"
        );
    }
}

/// A new TPM reports the initial configuration
///
/// `NTC2_GetConfig` returns the 18 raw bytes of the initial configuration.
#[test]
fn new_tpm_reports_initial_config() {
    if !tpm2_impl::NTC2_VENDOR_COMMANDS {
        return;
    }
    let mut sim = Tpm::new();
    assert_eq!(get_config(&mut sim), INITIAL_CONFIG);
}

/// PreConfig replaces the configuration except IsLocked
///
/// `NTC2_PreConfig` stores every field as given (without checking `IsValid`) but keeps
/// `IsLocked` at 0xFF, and can be repeated while the configuration is unlocked.
#[test]
fn pre_config_replaces_configuration() {
    if !tpm2_impl::NTC2_VENDOR_COMMANDS {
        return;
    }
    let mut sim = Tpm::new();
    assert_eq!(rc(&ntc2(&mut sim, CC_NTC2_PRE_CONFIG, &NEW_CONFIG)), 0);
    assert_eq!(get_config(&mut sim), stored(NEW_CONFIG));
    assert_eq!(rc(&ntc2(&mut sim, CC_NTC2_PRE_CONFIG, &INITIAL_CONFIG)), 0);
    assert_eq!(get_config(&mut sim), INITIAL_CONFIG);
}

/// LockPreConfig locks the configuration against PreConfig
///
/// After `NTC2_LockPreConfig` (which may be repeated), `NTC2_GetConfig` reports `IsLocked`
/// 0xAA and `NTC2_PreConfig` fails with `TPM_RC_DISABLED`, leaving the configuration
/// unchanged.
#[test]
fn lock_pre_config_disables_pre_config() {
    if !tpm2_impl::NTC2_VENDOR_COMMANDS {
        return;
    }
    let mut sim = Tpm::new();
    assert_eq!(rc(&ntc2(&mut sim, CC_NTC2_PRE_CONFIG, &NEW_CONFIG)), 0);
    assert_eq!(rc(&ntc2(&mut sim, CC_NTC2_LOCK_PRE_CONFIG, &[])), 0);
    assert_eq!(rc(&ntc2(&mut sim, CC_NTC2_LOCK_PRE_CONFIG, &[])), 0);
    let mut locked = stored(NEW_CONFIG);
    locked[17] = 0xaa;
    assert_eq!(get_config(&mut sim), locked);
    assert_eq!(
        rc(&ntc2(&mut sim, CC_NTC2_PRE_CONFIG, &INITIAL_CONFIG)),
        RC_DISABLED
    );
    assert_eq!(get_config(&mut sim), locked);
}

/// The configuration lives in RAM: it survives power cycles but not a new TPM
///
/// As in `ibmswtpm2` (which does not store it in NV), the configuration and its lock are
/// kept across a power cycle with TPM Reset, an orderly TPM Restart and a `_TPM_Init` reset
/// signal, and `Tpm::reset` (a new TPM) restores the initial configuration.
#[test]
fn configuration_survives_power_cycles_until_new_tpm() {
    if !tpm2_impl::NTC2_VENDOR_COMMANDS {
        return;
    }
    let mut sim = Tpm::new();
    assert_eq!(rc(&ntc2(&mut sim, CC_NTC2_PRE_CONFIG, &NEW_CONFIG)), 0);
    assert_eq!(rc(&ntc2(&mut sim, CC_NTC2_LOCK_PRE_CONFIG, &[])), 0);
    let mut locked = stored(NEW_CONFIG);
    locked[17] = 0xaa;

    assert_eq!(power_cycle_with(&mut sim, None, SU_CLEAR), 0);
    assert_eq!(get_config(&mut sim), locked);
    assert_eq!(power_cycle_with(&mut sim, Some(SU_STATE), SU_CLEAR), 0);
    assert_eq!(get_config(&mut sim), locked);
    sim.signal_platform(SimulatorPlatformSignal::Reset).unwrap();
    assert_eq!(
        rc(&send_raw(
            &mut sim,
            &build_raw_cmd(ST_NO_SESSIONS, 0x144, &[], None, &SU_CLEAR.to_be_bytes())
        )),
        0
    );
    assert_eq!(get_config(&mut sim), locked);

    sim.reset();
    assert_eq!(get_config(&mut sim), INITIAL_CONFIG);
}

/// The NTC2 commands do not allow sessions
///
/// The commands have the `NO_SESSIONS` attribute: sent with `TPM_ST_SESSIONS` and a
/// password session, each fails with `TPM_RC_AUTH_CONTEXT` and changes nothing.
#[test]
fn sessions_are_rejected() {
    if !tpm2_impl::NTC2_VENDOR_COMMANDS {
        return;
    }
    let mut sim = Tpm::new();
    for (cc, params) in [
        (CC_NTC2_PRE_CONFIG, &NEW_CONFIG[..]),
        (CC_NTC2_LOCK_PRE_CONFIG, &[][..]),
        (CC_NTC2_GET_CONFIG, &[][..]),
    ] {
        let rsp = send_raw(
            &mut sim,
            &build_raw_cmd(ST_SESSIONS, cc, &[], Some(&PW_SESSION_CONTINUE), params),
        );
        assert_eq!(rc(&rsp), RC_AUTH_CONTEXT, "cc {cc:#x}");
    }
    assert_eq!(get_config(&mut sim), INITIAL_CONFIG);
}

/// Malformed parameter areas are rejected
///
/// A configuration shorter than 18 bytes is `TPM_RC_INSUFFICIENT + P1`, and bytes after the
/// parameters (of any of the three commands) are `TPM_RC_SIZE`; the configuration stays
/// unchanged.
#[test]
fn malformed_parameters_are_rejected() {
    if !tpm2_impl::NTC2_VENDOR_COMMANDS {
        return;
    }
    let mut sim = Tpm::new();
    assert_eq!(
        rc(&ntc2(&mut sim, CC_NTC2_PRE_CONFIG, &NEW_CONFIG[..17])),
        RC_INSUFFICIENT + P1
    );
    assert_eq!(
        rc(&ntc2(&mut sim, CC_NTC2_PRE_CONFIG, &[])),
        RC_INSUFFICIENT + P1
    );
    let mut long = NEW_CONFIG.to_vec();
    long.push(0);
    assert_eq!(rc(&ntc2(&mut sim, CC_NTC2_PRE_CONFIG, &long)), RC_SIZE);
    assert_eq!(rc(&ntc2(&mut sim, CC_NTC2_LOCK_PRE_CONFIG, &[0])), RC_SIZE);
    assert_eq!(rc(&ntc2(&mut sim, CC_NTC2_GET_CONFIG, &[0])), RC_SIZE);
    assert_eq!(get_config(&mut sim), INITIAL_CONFIG);
}

/// TPM_CAP_COMMANDS reports the NTC2 commands as vendor commands that may write NV
///
/// Each `NTC2_*` command has a `TPMA_CC` of `V` and `nv` SET, no handles and its low 16
/// command-code bits as `commandIndex`.
#[test]
fn command_attributes_are_vendor_and_nv() {
    if !tpm2_impl::NTC2_VENDOR_COMMANDS {
        return;
    }
    let mut sim = Tpm::new();
    for cc in [
        CC_NTC2_PRE_CONFIG,
        CC_NTC2_LOCK_PRE_CONFIG,
        CC_NTC2_GET_CONFIG,
    ] {
        let (_, data) = get_cap(&mut sim, CAP_COMMANDS, cc, 1).unwrap();
        assert_eq!(u32::from_be_bytes(data[0..4].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_be_bytes(data[4..8].try_into().unwrap()),
            (1 << 29) | (1 << 22) | (cc & 0xFFFF),
            "cc {cc:#x}"
        );
    }
}
