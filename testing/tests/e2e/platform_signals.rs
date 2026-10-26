//! The platform signals of the simulator's MSSIM platform port (power, TPM
//! reset, NV availability) and the command locality: signals in states where
//! they have no effect, as in the TCG
//! reference simulator (`_rpc__Signal_PowerOn(isReset)`,
//! `_rpc__Signal_NvOff()`): power on while the power is on, and a reset or NV
//! off while the power is off, are ignored; a power cycle makes NV available
//! again, a reset without a power loss does not; localities 5-31 select
//! locality 0, and extended localities match no PCR locality attribute.
//!
//! TPM 2.0 Part 1, "_TPM_Init": "_TPM_Init indicates that a TPM is to be
//! initialized. [...] The method of signaling _TPM_Init is platform
//! specific." The specification leaves these platform signals to the
//! platform, so the simulator follows the reference simulator.

use crate::_common::rc_of;
use testing::tpm::{SimulatorPlatformSignal, Tpm};

/// `TPM2_Startup(TPM_SU_CLEAR)`.
const STARTUP_CLEAR: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x44, 0, 0];

/// `TPM2_GetRandom(8)`.
const GET_RANDOM: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0, 8];

/// `TPM_RC_INITIALIZE`.
const TPM_RC_INITIALIZE: u32 = 0x100;

/// `TPM_RC_NV_UNAVAILABLE`.
const TPM_RC_NV_UNAVAILABLE: u32 = 0x923;

/// Power on while the TPM is powered on does not initialize it again: the TPM
/// stays started, so `TPM2_Startup` fails with `TPM_RC_INITIALIZE` (TPM 2.0
/// Part 3, TPM2_Startup: "`TPM_RC_INITIALIZE` | TPM not in initialized
/// state").
#[test]
fn power_on_while_powered_on_is_ignored() {
    let mut tpm = Tpm::new();
    tpm.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    assert_eq!(
        rc_of(&tpm.send_command(0, &STARTUP_CLEAR)),
        TPM_RC_INITIALIZE
    );
    assert_eq!(rc_of(&tpm.send_command(0, &GET_RANDOM)), 0);
}

/// A reset while the TPM is powered off is ignored: the TPM stays off (no
/// response) until it is powered on, and then needs `TPM2_Startup`.
#[test]
fn reset_while_powered_off_is_ignored() {
    let mut tpm = Tpm::new();
    tpm.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    tpm.signal_platform(SimulatorPlatformSignal::Reset).unwrap();
    assert!(tpm.send_command(0, &GET_RANDOM).is_empty());
    tpm.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    assert_eq!(rc_of(&tpm.send_command(0, &GET_RANDOM)), TPM_RC_INITIALIZE);
    assert_eq!(rc_of(&tpm.send_command(0, &STARTUP_CLEAR)), 0);
}

/// A reset initializes the TPM (`_TPM_Init`) but, without a power loss,
/// leaves NV unavailable after `NvOff` (`TPM2_Startup` fails with
/// `TPM_RC_NV_UNAVAILABLE`); a power cycle makes NV available again.
#[test]
fn reset_keeps_nv_unavailable_and_power_cycle_restores_it() {
    let mut tpm = Tpm::new();
    tpm.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    tpm.signal_platform(SimulatorPlatformSignal::Reset).unwrap();
    assert_eq!(
        rc_of(&tpm.send_command(0, &STARTUP_CLEAR)),
        TPM_RC_NV_UNAVAILABLE
    );
    tpm.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    tpm.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    assert_eq!(rc_of(&tpm.send_command(0, &STARTUP_CLEAR)), 0);
}

/// NV off while the TPM is powered off is ignored, and powering on makes NV
/// available, so `TPM2_Startup(TPM_SU_CLEAR)` succeeds without `NvOn`.
#[test]
fn nv_off_while_powered_off_is_ignored() {
    let mut tpm = Tpm::new();
    tpm.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    tpm.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    tpm.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    assert_eq!(rc_of(&tpm.send_command(0, &STARTUP_CLEAR)), 0);
}

/// A command at a locality from 5 to 31 runs at locality 0: TPM 2.0 Part 1, "Locality":
/// "Locality 5 through 31 cannot be selected." (the TCG reference platform,
/// `_plat__LocalitySet()`, selects locality 0 instead), so `TPM2_PCR_Extend` of PCR 0, which
/// only locality 0 may extend, succeeds at locality 5.
#[test]
fn locality_5_to_31_selects_locality_0() {
    let mut tpm = Tpm::new();
    for locality in [5, 31] {
        assert_eq!(
            rc_of(&tpm.send_command(locality, &pcr_extend(0))),
            0,
            "locality {locality}"
        );
    }
}

/// An extended locality (32-255) is not one of the localities 0-4 of a PCR's extend and reset
/// attributes: TPM 2.0 Part 1, "Locality": "Localities 0 through 4 are represented as bits in
/// the byte [...] For extended localities, the locality byte is an integer value representing
/// the locality." So `TPM2_PCR_Extend` of PCR 0 and `TPM2_PCR_Reset` of PCR 16 fail with
/// `TPM_RC_LOCALITY` at localities 67 and 68 (which the references once aliased to localities 3
/// and 4). Found by differential fuzzing.
#[test]
fn extended_locality_cannot_extend_or_reset_pcrs() {
    let mut tpm = Tpm::new();
    for locality in [32, 67, 68, 255] {
        assert_eq!(
            rc_of(&tpm.send_command(locality, &pcr_extend(0))),
            TPM_RC_LOCALITY,
            "extend at locality {locality}"
        );
        assert_eq!(
            rc_of(&tpm.send_command(locality, &pcr_reset(16))),
            TPM_RC_LOCALITY,
            "reset at locality {locality}"
        );
    }
}

/// `TPM_RC_LOCALITY`.
const TPM_RC_LOCALITY: u32 = 0x907;

/// `TPM2_PCR_Extend(pcr, password session, digests = [SHA-256: 32 x 0x11])`.
fn pcr_extend(pcr: u32) -> Vec<u8> {
    let mut cmd = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x82];
    cmd.extend_from_slice(&pcr.to_be_bytes());
    cmd.extend_from_slice(&[0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0]);
    cmd.extend_from_slice(&[0, 0, 0, 1, 0x00, 0x0b]);
    cmd.extend_from_slice(&[0x11; 32]);
    let size = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&size.to_be_bytes());
    cmd
}

/// `TPM2_PCR_Reset(pcr, password session)`.
fn pcr_reset(pcr: u32) -> Vec<u8> {
    let mut cmd = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x01, 0x3d];
    cmd.extend_from_slice(&pcr.to_be_bytes());
    cmd.extend_from_slice(&[0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0]);
    cmd
}

/// Until a `TPM2_Startup` completes after a power loss, every `_TPM_Init` (also a reset) treats
/// the power as lost and makes NV available again (TCG reference: `g_powerWasLost` is cleared
/// only by a successful `TPM2_Startup`, and `NvPowerOn()` re-enables NV), so after power on, NV
/// off and a reset, `TPM2_Startup(TPM_SU_STATE)` gets past the NV check and fails because there
/// is no saved state (`TPM_RC_VALUE` on `startupType`). Found by differential fuzzing.
#[test]
fn reset_before_startup_after_power_loss_restores_nv() {
    let mut tpm = Tpm::new();
    for signal in [
        SimulatorPlatformSignal::PowerOff,
        SimulatorPlatformSignal::PowerOn,
        SimulatorPlatformSignal::NvOff,
        SimulatorPlatformSignal::Reset,
    ] {
        tpm.signal_platform(signal).unwrap();
    }
    let startup_state = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x44, 0, 1];
    assert_eq!(rc_of(&tpm.send_command(0, &startup_state)), 0x1c4);
    assert_eq!(rc_of(&tpm.send_command(0, &STARTUP_CLEAR)), 0);
}
