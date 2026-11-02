//! TPM2_SetAlgorithmSet: the platform sets the vendor-dependent algorithm set reported as
//! TPM_PT_ALGORITHM_SET, which is persistent and changes no algorithm.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{SetAlgorithmSet, Startup};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmPt, TpmSu};

/// `TPM2_SetAlgorithmSet(auth_handle, algorithm_set)` with an empty password.
fn set_algorithm_set(tpm: &mut Tpm, auth_handle: Handle, algorithm_set: u32) -> Result<(), u32> {
    execute_with_password_sessions(
        tpm,
        &SetAlgorithmSet {
            auth_handle,
            algorithm_set,
        },
        1,
        &[],
    )
    .map(|_| ())
}

/// TPM_PT_ALGORITHM_SET is 0 after manufacture and reports the value the platform sets.
#[test]
fn sets_algorithm_set_property() {
    let mut tpm = Tpm::new();
    assert_eq!(get_tpm_property(&mut tpm, TpmPt::ALGORITHM_SET), 0);
    assert_eq!(
        set_algorithm_set(&mut tpm, Handle::RH_PLATFORM, 0xA5A5_0001),
        Ok(())
    );
    assert_eq!(
        get_tpm_property(&mut tpm, TpmPt::ALGORITHM_SET),
        0xA5A5_0001
    );
}

/// Only the platform can set the algorithm set (`TPMI_RH_PLATFORM`): `TPM_RC_VALUE` (handle 1)
/// for the owner, and a wrong platform password fails authorization.
#[test]
fn requires_platform_authorization() {
    let mut tpm = Tpm::new();
    assert_eq!(
        set_algorithm_set(&mut tpm, Handle::RH_OWNER, 1),
        Err(TpmRc::VALUE.with(Position::handle(1)).get())
    );
    assert_eq!(
        execute_with_password_sessions(
            &mut tpm,
            &SetAlgorithmSet {
                auth_handle: Handle::RH_PLATFORM,
                algorithm_set: 1,
            },
            1,
            b"wrong",
        )
        .unwrap_err(),
        TpmRc::BAD_AUTH.with(Position::session(1)).get()
    );
    assert_eq!(get_tpm_property(&mut tpm, TpmPt::ALGORITHM_SET), 0);
}

/// The algorithm set is persistent: it survives a TPM Reset, and since it changes no PCR bank,
/// a later TPM Resume (`TPM2_Startup(TPM_SU_STATE)`) is not refused.
#[test]
fn survives_reset_and_allows_resume() {
    let mut tpm = Tpm::new();
    assert_eq!(set_algorithm_set(&mut tpm, Handle::RH_PLATFORM, 7), Ok(()));
    power_cycle_orderly(&mut tpm, false);
    assert_eq!(get_tpm_property(&mut tpm, TpmPt::ALGORITHM_SET), 7);

    assert_eq!(set_algorithm_set(&mut tpm, Handle::RH_PLATFORM, 8), Ok(()));
    assert_eq!(
        power_cycle_with(&mut tpm, Some(TpmSu::State as u16), TpmSu::State as u16),
        0
    );
    assert_eq!(get_tpm_property(&mut tpm, TpmPt::ALGORITHM_SET), 8);
}

/// TPM2_SetAlgorithmSet updates NV: `TPM_RC_NV_UNAVAILABLE` while NV is unavailable.
#[test]
fn needs_nv() {
    let mut tpm = Tpm::new();
    tpm.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(
        set_algorithm_set(&mut tpm, Handle::RH_PLATFORM, 3),
        Err(TpmRc::NV_UNAVAILABLE.get())
    );
    tpm.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    assert_eq!(get_tpm_property(&mut tpm, TpmPt::ALGORITHM_SET), 0);
}

/// TPM2_SetAlgorithmSet needs `TPM2_Startup` like every command but TPM2_Startup.
#[test]
fn needs_startup() {
    let mut tpm = Tpm::new();
    tpm.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    tpm.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    nv_on(&mut tpm);
    assert_eq!(
        set_algorithm_set(&mut tpm, Handle::RH_PLATFORM, 3),
        Err(TpmRc::INITIALIZE.get())
    );
    tpm.execute(Startup {
        startup_type: TpmSu::Clear,
    })
    .unwrap();
    assert_eq!(set_algorithm_set(&mut tpm, Handle::RH_PLATFORM, 3), Ok(()));
}
