//! TPM2_Clear and TPM2_ClearControl: disableClear handling, NV requirements, and what Clear resets
//! or keeps.

use crate::_common::{
    SU_CLEAR, clear, clear_control, create_storage_primary_with_auth, evict, flush_context, nv_off,
    nv_on, nv_unavailable, object_exists, pcr_update_counter, power_cycle_with, read_clock,
};
use testing::tpm::Tpm;
use tpm2::Handle;
use tpm2::commands::{Clear, ClearControl, ContextLoad, ContextSave};
use tpm2::errors::TpmRc;

/// After ClearControl(disable), Clear is TPM_RC_DISABLED and ClearControl(enable) via lockout is TPM_RC_AUTH_FAIL
#[test]
fn clear_rejected_when_disabled() {
    let mut sim = Tpm::new();

    let disable_cmd = ClearControl {
        auth: Handle::RH_LOCKOUT,
        disable: true,
    };
    sim.execute(disable_cmd).expect("ClearControl failed");

    let cmd = Clear {
        auth_handle: Handle::RH_LOCKOUT,
    };

    let err = sim.execute(cmd).unwrap_err();
    assert_eq!(err.get(), TpmRc::DISABLED.get());

    let reenable_cmd = ClearControl {
        auth: Handle::RH_LOCKOUT,
        disable: false,
    };
    let err2 = sim.execute(reenable_cmd).unwrap_err();
    assert_eq!(err2.get(), TpmRc::AUTH_FAIL.get());
}

/// ClearControl needs NV, and disableClear survives an unorderly power loss.
///
/// Same persistence / NV checks for ClearControl.
#[test]
fn disable_clear_survives_power_loss() {
    let mut sim = Tpm::new();
    clear_control(&mut sim, Handle::RH_PLATFORM, true).unwrap();
    // Unorderly power loss must not lose disableClear either.
    assert_eq!(power_cycle_with(&mut sim, None, SU_CLEAR), 0);
    assert_eq!(
        clear(&mut sim, Handle::RH_PLATFORM),
        Err(TpmRc::DISABLED.get())
    );
    nv_off(&mut sim);
    assert_eq!(
        clear_control(&mut sim, Handle::RH_PLATFORM, false),
        Err(nv_unavailable())
    );
}

/// Clear keeps platform persistent objects, bumps the PCR update counter, resets clearCount and persists resetCount.
///
/// Clear keeps platform persistent objects, bumps the PCR update counter, resets clearCount,
/// and persists the zeroed resetCount.
#[test]
fn keeps_platform_objects_and_updates_counters() {
    let mut sim = Tpm::new();
    let (owner_key, _) = create_storage_primary_with_auth(&mut sim, Handle::RH_OWNER, &[]);
    evict(&mut sim, Handle::RH_OWNER, owner_key, 0x8100_0001);
    let (platform_key, _) = create_storage_primary_with_auth(&mut sim, Handle::RH_PLATFORM, &[]);
    evict(&mut sim, Handle::RH_PLATFORM, platform_key, 0x8180_0001);

    // A saved platform-object context must remain loadable: clearCount is reset to 0
    // (it was already 0 after the TPM Reset), not incremented.
    let saved = sim
        .execute(ContextSave {
            save_handle: platform_key,
        })
        .unwrap()
        .context;

    let counter_before = pcr_update_counter(&mut sim);
    clear(&mut sim, Handle::RH_PLATFORM).unwrap();

    assert!(
        !object_exists(&mut sim, 0x8100_0001),
        "owner object survived"
    );
    assert!(
        object_exists(&mut sim, 0x8180_0001),
        "platform object deleted"
    );
    assert_eq!(pcr_update_counter(&mut sim), counter_before + 1);

    flush_context(&mut sim, platform_key).unwrap();
    sim.execute(ContextLoad { context: saved })
        .expect("platform context no longer loadable after Clear");

    // resetCount was zeroed and written to NV: the next TPM Reset makes it 1.
    assert_eq!(read_clock(&mut sim).clock_info.reset_count, 0);
    assert_eq!(power_cycle_with(&mut sim, None, SU_CLEAR), 0);
    assert_eq!(read_clock(&mut sim).clock_info.reset_count, 1);
}

/// Clear checks NV availability before disableClear (NV_UNAVAILABLE, then DISABLED).
///
/// `TPM2_Clear`: NV availability is checked before `disableClear`.
#[test]
fn nv_checked_before_disable_clear() {
    let mut sim = Tpm::new();
    clear_control(&mut sim, Handle::RH_PLATFORM, true).unwrap();
    nv_off(&mut sim);
    assert_eq!(clear(&mut sim, Handle::RH_LOCKOUT), Err(nv_unavailable()));
    nv_on(&mut sim);
    assert_eq!(
        clear(&mut sim, Handle::RH_LOCKOUT),
        Err(TpmRc::DISABLED.get())
    );
}
