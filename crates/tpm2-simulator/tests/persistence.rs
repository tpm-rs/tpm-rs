//! Tests of the persistence of a complete simulated TPM (`Simulator::save_persisted_state` /
//! `restore_persisted_state`): besides the engine's state, the platform state that only the
//! simulator keeps (the installed firmware image) moves to the target of a live migration, which
//! is then powered on with NV enabled and keeps time on its own platform timer.
#![cfg(feature = "persistence")]

use tpm2::Connection;
use tpm2::commands::{GetRandom, HierarchyChangeAuth, PCRExtend, PCRRead, ReadClock};
use tpm2::platform::{SimulatedFirmware, TpmFirmware};
use tpm2::{
    Handle, Tpm2bAuth, TpmiAlgHash, TpmlDigestValues, TpmlPcrSelection, TpmsPcrSelection, TpmtHa,
};
use tpm2_engine::persistence::{DeserializeError, PersistedTpmState};
use tpm2_engine::storage::ram_storage_mock::RamStorageMock;
use tpm2_platform_linux::{LinuxRng, LinuxTimer, PlatformCryptoProvider};
use tpm2_simulator::{NO_STREAM, PlatformConnection, Simulator, SimulatorPlatformSignal};

/// Builds a simulator `$sim` over its own components and firmware `$fw`.
macro_rules! simulator {
    ($sim:ident, $fw:ident) => {
        let mut crypto = PlatformCryptoProvider;
        let mut storage = Box::new(RamStorageMock::<{ tpm2_simulator::NV_STORAGE_SIZE }>::new());
        let mut timer = LinuxTimer::new();
        let mut rng = LinuxRng::new();
        let $fw = SimulatedFirmware::default();
        #[allow(unused_mut)]
        let mut $sim =
            Simulator::new(&mut crypto, &mut storage, &mut timer, &mut rng, &$fw).unwrap();
    };
}

/// Powers `sim` on, enables NV and starts the TPM (`TPM2_Startup(TPM_SU_CLEAR)`).
fn power_on_start_up(sim: &mut Simulator<'_>) {
    sim.signal_platform(SimulatorPlatformSignal::PowerOn, NO_STREAM)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::NvOn, NO_STREAM)
        .unwrap();
    sim.execute(tpm2::commands::Startup {
        startup_type: tpm2::TpmSu::Clear,
    })
    .unwrap();
}

/// Whether `sim` answers a command (`TPM2_GetRandom` sent raw): a powered-off simulator returns
/// an empty response.
fn answers(sim: &mut Simulator<'_>) -> bool {
    const GET_RANDOM: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0, 8];
    let mut rsp = [0u8; 64];
    !sim.transact(&GET_RANDOM, &mut rsp).unwrap().is_empty()
}

/// The SHA-256 value of PCR 16.
fn pcr16(sim: &mut Simulator<'_>) -> Vec<u8> {
    let mut list = TpmlPcrSelection::default();
    list.add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0, 0, 1]).unwrap())
        .unwrap();
    let rsp = sim
        .execute(PCRRead {
            pcr_selection_in: list,
        })
        .unwrap();
    rsp.pcr_values.as_ref()[0].as_slice().to_vec()
}

/// `persisted` without the platform time that elapsed since the last command (it grows with the
/// real time between two saves).
fn without_elapsed_platform_time(persisted: &PersistedTpmState) -> Box<PersistedTpmState> {
    let mut persisted = Box::new(persisted.clone());
    persisted.time.pending_platform_ms = 0;
    persisted.act.tick_phase_ms = 0;
    persisted
}

/// *Time* (`TPM2_ReadClock`).
fn time(sim: &mut Simulator<'_>) -> u64 {
    sim.execute(ReadClock {}).unwrap().current_time.time
}

/// A migrated simulator keeps time on its own platform timer: the target's timer, created after
/// the source's, reads less than the source's did at the save, yet *Time* goes on from the
/// source's value with the time elapsed on the target.
#[test]
fn migrated_simulator_keeps_time_on_its_own_timer() {
    simulator!(source, _source_fw);
    power_on_start_up(&mut source);
    std::thread::sleep(std::time::Duration::from_millis(400));
    let source_time = time(&mut source);
    let mut persisted = Box::<PersistedTpmState>::default();
    source.save_persisted_state(&mut persisted).unwrap();

    simulator!(target, _target_fw);
    target.restore_persisted_state(&persisted).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(time(&mut target) >= source_time + 100);
}

/// A migrated simulator is powered on with NV enabled and the source's firmware image, and
/// continues with the source's TPM state.
#[test]
fn migrated_simulator_keeps_power_nv_and_firmware() {
    simulator!(source, source_fw);
    simulator!(target, target_fw);
    power_on_start_up(&mut source);
    source
        .execute(HierarchyChangeAuth {
            auth_handle: Handle::RH_OWNER,
            new_auth: Tpm2bAuth::from_bytes(b"pw").unwrap(),
        })
        .unwrap();
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&[0x5A; 32])).unwrap();
    source
        .execute(PCRExtend {
            pcr_handle: Handle(16),
            digests,
        })
        .unwrap();
    source_fw.set_firmware_hash(0x1234_5678);
    source_fw.set_firmware_svn(42);

    let mut persisted = Box::<PersistedTpmState>::default();
    source.save_persisted_state(&mut persisted).unwrap();
    let platform = persisted.platform.unwrap();
    assert_eq!(
        (platform.firmware_hash, platform.firmware_svn),
        (0x1234_5678, 42)
    );

    // The target was never powered on: commands get an empty response.
    assert!(!answers(&mut target));
    target.restore_persisted_state(&persisted).unwrap();
    assert_eq!(target_fw.firmware_hash(), 0x1234_5678);
    assert_eq!(target_fw.firmware_svn(), 42);

    // Powered on, started and with the source's PCRs, without any platform signal.
    assert_eq!(pcr16(&mut target), pcr16(&mut source));
    target.execute(GetRandom { bytes_requested: 8 }).unwrap();
    target.execute(ReadClock {}).unwrap();

    let mut restored = Box::<PersistedTpmState>::default();
    target.save_persisted_state(&mut restored).unwrap();
    let mut again = Box::<PersistedTpmState>::default();
    source.save_persisted_state(&mut again).unwrap();
    assert_eq!(restored.platform, again.platform);
}

/// The platform state holds the firmware image only: the state is saved between commands of a
/// powered-on simulator with NV enabled, and a restored simulator is powered on with NV
/// enabled, also if its NV was disabled before.
#[test]
fn restored_simulator_has_nv_enabled() {
    simulator!(source, _source_fw);
    simulator!(target, _target_fw);
    power_on_start_up(&mut source);
    let mut persisted = Box::<PersistedTpmState>::default();
    source.save_persisted_state(&mut persisted).unwrap();

    power_on_start_up(&mut target);
    target
        .signal_platform(SimulatorPlatformSignal::NvOff, NO_STREAM)
        .unwrap();
    let change_auth = || HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(b"pw").unwrap(),
    };
    assert!(target.execute(change_auth()).is_err());
    target.restore_persisted_state(&persisted).unwrap();
    target.execute(change_auth()).unwrap();
}

/// A persisted state without the simulator's platform state (extracted from an engine alone)
/// and a firmware SVN above the maximum are rejected without changing the simulator.
#[test]
fn incomplete_or_invalid_platform_state_is_rejected() {
    simulator!(source, _source_fw);
    simulator!(target, target_fw);
    power_on_start_up(&mut source);
    power_on_start_up(&mut target);
    let mut before = Box::<PersistedTpmState>::default();
    target.save_persisted_state(&mut before).unwrap();

    let mut persisted = Box::<PersistedTpmState>::default();
    source.save_persisted_state(&mut persisted).unwrap();

    let mut no_platform = persisted.clone();
    no_platform.platform = None;
    assert_eq!(
        target.restore_persisted_state(&no_platform).unwrap_err(),
        DeserializeError::MissingField("platform")
    );

    let mut bad_svn = persisted.clone();
    if let Some(p) = &mut bad_svn.platform {
        p.firmware_svn = target_fw.firmware_max_svn() + 1;
    }
    assert_eq!(
        target.restore_persisted_state(&bad_svn).unwrap_err(),
        DeserializeError::InvalidValue("firmware_svn")
    );

    let mut after = Box::<PersistedTpmState>::default();
    target.save_persisted_state(&mut after).unwrap();
    assert_eq!(
        without_elapsed_platform_time(&before),
        without_elapsed_platform_time(&after)
    );
}
