use std::io::Cursor;
use tpm2::platform::SimulatedFirmware;
use tpm2_impl::storage::ram_storage_mock::RamStorageMock;
use tpm2_platform_linux::{LinuxRng, LinuxTimer, PlatformCryptoProvider};
use tpm2_simulator::{PlatformConnection, Simulator, SimulatorPlatformSignal};

#[test]
fn test_invalid_platform_signal() {
    let mut crypto = PlatformCryptoProvider;
    let mut storage = RamStorageMock::<{ tpm2_simulator::NV_STORAGE_SIZE }>::new();
    let mut timer = LinuxTimer::new();
    let mut rng = LinuxRng::new();
    let firmware = SimulatedFirmware::default();
    let _sim = Simulator::new(&mut crypto, &mut storage, &mut timer, &mut rng, &firmware).unwrap();

    // 99 is not a platform signal code.
    assert!(SimulatorPlatformSignal::try_from(99).is_err());
}

#[test]
fn test_oversized_tpm_command() {
    let mut crypto = PlatformCryptoProvider;
    let mut storage = RamStorageMock::<{ tpm2_simulator::NV_STORAGE_SIZE }>::new();
    let mut timer = LinuxTimer::new();
    let mut rng = LinuxRng::new();
    let firmware = SimulatedFirmware::default();
    let mut sim =
        Simulator::new(&mut crypto, &mut storage, &mut timer, &mut rng, &firmware).unwrap();

    // TPM_SEND_COMMAND = 8
    // Payload length = 8193 (oversized)
    let mut payload = Vec::new();
    payload.push(0u8); // locality
    payload.extend_from_slice(&8193u32.to_be_bytes()); // length

    let mut stream = Cursor::new(payload);
    let res = sim.transact_platform(8, &mut stream);
    assert!(res.is_err());
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("exceeds maximum of 8192")
    );
}

/// Sends the MSSIM `ACT_GET_SIGNALED` platform signal for `act_handle` and returns the reply
/// value.
fn act_get_signaled(sim: &mut Simulator<'_>, act_handle: u32) -> u32 {
    let mut stream = Cursor::new(act_handle.to_be_bytes().to_vec());
    stream.set_position(0);
    let mut io = ReadThenWrite {
        input: stream,
        output: Vec::new(),
    };
    sim.signal_platform(SimulatorPlatformSignal::ActGetSignaled, Some(&mut io))
        .unwrap();
    assert_eq!(io.output.len(), 8, "value and result code");
    assert_eq!(&io.output[4..], &[0, 0, 0, 0]);
    u32::from_be_bytes(io.output[..4].try_into().unwrap())
}

/// A stream that reads its input and collects its output separately.
struct ReadThenWrite {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl std::io::Read for ReadThenWrite {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

impl std::io::Write for ReadThenWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `ACT_GET_SIGNALED` reports a started ACT that has not signaled as 0, also for handles that
/// are not implemented ACTs and while the power is off.
#[test]
fn act_get_signaled_reports_unsignaled_acts() {
    let mut sim = tpm2_simulator::create_simulator!();
    assert_eq!(act_get_signaled(&mut sim, 0x4000_0110), 0);
    assert_eq!(act_get_signaled(&mut sim, 0x4000_0111), 0);
    assert_eq!(act_get_signaled(&mut sim, 0x4000_0001), 0);
    sim.signal_platform(SimulatorPlatformSignal::PowerOff, tpm2_simulator::NO_STREAM)
        .unwrap();
    assert_eq!(act_get_signaled(&mut sim, 0x4000_0110), 0);
}

#[test]
fn test_args_pick_ports_dash() {
    use clap::Parser;
    use tpm2_simulator::Args;

    let args = Args::try_parse_from(["tpm2-simulator", "--pick-ports"]).unwrap();
    assert!(args.pick_ports);
}

#[test]
fn test_args_pick_ports_underscore() {
    use clap::Parser;
    use tpm2_simulator::Args;

    let args = Args::try_parse_from(["tpm2-simulator", "--pick_ports"]).unwrap();
    assert!(args.pick_ports);
}

#[test]
fn test_args_pick_ports_short() {
    use clap::Parser;
    use tpm2_simulator::Args;

    let args = Args::try_parse_from(["tpm2-simulator", "-p"]).unwrap();
    assert!(args.pick_ports);
}

#[test]
fn test_args_default() {
    use clap::Parser;
    use tpm2_simulator::Args;

    let args = Args::try_parse_from(["tpm2-simulator"]).unwrap();
    assert!(!args.pick_ports);
}

/// Reference simulators (`reference-rng`): the randomness is fully
/// determined by the modeled reference process's ID and initial real time.
#[cfg(feature = "reference-rng")]
mod reference_simulator {
    use tpm2::Connection;
    use tpm2_simulator::create_reference_simulator;

    /// `TPM2_GetRandom(16)`.
    const GET_RANDOM_16: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0, 16];

    /// `TPM2_ReadClock` (no sessions).
    const READ_CLOCK: [u8; 10] = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x81];

    /// Two `GetRandom(16)` responses of a fresh reference simulator for
    /// `pid` and `realtime_ms`, with `sleep_ms` of virtual time in between.
    fn draws(pid: u32, realtime_ms: u64, sleep_ms: u64) -> (Vec<u8>, Vec<u8>) {
        let mut sim = create_reference_simulator!(pid, realtime_ms);
        let mut rsp = [0u8; 64];
        let first = sim.transact(&GET_RANDOM_16, &mut rsp).unwrap().to_vec();
        assert_eq!(
            &first[6..10],
            &[0, 0, 0, 0],
            "GetRandom failed: {first:02x?}"
        );
        assert!(sim.advance_clock(sleep_ms));
        let second = sim.transact(&GET_RANDOM_16, &mut rsp).unwrap().to_vec();
        (first, second)
    }

    #[test]
    fn same_pid_and_realtime_give_identical_randomness() {
        let a = draws(4242, 123_456_789, 1500);
        assert_eq!(a, draws(4242, 123_456_789, 1500));
        assert_ne!(a.0, a.1, "the DRBG advances");
    }

    #[test]
    fn different_pid_or_realtime_give_different_randomness() {
        let a = draws(4242, 123_456_789, 0);
        assert_ne!(a.0, draws(4243, 123_456_789, 0).0);
        assert_ne!(a.0, draws(4242, 123_457_789, 0).0);
    }

    #[test]
    fn virtual_clock_only_moves_when_advanced() {
        let mut sim = create_reference_simulator!(1, 1_000_000);
        let mut rsp = [0u8; 64];
        let time = |sim: &mut tpm2_simulator::Simulator<'_>, rsp: &mut [u8]| {
            let r = sim.transact(&READ_CLOCK, rsp).unwrap();
            assert_eq!(&r[6..10], &[0, 0, 0, 0]);
            u64::from_be_bytes(r[10..18].try_into().unwrap())
        };
        let t0 = time(&mut sim, &mut rsp);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(time(&mut sim, &mut rsp), t0);
        assert!(sim.advance_clock(2500));
        assert_eq!(time(&mut sim, &mut rsp), t0 + 2500);
    }

    /// `TPM_CC_HierarchyChangeAuth(TPM_RH_OWNER, "auth")` with an empty
    /// password session.
    const CHANGE_OWNER_AUTH: [u8; 33] = [
        0x80, 0x02, 0, 0, 0, 33, 0, 0, 0x01, 0x29, 0x40, 0, 0, 0x01, 0, 0, 0, 9, 0x40, 0, 0, 0x09,
        0, 0, 0x01, 0, 0, 0, 4, b'a', b'u', b't', b'h',
    ];

    /// A reset reference simulator repeats the responses of a new one with
    /// the same seed, whatever happened before the reset (clock, DRBG, NV
    /// state such as the owner authorization), also for another seed.
    #[test]
    fn reset_reference_repeats_a_new_simulator() {
        let mut rsp = [0u8; 64];
        let mut run = |sim: &mut tpm2_simulator::Simulator<'_>| -> Vec<Vec<u8>> {
            [
                &GET_RANDOM_16[..],
                &READ_CLOCK,
                &CHANGE_OWNER_AUTH,
                &GET_RANDOM_16,
            ]
            .iter()
            .map(|cmd| sim.transact(cmd, &mut rsp).unwrap().to_vec())
            .collect()
        };
        let fresh = run(&mut create_reference_simulator!(7, 5_000_000));
        let other = run(&mut create_reference_simulator!(8, 6_000_000));
        let mut sim = create_reference_simulator!(7, 5_000_000);
        for _ in 0..3 {
            assert_eq!(run(&mut sim), fresh);
            assert!(sim.advance_clock(1500));
            sim.reset_reference(7, 5_000_000);
        }
        // The owner authorization is empty again: the change succeeds.
        assert_eq!(&fresh[2][6..10], &[0, 0, 0, 0]);
        assert_eq!(run(&mut sim), fresh);
        sim.reset_reference(8, 6_000_000);
        assert_eq!(run(&mut sim), other);
    }

    /// `TPM2_ACT_SetTimeout(TPM_RH_ACT_0, ...)` with an empty password session, up to the
    /// `startTimeout` parameter (the size field counts it).
    const ACT_0_SET_TIMEOUT: [u8; 27] = [
        0x80, 0x02, 0, 0, 0, 31, 0, 0, 0x01, 0x98, 0x40, 0, 0x01, 0x10, 0, 0, 0, 9, 0x40, 0, 0,
        0x09, 0, 0, 0x01, 0, 0,
    ];

    /// `ACT_GET_SIGNALED` follows the countdown on the virtual clock: the ACT signals at the
    /// first tick after `TPM2_ACT_SetTimeout(1)`, without another command.
    #[test]
    fn act_get_signaled_follows_the_virtual_clock() {
        let mut sim = create_reference_simulator!(3, 2_000_000);
        let mut rsp = [0u8; 64];
        let mut cmd = ACT_0_SET_TIMEOUT.to_vec();
        cmd.extend_from_slice(&1u32.to_be_bytes());
        let r = sim.transact(&cmd, &mut rsp).unwrap();
        assert_eq!(&r[6..10], &[0, 0, 0, 0], "ACT_SetTimeout failed: {r:02x?}");
        assert_eq!(super::act_get_signaled(&mut sim, 0x4000_0110), 0);
        assert!(sim.advance_clock(999));
        assert_eq!(super::act_get_signaled(&mut sim, 0x4000_0110), 0);
        assert!(sim.advance_clock(1));
        assert_eq!(super::act_get_signaled(&mut sim, 0x4000_0110), 1);
    }
}
