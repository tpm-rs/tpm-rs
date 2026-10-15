use std::io::Cursor;
use tpm2_impl::storage::ram_storage_mock::RamStorageMock;
use tpm2_platform_linux::{LinuxRng, LinuxTimer, PlatformCryptoProvider};
use tpm2_simulator::{PlatformConnection, Simulator, SimulatorPlatformSignal};

#[test]
fn test_invalid_platform_signal() {
    let mut crypto = PlatformCryptoProvider;
    let mut storage = RamStorageMock::<4096>::new();
    let mut timer = LinuxTimer::new();
    let mut rng = LinuxRng::new();
    let _sim = Simulator::new(&mut crypto, &mut storage, &mut timer, &mut rng).unwrap();

    // 99 is not a platform signal code.
    assert!(SimulatorPlatformSignal::try_from(99).is_err());
}

#[test]
fn test_oversized_tpm_command() {
    let mut crypto = PlatformCryptoProvider;
    let mut storage = RamStorageMock::<4096>::new();
    let mut timer = LinuxTimer::new();
    let mut rng = LinuxRng::new();
    let mut sim = Simulator::new(&mut crypto, &mut storage, &mut timer, &mut rng).unwrap();

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
}
