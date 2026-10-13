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
