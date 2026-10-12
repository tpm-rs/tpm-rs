use std::io::Cursor;
use tpm2_impl::storage::ram_storage_mock::RamStorageMock;
use tpm2_platform_linux::{LinuxTimer, PlatformCryptoProvider};
use tpm2_simulator::Simulator;

#[test]
fn test_invalid_platform_signal() {
    let crypto = PlatformCryptoProvider;
    let mut storage = RamStorageMock::<4096>::new();
    let mut timer = LinuxTimer::new();
    let mut sim = Simulator::new(&crypto, &mut storage, &mut timer).unwrap();

    let mut stream = Cursor::new(Vec::new());
    // 99 is invalid platform signal
    let res = sim.handle_platform_command_raw(99, &mut stream);
    assert!(res.is_err());
}

#[test]
fn test_oversized_tpm_command() {
    let crypto = PlatformCryptoProvider;
    let mut storage = RamStorageMock::<4096>::new();
    let mut timer = LinuxTimer::new();
    let mut sim = Simulator::new(&crypto, &mut storage, &mut timer).unwrap();
    sim.power_on_start_up();

    // A command larger than MAX_MESSAGE_SIZE (8192) but within the wire limit returns
    // TPM_RC_COMMAND_SIZE without dropping the connection.
    let mut cmd = vec![0u8; 8193];
    cmd[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    cmd[2..6].copy_from_slice(&8193u32.to_be_bytes());
    cmd[6..10].copy_from_slice(&0x0000_017Bu32.to_be_bytes());
    let mut payload = Vec::new();
    payload.push(0u8); // locality
    payload.extend_from_slice(&8193u32.to_be_bytes());
    payload.extend_from_slice(&cmd);
    let mut stream = Cursor::new(payload);
    assert!(!sim.handle_regular_command_raw(8, &mut stream).unwrap());
    let out = stream.into_inner();
    let resp = tpm2_simulator::SimResponse::parse(&out[5 + 8193..]).unwrap();
    assert_eq!(
        u32::from_be_bytes(resp.response[6..10].try_into().unwrap()),
        tpm2::errors::TpmRc::COMMAND_SIZE.get()
    );

    // Payload length = 65537 (exceeds 64 KiB wire limit)
    let mut payload = Vec::new();
    payload.push(0u8); // locality
    payload.extend_from_slice(&65537u32.to_be_bytes()); // length

    let mut stream = Cursor::new(payload);
    let res = sim.handle_regular_command_raw(8, &mut stream);
    assert!(res.is_err());
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("exceeds maximum of 65536")
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
