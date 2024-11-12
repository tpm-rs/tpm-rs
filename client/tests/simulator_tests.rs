#![cfg(feature = "tpm-simulator-tests")]

/// These tests are enabled with the tpm-simulator-tests feature and only run against a TPM
/// simulator. The docker container in this crate builds a simulator binary, or you may provide
/// your own simulator binary by setting the TPM_RS_SIMULATOR env var for `cargo test` on the
/// command line.
///
/// To run locally in the docker container:
///  `cd client && docker compose run simulator_tests`
///
/// These tests must be run with `--test-threads=1`, because they use a single TCP port.
use std::io::{Error, ErrorKind, IoSlice, Read, Result, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use tpm2_rs_base::commands::{GetCapabilityCmd, GetRandomCmd, StartupCmd};
use tpm2_rs_base::constants::{TpmCap, TpmPt, TpmSu};
use tpm2_rs_base::errors::{TssResult, TssTcsError};
use tpm2_rs_base::{TpmlTaggedTpmProperty, TpmsCapabilityData, TpmsTaggedProperty};
use tpm2_rs_client::run_command;
use tpm2_rs_client::Tpm;
use zerocopy::big_endian::U32;
use zerocopy::AsBytes;

const SIMULATOR_IP: &str = "127.0.0.1";
// TODO: Either pass ports or get simulator to export ports for multithreaded-use.
const SIMULATOR_TPM_PORT: u16 = 2321;
const SIMULATOR_PLAT_PORT: u16 = 2322;

const TPM_SIMULATOR_ENV_VAR: &str = "TPM_RS_SIMULATOR";
fn get_simulator_path() -> String {
    std::env::var(TPM_SIMULATOR_ENV_VAR)
        .expect("Set TPM_RS_SIMULATOR to run tests against a simulator")
}

#[test]
fn test_startup_tpm() {
    let (_sim_lifeline, mut tpm) = run_tpm_simulator(&get_simulator_path()).unwrap();
    let startup = StartupCmd {
        startup_type: TpmSu::Clear,
    };
    assert!(run_command(&startup, &mut tpm).is_ok());
}

// If test_startup_tpm passes, this will not panic.
fn get_started_tpm() -> (TpmSim, TcpTpm) {
    let (sim_lifeline, mut tpm) = run_tpm_simulator(&get_simulator_path()).unwrap();
    let startup = StartupCmd {
        startup_type: TpmSu::Clear,
    };
    run_command(&startup, &mut tpm).unwrap();
    (sim_lifeline, tpm)
}

#[test]
fn test_get_capability_manufacturer_id() {
    let (_sim_lifeline, mut tpm) = get_started_tpm();

    let mut expected = TpmlTaggedTpmProperty {
        count: 1,
        tpm_property: [TpmsTaggedProperty::default(); 127],
    };

    expected.tpm_property[0] = TpmsTaggedProperty {
        property: TpmPt::Manufacturer,
        value: 0x58595A20,
    };

    let command = GetCapabilityCmd {
        capability: TpmCap::TPMProperties,
        property: TpmPt::Manufacturer,
        property_count: 1,
    };

    // We allow panic in test cases.
    let resp = run_command(&command, &mut tpm).expect("Failed running command.");

    // Extract the TpmlTaggedTpmProperty data form the response.
    let TpmsCapabilityData::TpmProperties(received) = resp.capability_data else {
        panic!("Unexpected variant data.")
    };

    // Confirm we received the expected response.
    assert_eq!(received, expected);
}

#[test]
fn test_get_random() {
    const REQUEST_SIZE: u16 = 32;
    const MIN_RECEIVED: u16 = 32;

    let (_sim_lifeline, mut tpm) = get_started_tpm();

    let command = GetRandomCmd {
        bytes_requested: REQUEST_SIZE,
    };

    // We allow panic in test cases.
    let resp = run_command(&command, &mut tpm).expect("Failed running command.");

    // Validate that retrieved data contains at least 32 values (SHA256 digest),
    // and is less that requested amount.
    assert!(resp.random_bytes.size >= MIN_RECEIVED);
    assert!(resp.random_bytes.size <= REQUEST_SIZE);

    // Lets pull out the actual data as a slice for convenience
    let random_slice = &resp.random_bytes.buffer[0..resp.random_bytes.size as usize];

    // Print for test inspection.
    println!("Got random sequence: {:?}", random_slice);

    // Crude randomness test. Confirm we did not get identical data sequences.
    {
        let mut zeros: u16 = 0;
        let mut count: [u16; 16] = [0; 16]; // 16 slots.
        let mut last_value = random_slice[random_slice.len() - 1];
        let mut i = 0;
        for i in 0..random_slice.len() as usize {
            // Calculate the circular distance modulo 256 going upwards from first value.
            // This will give an even probability distribution of values [0 ; 255].
            let diff: u16 = (256 as u16 + random_slice[i] as u16 - last_value as u16) % 256;
            count[(diff >> 4) as usize] += 1;
            last_value = random_slice[i];
        }

        for i in 0..count.len() as usize {
            if count[i] == 0 {
                zeros += 1;
            }
        }
        println!(
            "Filled circular distance of RND bytes into {} slots: {:?}",
            count.len(),
            count
        );
        println!(
            "After drawing 32 values, allow at most 8 empty slots. Empty slots {}",
            zeros
        );
        assert!(zeros <= 8); // Probability of 8 empty slots after 32 draws is < 0.0003%
    }
}

// Launches the TPM simulator at the given path in a subprocess and powers it up.
pub fn run_tpm_simulator(simulator_bin: &str) -> Result<(TpmSim, TcpTpm)> {
    let sim_lifeline = TpmSim::new(simulator_bin)?;
    let mut attempts = 0;
    while let Err(err) = start_tcp_tpm(SIMULATOR_IP, SIMULATOR_PLAT_PORT) {
        if attempts == 3 {
            return Err(err);
        }
        attempts += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Ok((sim_lifeline, TcpTpm::new(SIMULATOR_IP, SIMULATOR_TPM_PORT)?))
}

// Holder that manages the lifetime of the simulator subprocess.
pub struct TpmSim(Child);
impl TpmSim {
    fn new(simulator_bin: &str) -> Result<TpmSim> {
        Ok(TpmSim(
            Command::new(format!(".{simulator_bin}"))
                .current_dir("/")
                .spawn()?,
        ))
    }
}
impl Drop for TpmSim {
    fn drop(&mut self) {
        if let Err(x) = self.0.kill() {
            println!("Failed to stop simulator: {x}");
        }
    }
}

// Starts up the TPM simulator with a platform server listening at the give IP/port.
fn start_tcp_tpm(ip: &str, plat_port: u16) -> Result<()> {
    let mut connection = TcpStream::connect(format!("{ip}:{plat_port}"))?;
    TpmCommand::SignalNvOff.issue_to_platform(&mut connection)?;
    TpmCommand::SignalPowerOff.issue_to_platform(&mut connection)?;
    TpmCommand::SignalPowerOn.issue_to_platform(&mut connection)?;
    TpmCommand::SignalNvOn.issue_to_platform(&mut connection)
}

#[repr(u32)]
enum TpmCommand {
    SignalPowerOn = 1,
    SignalPowerOff = 2,
    SendCommand = 8,
    SignalNvOn = 11,
    SignalNvOff = 12,
}
impl TpmCommand {
    // Issues a platform TPM command on the given TCP stream.
    pub fn issue_to_platform(self, connection: &mut TcpStream) -> Result<()> {
        connection.write_all(U32::from(self as u32).as_bytes())?;
        let mut rc = U32::ZERO;
        connection.read_exact(rc.as_bytes_mut())?;
        if rc != U32::ZERO {
            Err(Error::new(
                ErrorKind::Other,
                format!("Platform command error {}", rc.get()),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(AsBytes)]
#[repr(C, packed)]
struct TcpTpmHeader {
    tcp_cmd: U32,
    locality: u8,
    cmd_len: U32,
}
// Provides TCP transport for talking to a TPM simulator.
pub struct TcpTpm {
    tpm_conn: TcpStream,
}
impl TcpTpm {
    pub fn new(ip: &str, tpm_port: u16) -> Result<TcpTpm> {
        Ok(TcpTpm {
            tpm_conn: TcpStream::connect(format!("{ip}:{tpm_port}"))?,
        })
    }

    fn read_tpm_u32(&mut self) -> TssResult<u32> {
        let mut val = U32::ZERO;
        self.tpm_conn
            .read_exact(val.as_bytes_mut())
            .map_err(|_| TssTcsError::OutOfMemory)?;
        Ok(val.get())
    }
}

impl Tpm for TcpTpm {
    fn transact(&mut self, command: &[u8], response: &mut [u8]) -> TssResult<()> {
        let cmd_size: u32 = command
            .len()
            .try_into()
            .map_err(|_| TssTcsError::OutOfMemory)?;
        let tcp_hdr = TcpTpmHeader {
            tcp_cmd: U32::new(TpmCommand::SendCommand as u32),
            locality: 0,
            cmd_len: U32::new(cmd_size),
        };
        let txed = self
            .tpm_conn
            .write_vectored(&[IoSlice::new(tcp_hdr.as_bytes()), IoSlice::new(command)]);
        if txed.unwrap_or(0) != tcp_hdr.as_bytes().len() + command.len() {
            return Err(TssTcsError::OutOfMemory.into());
        }

        // Response contains a u32 size, the TPM response, and then an always-zero u32 trailer.
        let resp_size = self.read_tpm_u32()?;
        if resp_size as usize > response.len() {
            return Err(TssTcsError::OutOfMemory.into());
        }
        self.tpm_conn
            .read_exact(&mut response[..resp_size as usize])
            .map_err(|_| TssTcsError::OutOfMemory)?;
        if self.read_tpm_u32()? != 0 {
            return Err(TssTcsError::OutOfMemory.into());
        }
        Ok(())
    }
}
