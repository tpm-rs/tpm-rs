#![cfg(feature = "tpm-simulator-tests")]

/// These tests are enabled with the tpm-simulator-tests feature and only run against a TPM
/// simulator. The docker container in this crate builds a simulator binary, or you may provide
/// your own simulator binary by setting the TPM_RS_SIMULATOR env var for `cargo test` on the
/// command line.
///
/// To run locally in the docker container:
///  `cd client && docker compose run --rm simulator_tests`
///
/// These tests must be run with `--test-threads=1`, because they use a single TCP port.
use std::io::{Error, ErrorKind, IoSlice, Read, Result, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use tpm2_rs_base::commands::StartupCmd;
use tpm2_rs_base::constants::TpmSu;
use tpm2_rs_base::errors::{TssResult, TssTcsError};
use tpm2_rs_client::run_command;
use tpm2_rs_client::Tpm;
use zerocopy::big_endian::U32;
use zerocopy::AsBytes;

// Include the simulator test module.
mod simulator_tests_registration;

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
    let mut tpm = run_tpm_simulator(&get_simulator_path()).unwrap();
    let startup = StartupCmd {
        startup_type: TpmSu::Clear,
    };
    assert!(run_command(&startup, &mut tpm).is_ok());
}

// If test_startup_tpm passes, this will not panic.
fn get_started_tpm() -> TpmSim {
    let mut tpm = run_tpm_simulator(&get_simulator_path()).unwrap();
    let startup = StartupCmd {
        startup_type: TpmSu::Clear,
    };
    run_command(&startup, &mut tpm).unwrap();
    tpm
}

// Launches the TPM simulator at the given path in a subprocess and powers it up.
pub fn run_tpm_simulator(simulator_bin: &str) -> Result<TpmSim> {
    let mut tpm = TpmSim::new(
        simulator_bin,
        SIMULATOR_IP,
        SIMULATOR_PLAT_PORT,
        SIMULATOR_TPM_PORT,
    )?;
    let mut attempts = 0;
    while let Err(err) = tpm.start_tcp_tpm() {
        if attempts == 3 {
            return Err(err);
        }
        attempts += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Ok(tpm)
}

// Holder that manages the lifetime of the simulator subprocess.
pub struct TpmSim {
    child: Child,
    plat_channel: TcpTpmChannel,
    tpm_channel: TcpTpmChannel,
}

impl TpmSim {
    fn new(simulator_bin: &str, ip: &str, plat_port: u16, tpm_port: u16) -> Result<TpmSim> {
        let child = Command::new(format!(".{simulator_bin}"))
            .current_dir("/")
            .spawn()?;

        let child_guard = ChildGuard(Some(child));

        let plat_channel = TcpTpmChannel::new(ip, plat_port)?;
        let tpm_channel = TcpTpmChannel::new(ip, tpm_port)?;

        let child = child_guard.into_inner();
        Ok(TpmSim {
            child,
            plat_channel,
            tpm_channel,
        })
    }

    // Starts up the TPM simulator with a platform server listening at the give IP/port.
    fn start_tcp_tpm(&mut self) -> Result<()> {
        TpmCommand::SignalNvOff.issue_to_platform(&mut self.plat_channel)?;
        TpmCommand::SignalPowerOff.issue_to_platform(&mut self.plat_channel)?;
        TpmCommand::SignalPowerOn.issue_to_platform(&mut self.plat_channel)?;
        TpmCommand::SignalNvOn.issue_to_platform(&mut self.plat_channel)
    }
}
impl Tpm for TpmSim {
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
            .tpm_channel
            .0
            .write_vectored(&[IoSlice::new(tcp_hdr.as_bytes()), IoSlice::new(command)]);
        if txed.unwrap_or(0) != tcp_hdr.as_bytes().len() + command.len() {
            return Err(TssTcsError::OutOfMemory.into());
        }

        // Response contains a u32 size, the TPM response, and then an always-zero u32 trailer.
        let resp_size = self
            .tpm_channel
            .read_tpm_u32()
            .map_err(|_| TssTcsError::OutOfMemory)?;
        let (response, _) = response
            .split_at_mut_checked(resp_size as usize)
            .ok_or(TssTcsError::OutOfMemory)?;
        self.tpm_channel
            .0
            .read_exact(response)
            .map_err(|_| TssTcsError::OutOfMemory)?;
        if self
            .tpm_channel
            .read_tpm_u32()
            .map_err(|_| TssTcsError::OutOfMemory)?
            != 0
        {
            return Err(TssTcsError::OutOfMemory.into());
        }
        Ok(())
    }
}
impl Drop for TpmSim {
    fn drop(&mut self) {
        if let Err(x) = self.child.kill() {
            eprintln!("Failed to stop simulator: {x}");
        }
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn into_inner(mut self) -> Child {
        self.0.take().expect("Child already dropped")
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if let Err(kill_err) = child.kill() {
                eprintln!(
                    "Failed to kill simulator child process after setup failure: {}",
                    kill_err
                );
            }
            if let Err(wait_err) = child.wait() {
                eprintln!(
                    "Failed to wait for simulator child process after setup failure: {}",
                    wait_err
                );
            }
        }
    }
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
    pub fn issue_to_platform(self, connection: &mut TcpTpmChannel) -> Result<()> {
        connection.0.write_all(U32::from(self as u32).as_bytes())?;
        let rc = connection.read_tpm_u32()?;
        if rc != 0 {
            Err(Error::new(
                ErrorKind::Other,
                format!("Platform command error {}", rc),
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
struct TcpTpmChannel(TcpStream);
impl TcpTpmChannel {
    fn new(ip: &str, tpm_port: u16) -> Result<TcpTpmChannel> {
        let mut last_err = None;
        for _ in 0..4 {
            match TcpStream::connect(format!("{ip}:{tpm_port}")) {
                Ok(stream) => return Ok(TcpTpmChannel(stream)),
                Err(err) => {
                    last_err = Some(err);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
        Err(last_err.unwrap())
    }

    fn read_tpm_u32(&mut self) -> Result<u32> {
        let mut val = U32::ZERO;
        self.0.read_exact(val.as_bytes_mut())?;
        Ok(val.get())
    }
}
