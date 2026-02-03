/// These tests are not enabled by default and only run against a TPM simulator.
/// The docker container in this crate builds a simulator binary, or you may provide
/// your own simulator binary by setting the TPM_RS_SIMULATOR env var for `cargo test` on the
/// command line.
///
/// To run locally in the docker container:
///  `cd client && docker compose run simulator_tests`
///
/// These tests must be run with `--test-threads=1`, because they use a single TCP port.
use std::io::Result;
use std::process::{Child, Command};
use tpm2_rs_base::commands::StartupCmd;
use tpm2_rs_base::constants::TpmSu;
use tpm2_rs_client::connection::SimulatorPlatformSignal;
use tpm2_rs_client::connection::TcpConnection;
use tpm2_rs_client::run_command;

// Include the command-specific tests
mod commands;

const SIMULATOR_IP: &str = "127.0.0.1";
const TPM_SIMULATOR_ENV_VAR: &str = "TPM_RS_SIMULATOR";

fn get_simulator_path() -> String {
    std::env::var(TPM_SIMULATOR_ENV_VAR)
        .expect("Set TPM_RS_SIMULATOR to run tests against a simulator")
}

#[test]
fn test_startup_tpm() {
    let (_sim_lifeline, mut conn) = run_tpm_simulator(&get_simulator_path()).unwrap();
    let startup = StartupCmd {
        startup_type: TpmSu::Clear,
    };
    assert!(run_command(&startup, &mut conn).is_ok());
}

// If test_startup_tpm passes, this will not panic.
fn get_started_tpm() -> (TpmSim, TcpConnection) {
    let (sim_lifeline, mut conn) = run_tpm_simulator(&get_simulator_path()).unwrap();
    let startup = StartupCmd {
        startup_type: TpmSu::Clear,
    };
    run_command(&startup, &mut conn).unwrap();
    (sim_lifeline, conn)
}

// Launches the TPM simulator at the given path in a subprocess and powers it up.
pub fn run_tpm_simulator(simulator_bin: &str) -> Result<(TpmSim, TcpConnection)> {
    let sim_lifeline = TpmSim::new(simulator_bin)?;
    let mut attempts = 0;

    let mut conn = loop {
        attempts += 1;
        match TcpConnection::new_default(SIMULATOR_IP) {
            Ok(conn) => break conn,
            Err(err) => {
                if attempts > 3 {
                    return Err(err);
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    };

    initialize_tpm_simulator(&mut conn)?;

    Ok((sim_lifeline, conn))
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

// Issues the commands to initialize the TPM simulator.
fn initialize_tpm_simulator(conn: &mut TcpConnection) -> Result<()> {
    conn.platform_signal(SimulatorPlatformSignal::NvOff)?;
    conn.platform_signal(SimulatorPlatformSignal::PowerOff)?;
    conn.platform_signal(SimulatorPlatformSignal::PowerOn)?;
    conn.platform_signal(SimulatorPlatformSignal::NvOn)
}
