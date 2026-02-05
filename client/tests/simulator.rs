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

use tpm2_rs_base::commands::StartupCmd;
use tpm2_rs_base::constants::TpmSu;
use tpm2_rs_client::connection::TcpSimulator;
use tpm2_rs_client::run_command;

// Include the command-specific tests
mod commands;

/// Environment variable used to connect to the TPM simulator over TCP.
const ENV_VAR_SIMULATOR_IP: &str = "SIMULATOR_IP";

/// Default IP address of the TPM simulator program. This value assumes the
/// simulator is running on the same location as the test.
const DEFAULT_SIMULATOR_IP: &str = "127.0.0.1";

/// Get the IP address to connect to the TPM simulator. Set the environment
/// variable at the command line to specify a different IP address, e.g.
///
/// ```shell
/// SIMULATOR_IP="192.168.1.1" cargo test
/// ```
fn get_simulator_ip() -> String {
    std::env::var(ENV_VAR_SIMULATOR_IP).unwrap_or(DEFAULT_SIMULATOR_IP.to_string())
}

/// Environment variable used to override the TPM simulator program.
const ENV_VAR_SIMULATOR_PROGRAM: &str = "SIMULATOR_BIN";

/// Default location of the TPM simulator program. This value assumes we're
/// running in a docker container built by the TPM-provided Dockerfile.
const DEFAULT_SIMULATOR_PROGRAM: &str = "/tpm2-simulator";

/// Get the program to run to launch the TPM simulator. Set the environment
/// variable at the command line to specify a different program to run, e.g.
///
/// ```shell
/// SIMULATOR_BIN="/my/custom/simulator" cargo test
/// ```
fn get_simulator_path() -> String {
    std::env::var(ENV_VAR_SIMULATOR_PROGRAM).unwrap_or(DEFAULT_SIMULATOR_PROGRAM.to_string())
}

/// Environment variable used to override the arguments to the TPM simulator.
const ENV_VAR_SIMULATOR_ARGS: &str = "SIMULATOR_ARGS";

/// Default arguments to pass to the TPM simulator.
const DEFAULT_SIMULATOR_ARGS: &str = "";

/// Get the arguments to pass to the TPM simulator. Set the environment
/// variable at the command line to specify different arguments, e.g.
///
/// ```shell
/// SIMULATOR_ARGS="--custom-arg" cargo test
/// ```
fn get_simulator_args() -> Vec<String> {
    std::env::var(ENV_VAR_SIMULATOR_ARGS)
        .unwrap_or(DEFAULT_SIMULATOR_ARGS.to_string())
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

/// Convenience function to spawn a TPM simulator and establish a TCP connection.
pub fn spawn_simulator_and_connect() -> Result<TcpSimulator> {
    let mut simulator = TcpSimulator::new(
        get_simulator_path(),
        get_simulator_args().as_slice(),
        &get_simulator_ip(),
    )?;
    simulator.connection_mut().reinit()?;

    Ok(simulator)
}

#[test]
fn test_startup_tpm() {
    let mut simulator = spawn_simulator_and_connect().unwrap();
    let startup = StartupCmd {
        startup_type: TpmSu::Clear,
    };
    assert!(run_command(&startup, simulator.connection_mut()).is_ok());
}

// If test_startup_tpm passes, this will not panic.
fn get_started_tpm() -> TcpSimulator {
    let mut simulator = spawn_simulator_and_connect().unwrap();
    let startup = StartupCmd {
        startup_type: TpmSu::Clear,
    };
    run_command(&startup, simulator.connection_mut()).unwrap();
    simulator
}
