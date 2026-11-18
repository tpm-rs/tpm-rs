//! Tests that launch a TPM simulator, so they are ignored by default.
//! See "Simulator Tests" in the top-level README.md for how to run them.

use tpm2::TpmSu;
use tpm2::commands::Startup;
use tpm2_client::run_command;
use tpm2_tcp::TcpSimulator;

// Include the command-specific tests
mod commands;

#[test]
#[ignore = "requires TPM_SIMULATOR_BIN"]
fn test_startup_tpm() {
    get_started_tpm();
}

/// Launches a simulator and sends it `TPM2_Startup(TPM_SU_CLEAR)`.
fn get_started_tpm() -> TcpSimulator {
    let mut simulator = TcpSimulator::launch_from_env().unwrap();
    let startup = Startup {
        startup_type: TpmSu::Clear,
    };
    let mut resp_buffer = [0u8; tpm2_client::protocol::RESP_BUFFER_SIZE];
    run_command(&startup, &mut simulator.connection, &mut resp_buffer).unwrap();
    simulator
}
