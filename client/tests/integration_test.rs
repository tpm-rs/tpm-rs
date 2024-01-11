/// These tests are enabled with the tpm-simulator-tests feature and only run against a TPM
/// simulator. The docker container in this crate builds a simulator binary, or you may provide
/// your own simulator binary by setting the TPM_RS_SIMULATOR env var for `cargo test` on the
/// command line.
///
/// To run locally in the docker container:
///  `cd client && docker compose run simulator_tests``
///
/// These tests must be run with `--test-threads=1`, because they use a single TCP port.

#[cfg(feature = "tpm-simulator-tests")]
mod common;

#[cfg(feature = "tpm-simulator-tests")]
mod simulator_tests {

    use crate::common::tcp_simulator::*;
    use client::{get_manufacturer_id, run_command};
    use tpm2_rs_base::{commands::StartupCmd, constants::TPM2SU};

    const TPM_SIMULATOR_ENV_VAR: &str = "TPM_RS_SIMULATOR";
    fn get_simulator_path() -> String {
        std::env::var(TPM_SIMULATOR_ENV_VAR)
            .expect("Set TPM_RS_SIMULATOR to run tests against a simulator")
    }

    #[test]
    fn test_startup_tpm() {
        let (_sim_lifeline, mut tpm) = run_tpm_simulator(&get_simulator_path()).unwrap();
        let startup = StartupCmd {
            startup_type: TPM2SU::Clear,
        };
        assert!(run_command(&startup, &mut tpm).is_ok());
    }

    // If test_startup_tpm passes, this will not panic.
    fn get_started_tpm() -> (TpmSim, TcpTpm) {
        let (sim_lifeline, mut tpm) = run_tpm_simulator(&get_simulator_path()).unwrap();
        let startup = StartupCmd {
            startup_type: TPM2SU::Clear,
        };
        run_command(&startup, &mut tpm).unwrap();
        (sim_lifeline, tpm)
    }

    #[test]
    fn test_get_manufacturer_id() {
        let (_sim_lifeline, mut tpm) = get_started_tpm();
        assert!(get_manufacturer_id(&mut tpm).is_ok());
    }
}
