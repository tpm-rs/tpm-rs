/// These tests are enabled with the tpm-simulator-tests feature and only run against a TPM
/// simulator. The docker container in this crate builds a simulator binary, or you may provide
/// your own simulator binary by setting the TPM_RS_SIMULATOR env var for `cargo test` on the
/// command line.
///
/// To run locally in the docker container:
///  `cd client && docker compose run simulator_tests`
///
/// These tests must be run with `--test-threads=1`, because they use a single TCP port.

// Separate module to avoid us running these tests under normal `cargo test` runs.
#[cfg(feature = "tpm-simulator-tests")]
mod simulator_tests;
