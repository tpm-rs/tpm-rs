use tpm2::commands::GetRandom;
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

// Original Go test: get_random_test.go - TestGetRandom
#[test]
fn test_get_random() {
    let mut sim = create_simulator!();

    let cmd = GetRandom {
        bytes_requested: 16,
    };

    sim.execute(cmd).expect("GetRandom failed");
}
