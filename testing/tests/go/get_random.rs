use testing::tpm::Tpm;
use tpm2::commands::GetRandom;

// Original Go test: get_random_test.go - TestGetRandom
#[test]
fn test_get_random() {
    let mut sim = Tpm::new();

    let cmd = GetRandom {
        bytes_requested: 16,
    };

    sim.execute(cmd).expect("GetRandom failed");
}
