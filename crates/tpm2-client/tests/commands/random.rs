use crate::get_started_tpm;
use tpm2::commands::GetRandom;
use tpm2::{Tpm2bDigest, TpmiAlgHash};
use tpm2_client::run_command;

#[test]
#[ignore = "requires running TPM simulator"]
fn test_get_random_duplicate_value_trap() {
    let mut tpm = get_started_tpm();

    let command = GetRandom {
        bytes_requested: TpmiAlgHash::Sha256.digest_size() as u16,
    };

    let mut resp_buffer = [0u8; tpm2_client::protocol::RESP_BUFFER_SIZE];
    let resp = run_command(&command, tpm.connection_mut(), &mut resp_buffer)
        .expect("Failed running command.");

    // Lets pull out the actual data as a slice for convenience
    let random_slice = &resp.random_bytes.as_ref();

    assert_eq!(
        random_slice.len(),
        TpmiAlgHash::Sha256.digest_size(),
        "We should have received exactly size of SHA256 bytes, but got {}.",
        random_slice.len()
    );

    // Duplicate value trap, to catch any same value sequences.
    let same_twice_occurrences = random_slice
        .iter()
        .zip(random_slice.iter().skip(1))
        .filter(|(prev, curr)| prev == curr)
        .count();

    assert!(
        same_twice_occurrences < (random_slice.len() / 2),
        "More than 50% of the values equals previous value: {random_slice:?}"
    );
}

#[test]
#[ignore = "requires running TPM simulator"]
fn test_get_random_large_sizes() {
    let mut tpm = get_started_tpm();
    let mut detected_max_size = 0;

    // The first value is used to detect the servers max digest size.
    // The second value is used to confirm that server is still providing that size.
    for i in [0xFFF, 0xFFFF] {
        let command = GetRandom { bytes_requested: i };
        let mut resp_buffer = [0u8; tpm2_client::protocol::RESP_BUFFER_SIZE];
        let resp = run_command(&command, tpm.connection_mut(), &mut resp_buffer)
            .expect("Failed running command.");

        // Lets pull out the actual slice size for convenience
        let random_slice_len = resp.random_bytes.as_ref().len();

        if detected_max_size == 0 {
            // Detect the max size used by the server.
            assert!(
                Tpm2bDigest::CAP >= random_slice_len,
                "We received more random data, than client implementation supports {random_slice_len} > {}.",
                Tpm2bDigest::CAP
            );

            assert!(
                TpmiAlgHash::Sha256.digest_size() <= random_slice_len,
                "We should have received at least size of SHA256 bytes, but got {random_slice_len}."
            );

            detected_max_size = random_slice_len;
        } else {
            assert_eq!(
                detected_max_size, random_slice_len,
                "We should have received max size {detected_max_size}, but got {random_slice_len}.",
            );
        }
    }
}

#[test]
#[ignore = "requires running TPM simulator"]
fn test_get_random_small_sizes() {
    let mut tpm = get_started_tpm();

    for i in 0..1 {
        let command = GetRandom { bytes_requested: i };

        let mut resp_buffer = [0u8; tpm2_client::protocol::RESP_BUFFER_SIZE];
        let resp = run_command(&command, tpm.connection_mut(), &mut resp_buffer)
            .expect("Failed running command.");

        // Lets pull out the actual slice size for convenience
        let random_slice_len = resp.random_bytes.as_ref().len();

        assert_eq!(
            random_slice_len, i as usize,
            "We should have received {i}, but got {random_slice_len} bytes."
        );
    }
}
