use crate::get_started_tpm;
use tpm2_rs_base::commands::GetRandomCmd;
use tpm2_rs_base::constants::TPM2_SHA256_DIGEST_SIZE;
use tpm2_rs_base::TpmtHa;
use tpm2_rs_client::run_command;
use tpm2_rs_unionify::UnionSize;

#[test]
fn test_get_random_duplicate_value_trap() {
    let (_sim_lifeline, mut tpm) = get_started_tpm();

    let command = GetRandomCmd {
        bytes_requested: TPM2_SHA256_DIGEST_SIZE as u16,
    };

    let resp = run_command(&command, &mut tpm).expect("Failed running command.");

    // Lets pull out the actual data as a slice for convenience
    let random_slice = &resp.random_bytes.as_ref();

    assert_eq!(
        random_slice.len(),
        TPM2_SHA256_DIGEST_SIZE as usize,
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
        same_twice_occurrences < (random_slice.len() / 2).into(),
        "More than 50% of the values equals previous value: {random_slice:?}"
    );
}

#[test]
fn test_get_random_large_sizes() {
    let (_sim_lifeline, mut tpm) = get_started_tpm();
    let mut detected_max_size = 0;

    // The first value is used to detect the servers max digest size.
    // The second value is used to confirm that server is still providing that size.
    for i in [0xFFF, 0xFFFF] {
        let command = GetRandomCmd { bytes_requested: i };
        let resp = run_command(&command, &mut tpm).expect("Failed running command.");

        // Lets pull out the actual slice size for convenience
        let random_slice_len = resp.random_bytes.as_ref().len();

        if detected_max_size == 0 {
            // Detect the max size used by the server.
            assert!(
                TpmtHa::UNION_SIZE as usize >= random_slice_len,
                "We received more random data, than client implementation supports {random_slice_len} > {}.",
                TpmtHa::UNION_SIZE
            );

            assert!(
                TPM2_SHA256_DIGEST_SIZE as usize <= random_slice_len,
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
fn test_get_random_small_sizes() {
    let (_sim_lifeline, mut tpm) = get_started_tpm();

    for i in 0..1 {
        let command = GetRandomCmd { bytes_requested: i };

        let resp = run_command(&command, &mut tpm).expect("Failed running command.");

        // Lets pull out the actual slice size for convenience
        let random_slice_len = resp.random_bytes.as_ref().len();

        assert_eq!(
            random_slice_len, i as usize,
            "We should have received {i}, but got {random_slice_len} bytes."
        );
    }
}
