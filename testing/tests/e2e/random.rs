//! TPM2_GetRandom and TPM2_StirRandom.

use crate::_common::*;
use tpm2_simulator::create_simulator;

/// GetRandom returns a well-formed response with exactly the requested number of bytes.
///
/// `TPM2_GetRandom` through the regular command interface returns a
/// well-formed response with exactly the requested number of bytes.
#[test]
fn get_random_returns_requested_bytes() {
    let mut sim = create_simulator!();

    let request = hx(concat!(
        "8001",     // tag
        "0000000c", // size
        "0000017B", // command code
        "000c",     // requested random bytes
    ));
    let mut response = [0u8; 256];
    let response = sim.transact(&request, &mut response).unwrap();
    assert_eq!(response.len(), 0x18);
    assert_eq!(
        &response[..12],
        hx(concat!(
            "8001",     // session
            "00000018", // size
            "00000000", // successful response
            "000c",     // 2B size prefix
        ))
    );
}

/// StirRandom with 32 bytes of input succeeds.
#[test]
fn stir_random_accepts_32_bytes() {
    let mut sim = create_simulator!();

    // TPM2_StirRandom request: tag=8001, size=0000002C (44), cc=00000146, inData.size=0020 (32 bytes), 32 bytes data
    let mut stir_request = [0u8; 44];
    stir_request[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    stir_request[2..6].copy_from_slice(&44u32.to_be_bytes());
    stir_request[6..10].copy_from_slice(&0x00000146u32.to_be_bytes());
    stir_request[10..12].copy_from_slice(&32u16.to_be_bytes());
    for (i, byte) in stir_request[12..44].iter_mut().enumerate() {
        *byte = i as u8;
    }

    assert_eq!(raw_rc(&mut sim, &stir_request), 0);
}

/// StirRandom with 129 bytes (over MAX_STIR_RANDOM_SIZE) fails.
#[test]
fn stir_random_oversized_input_rejected() {
    let mut sim = create_simulator!();

    // TPM2_StirRandom request with inData.size = 129 (exceeding MAX_STIR_RANDOM_SIZE = 128)
    let total_size = 10 + 2 + 129;
    let mut stir_request = vec![0u8; total_size];
    stir_request[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    stir_request[2..6].copy_from_slice(&(total_size as u32).to_be_bytes());
    stir_request[6..10].copy_from_slice(&0x00000146u32.to_be_bytes());
    stir_request[10..12].copy_from_slice(&129u16.to_be_bytes());

    let rc = raw_rc(&mut sim, &stir_request);
    assert_ne!(rc, 0);
    // TPM_RC_SIZE (0x95) or TPM_RC_SIZE with parameter 1 (0x1D5) or TPM_RC_VALUE (0x1C4)
    assert!(
        rc == 0x000001D5 || rc == 0x00000095 || rc == 0x000001C4,
        "Unexpected error code: {:#x}",
        rc
    );
}
