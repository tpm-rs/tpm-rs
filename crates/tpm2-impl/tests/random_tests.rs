mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2_impl::{TpmEngine, TpmPlatform};

#[test]
fn test_stir_random_success() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.g_nv_ok = true;

    // Startup(CLEAR)
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    assert_eq!(&startup_response[6..10], &[0, 0, 0, 0]);

    // TPM2_StirRandom request: tag=8001, size=0000002C (44), cc=00000146, inData.size=0020 (32 bytes), 32 bytes data
    let mut stir_request = [0u8; 44];
    stir_request[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    stir_request[2..6].copy_from_slice(&44u32.to_be_bytes());
    stir_request[6..10].copy_from_slice(&0x00000146u32.to_be_bytes());
    stir_request[10..12].copy_from_slice(&32u16.to_be_bytes());
    for (i, byte) in stir_request[12..44].iter_mut().enumerate() {
        *byte = i as u8;
    }

    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &stir_request[..], &mut response[..]);
    assert_eq!(&response[6..10], &[0, 0, 0, 0]);
}

#[test]
fn test_stir_random_size_exceeded() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.g_nv_ok = true;

    // Startup(CLEAR)
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    assert_eq!(&startup_response[6..10], &[0, 0, 0, 0]);

    // TPM2_StirRandom request with inData.size = 129 (exceeding MAX_STIR_RANDOM_SIZE = 128)
    let total_size = 10 + 2 + 129;
    let mut stir_request = vec![0u8; total_size];
    stir_request[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    stir_request[2..6].copy_from_slice(&(total_size as u32).to_be_bytes());
    stir_request[6..10].copy_from_slice(&0x00000146u32.to_be_bytes());
    stir_request[10..12].copy_from_slice(&129u16.to_be_bytes());

    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &stir_request[..], &mut response[..]);
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_ne!(rc, 0);
    // TPM_RC_SIZE (0x95) or TPM_RC_SIZE with parameter 1 (0x1D5) or TPM_RC_VALUE (0x1C4)
    assert!(
        rc == 0x000001D5 || rc == 0x00000095 || rc == 0x000001C4,
        "Unexpected error code: {:#x}",
        rc
    );
}
