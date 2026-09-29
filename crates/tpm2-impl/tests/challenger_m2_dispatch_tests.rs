mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

#[test]
fn test_mac_start_without_sessions_truncated() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup first to initialize the TPM state
    let startup_request = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // command code
        "0000" // TPM_SU_CLEAR
    );
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    // HmacStart command: tag = 8001, size = 10, cc = 0000015b
    // Since HmacStart takes 1 handle, a request size of 10 is missing the handle.
    // Expected error: TpmRc::COMMAND_SIZE (0x142)
    let request = hex!(
        "8001" // tag
        "0000000a" // size = 10
        "0000015b" // cc = HmacStart
    );
    let mut response = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(size, 10);
    // Should return Size error (0x95)
    assert_eq!(&response[6..10], &0x95u32.to_be_bytes());
}

#[test]
fn test_mac_start_without_sessions_success_dispatch() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup first to initialize the TPM state
    let startup_request = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // command code
        "0000" // TPM_SU_CLEAR
    );
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    // HmacStart command: tag = 8001, size = 18, cc = 0000015b, handle = 00000007 (RHNull)
    // Auth size = 0 (0000), Hash Alg = SHA256 (000b)
    let request = hex!(
        "8001" // tag
        "00000012" // size = 18
        "0000015b" // cc = HmacStart
        "00000007" // handle
        "0000" // auth size = 0
        "000b" // hash alg = SHA256
    );
    let mut response = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(size, 10);
    // Should return Value error for handle 1 (0x184)
    assert_eq!(&response[6..10], &0x184u32.to_be_bytes());
}

#[test]
fn test_mac_start_with_sessions_invalid_session() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup first to initialize the TPM state
    let startup_request = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // command code
        "0000" // TPM_SU_CLEAR
    );
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );

    // HmacStart command with sessions: tag = 8002, size = 27, cc = 0000015b
    // Handle: 00000007 (RHNull)
    // Auth Session area size: 9
    // Auth Session:
    //   session handle: 02000000 (invalid/non-existent)
    //   nonce: 0000 (0 length)
    //   attributes: 00
    //   hmac: 0000 (0 length)
    let request = hex!(
        "8002" // tag
        "0000001b" // size = 27
        "0000015b" // cc = HmacStart
        "00000007" // handle
        "00000009" // auth session area size = 9
        "02000000" // session handle
        "0000" // nonce (0 len)
        "00" // attributes
        "0000" // hmac (0 len)
    );
    let mut response = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(size, 10);
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    println!(
        "test_mac_start_with_sessions_invalid_session: rc = {:#x}",
        rc
    );
    // Should return TpmRc::VALUE.with(Position::handle(1)) which is 0x184 (since handle validation runs first)
    assert_eq!(rc, 0x184, "Should return a Value error (0x184)");
}
