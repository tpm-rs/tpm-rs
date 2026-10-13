mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

#[test]
fn test_clear_overflow() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup
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

    // Set clear_count to MAX
    global_state.clear_count = u32::MAX;

    // Clear command: authHandle=0x4000000A (TPM_RH_LOCKOUT), authorized with an empty password
    // session (C `CheckAuthNoSession()` returns TPM_RC_AUTH_MISSING without one).
    let clear_request = hex!(
        "8002" // tag: TPM_ST_SESSIONS
        "0000001b" // size
        "00000126" // TPM_CC_Clear
        "4000000a" // TPM_RH_LOCKOUT
        "00000009" // authorizationSize
        "40000009" // TPM_RS_PW
        "0000" // nonce
        "01" // continueSession
        "0000" // empty password
    );
    let mut clear_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &clear_request[..],
        &mut clear_response[..],
    );

    // Should not panic, should return Success
    assert_eq!(&clear_response[6..10], &[0, 0, 0, 0]);
}
