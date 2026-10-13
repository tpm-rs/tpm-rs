//! White-box clock tests that inspect `GlobalState` and NV storage directly.
//!
//! The black-box clock tests were moved to `testing/src/impl_clock_tests.rs`.

mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;

use tpm2_impl::{TpmEngine, TpmPlatform};

#[test]
fn test_time_epoch_monotonic_persistence_and_resume_preservation() {
    use tpm2_impl::storage::NvStorage;

    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.g_nv_ok = true;

    assert_eq!(global_state.time_epoch, 0);

    // 1. Cold boot TPM Reset -> Startup(CLEAR) increments time_epoch to 1 and persists to NV
    let startup_clear = hex!("8001 0000000c 00000144 0000");
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup_clear[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    assert_eq!(global_state.time_epoch, 1);

    let mut nv_epoch_bytes = [0u8; 8];
    tpm.platform
        .storage
        .read_nv(24, &mut nv_epoch_bytes)
        .unwrap();
    assert_eq!(u64::from_be_bytes(nv_epoch_bytes), 1);

    // 2. Orderly Shutdown(STATE) -> Startup(STATE) (TPM Resume) preserves time_epoch == 1
    let shutdown_state = hex!("8001 0000000c 00000145 0001");
    tpm.execute_command_separate(&mut global_state, &shutdown_state[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);

    global_state.initialized = false;
    let startup_state = hex!("8001 0000000c 00000144 0001");
    tpm.execute_command_separate(&mut global_state, &startup_state[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    assert_eq!(global_state.time_epoch, 1);

    // 3. Unorderly power cycle / TPM Reset -> Startup(CLEAR) increments time_epoch to 2 and persists
    global_state.initialized = false;
    tpm.execute_command_separate(&mut global_state, &startup_clear[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    assert_eq!(global_state.time_epoch, 2);

    tpm.platform
        .storage
        .read_nv(24, &mut nv_epoch_bytes)
        .unwrap();
    assert_eq!(u64::from_be_bytes(nv_epoch_bytes), 2);
}
