use common::marshal_to_slice;

mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm() -> TpmEngine<'static, FakeCrypto, FakeStorage, FakeTimer, FakeRng> {
    // Create static references or owned items that match the test common setup
    // We can allocate them on the heap or leak box for tests or follow random_tests structure
    let crypto = FakeCrypto;
    let storage = FakeStorage::default();
    let timer = FakeTimer::new();
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(
        Box::leak(Box::new(crypto)),
        Box::leak(Box::new(storage)),
        Box::leak(Box::new(timer)),
        Box::leak(Box::new(rng)),
    );

    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.init_storage();
    tpm.state.nv_available = true;
    tpm.state.g_nv_ok = true;

    // Startup(CLEAR)
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(&startup_request[..], &mut startup_response[..]);
    assert_eq!(&startup_response[6..10], &[0, 0, 0, 0]);
    tpm
}

fn send_da_lock_reset(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    auth_handle: u32,
    tag: u16,
) -> u32 {
    let mut req = [0u8; 256];
    let mut offset = 0;
    req[offset..offset + 2].copy_from_slice(&tag.to_be_bytes());
    offset += 2;
    // placeholder size
    offset += 4;
    req[offset..offset + 4]
        .copy_from_slice(&(tpm2::TpmCc::DictionaryAttackLockReset.code()).to_be_bytes());
    offset += 4;
    req[offset..offset + 4].copy_from_slice(&auth_handle.to_be_bytes());
    offset += 4;
    if tag == 0x8002 {
        let auth = tpm2::TpmsAuthCommand {
            session_handle: tpm2::Handle::RS_PW,
            nonce: tpm2::Tpm2bNonce::default(),
            session_attributes: tpm2::TpmaSession(1),
            hmac: tpm2::Tpm2bAuth::default(),
        };
        let mut auth_buf = [0u8; 64];
        let auth_len = marshal_to_slice(&auth, &mut auth_buf);
        req[offset..offset + 4].copy_from_slice(&(auth_len as u32).to_be_bytes());
        offset += 4;
        req[offset..offset + auth_len].copy_from_slice(&auth_buf[..auth_len]);
        offset += auth_len;
    }
    let size = offset as u32;
    req[2..6].copy_from_slice(&size.to_be_bytes());

    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&req[..offset], &mut resp[..]);
    u32::from_be_bytes(resp[6..10].try_into().unwrap())
}

fn send_da_parameters(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    auth_handle: u32,
    new_max_tries: u32,
    new_recovery_time: u32,
    lockout_recovery: u32,
    tag: u16,
) -> u32 {
    let mut req = [0u8; 256];
    let mut offset = 0;
    req[offset..offset + 2].copy_from_slice(&tag.to_be_bytes());
    offset += 2;
    // placeholder size
    offset += 4;
    req[offset..offset + 4]
        .copy_from_slice(&(tpm2::TpmCc::DictionaryAttackParameters.code()).to_be_bytes());
    offset += 4;
    req[offset..offset + 4].copy_from_slice(&auth_handle.to_be_bytes());
    offset += 4;
    if tag == 0x8002 {
        let auth = tpm2::TpmsAuthCommand {
            session_handle: tpm2::Handle::RS_PW,
            nonce: tpm2::Tpm2bNonce::default(),
            session_attributes: tpm2::TpmaSession(1),
            hmac: tpm2::Tpm2bAuth::default(),
        };
        let mut auth_buf = [0u8; 64];
        let auth_len = marshal_to_slice(&auth, &mut auth_buf);
        req[offset..offset + 4].copy_from_slice(&(auth_len as u32).to_be_bytes());
        offset += 4;
        req[offset..offset + auth_len].copy_from_slice(&auth_buf[..auth_len]);
        offset += auth_len;
    }
    req[offset..offset + 4].copy_from_slice(&new_max_tries.to_be_bytes());
    offset += 4;
    req[offset..offset + 4].copy_from_slice(&new_recovery_time.to_be_bytes());
    offset += 4;
    req[offset..offset + 4].copy_from_slice(&lockout_recovery.to_be_bytes());
    offset += 4;
    let size = offset as u32;
    req[2..6].copy_from_slice(&size.to_be_bytes());

    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&req[..offset], &mut resp[..]);
    u32::from_be_bytes(resp[6..10].try_into().unwrap())
}

#[test]
fn test_da_self_heal_and_host_migration_monotonic_clock_discontinuity() {
    let mut tpm = setup_tpm();
    tpm.platform.timer.set_time(2_500_000_000); // Simulate Host A with 30 days uptime

    // Configure DA: maxTries=5, recoveryTime=100s, lockoutRecovery=200s
    let rc = send_da_parameters(&mut tpm, 0x4000000A, 5, 100, 200, 0x8002);
    assert_eq!(rc, 0);

    // Simulate 3 failed tries registered at current tpm_time_ms
    tpm.state.failed_tries = 3;
    tpm.state.self_heal_timer = tpm.state.tpm_time_ms as i64;

    // Simulate live migration from Host A (2,500,000,000 ms) to Host B (600,000 ms / 10 min uptime)
    tpm.platform.timer.set_time(600_000);
    tpm.state.last_timer_read_ms = None; // Transient host timer snapshot cleared on restore

    // Execute a command on Host B immediately after migration
    let read_clock_req = hex!("8001 0000000a 00000181");
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&read_clock_req[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);

    // Verify failed_tries did NOT underflow or instantly decay due to host clock discontinuity
    assert_eq!(tpm.state.failed_tries, 3);

    // Advance Host B timer by 100 seconds (1 recovery_time interval)
    tpm.platform.timer.advance(100_000);
    tpm.execute_command_separate(&read_clock_req[..], &mut resp[..]);
    assert_eq!(tpm.state.failed_tries, 2);

    // Advance Host B timer by 200 seconds (2 recovery_time intervals)
    tpm.platform.timer.advance(200_000);
    tpm.execute_command_separate(&read_clock_req[..], &mut resp[..]);
    assert_eq!(tpm.state.failed_tries, 0);
}

#[test]
fn test_lockout_auth_recovery_timer() {
    let mut tpm = setup_tpm();
    tpm.platform.timer.set_time(1_000_000);

    // Set lockoutRecovery = 200 seconds
    let rc = send_da_parameters(&mut tpm, 0x4000000A, 5, 100, 200, 0x8002);
    assert_eq!(rc, 0);

    // Set non-empty lockout_auth
    tpm.state.lockout_auth = tpm2::Tpm2bAuth::from_bytes(b"secret").unwrap().into();

    // Attempt DictionaryAttackLockReset with wrong password (empty auth) on TPM_RH_LOCKOUT
    let rc_fail = send_da_lock_reset(&mut tpm, 0x4000000A, 0x8002);
    assert_eq!(rc_fail, 0x0000098E); // TPM_RC_AUTH_FAIL (session 1)
    assert!(!tpm.state.lockout_auth_enabled);

    // Clear lockout_auth to empty so password matches, but lockout_auth_enabled is still false
    tpm.state.lockout_auth = tpm2::Tpm2bAuth::default().into();
    let rc_locked = send_da_lock_reset(&mut tpm, 0x4000000A, 0x8002);
    assert_eq!(rc_locked, 0x00000921); // TPM_RC_LOCKOUT

    // Advance timer by 200 seconds (lockout_recovery)
    tpm.platform.timer.advance(200_000);
    let rc_recovered = send_da_lock_reset(&mut tpm, 0x4000000A, 0x8002);
    assert_eq!(rc_recovered, 0);
    assert!(tpm.state.lockout_auth_enabled);
}

#[test]
fn test_da_timers_preserved_across_orderly_shutdown_and_startup() {
    let mut tpm = setup_tpm();
    tpm.platform.timer.set_time(10_000);

    // Configure DA: recoveryTime = 100s
    let rc = send_da_parameters(&mut tpm, 0x4000000A, 5, 100, 200, 0x8002);
    assert_eq!(rc, 0);

    tpm.state.failed_tries = 2;
    tpm.state.self_heal_timer = tpm.state.tpm_time_ms as i64;

    // Advance timer by 60 seconds (60% of recoveryTime)
    tpm.platform.timer.advance(60_000);
    let read_clock_req = hex!("8001 0000000a 00000181");
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&read_clock_req[..], &mut resp[..]);
    assert_eq!(tpm.state.failed_tries, 2);

    // Orderly Shutdown(SU_STATE)
    let shutdown_req = hex!("8001 0000000c 00000145 0001");
    tpm.execute_command_separate(&shutdown_req[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);

    // Simulate power cycle (the platform timer is reset) and Startup(SU_STATE)
    tpm.platform_timer_reset();
    tpm.state.initialized = false;
    let startup_req = hex!("8001 0000000c 00000144 0001");
    tpm.execute_command_separate(&startup_req[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);

    // Verify self_heal_timer was adjusted negatively by the 60,000 ms accumulated prior to shutdown
    assert_eq!(tpm.state.self_heal_timer, -60_000);
    assert_eq!(tpm.state.tpm_time_ms, 0);

    // Advance timer by remaining 40 seconds (total 60s + 40s = 100s = 1 recoveryTime)
    tpm.platform.timer.advance(40_000);
    tpm.execute_command_separate(&read_clock_req[..], &mut resp[..]);
    assert_eq!(tpm.state.failed_tries, 1);
}

#[test]
fn test_da_pending_on_nv_deferred_and_flushed_when_nv_becomes_available() {
    use tpm2::platform::NvStorage;
    let mut tpm = setup_tpm();

    // Ensure NV offset 32 (failed_tries) starts at 0
    let mut nv_buf = [0u8; 4];
    tpm.platform.storage.read_nv(32, &mut nv_buf).unwrap();
    assert_eq!(u32::from_be_bytes(nv_buf), 0);

    // Transition to unorderly state (0xFFFF) and make NV temporarily unavailable
    tpm.state.orderly_state = 0xFFFF;
    tpm.state.nv_available = false;

    // Set lockout auth so password verification fails
    tpm.state.lockout_auth = tpm2::Tpm2bAuth::from_bytes(b"secret").unwrap().into();
    let rc_fail = send_da_lock_reset(&mut tpm, 0x4000000A, 0x8002);
    assert_eq!(rc_fail, 0x0000098E); // TPM_RC_AUTH_FAIL (session 1)
    assert!(!tpm.state.lockout_auth_enabled);
    assert!(tpm.state.da_pending_on_nv);

    // Also simulate a non-lockout DA failure (failed_tries increment while NV unavailable)
    tpm.state.failed_tries = 2;

    // Verify NV offset 32 was NOT written while nv_available == false
    tpm.platform.storage.read_nv(32, &mut nv_buf).unwrap();
    assert_eq!(u32::from_be_bytes(nv_buf), 0);

    // Restore NV availability
    tpm.state.nv_available = true;
    tpm.state.lockout_auth_enabled = true;
    tpm.state.lockout_auth = tpm2::Tpm2bAuth::default().into();

    // Trigger check_locked_out (via send_da_parameters with wrong password or any lockout check)
    let rc_check = send_da_parameters(&mut tpm, 0x4000000A, 5, 100, 200, 0x8002);
    assert_eq!(rc_check, 0);

    // Verify da_pending_on_nv was cleared and failed_tries (2) was flushed to NV offset 32
    assert!(!tpm.state.da_pending_on_nv);
    tpm.platform.storage.read_nv(32, &mut nv_buf).unwrap();
    assert_eq!(u32::from_be_bytes(nv_buf), 2);
}
