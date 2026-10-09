use tpm2::commands::{Command, ReadClock};

use tpm2::{Marshal, Unmarshal};
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;

use tpm2_impl::{TpmEngine, TpmPlatform};

#[test]
fn test_read_clock_success() {
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

    tpm.platform.timer.set_time(42);

    // ReadClock request: 8001 (tag) 0000000a (size) 00000181 (command code)
    let read_clock_request = hex!("8001 0000000a 00000181");
    let mut response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &read_clock_request[..],
        &mut response[..],
    );
    assert_eq!(&response[6..10], &[0, 0, 0, 0]);

    let mut resp_slice = &response[10..];
    let rsp = <ReadClock as Command>::Response::unmarshal(&mut resp_slice)
        .expect("unmarshal <ReadClock as Command>::Response");
    assert!(rsp.current_time.clock_info.safe);
    assert_eq!(rsp.current_time.clock_info.clock, 42);
    assert_eq!(rsp.current_time.time, 42);
}

#[test]
fn test_read_clock_after_restart() {
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

    // Initial Startup(CLEAR)
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    assert_eq!(&startup_response[6..10], &[0, 0, 0, 0]);

    // Check initial ReadClock
    tpm.platform.timer.set_time(100);
    let read_clock_request = hex!("8001 0000000a 00000181");
    let mut response1 = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &read_clock_request[..],
        &mut response1[..],
    );
    assert_eq!(&response1[6..10], &[0, 0, 0, 0]);
    let mut resp_slice1 = &response1[10..];
    let rsp1 = <ReadClock as Command>::Response::unmarshal(&mut resp_slice1)
        .expect("unmarshal <ReadClock as Command>::Response");
    let initial_reset = rsp1.current_time.clock_info.reset_count;
    let initial_restart = rsp1.current_time.clock_info.restart_count;

    // Advance clock and simulate Shutdown(CLEAR) + reset/restart + Startup(CLEAR)
    tpm.platform.timer.advance(1000);
    let shutdown_request = hex!("8001 0000000c 00000145 0000");
    let mut shutdown_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &shutdown_request[..],
        &mut shutdown_response[..],
    );
    assert_eq!(&shutdown_response[6..10], &[0, 0, 0, 0]);

    // Simulate power/initialization reset before next startup
    global_state.initialized = false;
    let mut startup_response2 = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response2[..],
    );
    assert_eq!(&startup_response2[6..10], &[0, 0, 0, 0]);

    // ReadClock after restart
    let mut response2 = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &read_clock_request[..],
        &mut response2[..],
    );
    assert_eq!(&response2[6..10], &[0, 0, 0, 0]);
    let mut resp_slice = &response2[10..];
    let rsp2 = <ReadClock as Command>::Response::unmarshal(&mut resp_slice)
        .expect("unmarshal <ReadClock as Command>::Response");

    assert_eq!(rsp2.current_time.clock_info.clock, 1100);
    // Shutdown(CLEAR) + Startup(CLEAR) is a TPM Reset (`Startup.c`): resetCount increments and
    // restartCount is cleared.
    let _ = initial_restart;
    assert_eq!(rsp2.current_time.clock_info.reset_count, initial_reset + 1);
    assert_eq!(rsp2.current_time.clock_info.restart_count, 0);
}

fn send_clock_set(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    auth_handle: u32,
    new_time: u64,
    tag: u16,
) -> u32 {
    let mut req = [0u8; 256];
    let mut offset = 0;
    req[offset..offset + 2].copy_from_slice(&tag.to_be_bytes());
    offset += 2;
    // placeholder size
    offset += 4;
    req[offset..offset + 4].copy_from_slice(&(tpm2::TpmCc::ClockSet.code()).to_be_bytes());
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
        let mut auth_buf = [0u8; tpm2::TpmsAuthCommand::MAX_SIZE];
        let auth_len = auth.marshal(&mut auth_buf);
        req[offset..offset + 4].copy_from_slice(&(auth_len as u32).to_be_bytes());
        offset += 4;
        req[offset..offset + auth_len].copy_from_slice(&auth_buf[..auth_len]);
        offset += auth_len;
    }
    req[offset..offset + 8].copy_from_slice(&new_time.to_be_bytes());
    offset += 8;
    let size = offset as u32;
    req[2..6].copy_from_slice(&size.to_be_bytes());

    let mut resp = [0u8; 256];
    tpm.execute_command_separate(global_state, &req[..offset], &mut resp[..]);
    u32::from_be_bytes(resp[6..10].try_into().unwrap())
}

fn send_clock_rate_adjust(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    auth_handle: u32,
    raw_adjust: i8,
    tag: u16,
) -> u32 {
    let mut req = [0u8; 256];
    let mut offset = 0;
    req[offset..offset + 2].copy_from_slice(&tag.to_be_bytes());
    offset += 2;
    // placeholder size
    offset += 4;
    req[offset..offset + 4].copy_from_slice(&(tpm2::TpmCc::ClockRateAdjust.code()).to_be_bytes());
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
        let mut auth_buf = [0u8; tpm2::TpmsAuthCommand::MAX_SIZE];
        let auth_len = auth.marshal(&mut auth_buf);
        req[offset..offset + 4].copy_from_slice(&(auth_len as u32).to_be_bytes());
        offset += 4;
        req[offset..offset + auth_len].copy_from_slice(&auth_buf[..auth_len]);
        offset += auth_len;
    }
    req[offset] = raw_adjust as u8;
    offset += 1;
    let size = offset as u32;
    req[2..6].copy_from_slice(&size.to_be_bytes());

    let mut resp = [0u8; 256];
    tpm.execute_command_separate(global_state, &req[..offset], &mut resp[..]);
    u32::from_be_bytes(resp[6..10].try_into().unwrap())
}

#[test]
fn test_clock_set_success() {
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

    tpm.platform.timer.set_time(100);

    let rc = send_clock_set(&mut tpm, &mut global_state, 0x40000001, 100 + 1000, 0x8002);
    assert_eq!(rc, 0);

    let read_clock_request = hex!("8001 0000000a 00000181");
    let mut response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &read_clock_request[..],
        &mut response[..],
    );
    assert_eq!(&response[6..10], &[0, 0, 0, 0]);

    let mut resp_slice = &response[10..];
    let rsp = <ReadClock as Command>::Response::unmarshal(&mut resp_slice)
        .expect("unmarshal <ReadClock as Command>::Response");
    assert!(rsp.current_time.clock_info.clock >= 100 + 1000);
}

#[test]
fn test_clock_set_backward_fails() {
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

    tpm.platform.timer.set_time(1000);

    let rc = send_clock_set(&mut tpm, &mut global_state, 0x40000001, 500, 0x8002);
    assert_eq!(rc, 0x000001C4); // TPM_RC_VALUE | TPM_RC_P | TPM_RC_1
}

#[test]
fn test_clock_rate_adjust_modes() {
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

    for mode in -3..=3i8 {
        let rc = send_clock_rate_adjust(&mut tpm, &mut global_state, 0x40000001, mode, 0x8002);
        assert_eq!(rc, 0, "Failed on valid adjustment mode {mode}");
        assert_eq!(i8::from(global_state.clock_rate_adjust), mode);
    }

    let out_of_bounds = [-4i8, 4i8, 127i8];
    for mode in out_of_bounds {
        let rc = send_clock_rate_adjust(&mut tpm, &mut global_state, 0x40000001, mode, 0x8002);
        assert_eq!(
            rc, 0x000001C4,
            "Did not return TPM_RC_VALUE for out of bounds mode {mode}"
        );
    }
}

#[test]
fn test_time_epoch_monotonic_persistence_and_resume_preservation() {
    use tpm2_impl::storage::NvStorage;

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

#[test]
fn test_read_clock_g_time_vs_clock_separation_and_migration_semantics() {
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

    // 1. Initial Startup(CLEAR)
    let startup_clear = hex!("8001 0000000c 00000144 0000");
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup_clear[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);

    // 2. Advance host timer by 200 ms. Both g_time (time) and go.clock (clock) should be 200.
    tpm.platform.timer.advance(200);
    let read_clock_req = hex!("8001 0000000a 00000181");
    tpm.execute_command_separate(&mut global_state, &read_clock_req[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    let mut slice = &resp[10..];
    let rsp1 = <ReadClock as Command>::Response::unmarshal(&mut slice).unwrap();
    assert_eq!(rsp1.current_time.time, 200, "g_time should be 200 ms");
    assert_eq!(
        rsp1.current_time.clock_info.clock, 200,
        "go.clock should be 200 ms"
    );

    // 3. Execute TPM2_ClockSet to set go.clock to 10_000 ms.
    // g_time (TpmsTimeInfo.time) MUST remain 200 ms (unmodified by ClockSet), while go.clock becomes 10_000 ms.
    let rc = send_clock_set(&mut tpm, &mut global_state, 0x40000001, 10_000, 0x8002);
    assert_eq!(rc, 0);

    tpm.execute_command_separate(&mut global_state, &read_clock_req[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    let mut slice = &resp[10..];
    let rsp2 = <ReadClock as Command>::Response::unmarshal(&mut slice).unwrap();
    assert_eq!(
        rsp2.current_time.time, 200,
        "g_time must never be modified by TPM2_ClockSet"
    );
    assert_eq!(
        rsp2.current_time.clock_info.clock, 10_000,
        "go.clock must reflect new ClockSet value"
    );

    // 4. Advance host timer by 300 ms. g_time -> 500 ms, go.clock -> 10_300 ms.
    tpm.platform.timer.advance(300);
    tpm.execute_command_separate(&mut global_state, &read_clock_req[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    let mut slice = &resp[10..];
    let rsp3 = <ReadClock as Command>::Response::unmarshal(&mut slice).unwrap();
    assert_eq!(rsp3.current_time.time, 500);
    assert_eq!(rsp3.current_time.clock_info.clock, 10_300);

    // 5. Simulate live migration / power cycle: Shutdown(STATE) -> Startup(STATE).
    // g_time resets to 0 ms for the new power period, while go.clock preserves 10_300 ms.
    let shutdown_state = hex!("8001 0000000c 00000145 0001");
    tpm.execute_command_separate(&mut global_state, &shutdown_state[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);

    global_state.initialized = false;
    let startup_state = hex!("8001 0000000c 00000144 0001");
    tpm.execute_command_separate(&mut global_state, &startup_state[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);

    tpm.execute_command_separate(&mut global_state, &read_clock_req[..], &mut resp[..]);
    assert_eq!(&resp[6..10], &[0, 0, 0, 0]);
    let mut slice = &resp[10..];
    let rsp4 = <ReadClock as Command>::Response::unmarshal(&mut slice).unwrap();
    assert_eq!(
        rsp4.current_time.time, 0,
        "g_time resets to 0 on power cycle"
    );
    assert_eq!(
        rsp4.current_time.clock_info.clock, 10_300,
        "go.clock preserves orderly clock value across power cycle"
    );
}
