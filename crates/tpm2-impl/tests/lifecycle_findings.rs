//! White-box regression tests for the `lifecycle` findings in command-handlers.toml that cannot
//! be observed through the in-process simulator, because it keeps `GlobalState` in RAM across a
//! simulated power cycle:
//!
//! - state that must be reloaded from NV storage by `_TPM_Init` (a fresh `GlobalState` over the
//!   same NV models a real reboot where RAM is lost), and
//! - a failing platform RNG (`TPM2_GetRandom` must not panic).

mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use std::sync::atomic::{AtomicBool, Ordering};
use tpm2::crypto::{CryptoError, Rng};
use tpm2_impl::{GlobalState, TpmEngine, TpmPlatform};

/// Builds a `TPM_ST_SESSIONS` command authorized with one empty password session per handle.
fn pw_command(cc: u32, handles: &[u32], params: &[u8]) -> Vec<u8> {
    let mut auth = Vec::new();
    for _ in handles {
        auth.extend_from_slice(&0x4000_0009u32.to_be_bytes()); // TPM_RS_PW
        auth.extend_from_slice(&0u16.to_be_bytes()); // nonce
        auth.push(0x01); // continueSession
        auth.extend_from_slice(&0u16.to_be_bytes()); // hmac
    }
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&0x8002u16.to_be_bytes());
    cmd.extend_from_slice(&0u32.to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    for h in handles {
        cmd.extend_from_slice(&h.to_be_bytes());
    }
    cmd.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    cmd.extend_from_slice(&auth);
    cmd.extend_from_slice(params);
    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

/// Builds a `TPM_ST_NO_SESSIONS` command without handles.
fn plain_command(cc: u32, params: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&0x8001u16.to_be_bytes());
    cmd.extend_from_slice(&((10 + params.len()) as u32).to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    cmd.extend_from_slice(params);
    cmd
}

/// Executes `cmd` and returns the response code.
fn run<R: Rng + Sync>(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, R>,
    gs: &mut GlobalState,
    cmd: &[u8],
) -> u32 {
    let mut rsp = [0u8; 4096];
    let n = tpm.execute_command_separate(gs, cmd, &mut rsp);
    assert!(n >= 10);
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

const TPM_CC_STARTUP: u32 = 0x144;
const TPM_CC_SHUTDOWN: u32 = 0x145;
const TPM_CC_CLEAR_CONTROL: u32 = 0x127;
const TPM_CC_DA_PARAMETERS: u32 = 0x13A;
const TPM_CC_GET_RANDOM: u32 = 0x17B;
const TPM_RH_LOCKOUT: u32 = 0x4000_000A;
const TPM_RH_PLATFORM: u32 = 0x4000_000C;

/// Powers on (`_TPM_Init`) with `gs` and runs `TPM2_Startup(CLEAR)`.
fn power_on_startup<R: Rng + Sync>(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, R>,
    gs: &mut GlobalState,
) {
    tpm.reset(gs);
    assert_eq!(run(tpm, gs, &plain_command(TPM_CC_STARTUP, &[0, 0])), 0);
}

/// Persistent data (`gp`) must be reloaded from NV at `_TPM_Init`: DA parameters,
/// `lockOutAuthEnabled`, `disableClear`, `resetCount`, `totalResetCount` and the
/// orderly state (finding tpm2-startup-missing-nv-loads-for-orderly-counters-and-lockout and
/// tpm2-dictionaryattackparameters-omits-nv-persistence-and-resets-failedtries).
#[test]
fn tpm2_startup_missing_nv_loads_for_orderly_counters_and_lockout() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();

    let mut gs = GlobalState::default();
    tpm.init_storage(&mut gs);
    power_on_startup(&mut tpm, &mut gs);
    power_on_startup(&mut tpm, &mut gs);
    let reset_count = gs.reset_count;
    let total_reset_count = gs.total_reset_count;
    assert!(reset_count >= 2);

    // DictionaryAttackParameters(maxTries = 7, recoveryTime = 0, lockoutRecovery = 55).
    let mut params = Vec::new();
    params.extend_from_slice(&7u32.to_be_bytes());
    params.extend_from_slice(&0u32.to_be_bytes());
    params.extend_from_slice(&55u32.to_be_bytes());
    let cmd = pw_command(TPM_CC_DA_PARAMETERS, &[TPM_RH_LOCKOUT], &params);
    assert_eq!(run(&mut tpm, &mut gs, &cmd), 0);

    // Model a lockoutAuth failure and the disableClear state, persisted by the next
    // ClearControl (which itself must persist disableClear).
    gs.lockout_auth_enabled = false;
    let cmd = pw_command(TPM_CC_CLEAR_CONTROL, &[TPM_RH_PLATFORM], &[1]);
    assert_eq!(run(&mut tpm, &mut gs, &cmd), 0);
    // Shutdown(CLEAR) so that the next boot is orderly.
    assert_eq!(
        run(&mut tpm, &mut gs, &plain_command(TPM_CC_SHUTDOWN, &[0, 0])),
        0
    );

    // Real reboot: RAM is lost, only NV survives.
    let mut fresh = GlobalState::default();
    tpm.reset(&mut fresh);
    assert_eq!(fresh.max_tries, 7);
    assert_eq!(fresh.recovery_time, 0);
    assert_eq!(fresh.lockout_recovery, 55);
    assert!(fresh.disable_clear, "disableClear not reloaded from NV");
    assert!(
        !fresh.lockout_auth_enabled,
        "lockOutAuthEnabled not reloaded from NV (lockoutRecovery bypass)"
    );
    assert_eq!(fresh.reset_count, reset_count);
    assert_eq!(fresh.total_reset_count, total_reset_count);
    assert_eq!(fresh.orderly_state, 0x0000, "orderly state not reloaded");
    assert!(fresh.g_nv_ok);

    // lockoutRecovery != 0, so Startup must not re-enable lockoutAuth.
    assert_eq!(
        run(
            &mut tpm,
            &mut fresh,
            &plain_command(TPM_CC_STARTUP, &[0, 0])
        ),
        0
    );
    assert!(!fresh.lockout_auth_enabled);
    assert_eq!(fresh.reset_count, reset_count + 1);
}

/// A platform RNG that can be switched into a failing state.
struct FlakyRng {
    inner: FakeRng,
    fail: AtomicBool,
}

impl Rng for FlakyRng {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(CryptoError::HardwareFailure);
        }
        self.inner.get_random(dest)
    }
}

/// `TPM2_GetRandom` fails with `TPM_RC_FAILURE` (instead of panicking via `todo!()`) when the
/// platform RNG fails (findings tpm2-getrandom-stirrandom-unmarshal-panic-and-size-bugs and
/// get-random-and-stir-random-parameter-validation-and-failure-mode-bugs).
#[test]
fn tpm2_getrandom_stirrandom_unmarshal_panic_and_size_bugs() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FlakyRng {
        inner: FakeRng::new(),
        fail: AtomicBool::new(false),
    };
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut gs = GlobalState::default();
    tpm.init_storage(&mut gs);
    power_on_startup(&mut tpm, &mut gs);

    let get_random = plain_command(TPM_CC_GET_RANDOM, &16u16.to_be_bytes());
    assert_eq!(run(&mut tpm, &mut gs, &get_random), 0);
    rng.fail.store(true, Ordering::SeqCst);
    assert_eq!(run(&mut tpm, &mut gs, &get_random), 0x101); // TPM_RC_FAILURE
    rng.fail.store(false, Ordering::SeqCst);
    assert_eq!(run(&mut tpm, &mut gs, &get_random), 0);
}
