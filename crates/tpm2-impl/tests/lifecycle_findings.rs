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
    cmd: &[u8],
) -> u32 {
    let mut rsp = [0u8; 4096];
    let n = tpm.execute_command_separate(cmd, &mut rsp);
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
fn power_on_startup<R: Rng + Sync>(tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, R>) {
    tpm.reset();
    assert_eq!(run(tpm, &plain_command(TPM_CC_STARTUP, &[0, 0])), 0);
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
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();

    tpm.init_storage();
    power_on_startup(&mut tpm);
    power_on_startup(&mut tpm);
    let reset_count = tpm.state.reset_count;
    let total_reset_count = tpm.state.total_reset_count;
    assert!(reset_count >= 2);

    // DictionaryAttackParameters(maxTries = 7, recoveryTime = 0, lockoutRecovery = 55).
    let mut params = Vec::new();
    params.extend_from_slice(&7u32.to_be_bytes());
    params.extend_from_slice(&0u32.to_be_bytes());
    params.extend_from_slice(&55u32.to_be_bytes());
    let cmd = pw_command(TPM_CC_DA_PARAMETERS, &[TPM_RH_LOCKOUT], &params);
    assert_eq!(run(&mut tpm, &cmd), 0);

    // Model a lockoutAuth failure and the disableClear state, persisted by the next
    // ClearControl (which itself must persist disableClear).
    tpm.state.lockout_auth_enabled = false;
    let cmd = pw_command(TPM_CC_CLEAR_CONTROL, &[TPM_RH_PLATFORM], &[1]);
    assert_eq!(run(&mut tpm, &cmd), 0);
    // Shutdown(CLEAR) so that the next boot is orderly.
    assert_eq!(run(&mut tpm, &plain_command(TPM_CC_SHUTDOWN, &[0, 0])), 0);

    // Real reboot: RAM is lost, only NV survives.
    tpm.state = GlobalState::default();
    tpm.reset();
    assert_eq!(tpm.state.max_tries, 7);
    assert_eq!(tpm.state.recovery_time, 0);
    assert_eq!(tpm.state.lockout_recovery, 55);
    assert!(tpm.state.disable_clear, "disableClear not reloaded from NV");
    assert!(
        !tpm.state.lockout_auth_enabled,
        "lockOutAuthEnabled not reloaded from NV (lockoutRecovery bypass)"
    );
    assert_eq!(tpm.state.reset_count, reset_count);
    assert_eq!(tpm.state.total_reset_count, total_reset_count);
    assert_eq!(
        tpm.state.orderly_state, 0x0000,
        "orderly state not reloaded"
    );
    assert!(tpm.state.g_nv_ok);

    // lockoutRecovery != 0, so Startup must not re-enable lockoutAuth.
    assert_eq!(run(&mut tpm, &plain_command(TPM_CC_STARTUP, &[0, 0])), 0);
    assert!(!tpm.state.lockout_auth_enabled);
    assert_eq!(tpm.state.reset_count, reset_count + 1);
}

/// A platform RNG that can be switched into a failing state.
///
/// The switch is shared (`fail`), because the engine borrows the RNG mutably while the test
/// toggles it.
struct FlakyRng<'f> {
    inner: FakeRng,
    fail: &'f AtomicBool,
}

impl Rng for FlakyRng<'_> {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(CryptoError::Internal);
        }
        self.inner.fill_bytes(dest)
    }

    /// Ignores `data`, even in the failing state (like the default `stir_random` of the previous
    /// `Rng` trait).
    fn reseed(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// `TPM2_GetRandom` fails with `TPM_RC_FAILURE` (instead of panicking via `todo!()`) when the
/// platform RNG fails (findings tpm2-getrandom-stirrandom-unmarshal-panic-and-size-bugs and
/// get-random-and-stir-random-parameter-validation-and-failure-mode-bugs).
#[test]
#[cfg_attr(
    feature = "reference-rng",
    ignore = "checks the default random sources; `reference-rng` draws from the reference DRBG"
)]
fn tpm2_getrandom_stirrandom_unmarshal_panic_and_size_bugs() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let fail = AtomicBool::new(false);
    let mut rng = FlakyRng {
        inner: FakeRng::new(),
        fail: &fail,
    };
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.init_storage();
    power_on_startup(&mut tpm);

    let get_random = plain_command(TPM_CC_GET_RANDOM, &16u16.to_be_bytes());
    assert_eq!(run(&mut tpm, &get_random), 0);
    fail.store(true, Ordering::SeqCst);
    assert_eq!(run(&mut tpm, &get_random), 0x101); // TPM_RC_FAILURE
    fail.store(false, Ordering::SeqCst);
    assert_eq!(run(&mut tpm, &get_random), 0);
}

/// Primary Seeds and hierarchy proofs the platform RNG cannot produce at manufacture stay
/// unprovisioned (size 0) and are never used as key material: `TPM2_CreatePrimary` under the
/// owner, endorsement and platform hierarchies then fails with `TPM_RC_FAILURE`, while the
/// null hierarchy (whose seed is drawn at TPM Reset) is unaffected.
#[test]
fn rng_failure_at_manufacture_leaves_seeds_and_proofs_unprovisioned() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let fail = AtomicBool::new(true);
    let mut rng = FlakyRng {
        inner: FakeRng::new(),
        fail: &fail,
    };
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.init_storage();
    for size in [
        tpm.state.ep_seed_size,
        tpm.state.sp_seed_size,
        tpm.state.pp_seed_size,
        tpm.state.ph_proof_size,
        tpm.state.sh_proof_size,
        tpm.state.eh_proof_size,
    ] {
        assert_eq!(size, 0);
    }
    assert_eq!(
        [
            tpm.state.ep_seed,
            tpm.state.sp_seed,
            tpm.state.pp_seed,
            tpm.state.ph_proof,
            tpm.state.sh_proof,
            tpm.state.eh_proof
        ],
        [[0u8; 64]; 6]
    );

    fail.store(false, Ordering::SeqCst);
    power_on_startup(&mut tpm);

    // inSensitive (empty) and a KEYEDHASH HMAC-SHA256 signing template.
    let mut params = Vec::new();
    params.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
    let public = [
        0x00, 0x08, // type: TPM_ALG_KEYEDHASH
        0x00, 0x0B, // nameAlg: SHA256
        0x00, 0x04, 0x00, 0x72, // fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|sign
        0x00, 0x00, // authPolicy
        0x00, 0x05, 0x00, 0x0B, // scheme: HMAC(SHA256)
        0x00, 0x00, // unique
    ];
    params.extend_from_slice(&(public.len() as u16).to_be_bytes());
    params.extend_from_slice(&public);
    params.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // outsideInfo, creationPCR

    const TPM_CC_CREATE_PRIMARY: u32 = 0x131;
    for hierarchy in [0x4000_0001, 0x4000_000B, TPM_RH_PLATFORM] {
        let cmd = pw_command(TPM_CC_CREATE_PRIMARY, &[hierarchy], &params);
        assert_eq!(run(&mut tpm, &cmd), 0x101, "hierarchy {hierarchy:#x}");
    }
    let cmd = pw_command(TPM_CC_CREATE_PRIMARY, &[0x4000_0007], &params);
    assert_ne!(run(&mut tpm, &cmd), 0x101, "null hierarchy");
}
