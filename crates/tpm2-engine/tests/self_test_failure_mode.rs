//! Failure mode after a failed algorithm self test (TPM 2.0 Part 1, "Failure Mode"): every
//! command but `TPM2_GetTestResult` and `TPM2_GetCapability` is `TPM_RC_FAILURE` until the next
//! `_TPM_Init`.

mod common;

use common::FakePlatform;
use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use tpm2::errors::TpmRc;
use tpm2_engine::TpmEngine;

/// Executes `request` and returns the response.
fn execute(
    tpm: &mut TpmEngine<FakePlatform<'_, FakeCrypto, &'_ mut FakeStorage, FakeTimer>>,
    request: &[u8],
) -> Vec<u8> {
    let mut response = [0u8; 1024];
    let len = tpm.execute_command_separate(request, &mut response);
    response[..len].to_vec()
}

/// The response code of `response`.
fn rc(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[6..10].try_into().unwrap())
}

/// `TPM2_GetTestResult` returns the failure code in Failure mode, other commands fail, and
/// `_TPM_Init` ends Failure mode.
#[test]
fn failed_self_test_enters_failure_mode_until_tpm_init() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let platform = FakePlatform::new(&mut crypto, &mut timer);
    let mut tpm = TpmEngine::new(platform, &mut storage).unwrap();
    tpm.init_storage();
    tpm.reset();
    let startup = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0];
    assert_eq!(rc(&execute(&mut tpm, &startup)), 0);
    let get_test_result = [0x80, 0x01, 0, 0, 0, 0x0a, 0, 0, 0x01, 0x7c];
    // Outside Failure mode: no failure data; nothing has been tested yet.
    let response = execute(&mut tpm, &get_test_result);
    assert_eq!(&response[6..], &[0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x53]);

    tpm.self_test.fail();

    // `TPM2_GetTestResult`: `outData` = failure location (0) and `FATAL_ERROR_SELF_TEST`;
    // `testResult` = `TPM_RC_FAILURE`.
    let response = execute(&mut tpm, &get_test_result);
    assert_eq!(rc(&response), 0);
    assert_eq!(
        &response[10..],
        &[0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 1, 1]
    );
    // ... only without sessions.
    let with_sessions = [
        0x80, 0x02, 0, 0, 0, 0x17, 0, 0, 0x01, 0x7c, 0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 0, 0, 0,
    ];
    assert_eq!(rc(&execute(&mut tpm, &with_sessions)), TpmRc::FAILURE.get());
    // `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1)` works.
    let get_capability = [
        0x80, 0x01, 0, 0, 0, 0x16, 0, 0, 0x01, 0x7a, 0, 0, 0, 6, 0, 0, 0x01, 0x05, 0, 0, 0, 1,
    ];
    assert_eq!(rc(&execute(&mut tpm, &get_capability)), 0);
    // Every other command fails.
    let get_random = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x7b, 0, 8];
    assert_eq!(rc(&execute(&mut tpm, &get_random)), TpmRc::FAILURE.get());

    // `_TPM_Init` ends Failure mode and every algorithm needs its test again.
    tpm.reset();
    assert!(!tpm.self_test.failed());
    assert!(!tpm.self_test.all_tested());
}

/// `TPM2_GetTestResult` in Failure mode reports the failure information of the failure
/// (`_plat__GetFailureLocation()`, high half first, and `_plat__GetFailureCode()`), with
/// `testResult` `TPM_RC_NV_UNINITIALIZED` for `FATAL_ERROR_NV_UNRECOVERABLE` (`TpmFailureMode()`).
/// `_TPM_Init` ends Failure mode but keeps the information, like the references' `s_fail*`.
#[test]
fn failure_information_is_reported_by_get_test_result() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let platform = FakePlatform::new(&mut crypto, &mut timer);
    let mut tpm = TpmEngine::new(platform, &mut storage).unwrap();
    tpm.init_storage();
    tpm.reset();
    let startup = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0];
    assert_eq!(rc(&execute(&mut tpm, &startup)), 0);
    let get_test_result = [0x80, 0x01, 0, 0, 0, 0x0a, 0, 0, 0x01, 0x7c];
    for (code, test_result) in [(8u32, TpmRc::NV_UNINITIALIZED), (5, TpmRc::FAILURE)] {
        tpm.self_test.fail_with(0x0123_4567_89AB_CDEF, code);
        let response = execute(&mut tpm, &get_test_result);
        assert_eq!(rc(&response), 0);
        let mut expected = vec![0, 12];
        expected.extend_from_slice(&0x0123_4567_89AB_CDEFu64.to_be_bytes());
        expected.extend_from_slice(&code.to_be_bytes());
        expected.extend_from_slice(&test_result.get().to_be_bytes());
        assert_eq!(&response[10..], &expected[..]);
    }
    tpm.reset();
    assert!(!tpm.self_test.failed());
    assert_eq!(tpm.self_test.failure(), (0x0123_4567_89AB_CDEF, 5));
}

std::thread_local! {
    /// The calls of the [`LifecycleRng`] hooks of this thread, in order.
    static RNG_CALLS: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
    /// The result of the next [`LifecycleRng`] self tests of this thread.
    static RNG_SELF_TEST_PASSES: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// A TPM random number generator ([`FakeRng`]) that records its lifecycle hooks
/// ([`RNG_CALLS`]) and whose self test passes as [`RNG_SELF_TEST_PASSES`] says.
#[derive(Default)]
struct LifecycleRng(FakeRng);

impl tpm2::crypto::Rng for LifecycleRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), tpm2::crypto::CryptoError> {
        self.0.fill_bytes(dest)
    }

    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), tpm2::crypto::CryptoError> {
        self.0.stir_bytes(data)
    }

    fn init(&mut self) -> Result<(), tpm2::crypto::CryptoError> {
        RNG_CALLS.with_borrow_mut(|calls| calls.push("init"));
        Ok(())
    }

    fn startup(&mut self) -> Result<(), tpm2::crypto::CryptoError> {
        RNG_CALLS.with_borrow_mut(|calls| calls.push("startup"));
        Ok(())
    }

    fn self_test(&mut self) -> Result<bool, tpm2::crypto::CryptoError> {
        RNG_CALLS.with_borrow_mut(|calls| calls.push("self_test"));
        Ok(RNG_SELF_TEST_PASSES.get())
    }
}

/// The fake crypto backend with a [`LifecycleRng`].
struct LifecycleCrypto;

impl_fake_crypto!(common, LifecycleCrypto, LifecycleRng);

/// The TPM's random number generator is (re)initialized and self-tested at manufacture and at
/// every `_TPM_Init` (`CryptInit()`: `_plat__GetEntropy(NULL, 0)`, then `DRBG_SelfTest()`) and
/// started at manufacture and `TPM2_Startup` (`CryptRandStartup()`); a failed DRBG self test
/// puts the TPM into Failure mode until the next `_TPM_Init` whose self test passes.
#[test]
fn tpm_init_runs_the_drbg_self_test() {
    let mut crypto = LifecycleCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let platform = FakePlatform::new(&mut crypto, &mut timer);
    let mut tpm = TpmEngine::new(platform, &mut storage).unwrap();
    RNG_CALLS.with_borrow_mut(Vec::clear);
    RNG_SELF_TEST_PASSES.set(true);
    tpm.init_storage();
    assert_eq!(
        RNG_CALLS.with_borrow_mut(std::mem::take),
        ["init", "self_test", "startup"]
    );

    RNG_SELF_TEST_PASSES.set(false);
    tpm.reset();
    assert_eq!(
        RNG_CALLS.with_borrow_mut(std::mem::take),
        ["init", "self_test"]
    );
    assert!(tpm.self_test.failed());

    RNG_SELF_TEST_PASSES.set(true);
    tpm.reset();
    assert!(!tpm.self_test.failed());
    let startup = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0];
    let mut response = [0u8; 64];
    tpm.execute_command_separate(&startup, &mut response);
    assert_eq!(&response[6..10], &[0, 0, 0, 0]);
    assert_eq!(
        RNG_CALLS.with_borrow_mut(std::mem::take),
        ["init", "self_test", "startup"]
    );
}
