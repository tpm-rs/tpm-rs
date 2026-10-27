//! Failure mode after a failed algorithm self test (TPM 2.0 Part 1, "Failure Mode"): every
//! command but `TPM2_GetTestResult` and `TPM2_GetCapability` is `TPM_RC_FAILURE` until the next
//! `_TPM_Init`.

mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use tpm2::errors::TpmRc;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

/// Executes `request` and returns the response.
fn execute(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
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
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
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
