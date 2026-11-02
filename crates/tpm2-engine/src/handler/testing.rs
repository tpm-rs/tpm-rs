use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Alg;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmlAlg;
use tpm2::commands::{GetTestResult, IncrementalSelfTest, SelfTest, responses};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::SelfTest] command.
    pub fn self_test(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<SelfTest>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal_command::<SelfTest>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // `CryptSelfTest()`: the requested tests complete before the response (no
        // `TPM_RC_TESTING`, TPM 2.0 Part 3, TPM2_SelfTest, option b); a failed test is
        // `TPM_RC_FAILURE` (Failure mode).
        self.context.self_tester().self_test(_cmd.full_test)?;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::IncrementalSelfTest] command.
    pub fn incremental_self_test(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<IncrementalSelfTest>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<IncrementalSelfTest>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // `CryptIncrementalSelfTest`: the whole `toTest` list is validated before any test runs.
        // Every entry must be an implemented algorithm (`g_implementedAlgorithms`, built from the
        // same table as `TPM_CAP_ALGS`); `TPM_ALG_NULL` is never implemented.
        for &alg in cmd.to_test.algorithms() {
            if !is_implemented_algorithm(alg) {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        }

        // `CryptIncrementalSelfTest()`: the requested algorithms are tested before the response
        // (an algorithm that has been tested is not tested again; the implementation tests each
        // requested algorithm completely, e.g. a block cipher in all its untested modes).
        if cmd.to_test.count() > 0 {
            let mut to_test = crate::self_test::AlgorithmVector::default();
            for &alg in cmd.to_test.algorithms() {
                to_test.set(alg.id());
            }
            self.context.self_tester().run_self_tests(&mut to_test)?;
        }
        // The `toDoList`: every algorithm that still needs a test, in ascending order.
        let mut untested = [Alg::NULL; crate::self_test::MAX_ALG_LIST_SIZE];
        let mut count = 0;
        for alg in self.context.self_test.load().iter() {
            if count == untested.len() {
                break;
            }
            untested[count] = Alg::new(alg);
            count += 1;
        }
        let to_do_list = TpmlAlg::from_slice(&untested[..count]).ok_or(TpmRc::FAILURE)?;
        let rsp = responses::IncrementalSelfTest { to_do_list };

        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::GetTestResult] command.
    pub fn get_test_result(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<GetTestResult>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal_command::<GetTestResult>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // TPM 2.0 Part 3, TPM2_GetTestResult: "If TPM2_SelfTest() has not been executed and a
        // testable function has not been tested, testResult will be TPM_RC_NEEDS_TEST. If
        // TPM2_SelfTest() has been received and the tests are not complete, testResult will be
        // TPM_RC_TESTING. If testing of all functions is complete without functional failures,
        // testResult will be TPM_RC_SUCCESS." The tests are synchronous (TPM2_SelfTest completes
        // every test before it returns), so testing is never in progress: an untested algorithm
        // is `TPM_RC_NEEDS_TEST`. (The C references always return `TPM_RC_SUCCESS`, a deviation
        // fixed by `bug-fix-get-test-result-needs-test.patch`.) There is no manufacturer-specific
        // information outside Failure mode, which the engine handles before the command.
        let rsp = responses::GetTestResult {
            test_result: if self.context.self_test.all_tested() {
                Ok(())
            } else {
                Err(TpmRc::NEEDS_TEST)
            },
            ..Default::default()
        };

        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}

/// Returns whether `alg` is implemented by this TPM (`TEST_BIT(alg, g_implementedAlgorithms)`):
/// it is advertised in `TPM_CAP_ALGS`. `TPM_ALG_NULL` is never implemented.
///
/// TPM 2.0 Part 3, TPM2_IncrementalSelfTest, only says "This command causes the TPM to perform a
/// test of the selected algorithms." and "If *toTest* contains an algorithm that has already been
/// tested, it will not be tested again."; it is silent on algorithms the TPM does not implement.
/// Like the TCG reference (`CryptIncrementalSelfTest()`, which checks `toTest` against
/// `g_implementedAlgorithms`, the table behind `TPM_CAP_ALGS`), such an entry is
/// `TPM_RC_VALUE + RC_P1`. (The to-do list's own entries, e.g. `TPM_ALG_ECSCHNORR`, are not
/// implementation evidence: ECSCHNORR is not in `TPM_CAP_ALGS`.)
fn is_implemented_algorithm(alg: Alg) -> bool {
    alg != Alg::NULL && crate::handler::capability::is_implemented_algorithm(alg)
}
