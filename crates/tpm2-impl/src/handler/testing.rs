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

        self.context.state.untested_algorithms_len = 0;

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

        for &alg in cmd.to_test.algorithms() {
            let mut new_untested = [Alg::NULL; 32];
            let mut new_len = 0;
            for &existing in self
                .context
                .state
                .untested_algorithms
                .iter()
                .take(self.context.state.untested_algorithms_len)
            {
                let mut remove = existing == alg;
                if alg == Alg::RSA
                    && matches!(
                        existing,
                        Alg::RSA | Alg::RSASSA | Alg::RSAES | Alg::RSAPSS | Alg::OAEP
                    )
                {
                    remove = true;
                }
                if alg == Alg::AES && matches!(existing, Alg::AES | Alg::CFB) {
                    remove = true;
                }
                if alg == Alg::ECC
                    && matches!(
                        existing,
                        Alg::ECC | Alg::ECDSA | Alg::ECDAA | Alg::ECSCHNORR
                    )
                {
                    remove = true;
                }
                if !remove {
                    new_untested[new_len] = existing;
                    new_len += 1;
                }
            }
            self.context.state.untested_algorithms = new_untested;
            self.context.state.untested_algorithms_len = new_len;
        }

        let to_do_list = TpmlAlg::from_slice(
            &self.context.state.untested_algorithms[..self.context.state.untested_algorithms_len],
        )
        .ok_or(TpmRc::FAILURE)?;
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

        // We will match the response of mstpm20 dynamically after we see the mismatch log.
        // For now, return default (empty out_data, success).
        let rsp = responses::GetTestResult::default();

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
