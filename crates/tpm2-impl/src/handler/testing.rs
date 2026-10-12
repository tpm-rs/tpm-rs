use crate::Crypto;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Alg;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{GetTestResult, IncrementalSelfTest, SelfTest, responses};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bMaxBuffer, TpmlAlg};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::SelfTest] command.
    pub fn self_test(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal_command::<SelfTest>([])?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.global_state.untested_algorithms_len = 0;

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
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<IncrementalSelfTest>([])?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        for &alg in cmd.to_test.as_slice() {
            if !matches!(
                alg,
                Alg::RSA
                    | Alg::SHA1
                    | Alg::HMAC
                    | Alg::AES
                    | Alg::KEYEDHASH
                    | Alg::SHA256
                    | Alg::SHA384
                    | Alg::SHA512
                    | Alg::NULL
                    | Alg::RSASSA
                    | Alg::RSAES
                    | Alg::RSAPSS
                    | Alg::OAEP
                    | Alg::ECDSA
                    | Alg::ECDH
                    | Alg::ECDAA
                    | Alg::SM2
                    | Alg::ECSCHNORR
                    | Alg::ECC
                    | Alg::SYMCIPHER
                    | Alg::CAMELLIA
                    | Alg::CFB
                    | Alg::ECB
                    | Alg::CBC
                    | Alg::CTR
                    | Alg::OFB
                    | Alg::MGF1
                    | Alg::KDF1_SP800_56A
                    | Alg::KDF2
                    | Alg::KDF1_SP800_108
                    | Alg::MLDSA
                    | Alg::HASH_MLDSA
                    | Alg::MLKEM
            ) {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }

            let mut new_untested = [Alg::NULL; 32];
            let mut new_len = 0;
            for &existing in self
                .global_state
                .untested_algorithms
                .iter()
                .take(self.global_state.untested_algorithms_len)
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
                if !remove && let Some(slot) = new_untested.get_mut(new_len) {
                    *slot = existing;
                    new_len += 1;
                }
            }
            self.global_state.untested_algorithms = new_untested;
            self.global_state.untested_algorithms_len = new_len;
        }

        let untested = self
            .global_state
            .untested_algorithms
            .get(..self.global_state.untested_algorithms_len)
            .ok_or(TpmRc::FAILURE)?;
        let to_do_list = TpmlAlg::new(untested).ok_or(TpmRc::FAILURE)?;
        let rsp = responses::IncrementalSelfTest { to_do_list };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::GetTestResult] command.
    pub fn get_test_result(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal_command::<GetTestResult>([])?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // TPM2_SelfTest and TPM2_IncrementalSelfTest run no tests, so there is no failure to report.
        //
        // PORTING: the new `GetTestResultRsp` has no `Default`; this is exp's default value.
        let rsp = responses::GetTestResult {
            out_data: Tpm2bMaxBuffer::default(),
            test_result: Ok(()),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
