#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::errors::TpmRc;

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::commands::ReadClock;
use tpm2::crypto::{CryptoProvider, Rng};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [tpm2::TpmCc::ReadClock] (`0x00000181`) command.
    ///
    /// # Description
    /// This command reads the current TPMS_TIME_INFO structure that contains the current
    /// setting of Time, Clock, resetCount, and restartCount.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.1 (TPM2_ReadClock).
    pub fn read_clock(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        request.try_unmarshal::<()>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal::<ReadClock>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let current_time = self.get_time_info();

        let rsp = responses::ReadClock { current_time };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
