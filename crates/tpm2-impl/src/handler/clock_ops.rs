use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{ClockRateAdjust, ClockRateAdjustHandles, ClockSet, ClockSetHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [tpm2::TpmCc::ClockSet] (`0x00000128`) command.
    ///
    /// # Description
    /// This command advances the current value of the TPM clock (`TPMS_CLOCK_INFO.clock`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.2 (TPM2_ClockSet).
    pub fn clock_set(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<ClockSetHandles>()?;
        let auth_handle = handles.auth.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.global_state.parsed_auths[..self.global_state.parsed_auths_len]
            .first()
            .cloned();

        self.validate_provision_auth(auth_handle, provided_auth)?;

        let cmd = request.try_unmarshal::<ClockSet>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let current_clock = self.get_clock();
        if cmd.new_time < current_clock || cmd.new_time > 0xFFFF_0000_0000_0000 {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        let new_offset = (cmd.new_time as i128 - self.global_state.tpm_time_ms as i128) as i64;
        self.global_state.clock_offset = new_offset;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [tpm2::TpmCc::ClockRateAdjust] (`0x00000130`) command.
    ///
    /// # Description
    /// This command adjusts the rate of advance of Clock and Time.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 31.3 (TPM2_ClockRateAdjust).
    pub fn clock_rate_adjust(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<ClockRateAdjustHandles>()?;
        let auth_handle = handles.auth.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.global_state.parsed_auths[..self.global_state.parsed_auths_len]
            .first()
            .cloned();

        self.validate_provision_auth(auth_handle, provided_auth)?;

        let cmd = request.try_unmarshal::<ClockRateAdjust>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.global_state.clock_rate_adjust = cmd.rate_adjust;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
