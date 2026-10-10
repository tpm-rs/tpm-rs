use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{ClockRateAdjust, ClockSet};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
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

        let handles = request.try_unmarshal_handles::<ClockSet>()?;
        let [auth] = handles;
        check(auth, Tpmi::RhProvision, Position::handle(1))?;
        let auth_handle = auth.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.global_state.parsed_auths[..self.global_state.parsed_auths_len]
            .first()
            .cloned();

        self.validate_provision_auth(auth_handle, provided_auth)?;

        let cmd = request.try_unmarshal_command::<ClockSet>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let current_clock = self.get_clock();
        if cmd.new_time < current_clock || cmd.new_time > 0xFFFF_0000_0000_0000 {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        // PORTING: exp truncated this difference with `as i64`; it is now saturated. It only
        // leaves the `i64` range for `newTime > i64::MAX + Time`.
        let new_offset = i128::from(cmd.new_time) - i128::from(self.global_state.tpm_time_ms);
        self.global_state.clock_offset =
            i64::try_from(new_offset).unwrap_or(if new_offset < 0 { i64::MIN } else { i64::MAX });

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

        let handles = request.try_unmarshal_handles::<ClockRateAdjust>()?;
        let [auth] = handles;
        check(auth, Tpmi::RhProvision, Position::handle(1))?;
        let auth_handle = auth.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.global_state.parsed_auths[..self.global_state.parsed_auths_len]
            .first()
            .cloned();

        self.validate_provision_auth(auth_handle, provided_auth)?;

        let cmd = request.try_unmarshal_command::<ClockRateAdjust>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.global_state.clock_rate_adjust = cmd.rate_adjust;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
