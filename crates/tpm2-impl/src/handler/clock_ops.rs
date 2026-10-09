use crate::engine::{
    CLOCK_ADJUST_COARSE, CLOCK_ADJUST_FINE, CLOCK_ADJUST_LIMIT, CLOCK_ADJUST_MEDIUM, CLOCK_NOMINAL,
};
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

        // The command needs NV update (`RETURN_IF_NV_IS_NOT_AVAILABLE`, `ClockSet.c`).
        self.return_if_nv_is_not_available()?;

        // `clock_offset` holds `Clock - Time` in two's complement, so every `newTime` up to
        // `0xFFFF_0000_0000_0000` is represented exactly (see `TpmEngine::get_clock`).
        self.global_state.clock_offset =
            cmd.new_time.wrapping_sub(self.global_state.tpm_time_ms) as i64;
        // `TimeClockUpdate(newTime)`: persists the clock and SETs `clockSafe` when an
        // `NV_CLOCK_UPDATE_INTERVAL` boundary is crossed.
        self.context
            .clock_update(self.global_state, current_clock, cmd.new_time);

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
        // `TimeSetAdjustRate` / `_plat__ClockRateAdjust`: "slower" increases and "faster"
        // decreases the cumulative divisor applied to elapsed platform time, clamped to
        // `CLOCK_NOMINAL ± CLOCK_ADJUST_LIMIT`.
        let rate = self.global_state.clock_adjust_rate;
        let rate = match cmd.rate_adjust {
            tpm2::TpmClockAdjust::CoarseSlower => rate.saturating_add(CLOCK_ADJUST_COARSE),
            tpm2::TpmClockAdjust::MediumSlower => rate.saturating_add(CLOCK_ADJUST_MEDIUM),
            tpm2::TpmClockAdjust::FineSlower => rate.saturating_add(CLOCK_ADJUST_FINE),
            tpm2::TpmClockAdjust::FineFaster => rate.saturating_sub(CLOCK_ADJUST_FINE),
            tpm2::TpmClockAdjust::MediumFaster => rate.saturating_sub(CLOCK_ADJUST_MEDIUM),
            tpm2::TpmClockAdjust::CoarseFaster => rate.saturating_sub(CLOCK_ADJUST_COARSE),
            tpm2::TpmClockAdjust::NoChange => rate,
        };
        self.global_state.clock_adjust_rate = rate.clamp(
            CLOCK_NOMINAL - CLOCK_ADJUST_LIMIT,
            CLOCK_NOMINAL + CLOCK_ADJUST_LIMIT,
        );

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
