use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::ClearControl;
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::ClearControl] (`0x127`) command.
    ///
    /// # Description
    /// This command allows owner or platform to enable or disable the execution of [TpmCc::Clear](clear.rs).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 24.5 (TPM2_ClearControl).
    ///
    /// # Relationships
    /// - Authorization can be [Handle::RH_LOCKOUT] (which can only disable Clear) or [Handle::RH_PLATFORM] (which can enable or disable Clear).
    /// - Controls whether [TpmCc::Clear](clear.rs) is allowed to execute.
    pub fn clear_control(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<ClearControl>()?;
        let [auth] = handles;
        check(auth, Tpmi::RhClear, Position::handle(1))?;
        let auth = auth.0;

        if auth != Handle::RH_LOCKOUT.0 && auth != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<ClearControl>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let disable = cmd.disable;

        if auth == Handle::RH_LOCKOUT.0 && !disable {
            return Err(TpmRc::AUTH_FAIL.to_rc());
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        self.global_state.disable_clear = disable;
        Ok(())
    }
}
