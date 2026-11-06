use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::ReadOnlyControl;
use tpm2::crypto::{Crypto, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::ReadOnlyControl] (`0x1A0`) command.
    ///
    /// # Description
    /// This command enables (`state` = YES) or disables (`state` = NO) the Read-Only mode of
    /// operation of the TPM, with Platform Authorization (see `crate::read_only` for its
    /// effect on the other commands).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, TPM2_ReadOnlyControl; Part 1,
    /// "Read-Only Mode of Operation"; Part 2, TPMA_STARTUP_CLEAR (*readOnly*).
    ///
    /// # Relationships
    /// - The mode is reported by [TpmCc::GetCapability](capability.rs) as
    ///   `TPMA_STARTUP_CLEAR.readOnly` (`TPM_PT_STARTUP_CLEAR`).
    /// - [TpmCc::Startup](startup.rs) for TPM Reset or TPM Restart leaves the mode; TPM Resume
    ///   restores the mode saved by [TpmCc::Shutdown](shutdown.rs)`(TPM_SU_STATE)`.
    pub fn read_only_control(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<ReadOnlyControl>()?;
        let [auth_handle] = handles;
        check(auth_handle, Tpmi::RhPlatform, Position::handle(1))?;
        if auth_handle != Handle::RH_PLATFORM {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<ReadOnlyControl>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // The mode is part of the state-clear data: changing it makes the TPM non-orderly
        // (`RETURN_IF_ORDERLY` before the change, `g_clearOrderly`), while a request for the
        // current mode changes nothing.
        if cmd.state != self.context.state.read_only {
            self.nv_clear_orderly()?;
            self.context.state.read_only = cmd.state;
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
