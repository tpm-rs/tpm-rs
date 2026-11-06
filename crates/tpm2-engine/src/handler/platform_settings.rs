use crate::Platform;
use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{PPCommands, SetAlgorithmSet};
use tpm2::crypto::Crypto;
use tpm2::errors::{Position, TpmRc};

impl<'b, C: Crypto, P: Platform<Crypto = C>> CommandHandler<'b, P> {
    /// Handles the [TpmCc::PPCommands] (`0x12D`) command.
    ///
    /// # Description
    /// TPM 2.0 Part 3, TPM2_PP_Commands: "This command is used to determine which commands
    /// require assertion of Physical Presence (PP) in addition to
    /// *platformAuth*/*platformPolicy*. [...] After this command executes successfully, the
    /// commands listed in *setList* will be added to the list of commands that require that
    /// Physical Presence be asserted when the handle associated with the authorization is
    /// `TPM_RH_PLATFORM`. The commands in *clearList* will no longer require assertion of
    /// Physical Presence in order to authorize a command. If a command is not in either list,
    /// its state is not changed. If a command is in both lists, then it will no longer require
    /// Physical Presence (for example, *setList* is processed first). Only commands with handle
    /// types of `TPMI_RH_PLATFORM`, `TPMI_RH_PROVISION`, `TPMI_RH_CLEAR`, or
    /// `TPMI_RH_HIERARCHY` can be gated with Physical Presence. If any other command is in
    /// either list, it is discarded." `TPM2_PP_Commands()` itself always requires Physical
    /// Presence (checked with its authorization, see [`crate::physical_presence`]) and cannot
    /// be cleared. The list is persistent (`NV_SYNC_PERSISTENT(ppList)`), so the command needs
    /// NV (`TPM_RC_NV_UNAVAILABLE`).
    pub fn pp_commands(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PPCommands>()?;
        let [auth] = handles;
        check(auth, Tpmi::RhPlatform, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<PPCommands>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.return_if_nv_is_not_available()?;

        let mut pp_list = self.context.state.nv.persistent.pp_list;
        for &cc in cmd.set_list.as_slice() {
            pp_list.set(cc);
        }
        for &cc in cmd.clear_list.as_slice() {
            pp_list.clear(cc);
        }
        self.context.state.nv.persistent.pp_list = pp_list;
        self.context.save_platform_settings();

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])
    }

    /// Handles the [TpmCc::SetAlgorithmSet] (`0x13F`) command.
    ///
    /// # Description
    /// TPM 2.0 Part 3, TPM2_SetAlgorithmSet: "This command allows the platform to change the
    /// set of algorithms that are used by the TPM. The *algorithmSet* setting is a
    /// vendor-dependent value." This TPM has a single set of algorithms (its build
    /// configuration): the value is recorded (`gp.algorithmSet`, persistent, reported as
    /// `TPM_PT_ALGORITHM_SET`) and changes no algorithm, so no PCR bank changes and the next
    /// `TPM2_Startup()` is not restricted (as in the TCG reference). The command needs NV
    /// (`TPM_RC_NV_UNAVAILABLE`).
    pub fn set_algorithm_set(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<SetAlgorithmSet>()?;
        let [auth_handle] = handles;
        check(auth_handle, Tpmi::RhPlatform, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<SetAlgorithmSet>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.return_if_nv_is_not_available()?;

        self.context.state.nv.persistent.algorithm_set = cmd.algorithm_set;
        self.context.save_platform_settings();

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])
    }
}
