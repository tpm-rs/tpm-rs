use crate::Platform;
use crate::{
    handle_checks::{Tpmi, check},
    handler::CommandHandler,
    req_resp::RequestThenResponse,
};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::ContextSave;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmHt};

impl<'b, P: Platform> CommandHandler<'b, P> {
    /// Handles the [TpmCc::ContextSave] (`0x112`) command.
    ///
    /// # Description
    /// This command serializes the volatile state of a transient object or session into an encrypted
    /// and integrity-protected blob, allowing it to be stored off-TPM.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 28.1 (TPM2_ContextSave).
    ///
    /// # Relationships
    /// - Serializes state that can be reloaded into the TPM using [TpmCc::ContextLoad](context_load.rs).
    /// - If the saved entity is a session, it remains active but its slot in volatile memory is freed.
    /// - For transient objects, saving a context does not flush it; a separate call to [TpmCc::FlushContext](flush_context.rs) is needed to remove it from RAM.
    pub fn context_save(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<ContextSave>()?;
        let [save] = handles;
        check(save, Tpmi::DhContext, Position::handle(1))?;
        let save_handle = save.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal_command::<ContextSave>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let is_session = matches!(
            Handle(save_handle).handle_type(),
            Some(TpmHt::HMACSession | TpmHt::PolicySession)
        );
        if !is_session && (save_handle >> 24) != (TpmHt::Transient as u8 as u32) {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }
        if is_session && (save_handle & 0x00FF_FFFF) >= tpm2::TPM2_MAX_ACTIVE_SESSIONS {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }
        if (save_handle >> 24) == (TpmHt::Transient as u8 as u32)
            && save_handle > tpm2::Handle::TRANSIENT_LAST.0
        {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        // `RETURN_IF_ORDERLY` is the first statement of the command action, i.e. it runs only
        // after the handle and parameter checks of the dispatcher.
        self.nv_clear_orderly()?;

        // The context of the TCG reference (`context_format.rs`).
        self.tcg_context_save(request, save_handle, &session_responses[..num_sessions])
    }
}

/// `TPM_PT_MAX_OBJECT_CONTEXT`: the largest object context `TPM2_ContextSave` returns, that of the
/// TCG reference (`SIZE_OF_CONTEXT_OVERHEAD + sizeof(OBJECT)`). TPM 2.0 Part 2, TPM_PT:
/// "TPM_PT_MAX_OBJECT_CONTEXT | PT_FIXED + 33 | the maximum size of an object context that will be
/// returned by TPM2_ContextSave()".
pub(crate) const MAX_OBJECT_CONTEXT_SIZE: usize = super::context_format::MAX_OBJECT_CONTEXT_SIZE;

/// `TPM_PT_MAX_SESSION_CONTEXT`: the size of every session context `TPM2_ContextSave` returns
/// (`SIZE_OF_CONTEXT_OVERHEAD + sizeof(SESSION)`). TPM 2.0 Part 2, TPM_PT:
/// "TPM_PT_MAX_SESSION_CONTEXT | PT_FIXED + 34 | the maximum size of a session context that will
/// be returned by TPM2_ContextSave()".
pub(crate) const MAX_SESSION_CONTEXT_SIZE: usize = super::context_format::MAX_SESSION_CONTEXT_SIZE;
