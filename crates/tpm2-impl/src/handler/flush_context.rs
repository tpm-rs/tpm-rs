use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmHt;
use tpm2::commands::FlushContext;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::FlushContext] (`0x165`) command.
    ///
    /// # Description
    /// This command removes a specified transient object, active sequence, or authorization session from the TPM's volatile memory.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 28.4 (TPM2_FlushContext).
    ///
    /// # Relationships
    /// - Used to free up TPM RAM by removing loaded transient objects (loaded via [TpmCc::Load](load.rs) or created via [TpmCc::CreatePrimary](create_primary.rs)).
    /// - Can close sessions created via [TpmCc::StartAuthSession](session.rs).
    /// - Does not affect persistent objects (which are managed via [TpmCc::EvictControl](evict_control.rs)).
    pub fn flush_context(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<FlushContext>()?;
        let flush_handle = cmd.flush_handle.0;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let handle_type = flush_handle >> 24;
        let is_transient = handle_type == (TpmHt::Transient as u8) as u32;
        let is_session = handle_type == (TpmHt::HMACSession as u8) as u32
            || handle_type == (TpmHt::PolicySession as u8) as u32;

        if !is_transient && !is_session {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        let is_valid_transient = is_transient
            && (self
                .global_state
                .find_transient_object(flush_handle)
                .is_some()
                || self
                    .global_state
                    .find_active_sequence(flush_handle)
                    .is_some());

        let is_saved_session = is_session
            && self
                .global_state
                .saved_sessions
                .contains(&Some(flush_handle));

        if is_session && self.global_state.session(flush_handle).is_none() && !is_saved_session {
            return Err(TpmRc::HANDLE.to_rc());
        }
        if is_transient && !is_valid_transient {
            return Err(TpmRc::HANDLE.to_rc());
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        if is_session {
            for slot in self.global_state.saved_sessions.iter_mut() {
                if *slot == Some(flush_handle) {
                    *slot = None;
                }
            }
            if self.global_state.exclusive_audit_session == Some(flush_handle) {
                self.global_state.exclusive_audit_session = None;
            }
            let _ = self.global_state.flush_session(flush_handle);
        } else if is_transient {
            if self
                .global_state
                .find_transient_object(flush_handle)
                .is_some()
            {
                self.global_state.remove_transient_object(flush_handle)?;
            } else {
                self.global_state.remove_active_sequence(flush_handle)?;
            }
        }
        Ok(())
    }
}
