use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmHt;
use tpm2::commands::FlushContext;
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
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

        let cmd = request.try_unmarshal_command::<FlushContext>([])?;
        // exp's typed unmarshal rejected handles outside TPMI_DH_CONTEXT before the size check.
        check(cmd.flush_handle, Tpmi::DhContext, Position::parameter(1))?;
        let flush_handle = cmd.flush_handle.0;
        let handle_type = cmd.flush_handle.handle_type();
        let is_transient = handle_type == Some(TpmHt::Transient);
        let is_session = matches!(handle_type, Some(TpmHt::HMACSession | TpmHt::PolicySession));

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
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

#[cfg(test)]
mod tests {
    use crate::owned::OwnedAuth;
    use crate::test_support::{TestEngine, execute, make_test_session_state, with_test_engine};
    use crate::{
        ActiveSequence, GlobalState, MAX_ACTIVE_SESSIONS, MAX_LOADED_OBJECTS, SequenceType,
    };
    use alloc::vec::Vec;
    use tpm2::errors::{Position, TpmRc};
    use tpm2::{Handle, Tpm2bNonce, TpmCc, TpmSe, TpmiAlgHash};

    fn startup(tpm: &mut TestEngine<'_>, gs: &mut GlobalState) {
        assert_eq!(execute(tpm, gs, TpmCc::Startup, &[0, 0]).0, 0);
    }

    fn flush(tpm: &mut TestEngine<'_>, gs: &mut GlobalState, handle: u32) -> u32 {
        let (rc, body) = execute(tpm, gs, TpmCc::FlushContext, &handle.to_be_bytes());
        assert_eq!(body, Vec::new());
        rc
    }

    #[test]
    fn rejects_handles_outside_tpmi_dh_context() {
        let max_transient = 0x8000_0000 + u32::try_from(MAX_LOADED_OBJECTS).unwrap();
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            for handle in [
                0x4000_0001,
                0x0100_0000,
                0x8100_0000,
                // Session and transient indexes this TPM never assigns.
                0x0200_0000 + MAX_ACTIVE_SESSIONS,
                0x0300_0000 + MAX_ACTIVE_SESSIONS,
                max_transient,
            ] {
                assert_eq!(
                    flush(tpm, gs, handle),
                    TpmRc::VALUE.with(Position::parameter(1)).get(),
                    "{handle:#010x}"
                );
            }
        });
    }

    #[test]
    fn range_check_precedes_size_check() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            let (rc, _) = execute(tpm, gs, TpmCc::FlushContext, &[0x40, 0, 0, 1, 0xFF]);
            assert_eq!(rc, TpmRc::VALUE.with(Position::parameter(1)).get());
            let (rc, _) = execute(tpm, gs, TpmCc::FlushContext, &[0x80, 0, 0, 0, 0xFF]);
            assert_eq!(rc, TpmRc::SIZE.to_rc().get());
        });
    }

    #[test]
    fn rejects_unloaded_transient_and_session() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            assert_eq!(flush(tpm, gs, 0x8000_0000), TpmRc::HANDLE.to_rc().get());
            assert_eq!(flush(tpm, gs, 0x0200_0000), TpmRc::HANDLE.to_rc().get());
            assert_eq!(flush(tpm, gs, 0x0300_0000), TpmRc::HANDLE.to_rc().get());
        });
    }

    #[test]
    fn flushes_active_sequence() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            let (index, handle) = gs.find_empty_sequence_slot().unwrap();
            gs.active_sequences[index] = Some(ActiveSequence::new(
                handle,
                OwnedAuth::default(),
                SequenceType::Event,
            ));

            assert_eq!(flush(tpm, gs, handle), 0);
            assert!(gs.find_active_sequence(handle).is_none());
            assert_eq!(flush(tpm, gs, handle), TpmRc::HANDLE.to_rc().get());
        });
    }

    #[test]
    fn flushes_session() {
        const SESSION: u32 = 0x0200_0001;
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            gs.add_session(make_test_session_state(
                SESSION,
                TpmSe::HMAC,
                TpmiAlgHash::Sha256,
                Tpm2bNonce::default(),
                Tpm2bNonce::default(),
                &[],
                None,
                Handle(0x4000_0007),
            ))
            .unwrap();

            assert_eq!(flush(tpm, gs, SESSION), 0);
            assert!(gs.session(SESSION).is_none());
            assert_eq!(flush(tpm, gs, SESSION), TpmRc::HANDLE.to_rc().get());
        });
    }
}
