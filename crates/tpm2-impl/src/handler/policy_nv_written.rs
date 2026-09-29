use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::commands::{PolicyNvWritten, PolicyNvWrittenHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmCc, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyNvWritten] (`0x18F`) command.
    ///
    /// # Description
    /// This command binds a requirement to the policy session that any NV Index used to authorize the operation
    /// must have its `WRITTEN` attribute set to a specified state (either `YES` or `NO`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.20 (TPM2_PolicyNvWritten).
    ///
    /// # Relationships
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    /// - Affects validation of NV Indices used later in the policy session (such as for NV index authorization).
    pub fn policy_nv_written(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<PolicyNvWrittenHandles>()?;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<PolicyNvWritten>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Validate session expiration
        self.validate_policy_session(policy_session, Position::handle(1))?;

        // 1. Retrieve policy session state details
        let (auth_hash, policy_digest, policy_digest_len, check_nv_written, nv_written_state) = {
            let session_state = self
                .global_state
                .session(policy_session)
                .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::HANDLE.with(Position::handle(1)));
            }
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
                session_state.check_nv_written,
                session_state.nv_written_state,
            )
        };

        // If check_nv_written is already set, verify it doesn't conflict
        if check_nv_written {
            let required_written = cmd.written_set;
            if required_written != nv_written_state {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        }

        // 2. Compute new policy digest
        // policyDigest_new = hash(policyDigest_old || TPM_CC_PolicyNvWritten || writtenSet)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &(TpmCc::PolicyNvWritten.code()).to_be_bytes(),
                &[(cmd.written_set as u8)],
            ],
        )?;

        // 3. Update session state
        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            session_state.check_nv_written = true;
            session_state.nv_written_state = cmd.written_set;
        }

        // 4. Write response
        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
