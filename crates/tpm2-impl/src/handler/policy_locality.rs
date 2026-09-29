use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::{PolicyLocality, PolicyLocalityHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmCc, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyLocality] (`0x16F`) command.
    ///
    /// # Description
    /// This command indicates that the authorization will be limited to a specific locality.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.8 (TPM2_PolicyLocality).
    ///
    /// # Relationships
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    /// - Restricts the authorization session so that commands authorized with it will fail if their locality does not match the enabled localities.
    pub fn policy_locality(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<PolicyLocalityHandles>()?;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal::<PolicyLocality>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Validate session expiration
        self.validate_policy_session(policy_session, Position::handle(1))?;

        // Retrieve policy session state details
        let (auth_hash, policy_digest, policy_digest_len, command_locality) = {
            let session_state = self
                .global_state
                .session(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::HANDLE.with(Position::handle(1)));
            }
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
                session_state.command_locality,
            )
        };

        // TCG Part 3 Section 23.8 validation:
        let new_locality = if cmd.locality.is_extended() {
            // For an extended locality (> 31):
            // Validate commandLocality has not previously been set (0) OR equals locality
            if command_locality != 0 && command_locality != cmd.locality.0 {
                return Err(TpmRc::RANGE.with(Position::parameter(1)));
            }
            cmd.locality.0
        } else {
            // When locality is not an extended locality (<= 31):
            // Validate commandLocality is not currently an extended locality value (> 31)
            if command_locality > 31 {
                return Err(TpmRc::RANGE.with(Position::parameter(1)));
            }
            // Disable any locality not SET in the locality parameter
            let updated = if command_locality == 0 {
                cmd.locality.0
            } else {
                command_locality & cmd.locality.0
            };
            if updated == 0 {
                return Err(TpmRc::RANGE.with(Position::parameter(1)));
            }
            updated
        };

        // Compute new policy digest
        // policyDigest_new = hash(policyDigest_old || TPM_CC_PolicyLocality || locality)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &(TpmCc::PolicyLocality.code()).to_be_bytes(),
                &[cmd.locality.0],
            ],
        )?;

        // Update session state
        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            session_state.command_locality = new_locality;
        }

        // Write response
        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
