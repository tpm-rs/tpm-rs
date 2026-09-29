use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::{PolicyAuthValue, PolicyAuthValueHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmCc, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyAuthValue] (`0x16B`) command.
    ///
    /// # Description
    /// This command binds the authorization value (authValue) of the authorized object to the policy session.
    /// When the policy session is eventually used to authorize an action, the TPM will check that the client
    /// has supplied a valid authValue (or password) for the entity.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.17 (TPM2_PolicyAuthValue).
    ///
    /// # Relationships
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    /// - It sets the `is_auth_value_needed` flag in the session state.
    pub fn policy_auth_value(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<PolicyAuthValueHandles>()?;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<PolicyAuthValue>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Validate session expiration
        self.validate_policy_session(policy_session, Position::handle(1))?;

        // 1. Retrieve session state details.

        let (auth_hash, policy_digest, policy_digest_len) = {
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
            )
        };

        // 2. Compute new policy digest.
        // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyAuthValue)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &(TpmCc::PolicyAuthValue.code()).to_be_bytes(),
            ],
        )?;

        // 3. Mutate the session state.
        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.to_rc())?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            session_state.is_auth_value_needed = true;
            session_state.is_password_needed = false;
        }

        let response = request.into_response();
        self.write_response_all(response, &(), &(), &session_responses[..num_sessions])?;
        Ok(())
    }
}
