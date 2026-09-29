use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::commands::{PolicyTemplate, PolicyTemplateHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyTemplate] (`0x190`) command.
    ///
    /// # Description
    /// This command allows a policy to be bound to a specific template hash for object creation.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.21 (TPM2_PolicyTemplate).
    pub fn policy_template(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<PolicyTemplateHandles>()?;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<PolicyTemplate>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Validate session expiration
        self.validate_policy_session(policy_session, Position::handle(1))?;

        // 1. Retrieve policy session state details
        let (auth_hash, policy_digest, policy_digest_len, _session_type) = {
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
                session_state.session_type,
            )
        };

        // A valid templateHash must have the same size as session hash digest size.
        let digest_size = auth_hash.digest_size();
        if cmd.template_hash.get_size() as usize != digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        // 2. Occupied Union Check
        {
            let session_state = self
                .global_state
                .session(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            let is_occupied = (session_state.bind_entity != Handle::RH_NULL)
                || session_state.is_cp_hash_defined
                || session_state.is_name_hash_defined
                || session_state.is_template_hash_defined;

            if is_occupied
                && (!session_state.is_template_hash_defined
                    || cmd.template_hash.get_buffer()
                        != &session_state.policy_hash[..session_state.policy_hash_len])
            {
                return Err(TpmRc::CPHASH);
            }
        }

        // 3. Compute new policy digest
        // policyDigest_new = hash(policyDigest_old || TPM_CC_PolicyTemplate || templateHash)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &(TpmCc::PolicyTemplate.code()).to_be_bytes(),
                cmd.template_hash.get_buffer(),
            ],
        )?;

        // 4. Update session state
        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            session_state.policy_hash[..cmd.template_hash.get_size() as usize]
                .copy_from_slice(cmd.template_hash.get_buffer());
            session_state.policy_hash_len = cmd.template_hash.get_size() as usize;
            session_state.is_template_hash_defined = true;
        }

        // 5. Write the response
        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
