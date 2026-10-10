use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::commands::PolicyCpHash;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmSe};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::PolicyCpHash] (`0x16E`) command.
    ///
    /// # Description
    /// This command binds a command parameters hash (`cpHashA`) to the policy session.
    /// It ensures that the policy session can only be used to authorize a command whose parameters
    /// match `cpHashA`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.13 (TPM2_PolicyCpHash).
    ///
    /// # Relationships
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    /// - Fails if the session is already bound to an entity or has a different policy hash or name hash defined.
    pub fn policy_cp_hash(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PolicyCpHash>()?;
        let [policy_session] = handles;
        check(policy_session, Tpmi::ShPolicy, Position::handle(1))?;
        let policy_session = policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<PolicyCpHash>(handles)?;
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

        // A valid cpHash must have the same size as session hash digest size.
        let cp_hash_a = cmd.cp_hash_a.as_slice();
        let digest_size = auth_hash.digest_size();
        if cp_hash_a.len() != digest_size {
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
                || session_state.is_name_hash_defined;

            if is_occupied
                && (!session_state.is_cp_hash_defined
                    || cp_hash_a != &session_state.policy_hash[..session_state.policy_hash_len])
            {
                return Err(TpmRc::CPHASH);
            }
        }

        // 3. Compute new policy digest
        // policyDigest_new = hash(policyDigest_old || TPM_CC_PolicyCpHash || cpHashA)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &(TpmCc::PolicyCpHash.code()).to_be_bytes(),
                cp_hash_a,
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
            session_state.policy_hash[..cp_hash_a.len()].copy_from_slice(cp_hash_a);
            session_state.policy_hash_len = cp_hash_a.len();
            session_state.is_cp_hash_defined = true;
        }

        // 5. Write the response
        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
