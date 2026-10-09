use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::commands::{PolicyOR, PolicyORHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmCc, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyOR] (`0x15F`) command.
    ///
    /// # Description
    /// This command allows a policy to specify multiple alternative authorization branches (logical OR).
    /// It verifies that the current policy digest is one of the options in `p_hash_list`, resets the digest,
    /// and extends it with the sorted list of digests.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.6 (TPM2_PolicyOR).
    ///
    /// # Relationships
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    /// - Combines multiple distinct policy outcomes (each built from different command paths like [TpmCc::PolicyPCR](policy_pcr.rs)
    ///   or [TpmCc::PolicySigned](policy_signed.rs)) into a single valid authorization step.
    pub fn policy_or(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<PolicyORHandles>()?;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<PolicyOR>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if cmd.p_hash_list.count() < 2 || cmd.p_hash_list.count() > 8 {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        // Validate session expiration
        self.validate_policy_session(policy_session, Position::handle(1))?;

        // 1. Retrieve policy session state details

        let (auth_hash, policy_digest, policy_digest_len, session_type) = {
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

        if session_type != TpmSe::Trial {
            // 2. If POLICY session, check if current policy_digest is in p_hash_list
            let mut found = false;
            let current_digest = &policy_digest[..policy_digest_len];
            for digest in cmd.p_hash_list.digests() {
                if digest.get_buffer() == current_digest {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        }

        // 3. Compute new policy digest
        // policyDigest_new = hash(0_size || TPM_CC_PolicyOR || pHashList)
        let digest_size = auth_hash.digest_size();
        let zero_digest = [0u8; 64];
        let zero_slice = &zero_digest[..digest_size];

        let mut p_hash_list_buf = [0u8; 1024];
        let mut p_hash_list_len = 0;
        for digest in cmd.p_hash_list.digests() {
            let buf = digest.get_buffer();
            if p_hash_list_len + buf.len() > p_hash_list_buf.len() {
                return Err(TpmRc::FAILURE);
            }
            p_hash_list_buf[p_hash_list_len..p_hash_list_len + buf.len()].copy_from_slice(buf);
            p_hash_list_len += buf.len();
        }

        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                zero_slice,
                &(TpmCc::PolicyOR.code()).to_be_bytes(),
                &p_hash_list_buf[..p_hash_list_len],
            ],
        )?;

        // 4. Update the session state
        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
        }

        // 5. Write the response
        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
