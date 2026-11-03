use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::PolicyParameters;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmCc, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyParameters] (`0x19C`) command.
    ///
    /// # Description
    /// TPM 2.0 Part 3, TPM2_PolicyParameters: "This command is used to allow a policy to be
    /// bound to a specific command and command parameters, but not specific objects." Only one
    /// of a bound session, `TPM2_PolicyCpHash()`, `TPM2_PolicyNameHash()`,
    /// `TPM2_PolicyParameters()` and `TPM2_PolicyTemplate()` can be used for a policy session:
    /// "If *policySession*→*cpHash* is already set, the TPM shall return `TPM_RC_CPHASH`. If
    /// the size of *pHash* is not the size of *policySession*→*policyDigest*, the TPM shall
    /// return `TPM_RC_SIZE`. Otherwise, *policySession*→*cpHash* is set to *pHash*", and
    /// policyDigest_new ≔ H_policyAlg(policyDigest_old ∥ TPM_CC_PolicyParameters ∥ pHash).
    ///
    /// As in `TPM2_PolicyNameHash` (and the TCG reference), the size is checked first. Unlike
    /// `TPM2_PolicyCpHash`, a repeat of the same value is also `TPM_RC_CPHASH` (the spec
    /// allows none). The pHash, H(commandCode ∥ parameters), is compared when the session
    /// authorizes (see `TpmEngine::check_policy_auth_session`).
    pub fn policy_parameters(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PolicyParameters>()?;
        let [policy_session] = handles;
        check(policy_session, Tpmi::ShPolicy, Position::handle(1))?;
        let policy_session = policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<PolicyParameters>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.validate_policy_session(policy_session, Position::handle(1))?;

        let (auth_hash, policy_digest, policy_digest_len, is_occupied) = {
            let session_state = self
                .context
                .state
                .session(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::HANDLE.with(Position::handle(1)));
            }
            // C `IsCpHashUnionOccupied` (policy sessions are never bound).
            let is_occupied = session_state.is_cp_hash_defined
                || session_state.is_name_hash_defined()
                || session_state.is_parameters_hash_defined
                || session_state.is_template_hash_defined;
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
                is_occupied,
            )
        };

        let p_hash = cmd.p_hash.get_buffer();
        if p_hash.len() != auth_hash.digest_size() {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        if is_occupied {
            return Err(TpmRc::CPHASH);
        }

        // policyDigest_new = H(policyDigest_old || TPM_CC_PolicyParameters || pHash)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &TpmCc::PolicyParameters.code().to_be_bytes(),
                p_hash,
            ],
        )?;

        {
            let session_state = self
                .context
                .state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            session_state.policy_hash[..p_hash.len()].copy_from_slice(p_hash);
            session_state.policy_hash_len = p_hash.len();
            session_state.is_parameters_hash_defined = true;
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])
    }
}
