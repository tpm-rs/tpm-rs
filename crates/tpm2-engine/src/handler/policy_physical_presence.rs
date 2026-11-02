use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::PolicyPhysicalPresence;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmCc, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyPhysicalPresence] (`0x187`) command.
    ///
    /// # Description
    /// TPM 2.0 Part 3, TPM2_PolicyPhysicalPresence: "This command indicates that physical
    /// presence will need to be asserted at the time the authorization is performed. If this
    /// command is successful, *policySession*→*isPPRequired* will be SET to indicate that this
    /// check is required when the policy is used for authorization. Additionally,
    /// *policySession*→*policyDigest* is extended with
    /// policyDigest_new ≔ H_policyAlg(policyDigest_old ∥ TPM_CC_PolicyPhysicalPresence)".
    ///
    /// The check itself happens when the session authorizes (`TPM_RC_PP`, see
    /// `TpmEngine::check_policy_auth_session`).
    pub fn policy_physical_presence(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PolicyPhysicalPresence>()?;
        let [policy_session] = handles;
        check(policy_session, Tpmi::ShPolicy, Position::handle(1))?;
        let policy_session = policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal_command::<PolicyPhysicalPresence>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.validate_policy_session(policy_session, Position::handle(1))?;

        let (auth_hash, policy_digest, policy_digest_len) = {
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
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
            )
        };

        // policyDigest_new = H(policyDigest_old || TPM_CC_PolicyPhysicalPresence)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &TpmCc::PolicyPhysicalPresence.code().to_be_bytes(),
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
            session_state.is_pp_required = true;
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])
    }
}
