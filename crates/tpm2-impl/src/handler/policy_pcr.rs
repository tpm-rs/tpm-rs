use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::TpmiAlgHash;
use tpm2::commands::{PolicyPCR, PolicyPCRHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Marshal, Unmarshal};
use tpm2::{TpmCc, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyPCR] (`0x17F`) command.
    ///
    /// # Description
    /// This command makes a policy conditional on the current values of selected Platform Configuration Registers (PCRs).
    /// It verifies that the selected PCR bank/indices match the expected `pcr_digest` and extends the policy session's digest.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.7 (TPM2_PolicyPCR).
    ///
    /// # Relationships
    /// - Evaluates PCRs whose values are modified by [TpmCc::PCRExtend](pcr.rs)
    ///   or [TpmCc::PCREvent](pcr.rs).
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    /// - For non-trial sessions, it locks the PCR state using the PCR update counter; if the PCRs are modified afterwards, authorization will fail.
    pub fn policy_pcr(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<PolicyPCRHandles>()?;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = match request.try_unmarshal::<PolicyPCR>() {
            Ok(cmd) => cmd,
            Err(e) => {
                let mut slice = request.remaining_slice();
                if let Ok(_pcr_digest) = tpm2::Tpm2bDigest::unmarshal(&mut slice)
                    && slice.len() >= 4
                {
                    let count = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
                    if count > 0 && slice.len() >= 6 {
                        let hash_raw = u16::from_be_bytes([slice[4], slice[5]]);
                        if TpmiAlgHash::try_from(hash_raw).is_err() {
                            // `pcrs` is parameter 2 (parameter 1 is `pcrDigest`).
                            return Err(TpmRc::HASH.with(Position::parameter(2)));
                        }
                    }
                }
                return Err(e);
            }
        };
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Validate session expiration
        self.validate_policy_session(policy_session, Position::handle(1))?;

        // 1. Retrieve session state details.

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

        // 2. Validate the selection and filter it against the allocated PCR banks (C `FilterPcr`,
        //    applied in place by `PCRComputeCurrentDigest`). The caller's bank order is preserved:
        //    PCR values are hashed in that order and the filtered selection (in that order) is
        //    extended into the policy digest for both trial and policy sessions.
        for in_sel in cmd.pcrs.pcr_selections() {
            let sizeof_select = in_sel.sizeof_select() as usize;
            if sizeof_select < tpm2::TPM2_PCR_SELECT_MIN
                || sizeof_select > (tpm2::TPM2_PCR_SELECT_MAX as usize)
            {
                return Err(TpmRc::VALUE.with(Position::parameter(2)));
            }
        }
        let pcrs_selection_out = self.filter_pcr_selection(&cmd.pcrs);

        // 3. Digest of the selected (allocated) PCR values, in the caller's bank order
        //    (`PCRComputeCurrentDigest`).
        let current = self.compute_pcr_digest(&pcrs_selection_out, auth_hash)?;
        let mut digest = [0u8; 64];
        let len = current.get_buffer().len();
        digest[..len].copy_from_slice(current.get_buffer());

        // 4. PCR counter check and pcrDigest verification for non-trial sessions; a trial session
        //    uses the caller's pcrDigest when one is provided.
        let mut pcr_counter = None;
        let (digest_tpm, digest_tpm_len) = if session_type != TpmSe::Trial {
            let current_pcr_counter = self.global_state.pcrs.update_counter;
            let session_pcr_counter = {
                let session_state = self
                    .global_state
                    .session(policy_session)
                    .ok_or(TpmRc::HANDLE.to_rc())?;
                session_state.pcr_counter
            };
            if let Some(session_pcr_counter) = session_pcr_counter
                && session_pcr_counter != current_pcr_counter
            {
                return Err(TpmRc::PCR_CHANGED);
            }
            pcr_counter = Some(current_pcr_counter);

            if !cmd.pcr_digest.get_buffer().is_empty()
                && cmd.pcr_digest.get_buffer() != &digest[..len]
            {
                // `TPM_RCS_VALUE + RC_PolicyPCR_pcrDigest` (pcrDigest is parameter 1).
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
            (digest, len)
        } else if !cmd.pcr_digest.get_buffer().is_empty() {
            let mut buf = [0u8; 64];
            let pcr_len = cmd.pcr_digest.get_buffer().len();
            buf[..pcr_len].copy_from_slice(cmd.pcr_digest.get_buffer());
            (buf, pcr_len)
        } else {
            (digest, len)
        };

        // 5. The filtered selection is extended into the policy digest.
        let pcrs_to_extend = &pcrs_selection_out;

        let mut pcrs_bytes = [0u8; tpm2::TpmlPcrSelection::MAX_SIZE];
        let pcrs_len = pcrs_to_extend.marshal(&mut pcrs_bytes);

        // 6. Compute new policy digest.
        // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyPCR || pcrs || digestTPM)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &(TpmCc::PolicyPCR.code()).to_be_bytes(),
                &pcrs_bytes[..pcrs_len],
                &digest_tpm[..digest_tpm_len],
            ],
        )?;

        // 7. Mutate session state.
        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.to_rc())?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            if session_type != TpmSe::Trial {
                session_state.pcr_counter = pcr_counter;
            }
        }

        let response = request.into_response();
        self.write_response_all(response, &(), &(), &session_responses[..num_sessions])?;
        Ok(())
    }
}
