use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::{PolicyPCR, PolicyPCRHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Alg, TpmiAlgHash};
use tpm2::{Marshal, TpmsPcrSelection, Unmarshal};
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
                if let Ok(_pcr_digest) = tpm2::Tpm2bDigest::unmarshal(&mut slice) {
                    if slice.len() >= 4 {
                        let count = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
                        if count > 0 && slice.len() >= 6 {
                            let hash_raw = u16::from_be_bytes([slice[4], slice[5]]);
                            if TpmiAlgHash::try_from(hash_raw).is_err() {
                                return Err(TpmRc::HASH.with(Position::parameter(1)));
                            }
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

        // 2. PCR counter check for non-trial sessions.
        let mut pcr_counter = None;
        if session_type != TpmSe::Trial {
            let current_pcr_counter = self.global_state.pcrs.update_counter;
            let session_pcr_counter = {
                let session_state = self
                    .global_state
                    .session(policy_session)
                    .ok_or(TpmRc::HANDLE.to_rc())?;
                session_state.pcr_counter
            };
            if let Some(session_pcr_counter) = session_pcr_counter {
                if session_pcr_counter != current_pcr_counter {
                    return Err(TpmRc::PCR_CHANGED);
                }
            }
            pcr_counter = Some(current_pcr_counter);
        }

        // 3. Process PCR selection and read platform PCR values.
        let mut pcrs_selection_out = tpm2::TpmlPcrSelection::default();

        let count = cmd.pcrs.count();
        if count > tpm2::TPM2_NUM_PCR_BANKS as usize {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let mut selections = [TpmsPcrSelection::default(); tpm2::TPM2_NUM_PCR_BANKS as usize];
        for (i, sel) in cmd.pcrs.pcr_selections().enumerate() {
            selections[i] = *sel;
        }
        selections[..count].sort_unstable_by_key(|sel| Alg::from(sel.hash()).id());

        for in_sel in &selections[..count] {
            let hash_alg = in_sel.hash();
            if !matches!(
                hash_alg,
                TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384
            ) {
                return Err(TpmRc::HASH.with(Position::parameter(1)));
            }
            if (in_sel.sizeof_select() as usize) < tpm2::TPM2_PCR_SELECT_MIN
                || (in_sel.sizeof_select() as usize) > (tpm2::TPM2_PCR_SELECT_MAX as usize)
            {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        }

        for i in 1..count {
            if selections[i].hash() == selections[i - 1].hash() {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        }

        // 24 represents the maximum number of PCRs in each bank (TPM 2.0 Library Specification Part 4, Section 8.1).
        let mut pcr_slices = [&[0u8][..]; tpm2::TPM2_NUM_PCR_BANKS as usize * 24];
        let mut num_slices = 0;

        for in_sel in &selections[..count] {
            let hash_alg = in_sel.hash();
            let sizeof_select = in_sel.sizeof_select();
            let mut out_pcr_select = [0u8; tpm2::TPM2_PCR_SELECT_MAX as usize];
            // Iterate over the 24 PCRs in each bank (TPM 2.0 Library Specification Part 4, Section 8.1).
            for pcr in 0..24 {
                let byte_idx = (pcr / 8) as usize;
                let bit_idx = (pcr % 8) as usize;
                if byte_idx < sizeof_select as usize
                    && (in_sel.pcr_select()[byte_idx] & (1 << bit_idx)) != 0
                {
                    let digest_bytes = match hash_alg {
                        TpmiAlgHash::Sha1 => &self.global_state.pcrs.sha1[pcr as usize][..],
                        TpmiAlgHash::Sha256 => &self.global_state.pcrs.sha256[pcr as usize][..],
                        TpmiAlgHash::Sha384 => &self.global_state.pcrs.sha384[pcr as usize][..],
                        _ => unreachable!(),
                    };
                    if num_slices >= pcr_slices.len() {
                        return Err(TpmRc::FAILURE);
                    }
                    pcr_slices[num_slices] = digest_bytes;
                    num_slices += 1;
                    out_pcr_select[byte_idx] |= 1 << bit_idx;
                }
            }

            let out_sel =
                TpmsPcrSelection::new(hash_alg, &out_pcr_select[..sizeof_select as usize])
                    .map_err(|_| TpmRc::FAILURE)?;
            pcrs_selection_out.add(&out_sel)?;
        }

        // 4. Compute/Verify the PCR digest.
        let (digest_tpm, digest_tpm_len) = {
            let (digest, len) = self.compute_hash(auth_hash, &pcr_slices[..num_slices])?;
            if session_type == TpmSe::Trial {
                if !cmd.pcr_digest.get_buffer().is_empty() {
                    let mut buf = [0u8; 64];
                    let pcr_len = cmd.pcr_digest.get_buffer().len();
                    buf[..pcr_len].copy_from_slice(cmd.pcr_digest.get_buffer());
                    (buf, pcr_len)
                } else if auth_hash == TpmiAlgHash::Sha1 {
                    ([0u8; 64], 0)
                } else {
                    (digest, len)
                }
            } else {
                if !cmd.pcr_digest.get_buffer().is_empty()
                    && cmd.pcr_digest.get_buffer() != &digest[..len]
                {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                (digest, len)
            }
        };

        // 5. Determine PCR selection to extend.
        let pcrs_to_extend = if session_type == TpmSe::Trial {
            &cmd.pcrs
        } else {
            &pcrs_selection_out
        };

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
