use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::PolicyPCR;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Alg, Tpm2bDigest, TpmiAlgHash, TpmlElement, TpmlPcrSelection};
use tpm2::{Marshal, TpmsPcrSelect, TpmsPcrSelection, Unmarshal};
use tpm2::{TpmCc, TpmSe};

/// `TPM2_PCR_SELECT_MIN` / `TPM2_PCR_SELECT_MAX` of exp's old `tpm2` crate: 24 PCRs per bank,
/// so `sizeofSelect` must be exactly 3.
///
/// PORTING: the new [`TpmsPcrSelect`] accepts `sizeofSelect` up to
/// [`TpmsPcrSelect::MAX`] (4, for `IMPLEMENTATION_PCR == 32`), where exp's unmarshal already
/// rejected anything but 3 with `TPM_RC_VALUE`.
const PCR_SELECT_MIN: usize = TpmsPcrSelect::MIN;
const PCR_SELECT_MAX: usize = TpmsPcrSelect::PLATFORM_PCRS.div_ceil(8);

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
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

        let handles = request.try_unmarshal_handles::<PolicyPCR>()?;
        let [policy_session] = handles;
        check(policy_session, Tpmi::ShPolicy, Position::handle(1))?;
        let policy_session = policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = match request.try_unmarshal_command::<PolicyPCR>(handles) {
            Ok(cmd) => cmd,
            Err(e) => {
                let mut slice = request.remaining_slice();
                if Tpm2bDigest::unmarshal(&mut slice).is_ok()
                    && let Some((count, rest)) = slice.split_first_chunk::<4>()
                    && u32::from_be_bytes(*count) > 0
                    && let Some(hash_raw) = rest.first_chunk::<2>()
                    && TpmiAlgHash::try_from(Alg::from(u16::from_be_bytes(*hash_raw))).is_err()
                {
                    return Err(TpmRc::HASH.with(Position::parameter(1)));
                }
                return Err(e);
            }
        };
        // PORTING: see `PCR_SELECT_MAX` (exp's unmarshal error for this was VALUE at `pcrs`).
        if cmd
            .pcrs
            .as_slice()
            .iter()
            .any(|sel| sel.selection.pcrs().len() > PCR_SELECT_MAX)
        {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }
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
            if let Some(session_pcr_counter) = session_pcr_counter
                && session_pcr_counter != current_pcr_counter
            {
                return Err(TpmRc::PCR_CHANGED);
            }
            pcr_counter = Some(current_pcr_counter);
        }

        // 3. Process PCR selection and read platform PCR values.
        let count = cmd.pcrs.as_slice().len();
        if count > TpmlPcrSelection::CAP {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let mut selections = [TpmsPcrSelection::DEFAULT; TpmlPcrSelection::CAP];
        selections[..count].copy_from_slice(cmd.pcrs.as_slice());
        selections[..count].sort_unstable_by_key(|sel| Alg::from(sel.hash).id());

        for in_sel in &selections[..count] {
            let hash_alg = in_sel.hash;
            if !matches!(
                hash_alg,
                TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384
            ) {
                return Err(TpmRc::HASH.with(Position::parameter(1)));
            }
            if !(PCR_SELECT_MIN..=PCR_SELECT_MAX).contains(&in_sel.selection.pcrs().len()) {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        }

        if selections[..count]
            .windows(2)
            .any(|pair| pair[0].hash == pair[1].hash)
        {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        // 24 represents the maximum number of PCRs in each bank (TPM 2.0 Library Specification Part 4, Section 8.1).
        let mut pcr_slices = [&[0u8][..]; TpmlPcrSelection::CAP * 24];
        let mut num_slices = 0;
        let mut out_selections = [TpmsPcrSelection::DEFAULT; TpmlPcrSelection::CAP];

        for (in_sel, out_sel) in selections[..count].iter().zip(out_selections.iter_mut()) {
            let hash_alg = in_sel.hash;
            let pcr_select = in_sel.selection.pcrs();
            let sizeof_select = pcr_select.len();
            let mut out_pcr_select = [0u8; PCR_SELECT_MAX];
            // Iterate over the 24 PCRs in each bank (TPM 2.0 Library Specification Part 4, Section 8.1).
            for pcr in 0..24usize {
                let byte_idx = pcr / 8;
                let bit_idx = pcr % 8;
                if byte_idx < sizeof_select && (pcr_select[byte_idx] & (1 << bit_idx)) != 0 {
                    let digest_bytes = match hash_alg {
                        TpmiAlgHash::Sha1 => &self.global_state.pcrs.sha1[pcr][..],
                        TpmiAlgHash::Sha256 => &self.global_state.pcrs.sha256[pcr][..],
                        TpmiAlgHash::Sha384 => &self.global_state.pcrs.sha384[pcr][..],
                        // PORTING: exp had `unreachable!()` (rejected by the check above).
                        _ => return Err(TpmRc::HASH.with(Position::parameter(1))),
                    };
                    if num_slices >= pcr_slices.len() {
                        return Err(TpmRc::FAILURE);
                    }
                    pcr_slices[num_slices] = digest_bytes;
                    num_slices += 1;
                    out_pcr_select[byte_idx] |= 1 << bit_idx;
                }
            }

            *out_sel = TpmsPcrSelection {
                hash: hash_alg,
                selection: TpmsPcrSelect::new(&out_pcr_select[..sizeof_select])
                    .ok_or(TpmRc::FAILURE)?,
            };
        }
        let pcrs_selection_out =
            TpmlPcrSelection::new(&out_selections[..count]).ok_or(TpmRc::FAILURE)?;

        // 4. Compute/Verify the PCR digest.
        let (digest_tpm, digest_tpm_len) = {
            let (digest, len) = self.compute_hash(auth_hash, &pcr_slices[..num_slices])?;
            let pcr_digest = cmd.pcr_digest.as_slice();
            if session_type == TpmSe::Trial {
                if !pcr_digest.is_empty() {
                    let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
                    let pcr_len = pcr_digest.len();
                    buf[..pcr_len].copy_from_slice(pcr_digest);
                    (buf, pcr_len)
                } else if auth_hash == TpmiAlgHash::Sha1 {
                    ([0u8; TpmiAlgHash::MAX_DIGEST_BYTES], 0)
                } else {
                    (digest, len)
                }
            } else {
                if !pcr_digest.is_empty() && pcr_digest != &digest[..len] {
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

        let mut pcrs_bytes = [0u8; TpmlPcrSelection::MAX_SIZE];
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
