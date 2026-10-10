use tpm2::Alg;
#[allow(unused_imports)]
use tpm2::TpmCc;

use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::pcr::PcrState;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::{
    PCRAllocate, PCREvent, PCRExtend, PCRRead, PCRReset, PCRSetAuthPolicy, PCRSetAuthValue,
    responses,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bDigest, TpmiAlgHash, TpmlDigest, TpmlDigestValues, TpmlElement, TpmlPcrSelection,
    TpmsPcrSelect, TpmsPcrSelection, TpmtHa,
};

use crate::{handler::CommandHandler, req_resp::RequestThenResponse};

/// Allowed localities mask for PCR Extend operations.
/// Each index corresponds to a PCR index, and the value is a bitmask of localities (0-4) allowed
/// to perform extensions.
/// Defined in TCG PC Client Platform TPM Profile (PTP) Specification, Section 4.2 ("PCR Usage").
pub(crate) const PCR_EXTEND_LOCALITY: [u8; 24] = [
    0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, // 0 - 7
    0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, // 8 - 15
    0x1F, // 16
    0x1C, // 17
    0x1C, // 18
    0x0C, // 19
    0x0E, // 20
    0x04, // 21
    0x04, // 22
    0x1F, // 23
];

/// Allowed localities mask for PCR Reset operations.
/// Each index corresponds to a PCR index, and the value is a bitmask of localities (0-4) allowed
/// to perform resets.
/// Defined in TCG PC Client Platform TPM Profile (PTP) Specification, Section 4.2 ("PCR Usage").
const PCR_RESET_LOCALITY: [u8; 24] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0 - 7
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8 - 15
    0x0F, // 16
    0x00, // 17
    0x00, // 18
    0x00, // 19
    0x00, // 20
    0x00, // 21
    0x00, // 22
    0x0F, // 23
];

/// `PCR_SELECT_MAX` for this TPM's 24 PCRs: the largest `sizeofSelect` accepted in a
/// `TPMS_PCR_SELECTION`.
///
/// PORTING: the new `tpm2` crate unmarshals up to [`TpmsPcrSelect::MAX`] (4) bytes, while exp's
/// typed unmarshal rejected more than 3 with `TPM_RC_VALUE`.
const PCR_SELECT_MAX: usize = TpmsPcrSelect::PLATFORM_PCRS.div_ceil(8);

/// Returns `true` if any selection in `pcr_selection` is larger than [`PCR_SELECT_MAX`] bytes,
/// which exp's typed unmarshal of a `TPML_PCR_SELECTION` rejected with `TPM_RC_VALUE`.
fn has_oversized_select(pcr_selection: &TpmlPcrSelection) -> bool {
    pcr_selection
        .as_slice()
        .iter()
        .any(|sel| sel.selection.pcrs().len() > PCR_SELECT_MAX)
}

/// Returns the bank index of PCR handle `pcr_handle`, or `None` if it is not one of the 24 PCRs
/// defined for PC Client profiles (TPM 2.0 Library Specification Part 4: Support Structures,
/// Section 8.1).
///
/// PORTING: replaces exp's `pcr_handle >= 24` checks followed by `pcr_handle as usize`.
fn pcr_index(pcr_handle: u32) -> Option<usize> {
    usize::try_from(pcr_handle).ok().filter(|&index| index < 24)
}

/// Returns the value of PCR `pcr` in the `hash_alg` bank, for the banks this TPM implements
/// (SHA-1, SHA-256 and SHA-384).
///
/// PORTING: replaces exp's inline `match` with an `unreachable!()` arm for other banks.
fn pcr_value(pcrs: &PcrState, hash_alg: TpmiAlgHash, pcr: usize) -> Option<&[u8]> {
    match hash_alg {
        TpmiAlgHash::Sha1 => pcrs.sha1.get(pcr).map(|value| value.as_slice()),
        TpmiAlgHash::Sha256 => pcrs.sha256.get(pcr).map(|value| value.as_slice()),
        TpmiAlgHash::Sha384 => pcrs.sha384.get(pcr).map(|value| value.as_slice()),
        _ => None,
    }
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::PCRRead] (`0x17e`) command.
    ///
    /// # Description
    /// This command reads the current value of the selected PCR banks and indices.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 22.4 (TPM2_PCR_Read).
    ///
    /// # Relationships
    /// - Reads PCR values modified by [TpmCc::PCRExtend](pcr.rs),
    ///   [TpmCc::PCREvent](pcr.rs), or [TpmCc::PCRReset](pcr.rs).
    /// - The PCR values returned are used by external entities to verify platform state or by [TpmCc::PolicyPCR](policy_pcr.rs) to restrict session access.
    pub fn pcr_read(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<PCRRead>([])?;
        if has_oversized_select(&cmd.pcr_selection_in) {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let mut out_selections = [TpmsPcrSelection::DEFAULT; TpmlPcrSelection::CAP];
        let mut pcr_values = [Tpm2bDigest::default(); TpmlDigest::CAP];
        let mut num_values = 0;

        let in_selections = cmd.pcr_selection_in.as_slice();
        let count = in_selections.len();
        let mut selections = [TpmsPcrSelection::DEFAULT; TpmlPcrSelection::CAP];
        let selections = selections.get_mut(..count).ok_or(TpmRc::SIZE.to_rc())?;
        selections.copy_from_slice(in_selections);
        selections.sort_unstable_by_key(|sel| Alg::from(sel.hash).id());

        for (in_sel, out_sel) in selections.iter().zip(out_selections.iter_mut()) {
            let hash_alg = in_sel.hash;
            let pcr_select = in_sel.selection.pcrs();
            let sizeof_select = pcr_select.len();
            let mut out_pcr_select = [0u8; TpmsPcrSelect::MAX];

            let bank_supported = matches!(
                hash_alg,
                TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384
            );

            if bank_supported {
                // Iterate over the 24 PCRs in each bank (TPM 2.0 Library Specification Part 4, Section 8.1).
                for pcr in 0..24usize {
                    let byte_idx = pcr / 8;
                    let bit_idx = pcr % 8;
                    if byte_idx < sizeof_select
                        && (pcr_select[byte_idx] & (1 << bit_idx)) != 0
                        && num_values < TpmlDigest::CAP
                    {
                        let digest_bytes = pcr_value(&self.global_state.pcrs, hash_alg, pcr)
                            .ok_or(TpmRc::FAILURE)?;

                        pcr_values[num_values] =
                            Tpm2bDigest::new(digest_bytes).ok_or(TpmRc::FAILURE)?;
                        num_values += 1;
                        out_pcr_select[byte_idx] |= 1 << bit_idx;
                    }
                }
            }

            *out_sel = TpmsPcrSelection {
                hash: hash_alg,
                selection: TpmsPcrSelect::new(&out_pcr_select[..sizeof_select])
                    .ok_or(TpmRc::FAILURE)?,
            };
        }

        let rsp = responses::PCRRead {
            pcr_update_counter: self.global_state.pcrs.update_counter,
            pcr_selection_out: TpmlPcrSelection::new(&out_selections[..count])
                .ok_or(TpmRc::FAILURE)?,
            pcr_values: TpmlDigest::new(&pcr_values[..num_values]).ok_or(TpmRc::FAILURE)?,
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PCRExtend] (`0x182`) command.
    ///
    /// # Description
    /// This command extends a PCR bank value with an input digest: `NewValue = Hash(OldValue || InputDigest)`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 22.2 (TPM2_PCR_Extend).
    ///
    /// # Relationships
    /// - Can be checked afterwards using [TpmCc::PCRRead](pcr.rs).
    /// - Different from [TpmCc::PCREvent](pcr.rs), which takes raw event data and hashes it internally before extending.
    pub fn pcr_extend(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PCRExtend>()?;
        let [pcr_handle] = handles;
        check(pcr_handle, Tpmi::DhPcrOrNull, Position::handle(1))?;
        let pcr_handle = pcr_handle.0;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<PCRExtend>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if pcr_handle == Handle::RH_NULL.0 {
            let response = request.into_response();
            self.write_response_none(response, &session_responses[..num_sessions])?;
            return Ok(());
        }

        // Dynamic PCR handle bounds check. The TPM 2.0 specification defines 24 PCRs for PC Client profiles
        // (TPM 2.0 Library Specification Part 4: Support Structures, Section 8.1).
        let Some(pcr_index) = pcr_index(pcr_handle) else {
            return Err(TpmRc::VALUE.to_rc());
        };

        let locality = self.global_state.locality;
        if locality > 4 {
            return Err(TpmRc::LOCALITY);
        }
        let extend_mask = PCR_EXTEND_LOCALITY[pcr_index];
        if (extend_mask & (1 << locality)) == 0 {
            return Err(TpmRc::LOCALITY);
        }

        if pcr_index < 16 {
            self.nv_clear_orderly()?;
        }

        let mut changed = false;

        for digest_val in cmd.digests.as_slice() {
            match *digest_val {
                TpmtHa::Sha1(val) => {
                    let old_hash = &self.global_state.pcrs.sha1[pcr_index];
                    let (new_hash, _) = self.compute_hash(TpmiAlgHash::Sha1, &[old_hash, val])?;
                    self.global_state.pcrs.sha1[pcr_index].copy_from_slice(&new_hash[..20]);
                    changed = true;
                }
                TpmtHa::Sha256(val) => {
                    let old_hash = &self.global_state.pcrs.sha256[pcr_index];
                    let (new_hash, _) = self.compute_hash(TpmiAlgHash::Sha256, &[old_hash, val])?;
                    self.global_state.pcrs.sha256[pcr_index].copy_from_slice(&new_hash[..32]);
                    changed = true;
                }
                TpmtHa::Sha384(val) => {
                    let old_hash = &self.global_state.pcrs.sha384[pcr_index];
                    let (new_hash, _) = self.compute_hash(TpmiAlgHash::Sha384, &[old_hash, val])?;
                    self.global_state.pcrs.sha384[pcr_index].copy_from_slice(&new_hash[..48]);
                    changed = true;
                }
                _ => {}
            }
        }

        if changed {
            self.global_state.pcrs.update_counter =
                self.global_state.pcrs.update_counter.wrapping_add(1);
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PCREvent] (`0x130`) command.
    ///
    /// # Description
    /// This command hashes an input event data buffer and extends the resulting digest into the selected PCR bank.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 22.3 (TPM2_PCR_Event).
    ///
    /// # Relationships
    /// - Simulates an extend operation on raw data by calculating hashes dynamically and calling the extend process.
    /// - Similar to [TpmCc::PCRExtend](pcr.rs) but takes raw data instead of pre-computed digest values.
    pub fn pcr_event(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PCREvent>()?;
        let [pcr_handle] = handles;
        check(pcr_handle, Tpmi::DhPcrOrNull, Position::handle(1))?;
        let pcr_handle = pcr_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<PCREvent>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let pcr_index = if pcr_handle != Handle::RH_NULL.0 {
            // Dynamic PCR handle bounds check. The TPM 2.0 specification defines 24 PCRs for PC Client profiles
            // (TPM 2.0 Library Specification Part 4: Support Structures, Section 8.1).
            let Some(pcr_index) = pcr_index(pcr_handle) else {
                return Err(TpmRc::VALUE.to_rc());
            };
            let locality = self.global_state.locality;
            if locality > 4 {
                return Err(TpmRc::LOCALITY);
            }
            let extend_mask = PCR_EXTEND_LOCALITY[pcr_index];
            if (extend_mask & (1 << locality)) == 0 {
                return Err(TpmRc::LOCALITY);
            }
            if pcr_index < 16 {
                self.nv_clear_orderly()?;
            }
            Some(pcr_index)
        } else {
            None
        };

        let event_data_buf = cmd.event_data.as_slice();

        let (sha1_d, _) = self.compute_hash(TpmiAlgHash::Sha1, &[event_data_buf])?;
        let (sha256_d, _) = self.compute_hash(TpmiAlgHash::Sha256, &[event_data_buf])?;
        let (sha384_d, _) = self.compute_hash(TpmiAlgHash::Sha384, &[event_data_buf])?;

        let mut d_sha1 = [0u8; 20];
        d_sha1.copy_from_slice(&sha1_d[..20]);

        let mut d_sha256 = [0u8; 32];
        d_sha256.copy_from_slice(&sha256_d[..32]);

        let mut d_sha384 = [0u8; 48];
        d_sha384.copy_from_slice(&sha384_d[..48]);

        let digests = TpmlDigestValues::new(&[
            TpmtHa::Sha1(&d_sha1),
            TpmtHa::Sha256(&d_sha256),
            TpmtHa::Sha384(&d_sha384),
        ])
        .ok_or(TpmRc::FAILURE)?;

        if let Some(pcr_index) = pcr_index {
            let old_sha1 = &self.global_state.pcrs.sha1[pcr_index];
            let (new_sha1, _) = self.compute_hash(TpmiAlgHash::Sha1, &[old_sha1, &d_sha1])?;
            self.global_state.pcrs.sha1[pcr_index].copy_from_slice(&new_sha1[..20]);

            let old_sha256 = &self.global_state.pcrs.sha256[pcr_index];
            let (new_sha256, _) =
                self.compute_hash(TpmiAlgHash::Sha256, &[old_sha256, &d_sha256])?;
            self.global_state.pcrs.sha256[pcr_index].copy_from_slice(&new_sha256[..32]);

            let old_sha384 = &self.global_state.pcrs.sha384[pcr_index];
            let (new_sha384, _) =
                self.compute_hash(TpmiAlgHash::Sha384, &[old_sha384, &d_sha384])?;
            self.global_state.pcrs.sha384[pcr_index].copy_from_slice(&new_sha384[..48]);

            self.global_state.pcrs.update_counter =
                self.global_state.pcrs.update_counter.wrapping_add(1);
        }

        let rsp = responses::PCREvent { digests };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PCRReset] (`0x13d`) command.
    ///
    /// # Description
    /// This command resets a resettable PCR index to its default value (zeros or ones).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 22.8 (TPM2_PCR_Reset).
    ///
    /// # Relationships
    /// - Only PCR indices configured as resettable (typically PCR 16 and PCR 23 in PC Client) can be reset.
    /// - Restores the default state of the PCR index that was previously modified by [TpmCc::PCRExtend](pcr.rs) or [TpmCc::PCREvent](pcr.rs).
    pub fn pcr_reset(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PCRReset>()?;
        let [pcr_handle] = handles;
        check(pcr_handle, Tpmi::DhPcr, Position::handle(1))?;
        let pcr_handle = pcr_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal_command::<PCRReset>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Dynamic PCR handle bounds check. The TPM 2.0 specification defines 24 PCRs for PC Client profiles
        // (TPM 2.0 Library Specification Part 4: Support Structures, Section 8.1).
        let Some(pcr_index) = pcr_index(pcr_handle) else {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        };

        if pcr_index != 16 && pcr_index != 23 {
            return Err(TpmRc::LOCALITY);
        }

        let locality = self.global_state.locality;
        if locality > 4 {
            return Err(TpmRc::LOCALITY);
        }
        let reset_mask = PCR_RESET_LOCALITY[pcr_index];
        if (reset_mask & (1 << locality)) == 0 {
            return Err(TpmRc::LOCALITY);
        }

        self.global_state.pcrs.sha1[pcr_index] = [0u8; 20];
        self.global_state.pcrs.sha256[pcr_index] = [0u8; 32];
        self.global_state.pcrs.sha384[pcr_index] = [0u8; 48];

        self.global_state.pcrs.update_counter =
            self.global_state.pcrs.update_counter.wrapping_add(1);

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PCRAllocate] (`0x12B`) command.
    ///
    /// # Description
    /// This command is used to set the desired PCR allocation of PCR banks across supported hash algorithms.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 22.5 (TPM2_PCR_Allocate).
    ///
    /// # Relationships
    /// - Requires Platform Authorization (`TPM_RH_PLATFORM`).
    /// - Stored PCR bank allocation takes effect across subsequent resets and is reported via [TpmCc::GetCapability](capability.rs).
    pub fn pcr_allocate(&mut self, mut request: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let handles = request.try_unmarshal_handles::<PCRAllocate>()?;
        let [auth_handle] = handles;
        check(auth_handle, Tpmi::RhPlatform, Position::handle(1))?;
        let auth_handle = auth_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.global_state.parsed_auths[..self.global_state.parsed_auths_len]
            .first()
            .cloned();

        self.validate_platform_auth(auth_handle, provided_auth)?;

        let cmd = request.try_unmarshal_command::<PCRAllocate>(handles)?;
        if has_oversized_select(&cmd.pcr_allocation) {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let input_selections = cmd.pcr_allocation.as_slice();
        let mut selections = [TpmsPcrSelection::DEFAULT; TpmlPcrSelection::CAP];
        let current_allocation = self.global_state.pcrs.pcr_allocation.as_slice();
        let mut count = current_allocation.len();
        selections
            .get_mut(..count)
            .ok_or(TpmRc::FAILURE)?
            .copy_from_slice(current_allocation);

        let mut success = true;

        for in_sel in input_selections {
            let hash_alg = in_sel.hash;
            if !matches!(
                hash_alg,
                TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
            ) {
                success = false;
            }

            if in_sel
                .selection
                .pcrs()
                .get(3..)
                .is_some_and(|rest| rest.iter().any(|&b| b != 0))
            {
                success = false;
            }

            if let Some(idx) = selections[..count].iter().position(|s| s.hash == hash_alg) {
                selections[idx] = *in_sel;
            } else if count < TpmlPcrSelection::CAP {
                selections[count] = *in_sel;
                count += 1;
            } else {
                success = false;
            }
        }

        if success {
            // Check TCG requirement: if DRTM_PCR or HCRTM_PCR is defined, the resulting allocation
            // must have at least one bank with DRTM_PCR and HCRTM_PCR allocated. Otherwise return TPM_RC_PCR.
            let mut has_hcrtm = false;
            let mut has_drtm = false;
            for sel in &selections[..count] {
                let pcr_select = sel.selection.pcrs();
                if pcr_select.first().is_some_and(|&b| (b & 0x01) != 0) {
                    has_hcrtm = true;
                }
                if pcr_select.get(2).is_some_and(|&b| (b & 0x7E) != 0) {
                    has_drtm = true;
                }
            }
            if !has_hcrtm || !has_drtm {
                return Err(TpmRc::PCR);
            }

            let new_allocation =
                TpmlPcrSelection::new(&selections[..count]).ok_or(TpmRc::FAILURE)?;
            self.nv_clear_orderly()?;
            self.global_state.pcrs.pcr_allocation = new_allocation;
            self.global_state.pcr_reconfig = true;
            self.global_state.state_saved = false;
        }

        let resp = responses::PCRAllocate {
            allocation_success: success,
            max_pcr: 24,
            size_needed: if success { 0 } else { 2048 },
            size_available: 1024,
        };

        let response = request.into_response();
        self.write_response_rsp(response, &resp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PCRSetAuthValue] (`0x183`) command.
    ///
    /// # Description
    /// This command changes the `authValue` associated with a PCR or group of PCRs.
    /// In accordance with the TPM 2.0 Reference Implementation (`PCRBelongsAuthGroup`),
    /// PCRs 20, 21, and 22 share a common authorization group (`gc.pcrAuthValues`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 22.7 (TPM2_PCR_SetAuthValue).
    pub fn pcr_set_auth_value(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PCRSetAuthValue>()?;
        let [pcr_handle] = handles;
        check(pcr_handle, Tpmi::DhPcr, Position::handle(1))?;
        let pcr_handle = pcr_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<PCRSetAuthValue>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Only PCRs belonging to an authorization group (PCR 20-22) allow an authValue.
        if !(20..=22).contains(&pcr_handle) {
            return Err(TpmRc::VALUE.to_rc());
        }

        self.nv_clear_orderly()?;

        let stripped = crate::util::strip_trailing_zeros(cmd.auth.as_slice());
        self.global_state.pcr_auth_value =
            crate::owned::OwnedAuth::from_bytes(stripped).map_err(|_| TpmRc::SIZE.to_rc())?;

        self.global_state.state_saved = false;
        self.context.save_hierarchy_auths(self.global_state);

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PCRSetAuthPolicy] (`0x12c`) command.
    ///
    /// # Description
    /// This command associates a policy digest and hash algorithm with a PCR or group of PCRs.
    /// In accordance with the TPM 2.0 Reference Implementation (`PCRBelongsPolicyGroup`),
    /// PCRs 20, 21, and 22 share a common policy group (`gp.pcrPolicies`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 22.6 (TPM2_PCR_SetAuthPolicy).
    pub fn pcr_set_auth_policy(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PCRSetAuthPolicy>()?;
        let [auth_handle] = handles;
        check(auth_handle, Tpmi::RhPlatform, Position::handle(1))?;
        let auth_handle = auth_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.global_state.parsed_auths[..self.global_state.parsed_auths_len]
            .first()
            .cloned();
        self.validate_platform_auth(auth_handle, provided_auth)?;

        let cmd = request.try_unmarshal_command::<PCRSetAuthPolicy>(handles)?;
        check(cmd.pcr_num, Tpmi::DhPcr, Position::parameter(3))?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let expected_size = match cmd.hash_alg {
            Some(alg) => alg.digest_size(),
            None => 0,
        };
        if cmd.auth_policy.as_slice().len() != expected_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        // Only PCRs belonging to a policy group (PCR 20-22) allow a policy.
        if !(20..=22).contains(&cmd.pcr_num.0) {
            return Err(TpmRc::VALUE.with(Position::parameter(3)));
        }

        self.global_state.pcr_policy_alg = cmd.hash_alg;
        self.global_state.pcr_policy = crate::owned::OwnedDigest::from(cmd.auth_policy);
        self.context.save_hierarchy_auths(self.global_state);

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
