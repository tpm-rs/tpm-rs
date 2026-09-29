use tpm2::Alg;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::{
    PCRAllocate, PCRAllocateHandles, PCREvent, PCREventHandles, PCRExtend, PCRExtendHandles,
    PCRRead, PCRReset, PCRResetHandles, PCRSetAuthPolicy, PCRSetAuthPolicyHandles, PCRSetAuthValue,
    PCRSetAuthValueHandles,
};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bDigest, TpmiAlgHash, TpmlDigest, TpmlDigestValues, TpmlPcrSelection,
    TpmsPcrSelection, TpmtHa,
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

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
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

        request.try_unmarshal::<()>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal::<PCRRead>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let mut pcr_selection_out = TpmlPcrSelection::default();
        let mut pcr_values = TpmlDigest::default();

        let count = cmd.pcr_selection_in.count();
        if count > tpm2::TPM2_NUM_PCR_BANKS as usize {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut selections = [TpmsPcrSelection::default(); tpm2::TPM2_NUM_PCR_BANKS as usize];
        for (i, sel) in cmd.pcr_selection_in.pcr_selections().enumerate() {
            selections[i] = *sel;
        }
        selections[..count].sort_unstable_by_key(|sel| Alg::from(sel.hash()).id());

        for in_sel in &selections[..count] {
            let hash_alg = in_sel.hash();
            let sizeof_select = in_sel.sizeof_select();
            let mut out_pcr_select = [0u8; tpm2::TPM2_PCR_SELECT_MAX as usize];

            let bank_supported = matches!(
                hash_alg,
                TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384
            );

            if bank_supported {
                // Iterate over the 24 PCRs in each bank (TPM 2.0 Library Specification Part 4, Section 8.1).
                for pcr in 0..24 {
                    let byte_idx = (pcr / 8) as usize;
                    let bit_idx = (pcr % 8) as usize;
                    if byte_idx < sizeof_select as usize
                        && (in_sel.pcr_select()[byte_idx] & (1 << bit_idx)) != 0
                        && pcr_values.count() < tpm2::TPML_DIGEST_MAX_DIGESTS
                    {
                        let digest_bytes = match hash_alg {
                            TpmiAlgHash::Sha1 => &self.global_state.pcrs.sha1[pcr as usize][..],
                            TpmiAlgHash::Sha256 => &self.global_state.pcrs.sha256[pcr as usize][..],
                            TpmiAlgHash::Sha384 => &self.global_state.pcrs.sha384[pcr as usize][..],
                            _ => unreachable!(),
                        };

                        let digest =
                            Tpm2bDigest::from_bytes(digest_bytes).map_err(|_| TpmRc::FAILURE)?;
                        pcr_values.add(&digest)?;
                        out_pcr_select[byte_idx] |= 1 << bit_idx;
                    }
                }
            }

            let out_sel =
                TpmsPcrSelection::new(hash_alg, &out_pcr_select[..sizeof_select as usize])
                    .map_err(|_| TpmRc::FAILURE)?;
            pcr_selection_out.add(&out_sel)?;
        }

        let rsp = responses::PCRRead {
            pcr_update_counter: self.global_state.pcrs.update_counter,
            pcr_selection_out,
            pcr_values,
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

        let handles = request.try_unmarshal::<PCRExtendHandles>()?;
        let pcr_handle = handles.pcr_handle.0;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<PCRExtend>()?;

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
        if pcr_handle >= 24 {
            return Err(TpmRc::VALUE.to_rc());
        }

        let locality = self.global_state.locality;
        if locality > 4 {
            return Err(TpmRc::LOCALITY);
        }
        let extend_mask = PCR_EXTEND_LOCALITY[pcr_handle as usize];
        if (extend_mask & (1 << locality)) == 0 {
            return Err(TpmRc::LOCALITY);
        }

        if pcr_handle < 16 {
            self.nv_clear_orderly()?;
        }

        let mut changed = false;

        for digest_val in cmd.digests.digests() {
            match *digest_val {
                TpmtHa::Sha1(val) => {
                    let old_hash = &self.global_state.pcrs.sha1[pcr_handle as usize];
                    let (new_hash, _) = self.compute_hash(TpmiAlgHash::Sha1, &[old_hash, val])?;
                    self.global_state.pcrs.sha1[pcr_handle as usize]
                        .copy_from_slice(&new_hash[..20]);
                    changed = true;
                }
                TpmtHa::Sha256(val) => {
                    let old_hash = &self.global_state.pcrs.sha256[pcr_handle as usize];
                    let (new_hash, _) = self.compute_hash(TpmiAlgHash::Sha256, &[old_hash, val])?;
                    self.global_state.pcrs.sha256[pcr_handle as usize]
                        .copy_from_slice(&new_hash[..32]);
                    changed = true;
                }
                TpmtHa::Sha384(val) => {
                    let old_hash = &self.global_state.pcrs.sha384[pcr_handle as usize];
                    let (new_hash, _) = self.compute_hash(TpmiAlgHash::Sha384, &[old_hash, val])?;
                    self.global_state.pcrs.sha384[pcr_handle as usize]
                        .copy_from_slice(&new_hash[..48]);
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

        let handles = request.try_unmarshal::<PCREventHandles>()?;
        let pcr_handle = handles.pcr_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal::<PCREvent>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if pcr_handle != Handle::RH_NULL.0 {
            // Dynamic PCR handle bounds check. The TPM 2.0 specification defines 24 PCRs for PC Client profiles
            // (TPM 2.0 Library Specification Part 4: Support Structures, Section 8.1).
            if pcr_handle >= 24 {
                return Err(TpmRc::VALUE.to_rc());
            }
            let locality = self.global_state.locality;
            if locality > 4 {
                return Err(TpmRc::LOCALITY);
            }
            let extend_mask = PCR_EXTEND_LOCALITY[pcr_handle as usize];
            if (extend_mask & (1 << locality)) == 0 {
                return Err(TpmRc::LOCALITY);
            }
            if pcr_handle < 16 {
                self.nv_clear_orderly()?;
            }
        }

        let event_data_buf = cmd.event_data.get_buffer();

        let (sha1_d, _) = self.compute_hash(TpmiAlgHash::Sha1, &[event_data_buf])?;
        let (sha256_d, _) = self.compute_hash(TpmiAlgHash::Sha256, &[event_data_buf])?;
        let (sha384_d, _) = self.compute_hash(TpmiAlgHash::Sha384, &[event_data_buf])?;

        let mut digests = TpmlDigestValues::default();
        let mut d_sha1 = [0u8; 20];
        d_sha1.copy_from_slice(&sha1_d[..20]);
        digests.add(&TpmtHa::Sha1(&d_sha1))?;

        let mut d_sha256 = [0u8; 32];
        d_sha256.copy_from_slice(&sha256_d[..32]);
        digests.add(&TpmtHa::Sha256(&d_sha256))?;

        let mut d_sha384 = [0u8; 48];
        d_sha384.copy_from_slice(&sha384_d[..48]);
        digests.add(&TpmtHa::Sha384(&d_sha384))?;

        if pcr_handle != Handle::RH_NULL.0 {
            let old_sha1 = &self.global_state.pcrs.sha1[pcr_handle as usize];
            let (new_sha1, _) = self.compute_hash(TpmiAlgHash::Sha1, &[old_sha1, &d_sha1])?;
            self.global_state.pcrs.sha1[pcr_handle as usize].copy_from_slice(&new_sha1[..20]);

            let old_sha256 = &self.global_state.pcrs.sha256[pcr_handle as usize];
            let (new_sha256, _) =
                self.compute_hash(TpmiAlgHash::Sha256, &[old_sha256, &d_sha256])?;
            self.global_state.pcrs.sha256[pcr_handle as usize].copy_from_slice(&new_sha256[..32]);

            let old_sha384 = &self.global_state.pcrs.sha384[pcr_handle as usize];
            let (new_sha384, _) =
                self.compute_hash(TpmiAlgHash::Sha384, &[old_sha384, &d_sha384])?;
            self.global_state.pcrs.sha384[pcr_handle as usize].copy_from_slice(&new_sha384[..48]);

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

        let handles = request.try_unmarshal::<PCRResetHandles>()?;
        let pcr_handle = handles.pcr_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal::<PCRReset>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Dynamic PCR handle bounds check. The TPM 2.0 specification defines 24 PCRs for PC Client profiles
        // (TPM 2.0 Library Specification Part 4: Support Structures, Section 8.1).
        if pcr_handle >= 24 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        if pcr_handle != 16 && pcr_handle != 23 {
            return Err(TpmRc::LOCALITY);
        }

        let locality = self.global_state.locality;
        if locality > 4 {
            return Err(TpmRc::LOCALITY);
        }
        let reset_mask = PCR_RESET_LOCALITY[pcr_handle as usize];
        if (reset_mask & (1 << locality)) == 0 {
            return Err(TpmRc::LOCALITY);
        }

        self.global_state.pcrs.sha1[pcr_handle as usize] = [0u8; 20];
        self.global_state.pcrs.sha256[pcr_handle as usize] = [0u8; 32];
        self.global_state.pcrs.sha384[pcr_handle as usize] = [0u8; 48];

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
        let handles = request.try_unmarshal::<PCRAllocateHandles>()?;
        let auth_handle = handles.auth_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.global_state.parsed_auths[..self.global_state.parsed_auths_len]
            .first()
            .cloned();

        self.validate_platform_auth(auth_handle, provided_auth)?;

        let cmd = request.try_unmarshal::<PCRAllocate>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let input_selections = cmd.pcr_allocation.pcr_selections();
        let mut selections = [TpmsPcrSelection::default(); tpm2::TPM2_NUM_PCR_BANKS as usize];
        let mut count = self.global_state.pcrs.pcr_allocation.count();
        for (i, sel) in self
            .global_state
            .pcrs
            .pcr_allocation
            .pcr_selections()
            .enumerate()
        {
            selections[i] = *sel;
        }

        let mut success = true;

        for in_sel in input_selections {
            let hash_alg = in_sel.hash();
            if !matches!(
                hash_alg,
                TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
            ) {
                success = false;
            }

            if in_sel.sizeof_select() > 3 && in_sel.pcr_select()[3..].iter().any(|&b| b != 0) {
                success = false;
            }

            if let Some(idx) = selections[..count]
                .iter()
                .position(|s| s.hash() == hash_alg)
            {
                selections[idx] = *in_sel;
            } else if count < tpm2::TPM2_NUM_PCR_BANKS as usize {
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
                if sel.sizeof_select() >= 1 && (sel.pcr_select()[0] & 0x01) != 0 {
                    has_hcrtm = true;
                }
                if sel.sizeof_select() >= 3 && (sel.pcr_select()[2] & 0x7E) != 0 {
                    has_drtm = true;
                }
            }
            if !has_hcrtm || !has_drtm {
                return Err(TpmRc::PCR);
            }

            let new_allocation =
                TpmlPcrSelection::from_slice(&selections[..count]).ok_or(TpmRc::FAILURE)?;
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

        let handles = request.try_unmarshal::<PCRSetAuthValueHandles>()?;
        let pcr_handle = handles.pcr_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal::<PCRSetAuthValue>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Only PCRs belonging to an authorization group (PCR 20-22) allow an authValue.
        if !(20..=22).contains(&pcr_handle) {
            return Err(TpmRc::VALUE.to_rc());
        }

        self.nv_clear_orderly()?;

        let stripped = crate::util::strip_trailing_zeros(cmd.auth.get_buffer());
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

        let handles = request.try_unmarshal::<PCRSetAuthPolicyHandles>()?;
        let auth_handle = handles.auth_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.global_state.parsed_auths[..self.global_state.parsed_auths_len]
            .first()
            .cloned();
        self.validate_platform_auth(auth_handle, provided_auth)?;

        let cmd = request.try_unmarshal::<PCRSetAuthPolicy>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let expected_size = match cmd.hash_alg {
            Some(alg) => alg.digest_size(),
            None => 0,
        };
        if cmd.auth_policy.get_size() as usize != expected_size {
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
