use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::platform::PcrState;

use crate::storage::manager::StorageManager;
use crate::storage::{NvStorage, Tpm2Storage};
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

/// Number of implemented PCRs (`IMPLEMENTATION_PCR`).
pub(crate) const IMPLEMENTATION_PCR: u32 = 24;

/// The DRTM PCR (`DRTM_PCR` in `TpmProfile_Misc.h`). `TPM2_PCR_Allocate` requires that at least
/// one bank keeps it allocated.
const DRTM_PCR: usize = 17;

/// The H-CRTM PCR (`HCRTM_PCR` in `TpmProfile_Misc.h`). `TPM2_PCR_Allocate` requires that at
/// least one bank keeps it allocated.
const HCRTM_PCR: usize = 0;

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

/// Allowed localities mask for PCR Reset operations (`resetLocality` of `s_initAttributes` in the
/// C reference `PlatformPcr.c`).
///
/// Each index corresponds to a PCR index, and the value is a bitmask of localities (0-4) allowed
/// to perform resets. PCRs 17-19 are DRTM PCRs resettable only by locality 4 and PCRs 20-22 by
/// localities 2 and 4. Because this TPM implements DRTM, `TPM2_PCR_Reset` is never allowed from
/// locality 4 (`PCRIsResetAllowed`), so PCRs 17-19 cannot be reset by the command at all.
const PCR_RESET_LOCALITY: [u8; 24] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0 - 7
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8 - 15
    0x0F, // 16
    0x10, // 17
    0x10, // 18
    0x10, // 19
    0x14, // 20
    0x14, // 21
    0x14, // 22
    0x0F, // 23
];

/// Returns `true` if `pcr` belongs to the TCB group whose changes do not increment the PCR update
/// counter (`PCRBelongsTCBGroup`; PCRs 20-22 have `doNotIncrementPcrCounter` set in
/// `PlatformPcr.c` and `ENABLE_PCR_NO_INCREMENT == YES`).
pub(crate) fn pcr_belongs_tcb_group(pcr: u32) -> bool {
    (20..=22).contains(&pcr)
}

/// Returns `true` if `pcr` is state-saved on `TPM2_Shutdown(TPM_SU_STATE)` (`PCRIsStateSaved`;
/// PCRs 0-15 in `PlatformPcr.c`). Modifying such a PCR invalidates the orderly state.
pub(crate) fn pcr_is_state_saved(pcr: u32) -> bool {
    pcr < 16
}

/// Returns `true` if `alg` is a hash algorithm implemented by this TPM, i.e. advertised in
/// `TPM_CAP_ALGS` (the `HASH_COUNT` algorithms enumerated by `CryptHashGetAlgByIndex`).
fn is_implemented_hash(alg: TpmiAlgHash) -> bool {
    let alg = tpm2::Alg::from(alg);
    crate::handler::capability::IMPLEMENTED_ALGORITHMS
        .iter()
        .any(|&(implemented, _)| implemented == alg)
}

/// Iterates over the hash algorithms implemented by this TPM that have a PCR bank, in
/// ascending algorithm-ID order.
fn implemented_hashes() -> impl Iterator<Item = TpmiAlgHash> {
    PcrState::IMPLEMENTED_BANKS
        .iter()
        .copied()
        .filter(|&alg| is_implemented_hash(alg))
}

/// Returns the size of the PCR storage of this implementation (`sizeof(s_pcrs)`): every
/// implemented PCR in the bank of every implemented hash algorithm.
fn pcr_storage_size() -> u32 {
    let per_pcr: usize = implemented_hashes().map(|alg| alg.digest_size()).sum();
    (per_pcr as u32) * IMPLEMENTATION_PCR
}

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Records that PCR `pcr` changed (`PCRChanged`): increments the PCR update counter unless
    /// the PCR belongs to the TCB group (PCRs 20-22).
    pub(crate) fn pcr_changed(&mut self, pcr: u32) {
        if pcr == 0 || !pcr_belongs_tcb_group(pcr) {
            self.global_state.pcrs.update_counter =
                self.global_state.pcrs.update_counter.wrapping_add(1);
        }
    }

    /// Extends `data` into PCR `pcr` of bank `alg` if that PCR is allocated (`PCRExtend`).
    ///
    /// Unallocated PCRs are silently skipped. Every bank that is actually extended counts as a
    /// change for the PCR update counter, as in the C reference.
    pub(crate) fn pcr_extend_bank(
        &mut self,
        pcr: u32,
        alg: TpmiAlgHash,
        data: &[u8],
    ) -> Result<(), TpmRc> {
        if !self.global_state.pcrs.is_allocated(alg, pcr as usize) {
            return Ok(());
        }
        let size = alg.digest_size();
        let mut old = [0u8; 64];
        old[..size].copy_from_slice(
            self.global_state
                .pcrs
                .value(alg, pcr as usize)
                .ok_or(TpmRc::FAILURE)?,
        );
        let (new_hash, _) = self.compute_hash(alg, &[&old[..size], data])?;
        self.global_state
            .pcrs
            .value_mut(alg, pcr as usize)
            .ok_or(TpmRc::FAILURE)?
            .copy_from_slice(&new_hash[..size]);
        self.pcr_changed(pcr);
        Ok(())
    }

    /// Checks that the current locality may extend `pcr` (`PCRIsExtendAllowed`).
    pub(crate) fn pcr_is_extend_allowed(&self, pcr: u32) -> bool {
        let locality = self.global_state.locality;
        locality <= 4 && (PCR_EXTEND_LOCALITY[pcr as usize] & (1 << locality)) != 0
    }

    /// Handles the [TpmCc::PCRRead] (`0x17e`) command.
    ///
    /// # Description
    /// This command reads the current value of the selected PCR banks and indices.
    ///
    /// As in the C reference (`PCRRead`), the selections are processed in the order given by the
    /// caller, every selection is filtered against the active PCR allocation (`FilterPcr`), and at
    /// most `TPML_DIGEST` capacity (8) values are returned; bits of PCRs that are not returned are
    /// cleared in `pcrSelectionOut`.
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
        let mut full = false;

        for in_sel in cmd.pcr_selection_in.pcr_selections() {
            let hash_alg = in_sel.hash();
            let filtered = self.global_state.pcrs.filter_selection(in_sel);
            let sizeof_select = filtered.sizeof_select() as usize;
            let mut out_bits = [0u8; tpm2::TPM2_PCR_SELECT_MAX as usize];
            if !full {
                out_bits[..sizeof_select].copy_from_slice(filtered.pcr_select());
                for pcr in 0..IMPLEMENTATION_PCR as usize {
                    let byte_idx = pcr / 8;
                    let mask = 1u8 << (pcr % 8);
                    if byte_idx >= sizeof_select || out_bits[byte_idx] & mask == 0 {
                        continue;
                    }
                    if pcr_values.count() >= tpm2::TPML_DIGEST_MAX_DIGESTS {
                        // The output list is full: clear the rest of this selection (and, below,
                        // every following selection) so `pcrSelectionOut` matches the values.
                        for rest in pcr..IMPLEMENTATION_PCR as usize {
                            if rest / 8 < sizeof_select {
                                out_bits[rest / 8] &= !(1u8 << (rest % 8));
                            }
                        }
                        full = true;
                        break;
                    }
                    let value = self
                        .global_state
                        .pcrs
                        .value(hash_alg, pcr)
                        .ok_or(TpmRc::FAILURE)?;
                    let digest = Tpm2bDigest::from_bytes(value).map_err(|_| TpmRc::FAILURE)?;
                    pcr_values.add(&digest)?;
                }
            }

            let out_sel = TpmsPcrSelection::new(hash_alg, &out_bits[..sizeof_select])
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
    /// Banks in which the PCR is not allocated are skipped (`PCRExtend`), and extending a PCR of
    /// the TCB group (PCRs 20-22) does not increment the PCR update counter.
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

        // `TPMI_DH_PCR` admits only implemented PCRs (normally rejected during handle validation).
        if pcr_handle >= IMPLEMENTATION_PCR {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        if !self.pcr_is_extend_allowed(pcr_handle) {
            return Err(TpmRc::LOCALITY);
        }

        if pcr_is_state_saved(pcr_handle) {
            self.nv_clear_orderly()?;
        }

        for digest_val in cmd.digests.digests() {
            let alg = digest_val.hash_alg();
            self.pcr_extend_bank(pcr_handle, alg, digest_val.digest())?;
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PCREvent] (`0x130`) command.
    ///
    /// # Description
    /// This command hashes an input event data buffer with every implemented hash algorithm,
    /// returns all digests, and extends each digest into the corresponding bank of the selected
    /// PCR if it is allocated there (`TPM2_PCR_Event` in the C reference).
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

        let extend = pcr_handle != Handle::RH_NULL.0;
        if extend {
            // `TPMI_DH_PCR` admits only implemented PCRs (normally rejected during handle
            // validation).
            if pcr_handle >= IMPLEMENTATION_PCR {
                return Err(TpmRc::VALUE.with(Position::handle(1)));
            }
            if !self.pcr_is_extend_allowed(pcr_handle) {
                return Err(TpmRc::LOCALITY);
            }
            if pcr_is_state_saved(pcr_handle) {
                self.nv_clear_orderly()?;
            }
        }

        let event_data_buf = cmd.event_data.get_buffer();

        let mut hashes = [[0u8; 64]; PcrState::IMPLEMENTED_BANKS.len()];
        let mut algs = [TpmiAlgHash::DEFAULT_HASH; PcrState::IMPLEMENTED_BANKS.len()];
        let mut count = 0;
        for alg in implemented_hashes() {
            let (digest, _) = self.compute_hash(alg, &[event_data_buf])?;
            hashes[count] = digest;
            algs[count] = alg;
            count += 1;
            if extend {
                self.pcr_extend_bank(pcr_handle, alg, &digest[..alg.digest_size()])?;
            }
        }

        let mut digests = TpmlDigestValues::default();
        for (alg, hash) in algs.iter().zip(hashes.iter()).take(count) {
            let ha = TpmtHa::new(*alg, &hash[..alg.digest_size()]).ok_or(TpmRc::FAILURE)?;
            digests.add(&ha)?;
        }

        let rsp = responses::PCREvent { digests };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PCRReset] (`0x13d`) command.
    ///
    /// # Description
    /// This command resets a resettable PCR index to zero in every allocated bank.
    ///
    /// Whether the PCR may be reset depends only on its reset localities
    /// ([`PCR_RESET_LOCALITY`]) and the command locality (`PCRIsResetAllowed`); resets from
    /// locality 4 are never allowed because this TPM implements DRTM. Resetting a PCR of the TCB
    /// group (PCRs 20-22) does not increment the PCR update counter.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 22.8 (TPM2_PCR_Reset).
    ///
    /// # Relationships
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

        // `TPMI_DH_PCR` admits only implemented PCRs (normally rejected during handle validation).
        if pcr_handle >= IMPLEMENTATION_PCR {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        // `PCRIsResetAllowed`: a TPM that implements DRTM never allows a reset from locality 4.
        let locality = self.global_state.locality;
        if locality >= 4 || (PCR_RESET_LOCALITY[pcr_handle as usize] & (1 << locality)) == 0 {
            return Err(TpmRc::LOCALITY);
        }

        if pcr_is_state_saved(pcr_handle) {
            self.nv_clear_orderly()?;
        }

        // `PCRSetValue(pcrHandle, 0)`: zero the PCR in every bank in which it is allocated.
        for alg in implemented_hashes() {
            if self
                .global_state
                .pcrs
                .is_allocated(alg, pcr_handle as usize)
                && let Some(value) = self.global_state.pcrs.value_mut(alg, pcr_handle as usize)
            {
                value.fill(0);
            }
        }

        self.pcr_changed(pcr_handle);

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PCRAllocate] (`0x12B`) command.
    ///
    /// # Description
    /// This command is used to set the desired PCR allocation of PCR banks across supported hash algorithms.
    ///
    /// As in the C reference (`PCRAllocate`), the new allocation is built from the active one
    /// (banks that are not listed keep their current allocation, the last entry for a bank
    /// wins), must keep the H-CRTM PCR (0) and the DRTM PCR (17) allocated in at least one bank
    /// (`TPM_RC_PCR`), and is only written to NV ([`crate::engine::PCR_ALLOCATION_HANDLE`]): the
    /// active allocation is unchanged until the next `_TPM_Init`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 22.5 (TPM2_PCR_Allocate).
    ///
    /// # Relationships
    /// - Requires Platform Authorization (`TPM_RH_PLATFORM`).
    /// - The current allocation is reported via [TpmCc::GetCapability](capability.rs).
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

        self.return_if_nv_is_not_available()?;

        let mut selections = [TpmsPcrSelection::default(); tpm2::TPM2_NUM_PCR_BANKS as usize];
        let count = self.global_state.pcrs.pcr_allocation.count();
        for (i, sel) in self
            .global_state
            .pcrs
            .pcr_allocation
            .pcr_selections()
            .enumerate()
        {
            selections[i] = *sel;
        }

        // Every implemented bank is part of the allocation (possibly empty), so every requested
        // bank replaces an existing entry; anything else is an internal inconsistency.
        for in_sel in cmd.pcr_allocation.pcr_selections() {
            let idx = selections[..count]
                .iter()
                .position(|s| s.hash() == in_sel.hash())
                .ok_or(TpmRc::FAILURE)?;
            selections[idx] = *in_sel;
        }

        let is_selected = |sel: &TpmsPcrSelection, pcr: usize| {
            sel.pcr_select()
                .get(pcr / 8)
                .is_some_and(|b| b & (1 << (pcr % 8)) != 0)
        };
        let mut size_needed = 0u32;
        let mut has_hcrtm = false;
        let mut has_drtm = false;
        for sel in &selections[..count] {
            has_drtm |= is_selected(sel, DRTM_PCR);
            has_hcrtm |= is_selected(sel, HCRTM_PCR);
            let bits: u32 = sel.pcr_select().iter().map(|b| b.count_ones()).sum();
            size_needed += bits * sel.hash().digest_size() as u32;
        }
        if !has_hcrtm || !has_drtm {
            return Err(TpmRc::PCR);
        }

        let new_allocation =
            TpmlPcrSelection::from_slice(&selections[..count]).ok_or(TpmRc::FAILURE)?;
        self.write_nv_pcr_allocation(&new_allocation)?;
        self.global_state.pcr_reconfig = true;
        self.global_state.state_saved = false;

        let resp = responses::PCRAllocate {
            allocation_success: true,
            max_pcr: IMPLEMENTATION_PCR,
            size_needed,
            size_available: pcr_storage_size(),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &resp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Writes the NV copy of the PCR allocation (`NV_WRITE_PERSISTENT(pcrAllocated, ...)`),
    /// which becomes the active allocation at the next `_TPM_Init`.
    fn write_nv_pcr_allocation(&mut self, allocation: &TpmlPcrSelection) -> Result<(), TpmRc> {
        let mut buf = [0u8; TpmlPcrSelection::MAX_SIZE];
        let len = allocation.marshal(&mut buf);
        let handle = crate::engine::PCR_ALLOCATION_HANDLE;
        let mut storage = StorageManager::new(&mut *self.context.platform.storage);
        let _ = storage.undefine_space(handle);
        storage
            .define_space(handle, len as u16, 0)
            .map_err(|_| TpmRc::NV_SPACE)?;
        storage
            .write_item(handle, 0, &buf[..len])
            .map_err(|_| TpmRc::FAILURE)?;
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

        // `TPMI_DH_PCR` admits only implemented PCRs (normally rejected during handle validation).
        if pcr_handle >= IMPLEMENTATION_PCR {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        // Only PCRs belonging to an authorization group (PCR 20-22) allow an authValue; the C
        // reference returns a bare `TPM_RC_VALUE` here.
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
    /// PCRs 20, 21, and 22 share a common policy group (`gp.pcrPolicies`). The policy is
    /// NV-persistent, so NV must be available (`RETURN_IF_NV_IS_NOT_AVAILABLE`).
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

        self.return_if_nv_is_not_available()?;

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
