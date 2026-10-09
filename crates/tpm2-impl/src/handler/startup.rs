use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

/// Custom value matching the TCG reference code implementation indicating that no orderly shutdown
/// state is currently saved.
const SU_NONE_VALUE: u16 = 0xFFFF;

/// Custom value matching the TCG reference code implementation indicating that the dictionary attack
/// lockout parameters were updated before shutdown.
const SU_DA_USED_VALUE: u16 = 0xFFFF - 1;

/// Flag bit matching the TCG reference code implementation. It is combined with the orderly
/// state representation in NV storage to indicate that the TPM has not yet received a startup
/// command (`_TPM_Init`).
const PRE_STARTUP_FLAG: u16 = 0x8000;

/// Flag bit matching the TCG reference code implementation. It is combined with the orderly
/// state representation in NV storage to indicate that the startup command was processed at Locality 3.
const STARTUP_LOCALITY_3: u16 = 0x4000;

/// `TPM_SU_CLEAR`.
const TPM_SU_CLEAR: u16 = 0x0000;

/// `TPM_SU_STATE`.
const TPM_SU_STATE: u16 = 0x0001;

fn is_orderly(value: u16) -> bool {
    value < SU_DA_USED_VALUE
}

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    pub(crate) fn nv_sync_persistent_reset_count(&mut self) -> Result<(), TpmRc> {
        self.context
            .platform
            .storage
            .write_nv(0, &self.global_state.reset_count.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }
    fn nv_sync_persistent_total_reset_count(&mut self) -> Result<(), TpmRc> {
        self.context
            .platform
            .storage
            .write_nv(8, &self.global_state.total_reset_count.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }
    pub(crate) fn nv_sync_persistent_orderly_state(&mut self) -> Result<(), TpmRc> {
        self.context
            .platform
            .storage
            .write_nv(4, &self.global_state.orderly_state.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }

    /// Persists the monotonic NV `max_counter` (`s_maxCounter`, 8 bytes at offset 16) to non-volatile storage.
    pub(crate) fn nv_sync_persistent_max_counter(&mut self) -> Result<(), TpmRc> {
        self.context
            .platform
            .storage
            .write_nv(16, &self.global_state.max_counter.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }

    /// Loads the monotonic NV `max_counter` (`s_maxCounter`, 8 bytes at offset 16) from non-volatile storage.
    pub(crate) fn nv_load_persistent_max_counter(&mut self) -> Result<(), TpmRc> {
        let mut buf = [0u8; 8];
        if self.context.platform.storage.read_nv(16, &mut buf).is_ok() {
            let nv_val = u64::from_be_bytes(buf);
            if nv_val > self.global_state.max_counter {
                self.global_state.max_counter = nv_val;
            }
        }
        Ok(())
    }

    /// Marks the TPM orderly state (`gp.orderlyState`) to be cleared at the end of command execution
    /// (`NvClearOrderly()` in `NV_spt.c`). Fails with `TPM_RC_NV_UNAVAILABLE` if the TPM is currently
    /// in an orderly state (`< SU_DA_USED_VALUE`) and NV storage is unavailable.
    pub(crate) fn nv_clear_orderly(&mut self) -> Result<(), TpmRc> {
        if self.global_state.orderly_state < SU_DA_USED_VALUE && !self.global_state.nv_available {
            return Err(TpmRc::NV_UNAVAILABLE);
        }
        self.global_state.clear_orderly = true;
        Ok(())
    }

    /// Fails with `TPM_RC_NV_UNAVAILABLE` if NV storage is currently unavailable, regardless of the
    /// orderly state (`RETURN_IF_NV_IS_NOT_AVAILABLE` in `NV.h`).
    ///
    /// Unlike [`Self::nv_clear_orderly`] (`RETURN_IF_ORDERLY`), which only needs NV when the orderly
    /// flag still has to be cleared, this check must be used by every command that writes persistent
    /// state to NV (hierarchy auths/policies/seeds, DA parameters, `disableClear`, the clock, ...).
    /// It does not modify the orderly state.
    pub(crate) fn return_if_nv_is_not_available(&self) -> Result<(), TpmRc> {
        if !self.global_state.nv_available {
            return Err(TpmRc::NV_UNAVAILABLE);
        }
        Ok(())
    }

    /// Persists the monotonic `time_epoch` counter (8 bytes at offset 24) to non-volatile storage.
    ///
    /// This ensures that time-bound authorization sessions and policy tickets (`TPMT_TK_AUTH`)
    /// from previous power cycles or resets are permanently invalidated and cannot be replayed
    /// across cold reboots (`TPM Reset` / `TPM Restart`).
    fn nv_sync_persistent_time_epoch(&mut self) -> Result<(), TpmRc> {
        self.context
            .platform
            .storage
            .write_nv(24, &self.global_state.time_epoch.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }

    /// Persists the dictionary attack `failed_tries` counter (4 bytes at offset 32) to non-volatile storage.
    pub(crate) fn nv_sync_persistent_failed_tries(&mut self) -> Result<(), TpmRc> {
        self.context
            .platform
            .storage
            .write_nv(32, &self.global_state.failed_tries.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }

    /// Persists the internal SP800-90A CTR_DRBG state (`go.drbgState`, 76 bytes at offset 36) to non-volatile storage.
    pub(crate) fn nv_sync_persistent_drbg_state(&mut self) -> Result<(), TpmRc> {
        self.context
            .platform
            .storage
            .write_nv(36, &self.global_state.drbg_state.to_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }

    /// Loads the internal SP800-90A CTR_DRBG state (`go.drbgState`, 76 bytes at offset 36) from non-volatile storage.
    pub(crate) fn nv_load_persistent_drbg_state(&mut self) -> Result<(), TpmRc> {
        let mut buf = [0u8; 76];
        if self.context.platform.storage.read_nv(36, &mut buf).is_ok() {
            self.global_state.drbg_state = crate::engine::DrbgState::from_bytes(&buf);
        }
        Ok(())
    }

    /// Persists the dictionary attack recovery timers (`go.selfHealTimer`, `go.lockoutTimer`, 16 bytes at offset 112) to non-volatile storage.
    pub(crate) fn nv_sync_persistent_da_timers(&mut self) -> Result<(), TpmRc> {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&self.global_state.self_heal_timer.to_be_bytes());
        buf[8..16].copy_from_slice(&self.global_state.lockout_timer.to_be_bytes());
        self.context
            .platform
            .storage
            .write_nv(112, &buf)
            .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }

    /// Loads the dictionary attack recovery timers (`go.selfHealTimer`, `go.lockoutTimer`, 16 bytes at offset 112) from non-volatile storage.
    pub(crate) fn nv_load_persistent_da_timers(&mut self) -> Result<(), TpmRc> {
        let mut buf = [0u8; 16];
        if self.context.platform.storage.read_nv(112, &mut buf).is_ok() {
            let mut sh_bytes = [0u8; 8];
            let mut lo_bytes = [0u8; 8];
            sh_bytes.copy_from_slice(&buf[0..8]);
            lo_bytes.copy_from_slice(&buf[8..16]);
            self.global_state.self_heal_timer = i64::from_be_bytes(sh_bytes);
            self.global_state.lockout_timer = i64::from_be_bytes(lo_bytes);
        }
        Ok(())
    }

    /// Handles the [TpmCc::Startup] (`0x144`) command.
    ///
    /// # Description
    /// This command is the first command that must be executed after a power-on or platform reset (`_TPM_Init`).
    /// It initializes the internal TPM state and selects the startup behavior (either `SU_CLEAR` or `SU_STATE`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 9.3 (TPM2_Startup).
    ///
    /// # Relationships
    /// - Must be executed after a hardware reset and [TpmCc::Shutdown](shutdown.rs) before any other commands can be executed.
    /// - If `startup_type` is `SU_STATE`, the TPM attempts to restore volatile state (such as active authorization sessions)
    ///   saved by [TpmCc::Shutdown](shutdown.rs) with `SU_STATE`.
    /// - If `startup_type` is `SU_CLEAR`, volatile state is discarded, and PCRs are reset.
    pub fn startup(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        // A second TPM2_Startup is rejected before its parameters are examined (`ExecCommand.c`).
        if self.global_state.initialized {
            return Err(TpmRc::INITIALIZE);
        }

        let mut request = request_response;
        let startup_type = request
            .try_unmarshal::<u16>()
            .map_err(|e| e.with_position(Position::parameter(1)))?;
        // `TPM_SU_Unmarshal` only accepts TPM_SU_CLEAR and TPM_SU_STATE; this is a parameter
        // unmarshaling error, reported before any NV or locality check of the command action.
        if startup_type != TPM_SU_CLEAR && startup_type != TPM_SU_STATE {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Validate startup rules & handle flags/localities
        let prev_orderly_state = self.validate_startup_state(startup_type)?;

        self.global_state.orderly_state = prev_orderly_state;
        self.global_state.prev_orderly_state = prev_orderly_state;

        // Select the startup kind (`Startup.c`): TPM Restart / Resume require a previous
        // Shutdown(STATE) whose saved state was recovered (`g_nvOk`); Shutdown(CLEAR) followed by
        // Startup(CLEAR), no orderly shutdown, or unrecoverable state data is a TPM Reset.
        let kind = if prev_orderly_state == TPM_SU_STATE && self.global_state.g_nv_ok {
            if startup_type == TPM_SU_STATE {
                StartupKind::Resume
            } else {
                StartupKind::Restart
            }
        } else {
            StartupKind::Reset
        };

        self.nv_load_persistent_max_counter()?;

        if is_orderly(prev_orderly_state) {
            self.nv_load_persistent_da_timers()?;
        }

        // 2. Perform state updates on reset/restart counters
        self.perform_startup_state_transition(kind, prev_orderly_state)?;

        // 3. Restore and reseed or instantiate DRBG state (`CryptRandStartup`)
        if is_orderly(prev_orderly_state) {
            self.nv_load_persistent_drbg_state()?;
        }
        if is_orderly(prev_orderly_state)
            && self.global_state.drbg_state.magic == crate::engine::DRBG_MAGIC
        {
            self.global_state
                .drbg_state
                .reseed(self.context.platform.rng)?;
        } else {
            self.global_state
                .drbg_state
                .instantiate(self.context.platform.rng)?;
        }
        self.nv_sync_persistent_drbg_state()?;

        // `TimeStartup`: after an unorderly shutdown the clock may have rolled back.
        if !is_orderly(prev_orderly_state) {
            self.global_state.clock_safe = false;
        }

        self.global_state.orderly_state = SU_NONE_VALUE;
        self.nv_sync_persistent_orderly_state()?;
        self.global_state.power_was_lost = false;
        self.global_state.pcr_reconfig = false;

        self.global_state.initialized = true;

        // `HierarchyStartup`: phEnable is SET on any startup. On TPM Reset / Restart the
        // platform authorization is cleared and the other hierarchies are enabled; on TPM Resume
        // the saved `STATE_CLEAR_DATA` values are kept.
        self.global_state.ph_enable = true;
        if kind != StartupKind::Resume {
            self.global_state.sh_enable = true;
            self.global_state.eh_enable = true;
            self.global_state.ph_enable_nv = true;
            self.global_state.platform_auth = crate::owned::OwnedAuth::default();
            self.global_state.platform_policy = crate::owned::OwnedDigest::default();
            self.global_state.platform_alg = None;

            // `PCRStartup`: PCRs (and their authValues) are only preserved on TPM Resume.
            self.global_state.pcr_auth_value = crate::owned::OwnedAuth::default();
            let saved_pcr0_sha1 = self.global_state.pcrs.sha1[0];
            let saved_pcr0_sha256 = self.global_state.pcrs.sha256[0];
            let saved_pcr0_sha384 = self.global_state.pcrs.sha384[0];
            let saved_update_counter = self.global_state.pcrs.update_counter;
            self.global_state.pcrs.reset();
            if self.global_state.drtm_pre_startup {
                self.global_state.pcrs.sha1[0] = saved_pcr0_sha1;
                self.global_state.pcrs.sha256[0] = saved_pcr0_sha256;
                self.global_state.pcrs.sha384[0] = saved_pcr0_sha384;
                self.global_state.pcrs.update_counter = saved_update_counter;
            }
        }
        // `SessionStartup`: saved session contexts survive TPM Restart and Resume, but not a
        // TPM Reset. Loaded sessions never survive.
        if kind == StartupKind::Reset {
            for sess in self.global_state.saved_sessions.iter_mut() {
                *sess = None;
            }
        }
        for obj in self.global_state.transient_objects.iter_mut() {
            *obj = None;
        }
        for p in self.global_state.transient_parents.iter_mut() {
            *p = None;
        }
        self.global_state.next_transient_index = 0;
        for sess in self.global_state.active_sessions.iter_mut() {
            *sess = None;
        }
        for seq in self.global_state.active_sequences.iter_mut() {
            *seq = None;
        }
        self.global_state.drtm_handle = tpm2::Handle::RH_UNASSIGNED.0;

        // `NvEntityStartup`: clear the per-boot NV index attributes (not on TPM Resume).
        if kind != StartupKind::Resume {
            self.nv_entity_startup(kind == StartupKind::Reset)?;
        }

        // The saved TPM_SU_STATE data has been consumed (or is stale): release its NV space.
        self.context.delete_state_data();

        // Read the platform unique value that is used as VENDOR_PERMANENT (`g_platformUniqueDetails`).
        // Matches `_plat__GetUnique(1, sizeof(g_platformUniqueDetails.t.buffer), g_platformUniqueDetails.t.buffer)` in `StartupCommands.c` / `Unique.c`.
        if self.global_state.platform_unique_details.get_size() == 0 {
            const NOT_REALLY_UNIQUE: &[u8] = b"This is not really a unique value. A real unique value should be generated by the platform.";
            let mut buf = [0u8; 48];
            let mut i = 0;
            while i < 48 {
                buf[47 - i] = NOT_REALLY_UNIQUE[i];
                i += 1;
            }
            if let Ok(auth) = crate::owned::OwnedAuth::from_bytes(&buf) {
                self.global_state.platform_unique_details = auth;
            }
        }

        let _response = request.into_response();
        Ok(())
    }

    /// Validates NV availability, locality, and orderly flags (the input validation of
    /// `TPM2_Startup` in `Startup.c`) and returns the previous orderly state with the startup
    /// modifier flags removed (`g_prevOrderlyState`).
    fn validate_startup_state(&mut self, startup_type: u16) -> Result<u16, TpmRc> {
        // The command needs NV update (`RETURN_IF_NV_IS_NOT_AVAILABLE`).
        self.return_if_nv_is_not_available()?;

        let mut locality = self.global_state.locality;

        if locality != 0 && locality != 3 {
            return Err(TpmRc::LOCALITY);
        }
        // If there was an H-CRTM, treat the startup as being at locality 0.
        if self.global_state.drtm_pre_startup {
            locality = 0;
        }
        self.global_state.startup_locality_3 = locality == 3;

        self.global_state.da_used = self.global_state.orderly_state == SU_DA_USED_VALUE;
        if self.global_state.da_used {
            self.global_state.orderly_state = SU_NONE_VALUE;
        }

        let mut prev_orderly_state = self.global_state.orderly_state;

        if is_orderly(prev_orderly_state) {
            prev_orderly_state &= !(PRE_STARTUP_FLAG | STARTUP_LOCALITY_3);
        }

        if startup_type == TPM_SU_STATE {
            // There must have been a prior TPM2_Shutdown(STATE).
            if prev_orderly_state != TPM_SU_STATE {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
            // The state saved by TPM2_Shutdown(STATE) must have been recovered.
            if !self.global_state.g_nv_ok {
                return Err(TpmRc::NV_UNINITIALIZED);
            }
            // For Resume, the H-CRTM has to be the same as the previous boot.
            if self.global_state.drtm_pre_startup
                != ((self.global_state.orderly_state & PRE_STARTUP_FLAG) != 0)
            {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
            if self.global_state.startup_locality_3
                != ((self.global_state.orderly_state & STARTUP_LOCALITY_3) != 0)
            {
                return Err(TpmRc::LOCALITY);
            }
        }

        Ok(prev_orderly_state)
    }

    /// Transitions reset_count, restart_count, and total_reset_count based on the startup kind.
    fn perform_startup_state_transition(
        &mut self,
        kind: StartupKind,
        prev_orderly_state: u16,
    ) -> Result<(), TpmRc> {
        let current_timer = self.context.platform.timer.timer_read();
        self.global_state.clock_offset = self
            .global_state
            .clock_offset
            .wrapping_add(self.global_state.tpm_time_ms as i64);
        if !is_orderly(prev_orderly_state) {
            self.global_state.self_heal_timer = 0;
            self.global_state.lockout_timer = 0;
            self.global_state.tpm_time_ms = 0;
            self.global_state.last_timer_read_ms = Some(current_timer);
        } else {
            self.global_state.self_heal_timer = self
                .global_state
                .self_heal_timer
                .saturating_sub(self.global_state.tpm_time_ms as i64);
            self.global_state.lockout_timer = self
                .global_state
                .lockout_timer
                .saturating_sub(self.global_state.tpm_time_ms as i64);
            self.global_state.tpm_time_ms = 0;
            self.global_state.last_timer_read_ms = Some(current_timer);
        }

        if self.global_state.lockout_recovery == 0 && !self.global_state.lockout_auth_enabled {
            self.global_state.lockout_auth_enabled = true;
            // NV_SYNC_PERSISTENT(lockOutAuthEnabled)
            self.context.save_hierarchy_auths(self.global_state);
        }

        if self.global_state.recovery_time != 0
            && self.global_state.failed_tries < self.global_state.max_tries
            && !is_orderly(prev_orderly_state)
            && self.global_state.da_used
        {
            self.global_state.failed_tries = self.global_state.failed_tries.saturating_add(1);
            self.global_state.da_used = false;
            self.nv_sync_persistent_failed_tries()?;
        }

        match kind {
            StartupKind::Resume => {
                self.global_state.restart_count += 1;
            }
            StartupKind::Restart => {
                self.global_state.clear_count += 1;
                self.global_state.restart_count += 1;
                self.global_state.time_epoch = self.global_state.time_epoch.wrapping_add(1);
                self.nv_sync_persistent_time_epoch()?;
            }
            StartupKind::Reset => {
                // `HierarchyStartup`: nullProof and nullSeed are regenerated on every TPM Reset.
                self.context
                    .platform
                    .rng
                    .get_random(&mut self.global_state.null_seed[..64])
                    .map_err(|_| TpmRc::FAILURE)?;
                self.global_state.null_seed_size = 64;

                self.context
                    .platform
                    .rng
                    .get_random(&mut self.global_state.null_proof[..64])
                    .map_err(|_| TpmRc::FAILURE)?;
                self.global_state.null_proof_size = 64;

                // `CryptStartup(SU_RESET)`: a new secret commit nonce is generated and all
                // outstanding commitments are dropped, so commit values (`r`) are
                // unpredictable and never repeat across TPM Resets.
                self.context
                    .platform
                    .rng
                    .get_random(&mut self.global_state.commit_nonce)
                    .map_err(|_| TpmRc::FAILURE)?;
                self.global_state.commit_counter = 0;
                self.global_state.commit_array = [0u8; 16];

                self.global_state.object_context_id = 0;
                self.global_state.clear_count = 0;
                self.global_state.reset_count += 1;
                self.nv_sync_persistent_reset_count()?;

                self.global_state.total_reset_count = self
                    .global_state
                    .total_reset_count
                    .checked_add(1)
                    .ok_or(TpmRc::FAILURE)?;
                self.nv_sync_persistent_total_reset_count()?;
                self.global_state.restart_count = 0;

                self.global_state.time_epoch = self.global_state.time_epoch.wrapping_add(1);
                self.nv_sync_persistent_time_epoch()?;
            }
        }
        Ok(())
    }

    /// Applies the per-boot NV index attribute rules to every defined NV index
    /// (`NvEntityStartup` / `NvSetStartupAttributes` in `NvDynamic.c`); called on TPM Reset and
    /// TPM Restart, not on TPM Resume:
    /// - `TPMA_NV_READLOCKED` is cleared;
    /// - for non-counter indices, `TPMA_NV_WRITTEN` is cleared if `TPMA_NV_CLEAR_STCLEAR` is SET,
    ///   or if `TPMA_NV_ORDERLY` is SET and this is a TPM Reset;
    /// - `TPMA_NV_WRITELOCKED` is cleared if the index is unwritten or lacks
    ///   `TPMA_NV_WRITEDEFINE`.
    fn nv_entity_startup(&mut self, is_reset: bool) -> Result<(), TpmRc> {
        use crate::storage::Tpm2Storage;
        use tpm2::{Marshal, TpmaNv};
        const HEADER_MAX: usize = tpm2::Tpm2bAuth::MAX_SIZE + tpm2::Tpm2bNvPublic::MAX_SIZE;
        let mut storage =
            crate::storage::manager::StorageManager::new(&mut *self.context.platform.storage);
        let toc = storage.read_toc().map_err(|_| TpmRc::FAILURE)?;
        for item in toc.iter().filter(|item| item.in_use != 0) {
            if (item.handle >> 24) != tpm2::TpmHt::NVIndex as u32 {
                continue;
            }
            let read_len = core::cmp::min(item.data_size as usize, HEADER_MAX);
            let mut buf = [0u8; HEADER_MAX];
            if storage
                .read_item(item.handle, 0, &mut buf[..read_len])
                .is_err()
            {
                continue;
            }
            let Ok((_, nv_public, nv_auth, _)) =
                crate::handler::nv_storage::unmarshal_nv_header(&buf[..read_len])
            else {
                continue;
            };
            let original = nv_public.attributes;
            let mut attributes = original;
            attributes.remove(TpmaNv::READLOCKED);
            let is_counter = attributes.get_index_type() == Ok(tpm2::TpmNt::Counter);
            if !is_counter
                && (attributes.contains(TpmaNv::CLEAR_STCLEAR)
                    || (attributes.contains(TpmaNv::ORDERLY) && is_reset))
            {
                attributes.remove(TpmaNv::WRITTEN);
            }
            if !attributes.contains(TpmaNv::WRITTEN) || !attributes.contains(TpmaNv::WRITEDEFINE) {
                attributes.remove(TpmaNv::WRITELOCKED);
            }
            if attributes == original {
                continue;
            }
            let mut updated_public = nv_public;
            updated_public.attributes = attributes;
            let mut write_buf = [0u8; HEADER_MAX];
            let len = crate::handler::nv_storage::marshal_nv_header(
                &nv_auth,
                &updated_public.as_tpm2b(),
                &mut write_buf,
            )?;
            storage
                .write_item(item.handle, 0, &write_buf[..len])
                .map_err(|_| TpmRc::FAILURE)?;
        }
        Ok(())
    }
}

/// The three kinds of `TPM2_Startup` (`STARTUP_TYPE` in the C reference).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupKind {
    /// TPM Reset (`SU_RESET`): no orderly `TPM_SU_STATE` shutdown preceded this startup.
    Reset,
    /// TPM Restart (`SU_RESTART`): `TPM2_Shutdown(TPM_SU_STATE)` + `TPM2_Startup(TPM_SU_CLEAR)`.
    Restart,
    /// TPM Resume (`SU_RESUME`): `TPM2_Shutdown(TPM_SU_STATE)` + `TPM2_Startup(TPM_SU_STATE)`.
    Resume,
}
