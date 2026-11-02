use crate::handle_checks::{Tpmi, check};
use crate::storage::{NvStorage, Tpm2Storage};
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::Clear;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::Clear] (`0x126`) command.
    ///
    /// # Description
    /// This command resets the TPM to its default state. It generates new seeds for the storage
    /// and endorsement hierarchies, invalidating all keys created under them, clears all hierarchy
    /// authorization values (owner, endorsement, lockout), and flushes all transient objects.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 24.4 (TPM2_Clear).
    ///
    /// # Relationships
    /// - Authorization must be from either [Handle::RH_LOCKOUT] or [Handle::RH_PLATFORM].
    /// - Can be disabled/enabled via [TpmCc::ClearControl](clear_control.rs).
    pub fn clear(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<Clear>()?;
        let [auth_handle] = handles;
        check(auth_handle, Tpmi::RhClear, Position::handle(1))?;
        let auth_handle = auth_handle.0;

        if auth_handle != Handle::RH_LOCKOUT.0 && auth_handle != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal_command::<Clear>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Ported from C reference implementation: TPMCmd/tpm/src/command/Hierarchy/Clear.c.
        // The command needs NV update: RETURN_IF_NV_IS_NOT_AVAILABLE runs before the
        // `disableClear` check.
        self.return_if_nv_is_not_available()?;

        // if(gp.disableClear) return TPM_RC_DISABLED;
        if self.context.state.disable_clear {
            return Err(TpmRc::DISABLED);
        }

        self.nv_clear_orderly()?;

        let mut new_sh_proof = [0u8; 64];
        let mut new_eh_proof = [0u8; 64];
        let mut new_sp_seed = [0u8; 64];

        // The reference order (`Clear.c`): the new SPS, then shProof, then ehProof.
        self.context.random_platform(&mut new_sp_seed)?;
        self.context.random_platform(&mut new_sh_proof)?;
        self.context.random_platform(&mut new_eh_proof)?;

        // All random generated successfully, now mutate state
        self.context.state.sh_enable = true;
        self.context.state.eh_enable = true;

        // gp.resetCount = gr.restartCount = gr.clearCount = 0; gp.auditCounter = 0;
        self.context.state.reset_count = 0;
        self.context.state.restart_count = 0;
        self.context.state.clear_count = 0;
        self.context.state.audit_counter = 0;
        // go.clock = 0; go.clockSafe = YES;
        self.context.state.clock_offset = -(self.context.state.tpm_time_ms as i64);
        self.context.state.clock_safe = true;
        self.context.state.clock_rate_adjust = tpm2::TpmClockAdjust::NoChange;

        self.context.state.nv_locked = false;

        self.context.state.sh_proof.copy_from_slice(&new_sh_proof);
        self.context.state.sh_proof_size = 64;

        self.context.state.eh_proof.copy_from_slice(&new_eh_proof);
        self.context.state.eh_proof_size = 64;

        self.context.state.sp_seed.copy_from_slice(&new_sp_seed);
        self.context.state.sp_seed_size = 64;

        // Flush loaded objects in the storage and endorsement hierarchies.
        for (i, slot) in self.context.state.transient_objects.iter_mut().enumerate() {
            if let Some(obj) = slot
                && (crate::hierarchy::normalize(obj.hierarchy) == Handle::RH_OWNER.0
                    || crate::hierarchy::normalize(obj.hierarchy) == Handle::RH_ENDORSEMENT.0)
            {
                *slot = None;
                self.context.state.transient_parents[i] = None;
            }
        }

        self.context.state.owner_auth = crate::owned::OwnedAuth::default();
        self.context.state.endorsement_auth = crate::owned::OwnedAuth::default();
        self.context.state.lockout_auth = crate::owned::OwnedAuth::default();
        self.context.state.owner_policy = crate::owned::OwnedDigest::default();
        self.context.state.endorsement_policy = crate::owned::OwnedDigest::default();
        self.context.state.lockout_policy = crate::owned::OwnedDigest::default();
        self.context.state.owner_alg = None;
        self.context.state.endorsement_alg = None;
        self.context.state.lockout_alg = None;

        // Flush owner and endorsement evict objects and owner NV indices (`NvFlushHierarchy`).
        self.nv_flush_hierarchy(Handle::RH_OWNER.0)?;
        self.nv_flush_hierarchy(Handle::RH_ENDORSEMENT.0)?;

        // Initialize dictionary attack parameters (`DAPreInstall_Init`).
        self.context.state.failed_tries = 0;
        self.context.state.max_tries = 3;
        self.context.state.recovery_time = 1000;
        self.context.state.lockout_recovery = 1000;
        self.context.state.lockout_auth_enabled = true;
        self.context.state.da_pending_on_nv = false;
        self.nv_sync_persistent_failed_tries()?;

        // Save persistent data changes to NV.
        self.nv_sync_persistent_reset_count()?;
        self.nv_sync_persistent_max_counter()?;

        // Reset the PCR authValues (`PCR_ClearAuth`) and bump the PCR counter (`PCRChanged(0)`).
        self.context.state.pcr_auth_value = crate::owned::OwnedAuth::default();
        self.context.state.pcrs.update_counter =
            self.context.state.pcrs.update_counter.wrapping_add(1);

        self.context.save_hierarchy_auths();
        // `NvWrite(NV_ORDERLY_DATA, ...)` of `Clear.c` also persists the DRBG state.
        #[cfg(feature = "reference-rng")]
        self.context.save_drbg_state();

        // Only report success once every state and NV update has been performed.
        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Deletes the NV entities that belong to `hierarchy` (`NvFlushHierarchy` in `NvDynamic.c`).
    ///
    /// - Evict (persistent) objects are deleted when their stored hierarchy equals `hierarchy`.
    /// - NV indices are only deleted when flushing [`Handle::RH_OWNER`], and only those that were
    ///   not created by the platform (`TPMA_NV_PLATFORMCREATE` clear). Flushing the endorsement or
    ///   platform hierarchy never deletes NV indices.
    ///
    /// There is no limit on the number of deleted entities. Before deleting a written NV counter
    /// index, its value is folded into `max_counter` so that a later counter index can never
    /// reuse a smaller value.
    pub(crate) fn nv_flush_hierarchy(&mut self, hierarchy: u32) -> Result<(), TpmRc> {
        /// `TPMA_NV_PLATFORMCREATE`.
        const PLATFORMCREATE: u32 = 0x4000_0000;
        loop {
            // Find the next entity to delete, re-reading the TOC after every deletion (like the
            // C code re-iterates from the beginning after `NvDelete`).
            let toc = {
                let storage = crate::storage::manager::StorageManager::new(
                    &mut *self.context.platform.storage,
                );
                storage.read_toc().map_err(|_| TpmRc::FAILURE)?
            };
            let mut victim = None;
            for item in toc.iter().filter(|item| item.in_use != 0) {
                let handle_type = item.handle >> 24;
                if handle_type == tpm2::TpmHt::NVIndex as u32 {
                    if hierarchy != Handle::RH_OWNER.0 {
                        continue;
                    }
                    let storage = crate::storage::manager::StorageManager::new(
                        &mut *self.context.platform.storage,
                    );
                    if let Ok(meta) = storage.get_metadata(item.handle)
                        && (meta.attributes & PLATFORMCREATE) == 0
                    {
                        victim = Some(item.handle);
                        break;
                    }
                } else if handle_type == tpm2::TpmHt::Persistent as u32 {
                    // Only the stored hierarchy matters (`ppsHierarchy`/`spsHierarchy`/
                    // `epsHierarchy`); unlike loading an evict object, the hierarchy enables are
                    // not consulted.
                    if let Ok(obj) = self.context.read_persistent_object(item.handle)
                        && obj.hierarchy == hierarchy
                    {
                        victim = Some(item.handle);
                        break;
                    }
                }
            }
            let Some(handle) = victim else {
                return Ok(());
            };
            if (handle >> 24) == tpm2::TpmHt::NVIndex as u32 {
                self.fold_nv_counter_into_max_counter(handle);
            }
            let mut storage =
                crate::storage::manager::StorageManager::new(&mut *self.context.platform.storage);
            storage.undefine_space(handle).map_err(|_| TpmRc::FAILURE)?;
        }
    }

    /// If `handle` is a written NV counter index, raises `max_counter` to its current value.
    fn fold_nv_counter_into_max_counter(&mut self, handle: u32) {
        let storage =
            crate::storage::manager::StorageManager::new(&mut *self.context.platform.storage);
        let Ok(meta) = storage.get_metadata(handle) else {
            return;
        };
        let read_len = core::cmp::min(meta.data_size as usize, 1536);
        let mut read_buf = [0u8; 1536];
        if storage
            .read_item(handle, 0, &mut read_buf[..read_len])
            .is_ok()
            && let Ok((metadata_size, nv_public, _, _)) =
                crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len])
            && nv_public.attributes.get_index_type() == Ok(tpm2::TpmNt::Counter)
            && nv_public.attributes.contains(tpm2::TpmaNv::WRITTEN)
            && read_len >= metadata_size + 8
        {
            let mut val_bytes = [0u8; 8];
            val_bytes.copy_from_slice(&read_buf[metadata_size..metadata_size + 8]);
            let val = u64::from_be_bytes(val_bytes);
            if val > self.context.state.max_counter {
                self.context.state.max_counter = val;
            }
        }
    }
}
