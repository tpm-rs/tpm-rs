use crate::storage::{NvStorage, Tpm2Storage};
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{Clear, ClearHandles};
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

        let handles = request.try_unmarshal::<ClearHandles>()?;
        let auth_handle = handles.auth_handle.0;

        if auth_handle != Handle::RH_LOCKOUT.0 && auth_handle != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<Clear>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Ported from C reference implementation: TPMCmd/tpm/src/command/Hierarchy/Clear.c (lines 11-87)
        // if(gp.disableClear) return TPM_RCS_DISABLED + RC_Clear_authHandle;
        if self.global_state.disable_clear {
            return Err(TpmRc::DISABLED);
        }

        self.nv_clear_orderly()?;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        let mut new_sh_proof = [0u8; 64];
        let mut new_eh_proof = [0u8; 64];
        let mut new_sp_seed = [0u8; 64];

        self.context
            .platform
            .rng
            .get_random(&mut new_sh_proof)
            .map_err(|_| TpmRc::FAILURE)?;
        self.context
            .platform
            .rng
            .get_random(&mut new_eh_proof)
            .map_err(|_| TpmRc::FAILURE)?;
        self.context
            .platform
            .rng
            .get_random(&mut new_sp_seed)
            .map_err(|_| TpmRc::FAILURE)?;

        // All random generated successfully, now mutate state
        self.global_state.sh_enable = true;
        self.global_state.eh_enable = true;

        self.global_state.reset_count = 0;
        self.global_state.restart_count = 0;
        self.global_state.clear_count = self.global_state.clear_count.saturating_add(1);
        self.global_state.clock_offset = -(self.global_state.tpm_time_ms as i64);
        self.global_state.clock_rate_adjust = tpm2::TpmClockAdjust::NoChange;

        self.global_state.nv_locked = false;

        self.global_state.sh_proof.copy_from_slice(&new_sh_proof);
        self.global_state.sh_proof_size = 64;

        self.global_state.eh_proof.copy_from_slice(&new_eh_proof);
        self.global_state.eh_proof_size = 64;

        self.global_state.sp_seed.copy_from_slice(&new_sp_seed);
        self.global_state.sp_seed_size = 64;

        for slot in self.global_state.transient_objects.iter_mut() {
            if let Some(obj) = slot {
                if obj.hierarchy == Handle::RH_OWNER.0 || obj.hierarchy == Handle::RH_ENDORSEMENT.0
                {
                    *slot = None;
                }
            }
        }

        self.global_state.owner_auth = crate::owned::OwnedAuth::default();
        self.global_state.endorsement_auth = crate::owned::OwnedAuth::default();
        self.global_state.lockout_auth = crate::owned::OwnedAuth::default();
        self.global_state.owner_policy = crate::owned::OwnedDigest::default();
        self.global_state.endorsement_policy = crate::owned::OwnedDigest::default();
        self.global_state.lockout_policy = crate::owned::OwnedDigest::default();
        self.global_state.owner_alg = None;
        self.global_state.endorsement_alg = None;
        self.global_state.lockout_alg = None;
        self.global_state.pcr_auth_value = crate::owned::OwnedAuth::default();

        self.global_state.failed_tries = 0;
        self.global_state.max_tries = 3;
        self.global_state.recovery_time = 1000;
        self.global_state.lockout_recovery = 1000;
        self.global_state.lockout_auth_enabled = true;
        self.global_state.da_pending_on_nv = false;
        let _ = self.nv_sync_persistent_failed_tries();

        {
            let mut storage =
                crate::storage::manager::StorageManager::new(&mut *self.context.platform.storage);
            if let Ok(toc) = storage.read_toc() {
                let mut to_remove = [0u32; 64];
                let mut count = 0;
                for item in toc.iter() {
                    if item.in_use != 0 && count < 64 {
                        if (item.handle >> 24) == 0x01 {
                            if let Ok(meta) = storage.get_metadata(item.handle) {
                                if (meta.attributes & 0x40000000) == 0 {
                                    to_remove[count] = item.handle;
                                    count += 1;
                                }
                            }
                        } else if (item.handle >> 24) == (tpm2::TpmHt::Persistent as u8) as u32 {
                            to_remove[count] = item.handle;
                            count += 1;
                        }
                    }
                }
                for handle in &to_remove[..count] {
                    if (*handle >> 24) == 0x01 {
                        if let Ok(meta) = storage.get_metadata(*handle) {
                            let read_len = core::cmp::min(meta.data_size as usize, 1536);
                            let mut read_buf = [0u8; 1536];
                            if storage
                                .read_item(*handle, 0, &mut read_buf[..read_len])
                                .is_ok()
                            {
                                if let Ok((metadata_size, nv_public, _, _)) =
                                    crate::handler::nv_storage::unmarshal_nv_header(
                                        &read_buf[..read_len],
                                    )
                                {
                                    if nv_public.attributes.get_index_type()
                                        == Ok(tpm2::TpmNt::Counter)
                                        && nv_public.attributes.contains(tpm2::TpmaNv::WRITTEN)
                                        && read_len >= metadata_size + 8
                                    {
                                        let mut val_bytes = [0u8; 8];
                                        val_bytes.copy_from_slice(
                                            &read_buf[metadata_size..metadata_size + 8],
                                        );
                                        let val = u64::from_be_bytes(val_bytes);
                                        if val > self.global_state.max_counter {
                                            self.global_state.max_counter = val;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    let _ = storage.undefine_space(*handle);
                }
            }
        }

        self.nv_sync_persistent_max_counter()?;
        self.context.save_hierarchy_auths(self.global_state);

        Ok(())
    }
}
