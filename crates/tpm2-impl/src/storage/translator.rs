//! Bidirectional Live Migration State Translator (`TpmStateTranslator` & `Ibmswtpm2StateDto`).
//!
//! # Architectural Context
//! In vTPM live migration, the internal execution state of `ibmswtpm2` (version 974)
//! is serialized and deserialized as a structured map under key `"974"`.
//!
//! While [`super::transcoder`] transcodes the 16 KB non-volatile `s_NV` buffer for cold-boot
//! persistence, live migration requires preserving all 66 C global variables serialized
//! for `ibmswtpm2` version 974, including:
//! - Volatile PCR banks (`"s_pcrs"`, 2400 bytes)
//! - Loaded transient objects and active hash sequences (`"s_objects"`, 3612 bytes)
//! - Active authorization sessions (`"s_sessions"`, 792 bytes)
//! - Monotonic timers and uptime (`"g_time"`, `"s_tpmTime"`, `"s_selfHealTimer"`, `"s_lockoutTimer"`)
//! - Execution flags (`"g_DRTMHandle"`, `"g_updateNV"`, `"g_clearOrderly"`, `"s_DAPendingOnNV"`, etc.)
//! - In-memory C state structures (`"gp"`, `"go"`, `"gc"`, `"gr"`, `"s_indexOrderlyRam"`) and `"s_NV"`.
//!
//! This module provides [`Ibmswtpm2StateDto`] (representing the exact 66-key binary schema of `"974"`)
//! and [`TpmStateTranslator`] for lossless bidirectional translation between `tpm-rs`'s
//! [`GlobalState`] + [`NvStorage`] and the `"974"` DTO format.

use super::transcoder::{
    NV_INDEX_RAM_DATA_OFFSET, NV_MEMORY_SIZE, NV_ORDERLY_DATA_OFFSET, NV_PERSISTENT_DATA_OFFSET,
    NV_STATE_CLEAR_DATA_OFFSET, NV_STATE_RESET_DATA_OFFSET, transcode_s_nv_to_storage,
    transcode_storage_to_s_nv,
};
use super::{NvStorage, StorageError};
use crate::engine::{ActiveSequence, GlobalState, SequenceType};
use crate::handler::{SessionState, TransientObject};
use crate::hash_state::StreamingHashState;
use crate::owned::{
    OwnedAuth, OwnedDigest, OwnedName, OwnedNonce, OwnedPublic, OwnedSensitiveData,
};
use tpm2::{
    Handle, Marshal, Tpm2bAuth, Tpm2bName, Tpm2bNonce, TpmSe, TpmiAlgHash, TpmtPublic, TpmtSymDef,
    Unmarshal,
};

/// Size of `g_implementedAlgorithms` and `g_toTest` bitvectors in bytes.
pub const ALG_VECTOR_SIZE: usize = 9;
/// Size of `PERSISTENT_DATA gp` in bytes.
pub const GP_SIZE: usize = 792;
/// Size of `ORDERLY_DATA go` in bytes.
pub const GO_SIZE: usize = 96;
/// Size of `STATE_CLEAR_DATA gc` in bytes.
pub const GC_SIZE: usize = 1772;
/// Size of `STATE_RESET_DATA gr` in bytes.
pub const GR_SIZE: usize = 312;
/// Size of `s_indexOrderlyRam` in bytes.
pub const INDEX_ORDERLY_RAM_SIZE: usize = 512;
/// Size of `s_objects` in bytes (3 slots * 1204 bytes).
pub const S_OBJECTS_SIZE: usize = 3612;
/// Size of each object slot in `s_objects`.
pub const OBJECT_SLOT_SIZE: usize = 1204;
/// Size of `s_pcrs` in bytes (24 PCRs * 100 bytes).
pub const S_PCRS_SIZE: usize = 2400;
/// Size of each PCR entry in `s_pcrs` (SHA-1 20B + SHA-256 32B + SHA-384 48B).
pub const PCR_SLOT_SIZE: usize = 100;
/// Size of `s_sessions` in bytes (3 slots * 264 bytes).
pub const S_SESSIONS_SIZE: usize = 792;
/// Size of each session slot in `s_sessions`.
pub const SESSION_SLOT_SIZE: usize = 264;

/// Data Transfer Object (DTO) representing the exact 66 global variables serialized
/// under key `"974"`.
#[derive(Clone)]
pub struct Ibmswtpm2StateDto {
    pub g_implemented_algorithms: [u8; ALG_VECTOR_SIZE],
    pub g_to_test: [u8; ALG_VECTOR_SIZE],
    pub g_exclusive_audit_session: [u8; 4],
    pub g_time: [u8; 8],
    pub g_ph_enable: [u8; 4],
    pub g_pcr_re_config: [u8; 4],
    pub g_drtm_handle: [u8; 4],
    pub g_drtm_pre_startup: [u8; 4],
    pub g_startup_locality_3: [u8; 4],
    pub g_update_nv: [u8; 1],
    pub g_power_was_lost: [u8; 4],
    pub g_clear_orderly: [u8; 4],
    pub g_prev_orderly_state: [u8; 2],
    pub g_nv_ok: [u8; 4],
    pub g_nv_status: [u8; 4],
    pub g_platform_unique_details: [u8; 50],
    pub gp: [u8; GP_SIZE],
    pub go: [u8; GO_SIZE],
    pub gc: [u8; GC_SIZE],
    pub gr: [u8; GR_SIZE],
    pub g_manufactured: [u8; 4],
    pub g_initialized: [u8; 4],
    pub s_session_handles: [u8; 12],
    pub s_attributes: [u8; 12],
    pub s_associated_handles: [u8; 12],
    pub s_nonce_caller: [u8; 150],
    pub s_input_auth_values: [u8; 150],
    pub s_encrypt_session_index: [u8; 4],
    pub s_decrypt_session_index: [u8; 4],
    pub s_audit_session_index: [u8; 4],
    pub s_cp_hash_for_command_audit: [u8; 50],
    pub s_da_pending_on_nv: [u8; 4],
    pub s_self_heal_timer: [u8; 8],
    pub s_lockout_timer: [u8; 8],
    pub s_evict_nv_end: [u8; 4],
    pub s_index_orderly_ram: [u8; INDEX_ORDERLY_RAM_SIZE],
    pub s_max_counter: [u8; 8],
    pub s_cached_nv_index: [u8; 116],
    pub s_cached_nv_ref: [u8; 4],
    pub s_objects: [u8; S_OBJECTS_SIZE],
    pub s_pcrs: [u8; S_PCRS_SIZE],
    pub s_sessions: [u8; S_SESSIONS_SIZE],
    pub s_oldest_saved_session: [u8; 4],
    pub s_free_session_slots: [u8; 4],
    pub s_action_input_buffer: [u8; 4096],
    pub s_action_output_buffer: [u8; 4096],
    pub g_in_failure_mode: [u8; 4],
    pub g_force_failure_mode: [u8; 4],
    pub s_fail_function: [u8; 4],
    pub s_fail_line: [u8; 4],
    pub s_fail_code: [u8; 4],
    pub s_is_canceled: [u8; 1],
    pub s_real_time_previous: [u8; 8],
    pub s_tpm_time: [u8; 8],
    pub s_timer_reset: [u8; 4],
    pub s_timer_stopped: [u8; 4],
    pub s_adjust_rate: [u8; 4],
    pub s_locality: [u8; 1],
    pub s_nv: [u8; NV_MEMORY_SIZE],
    pub s_nv_is_available: [u8; 4],
    pub s_nv_unrecoverable: [u8; 4],
    pub s_nv_recoverable: [u8; 4],
    pub s_physical_presence: [u8; 4],
    pub s_power_lost: [u8; 4],
    pub g_crypto_self_test_state: [u8; 20],
    pub s_is_power_on: [u8; 4],
}

impl Default for Ibmswtpm2StateDto {
    fn default() -> Self {
        Self {
            g_implemented_algorithms: [0; ALG_VECTOR_SIZE],
            g_to_test: [0; ALG_VECTOR_SIZE],
            g_exclusive_audit_session: [0xFF; 4],
            g_time: [0; 8],
            g_ph_enable: 1i32.to_le_bytes(),
            g_pcr_re_config: [0; 4],
            g_drtm_handle: 0xFFFF_FFFFu32.to_le_bytes(),
            g_drtm_pre_startup: [0; 4],
            g_startup_locality_3: [0; 4],
            g_update_nv: [0],
            g_power_was_lost: [0; 4],
            g_clear_orderly: [0; 4],
            g_prev_orderly_state: 0xFFFFu16.to_le_bytes(),
            g_nv_ok: 1i32.to_le_bytes(),
            g_nv_status: [0; 4],
            g_platform_unique_details: [0; 50],
            gp: [0; GP_SIZE],
            go: [0; GO_SIZE],
            gc: [0; GC_SIZE],
            gr: [0; GR_SIZE],
            g_manufactured: 1i32.to_le_bytes(),
            g_initialized: 1i32.to_le_bytes(),
            s_session_handles: [0; 12],
            s_attributes: [0; 12],
            s_associated_handles: [0; 12],
            s_nonce_caller: [0; 150],
            s_input_auth_values: [0; 150],
            s_encrypt_session_index: [0; 4],
            s_decrypt_session_index: [0; 4],
            s_audit_session_index: [0; 4],
            s_cp_hash_for_command_audit: [0; 50],
            s_da_pending_on_nv: [0; 4],
            s_self_heal_timer: [0; 8],
            s_lockout_timer: [0; 8],
            s_evict_nv_end: [0; 4],
            s_index_orderly_ram: [0; INDEX_ORDERLY_RAM_SIZE],
            s_max_counter: [0; 8],
            s_cached_nv_index: [0; 116],
            s_cached_nv_ref: [0; 4],
            s_objects: [0; S_OBJECTS_SIZE],
            s_pcrs: [0; S_PCRS_SIZE],
            s_sessions: [0; S_SESSIONS_SIZE],
            s_oldest_saved_session: [0; 4],
            s_free_session_slots: 3i32.to_le_bytes(),
            s_action_input_buffer: [0; 4096],
            s_action_output_buffer: [0; 4096],
            g_in_failure_mode: [0; 4],
            g_force_failure_mode: [0; 4],
            s_fail_function: [0; 4],
            s_fail_line: [0; 4],
            s_fail_code: [0; 4],
            s_is_canceled: [0],
            s_real_time_previous: [0; 8],
            s_tpm_time: [0; 8],
            s_timer_reset: [0; 4],
            s_timer_stopped: [0; 4],
            s_adjust_rate: [0; 4],
            s_locality: [0],
            s_nv: [0; NV_MEMORY_SIZE],
            s_nv_is_available: 1i32.to_le_bytes(),
            s_nv_unrecoverable: [0; 4],
            s_nv_recoverable: [0; 4],
            s_physical_presence: [0; 4],
            s_power_lost: [0; 4],
            g_crypto_self_test_state: [0; 20],
            s_is_power_on: 1i32.to_le_bytes(),
        }
    }
}

impl Ibmswtpm2StateDto {
    /// Returns the binary slice corresponding to a serialized `"974"` state map key.
    pub fn get_field(&self, key: &str) -> Option<&[u8]> {
        match key {
            "g_implementedAlgorithms" => Some(&self.g_implemented_algorithms),
            "g_toTest" => Some(&self.g_to_test),
            "g_exclusiveAuditSession" => Some(&self.g_exclusive_audit_session),
            "g_time" => Some(&self.g_time),
            "g_phEnable" => Some(&self.g_ph_enable),
            "g_pcrReConfig" => Some(&self.g_pcr_re_config),
            "g_DRTMHandle" => Some(&self.g_drtm_handle),
            "g_DrtmPreStartup" => Some(&self.g_drtm_pre_startup),
            "g_StartupLocality3" => Some(&self.g_startup_locality_3),
            "g_updateNV" => Some(&self.g_update_nv),
            "g_powerWasLost" => Some(&self.g_power_was_lost),
            "g_clearOrderly" => Some(&self.g_clear_orderly),
            "g_prevOrderlyState" => Some(&self.g_prev_orderly_state),
            "g_nvOk" => Some(&self.g_nv_ok),
            "g_NvStatus" => Some(&self.g_nv_status),
            "g_platformUniqueDetails" => Some(&self.g_platform_unique_details),
            "gp" => Some(&self.gp),
            "go" => Some(&self.go),
            "gc" => Some(&self.gc),
            "gr" => Some(&self.gr),
            "g_manufactured" => Some(&self.g_manufactured),
            "g_initialized" => Some(&self.g_initialized),
            "s_sessionHandles" => Some(&self.s_session_handles),
            "s_attributes" => Some(&self.s_attributes),
            "s_associatedHandles" => Some(&self.s_associated_handles),
            "s_nonceCaller" => Some(&self.s_nonce_caller),
            "s_inputAuthValues" => Some(&self.s_input_auth_values),
            "s_encryptSessionIndex" => Some(&self.s_encrypt_session_index),
            "s_decryptSessionIndex" => Some(&self.s_decrypt_session_index),
            "s_auditSessionIndex" => Some(&self.s_audit_session_index),
            "s_cpHashForCommandAudit" => Some(&self.s_cp_hash_for_command_audit),
            "s_DAPendingOnNV" => Some(&self.s_da_pending_on_nv),
            "s_selfHealTimer" => Some(&self.s_self_heal_timer),
            "s_lockoutTimer" => Some(&self.s_lockout_timer),
            "s_evictNvEnd" => Some(&self.s_evict_nv_end),
            "s_indexOrderlyRam" => Some(&self.s_index_orderly_ram),
            "s_maxCounter" => Some(&self.s_max_counter),
            "s_cachedNvIndex" => Some(&self.s_cached_nv_index),
            "s_cachedNvRef" => Some(&self.s_cached_nv_ref),
            "s_objects" => Some(&self.s_objects),
            "s_pcrs" => Some(&self.s_pcrs),
            "s_sessions" => Some(&self.s_sessions),
            "s_oldestSavedSession" => Some(&self.s_oldest_saved_session),
            "s_freeSessionSlots" => Some(&self.s_free_session_slots),
            "s_actionInputBuffer" => Some(&self.s_action_input_buffer),
            "s_actionOutputBuffer" => Some(&self.s_action_output_buffer),
            "g_inFailureMode" => Some(&self.g_in_failure_mode),
            "g_forceFailureMode" => Some(&self.g_force_failure_mode),
            "s_failFunction" => Some(&self.s_fail_function),
            "s_failLine" => Some(&self.s_fail_line),
            "s_failCode" => Some(&self.s_fail_code),
            "s_isCanceled" => Some(&self.s_is_canceled),
            "s_realTimePrevious" => Some(&self.s_real_time_previous),
            "s_tpmTime" => Some(&self.s_tpm_time),
            "s_timerReset" => Some(&self.s_timer_reset),
            "s_timerStopped" => Some(&self.s_timer_stopped),
            "s_adjustRate" => Some(&self.s_adjust_rate),
            "s_locality" => Some(&self.s_locality),
            "s_NV" => Some(&self.s_nv),
            "s_NvIsAvailable" => Some(&self.s_nv_is_available),
            "s_NV_unrecoverable" => Some(&self.s_nv_unrecoverable),
            "s_NV_recoverable" => Some(&self.s_nv_recoverable),
            "s_physicalPresence" => Some(&self.s_physical_presence),
            "s_powerLost" => Some(&self.s_power_lost),
            "g_cryptoSelfTestState" => Some(&self.g_crypto_self_test_state),
            "s_isPowerOn" => Some(&self.s_is_power_on),
            _ => None,
        }
    }

    /// Sets the binary slice for a serialized `"974"` state map key.
    pub fn set_field(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        fn copy_exact(dst: &mut [u8], src: &[u8]) -> Result<(), StorageError> {
            if dst.len() != src.len() {
                return Err(StorageError::OutOfBounds);
            }
            dst.copy_from_slice(src);
            Ok(())
        }
        match key {
            "g_implementedAlgorithms" => copy_exact(&mut self.g_implemented_algorithms, value),
            "g_toTest" => copy_exact(&mut self.g_to_test, value),
            "g_exclusiveAuditSession" => copy_exact(&mut self.g_exclusive_audit_session, value),
            "g_time" => copy_exact(&mut self.g_time, value),
            "g_phEnable" => copy_exact(&mut self.g_ph_enable, value),
            "g_pcrReConfig" => copy_exact(&mut self.g_pcr_re_config, value),
            "g_DRTMHandle" => copy_exact(&mut self.g_drtm_handle, value),
            "g_DrtmPreStartup" => copy_exact(&mut self.g_drtm_pre_startup, value),
            "g_StartupLocality3" => copy_exact(&mut self.g_startup_locality_3, value),
            "g_updateNV" => copy_exact(&mut self.g_update_nv, value),
            "g_powerWasLost" => copy_exact(&mut self.g_power_was_lost, value),
            "g_clearOrderly" => copy_exact(&mut self.g_clear_orderly, value),
            "g_prevOrderlyState" => copy_exact(&mut self.g_prev_orderly_state, value),
            "g_nvOk" => copy_exact(&mut self.g_nv_ok, value),
            "g_NvStatus" => copy_exact(&mut self.g_nv_status, value),
            "g_platformUniqueDetails" => copy_exact(&mut self.g_platform_unique_details, value),
            "gp" => copy_exact(&mut self.gp, value),
            "go" => copy_exact(&mut self.go, value),
            "gc" => copy_exact(&mut self.gc, value),
            "gr" => copy_exact(&mut self.gr, value),
            "g_manufactured" => copy_exact(&mut self.g_manufactured, value),
            "g_initialized" => copy_exact(&mut self.g_initialized, value),
            "s_sessionHandles" => copy_exact(&mut self.s_session_handles, value),
            "s_attributes" => copy_exact(&mut self.s_attributes, value),
            "s_associatedHandles" => copy_exact(&mut self.s_associated_handles, value),
            "s_nonceCaller" => copy_exact(&mut self.s_nonce_caller, value),
            "s_inputAuthValues" => copy_exact(&mut self.s_input_auth_values, value),
            "s_encryptSessionIndex" => copy_exact(&mut self.s_encrypt_session_index, value),
            "s_decryptSessionIndex" => copy_exact(&mut self.s_decrypt_session_index, value),
            "s_auditSessionIndex" => copy_exact(&mut self.s_audit_session_index, value),
            "s_cpHashForCommandAudit" => copy_exact(&mut self.s_cp_hash_for_command_audit, value),
            "s_DAPendingOnNV" => copy_exact(&mut self.s_da_pending_on_nv, value),
            "s_selfHealTimer" => copy_exact(&mut self.s_self_heal_timer, value),
            "s_lockoutTimer" => copy_exact(&mut self.s_lockout_timer, value),
            "s_evictNvEnd" => copy_exact(&mut self.s_evict_nv_end, value),
            "s_indexOrderlyRam" => copy_exact(&mut self.s_index_orderly_ram, value),
            "s_maxCounter" => copy_exact(&mut self.s_max_counter, value),
            "s_cachedNvIndex" => copy_exact(&mut self.s_cached_nv_index, value),
            "s_cachedNvRef" => copy_exact(&mut self.s_cached_nv_ref, value),
            "s_objects" => copy_exact(&mut self.s_objects, value),
            "s_pcrs" => copy_exact(&mut self.s_pcrs, value),
            "s_sessions" => copy_exact(&mut self.s_sessions, value),
            "s_oldestSavedSession" => copy_exact(&mut self.s_oldest_saved_session, value),
            "s_freeSessionSlots" => copy_exact(&mut self.s_free_session_slots, value),
            "s_actionInputBuffer" => copy_exact(&mut self.s_action_input_buffer, value),
            "s_actionOutputBuffer" => copy_exact(&mut self.s_action_output_buffer, value),
            "g_inFailureMode" => copy_exact(&mut self.g_in_failure_mode, value),
            "g_forceFailureMode" => copy_exact(&mut self.g_force_failure_mode, value),
            "s_failFunction" => copy_exact(&mut self.s_fail_function, value),
            "s_failLine" => copy_exact(&mut self.s_fail_line, value),
            "s_failCode" => copy_exact(&mut self.s_fail_code, value),
            "s_isCanceled" => copy_exact(&mut self.s_is_canceled, value),
            "s_realTimePrevious" => copy_exact(&mut self.s_real_time_previous, value),
            "s_tpmTime" => copy_exact(&mut self.s_tpm_time, value),
            "s_timerReset" => copy_exact(&mut self.s_timer_reset, value),
            "s_timerStopped" => copy_exact(&mut self.s_timer_stopped, value),
            "s_adjustRate" => copy_exact(&mut self.s_adjust_rate, value),
            "s_locality" => copy_exact(&mut self.s_locality, value),
            "s_NV" => copy_exact(&mut self.s_nv, value),
            "s_NvIsAvailable" => copy_exact(&mut self.s_nv_is_available, value),
            "s_NV_unrecoverable" => copy_exact(&mut self.s_nv_unrecoverable, value),
            "s_NV_recoverable" => copy_exact(&mut self.s_nv_recoverable, value),
            "s_physicalPresence" => copy_exact(&mut self.s_physical_presence, value),
            "s_powerLost" => copy_exact(&mut self.s_power_lost, value),
            "g_cryptoSelfTestState" => copy_exact(&mut self.g_crypto_self_test_state, value),
            "s_isPowerOn" => copy_exact(&mut self.s_is_power_on, value),
            _ => Err(StorageError::OutOfBounds),
        }
    }
}

/// Bidirectional state translator bridging `tpm-rs`'s [`GlobalState`] + [`NvStorage`]
/// and the `ibmswtpm2` `"974"` [`Ibmswtpm2StateDto`] representation.
pub struct TpmStateTranslator;

impl TpmStateTranslator {
    /// Serializes `tpm-rs` [`GlobalState`] and [`NvStorage`] into an [`Ibmswtpm2StateDto`].
    pub fn serialize_state(
        global_state: &GlobalState,
        storage: &mut dyn NvStorage,
        dto: &mut Ibmswtpm2StateDto,
    ) -> Result<(), StorageError> {
        // 1. Transcode persistent StorageManager state into `dto.s_nv`.
        transcode_storage_to_s_nv(storage, &mut dto.s_nv)?;

        // 2. Synchronize live `GlobalState` counters and flags into `s_nv` and extract RAM copies.
        dto.s_nv[740..744].copy_from_slice(&global_state.reset_count.to_be_bytes());
        dto.s_nv[732..736].copy_from_slice(&(global_state.total_reset_count as u32).to_be_bytes());
        dto.s_nv[748..750].copy_from_slice(&global_state.orderly_state.to_be_bytes());
        dto.s_nv[750..758].copy_from_slice(&global_state.time_epoch.to_be_bytes());
        dto.s_nv[744..748].copy_from_slice(&global_state.failed_tries.to_be_bytes());

        // Update `gc` flags and PCR update counter in `s_nv`.
        dto.s_nv[NV_STATE_CLEAR_DATA_OFFSET] = global_state.sh_enable as u8;
        dto.s_nv[NV_STATE_CLEAR_DATA_OFFSET + 1] = global_state.eh_enable as u8;
        dto.s_nv[NV_STATE_CLEAR_DATA_OFFSET + 2] = global_state.ph_enable_nv as u8;
        dto.s_nv[NV_STATE_CLEAR_DATA_OFFSET + 276..NV_STATE_CLEAR_DATA_OFFSET + 280]
            .copy_from_slice(&global_state.pcrs.update_counter.to_le_bytes());

        // Copy RAM mirrors (`gp`, `gr`, `gc`, `go`, `s_indexOrderlyRam`) from `s_nv`.
        dto.gp.copy_from_slice(
            &dto.s_nv[NV_PERSISTENT_DATA_OFFSET..NV_PERSISTENT_DATA_OFFSET + GP_SIZE],
        );
        dto.gr.copy_from_slice(
            &dto.s_nv[NV_STATE_RESET_DATA_OFFSET..NV_STATE_RESET_DATA_OFFSET + GR_SIZE],
        );
        dto.gc.copy_from_slice(
            &dto.s_nv[NV_STATE_CLEAR_DATA_OFFSET..NV_STATE_CLEAR_DATA_OFFSET + GC_SIZE],
        );
        dto.go
            .copy_from_slice(&dto.s_nv[NV_ORDERLY_DATA_OFFSET..NV_ORDERLY_DATA_OFFSET + GO_SIZE]);
        dto.s_index_orderly_ram.copy_from_slice(
            &dto.s_nv[NV_INDEX_RAM_DATA_OFFSET..NV_INDEX_RAM_DATA_OFFSET + INDEX_ORDERLY_RAM_SIZE],
        );

        // 3. Serialize scalar global variables.
        dto.g_time = global_state.tpm_time_ms.to_le_bytes();
        dto.s_tpm_time = global_state.tpm_time_ms.to_le_bytes();
        dto.g_ph_enable = (global_state.ph_enable as i32).to_le_bytes();
        dto.g_pcr_re_config = (global_state.pcr_reconfig as i32).to_le_bytes();
        dto.g_drtm_handle = global_state.drtm_handle.to_le_bytes();
        dto.g_drtm_pre_startup = (global_state.drtm_pre_startup as i32).to_le_bytes();
        dto.g_startup_locality_3 = (global_state.startup_locality_3 as i32).to_le_bytes();
        dto.g_update_nv = [global_state.update_nv];
        dto.g_power_was_lost = (global_state.power_was_lost as i32).to_le_bytes();
        dto.g_clear_orderly = (global_state.clear_orderly as i32).to_le_bytes();
        dto.g_prev_orderly_state = global_state.orderly_state.to_le_bytes();
        dto.g_nv_ok = (global_state.g_nv_ok as i32).to_le_bytes();
        dto.g_initialized = (global_state.initialized as i32).to_le_bytes();
        dto.g_manufactured = 1i32.to_le_bytes();
        dto.s_da_pending_on_nv = (global_state.da_pending_on_nv as i32).to_le_bytes();
        dto.s_self_heal_timer = (global_state.self_heal_timer as u64).to_le_bytes();
        dto.s_lockout_timer = (global_state.lockout_timer as u64).to_le_bytes();
        dto.s_max_counter = global_state.max_counter.to_le_bytes();
        dto.s_locality = [global_state.locality];
        dto.s_nv_is_available = (global_state.nv_available as i32).to_le_bytes();
        dto.s_is_power_on = 1i32.to_le_bytes();
        dto.g_exclusive_audit_session = global_state
            .exclusive_audit_session
            .unwrap_or(0xFFFF_FFFF)
            .to_le_bytes();

        // Pack `g_platformUniqueDetails` (50 bytes: u16 LE size + 48 bytes buffer).
        let unique_bytes = global_state.platform_unique_details.get_buffer();
        let unique_len = core::cmp::min(unique_bytes.len(), 48);
        dto.g_platform_unique_details.fill(0);
        dto.g_platform_unique_details[0..2].copy_from_slice(&(unique_len as u16).to_le_bytes());
        dto.g_platform_unique_details[2..2 + unique_len]
            .copy_from_slice(&unique_bytes[..unique_len]);

        // 4. Serialize PCR banks into `dto.s_pcrs` (24 PCRs * 100 bytes).
        dto.s_pcrs.fill(0);
        for i in 0..24 {
            let base = i * PCR_SLOT_SIZE;
            dto.s_pcrs[base..base + 20].copy_from_slice(&global_state.pcrs.sha1[i]);
            dto.s_pcrs[base + 20..base + 52].copy_from_slice(&global_state.pcrs.sha256[i]);
            dto.s_pcrs[base + 52..base + 100].copy_from_slice(&global_state.pcrs.sha384[i]);
        }

        // 5. Serialize transient objects and active sequences into `dto.s_objects` (3 slots of 1204 bytes).
        dto.s_objects.fill(0);
        let mut slot_idx = 0;
        for obj in global_state.transient_objects.iter().flatten() {
            if slot_idx >= 3 {
                break;
            }
            let slot =
                &mut dto.s_objects[slot_idx * OBJECT_SLOT_SIZE..(slot_idx + 1) * OBJECT_SLOT_SIZE];
            Self::pack_transient_object(obj, slot)?;
            slot_idx += 1;
        }
        for seq in global_state.active_sequences.iter().flatten() {
            if slot_idx >= 3 {
                break;
            }
            let slot =
                &mut dto.s_objects[slot_idx * OBJECT_SLOT_SIZE..(slot_idx + 1) * OBJECT_SLOT_SIZE];
            Self::pack_active_sequence(seq, slot);
            slot_idx += 1;
        }

        // 6. Serialize active authorization sessions into `dto.s_sessions` (3 slots of 264 bytes).
        dto.s_sessions.fill(0);
        for (sess_slot_idx, sess) in global_state.active_sessions.iter().flatten().enumerate() {
            if sess_slot_idx >= 3 {
                break;
            }
            let slot = &mut dto.s_sessions
                [sess_slot_idx * SESSION_SLOT_SIZE..(sess_slot_idx + 1) * SESSION_SLOT_SIZE];
            Self::pack_session_state(sess, slot);
        }

        Ok(())
    }

    /// Deserializes an [`Ibmswtpm2StateDto`] back into `tpm-rs` [`GlobalState`] and [`NvStorage`].
    pub fn unserialize_state(
        dto: &Ibmswtpm2StateDto,
        global_state: &mut GlobalState,
        storage: &mut dyn NvStorage,
    ) -> Result<(), StorageError> {
        // 1. Copy RAM mirrors (`gp`, `gr`, `gc`, `go`, `s_indexOrderlyRam`) into a working `s_nv` buffer
        // so any modifications made in RAM structs are reflected when transcoding to StorageManager.
        let mut s_nv_work = dto.s_nv;
        s_nv_work[NV_PERSISTENT_DATA_OFFSET..NV_PERSISTENT_DATA_OFFSET + GP_SIZE]
            .copy_from_slice(&dto.gp);
        s_nv_work[NV_STATE_RESET_DATA_OFFSET..NV_STATE_RESET_DATA_OFFSET + GR_SIZE]
            .copy_from_slice(&dto.gr);
        s_nv_work[NV_STATE_CLEAR_DATA_OFFSET..NV_STATE_CLEAR_DATA_OFFSET + GC_SIZE]
            .copy_from_slice(&dto.gc);
        s_nv_work[NV_ORDERLY_DATA_OFFSET..NV_ORDERLY_DATA_OFFSET + GO_SIZE]
            .copy_from_slice(&dto.go);
        s_nv_work[NV_INDEX_RAM_DATA_OFFSET..NV_INDEX_RAM_DATA_OFFSET + INDEX_ORDERLY_RAM_SIZE]
            .copy_from_slice(&dto.s_index_orderly_ram);

        transcode_s_nv_to_storage(&s_nv_work, storage)?;

        // 2. Restore scalar global variables into `GlobalState`.
        global_state.tpm_time_ms = u64::from_le_bytes(dto.g_time);
        global_state.ph_enable = i32::from_le_bytes(dto.g_ph_enable) != 0;
        global_state.pcr_reconfig = i32::from_le_bytes(dto.g_pcr_re_config) != 0;
        global_state.drtm_handle = u32::from_le_bytes(dto.g_drtm_handle);
        global_state.drtm_pre_startup = i32::from_le_bytes(dto.g_drtm_pre_startup) != 0;
        global_state.startup_locality_3 = i32::from_le_bytes(dto.g_startup_locality_3) != 0;
        global_state.update_nv = dto.g_update_nv[0];
        global_state.power_was_lost = i32::from_le_bytes(dto.g_power_was_lost) != 0;
        global_state.clear_orderly = i32::from_le_bytes(dto.g_clear_orderly) != 0;
        global_state.orderly_state = u16::from_le_bytes(dto.g_prev_orderly_state);
        global_state.g_nv_ok = i32::from_le_bytes(dto.g_nv_ok) != 0;
        global_state.initialized = i32::from_le_bytes(dto.g_initialized) != 0;
        global_state.da_pending_on_nv = i32::from_le_bytes(dto.s_da_pending_on_nv) != 0;
        global_state.self_heal_timer = u64::from_le_bytes(dto.s_self_heal_timer) as i64;
        global_state.lockout_timer = u64::from_le_bytes(dto.s_lockout_timer) as i64;
        global_state.max_counter = u64::from_le_bytes(dto.s_max_counter);
        global_state.locality = dto.s_locality[0];
        global_state.nv_available = i32::from_le_bytes(dto.s_nv_is_available) != 0;

        let excl_handle = u32::from_le_bytes(dto.g_exclusive_audit_session);
        global_state.exclusive_audit_session = if excl_handle == 0xFFFF_FFFF || excl_handle == 0 {
            None
        } else {
            Some(excl_handle)
        };

        // Restore persistent scalars from `gp` and `gc`.
        global_state.reset_count =
            u32::from_be_bytes([dto.gp[740], dto.gp[741], dto.gp[742], dto.gp[743]]);
        global_state.total_reset_count =
            u32::from_be_bytes([dto.gp[732], dto.gp[733], dto.gp[734], dto.gp[735]]) as u64;
        global_state.time_epoch = u64::from_be_bytes([
            dto.gp[750],
            dto.gp[751],
            dto.gp[752],
            dto.gp[753],
            dto.gp[754],
            dto.gp[755],
            dto.gp[756],
            dto.gp[757],
        ]);
        global_state.failed_tries =
            u32::from_be_bytes([dto.gp[744], dto.gp[745], dto.gp[746], dto.gp[747]]);
        global_state.sh_enable = dto.gc[0] != 0;
        global_state.eh_enable = dto.gc[1] != 0;
        global_state.ph_enable_nv = dto.gc[2] != 0;

        // Unpack `g_platformUniqueDetails`.
        let unique_len = core::cmp::min(
            u16::from_le_bytes([
                dto.g_platform_unique_details[0],
                dto.g_platform_unique_details[1],
            ]) as usize,
            48,
        );
        if let Ok(auth) = OwnedAuth::from_bytes(&dto.g_platform_unique_details[2..2 + unique_len]) {
            global_state.platform_unique_details = auth;
        }

        // 3. Restore PCR banks from `dto.s_pcrs` and `dto.gc[276..280]`.
        for i in 0..24 {
            let base = i * PCR_SLOT_SIZE;
            global_state.pcrs.sha1[i].copy_from_slice(&dto.s_pcrs[base..base + 20]);
            global_state.pcrs.sha256[i].copy_from_slice(&dto.s_pcrs[base + 20..base + 52]);
            global_state.pcrs.sha384[i].copy_from_slice(&dto.s_pcrs[base + 52..base + 100]);
        }
        global_state.pcrs.update_counter =
            u32::from_le_bytes([dto.gc[276], dto.gc[277], dto.gc[278], dto.gc[279]]);

        // 4. Restore transient objects and active sequences from `dto.s_objects`.
        global_state.transient_objects.fill(None);
        global_state.active_sequences.fill(None);
        let mut obj_idx = 0;
        let mut seq_idx = 0;
        for slot_i in 0..3 {
            let slot = &dto.s_objects[slot_i * OBJECT_SLOT_SIZE..(slot_i + 1) * OBJECT_SLOT_SIZE];
            match slot[0] {
                1 if obj_idx < global_state.transient_objects.len() => {
                    let obj = Self::unpack_transient_object(slot)?;
                    global_state.transient_objects[obj_idx] = Some(obj);
                    obj_idx += 1;
                }
                2 if seq_idx < global_state.active_sequences.len() => {
                    let seq = Self::unpack_active_sequence(slot)?;
                    global_state.active_sequences[seq_idx] = Some(seq);
                    seq_idx += 1;
                }
                _ => {}
            }
        }

        // 5. Restore active authorization sessions from `dto.s_sessions`.
        global_state.active_sessions.fill(None);
        let mut sess_idx = 0;
        for slot_i in 0..3 {
            let slot =
                &dto.s_sessions[slot_i * SESSION_SLOT_SIZE..(slot_i + 1) * SESSION_SLOT_SIZE];
            if slot[0] != 0 && sess_idx < global_state.active_sessions.len() {
                let sess = Self::unpack_session_state(slot)?;
                global_state.active_sessions[sess_idx] = Some(sess);
                sess_idx += 1;
            }
        }

        Ok(())
    }

    fn pack_transient_object(obj: &TransientObject, slot: &mut [u8]) -> Result<(), StorageError> {
        slot[0] = 1; // slot_kind = TransientObject
        let mut offset = 1;
        slot[offset..offset + 4].copy_from_slice(&obj.handle.to_be_bytes());
        offset += 4;
        slot[offset..offset + 4].copy_from_slice(&obj.hierarchy.to_be_bytes());
        offset += 4;
        // Flags byte: bit 0 = stClear ancestor, bit 1 = external, bit 2 = public-only.
        slot[offset] = u8::from(obj.st_clear)
            | (u8::from(obj.external) << 1)
            | (u8::from(obj.public_only) << 2);
        offset += 1;
        // seedValue: 1-byte length followed by the seed bytes (up to 64).
        let seed = obj.seed_bytes();
        slot[offset] = seed.len() as u8;
        offset += 1;
        slot[offset..offset + seed.len()].copy_from_slice(seed);
        offset += seed.len();

        offset += obj.name.marshal(
            (&mut slot[offset..offset + Tpm2bName::MAX_SIZE])
                .try_into()
                .map_err(|_| StorageError::OutOfBounds)?,
        );
        offset += obj.auth.marshal(
            (&mut slot[offset..offset + Tpm2bAuth::MAX_SIZE])
                .try_into()
                .map_err(|_| StorageError::OutOfBounds)?,
        );
        offset += obj.qualified_name.marshal(
            (&mut slot[offset..offset + Tpm2bName::MAX_SIZE])
                .try_into()
                .map_err(|_| StorageError::OutOfBounds)?,
        );
        let mut pub_buf = [0u8; TpmtPublic::MAX_SIZE];
        let pub_len = obj.public.marshal(&mut pub_buf);
        if offset + pub_len > slot.len() {
            return Err(StorageError::OutOfBounds);
        }
        slot[offset..offset + pub_len].copy_from_slice(&pub_buf[..pub_len]);
        offset += pub_len;

        if offset + 2 > slot.len() {
            return Err(StorageError::OutOfBounds);
        }
        let priv_len = core::cmp::min(obj.private_len, slot.len() - offset - 2);
        slot[offset..offset + 2].copy_from_slice(&(priv_len as u16).to_be_bytes());
        offset += 2;
        slot[offset..offset + priv_len].copy_from_slice(&obj.private[..priv_len]);
        Ok(())
    }

    fn unpack_transient_object(slot: &[u8]) -> Result<TransientObject, StorageError> {
        let mut slice = &slot[1..];
        let handle = u32::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let hierarchy = u32::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let flags = u8::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let st_clear = flags & 1 != 0;

        let seed_len = u8::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)? as usize;
        if seed_len > 64 || slice.len() < seed_len {
            return Err(StorageError::OutOfBounds);
        }
        let (seed, seed_len) = TransientObject::seed_from_bytes(&slice[..seed_len]);
        slice = &slice[seed_len..];

        let name: OwnedName = Tpm2bName::unmarshal(&mut slice)
            .map_err(|_| StorageError::OutOfBounds)?
            .into();
        let auth: OwnedAuth = Tpm2bAuth::unmarshal(&mut slice)
            .map_err(|_| StorageError::OutOfBounds)?
            .into();
        let qualified_name: OwnedName = Tpm2bName::unmarshal(&mut slice)
            .map_err(|_| StorageError::OutOfBounds)?
            .into();
        let public: OwnedPublic = TpmtPublic::unmarshal(&mut slice)
            .map_err(|_| StorageError::OutOfBounds)?
            .into();

        let priv_len = u16::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)? as usize;
        if slice.len() < priv_len {
            return Err(StorageError::OutOfBounds);
        }
        let mut private = [0u8; 1536];
        private[..priv_len].copy_from_slice(&slice[..priv_len]);

        Ok(TransientObject {
            handle,
            seed,
            seed_len,
            external: flags & 2 != 0,
            public_only: flags & 4 != 0,
            name,
            auth,
            public,
            private,
            private_len: priv_len,
            qualified_name,
            hierarchy,
            st_clear,
        })
    }

    fn pack_active_sequence(seq: &ActiveSequence, slot: &mut [u8]) {
        slot[0] = 2; // slot_kind = ActiveSequence
        let mut offset = 1;
        slot[offset..offset + 4].copy_from_slice(&seq.handle.to_be_bytes());
        offset += 4;
        if let Ok(dst) = (&mut slot[offset..offset + Tpm2bAuth::MAX_SIZE]).try_into() {
            offset += seq.auth.marshal(dst);
        }
        match &seq.sequence_type {
            SequenceType::Hash { alg } => {
                slot[offset] = 1;
                offset += 1;
                if let Ok(dst) = (&mut slot[offset..offset + TpmiAlgHash::MAX_SIZE]).try_into() {
                    offset += alg.marshal(dst);
                }
            }
            SequenceType::Hmac { hash_alg, key } => {
                slot[offset] = 2;
                offset += 1;
                if let Ok(dst) = (&mut slot[offset..offset + TpmiAlgHash::MAX_SIZE]).try_into() {
                    offset += hash_alg.marshal(dst);
                }
                if let Ok(dst) =
                    (&mut slot[offset..offset + tpm2::Tpm2bSensitiveData::MAX_SIZE]).try_into()
                {
                    offset += key.marshal(dst);
                }
            }
            SequenceType::Event => {
                slot[offset] = 0;
                offset += 1;
            }
        }
        slot[offset..offset + 4].copy_from_slice(&(seq.sequence_len as u32).to_be_bytes());
        offset += 4;
        slot[offset..offset + 4].copy_from_slice(&seq.first_bytes);
        offset += 4;
        slot[offset] = seq.first_bytes_len as u8;
        offset += 1;
        for state in &seq.hash_states {
            if offset + StreamingHashState::SERIALIZED_SIZE <= slot.len() {
                offset += state.serialize(&mut slot[offset..]);
            }
        }
    }

    fn unpack_active_sequence(slot: &[u8]) -> Result<ActiveSequence, StorageError> {
        let mut slice = &slot[1..];
        let handle = u32::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let auth: OwnedAuth = Tpm2bAuth::unmarshal(&mut slice)
            .map_err(|_| StorageError::OutOfBounds)?
            .into();
        let tag_byte = u8::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let sequence_type = match tag_byte {
            1 => {
                let alg =
                    TpmiAlgHash::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
                SequenceType::Hash { alg }
            }
            2 => {
                let hash_alg =
                    TpmiAlgHash::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
                let key: OwnedSensitiveData = tpm2::Tpm2bSensitiveData::unmarshal(&mut slice)
                    .map_err(|_| StorageError::OutOfBounds)?
                    .into();
                SequenceType::Hmac { hash_alg, key }
            }
            _ => SequenceType::Event,
        };
        let sequence_len =
            u32::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)? as usize;
        if slice.len() < 5 {
            return Err(StorageError::OutOfBounds);
        }
        let mut first_bytes = [0u8; 4];
        first_bytes.copy_from_slice(&slice[..4]);
        let first_bytes_len = (slice[4] as usize).min(4);
        slice = &slice[5..];

        let mut hash_states = [StreamingHashState::default(); 4];
        for state in &mut hash_states {
            if slice.len() >= StreamingHashState::SERIALIZED_SIZE {
                *state = StreamingHashState::deserialize(slice).ok_or(StorageError::OutOfBounds)?;
                slice = &slice[StreamingHashState::SERIALIZED_SIZE..];
            }
        }

        Ok(ActiveSequence {
            handle,
            intermediate_digest: OwnedDigest::default(),
            auth,
            sequence_type,
            sequence_buffer: [0u8; crate::MAX_SEQUENCE_BUFFER],
            sequence_len,
            first_bytes,
            first_bytes_len,
            hash_states,
        })
    }

    fn pack_session_state(sess: &SessionState, slot: &mut [u8]) {
        slot[0] = 1; // occupied
        let mut offset = 1;
        slot[offset..offset + 4].copy_from_slice(&sess.session_handle.to_be_bytes());
        offset += 4;
        if let Ok(dst) = (&mut slot[offset..offset + TpmSe::MAX_SIZE]).try_into() {
            offset += sess.session_type.marshal(dst);
        }
        if let Ok(dst) = (&mut slot[offset..offset + TpmiAlgHash::MAX_SIZE]).try_into() {
            offset += sess.auth_hash.marshal(dst);
        }
        if let Ok(dst) = (&mut slot[offset..offset + Tpm2bNonce::MAX_SIZE]).try_into() {
            offset += sess.nonce_tpm.marshal(dst);
        }
        if let Ok(dst) = (&mut slot[offset..offset + Tpm2bNonce::MAX_SIZE]).try_into() {
            offset += sess.nonce_caller.marshal(dst);
        }

        let sk_len = core::cmp::min(sess.session_key_len, 32);
        slot[offset] = sk_len as u8;
        offset += 1;
        slot[offset..offset + sk_len].copy_from_slice(&sess.session_key[..sk_len]);
        offset += sk_len;

        if let Ok(dst) = (&mut slot[offset..offset + <Option<TpmtSymDef>>::MAX_SIZE]).try_into() {
            offset += sess.symmetric.marshal(dst);
        }
        if let Ok(dst) = (&mut slot[offset..offset + Handle::MAX_SIZE]).try_into() {
            offset += sess.bind_entity.marshal(dst);
        }
        if let Ok(dst) = (&mut slot[offset..offset + Tpm2bName::MAX_SIZE]).try_into() {
            offset += sess.bound_entity.marshal(dst);
        }

        if let Some(audit) = sess.audit_digest {
            slot[offset] = 1;
            offset += 1;
            let ad_len = core::cmp::min(sess.audit_digest_len, 32);
            slot[offset] = ad_len as u8;
            offset += 1;
            slot[offset..offset + ad_len].copy_from_slice(&audit[..ad_len]);
            offset += ad_len;
        } else {
            slot[offset] = 0;
            offset += 1;
        }

        let pd_len = core::cmp::min(sess.policy_digest_len, 32);
        slot[offset] = pd_len as u8;
        offset += 1;
        slot[offset..offset + pd_len].copy_from_slice(&sess.policy_digest[..pd_len]);
        offset += pd_len;

        slot[offset..offset + 4].copy_from_slice(&sess.command_code.to_be_bytes());
        offset += 4;
        slot[offset..offset + 8].copy_from_slice(&sess.start_time.to_be_bytes());
        offset += 8;
        slot[offset..offset + 8].copy_from_slice(&sess.timeout.to_be_bytes());
        offset += 8;
        slot[offset..offset + 8].copy_from_slice(&sess.epoch.to_be_bytes());
        offset += 8;

        if let Some(pc) = sess.pcr_counter {
            slot[offset] = 1;
            offset += 1;
            slot[offset..offset + 4].copy_from_slice(&pc.to_be_bytes());
            offset += 4;
        } else {
            slot[offset] = 0;
            offset += 1;
        }

        let mut flags: u16 = 0;
        if sess.is_cp_hash_defined {
            flags |= 1 << 0;
        }
        if sess.is_name_hash_defined {
            flags |= 1 << 1;
        }
        if sess.is_template_hash_defined {
            flags |= 1 << 2;
        }
        if sess.is_auth_value_needed {
            flags |= 1 << 3;
        }
        if sess.is_password_needed {
            flags |= 1 << 4;
        }
        if sess.check_nv_written {
            flags |= 1 << 5;
        }
        if sess.nv_written_state {
            flags |= 1 << 6;
        }
        if sess.include_auth {
            flags |= 1 << 7;
        }
        if sess.is_da_bound {
            flags |= 1 << 8;
        }
        if sess.is_lockout_bound {
            flags |= 1 << 9;
        }
        slot[offset..offset + 2].copy_from_slice(&flags.to_be_bytes());
        offset += 2;
        slot[offset] = sess.command_locality;
    }

    fn unpack_session_state(slot: &[u8]) -> Result<SessionState, StorageError> {
        let mut slice = &slot[1..];
        let session_handle = u32::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let session_type = TpmSe::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let auth_hash =
            TpmiAlgHash::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let nonce_tpm: OwnedNonce = Tpm2bNonce::unmarshal(&mut slice)
            .map_err(|_| StorageError::OutOfBounds)?
            .into();
        let nonce_caller: OwnedNonce = Tpm2bNonce::unmarshal(&mut slice)
            .map_err(|_| StorageError::OutOfBounds)?
            .into();

        let sk_len = u8::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)? as usize;
        if slice.len() < sk_len {
            return Err(StorageError::OutOfBounds);
        }
        let mut session_key = [0u8; 128];
        session_key[..sk_len].copy_from_slice(&slice[..sk_len]);
        slice = &slice[sk_len..];

        let symmetric =
            <Option<TpmtSymDef>>::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let bind_entity = Handle::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let bound_entity: OwnedName = Tpm2bName::unmarshal(&mut slice)
            .map_err(|_| StorageError::OutOfBounds)?
            .into();

        let has_audit = u8::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)? != 0;
        let (audit_digest, audit_digest_len) = if has_audit {
            let ad_len = u8::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)? as usize;
            if slice.len() < ad_len {
                return Err(StorageError::OutOfBounds);
            }
            let mut ad = [0u8; 64];
            ad[..ad_len].copy_from_slice(&slice[..ad_len]);
            slice = &slice[ad_len..];
            (Some(ad), ad_len)
        } else {
            (None, 0)
        };

        let pd_len = u8::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)? as usize;
        if slice.len() < pd_len {
            return Err(StorageError::OutOfBounds);
        }
        let mut policy_digest = [0u8; 64];
        policy_digest[..pd_len].copy_from_slice(&slice[..pd_len]);
        slice = &slice[pd_len..];

        let command_code = u32::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let start_time = u64::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let timeout = u64::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let epoch = u64::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;

        let has_pc = u8::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)? != 0;
        let pcr_counter = if has_pc {
            Some(u32::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?)
        } else {
            None
        };

        let flags = u16::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;
        let command_locality = u8::unmarshal(&mut slice).map_err(|_| StorageError::OutOfBounds)?;

        Ok(SessionState {
            session_handle,
            session_type,
            auth_hash,
            nonce_tpm,
            nonce_caller,
            session_key,
            session_key_len: sk_len,
            symmetric,
            bind_entity,
            bound_entity,
            audit_digest,
            audit_digest_len,
            audit_cp_hash: [0; 64],
            audit_cp_hash_len: 0,
            policy_hash: [0; 64],
            policy_hash_len: 0,
            is_cp_hash_defined: (flags & (1 << 0)) != 0,
            is_name_hash_defined: (flags & (1 << 1)) != 0,
            is_template_hash_defined: (flags & (1 << 2)) != 0,
            policy_digest,
            policy_digest_len: pd_len,
            command_code,
            start_time,
            timeout,
            epoch,
            is_auth_value_needed: (flags & (1 << 3)) != 0,
            is_password_needed: (flags & (1 << 4)) != 0,
            pcr_counter,
            check_nv_written: (flags & (1 << 5)) != 0,
            nv_written_state: (flags & (1 << 6)) != 0,
            command_locality,
            include_auth: (flags & (1 << 7)) != 0,
            is_da_bound: (flags & (1 << 8)) != 0,
            is_lockout_bound: (flags & (1 << 9)) != 0,
        })
    }
}
