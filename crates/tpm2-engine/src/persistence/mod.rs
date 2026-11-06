#![forbid(unsafe_code)]

//! Persistence of the complete TPM state: a `no_std`, allocation-free [`PersistedTpmState`] and
//! bidirectional conversion between it and the engine's [`GlobalState`] plus its
//! [`NvStorage`].
//!
//! Ported from `tpm_rs_serializer_core` (`tpm-migration-proof`), whose
//! `PersistedTpmState` is the input of the wire-format serializer and of the round trip with
//! the `ibmswtpm2` live-migration state.
//!
//! # Assumptions
//!
//! The state is saved and restored where a platform would (the vTPM's Serialize/Unserialize):
//! between two commands, with the TPM powered on and NV available. Under these assumptions the
//! conversion is lossless: [`serialize`] followed by [`deserialize`] into a fresh state and
//! storage reproduces the logical content of the NV storage and every field of the TPM state
//! that outlives a command and that the TPM can observe, so that the restored TPM continues
//! exactly where the original one stopped, also on another platform timer.
//!
//! # Groups
//!
//! - `nv`: the NV content (the reserved header and the canonical payloads of the storage
//!   manager's items, in handle order; see [`PersistedNvImage`]). It is the source of truth for
//!   every NV-synced field (the fields that are written to NV in the same command that changes
//!   them): restore reloads the counters of the header and the `gp` fields of the hierarchy and
//!   platform-settings records through the structured records of [`crate::storage::nv`], so
//!   they are not persisted twice.
//! - `reset`/`clear`/`orderly`: C `gr`/`gc`/`go`, which are ahead of NV between shutdowns
//!   (`reset.clear_count` included: `TPM2_Startup` changes it in RAM only).
//! - `time`, `runtime`, `loaded`, `pcrs`, `act`, `vendor`, `self_test`: RAM-only state, and the
//!   RAM values of NV-synced fields that may be ahead of NV, which restore applies after the
//!   NV reload: `runtime.orderly_state` (`TPM2_Startup` replaces `SU_DA_USED` in RAM before
//!   checks that can still fail), `runtime.failed_tries` with `runtime.da_pending_on_nv` (a DA
//!   failure while NV was unavailable) and `runtime.lockout_auth_enabled`.
//! - `platform`: the state of the platform (set by the platform's persistence methods).
//!
//! # The platform timer
//!
//! The readings of the platform timer are not persisted: they are meaningless on another
//! platform. The save takes the current reading (`now_ms`) and persists the platform time that
//! has elapsed but is not yet accounted for, relative to it: the milliseconds not yet in *Time*
//! (`time.pending_platform_ms`) and the milliseconds since the last ACT tick
//! (`act.tick_phase_ms`). The restore takes the current reading of the target's timer and
//! continues from it.
//!
//! # Not persisted
//!
//! - The fields that only live during a command (the parsed authorizations,
//!   `command_persistent_objects`, `in_shadow_execution`, `sessions_validated_by_handler`, the
//!   command and session audit cpHashes `command_audit_cp_hash`/`session_audit_cp_hashes`, and
//!   a session's `include_auth`, which every command recomputes before it uses it).
//! - The fields that are derived between two commands with NV available, which restore sets:
//!   `update_nv`/`clear_orderly` (idle) and `nv_available` (true).
//! - The values restore derives: the Names of the loaded objects (`nameAlg ||
//!   H_nameAlg(public)`), `isNameHashDefined` and `isBound` of a session
//!   (`SessionState::is_name_hash_defined`, a non-empty bind value), whether the ACTs tick (while
//!   `runtime.initialized`), the full sequence numbers of the saved sessions (from their low
//!   bits and the context counter), and the metadata of the NV items.
//! - What the TPM cannot observe: the slots of the loaded objects, sessions and sequences in RAM
//!   (restore assigns them in handle order), the handle type of a saved session, the storage
//!   order of the NV items, and the first data block of a sequence beyond its `firstBlock` and
//!   `ticketSafe` attributes.
//! - The algorithm of each PCR bank, implied by its position (`PcrState::IMPLEMENTED_BANKS`).
//! - The Failure-mode diagnostics of the C references (`s_failFunction`, `s_failLine`,
//!   `s_failCode`): `tpm-rs` keeps none (in Failure mode `TPM2_GetTestResult` always reports
//!   the location 0 and `FATAL_ERROR_SELF_TEST`), so Failure mode is persisted as
//!   `self_test.failed` only, and a converter from a reference loses its diagnostics.
//!
//! The algorithm self-test state is not part of [`GlobalState`] (`TpmEngine::self_test`): the
//! free functions persist the state after `_TPM_Init` (every algorithm needs its test) and do
//! not apply it; [`TpmEngine::save_persisted_state`] and
//! [`TpmEngine::restore_persisted_state`] persist and restore it as well.

pub mod conversion;
#[cfg(feature = "serde")]
mod serde_arrays;
pub mod types;

pub use conversion::{DeserializeError, SerializeError};
pub use types::*;

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{GlobalState, TpmEngine};
use tpm2::crypto::backend::Hash;
use tpm2::crypto::{Crypto, Rng};

/// Extracts the persisted state of `global_state` and `storage` into `persisted`; `now_ms` is
/// the current reading of the platform timer (see the module documentation).
///
/// Fails if a value does not fit its persisted field (e.g. more NV data than
/// [`MAX_NV_DATA_SIZE`]), if `storage` cannot be read or holds an invalid record, or if the
/// state is inconsistent.
pub fn try_serialize<S: NvStorage>(
    global_state: &GlobalState,
    storage: &S,
    now_ms: u64,
    persisted: &mut PersistedTpmState,
) -> Result<(), SerializeError> {
    persisted.extract_from_global_state_and_storage(global_state, storage, now_ms)
}

/// Like [`try_serialize`], panicking on failure.
pub fn serialize<S: NvStorage>(
    global_state: &GlobalState,
    storage: &S,
    now_ms: u64,
    persisted: &mut PersistedTpmState,
) {
    try_serialize(global_state, storage, now_ms, persisted).expect("Failed to serialize");
}

/// Restores `global_state` and `storage` from `persisted`; `now_ms` is the current reading of
/// the target's platform timer (see the module documentation), and the hashes of the crypto
/// backend `H` compute the Names of the loaded objects.
///
/// `persisted` is validated before `global_state` is modified; `storage` is then erased and
/// rewritten.
pub fn try_deserialize<H: Hash, S: NvStorage>(
    persisted: &PersistedTpmState,
    global_state: &mut GlobalState,
    storage: &mut S,
    now_ms: u64,
) -> Result<(), DeserializeError> {
    persisted.apply_to_global_state::<H, S>(global_state, storage, now_ms)
}

/// Like [`try_deserialize`], panicking on failure.
pub fn deserialize<H: Hash, S: NvStorage>(
    persisted: &PersistedTpmState,
    global_state: &mut GlobalState,
    storage: &mut S,
    now_ms: u64,
) {
    try_deserialize::<H, S>(persisted, global_state, storage, now_ms)
        .expect("Failed to deserialize");
}

impl<C: Crypto, S: NvStorage, T: TpmTimer, R: Rng + Sync> TpmEngine<'_, C, S, T, R> {
    /// Extracts the complete state of the TPM (its [`GlobalState`], its NV storage and its
    /// algorithm self-test state) into `persisted`, relative to the current reading of its
    /// platform timer.
    pub fn save_persisted_state(
        &self,
        persisted: &mut PersistedTpmState,
    ) -> Result<(), SerializeError> {
        let now_ms = self.platform.timer.timer_read();
        try_serialize(&self.state, &*self.platform.storage, now_ms, persisted)?;
        persisted.extract_self_test(&self.self_test)
    }

    /// Restores the complete state of the TPM (its [`GlobalState`], its NV storage and its
    /// algorithm self-test state) from `persisted`, e.g. on the target of a live migration. The
    /// platform time continues from the current reading of its platform timer, and the Names of
    /// the loaded objects are recomputed with its crypto backend (directly, without the
    /// algorithm self tests, which would change the self-test state).
    pub fn restore_persisted_state(
        &mut self,
        persisted: &PersistedTpmState,
    ) -> Result<(), DeserializeError> {
        // Validate the self-test state first, so that a failure leaves the TPM unchanged.
        let staged = crate::self_test::SelfTestState::default();
        persisted.apply_self_test(&staged)?;
        let now_ms = self.platform.timer.timer_read();
        try_deserialize::<C, S>(
            persisted,
            &mut self.state,
            &mut *self.platform.storage,
            now_ms,
        )?;
        persisted.apply_self_test(&self.self_test)
    }
}
