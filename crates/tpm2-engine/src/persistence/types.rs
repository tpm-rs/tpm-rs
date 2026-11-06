#![forbid(unsafe_code)]

//! Core `no_std`, allocation-free type definitions for [`PersistedTpmState`] and its structured
//! components.
//!
//! Every type is `Copy` (except [`PersistedTpmState`] itself, which is only `Clone` because of
//! its size) and, with the `serde` feature, implements `serde`'s `Serialize` and `Deserialize`,
//! so that the persisted state can be written in any `serde` format and mapped field by field
//! onto another representation (e.g. the `ibmswtpm2` live-migration state). An [`Array`] is serialized as the sequence of its
//! active elements, and fixed byte arrays as byte strings (see `serde_arrays`).
//! Capacities are fixed upper bounds that do not depend on the enabled features where possible,
//! so that the layout stays the same across profiles; the ones that follow the profile (the public
//! area, the private key, the hash/CMAC/signature-sequence states) are taken from the engine.
//!
//! The state holds no derivable or unobservable value: what restore can recompute (the Names of
//! the loaded objects, `isNameHashDefined`, `isBound`, the NV item metadata) or what is
//! recomputed before it is used (`includeAuth`) is left out, and values that depend on the
//! platform timer are relative to the timer reading at the save.
//!
//! # Widths
//!
//! The widths hold every value that `tpm-rs` and the C references (`tcgtpm`, `ibmswtpm2`) can
//! produce, and no more precision than either keeps:
//!
//! - the time epoch ([`PersistedNvImage::header`], [`PersistedSessionState::epoch`]) is a
//!   `CLOCK_NONCE`, which is a `UINT32` with `CLOCK_STOPS == NO` (the reference profile, which
//!   `tpm-rs` follows) and a `UINT64` with `CLOCK_STOPS == YES`. A converter from a
//!   `CLOCK_STOPS` build must check that the epochs are below 2^32;
//! - a saved session is identified by the low `CONTEXT_SLOT` bits of its context sequence
//!   number ([`PersistedSavedSession::sequence`]). `CONTEXT_SLOT` is a `UINT16` in the
//!   reference profile (and `tpm-rs`), and a `UINT8` in the `SIMULATION && DEBUG` builds of
//!   `tcgtpm` and the `SIMULATION` builds of `ibmswtpm2` v974 (its default): a converter to such
//!   a build must check that every
//!   saved session is less than 256 context saves behind
//!   [`PersistedResetData::context_counter`];
//! - `gr.commitCounter` ([`PersistedCommitState::counter`]) is a `UINT64` everywhere.

use crate::act::ACT_COUNT;
use crate::cmac::CmacState;
use crate::engine::SignatureSequence;
use crate::handler::MAX_PRIVATE_KEY_SIZE;
use crate::hash_state::StreamingHashState;
use crate::storage::manager::MAX_ITEMS;
use crate::{MAX_ACTIVE_SEQUENCES, MAX_LOADED_OBJECTS, MAX_LOADED_SESSIONS};
use tpm2::{Marshal, TpmlPcrSelection, TpmtPublic, TpmtSymDef};

/// Capacity of a persisted digest, nonce, authorization value or policy (`TPM2B_DIGEST`,
/// `TPM2B_NONCE`, `TPM2B_AUTH`): the largest digest (SHA-512).
pub const DIGEST_CAP: usize = 64;
/// Capacity of a persisted Name (`TPM2B_NAME`): a `nameAlg` and the largest digest.
pub const NAME_CAP: usize = 2 + DIGEST_CAP;
/// Capacity of a persisted `TPM2B_SENSITIVE_DATA` (`MAX_SYM_DATA`).
pub const SENSITIVE_DATA_CAP: usize = 128;
/// Capacity of a persisted session key.
pub const SESSION_KEY_CAP: usize = 128;
/// Capacity of a persisted primary seed or hierarchy proof.
pub const SEED_CAP: usize = 64;
/// Number of PCRs per bank.
pub const PCR_COUNT: usize = 24;
/// Maximum number of PCR banks (SHA-1, SHA-256, SHA-384, SHA-512, SM3-256, SHA3-256/384/512).
pub const MAX_PCR_BANKS: usize = 8;
/// Maximum number of Authenticated Countdown Timers (`TPM_RH_ACT_0..=TPM_RH_ACT_F`).
pub const MAX_ACTS: usize = 16;
/// Maximum number of saved (context-saved, not loaded) sessions (`MAX_ACTIVE_SESSIONS`).
pub const MAX_SAVED_SESSIONS: usize = crate::engine::MAX_ACTIVE_SESSIONS;
/// Capacity of the persisted list of algorithms that still need a self test (`g_toTest`).
pub const MAX_UNTESTED_ALGORITHMS: usize = 64;
/// Size of the Nuvoton `NTC2_*` configuration (`NTC2_CFG_STRUCT`).
pub const NTC2_CONFIG_SIZE: usize = tpm2::commands::Ntc2CfgStruct::SIZE;
/// Maximum number of dynamic NV indices, persistent objects and internal records in storage.
pub const MAX_NV_ITEMS: usize = MAX_ITEMS;
/// Maximum total size of the payloads of all NV items: the NV backing store of the simulator
/// (twice the accounted `NV_MEMORY_SIZE`).
pub const MAX_NV_DATA_SIZE: usize = 2 * crate::storage::nv_capacity::NV_MEMORY_SIZE as usize;
/// Size of the reserved NV header (`storage::manager::RESERVED_SIZE`).
pub const NV_HEADER_SIZE: usize = crate::storage::manager::RESERVED_SIZE;

const _: () = assert!(tpm2::Tpm2bDigest::CAP <= DIGEST_CAP);
const _: () = assert!(tpm2::Tpm2bAuth::CAP <= DIGEST_CAP);
const _: () = assert!(tpm2::Tpm2bNonce::CAP <= DIGEST_CAP);
const _: () = assert!(tpm2::Tpm2bName::CAP <= NAME_CAP);
const _: () = assert!(tpm2::Tpm2bSensitiveData::CAP <= SENSITIVE_DATA_CAP);
const _: () = assert!(crate::engine::COMMIT_NONCE_SIZE <= DIGEST_CAP);
const _: () = assert!(ACT_COUNT <= MAX_ACTS);
const _: () = assert!(tpm2::platform::PcrState::IMPLEMENTED_BANKS.len() <= MAX_PCR_BANKS);

/// Allocation-free fixed-capacity array with explicit length.
///
/// Only `data[..len]` is meaningful. A `len` larger than `N` (which only a corrupted or hostile
/// persisted state can contain) is clamped by the accessors and rejected by the conversion into
/// a `GlobalState` (`DeserializeError::InvalidLength`).
#[derive(Clone, Copy, Debug)]
pub struct Array<T, const N: usize> {
    pub len: usize,
    pub data: [T; N],
}

impl<T: PartialEq, const N: usize> PartialEq for Array<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Eq, const N: usize> Eq for Array<T, N> {}

impl<T: Default + Copy, const N: usize> Default for Array<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Default + Copy, const N: usize> Array<T, N> {
    /// Creates an empty array.
    pub fn new() -> Self {
        Self {
            len: 0,
            data: [T::default(); N],
        }
    }

    /// Copies up to `N` elements from `src` into a new `Array<T, N>`.
    pub fn from_slice(src: &[T]) -> Self {
        let mut s = Self::new();
        let copy_len = src.len().min(N);
        s.data[..copy_len].copy_from_slice(&src[..copy_len]);
        s.len = copy_len;
        s
    }

    /// Copies `src` into a new `Array<T, N>`, or `None` if it has more than `N` elements.
    pub fn try_from_slice(src: &[T]) -> Option<Self> {
        (src.len() <= N).then(|| Self::from_slice(src))
    }

    /// Appends an element to the array if capacity allows.
    pub fn push(&mut self, item: T) {
        if self.len < N {
            self.data[self.len] = item;
            self.len += 1;
        }
    }
}

impl<T, const N: usize> Array<T, N> {
    /// The capacity `N`.
    pub const CAPACITY: usize = N;

    /// Returns the active slice `data[..len]` (`len` clamped to `N`).
    pub fn as_slice(&self) -> &[T] {
        &self.data[..self.len.min(N)]
    }

    /// Returns the active mutable slice `data[..len]` (`len` clamped to `N`).
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.data[..self.len.min(N)]
    }

    /// Returns an iterator over the active elements `data[..len]`.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.as_slice().iter()
    }

    /// Returns a mutable iterator over the active elements `data[..len]`.
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.as_mut_slice().iter_mut()
    }

    /// Whether the array holds no element.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a Array<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a mut Array<T, N> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_mut_slice().iter_mut()
    }
}

/// The NV content: the reserved header and the storage manager's items with their payloads. It
/// is the source of truth for every NV-synced field of the TPM state (the fields that are written
/// to NV in the same command that changes them; see the `persistence` module documentation),
/// which restore reloads from it through [`crate::storage::nv`].
///
/// The image is canonical: it holds only what the TPM can observe. The items are in ascending
/// handle order (the storage order is not observable: `TPM_CAP_HANDLES` sorts, and neither the
/// NV space accounting nor the storage capacity depends on it), and each payload is the
/// canonical encoding of its record:
///
/// - an NV Index ([`crate::storage::nv::NvIndexRecord`], `0x01xx_xxxx`): `TPM2B_AUTH ||
///   TPM2B_NV_PUBLIC || data`, whose length follows from the public area (`dataSize`);
/// - a persistent object ([`crate::storage::nv::NvPersistentObjectRecord`], `0x81xx_xxxx`) and
///   the internal records ([`crate::storage::nv`]): the encoding of the decoded record, whose
///   length follows from its content. The hierarchy record keeps its fixed item size
///   ([`crate::storage::nv::HIERARCHY_RECORD_SIZE`]) in storage; the octets after its encoding
///   are unused.
///
/// The item metadata of the storage manager is derived at restore: the payload size, and the
/// item attributes, which are only read for `TPMA_NV_PLATFORMCREATE` of an NV Index (the
/// attributes of its public area; 0 for the other items).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedNvImage {
    /// The reserved header ([`crate::storage::nv::NvHeader`]), as raw octets.
    #[cfg_attr(feature = "serde", serde(with = "super::serde_arrays::bytes"))]
    pub header: [u8; NV_HEADER_SIZE],
    /// The handles of the items, in ascending order.
    pub handles: Array<u32, MAX_NV_ITEMS>,
    /// Their payloads, back to back in handle order.
    pub data: Array<u8, MAX_NV_DATA_SIZE>,
}

impl Default for PersistedNvImage {
    fn default() -> Self {
        Self {
            header: [0; NV_HEADER_SIZE],
            handles: Array::new(),
            data: Array::new(),
        }
    }
}

/// Persisted representation of the NIST SP800-90A CTR_DRBG state (`DrbgState`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedDrbgState {
    pub reseed_counter: u64,
    pub magic: u32,
    #[cfg_attr(feature = "serde", serde(with = "super::serde_arrays::bytes"))]
    pub seed: [u8; 48],
    pub last_value: [u32; 4],
}

impl Default for PersistedDrbgState {
    fn default() -> Self {
        Self {
            reseed_counter: 0,
            magic: 0,
            seed: [0u8; 48],
            last_value: [0u32; 4],
        }
    }
}

/// The state-reset data (C `gr`, `STATE_RESET_DATA`): written to NV only by
/// `TPM2_Shutdown(TPM_SU_STATE)` (the state-save record), kept by TPM Restart and TPM Resume and
/// reset by TPM Reset. Between shutdowns the RAM values are the live ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedResetData {
    /// `gr.nullProof`.
    pub null_proof: Array<u8, SEED_CAP>,
    /// `gr.nullSeed`.
    pub null_seed: Array<u8, SEED_CAP>,
    /// `gr.objectContextID`: the sequence number of the last object context save.
    pub object_context_counter: u64,
    /// `gr.contextCounter`.
    pub context_counter: u64,
    /// The saved session contexts (`gr.contextArray`).
    pub saved_sessions: Array<PersistedSavedSession, MAX_SAVED_SESSIONS>,
    /// `gr.commandAuditDigest`.
    pub command_audit_digest: Array<u8, DIGEST_CAP>,
    /// `gr.restartCount`.
    pub restart_count: u32,
    /// `gr.clearCount`: written to NV only with the hierarchy record, so TPM Restart (`+= 1`)
    /// and TPM Reset (`= 0`) leave the RAM value ahead of NV.
    pub clear_count: u32,
    /// `gr.pcrCounter`.
    pub pcr_update_counter: u32,
    /// The ECDAA commit state.
    pub commit: PersistedCommitState,
}

/// The state-clear data (C `gc`, `STATE_CLEAR_DATA`): written to NV only by
/// `TPM2_Shutdown(TPM_SU_STATE)`, kept by TPM Resume and reset by TPM Reset and TPM Restart.
/// Between shutdowns the RAM values are the live ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedClearData {
    pub sh_enable: bool,
    pub eh_enable: bool,
    pub ph_enable_nv: bool,
    pub platform_auth: Array<u8, DIGEST_CAP>,
    pub platform_policy: Array<u8, DIGEST_CAP>,
    /// The platform policy hash algorithm (`None`: `TPM_ALG_NULL`).
    pub platform_alg: Option<u16>,
    /// `gc.pcrAuthValues`.
    pub pcr_auth_value: Array<u8, DIGEST_CAP>,
    /// `gc.readOnly` (`TPMA_STARTUP_CLEAR.readOnly`).
    pub read_only: bool,
}

/// The orderly data (C `go`, `ORDERLY_DATA`): written to NV on every orderly `TPM2_Shutdown`
/// (and the clock at `NV_CLOCK_UPDATE_INTERVAL`); the RAM values are the live ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedOrderlyData {
    /// `go.drbgState`.
    pub drbg: PersistedDrbgState,
    /// `go.clockSafe`.
    pub clock_safe: bool,
    /// `go.selfHealTimer`.
    pub self_heal_timer: i64,
    /// `go.lockoutTimer`.
    pub lockout_timer: i64,
    /// *Time* at the last `TPM2_Shutdown` (`go.time`).
    pub shutdown_time_ms: u64,
}

/// *Time* and the platform timer (`g_time` and the platform's `Clock.c`).
///
/// The platform timer is not persisted: its readings are meaningless on another platform (or
/// after the platform restarted). The platform milliseconds that have elapsed but are not yet in
/// *Time* are persisted instead, and restore continues from the reading of the target's timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedTimeState {
    /// *Time* (`g_time` / `s_tpmTime`).
    pub time_ms: u64,
    /// `Clock - Time` (two's complement; `Clock` itself is in NV only at update intervals).
    pub clock_offset: i64,
    /// The clock-rate divisor (`s_adjustRate`).
    pub adjust_rate: u32,
    /// The platform milliseconds not yet consumed by the rate-adjusted updates of *Time*
    /// (`timeNow - s_realTimePrevious` of `_plat__TimerRead()` at the save): the platform time
    /// elapsed since the last timer read plus the remainder of the last update.
    pub pending_platform_ms: u64,
    /// `s_timerStopped`.
    pub timer_stopped: bool,
    /// `s_timerReset`.
    pub timer_was_reset: bool,
}

/// The volatile state that is lost at `_TPM_Init` (C `g_*` globals and platform inputs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedRuntimeState {
    /// `g_initialized` (it also enables the ACT ticks, C `actTicksAllowed`).
    pub initialized: bool,
    /// `gp.orderlyState` in RAM: `TPM2_Startup` replaces `SU_DA_USED` with `SU_NONE` in RAM only
    /// before checks that can still fail, so the RAM value may differ from the NV header.
    pub orderly_state: u16,
    /// `gp.failedTries` in RAM: ahead of the NV header while a DA failure that happened with NV
    /// unavailable is pending (`da_pending_on_nv`).
    pub failed_tries: u32,
    /// `s_DAPendingOnNV`: `failed_tries` and `lockout_auth_enabled` still have to be written to NV
    /// (by the next command with NV available).
    pub da_pending_on_nv: bool,
    /// `g_nvOk`.
    pub nv_ok: bool,
    /// `g_prevOrderlyState`.
    pub prev_orderly_state: u16,
    /// `g_powerWasLost`.
    pub power_was_lost: bool,
    /// `g_phEnable`.
    pub ph_enable: bool,
    /// `g_pcrReConfig`.
    pub pcr_reconfig: bool,
    /// `g_exclusiveAuditSession`.
    pub exclusive_audit_session: Option<u32>,
    /// `g_DrtmPreStartup`.
    pub drtm_pre_startup: bool,
    /// `g_DRTMHandle` (`None`: `TPM_RH_UNASSIGNED`).
    pub drtm_handle: Option<u32>,
    /// `g_StartupLocality3`.
    pub startup_locality_3: bool,
    /// Whether a DA-protected entity was used in this power cycle (`g_daUsed`).
    pub da_used: bool,
    /// `gp.lockOutAuthEnabled`: the one `gp` field that is not always in NV (with
    /// `lockoutRecovery == 0` a `lockoutAuth` failure clears it in RAM only).
    pub lockout_auth_enabled: bool,
    /// The locality of the engine (`s_locality`).
    pub locality: u8,
    /// Whether Physical Presence is asserted (`s_physicalPresence`).
    pub physical_presence: bool,
}

/// One PCR bank: the 24 PCR values, each padded to 64 octets. The bank's algorithm is implied by
/// its position in [`PersistedPcrState::banks`] (`PcrState::IMPLEMENTED_BANKS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedPcrBank {
    #[cfg_attr(feature = "serde", serde(with = "super::serde_arrays::nested_bytes"))]
    pub values: [[u8; DIGEST_CAP]; PCR_COUNT],
}

impl Default for PersistedPcrBank {
    fn default() -> Self {
        Self {
            values: [[0u8; DIGEST_CAP]; PCR_COUNT],
        }
    }
}

/// The PCR banks and the active allocation (`s_pcrs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedPcrState {
    /// The implemented banks, in `PcrState::IMPLEMENTED_BANKS` order, allocated or not.
    pub banks: Array<PersistedPcrBank, MAX_PCR_BANKS>,
    /// The active allocation (a marshaled `TPML_PCR_SELECTION`). A pending allocation of
    /// `TPM2_PCR_Allocate` is in NV.
    pub allocation: Array<u8, { TpmlPcrSelection::MAX_SIZE }>,
}

/// A loaded transient object in RAM. Its Name (`nameAlg || H_nameAlg(public)`) is recomputed at
/// restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedTransientObject {
    pub handle: u32,
    pub hierarchy: u32,
    pub st_clear: bool,
    pub external: bool,
    pub public_only: bool,
    pub seed: Array<u8, SEED_CAP>,
    pub auth: Array<u8, DIGEST_CAP>,
    pub qualified_name: Array<u8, NAME_CAP>,
    /// The marshaled public area (`TPMT_PUBLIC`).
    pub public_bytes: Array<u8, { TpmtPublic::MAX_SIZE }>,
    /// The private value of the object ([`crate::handler::TransientObject::private`]: the prime
    /// `p` of an RSA key).
    pub private: Array<u8, MAX_PRIVATE_KEY_SIZE>,
}

/// The secure channel restrictions of a policy session (`TPM2_PolicyTransportSPDM()`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedSecChannelPolicy {
    pub check_secure_channel: bool,
    pub check_req_key: bool,
    pub check_tpm_key: bool,
    pub sc_key_name_hash: Array<u8, DIGEST_CAP>,
}

/// An active authorization session in RAM. `isBound` is `bound_entity` being non-empty,
/// `isNameHashDefined` follows from `policy_hash` and the other flags
/// (`SessionState::is_name_hash_defined`), and `includeAuth` is recomputed by every command
/// before it is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedSessionState {
    pub session_handle: u32,
    /// `TPM_SE`.
    pub session_type: u8,
    pub auth_hash: u16,
    pub nonce_tpm: Array<u8, DIGEST_CAP>,
    pub session_key: Array<u8, SESSION_KEY_CAP>,
    /// The marshaled symmetric definition (`TPMT_SYM_DEF+`).
    pub symmetric_bytes: Array<u8, { <Option<TpmtSymDef>>::MAX_SIZE }>,
    /// The bind value of a bound HMAC session (`u1.boundEntity`); empty if it is not bound.
    pub bound_entity: Array<u8, NAME_CAP>,
    pub audit_digest: Option<Array<u8, DIGEST_CAP>>,
    pub policy_hash: Array<u8, DIGEST_CAP>,
    pub policy_digest: Array<u8, DIGEST_CAP>,
    pub command_code: u32,
    pub start_time: u64,
    pub timeout: u64,
    /// The time epoch of `start_time` (`CLOCK_NONCE`, see the module documentation).
    pub epoch: u32,
    pub pcr_counter: Option<u32>,
    pub command_locality: u8,
    pub is_cp_hash_defined: bool,
    pub is_template_hash_defined: bool,
    pub is_parameters_hash_defined: bool,
    pub is_pp_required: bool,
    pub is_auth_value_needed: bool,
    pub is_password_needed: bool,
    pub check_nv_written: bool,
    pub nv_written_state: bool,
    pub is_da_bound: bool,
    pub is_lockout_bound: bool,
    pub sec_channel: PersistedSecChannelPolicy,
}

/// A session whose context has been saved (an entry of `gr.contextArray`). Only its slot is
/// observable, not the type of its handle: the lookups of saved sessions ignore the handle type,
/// and `TPM2_GetCapability(TPM_CAP_HANDLES)` reports HMAC session handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedSavedSession {
    /// The session slot (`handle & 0x00FF_FFFF`).
    pub slot: u32,
    /// The low `CONTEXT_SLOT` (16) bits of the context sequence number of the latest
    /// `TPM2_ContextSave` of the session, as in `gr.contextArray`: the sequence number is the
    /// latest one up to [`PersistedResetData::context_counter`] with these low bits (the context
    /// gap, `TPM_PT_CONTEXT_GAP_MAX`, keeps it within 2^16 of the counter).
    pub sequence: u16,
}

/// Type of an active cryptographic sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PersistedSequenceType {
    #[default]
    Event,
    Hash {
        alg: u16,
    },
    Hmac {
        hash_alg: u16,
        key: Array<u8, SENSITIVE_DATA_CAP>,
    },
    /// A CMAC sequence (`TPM2_MAC_Start`, the `cmac` feature): the serialized `CmacState`.
    Cmac {
        #[cfg_attr(feature = "serde", serde(with = "super::serde_arrays::bytes"))]
        state: [u8; CmacState::SERIALIZED_SIZE],
    },
    /// A signing sequence: the serialized `SignatureSequence`.
    Sign {
        state: Array<u8, { SignatureSequence::SERIALIZED_MAX_SIZE }>,
    },
    /// A verification sequence: the serialized `SignatureSequence`.
    Verify {
        state: Array<u8, { SignatureSequence::SERIALIZED_MAX_SIZE }>,
    },
}

/// An active hash/HMAC/event/MAC/signature sequence in RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedActiveSequence {
    pub handle: u32,
    pub auth: Array<u8, DIGEST_CAP>,
    pub sequence_type: PersistedSequenceType,
    /// Whether a data block has been received (C `firstBlock`).
    pub first_block: bool,
    /// Whether the first data block makes a ticket safe (C `ticketSafe`).
    pub ticket_safe: bool,
    /// The serialized streaming hash states (`ActiveSequence::serialize_state`, which holds the
    /// ML-DSA `mu` state in place of the last one).
    #[cfg_attr(feature = "serde", serde(with = "super::serde_arrays::nested_bytes"))]
    pub hash_states: [[u8; StreamingHashState::SERIALIZED_SIZE]; 4],
}

impl Default for PersistedActiveSequence {
    fn default() -> Self {
        Self {
            handle: 0,
            auth: Array::new(),
            sequence_type: PersistedSequenceType::Event,
            first_block: false,
            ticket_safe: false,
            hash_states: [[0u8; StreamingHashState::SERIALIZED_SIZE]; 4],
        }
    }
}

/// The objects, sessions and sequences loaded in RAM (`s_objects`, `s_sessions`), each in
/// ascending handle order. Their slots in RAM are not observable (every lookup goes by handle,
/// and `TPM_CAP_HANDLES` sorts): restore assigns them in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedLoadedEntities {
    pub objects: Array<PersistedTransientObject, MAX_LOADED_OBJECTS>,
    pub sessions: Array<PersistedSessionState, MAX_LOADED_SESSIONS>,
    pub sequences: Array<PersistedActiveSequence, MAX_ACTIVE_SEQUENCES>,
}

/// The ECDAA commit state (`gr.commitCounter`, `gr.commitArray`, `gr.commitNonce`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedCommitState {
    /// `gr.commitCounter`.
    pub counter: u64,
    #[cfg_attr(feature = "serde", serde(with = "super::serde_arrays::bytes"))]
    pub array: [u8; 16],
    /// `gr.commitNonce`: the octets the commit KDF uses (the size of the largest implemented
    /// digest).
    pub nonce: Array<u8, DIGEST_CAP>,
}

/// Algorithm self-test state (`g_toTest` and Failure mode), which the engine keeps outside
/// `GlobalState` (`TpmEngine::self_test`). The Failure-mode diagnostics of the references
/// (`s_failFunction`, `s_failLine`, `s_failCode`) have no counterpart: in Failure mode `tpm-rs`
/// always reports the location 0 and `FATAL_ERROR_SELF_TEST` (see the `persistence` module
/// documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedSelfTestState {
    /// The algorithms that still need a self test, in ascending order.
    pub untested_algorithms: Array<u16, MAX_UNTESTED_ALGORITHMS>,
    /// Whether a self test has failed (Failure mode).
    pub failed: bool,
}

/// One Authenticated Countdown Timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedAct {
    pub remaining: u32,
    pub new_value: u32,
    pub pending: bool,
    pub signaled: bool,
    /// The policy hash algorithm (`None`: `TPM_ALG_NULL`).
    pub policy_alg: Option<u16>,
    pub policy: Array<u8, DIGEST_CAP>,
    /// The timeout saved by the last `TPM2_Shutdown(TPM_SU_STATE)`.
    pub saved_timeout: u32,
}

/// The Authenticated Countdown Timers (`ActState`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedActState {
    /// One entry per implemented ACT (`act::IMPLEMENTED_ACTS` order).
    pub acts: Array<PersistedAct, MAX_ACTS>,
    pub saved_signaled: u16,
    pub preserved_signaled: u16,
    pub updated: u16,
    /// The platform milliseconds since the last tick (the last whole second of the platform
    /// timer since the power on) at the save; restore continues from the reading of the
    /// target's timer. Ticks are allowed while `runtime.initialized`.
    pub tick_phase_ms: u64,
}

/// Vendor-specific state in RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedVendorState {
    /// The vendor-permanent authorization value of `TPM_RH_AUTH_00`
    /// (`g_platformUniqueDetails`).
    pub platform_unique_details: Array<u8, DIGEST_CAP>,
    /// The Nuvoton `NTC2_*` configuration (`None` without the `ntc2-vendor-commands` feature).
    pub ntc2_config: Option<[u8; NTC2_CONFIG_SIZE]>,
}

/// The platform state that the platform (e.g. the simulator), not the engine, keeps: the
/// installed firmware image (the `SetFirmwareHash`/`SetFirmwareSvn` platform signals). The
/// platform is powered on with NV enabled at every point where the state is saved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedPlatformState {
    /// The firmware hash the Firmware Secret is derived from.
    pub firmware_hash: u32,
    /// The firmware SVN.
    pub firmware_svn: u16,
}

/// The complete state of a TPM: its NV content, the state that is ahead of NV or only in RAM,
/// and (when saved by a platform) the platform state. See the `persistence` module documentation
/// for what is not persisted and why.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedTpmState {
    /// The raw NV content: the source of truth for every NV-synced field.
    pub nv: PersistedNvImage,
    /// C `gr`.
    pub reset: PersistedResetData,
    /// C `gc`.
    pub clear: PersistedClearData,
    /// C `go`.
    pub orderly: PersistedOrderlyData,
    pub time: PersistedTimeState,
    pub runtime: PersistedRuntimeState,
    pub loaded: PersistedLoadedEntities,
    pub pcrs: PersistedPcrState,
    pub act: PersistedActState,
    pub vendor: PersistedVendorState,
    pub self_test: PersistedSelfTestState,
    /// The platform state: set by the platform's persistence methods (e.g.
    /// `tpm2_simulator::Simulator::save_persisted_state`); `None` when the state is extracted
    /// from an engine alone.
    pub platform: Option<PersistedPlatformState>,
}
