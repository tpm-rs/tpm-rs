#![forbid(unsafe_code)]

//! Bidirectional conversion between [`PersistedTpmState`] and `tpm-rs` [`State`] (with its NV
//! data, [`crate::Nv::index`]).
//!
//! Extraction copies the NV content (the reserved header and the canonical payloads of the
//! storage manager's items, see [`PersistedNvImage`]) and the state that is ahead of NV or only
//! in RAM. Restore rewrites the NV data from the image, reloads every NV-synced field of
//! [`State`] from the NV records of the image ([`crate::storage::nv`]: [`NvHeader`],
//! [`NvHierarchyRecord`] and [`NvPlatformSettingsRecord`]), applies the RAM groups, recomputes
//! the derivable values and sets the derived fields to the values they have between two
//! commands with NV available (see the `persistence` module documentation).
//!
//! Both directions take the reading of the platform timer (`now_ms`): the persisted state holds
//! the platform time relative to the reading at the save, and restore rebases it on the reading
//! of the target's timer.

use core::fmt;

use tpm2::crypto::backend::Hash;
use tpm2::{Alg, Handle, Marshal, TpmSe, TpmiAlgHash, TpmlPcrSelection, TpmtSymDef, Unmarshal};

use crate::Platform;
use crate::act::{ACT_COUNT, ActCounter, ActPolicy};
use crate::command_audit::CommandAuditList;
use crate::engine::{MAX_ACTIVE_SESSIONS, MAX_CONTEXT_GAP, SignatureSequence};
use crate::handler::{MAX_PRIVATE_KEY_SIZE, SecChannelPolicy, SessionState, TransientObject};
use crate::hash_state::StreamingHashState;
use crate::owned::{OwnedName, OwnedPublic, OwnedTpm2b};
use crate::physical_presence::PpList;
use crate::self_test::{ALG_LAST, AlgorithmVector, SelfTestState};
use crate::state::{Detached, NoIndex};
use crate::storage::manager::{MAX_ITEMS, RESERVED_SIZE, TOC_SIZE};
use crate::storage::nv::{
    HIERARCHY_RECORD_HANDLE, HIERARCHY_RECORD_SIZE, NvHeader, NvHierarchyRecord, NvIndexRecord,
    NvPersistentObjectRecord, NvPlatformSettingsRecord, NvStateSaveRecord, PCR_ALLOCATION_HANDLE,
    PERSISTENT_OBJECT_MAX_LEN, PLATFORM_SETTINGS_HANDLE, PLATFORM_SETTINGS_LEN, STATE_SAVE_HANDLE,
    STATE_SAVE_MAX_LEN,
};
use crate::storage::{IndexState, StorageError};
use crate::{
    ActiveSequence, DrbgState, MAX_ACTIVE_SEQUENCES, MAX_LOADED_OBJECTS, MAX_LOADED_SESSIONS,
    SequenceType, State,
};

use super::types::{
    Array, DIGEST_CAP, MAX_NV_DATA_SIZE, MAX_NV_ITEMS, MAX_PCR_BANKS, NV_HEADER_SIZE, PCR_COUNT,
    PersistedAct, PersistedActState, PersistedActiveSequence, PersistedClearData,
    PersistedCommitState, PersistedDrbgState, PersistedLoadedEntities, PersistedNvImage,
    PersistedOrderlyData, PersistedPcrBank, PersistedPcrState, PersistedResetData,
    PersistedRuntimeState, PersistedSavedSession, PersistedSecChannelPolicy,
    PersistedSelfTestState, PersistedSequenceType, PersistedSessionState, PersistedTimeState,
    PersistedTpmState, PersistedTransientObject, PersistedVendorState,
};

// A saved session is persisted with the low 16 bits (`CONTEXT_SLOT`) of its sequence number.
const _: () = assert!(MAX_CONTEXT_GAP == 1 << 16);

/// Errors that can occur when reconstructing a `State` or deserializing state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeserializeError {
    MissingField(&'static str),
    InvalidType {
        field: &'static str,
        expected: &'static str,
    },
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidValue(&'static str),
    /// Writing the NV storage failed.
    Storage(StorageError),
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeserializeError::MissingField(field) => {
                write!(f, "Missing required field '{}'", field)
            }
            DeserializeError::InvalidType { field, expected } => {
                write!(
                    f,
                    "Field '{}' has invalid type (expected {})",
                    field, expected
                )
            }
            DeserializeError::InvalidLength {
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Field '{}' has invalid length: expected {}, got {}",
                    field, expected, actual
                )
            }
            DeserializeError::InvalidValue(msg) => write!(f, "Invalid value: {}", msg),
            DeserializeError::Storage(err) => write!(f, "NV storage error: {:?}", err),
        }
    }
}

impl core::error::Error for DeserializeError {}

/// Errors that can occur when extracting a [`PersistedTpmState`] from a `State` and its
/// NV storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerializeError {
    /// A value does not fit the capacity of its persisted field.
    Capacity {
        field: &'static str,
        capacity: usize,
        actual: usize,
    },
    /// The NV storage is not in the layout of the storage manager, or an item is not a valid
    /// record.
    InvalidStorage(&'static str),
    /// The state is inconsistent (e.g. a saved session outside the context gap).
    InvalidState(&'static str),
    /// Reading the NV storage failed.
    Storage(StorageError),
}

impl fmt::Display for SerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializeError::Capacity {
                field,
                capacity,
                actual,
            } => write!(
                f,
                "Field '{}' does not fit: capacity {}, got {}",
                field, capacity, actual
            ),
            SerializeError::InvalidStorage(msg) => write!(f, "Invalid NV storage: {}", msg),
            SerializeError::InvalidState(msg) => write!(f, "Invalid TPM state: {}", msg),
            SerializeError::Storage(err) => write!(f, "NV storage error: {:?}", err),
        }
    }
}

impl core::error::Error for SerializeError {}

impl From<StorageError> for SerializeError {
    fn from(err: StorageError) -> Self {
        SerializeError::Storage(err)
    }
}

impl From<StorageError> for DeserializeError {
    fn from(err: StorageError) -> Self {
        DeserializeError::Storage(err)
    }
}

// ---------------------------------------------------------------------------------------------
// Extraction helpers (State -> PersistedTpmState).
// ---------------------------------------------------------------------------------------------

/// Copies `src` into a persisted array, failing if it exceeds the capacity `N`.
fn persist<T: Default + Copy, const N: usize>(
    src: &[T],
    field: &'static str,
) -> Result<Array<T, N>, SerializeError> {
    Array::try_from_slice(src).ok_or(SerializeError::Capacity {
        field,
        capacity: N,
        actual: src.len(),
    })
}

/// The first `len` bytes of `src` (an array with a separate length field).
fn prefix<'a>(src: &'a [u8], len: usize, field: &'static str) -> Result<&'a [u8], SerializeError> {
    src.get(..len).ok_or(SerializeError::Capacity {
        field,
        capacity: src.len(),
        actual: len,
    })
}

/// [`persist`] of the first `len` bytes of `src`.
fn persist_prefix<const N: usize>(
    src: &[u8],
    len: usize,
    field: &'static str,
) -> Result<Array<u8, N>, SerializeError> {
    persist(prefix(src, len, field)?, field)
}

/// The algorithm ID of an optional hash algorithm (`None`: `TPM_ALG_NULL`).
fn alg_id(alg: Option<TpmiAlgHash>) -> Option<u16> {
    alg.map(|a| Alg::from(a).id())
}

// ---------------------------------------------------------------------------------------------
// Application helpers (PersistedTpmState -> State).
// ---------------------------------------------------------------------------------------------

/// The active elements of a persisted array, rejecting a length beyond its capacity.
fn bytes<'a, T, const N: usize>(
    arr: &'a Array<T, N>,
    field: &'static str,
) -> Result<&'a [T], DeserializeError> {
    if arr.len > N {
        return Err(DeserializeError::InvalidLength {
            field,
            expected: N,
            actual: arr.len,
        });
    }
    Ok(&arr.data[..arr.len])
}

/// A `TPM2B`-like owned buffer from a persisted array.
fn owned<const CAP: usize, const N: usize>(
    arr: &Array<u8, N>,
    field: &'static str,
) -> Result<OwnedTpm2b<CAP>, DeserializeError> {
    OwnedTpm2b::new(bytes(arr, field)?).ok_or(DeserializeError::InvalidLength {
        field,
        expected: CAP,
        actual: arr.len,
    })
}

/// Copies a persisted array into the zero-padded fixed array `dst`, returning its length.
fn fixed<const M: usize, const N: usize>(
    arr: &Array<u8, N>,
    dst: &mut [u8; M],
    field: &'static str,
) -> Result<usize, DeserializeError> {
    let src = bytes(arr, field)?;
    if src.len() > M {
        return Err(DeserializeError::InvalidLength {
            field,
            expected: M,
            actual: src.len(),
        });
    }
    dst.fill(0);
    dst[..src.len()].copy_from_slice(src);
    Ok(src.len())
}

/// Like [`fixed`], for a fixed array with a `u16` size field.
fn fixed_u16<const M: usize, const N: usize>(
    arr: &Array<u8, N>,
    dst: &mut [u8; M],
    size: &mut u16,
    field: &'static str,
) -> Result<(), DeserializeError> {
    *size = fixed(arr, dst, field)? as u16;
    Ok(())
}

/// Like [`fixed`], requiring the persisted array to fill `dst` exactly.
fn exact<const M: usize, const N: usize>(
    arr: &Array<u8, N>,
    dst: &mut [u8; M],
    field: &'static str,
) -> Result<(), DeserializeError> {
    if arr.len != M {
        return Err(DeserializeError::InvalidLength {
            field,
            expected: M,
            actual: arr.len,
        });
    }
    fixed(arr, dst, field).map(|_| ())
}

/// An optional hash algorithm (`None`: `TPM_ALG_NULL`); `Some` must name an implemented hash.
fn opt_alg_hash(
    val: Option<u16>,
    field: &'static str,
) -> Result<Option<TpmiAlgHash>, DeserializeError> {
    val.map(|v| alg_hash(v, field)).transpose()
}

/// An implemented hash algorithm.
fn alg_hash(val: u16, field: &'static str) -> Result<TpmiAlgHash, DeserializeError> {
    TpmiAlgHash::try_from(val).map_err(|_| DeserializeError::InvalidValue(field))
}

/// Checks that a slot index is in range and not used twice.
fn claim_slot(
    slot: u32,
    used: &mut [bool],
    field: &'static str,
) -> Result<usize, DeserializeError> {
    let slot = slot as usize;
    match used.get_mut(slot) {
        Some(taken) if !*taken => {
            *taken = true;
            Ok(slot)
        }
        _ => Err(DeserializeError::InvalidValue(field)),
    }
}

// ---------------------------------------------------------------------------------------------
// Extraction.
// ---------------------------------------------------------------------------------------------

impl PersistedTpmState {
    /// Extracts a structured [`PersistedTpmState`] from a live `tpm-rs` [`State`] (with its NV
    /// data, [`crate::Nv::index`]).
    ///
    /// `now_ms` is the current reading of the platform timer: the platform time is persisted
    /// relative to it. The self-test state, which is not part of [`State`], is set to its
    /// state after `_TPM_Init` (every algorithm needs its test, no Failure mode); see
    /// [`Self::extract_self_test`]. The platform state is not known to the engine (`None`).
    pub(crate) fn extract_from_global_state<P: Platform>(
        &mut self,
        state: &State<P>,
        now_ms: u64,
    ) -> Result<(), SerializeError> {
        self.extract_nv(&state.nv.index)?;
        self.reset = extract_reset(state)?;
        self.clear = PersistedClearData {
            sh_enable: state.nv.clear.sh_enable,
            eh_enable: state.nv.clear.eh_enable,
            ph_enable_nv: state.nv.clear.ph_enable_nv,
            platform_auth: persist(state.nv.clear.platform_auth.get_buffer(), "platform_auth")?,
            platform_policy: persist(
                state.nv.clear.platform_policy.get_buffer(),
                "platform_policy",
            )?,
            platform_alg: alg_id(state.nv.clear.platform_alg),
            pcr_auth_value: persist(state.nv.clear.pcr_auth_value.get_buffer(), "pcr_auth_value")?,
            read_only: state.nv.clear.read_only,
        };
        self.orderly = PersistedOrderlyData {
            drbg: drbg_to_persisted(&state.nv.orderly.drbg_state),
            clock_safe: state.nv.orderly.clock_safe,
            self_heal_timer: state.nv.orderly.self_heal_timer,
            lockout_timer: state.nv.orderly.lockout_timer,
            shutdown_time_ms: state.nv.orderly.shutdown_time_ms,
        };
        // The platform time elapsed since the last timer read (none if the timer has not been
        // read since the TPM was created) and the remainder of the last update of *Time*.
        let unread_ms = state
            .last_timer_read_ms
            .map_or(0, |last| now_ms.saturating_sub(last));
        self.time = PersistedTimeState {
            time_ms: state.tpm_time_ms,
            clock_offset: state.nv.orderly.clock_offset,
            adjust_rate: state.clock_adjust_rate,
            pending_platform_ms: unread_ms.saturating_add(state.clock_adjust_remainder),
            timer_stopped: state.timer_stopped,
            timer_was_reset: state.timer_was_reset,
        };
        self.runtime = PersistedRuntimeState {
            initialized: state.initialized,
            orderly_state: state.nv.persistent.orderly_state,
            failed_tries: state.nv.persistent.failed_tries,
            da_pending_on_nv: state.da_pending_on_nv,
            nv_ok: state.g_nv_ok,
            prev_orderly_state: state.prev_orderly_state,
            power_was_lost: state.power_was_lost,
            ph_enable: state.ph_enable,
            pcr_reconfig: state.pcr_reconfig,
            exclusive_audit_session: state.exclusive_audit_session,
            drtm_pre_startup: state.drtm_pre_startup,
            drtm_handle: (state.drtm_handle != Handle::RH_UNASSIGNED.0)
                .then_some(state.drtm_handle),
            startup_locality_3: state.startup_locality_3,
            da_used: state.da_used,
            lockout_auth_enabled: state.nv.persistent.lockout_auth_enabled,
            locality: state.locality,
            physical_presence: state.physical_presence,
        };
        self.loaded = PersistedLoadedEntities {
            objects: extract_transient_objects(state)?,
            sessions: extract_sessions(state)?,
            sequences: extract_sequences(state)?,
        };
        self.pcrs = extract_pcrs(state)?;
        self.act = extract_act(state, now_ms)?;
        self.vendor = PersistedVendorState {
            platform_unique_details: persist(
                state.platform_unique_details.get_buffer(),
                "platform_unique_details",
            )?,
            ntc2_config: None,
        };
        #[cfg(feature = "ntc2-vendor-commands")]
        {
            let mut buf = [0u8; super::types::NTC2_CONFIG_SIZE];
            let len = state.ntc2_config.marshal(&mut buf);
            if len != buf.len() {
                return Err(SerializeError::Capacity {
                    field: "ntc2_config",
                    capacity: buf.len(),
                    actual: len,
                });
            }
            self.vendor.ntc2_config = Some(buf);
        }
        self.extract_self_test(&SelfTestState::default())?;
        self.platform = None;
        Ok(())
    }

    /// Extracts the algorithm self-test state (`TpmEngine::self_test`).
    pub(crate) fn extract_self_test(
        &mut self,
        self_test: &SelfTestState,
    ) -> Result<(), SerializeError> {
        let mut untested = Array::new();
        for alg in self_test.load().iter() {
            if untested.len == untested.data.len() {
                return Err(SerializeError::Capacity {
                    field: "untested_algorithms",
                    capacity: untested.data.len(),
                    actual: self_test.load().iter().count(),
                });
            }
            untested.push(alg);
        }
        self.self_test = PersistedSelfTestState {
            untested_algorithms: untested,
            failed: self_test.failed(),
        };
        Ok(())
    }

    /// Extracts the raw reserved NV header and every NV item with its canonical payload
    /// ([`read_canonical_nv_payload`]), in ascending handle order.
    fn extract_nv(&mut self, storage: &(impl IndexState + ?Sized)) -> Result<(), SerializeError> {
        let nv: &mut PersistedNvImage = &mut self.nv;
        storage.read_reserved(0, &mut nv.header)?;
        nv.handles = Array::new();
        nv.data = Array::new();
        // The items (handle, size) in storage order, then sorted by handle.
        let mut items = [(0u32, 0usize); MAX_ITEMS];
        let mut count = 0;
        for item in storage.items()? {
            if item.in_use == 0 {
                break;
            }
            items[count] = (item.handle, item.data_size as usize);
            count += 1;
        }
        let items = &mut items[..count];
        items.sort_unstable_by_key(|&(handle, _)| handle);
        if items.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(SerializeError::InvalidStorage("duplicate NV item handle"));
        }
        if count > MAX_NV_ITEMS {
            return Err(SerializeError::Capacity {
                field: "nv.handles",
                capacity: MAX_NV_ITEMS,
                actual: count,
            });
        }
        for &(handle, size) in items.iter() {
            let start = nv.data.len;
            let len = read_canonical_nv_payload(storage, handle, size, &mut nv.data.data[start..])?;
            nv.data.len += len;
            nv.handles.push(handle);
        }
        Ok(())
    }
}

/// Reads the NV item `handle` (`size` octets of `storage`), writes its canonical
/// payload to the start of `out` and returns its length:
///
/// - a persistent object and the hierarchy and state-save records: the encoding of the decoded
///   record (without the unused octets after the hierarchy record);
/// - an NV Index (`TPM2B_AUTH || TPM2B_NV_PUBLIC || data`), the PCR allocation and the
///   platform settings: the item itself.
///
/// In every case, [`nv_payload_len`] recovers the length from the content.
fn read_canonical_nv_payload(
    storage: &(impl IndexState + ?Sized),
    handle: u32,
    size: usize,
    out: &mut [u8],
) -> Result<usize, SerializeError> {
    let invalid = SerializeError::InvalidStorage("NV item payload");
    let too_large = |actual| SerializeError::Capacity {
        field: "nv.data",
        capacity: MAX_NV_DATA_SIZE,
        actual,
    };
    let reencoded = matches!(handle, HIERARCHY_RECORD_HANDLE | STATE_SAVE_HANDLE)
        || handle >> 24 == tpm2::TpmHt::Persistent as u32;
    let len = if reencoded {
        let mut raw = [0u8; PERSISTENT_OBJECT_MAX_LEN];
        let raw = raw.get_mut(..size).ok_or(invalid)?;
        storage.read_item(handle, 0, raw)?;
        let mut buf = [0u8; PERSISTENT_OBJECT_MAX_LEN];
        let len = match handle {
            HIERARCHY_RECORD_HANDLE => {
                let record = NvHierarchyRecord::decode(raw).ok_or(invalid)?;
                record.encode((&mut buf[..HIERARCHY_RECORD_SIZE]).try_into().unwrap())
            }
            STATE_SAVE_HANDLE => {
                let record = NvStateSaveRecord::decode(raw).ok_or(invalid)?;
                record.encode((&mut buf[..STATE_SAVE_MAX_LEN]).try_into().unwrap())
            }
            _ => {
                let record = NvPersistentObjectRecord::decode(raw).map_err(|_| invalid)?;
                record.encode(&mut buf).map_err(|_| invalid)?
            }
        };
        out.get_mut(..len)
            .ok_or(too_large(len))?
            .copy_from_slice(&buf[..len]);
        len
    } else {
        storage.read_item(handle, 0, out.get_mut(..size).ok_or(too_large(size))?)?;
        size
    };
    // The payload must be self-delimiting, so that restore can split the image.
    if nv_payload_len(handle, &out[..len]) != Some(len) {
        return Err(invalid);
    }
    Ok(len)
}

const _: () = assert!(HIERARCHY_RECORD_SIZE <= PERSISTENT_OBJECT_MAX_LEN);
const _: () = assert!(STATE_SAVE_MAX_LEN <= PERSISTENT_OBJECT_MAX_LEN);

/// The length of the canonical payload of the NV item `handle` at the start of `rest` (see
/// [`read_canonical_nv_payload`]), or `None` if `rest` does not start with one.
fn nv_payload_len(handle: u32, rest: &[u8]) -> Option<usize> {
    let len = match handle {
        HIERARCHY_RECORD_HANDLE => {
            let mut buf = [0u8; HIERARCHY_RECORD_SIZE];
            let len = NvHierarchyRecord::decode(rest)?.encode(&mut buf);
            (rest.get(..len)? == &buf[..len]).then_some(len)?
        }
        STATE_SAVE_HANDLE => {
            let mut buf = [0u8; STATE_SAVE_MAX_LEN];
            let len = NvStateSaveRecord::decode(rest)?.encode(&mut buf);
            (rest.get(..len)? == &buf[..len]).then_some(len)?
        }
        PCR_ALLOCATION_HANDLE => {
            let mut slice = rest;
            TpmlPcrSelection::unmarshal(&mut slice).ok()?;
            rest.len() - slice.len()
        }
        PLATFORM_SETTINGS_HANDLE => PLATFORM_SETTINGS_LEN,
        h if h >> 24 == tpm2::TpmHt::NVIndex as u32 => {
            let record = NvIndexRecord::decode(rest).ok()?;
            if record.public.nv_index.0 != h {
                return None;
            }
            record.metadata_size + usize::from(record.public.data_size)
        }
        h if h >> 24 == tpm2::TpmHt::Persistent as u32 => {
            let mut buf = [0u8; PERSISTENT_OBJECT_MAX_LEN];
            let record = NvPersistentObjectRecord::decode(rest).ok()?;
            let len = record.encode(&mut buf).ok()?;
            (rest.get(..len)? == &buf[..len]).then_some(len)?
        }
        _ => return None,
    };
    (len <= rest.len()).then_some(len)
}

fn extract_reset<P: Platform>(state: &State<P>) -> Result<PersistedResetData, SerializeError> {
    let mut saved_sessions = Array::new();
    for (slot, saved) in state.nv.reset.saved_sessions.iter().enumerate() {
        if saved.is_some() {
            let sequence = state.nv.reset.saved_session_sequences[slot];
            // The context gap keeps every saved session within `MAX_CONTEXT_GAP` of the
            // counter, so that the low bits identify its sequence number.
            let gap = state.nv.reset.context_counter.checked_sub(sequence);
            if !gap.is_some_and(|gap| (1..=MAX_CONTEXT_GAP).contains(&gap)) {
                return Err(SerializeError::InvalidState(
                    "saved session outside the context gap",
                ));
            }
            saved_sessions.push(PersistedSavedSession {
                slot: slot as u32,
                sequence: sequence as u16,
            });
        }
    }
    Ok(PersistedResetData {
        null_proof: persist_prefix(
            &state.nv.reset.null_proof,
            state.nv.reset.null_proof_size as usize,
            "null_proof",
        )?,
        null_seed: persist_prefix(
            &state.nv.reset.null_seed,
            state.nv.reset.null_seed_size as usize,
            "null_seed",
        )?,
        object_context_counter: state.nv.reset.object_context_counter,
        context_counter: state.nv.reset.context_counter,
        saved_sessions,
        command_audit_digest: persist(
            state.nv.reset.command_audit_digest.get_buffer(),
            "command_audit_digest",
        )?,
        restart_count: state.nv.reset.restart_count,
        clear_count: state.nv.reset.clear_count,
        pcr_update_counter: state.pcrs.update_counter,
        commit: PersistedCommitState {
            counter: state.nv.reset.commit_counter,
            array: state.nv.reset.commit_array,
            nonce: persist(&state.nv.reset.commit_nonce, "commit.nonce")?,
        },
    })
}

fn extract_pcrs<P: Platform>(state: &State<P>) -> Result<PersistedPcrState, SerializeError> {
    let mut banks = Array::<PersistedPcrBank, MAX_PCR_BANKS>::new();
    for &alg in tpm2::platform::PcrState::IMPLEMENTED_BANKS {
        let mut bank = PersistedPcrBank::default();
        for (pcr, value) in bank.values.iter_mut().enumerate() {
            let src = state
                .pcrs
                .value(alg, pcr)
                .ok_or(SerializeError::InvalidStorage("PCR bank"))?;
            value[..src.len()].copy_from_slice(src);
        }
        banks.push(bank);
    }
    let mut alloc = [0u8; tpm2::TpmlPcrSelection::MAX_SIZE];
    let alloc_len = state
        .pcrs
        .pcr_allocation
        .marshal((&mut alloc[..]).try_into().unwrap());
    Ok(PersistedPcrState {
        banks,
        allocation: persist(&alloc[..alloc_len], "pcrs.allocation")?,
    })
}

fn extract_transient_objects<P: Platform>(
    state: &State<P>,
) -> Result<Array<PersistedTransientObject, MAX_LOADED_OBJECTS>, SerializeError> {
    let mut objects: Array<PersistedTransientObject, MAX_LOADED_OBJECTS> = Array::new();
    for obj in state.transient_objects.iter().flatten() {
        let mut public = [0u8; tpm2::TpmtPublic::MAX_SIZE];
        let pub_len = obj
            .public
            .marshal((&mut public[..OwnedPublic::MAX_SIZE]).try_into().unwrap());
        objects.push(PersistedTransientObject {
            handle: obj.handle,
            hierarchy: obj.hierarchy,
            st_clear: obj.st_clear,
            external: obj.external,
            public_only: obj.public_only,
            seed: persist_prefix(&obj.seed, obj.seed_len, "object.seed")?,
            auth: persist(obj.auth.get_buffer(), "object.auth")?,
            qualified_name: persist(obj.qualified_name.get_buffer(), "object.qualified_name")?,
            public_bytes: persist(&public[..pub_len], "object.public")?,
            private: persist_prefix(&obj.private, obj.private_len, "object.private")?,
        });
    }
    objects
        .as_mut_slice()
        .sort_unstable_by_key(|obj| obj.handle);
    Ok(objects)
}

fn extract_sessions<P: Platform>(
    state: &State<P>,
) -> Result<Array<PersistedSessionState, MAX_LOADED_SESSIONS>, SerializeError> {
    let mut sessions: Array<PersistedSessionState, MAX_LOADED_SESSIONS> = Array::new();
    for sess in state.active_sessions.iter().flatten() {
        let mut sym = [0u8; <Option<TpmtSymDef>>::MAX_SIZE];
        let sym_len = sess.symmetric.marshal((&mut sym[..]).try_into().unwrap());
        let audit_digest = match &sess.audit_digest {
            Some(ad) => Some(persist_prefix(
                ad,
                sess.audit_digest_len,
                "session.audit_digest",
            )?),
            None => None,
        };
        let sc = &sess.sec_channel;
        sessions.push(PersistedSessionState {
            session_handle: sess.session_handle,
            session_type: u8::from(sess.session_type),
            auth_hash: Alg::from(sess.auth_hash).id(),
            nonce_tpm: persist(sess.nonce_tpm.get_buffer(), "session.nonce_tpm")?,
            session_key: persist_prefix(
                &sess.session_key,
                sess.session_key_len,
                "session.session_key",
            )?,
            symmetric_bytes: persist(&sym[..sym_len], "session.symmetric")?,
            bound_entity: persist(sess.bound_entity.get_buffer(), "session.bound_entity")?,
            audit_digest,
            policy_hash: persist_prefix(
                &sess.policy_hash,
                sess.policy_hash_len,
                "session.policy_hash",
            )?,
            policy_digest: persist_prefix(
                &sess.policy_digest,
                sess.policy_digest_len,
                "session.policy_digest",
            )?,
            command_code: sess.command_code,
            start_time: sess.start_time,
            timeout: sess.timeout,
            epoch: sess.epoch,
            pcr_counter: sess.pcr_counter,
            command_locality: sess.command_locality,
            is_cp_hash_defined: sess.is_cp_hash_defined,
            is_template_hash_defined: sess.is_template_hash_defined,
            is_parameters_hash_defined: sess.is_parameters_hash_defined,
            is_pp_required: sess.is_pp_required,
            is_auth_value_needed: sess.is_auth_value_needed,
            is_password_needed: sess.is_password_needed,
            check_nv_written: sess.check_nv_written,
            nv_written_state: sess.nv_written_state,
            is_da_bound: sess.is_da_bound,
            is_lockout_bound: sess.is_lockout_bound,
            sec_channel: PersistedSecChannelPolicy {
                check_secure_channel: sc.check_secure_channel,
                check_req_key: sc.check_req_key,
                check_tpm_key: sc.check_tpm_key,
                sc_key_name_hash: persist_prefix(
                    &sc.sc_key_name_hash,
                    sc.sc_key_name_hash_len,
                    "session.sc_key_name_hash",
                )?,
            },
        });
    }
    sessions
        .as_mut_slice()
        .sort_unstable_by_key(|sess| sess.session_handle);
    Ok(sessions)
}

fn extract_sequences<P: Platform>(
    state: &State<P>,
) -> Result<Array<PersistedActiveSequence, MAX_ACTIVE_SEQUENCES>, SerializeError> {
    let mut sequences: Array<PersistedActiveSequence, MAX_ACTIVE_SEQUENCES> = Array::new();
    for seq in state.active_sequences.iter().flatten() {
        let sequence_type = match &seq.sequence_type {
            SequenceType::Event => PersistedSequenceType::Event,
            SequenceType::Hash { alg } => PersistedSequenceType::Hash {
                alg: Alg::from(*alg).id(),
            },
            SequenceType::Hmac { hash_alg, key } => PersistedSequenceType::Hmac {
                hash_alg: Alg::from(*hash_alg).id(),
                key: persist(key.get_buffer(), "sequence.hmac_key")?,
            },
            #[cfg(feature = "cmac")]
            SequenceType::Cmac { state } => {
                let mut buf = [0u8; crate::cmac::CmacState::SERIALIZED_SIZE];
                state.serialize(&mut buf);
                PersistedSequenceType::Cmac { state: buf }
            }
            SequenceType::Sign(sig) => PersistedSequenceType::Sign {
                state: signature_sequence_to_persisted(sig),
            },
            SequenceType::Verify(sig) => PersistedSequenceType::Verify {
                state: signature_sequence_to_persisted(sig),
            },
        };
        let mut persisted = PersistedActiveSequence {
            handle: seq.handle,
            auth: persist(seq.auth.get_buffer(), "sequence.auth")?,
            sequence_type,
            first_block: seq.first_block,
            ticket_safe: seq.ticket_safe,
            ..Default::default()
        };
        for (i, dst) in persisted.hash_states.iter_mut().enumerate() {
            seq.serialize_state(i, dst);
        }
        sequences.push(persisted);
    }
    sequences
        .as_mut_slice()
        .sort_unstable_by_key(|seq| seq.handle);
    Ok(sequences)
}

fn extract_act<P: Platform>(
    state: &State<P>,
    now_ms: u64,
) -> Result<PersistedActState, SerializeError> {
    let act = &state.act;
    let mut acts = Array::new();
    for i in 0..ACT_COUNT {
        let counter = &act.counters[i];
        let policy = &act.policies[i];
        acts.push(PersistedAct {
            remaining: counter.remaining,
            new_value: counter.new_value,
            pending: counter.pending,
            signaled: counter.signaled,
            policy_alg: alg_id(policy.hash_alg),
            policy: persist(policy.auth_policy.get_buffer(), "act.policy")?,
            saved_timeout: act.saved_timeouts[i],
        });
    }
    Ok(PersistedActState {
        acts,
        saved_signaled: act.saved_signaled,
        preserved_signaled: act.preserved_signaled,
        updated: act.updated,
        tick_phase_ms: act
            .tick_phase_ms
            .saturating_add(now_ms.saturating_sub(act.tick_last_read_ms)),
    })
}

// ---------------------------------------------------------------------------------------------
// Restore.
// ---------------------------------------------------------------------------------------------

impl PersistedTpmState {
    /// Applies this [`PersistedTpmState`] onto an existing `tpm-rs` [`State`] (with its NV
    /// data, [`crate::Nv::index`]).
    ///
    /// The new state is built from scratch (`State::default()`, i.e. the derived fields
    /// get their values between two commands with NV available): the NV-synced fields are
    /// reloaded from the NV records of [`Self::nv`], then the RAM groups are applied, with the
    /// platform time rebased on `now_ms` (the current reading of the target's platform timer)
    /// and the Names of the loaded objects recomputed with the crypto backend `H`. The whole persisted state
    /// is validated before `state` is modified; the NV storage is then erased and rewritten
    /// from the image. The self-test state is not applied (see [`Self::apply_self_test`]).
    pub(crate) fn apply_to_global_state<H: Hash, P: Platform>(
        &self,
        state: &mut State<P>,
        now_ms: u64,
    ) -> Result<(), DeserializeError> {
        self.validate_nv(state.nv.index.nv_capacity())?;
        // The new state is staged without NV data, so that the target is not touched before
        // the whole persisted state is validated.
        let mut staged = State::<Detached<P>>::new(NoIndex);
        self.load_nv_synced(&mut staged)?;
        self.apply_ram_state::<H, _>(&mut staged, now_ms)?;
        self.write_nv(&mut state.nv.index)?;
        state.replace_except_index(staged);
        Ok(())
    }

    /// Calls `f` with the handle and the payload of every NV item of the image, in order,
    /// splitting [`PersistedNvImage::data`] by the lengths the payloads encode
    /// ([`nv_payload_len`]). Fails if a payload is malformed or the data does not end with the
    /// last payload.
    fn for_each_nv_item<'a>(
        &'a self,
        mut f: impl FnMut(u32, &'a [u8]) -> Result<(), DeserializeError>,
    ) -> Result<(), DeserializeError> {
        let data = bytes(&self.nv.data, "nv.data")?;
        let mut rest = data;
        for &handle in bytes(&self.nv.handles, "nv.handles")? {
            let len =
                nv_payload_len(handle, rest).ok_or(DeserializeError::InvalidValue("nv.data"))?;
            let (payload, tail) = rest.split_at(len);
            f(handle, payload)?;
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(DeserializeError::InvalidLength {
                field: "nv.data",
                expected: data.len() - rest.len(),
                actual: data.len(),
            });
        }
        Ok(())
    }

    /// The payload of the NV item `handle` of the image, if present (the image is validated by
    /// [`Self::validate_nv`]).
    fn nv_item(&self, handle: u32) -> Result<Option<&[u8]>, DeserializeError> {
        let mut found = None;
        self.for_each_nv_item(|h, payload| {
            if h == handle {
                found = Some(payload);
            }
            Ok(())
        })?;
        Ok(found)
    }

    /// Reloads the NV-synced fields from the NV records of the image, as `_TPM_Init` would: the
    /// counters and the orderly state of the reserved header ([`NvHeader`]), the hierarchy
    /// record ([`NvHierarchyRecord`]: the owner/endorsement/lockout authorizations and
    /// policies, the primary seeds and hierarchy proofs, `clearCount`, the PCR policy, the
    /// lifecycle and DA parameters and the command audit state) and the platform settings
    /// ([`NvPlatformSettingsRecord`]). A missing (or malformed) record or section leaves the
    /// manufacture defaults, like `_TPM_Init` does. The fields of the hierarchy record that
    /// are not authoritative in NV (`STATE_CLEAR_DATA`, `gp.lockOutAuthEnabled` and `go.clock`)
    /// come from the RAM groups instead.
    fn load_nv_synced<P: Platform>(&self, st: &mut State<P>) -> Result<(), DeserializeError> {
        let header = NvHeader::decode(&self.nv.header);
        st.nv.persistent.reset_count = header.reset_count;
        st.nv.persistent.orderly_state = header.orderly_state;
        st.nv.persistent.total_reset_count = header.total_reset_count;
        st.nv.persistent.time_epoch = header.time_epoch;
        st.nv.persistent.failed_tries = header.failed_tries;
        st.nv.persistent.max_counter = header.max_counter;

        let record = self
            .nv_item(HIERARCHY_RECORD_HANDLE)?
            .and_then(|b| NvHierarchyRecord::decode(&b[..b.len().min(HIERARCHY_RECORD_SIZE)]));
        if let Some(r) = record {
            st.nv.persistent.owner_auth = r.owner_auth;
            st.nv.persistent.endorsement_auth = r.endorsement_auth;
            st.nv.persistent.lockout_auth = r.lockout_auth;
            st.nv.persistent.owner_policy = r.owner_policy;
            st.nv.persistent.endorsement_policy = r.endorsement_policy;
            st.nv.persistent.lockout_policy = r.lockout_policy;
            st.nv.persistent.owner_alg = r.owner_alg;
            st.nv.persistent.endorsement_alg = r.endorsement_alg;
            st.nv.persistent.lockout_alg = r.lockout_alg;
            if let Some(seeds) = &r.seeds {
                st.nv.persistent.sp_seed = seeds.sp_seed;
                st.nv.persistent.sp_seed_size = seeds.sp_seed_size;
                st.nv.persistent.sh_proof = seeds.sh_proof;
                st.nv.persistent.sh_proof_size = seeds.sh_proof_size;
                st.nv.persistent.eh_proof = seeds.eh_proof;
                st.nv.persistent.eh_proof_size = seeds.eh_proof_size;
                st.nv.reset.clear_count = seeds.clear_count;
                st.nv.persistent.pp_seed = seeds.pp_seed;
                st.nv.persistent.pp_seed_size = seeds.pp_seed_size;
                st.nv.persistent.ph_proof = seeds.ph_proof;
                st.nv.persistent.ph_proof_size = seeds.ph_proof_size;
                st.nv.persistent.ep_seed = seeds.ep_seed;
                st.nv.persistent.ep_seed_size = seeds.ep_seed_size;
                if let Some(alg) = seeds.pcr_policy_alg {
                    st.nv.persistent.pcr_policy_alg = alg;
                }
                if let Some(policy) = seeds.pcr_policy {
                    st.nv.persistent.pcr_policy = policy;
                }
            }
            if let Some(ext) = &r.lifecycle {
                st.nv.persistent.disable_clear = ext.disable_clear;
                st.nv.persistent.max_tries = ext.max_tries;
                st.nv.persistent.recovery_time = ext.recovery_time;
                st.nv.persistent.lockout_recovery = ext.lockout_recovery;
            }
            if let Some(audit) = &r.audit {
                st.nv.persistent.audit_hash_alg = audit.hash_alg;
                st.nv.persistent.audit_counter = audit.counter;
                st.nv.persistent.audit_commands = CommandAuditList::from_bytes(&audit.commands);
            }
        }

        let settings = self.nv_item(PLATFORM_SETTINGS_HANDLE)?.and_then(|b| {
            b.get(..PLATFORM_SETTINGS_LEN)
                .map(|b| NvPlatformSettingsRecord::decode(b.try_into().unwrap()))
        });
        if let Some(settings) = settings {
            st.nv.persistent.pp_list = PpList::from_bits(settings.pp_list);
            st.nv.persistent.algorithm_set = settings.algorithm_set;
        }
        Ok(())
    }

    /// Applies the RAM groups (everything but the NV image and the self-test state), after the
    /// NV-synced fields: the RAM values that may be ahead of NV (`clear_count`,
    /// `orderly_state`, `failed_tries`, `lockout_auth_enabled`) replace the ones reloaded from
    /// NV.
    fn apply_ram_state<H: Hash, P: Platform>(
        &self,
        state: &mut State<P>,
        now_ms: u64,
    ) -> Result<(), DeserializeError> {
        self.apply_reset(state)?;

        let c = &self.clear;
        state.nv.clear.sh_enable = c.sh_enable;
        state.nv.clear.eh_enable = c.eh_enable;
        state.nv.clear.ph_enable_nv = c.ph_enable_nv;
        state.nv.clear.platform_auth = owned(&c.platform_auth, "clear.platform_auth")?;
        state.nv.clear.platform_policy = owned(&c.platform_policy, "clear.platform_policy")?;
        state.nv.clear.platform_alg = opt_alg_hash(c.platform_alg, "clear.platform_alg")?;
        state.nv.clear.pcr_auth_value = owned(&c.pcr_auth_value, "clear.pcr_auth_value")?;
        state.nv.clear.read_only = c.read_only;

        let o = &self.orderly;
        state.nv.orderly.drbg_state = drbg_from_persisted(&o.drbg);
        state.nv.orderly.clock_safe = o.clock_safe;
        state.nv.orderly.self_heal_timer = o.self_heal_timer;
        state.nv.orderly.lockout_timer = o.lockout_timer;
        state.nv.orderly.shutdown_time_ms = o.shutdown_time_ms;

        let t = &self.time;
        state.tpm_time_ms = t.time_ms;
        state.nv.orderly.clock_offset = t.clock_offset;
        state.clock_adjust_rate = t.adjust_rate;
        // The pending platform time continues from the current reading of the target's timer.
        state.clock_adjust_remainder = t.pending_platform_ms;
        state.last_timer_read_ms = Some(now_ms);
        state.timer_stopped = t.timer_stopped;
        state.timer_was_reset = t.timer_was_reset;

        let r = &self.runtime;
        state.initialized = r.initialized;
        state.nv.persistent.orderly_state = r.orderly_state;
        state.nv.persistent.failed_tries = r.failed_tries;
        state.da_pending_on_nv = r.da_pending_on_nv;
        state.g_nv_ok = r.nv_ok;
        state.prev_orderly_state = r.prev_orderly_state;
        state.power_was_lost = r.power_was_lost;
        state.ph_enable = r.ph_enable;
        state.pcr_reconfig = r.pcr_reconfig;
        state.exclusive_audit_session = r.exclusive_audit_session;
        state.drtm_pre_startup = r.drtm_pre_startup;
        state.drtm_handle = match r.drtm_handle {
            None => Handle::RH_UNASSIGNED.0,
            Some(h) if h == Handle::RH_UNASSIGNED.0 => {
                return Err(DeserializeError::InvalidValue("runtime.drtm_handle"));
            }
            Some(h) => h,
        };
        state.startup_locality_3 = r.startup_locality_3;
        state.da_used = r.da_used;
        state.nv.persistent.lockout_auth_enabled = r.lockout_auth_enabled;
        state.locality = r.locality;
        state.physical_presence = r.physical_presence;

        self.apply_transient_objects::<H, P>(state)?;
        self.apply_sessions(state)?;
        self.apply_sequences(state)?;
        self.check_loaded_handles()?;
        self.apply_pcrs(state)?;
        self.apply_act(state, now_ms)?;

        state.platform_unique_details = owned(
            &self.vendor.platform_unique_details,
            "vendor.platform_unique_details",
        )?;
        #[cfg(feature = "ntc2-vendor-commands")]
        {
            let config = self
                .vendor
                .ntc2_config
                .ok_or(DeserializeError::MissingField("vendor.ntc2_config"))?;
            state.ntc2_config = tpm2::commands::Ntc2CfgStruct::unmarshal(&mut &config[..])
                .map_err(|_| DeserializeError::InvalidValue("vendor.ntc2_config"))?;
        }
        #[cfg(not(feature = "ntc2-vendor-commands"))]
        if self.vendor.ntc2_config.is_some() {
            return Err(DeserializeError::InvalidValue("vendor.ntc2_config"));
        }
        Ok(())
    }

    fn apply_reset<P: Platform>(&self, state: &mut State<P>) -> Result<(), DeserializeError> {
        let r = &self.reset;
        fixed_u16(
            &r.null_proof,
            &mut state.nv.reset.null_proof,
            &mut state.nv.reset.null_proof_size,
            "reset.null_proof",
        )?;
        fixed_u16(
            &r.null_seed,
            &mut state.nv.reset.null_seed,
            &mut state.nv.reset.null_seed_size,
            "reset.null_seed",
        )?;
        state.nv.reset.object_context_counter = r.object_context_counter;
        state.nv.reset.context_counter = r.context_counter;

        state.nv.reset.saved_sessions = [None; MAX_ACTIVE_SESSIONS];
        state.nv.reset.saved_session_sequences = [0; MAX_ACTIVE_SESSIONS];
        let mut used = [false; MAX_ACTIVE_SESSIONS];
        for saved in bytes(&r.saved_sessions, "reset.saved_sessions")? {
            let slot = claim_slot(saved.slot, &mut used, "reset.saved_sessions.slot")?;
            // The low counter values 0..=MAX_LOADED_SESSIONS are never sequence numbers (they
            // mark loaded sessions in the C `contextArray`).
            if usize::from(saved.sequence) <= MAX_LOADED_SESSIONS {
                return Err(DeserializeError::InvalidValue(
                    "reset.saved_sessions.sequence",
                ));
            }
            // The latest sequence number up to the counter with these low bits (the counter is
            // never the sequence number of a saved session).
            let gap = match (r.context_counter as u16).wrapping_sub(saved.sequence) {
                0 => MAX_CONTEXT_GAP,
                gap => u64::from(gap),
            };
            let sequence =
                r.context_counter
                    .checked_sub(gap)
                    .ok_or(DeserializeError::InvalidValue(
                        "reset.saved_sessions.sequence",
                    ))?;
            // Only the slot of a saved session is observable, not its handle type.
            state.nv.reset.saved_sessions[slot] = Some(Handle::HR_HMAC_SESSION.0 | slot as u32);
            state.nv.reset.saved_session_sequences[slot] = sequence;
        }

        state.nv.reset.command_audit_digest =
            owned(&r.command_audit_digest, "reset.command_audit_digest")?;
        state.nv.reset.restart_count = r.restart_count;
        state.nv.reset.clear_count = r.clear_count;
        state.pcrs.update_counter = r.pcr_update_counter;

        state.nv.reset.commit_counter = r.commit.counter;
        state.nv.reset.commit_array = r.commit.array;
        exact(
            &r.commit.nonce,
            &mut state.nv.reset.commit_nonce,
            "reset.commit.nonce",
        )?;
        Ok(())
    }

    fn apply_pcrs<P: Platform>(&self, state: &mut State<P>) -> Result<(), DeserializeError> {
        let banks = bytes(&self.pcrs.banks, "pcrs.banks")?;
        let implemented = tpm2::platform::PcrState::IMPLEMENTED_BANKS;
        if banks.len() != implemented.len() {
            return Err(DeserializeError::InvalidLength {
                field: "pcrs.banks",
                expected: implemented.len(),
                actual: banks.len(),
            });
        }
        for (bank, &alg) in banks.iter().zip(implemented) {
            for (pcr, value) in bank.values.iter().enumerate().take(PCR_COUNT) {
                let dst = state
                    .pcrs
                    .value_mut(alg, pcr)
                    .ok_or(DeserializeError::InvalidValue("pcrs.banks"))?;
                let len = dst.len();
                dst.copy_from_slice(&value[..len]);
            }
        }
        let mut slice = bytes(&self.pcrs.allocation, "pcrs.allocation")?;
        state.pcrs.pcr_allocation = tpm2::TpmlPcrSelection::unmarshal(&mut slice)
            .map_err(|_| DeserializeError::InvalidValue("pcrs.allocation"))?;
        if !slice.is_empty() {
            return Err(DeserializeError::InvalidValue("pcrs.allocation"));
        }
        Ok(())
    }

    /// Applies the loaded objects, in the slots of their order, and recomputes their Names.
    fn apply_transient_objects<H: Hash, P: Platform>(
        &self,
        state: &mut State<P>,
    ) -> Result<(), DeserializeError> {
        state.transient_objects = [const { None }; MAX_LOADED_OBJECTS];
        for (i, obj) in bytes(&self.loaded.objects, "loaded.objects")?
            .iter()
            .enumerate()
        {
            let public_bytes = bytes(&obj.public_bytes, "object.public")?;
            let mut pub_slice = public_bytes;
            let public = OwnedPublic::unmarshal_nullable(&mut pub_slice)
                .map_err(|_| DeserializeError::InvalidValue("object.public"))?;
            if !pub_slice.is_empty() {
                return Err(DeserializeError::InvalidValue("object.public"));
            }
            let mut seed = [0u8; 64];
            let seed_len = fixed(&obj.seed, &mut seed, "object.seed")?;
            let mut private = [0u8; MAX_PRIVATE_KEY_SIZE];
            let private_len = fixed(&obj.private, &mut private, "object.private")?;
            state.transient_objects[i] = Some(TransientObject {
                handle: obj.handle,
                seed,
                seed_len,
                external: obj.external,
                public_only: obj.public_only,
                name: object_name::<H>(public.name_alg, public_bytes)?,
                auth: owned(&obj.auth, "object.auth")?,
                public,
                private,
                private_len,
                qualified_name: owned(&obj.qualified_name, "object.qualified_name")?,
                hierarchy: obj.hierarchy,
                st_clear: obj.st_clear,
            });
        }
        Ok(())
    }

    fn apply_sessions<P: Platform>(&self, state: &mut State<P>) -> Result<(), DeserializeError> {
        state.active_sessions = [const { None }; MAX_LOADED_SESSIONS];
        for (i, sess) in bytes(&self.loaded.sessions, "loaded.sessions")?
            .iter()
            .enumerate()
        {
            let session_type = TpmSe::try_from(sess.session_type)
                .map_err(|_| DeserializeError::InvalidValue("session.session_type"))?;
            let auth_hash = alg_hash(sess.auth_hash, "session.auth_hash")?;
            let mut sym_slice = bytes(&sess.symmetric_bytes, "session.symmetric")?;
            let symmetric = <Option<TpmtSymDef>>::unmarshal(&mut sym_slice)
                .map_err(|_| DeserializeError::InvalidValue("session.symmetric"))?;
            if !sym_slice.is_empty() {
                return Err(DeserializeError::InvalidValue("session.symmetric"));
            }
            let mut session_key = [0u8; 128];
            let session_key_len =
                fixed(&sess.session_key, &mut session_key, "session.session_key")?;
            let (audit_digest, audit_digest_len) = match &sess.audit_digest {
                Some(ad) => {
                    let mut arr = [0u8; 64];
                    let len = fixed(ad, &mut arr, "session.audit_digest")?;
                    (Some(arr), len)
                }
                None => (None, 0),
            };
            let mut policy_hash = [0u8; 64];
            let policy_hash_len =
                fixed(&sess.policy_hash, &mut policy_hash, "session.policy_hash")?;
            let mut policy_digest = [0u8; 64];
            let policy_digest_len = fixed(
                &sess.policy_digest,
                &mut policy_digest,
                "session.policy_digest",
            )?;
            let mut sc_key_name_hash = [0u8; 64];
            let sc_key_name_hash_len = fixed(
                &sess.sec_channel.sc_key_name_hash,
                &mut sc_key_name_hash,
                "session.sc_key_name_hash",
            )?;

            state.active_sessions[i] = Some(SessionState {
                session_handle: sess.session_handle,
                session_type,
                auth_hash,
                nonce_tpm: owned(&sess.nonce_tpm, "session.nonce_tpm")?,
                session_key,
                session_key_len,
                symmetric,
                bound_entity: owned(&sess.bound_entity, "session.bound_entity")?,
                audit_digest,
                audit_digest_len,
                policy_hash,
                policy_hash_len,
                is_cp_hash_defined: sess.is_cp_hash_defined,
                is_template_hash_defined: sess.is_template_hash_defined,
                is_parameters_hash_defined: sess.is_parameters_hash_defined,
                is_pp_required: sess.is_pp_required,
                policy_digest,
                policy_digest_len,
                command_code: sess.command_code,
                start_time: sess.start_time,
                timeout: sess.timeout,
                epoch: sess.epoch,
                is_auth_value_needed: sess.is_auth_value_needed,
                is_password_needed: sess.is_password_needed,
                pcr_counter: sess.pcr_counter,
                check_nv_written: sess.check_nv_written,
                nv_written_state: sess.nv_written_state,
                command_locality: sess.command_locality,
                // Recomputed by every command before it is used.
                include_auth: false,
                is_da_bound: sess.is_da_bound,
                is_lockout_bound: sess.is_lockout_bound,
                sec_channel: SecChannelPolicy {
                    check_secure_channel: sess.sec_channel.check_secure_channel,
                    check_req_key: sess.sec_channel.check_req_key,
                    check_tpm_key: sess.sec_channel.check_tpm_key,
                    sc_key_name_hash,
                    sc_key_name_hash_len,
                },
            });
        }
        Ok(())
    }

    fn apply_sequences<P: Platform>(&self, state: &mut State<P>) -> Result<(), DeserializeError> {
        state.active_sequences = [const { None }; MAX_ACTIVE_SEQUENCES];
        for (i, seq) in bytes(&self.loaded.sequences, "loaded.sequences")?
            .iter()
            .enumerate()
        {
            let sequence_type = match &seq.sequence_type {
                PersistedSequenceType::Event => SequenceType::Event,
                PersistedSequenceType::Hash { alg } => SequenceType::Hash {
                    alg: alg_hash(*alg, "sequence.alg")?,
                },
                PersistedSequenceType::Hmac { hash_alg, key } => SequenceType::Hmac {
                    hash_alg: alg_hash(*hash_alg, "sequence.hash_alg")?,
                    key: owned(key, "sequence.hmac_key")?,
                },
                #[cfg(feature = "cmac")]
                PersistedSequenceType::Cmac { state } => SequenceType::Cmac {
                    state: crate::cmac::CmacState::deserialize(state)
                        .ok_or(DeserializeError::InvalidValue("sequence.cmac_state"))?,
                },
                #[cfg(not(feature = "cmac"))]
                PersistedSequenceType::Cmac { .. } => {
                    return Err(DeserializeError::InvalidValue("sequence.cmac_state"));
                }
                PersistedSequenceType::Sign { state } => {
                    SequenceType::Sign(signature_sequence_from_persisted(state)?)
                }
                PersistedSequenceType::Verify { state } => {
                    SequenceType::Verify(signature_sequence_from_persisted(state)?)
                }
            };
            let has_mu_state = ActiveSequence::has_mu_state(&sequence_type);
            let mut hash_states = [StreamingHashState::default(); 4];
            let mut mu_state = None;
            for (h_idx, hs_bytes) in seq.hash_states.iter().enumerate() {
                if has_mu_state && h_idx == ActiveSequence::MU_STATE_SLOT {
                    mu_state = Some(
                        ActiveSequence::mu_state_from_slot(hs_bytes)
                            .ok_or(DeserializeError::InvalidValue("sequence.mu_state"))?,
                    );
                } else {
                    hash_states[h_idx] = StreamingHashState::deserialize(hs_bytes)
                        .ok_or(DeserializeError::InvalidValue("sequence.hash_state"))?;
                }
            }

            let mut sequence = ActiveSequence::new(
                seq.handle,
                owned::<{ tpm2::Tpm2bAuth::CAP }, DIGEST_CAP>(&seq.auth, "sequence.auth")?,
                sequence_type,
            );
            sequence.first_block = seq.first_block;
            sequence.ticket_safe = seq.ticket_safe;
            sequence.hash_states = hash_states;
            sequence.mu_state = mu_state;
            state.active_sequences[i] = Some(sequence);
        }
        Ok(())
    }

    fn apply_act<P: Platform>(
        &self,
        state: &mut State<P>,
        now_ms: u64,
    ) -> Result<(), DeserializeError> {
        let acts = bytes(&self.act.acts, "act.acts")?;
        if acts.len() != ACT_COUNT {
            return Err(DeserializeError::InvalidLength {
                field: "act.acts",
                expected: ACT_COUNT,
                actual: acts.len(),
            });
        }
        for (i, act) in acts.iter().enumerate() {
            state.act.counters[i] = ActCounter {
                remaining: act.remaining,
                new_value: act.new_value,
                pending: act.pending,
                signaled: act.signaled,
            };
            state.act.policies[i] = ActPolicy {
                hash_alg: opt_alg_hash(act.policy_alg, "act.policy_alg")?,
                auth_policy: owned(&act.policy, "act.policy")?,
            };
            state.act.saved_timeouts[i] = act.saved_timeout;
        }
        state.act.saved_signaled = self.act.saved_signaled;
        state.act.preserved_signaled = self.act.preserved_signaled;
        state.act.updated = self.act.updated;
        // The tick phase continues from the current reading of the target's timer.
        state.act.tick_last_read_ms = now_ms;
        state.act.tick_phase_ms = self.act.tick_phase_ms;
        Ok(())
    }

    /// Checks that the loaded entities have distinct handles: the objects and sequences share
    /// the transient handles, and the sessions (loaded or saved) the session slots.
    fn check_loaded_handles(&self) -> Result<(), DeserializeError> {
        let objects = bytes(&self.loaded.objects, "loaded.objects")?;
        let sequences = bytes(&self.loaded.sequences, "loaded.sequences")?;
        let mut transient = [0u32; MAX_LOADED_OBJECTS + MAX_ACTIVE_SEQUENCES];
        for (count, handle) in objects
            .iter()
            .map(|o| o.handle)
            .chain(sequences.iter().map(|s| s.handle))
            .enumerate()
        {
            if transient[..count].contains(&handle) {
                return Err(DeserializeError::InvalidValue("loaded.handle"));
            }
            transient[count] = handle;
        }
        let saved = bytes(&self.reset.saved_sessions, "reset.saved_sessions")?;
        let sessions = bytes(&self.loaded.sessions, "loaded.sessions")?;
        for (i, sess) in sessions.iter().enumerate() {
            let slot = sess.session_handle & 0x00FF_FFFF;
            if slot as usize >= MAX_ACTIVE_SESSIONS
                || sessions[..i]
                    .iter()
                    .any(|other| other.session_handle & 0x00FF_FFFF == slot)
                || saved.iter().any(|s| s.slot == slot)
            {
                return Err(DeserializeError::InvalidValue("session.session_handle"));
            }
        }
        Ok(())
    }

    /// Applies the algorithm self-test state onto `self_test` (`TpmEngine::self_test`).
    pub(crate) fn apply_self_test(
        &self,
        self_test: &SelfTestState,
    ) -> Result<(), DeserializeError> {
        let mut to_test = AlgorithmVector::default();
        for &alg in bytes(&self.self_test.untested_algorithms, "untested_algorithms")? {
            if alg > ALG_LAST {
                return Err(DeserializeError::InvalidValue("untested_algorithms"));
            }
            to_test.set(alg);
        }
        self_test.initialize();
        self_test.store(&to_test);
        if self.self_test.failed {
            self_test.fail();
        }
        Ok(())
    }

    /// Checks that the NV items are distinct, fit the storage manager (`capacity` octets of
    /// storage) and split `nv.data` exactly.
    fn validate_nv(&self, capacity: usize) -> Result<(), DeserializeError> {
        let handles = bytes(&self.nv.handles, "nv.handles")?;
        if handles.len() > MAX_ITEMS {
            return Err(DeserializeError::InvalidLength {
                field: "nv.handles",
                expected: MAX_ITEMS,
                actual: handles.len(),
            });
        }
        for (i, handle) in handles.iter().enumerate() {
            if handles[..i].contains(handle) {
                return Err(DeserializeError::InvalidValue("nv.handles"));
            }
        }
        let mut used = RESERVED_SIZE + TOC_SIZE;
        self.for_each_nv_item(|handle, payload| {
            used += nv_item_size(handle, payload);
            Ok(())
        })?;
        if used > capacity {
            return Err(DeserializeError::InvalidLength {
                field: "nv.data",
                expected: capacity,
                actual: used,
            });
        }
        Ok(())
    }

    /// Erases `storage` and writes the raw NV header and the NV items with their payloads; the
    /// item metadata is derived ([`nv_item_size`], [`nv_item_attributes`]).
    fn write_nv(&self, storage: &mut (impl IndexState + ?Sized)) -> Result<(), DeserializeError> {
        storage.erase()?;

        const _: () = assert!(NV_HEADER_SIZE == RESERVED_SIZE);
        storage.write_reserved(0, &self.nv.header)?;

        self.for_each_nv_item(|handle, payload| {
            storage.define_space(
                handle,
                nv_item_size(handle, payload) as u16,
                nv_item_attributes(handle, payload),
            )?;
            storage.write_item(handle, 0, payload)?;
            Ok(())
        })?;
        Ok(())
    }
}

impl PersistedNvImage {
    /// The range of [`Self::data`] that holds the payload of the NV item `handle`, or `None`
    /// if the image has no such item or a payload before it is malformed.
    pub fn item_range(&self, handle: u32) -> Option<core::ops::Range<usize>> {
        let mut rest = self.data.as_slice();
        let mut offset = 0;
        for &h in self.handles.iter() {
            let len = nv_payload_len(h, rest)?;
            if h == handle {
                return Some(offset..offset + len);
            }
            rest = &rest[len..];
            offset += len;
        }
        None
    }
}

/// The size of the storage item of the NV item `handle` with `payload`: the hierarchy record
/// keeps its fixed size ([`HIERARCHY_RECORD_SIZE`], so that it can grow in place), every other
/// item is its payload.
fn nv_item_size(handle: u32, payload: &[u8]) -> usize {
    if handle == HIERARCHY_RECORD_HANDLE {
        payload.len().max(HIERARCHY_RECORD_SIZE)
    } else {
        payload.len()
    }
}

/// The storage manager's attributes of the NV item `handle` with `payload`: the `TPMA_NV` of an
/// NV Index (the storage manager reads only its `TPMA_NV_PLATFORMCREATE`, which never changes;
/// `TPM2_NV_DefineSpace` stores the attributes of the new Index) and 0 for every other item.
fn nv_item_attributes(handle: u32, payload: &[u8]) -> u32 {
    if handle >> 24 == tpm2::TpmHt::NVIndex as u32 {
        NvIndexRecord::decode(payload).map_or(0, |record| record.public.attributes.0)
    } else {
        0
    }
}

/// The Name of an object (`nameAlg || H_nameAlg(public)`; empty with the `TPM_ALG_NULL`
/// `nameAlg`), from its marshaled public area.
fn object_name<H: Hash>(
    name_alg: Option<TpmiAlgHash>,
    public_bytes: &[u8],
) -> Result<OwnedName, DeserializeError> {
    let Some(alg) = name_alg else {
        return Ok(OwnedName::default());
    };
    let mut digest = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash::<H>(alg, &[public_bytes], &mut digest)
        .map_err(|_| DeserializeError::InvalidValue("object.public.name_alg"))?;
    let mut name = [0u8; 2 + TpmiAlgHash::MAX_DIGEST_BYTES];
    name[..2].copy_from_slice(&Alg::from(alg).id().to_be_bytes());
    let len = 2 + digest.digest().len();
    name[2..len].copy_from_slice(digest.digest());
    OwnedName::new(&name[..len]).ok_or(DeserializeError::InvalidValue("object.public"))
}

fn drbg_to_persisted(drbg: &DrbgState) -> PersistedDrbgState {
    PersistedDrbgState {
        reseed_counter: drbg.reseed_counter,
        magic: drbg.magic,
        seed: drbg.seed,
        last_value: drbg.last_value,
    }
}

fn drbg_from_persisted(drbg: &PersistedDrbgState) -> DrbgState {
    DrbgState {
        reseed_counter: drbg.reseed_counter,
        magic: drbg.magic,
        seed: drbg.seed,
        last_value: drbg.last_value,
    }
}

fn signature_sequence_to_persisted(
    sig: &SignatureSequence,
) -> Array<u8, { SignatureSequence::SERIALIZED_MAX_SIZE }> {
    let mut state = Array::new();
    state.len = sig.serialize(&mut state.data);
    state
}

fn signature_sequence_from_persisted(
    state: &Array<u8, { SignatureSequence::SERIALIZED_MAX_SIZE }>,
) -> Result<SignatureSequence, DeserializeError> {
    let mut slice = bytes(state, "sequence.signature_state")?;
    let sig = SignatureSequence::deserialize(&mut slice)
        .ok_or(DeserializeError::InvalidValue("sequence.signature_state"))?;
    if !slice.is_empty() {
        return Err(DeserializeError::InvalidValue("sequence.signature_state"));
    }
    Ok(sig)
}
