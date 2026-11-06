#![forbid(unsafe_code)]

//! Structured NV records: the layouts of everything tpm-rs keeps in NV, as typed records with
//! their `decode` (bytes → record) and `encode` (record → bytes), and the helpers that read and
//! write them through the TPM's NV data structure ([`IndexState`]).
//!
//! NV holds the reserved header (the first [`HEADER_SIZE`] octets, [`NvHeader`]) and the storage
//! manager's items. Besides the user's NV Indices ([`NvIndexRecord`], handles `0x01xx_xxxx`) and
//! persistent objects ([`NvPersistentObjectRecord`], `0x81xx_xxxx`), the engine keeps internal
//! records under implementation-specific handles that the specification leaves unused:
//!
//! | Handle | Record | Contents |
//! |---|---|---|
//! | [`HIERARCHY_RECORD_HANDLE`] `0x00FF_FFFF` | [`NvHierarchyRecord`] | hierarchy auths/policies, seeds and proofs, DA parameters, clock, audit settings |
//! | [`STATE_SAVE_HANDLE`] `0x00FF_FFFE` | [`NvStateSaveRecord`] | the `TPM2_Shutdown(TPM_SU_STATE)` data (`NV_STATE_RESET_DATA`/`NV_STATE_CLEAR_DATA`), between the shutdown and the next `TPM2_Startup` |
//! | [`PCR_ALLOCATION_HANDLE`] `0x00FF_FFFD` | [`NvPcrAllocationRecord`] | the PCR allocation of the last `TPM2_PCR_Allocate`, applied at the next `_TPM_Init` |
//! | [`PLATFORM_SETTINGS_HANDLE`] `0x00FF_FFFC` | [`NvPlatformSettingsRecord`] | `gp.ppList` and `gp.algorithmSet` |
//!
//! Every layout is defined only here: the engine reads and writes NV through these records, and
//! `persistence` uses them to load the NV-synced state from a restored NV image.

use crate::act::{ACT_COUNT, ActPolicy};
use crate::command_audit::COMMAND_AUDIT_LIST_SIZE;
use crate::engine::{COMMIT_NONCE_SIZE, DrbgState, MAX_ACTIVE_SESSIONS};
use crate::handler::{MAX_PRIVATE_KEY_SIZE, TransientObject};
use crate::owned::{OwnedAuth, OwnedDigest, OwnedName, OwnedPublic};
use crate::storage::manager::RESERVED_SIZE;
use crate::storage::{IndexState, StorageError};
use tpm2::errors::TpmRc;
use tpm2::{Marshal, Tpm2bAuth, Tpm2bNvPublic, TpmiAlgHash, TpmlPcrSelection, TpmsNvPublic};
use tpm2::{Tpm2bDigest, Unmarshal};

/// Size of the reserved NV header.
pub const HEADER_SIZE: usize = RESERVED_SIZE;
/// Handle of the hierarchy record ([`NvHierarchyRecord`]).
pub const HIERARCHY_RECORD_HANDLE: u32 = 0x00FF_FFFF;
/// Handle of the state-save record ([`NvStateSaveRecord`]).
pub const STATE_SAVE_HANDLE: u32 = 0x00FF_FFFE;
/// Handle of the pending PCR allocation ([`NvPcrAllocationRecord`]).
pub const PCR_ALLOCATION_HANDLE: u32 = 0x00FF_FFFD;
/// Handle of the platform settings record ([`NvPlatformSettingsRecord`]).
pub const PLATFORM_SETTINGS_HANDLE: u32 = 0x00FF_FFFC;

/// Whether `handle` is one of the engine's internal records (not a user NV Index or object).
pub const fn is_internal_record(handle: u32) -> bool {
    matches!(
        handle,
        HIERARCHY_RECORD_HANDLE
            | STATE_SAVE_HANDLE
            | PCR_ALLOCATION_HANDLE
            | PLATFORM_SETTINGS_HANDLE
    )
}

// ---------------------------------------------------------------------------------------------
// Reserved header.
// ---------------------------------------------------------------------------------------------

/// The reserved NV header (`NvReadPersistent()` / the persistent counters of `PERSISTENT_DATA`
/// and `ORDERLY_DATA` that the engine syncs field by field). All values are big-endian at their
/// `*_OFFSET`; the octets in between are zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NvHeader {
    /// `gp.resetCount`.
    pub reset_count: u32,
    /// `gp.orderlyState`.
    pub orderly_state: u16,
    /// `gp.totalResetCount`.
    pub total_reset_count: u64,
    /// `s_maxCounter`.
    pub max_counter: u64,
    /// `gp.timeEpoch` (a `UINT32` `CLOCK_NONCE`, zero-extended in its 8-octet slot).
    pub time_epoch: u32,
    /// `gp.failedTries`.
    pub failed_tries: u32,
    /// `go.drbgState` (written at startup, shutdown, `TPM2_Clear` and Clock updates).
    pub drbg: DrbgState,
    /// `go.selfHealTimer`.
    pub self_heal_timer: i64,
    /// `go.lockoutTimer`.
    pub lockout_timer: i64,
}

impl NvHeader {
    pub const RESET_COUNT_OFFSET: usize = 0;
    pub const ORDERLY_STATE_OFFSET: usize = 4;
    pub const TOTAL_RESET_COUNT_OFFSET: usize = 8;
    pub const MAX_COUNTER_OFFSET: usize = 16;
    pub const TIME_EPOCH_OFFSET: usize = 24;
    pub const FAILED_TRIES_OFFSET: usize = 32;
    pub const DRBG_OFFSET: usize = 36;
    pub const SELF_HEAL_TIMER_OFFSET: usize = 112;
    pub const LOCKOUT_TIMER_OFFSET: usize = 120;

    /// The octets of `time_epoch` in its slot at [`Self::TIME_EPOCH_OFFSET`].
    pub fn encode_time_epoch(time_epoch: u32) -> [u8; 8] {
        u64::from(time_epoch).to_be_bytes()
    }

    /// Decodes the header from its [`HEADER_SIZE`] octets.
    pub fn decode(b: &[u8; HEADER_SIZE]) -> Self {
        let u32_at = |o: usize| u32::from_be_bytes(b[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_be_bytes(b[o..o + 8].try_into().unwrap());
        Self {
            reset_count: u32_at(Self::RESET_COUNT_OFFSET),
            orderly_state: u16::from_be_bytes([
                b[Self::ORDERLY_STATE_OFFSET],
                b[Self::ORDERLY_STATE_OFFSET + 1],
            ]),
            total_reset_count: u64_at(Self::TOTAL_RESET_COUNT_OFFSET),
            max_counter: u64_at(Self::MAX_COUNTER_OFFSET),
            time_epoch: u64_at(Self::TIME_EPOCH_OFFSET) as u32,
            failed_tries: u32_at(Self::FAILED_TRIES_OFFSET),
            drbg: DrbgState::from_bytes(
                b[Self::DRBG_OFFSET..Self::DRBG_OFFSET + 76]
                    .try_into()
                    .unwrap(),
            ),
            self_heal_timer: u64_at(Self::SELF_HEAL_TIMER_OFFSET) as i64,
            lockout_timer: u64_at(Self::LOCKOUT_TIMER_OFFSET) as i64,
        }
    }

    /// Encodes the header into its [`HEADER_SIZE`] octets.
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut b = [0u8; HEADER_SIZE];
        let mut put = |o: usize, v: &[u8]| b[o..o + v.len()].copy_from_slice(v);
        put(Self::RESET_COUNT_OFFSET, &self.reset_count.to_be_bytes());
        put(
            Self::ORDERLY_STATE_OFFSET,
            &self.orderly_state.to_be_bytes(),
        );
        put(
            Self::TOTAL_RESET_COUNT_OFFSET,
            &self.total_reset_count.to_be_bytes(),
        );
        put(Self::MAX_COUNTER_OFFSET, &self.max_counter.to_be_bytes());
        put(
            Self::TIME_EPOCH_OFFSET,
            &Self::encode_time_epoch(self.time_epoch),
        );
        put(Self::FAILED_TRIES_OFFSET, &self.failed_tries.to_be_bytes());
        put(Self::DRBG_OFFSET, &self.drbg.to_bytes());
        put(
            Self::SELF_HEAL_TIMER_OFFSET,
            &self.self_heal_timer.to_be_bytes(),
        );
        put(
            Self::LOCKOUT_TIMER_OFFSET,
            &self.lockout_timer.to_be_bytes(),
        );
        b
    }

    /// Reads the header from `storage`.
    pub fn read(storage: &(impl IndexState + ?Sized)) -> Result<Self, StorageError> {
        let mut b = [0u8; HEADER_SIZE];
        storage.read_reserved(0, &mut b)?;
        Ok(Self::decode(&b))
    }
}

// ---------------------------------------------------------------------------------------------
// Item helpers.
// ---------------------------------------------------------------------------------------------

/// Reads the whole payload of item `handle` into `buf`, returning its length, or `None` if the
/// item is not defined, does not fit `buf`, or cannot be read.
fn read_item<'b>(
    storage: &mut (impl IndexState + ?Sized),
    handle: u32,
    buf: &'b mut [u8],
) -> Option<&'b [u8]> {
    let meta = storage.get_metadata(handle).ok()?;
    let len = meta.data_size as usize;
    let buf = buf.get_mut(..len)?;
    storage.read_item(handle, 0, buf).ok()?;
    Some(buf)
}

/// Replaces item `handle` with `data` (defining it with exactly `data.len()` octets).
fn replace_item(
    storage: &mut (impl IndexState + ?Sized),
    handle: u32,
    data: &[u8],
) -> Result<(), TpmRc> {
    let _ = storage.undefine_space(handle);
    storage
        .define_space(handle, data.len() as u16, 0)
        .map_err(|_| TpmRc::NV_SPACE)?;
    storage
        .write_item(handle, 0, data)
        .map_err(|_| TpmRc::FAILURE)
}

/// Removes item `handle`, if it exists.
pub fn delete_item(storage: &mut (impl IndexState + ?Sized), handle: u32) {
    let _ = storage.undefine_space(handle);
}

/// A writer over a fixed buffer for the record encoders.
struct Writer<'b> {
    buf: &'b mut [u8],
    len: usize,
}

impl<'b> Writer<'b> {
    fn new(buf: &'b mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    fn bytes(&mut self, v: &[u8]) {
        self.buf[self.len..self.len + v.len()].copy_from_slice(v);
        self.len += v.len();
    }

    fn marshal<M: Marshal>(&mut self, v: &M)
    where
        for<'a> &'a mut M::MaxBuffer: TryFrom<&'a mut [u8]>,
    {
        let dst = &mut self.buf[self.len..self.len + M::MAX_SIZE];
        let Ok(dst) = dst.try_into() else {
            unreachable!("M::MAX_SIZE octets always convert to M::MaxBuffer")
        };
        self.len += v.marshal(dst);
    }
}

/// A fixed `[u8; 64]` seed or proof with its size, stored as `size (u16) || 64 octets`.
fn put_sized64(w: &mut Writer<'_>, value: &[u8; 64], size: u16) {
    w.bytes(&size.to_be_bytes());
    w.bytes(value);
}

fn get_sized64(slice: &mut &[u8]) -> Option<([u8; 64], u16)> {
    let size = u16::unmarshal(slice).ok()?;
    let value = <[u8; 64]>::unmarshal(slice).ok()?;
    Some((value, size))
}

// ---------------------------------------------------------------------------------------------
// Hierarchy record (0x00FF_FFFF).
// ---------------------------------------------------------------------------------------------

/// Capacity of the hierarchy record (the item is always defined with this size).
pub const HIERARCHY_RECORD_SIZE: usize = 1152;
/// Marker of the seeds section of the hierarchy record.
pub const SEEDS_MARKER: u8 = 0xAA;
/// Marker of the persistent lifecycle extension of the hierarchy record.
pub const PERSISTENT_EXT_MARKER: u8 = 0xBB;
/// Length of the persistent lifecycle extension (marker + disableClear + lockOutAuthEnabled +
/// maxTries + recoveryTime + lockoutRecovery + clock + clockSafe).
pub const PERSISTENT_EXT_LEN: usize = 1 + 1 + 1 + 4 + 4 + 4 + 8 + 1;
/// Marker of the persistent command audit extension of the hierarchy record.
pub const AUDIT_EXT_MARKER: u8 = 0xCC;
/// Length of the persistent command audit extension (marker + `gp.auditHashAlg` +
/// `gp.auditCounter` + `gp.auditCommands` bitmap).
pub const AUDIT_EXT_LEN: usize = 1 + 2 + 8 + COMMAND_AUDIT_LIST_SIZE;

/// The hierarchy record: the persistent hierarchy data (`gp`) and a few related values.
///
/// Layout: the three auths and three policies (`TPM2B`s, owner/endorsement/lockout), the three
/// policy algorithms (`TPMI_ALG_HASH+`), then the optional sections, each introduced by its
/// marker: [`NvHierarchySeeds`] ([`SEEDS_MARKER`]), followed by [`NvLifecycleExt`]
/// ([`PERSISTENT_EXT_MARKER`]) and [`NvAuditExt`] ([`AUDIT_EXT_MARKER`]). Older layouts end
/// before a section, and the audit extension is also recognized directly after the seeds section
/// (a record without the lifecycle extension).
///
/// The `gc` state of the platform hierarchy (`platformAuth`, `platformPolicy`, `platformAlg`,
/// `shEnable`, `ehEnable`, `phEnableNV`) is not in this record: every `TPM2_Startup` sets it
/// (TPM Reset/Restart) or restores it from the state-save record ([`NvStateSaveRecord`], TPM
/// Resume) before it is used, and the live values are in RAM. The PCR auth value (also `gc`) is
/// in the seeds section: TPM Resume keeps the copy that `_TPM_Init` reloads from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NvHierarchyRecord {
    pub owner_auth: OwnedAuth,
    pub endorsement_auth: OwnedAuth,
    pub lockout_auth: OwnedAuth,
    pub owner_policy: OwnedDigest,
    pub endorsement_policy: OwnedDigest,
    pub lockout_policy: OwnedDigest,
    pub owner_alg: Option<TpmiAlgHash>,
    pub endorsement_alg: Option<TpmiAlgHash>,
    pub lockout_alg: Option<TpmiAlgHash>,
    pub seeds: Option<NvHierarchySeeds>,
    pub lifecycle: Option<NvLifecycleExt>,
    pub audit: Option<NvAuditExt>,
}

/// The seeds section of the hierarchy record: the primary seeds and hierarchy proofs (each
/// `size || 64 octets`), `clearCount` and the PCR policy group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvHierarchySeeds {
    pub sp_seed: [u8; 64],
    pub sp_seed_size: u16,
    pub sh_proof: [u8; 64],
    pub sh_proof_size: u16,
    pub eh_proof: [u8; 64],
    pub eh_proof_size: u16,
    pub clear_count: u32,
    pub pp_seed: [u8; 64],
    pub pp_seed_size: u16,
    pub ph_proof: [u8; 64],
    pub ph_proof_size: u16,
    pub ep_seed: [u8; 64],
    pub ep_seed_size: u16,
    /// `None` if the stored algorithm is not a valid `TPMI_ALG_HASH+` (the field is then not
    /// loaded).
    pub pcr_policy_alg: Option<Option<TpmiAlgHash>>,
    pub pcr_policy: Option<OwnedDigest>,
    pub pcr_auth_value: Option<OwnedAuth>,
}

/// The persistent lifecycle extension of the hierarchy record (`NV_SYNC_PERSISTENT` of
/// `gp.disableClear`, `gp.lockOutAuthEnabled` and the DA parameters, and `go.clock`/`go.clockSafe`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NvLifecycleExt {
    pub disable_clear: bool,
    pub lockout_auth_enabled: bool,
    pub max_tries: u32,
    pub recovery_time: u32,
    pub lockout_recovery: u32,
    pub clock: u64,
    pub clock_safe: bool,
}

/// The persistent command audit extension of the hierarchy record (`gp.auditHashAlg`,
/// `gp.auditCounter`, `gp.auditCommands`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NvAuditExt {
    pub hash_alg: u16,
    pub counter: u64,
    pub commands: [u8; COMMAND_AUDIT_LIST_SIZE],
}

impl NvLifecycleExt {
    fn encode(&self, dst: &mut [u8]) -> usize {
        let ext = &mut dst[..PERSISTENT_EXT_LEN];
        ext[0] = PERSISTENT_EXT_MARKER;
        ext[1] = u8::from(self.disable_clear);
        ext[2] = u8::from(self.lockout_auth_enabled);
        ext[3..7].copy_from_slice(&self.max_tries.to_be_bytes());
        ext[7..11].copy_from_slice(&self.recovery_time.to_be_bytes());
        ext[11..15].copy_from_slice(&self.lockout_recovery.to_be_bytes());
        ext[15..23].copy_from_slice(&self.clock.to_be_bytes());
        ext[23] = u8::from(self.clock_safe);
        PERSISTENT_EXT_LEN
    }

    /// Decodes the extension at the start of `src` (`None` if it does not start with one).
    fn decode(src: &[u8]) -> Option<Self> {
        let ext = src.get(..PERSISTENT_EXT_LEN)?;
        if ext[0] != PERSISTENT_EXT_MARKER {
            return None;
        }
        let be_u32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        Some(Self {
            disable_clear: ext[1] != 0,
            lockout_auth_enabled: ext[2] != 0,
            max_tries: be_u32(&ext[3..7]),
            recovery_time: be_u32(&ext[7..11]),
            lockout_recovery: be_u32(&ext[11..15]),
            clock: u64::from_be_bytes(ext[15..23].try_into().unwrap()),
            clock_safe: ext[23] != 0,
        })
    }
}

impl NvAuditExt {
    /// Encodes the extension (marker included) into `dst` (at least [`AUDIT_EXT_LEN`] octets).
    pub fn encode(&self, dst: &mut [u8]) -> usize {
        dst[0] = AUDIT_EXT_MARKER;
        dst[1..3].copy_from_slice(&self.hash_alg.to_be_bytes());
        dst[3..11].copy_from_slice(&self.counter.to_be_bytes());
        dst[11..AUDIT_EXT_LEN].copy_from_slice(&self.commands);
        AUDIT_EXT_LEN
    }

    /// Decodes the extension at the start of `src`: `None` if `src` does not start with a
    /// complete extension or it names an unsupported hash algorithm.
    pub fn decode(src: &[u8]) -> Option<Self> {
        let ext = src.get(..AUDIT_EXT_LEN)?;
        let hash_alg = u16::from_be_bytes([ext[1], ext[2]]);
        if ext[0] != AUDIT_EXT_MARKER || TpmiAlgHash::try_from(hash_alg).is_err() {
            return None;
        }
        let mut commands = [0u8; COMMAND_AUDIT_LIST_SIZE];
        commands.copy_from_slice(&ext[11..AUDIT_EXT_LEN]);
        Some(Self {
            hash_alg,
            counter: u64::from_be_bytes(ext[3..11].try_into().unwrap()),
            commands,
        })
    }
}

/// A policy algorithm of the hierarchy record: an invalid stored value (e.g. a raw `0`) falls back to the algorithm of the policy's digest size. The algorithms themselves are
/// part of the record's fixed part, which [`NvHierarchyRecord::decode`] requires in full.
fn decode_policy_alg(raw: u16, policy: &OwnedDigest) -> Option<TpmiAlgHash> {
    match <Option<TpmiAlgHash>>::unmarshal(&mut &raw.to_be_bytes()[..]) {
        Ok(alg) => alg,
        Err(_) => crate::engine::infer_alg_from_digest_size(policy.get_size() as usize),
    }
}

impl NvHierarchyRecord {
    /// Encodes the record into `buf` and returns its length.
    pub fn encode(&self, buf: &mut [u8; HIERARCHY_RECORD_SIZE]) -> usize {
        let mut w = Writer::new(buf);
        for auth in [&self.owner_auth, &self.endorsement_auth, &self.lockout_auth] {
            w.marshal(auth);
        }
        for policy in [
            &self.owner_policy,
            &self.endorsement_policy,
            &self.lockout_policy,
        ] {
            w.marshal(policy);
        }
        for alg in [&self.owner_alg, &self.endorsement_alg, &self.lockout_alg] {
            w.marshal(alg);
        }
        if let Some(s) = &self.seeds {
            w.bytes(&[SEEDS_MARKER]);
            put_sized64(&mut w, &s.sp_seed, s.sp_seed_size);
            put_sized64(&mut w, &s.sh_proof, s.sh_proof_size);
            put_sized64(&mut w, &s.eh_proof, s.eh_proof_size);
            w.bytes(&s.clear_count.to_be_bytes());
            put_sized64(&mut w, &s.pp_seed, s.pp_seed_size);
            put_sized64(&mut w, &s.ph_proof, s.ph_proof_size);
            put_sized64(&mut w, &s.ep_seed, s.ep_seed_size);
            w.marshal(&s.pcr_policy_alg.flatten());
            w.marshal(&s.pcr_policy.unwrap_or_default());
            w.marshal(&s.pcr_auth_value.unwrap_or_default());
            if let Some(ext) = &self.lifecycle {
                w.len += ext.encode(&mut w.buf[w.len..]);
            }
            if let Some(ext) = &self.audit {
                w.len += ext.encode(&mut w.buf[w.len..]);
            }
        }
        w.len
    }

    /// Decodes a record. Returns `None` if the fixed part is malformed; the optional sections are
    /// `None` when their marker is absent.
    pub fn decode(src: &[u8]) -> Option<Self> {
        let mut slice = src;
        let s = &mut slice;
        let owner_auth = OwnedAuth::unmarshal(s).ok()?;
        let endorsement_auth = OwnedAuth::unmarshal(s).ok()?;
        let lockout_auth = OwnedAuth::unmarshal(s).ok()?;
        let owner_policy = OwnedDigest::unmarshal(s).ok()?;
        let endorsement_policy = OwnedDigest::unmarshal(s).ok()?;
        let lockout_policy = OwnedDigest::unmarshal(s).ok()?;
        let owner_alg = decode_policy_alg(u16::unmarshal(s).ok()?, &owner_policy);
        let endorsement_alg = decode_policy_alg(u16::unmarshal(s).ok()?, &endorsement_policy);
        let lockout_alg = decode_policy_alg(u16::unmarshal(s).ok()?, &lockout_policy);
        let mut record = Self {
            owner_auth,
            endorsement_auth,
            lockout_auth,
            owner_policy,
            endorsement_policy,
            lockout_policy,
            owner_alg,
            endorsement_alg,
            lockout_alg,
            seeds: None,
            lifecycle: None,
            audit: None,
        };
        if u8::unmarshal(s).ok() != Some(SEEDS_MARKER) {
            return Some(record);
        }
        // A truncated seeds section (which tpm-rs never writes) leaves the record without one.
        let Some(seeds) = Self::decode_seeds(s) else {
            return Some(record);
        };
        record.seeds = Some(seeds);
        // The audit extension follows the lifecycle extension, or the PCR data directly when the
        // record has no lifecycle extension.
        record.lifecycle = NvLifecycleExt::decode(slice);
        if record.lifecycle.is_some() {
            slice = &slice[PERSISTENT_EXT_LEN..];
        }
        record.audit = NvAuditExt::decode(slice);
        Some(record)
    }

    fn decode_seeds(s: &mut &[u8]) -> Option<NvHierarchySeeds> {
        let (sp_seed, sp_seed_size) = get_sized64(s)?;
        let (sh_proof, sh_proof_size) = get_sized64(s)?;
        let (eh_proof, eh_proof_size) = get_sized64(s)?;
        let clear_count = u32::unmarshal(s).ok()?;
        let (pp_seed, pp_seed_size) = get_sized64(s)?;
        let (ph_proof, ph_proof_size) = get_sized64(s)?;
        let (ep_seed, ep_seed_size) = get_sized64(s)?;
        let pcr_policy_alg = <Option<TpmiAlgHash>>::unmarshal(s).ok();
        let pcr_policy = OwnedDigest::unmarshal(s).ok();
        let pcr_auth_value = OwnedAuth::unmarshal(s).ok();
        Some(NvHierarchySeeds {
            sp_seed,
            sp_seed_size,
            sh_proof,
            sh_proof_size,
            eh_proof,
            eh_proof_size,
            clear_count,
            pp_seed,
            pp_seed_size,
            ph_proof,
            ph_proof_size,
            ep_seed,
            ep_seed_size,
            pcr_policy_alg,
            pcr_policy,
            pcr_auth_value,
        })
    }

    /// Reads the record from `storage` (`None` if it is missing or malformed).
    pub fn read(storage: &mut (impl IndexState + ?Sized)) -> Option<Self> {
        let mut buf = [0u8; HIERARCHY_RECORD_SIZE];
        let storage_mgr = storage;
        let meta = storage_mgr.get_metadata(HIERARCHY_RECORD_HANDLE).ok()?;
        let len = core::cmp::min(meta.data_size as usize, HIERARCHY_RECORD_SIZE);
        storage_mgr
            .read_item(HIERARCHY_RECORD_HANDLE, 0, &mut buf[..len])
            .ok()?;
        Self::decode(&buf[..len])
    }

    /// Writes the record to `storage`. The item is (re)defined with [`HIERARCHY_RECORD_SIZE`]
    /// octets if it is missing or too small; NV write errors are ignored (as in
    /// `NV_SYNC_PERSISTENT`, a failed NV write does not fail the command).
    pub fn write(&self, storage: &mut (impl IndexState + ?Sized)) {
        let mut buf = [0u8; HIERARCHY_RECORD_SIZE];
        let len = self.encode(&mut buf);
        match storage.get_metadata(HIERARCHY_RECORD_HANDLE) {
            Ok(meta) if (meta.data_size as usize) >= len => {}
            Ok(_) => {
                let _ = storage.undefine_space(HIERARCHY_RECORD_HANDLE);
                let _ =
                    storage.define_space(HIERARCHY_RECORD_HANDLE, HIERARCHY_RECORD_SIZE as u16, 0);
            }
            Err(_) => {
                let _ =
                    storage.define_space(HIERARCHY_RECORD_HANDLE, HIERARCHY_RECORD_SIZE as u16, 0);
            }
        }
        let _ = storage.write_item(HIERARCHY_RECORD_HANDLE, 0, &buf[..len]);
    }
}

// ---------------------------------------------------------------------------------------------
// State-save record (0x00FF_FFFE).
// ---------------------------------------------------------------------------------------------

/// Marker identifying the layout of the state-save record.
pub const STATE_SAVE_MARKER: u8 = 0x5A;
/// The saved state of one ACT: its timeout, policy algorithm and policy digest.
const ACT_SAVE_LEN: usize = 4 + TpmiAlgHash::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
/// Upper bound of the state-save record size.
pub const STATE_SAVE_MAX_LEN: usize =
    512 + MAX_ACTIVE_SESSIONS * (1 + 4 + 8) + 2 + ACT_COUNT * ACT_SAVE_LEN;

/// The `TPM2_Shutdown(TPM_SU_STATE)` data (the equivalent of `NV_STATE_RESET_DATA` /
/// `NV_STATE_CLEAR_DATA` and the ACT state of `ORDERLY_DATA`), restored by TPM Restart/Resume.
/// It only exists between an orderly `TPM_SU_STATE` shutdown and the next `TPM2_Startup`.
///
/// Layout: [`STATE_SAVE_MARKER`], the fields below in order (seeds/proofs as `size || 64 octets`,
/// counters big-endian), the saved sessions as `count (u8)` then `slot (u8) || handle (u32) ||
/// sequence (u64)` per saved session, the flags as one octet each, `TPM2B`s and
/// `TPMI_ALG_HASH+`s marshaled, then `act_saved_signaled` and per ACT `timeout || alg ||
/// policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvStateSaveRecord {
    pub null_seed: [u8; 64],
    pub null_seed_size: u16,
    pub null_proof: [u8; 64],
    pub null_proof_size: u16,
    pub restart_count: u32,
    /// `gr.pcrCounter`: TPM Restart and TPM Resume continue from the value saved by
    /// `TPM2_Shutdown(TPM_SU_STATE)`, as the references (`gr` is read back from NV), so a change
    /// of a PCR that is not state-saved after the shutdown is not counted.
    pub pcr_update_counter: u32,
    pub context_counter: u64,
    pub object_context_counter: u64,
    /// The saved sessions by slot (`State::saved_sessions`).
    pub saved_sessions: [Option<u32>; MAX_ACTIVE_SESSIONS],
    /// Their context sequence numbers (`State::saved_session_sequences`).
    pub saved_session_sequences: [u64; MAX_ACTIVE_SESSIONS],
    pub commit_counter: u64,
    pub commit_nonce: [u8; COMMIT_NONCE_SIZE],
    pub commit_array: [u8; 16],
    pub sh_enable: bool,
    pub eh_enable: bool,
    pub ph_enable_nv: bool,
    pub read_only: bool,
    pub platform_auth: OwnedAuth,
    pub platform_policy: OwnedDigest,
    pub platform_alg: Option<TpmiAlgHash>,
    pub command_audit_digest: OwnedDigest,
    pub act_saved_signaled: u16,
    pub act_saved_timeouts: [u32; ACT_COUNT],
    pub act_policies: [ActPolicy; ACT_COUNT],
}

impl NvStateSaveRecord {
    /// Encodes the record into `buf` and returns its length.
    pub fn encode(&self, buf: &mut [u8; STATE_SAVE_MAX_LEN]) -> usize {
        let mut w = Writer::new(buf);
        w.bytes(&[STATE_SAVE_MARKER]);
        put_sized64(&mut w, &self.null_seed, self.null_seed_size);
        put_sized64(&mut w, &self.null_proof, self.null_proof_size);
        w.bytes(&self.restart_count.to_be_bytes());
        w.bytes(&self.pcr_update_counter.to_be_bytes());
        w.bytes(&self.context_counter.to_be_bytes());
        w.bytes(&self.object_context_counter.to_be_bytes());
        let saved_count = self.saved_sessions.iter().flatten().count();
        w.bytes(&[saved_count as u8]);
        for (slot, saved) in self.saved_sessions.iter().enumerate() {
            if let Some(handle) = saved {
                w.bytes(&[slot as u8]);
                w.bytes(&handle.to_be_bytes());
                w.bytes(&self.saved_session_sequences[slot].to_be_bytes());
            }
        }
        w.bytes(&self.commit_counter.to_be_bytes());
        w.bytes(&self.commit_nonce);
        w.bytes(&self.commit_array);
        w.bytes(&[
            u8::from(self.sh_enable),
            u8::from(self.eh_enable),
            u8::from(self.ph_enable_nv),
            u8::from(self.read_only),
        ]);
        w.marshal(&self.platform_auth);
        w.marshal(&self.platform_policy);
        w.marshal(&self.platform_alg);
        w.marshal(&self.command_audit_digest);
        w.bytes(&self.act_saved_signaled.to_be_bytes());
        for (policy, timeout) in self.act_policies.iter().zip(&self.act_saved_timeouts) {
            w.bytes(&timeout.to_be_bytes());
            w.marshal(&policy.hash_alg);
            w.marshal(&policy.auth_policy);
        }
        w.len
    }

    /// Decodes a record (`None` if it is malformed).
    pub fn decode(src: &[u8]) -> Option<Self> {
        let mut slice = src;
        let s = &mut slice;
        if u8::unmarshal(s).ok()? != STATE_SAVE_MARKER {
            return None;
        }
        let (null_seed, null_seed_size) = get_sized64(s)?;
        let (null_proof, null_proof_size) = get_sized64(s)?;
        let restart_count = u32::unmarshal(s).ok()?;
        let pcr_update_counter = u32::unmarshal(s).ok()?;
        let context_counter = u64::unmarshal(s).ok()?;
        let object_context_counter = u64::unmarshal(s).ok()?;
        let mut saved_sessions = [None; MAX_ACTIVE_SESSIONS];
        let mut saved_session_sequences = [0u64; MAX_ACTIVE_SESSIONS];
        let saved_count = u8::unmarshal(s).ok()? as usize;
        for _ in 0..saved_count {
            let slot = u8::unmarshal(s).ok()? as usize;
            let handle = u32::unmarshal(s).ok()?;
            let sequence = u64::unmarshal(s).ok()?;
            if slot >= MAX_ACTIVE_SESSIONS {
                return None;
            }
            saved_sessions[slot] = Some(handle);
            saved_session_sequences[slot] = sequence;
        }
        let commit_counter = u64::unmarshal(s).ok()?;
        let commit_nonce = <[u8; COMMIT_NONCE_SIZE]>::unmarshal(s).ok()?;
        let commit_array = <[u8; 16]>::unmarshal(s).ok()?;
        let sh_enable = u8::unmarshal(s).ok()? != 0;
        let eh_enable = u8::unmarshal(s).ok()? != 0;
        let ph_enable_nv = u8::unmarshal(s).ok()? != 0;
        let read_only = u8::unmarshal(s).ok()? != 0;
        let platform_auth = OwnedAuth::unmarshal(s).ok()?;
        let platform_policy = OwnedDigest::unmarshal(s).ok()?;
        let platform_alg = <Option<TpmiAlgHash>>::unmarshal(s).ok()?;
        let command_audit_digest = OwnedDigest::unmarshal(s).ok()?;
        let act_saved_signaled = u16::unmarshal(s).ok()?;
        let mut act_saved_timeouts = [0u32; ACT_COUNT];
        let mut act_policies = [ActPolicy::default(); ACT_COUNT];
        for (timeout, policy) in act_saved_timeouts.iter_mut().zip(&mut act_policies) {
            *timeout = u32::unmarshal(s).ok()?;
            *policy = ActPolicy {
                hash_alg: <Option<TpmiAlgHash>>::unmarshal(s).ok()?,
                auth_policy: OwnedDigest::unmarshal(s).ok()?,
            };
        }
        Some(Self {
            null_seed,
            null_seed_size,
            null_proof,
            null_proof_size,
            restart_count,
            pcr_update_counter,
            context_counter,
            object_context_counter,
            saved_sessions,
            saved_session_sequences,
            commit_counter,
            commit_nonce,
            commit_array,
            sh_enable,
            eh_enable,
            ph_enable_nv,
            read_only,
            platform_auth,
            platform_policy,
            platform_alg,
            command_audit_digest,
            act_saved_signaled,
            act_saved_timeouts,
            act_policies,
        })
    }

    /// Reads the record from `storage` (`None` if it is missing or malformed).
    pub fn read(storage: &mut (impl IndexState + ?Sized)) -> Option<Self> {
        let mut buf = [0u8; STATE_SAVE_MAX_LEN];
        Self::decode(read_item(storage, STATE_SAVE_HANDLE, &mut buf)?)
    }

    /// Writes the record to `storage` (replacing any previous one).
    pub fn write(&self, storage: &mut (impl IndexState + ?Sized)) -> Result<(), TpmRc> {
        let mut buf = [0u8; STATE_SAVE_MAX_LEN];
        let len = self.encode(&mut buf);
        replace_item(storage, STATE_SAVE_HANDLE, &buf[..len])
    }
}

// ---------------------------------------------------------------------------------------------
// Pending PCR allocation (0x00FF_FFFD).
// ---------------------------------------------------------------------------------------------

/// The PCR allocation written by `TPM2_PCR_Allocate` (`NV_WRITE_PERSISTENT(pcrAllocated)`), a
/// marshaled `TPML_PCR_SELECTION`. It replaces the active allocation at the next `_TPM_Init`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvPcrAllocationRecord {
    pub allocation: TpmlPcrSelection,
}

impl NvPcrAllocationRecord {
    /// Reads the record from `storage` (`None` if it is missing or malformed).
    pub fn read(storage: &mut (impl IndexState + ?Sized)) -> Option<Self> {
        let mut buf = [0u8; TpmlPcrSelection::MAX_SIZE];
        let mut slice = read_item(storage, PCR_ALLOCATION_HANDLE, &mut buf)?;
        let allocation = TpmlPcrSelection::unmarshal(&mut slice).ok()?;
        Some(Self { allocation })
    }

    /// Writes the record to `storage` (replacing any previous one).
    pub fn write(&self, storage: &mut (impl IndexState + ?Sized)) -> Result<(), TpmRc> {
        let mut buf = [0u8; TpmlPcrSelection::MAX_SIZE];
        let len = self.allocation.marshal(&mut buf);
        replace_item(storage, PCR_ALLOCATION_HANDLE, &buf[..len])
    }
}

// ---------------------------------------------------------------------------------------------
// Platform settings (0x00FF_FFFC).
// ---------------------------------------------------------------------------------------------

/// Size of the platform settings record.
pub const PLATFORM_SETTINGS_LEN: usize = 8;

/// `gp.ppList` (the raw `PpList` bits) and `gp.algorithmSet`, both big-endian `u32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NvPlatformSettingsRecord {
    pub pp_list: u32,
    pub algorithm_set: u32,
}

impl NvPlatformSettingsRecord {
    pub fn decode(b: &[u8; PLATFORM_SETTINGS_LEN]) -> Self {
        Self {
            pp_list: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            algorithm_set: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    pub fn encode(&self) -> [u8; PLATFORM_SETTINGS_LEN] {
        let mut b = [0u8; PLATFORM_SETTINGS_LEN];
        b[..4].copy_from_slice(&self.pp_list.to_be_bytes());
        b[4..].copy_from_slice(&self.algorithm_set.to_be_bytes());
        b
    }

    /// Reads the record from `storage` (`None` if it is missing).
    pub fn read(storage: &mut (impl IndexState + ?Sized)) -> Option<Self> {
        let mut b = [0u8; PLATFORM_SETTINGS_LEN];
        storage.get_metadata(PLATFORM_SETTINGS_HANDLE).ok()?;
        storage
            .read_item(PLATFORM_SETTINGS_HANDLE, 0, &mut b)
            .ok()?;
        Some(Self::decode(&b))
    }

    /// Writes the record to `storage`, defining it if needed; NV write errors are ignored.
    pub fn write(&self, storage: &mut (impl IndexState + ?Sized)) {
        if storage.get_metadata(PLATFORM_SETTINGS_HANDLE).is_err() {
            let _ = storage.define_space(PLATFORM_SETTINGS_HANDLE, PLATFORM_SETTINGS_LEN as u16, 0);
        }
        let _ = storage.write_item(PLATFORM_SETTINGS_HANDLE, 0, &self.encode());
    }
}

// ---------------------------------------------------------------------------------------------
// NV Indices (0x01xx_xxxx).
// ---------------------------------------------------------------------------------------------

/// An NV Index item: `TPM2B_AUTH || TPM2B_NV_PUBLIC || data`. Borrows the item's octets.
#[derive(Clone, Copy, Debug)]
pub struct NvIndexRecord<'a> {
    pub auth: Tpm2bAuth<'a>,
    pub public: TpmsNvPublic<'a>,
    /// The marshaled `TPM2B_NV_PUBLIC`.
    pub public_info: Tpm2bNvPublic<'a>,
    /// The octets of the `TPMS_NV_PUBLIC` (inside `public_info`), for the Name.
    pub public_bytes: &'a [u8],
    /// Size of the header (`auth` and `public_info`): the data starts at this offset.
    pub metadata_size: usize,
}

impl<'a> NvIndexRecord<'a> {
    /// Decodes the header of an NV Index item.
    pub fn decode(buf: &'a [u8]) -> Result<Self, TpmRc> {
        let mut slice = buf;
        let auth = Tpm2bAuth::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        if slice.len() < 2 {
            return Err(TpmRc::FAILURE);
        }
        let pub_len = u16::from_be_bytes([slice[0], slice[1]]) as usize;
        let public_bytes = slice.get(2..2 + pub_len).ok_or(TpmRc::FAILURE)?;
        let public_info = Tpm2bNvPublic::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let metadata_size = buf.len() - slice.len();
        Ok(Self {
            auth,
            public: public_info.0,
            public_info,
            public_bytes,
            metadata_size,
        })
    }
}

/// Size of a buffer large enough to hold the largest NV Index header.
pub const NV_INDEX_HEADER_BUF_SIZE: usize =
    Tpm2bAuth::<'static>::MAX_SIZE + Tpm2bNvPublic::<'static>::MAX_SIZE;

/// The authValue of an NV Index header (borrowed or owned).
pub(crate) trait NvHeaderAuth {
    fn marshal_auth(&self, buf: &mut [u8]) -> usize;
}

impl NvHeaderAuth for Tpm2bAuth<'_> {
    fn marshal_auth(&self, buf: &mut [u8]) -> usize {
        self.marshal((&mut buf[..Tpm2bAuth::MAX_SIZE]).try_into().unwrap())
    }
}

impl NvHeaderAuth for OwnedAuth {
    fn marshal_auth(&self, buf: &mut [u8]) -> usize {
        self.as_tpm2b().marshal_auth(buf)
    }
}

/// The public area of an NV Index header (borrowed or owned).
pub(crate) trait NvHeaderPub {
    fn marshal_pub(&self, buf: &mut [u8]) -> usize;
}

impl NvHeaderPub for Tpm2bNvPublic<'_> {
    fn marshal_pub(&self, buf: &mut [u8]) -> usize {
        self.marshal((&mut buf[..Tpm2bNvPublic::MAX_SIZE]).try_into().unwrap())
    }
}

impl NvHeaderPub for crate::owned::OwnedNvPublic {
    fn marshal_pub(&self, buf: &mut [u8]) -> usize {
        self.as_tpm2b().marshal_pub(buf)
    }
}

/// Encodes an NV Index header (`TPM2B_AUTH || TPM2B_NV_PUBLIC`) into `buf` (at least
/// [`NV_INDEX_HEADER_BUF_SIZE`] octets) and returns its length.
pub(crate) fn encode_nv_index_header(
    auth: &impl NvHeaderAuth,
    public_info: &impl NvHeaderPub,
    buf: &mut [u8],
) -> Result<usize, TpmRc> {
    if buf.len() < NV_INDEX_HEADER_BUF_SIZE {
        return Err(TpmRc::FAILURE);
    }
    let mut offset = auth.marshal_auth(buf);
    offset += public_info.marshal_pub(&mut buf[offset..]);
    Ok(offset)
}

// ---------------------------------------------------------------------------------------------
// Persistent objects (0x81xx_xxxx).
// ---------------------------------------------------------------------------------------------

/// Upper bound of a persistent object item.
pub const PERSISTENT_OBJECT_MAX_LEN: usize = 4096;

/// A persistent object (`TPM2_EvictControl`): `seedValue (TPM2B) || name || authValue ||
/// TPMT_PUBLIC || private size (u16) || private || qualifiedName || hierarchy (u32) || flags`,
/// where the flags octet has bit 0 = external and bit 1 = public-only (an older layout ends
/// before it).
#[derive(Clone, Copy, Debug)]
pub struct NvPersistentObjectRecord {
    pub seed: [u8; 64],
    pub seed_len: usize,
    pub name: OwnedName,
    pub auth: OwnedAuth,
    pub public: OwnedPublic,
    pub private: [u8; MAX_PRIVATE_KEY_SIZE],
    pub private_len: usize,
    pub qualified_name: OwnedName,
    pub hierarchy: u32,
    pub external: bool,
    pub public_only: bool,
}

impl NvPersistentObjectRecord {
    /// The record of a loaded object.
    pub fn from_object(obj: &TransientObject) -> Self {
        Self {
            seed: obj.seed,
            seed_len: obj.seed_len,
            name: obj.name,
            auth: obj.auth,
            public: obj.public,
            private: obj.private,
            private_len: obj.private_len,
            qualified_name: obj.qualified_name,
            hierarchy: obj.hierarchy,
            external: obj.external,
            public_only: obj.public_only,
        }
    }

    /// The object of this record, loaded under `handle`.
    pub fn into_object(self, handle: u32) -> TransientObject {
        TransientObject {
            handle,
            seed: self.seed,
            seed_len: self.seed_len,
            external: self.external,
            public_only: self.public_only,
            name: self.name,
            auth: self.auth,
            public: self.public,
            private: self.private,
            private_len: self.private_len,
            qualified_name: self.qualified_name,
            hierarchy: self.hierarchy,
            st_clear: false,
        }
    }

    /// Encodes the record into `buf` and returns its length.
    pub fn encode(&self, buf: &mut [u8; PERSISTENT_OBJECT_MAX_LEN]) -> Result<usize, TpmRc> {
        let mut w = Writer::new(buf);
        w.marshal(
            &Tpm2bDigest::from_bytes(&self.seed[..self.seed_len]).map_err(|_| TpmRc::FAILURE)?,
        );
        w.marshal(&self.name);
        w.marshal(&self.auth);
        w.marshal(&self.public);
        w.bytes(&(self.private_len as u16).to_be_bytes());
        w.bytes(&self.private[..self.private_len]);
        w.marshal(&self.qualified_name);
        w.bytes(&self.hierarchy.to_be_bytes());
        w.bytes(&[u8::from(self.external) | (u8::from(self.public_only) << 1)]);
        Ok(w.len)
    }

    /// Decodes a record.
    pub fn decode(src: &[u8]) -> Result<Self, TpmRc> {
        let mut slice = src;
        let s = &mut slice;
        // seedValue is stored as a TPM2B (the full nameAlg-sized seed).
        let seed_value = Tpm2bDigest::unmarshal(s).map_err(|_| TpmRc::FAILURE)?;
        let (seed, seed_len) = TransientObject::seed_from_bytes(seed_value.get_buffer());
        let name = OwnedName::unmarshal(s).map_err(|_| TpmRc::FAILURE)?;
        let auth = OwnedAuth::unmarshal(s).map_err(|_| TpmRc::FAILURE)?;
        let public = OwnedPublic::unmarshal(s).map_err(|_| TpmRc::FAILURE)?;
        let private_len = u16::unmarshal(s).map_err(|_| TpmRc::FAILURE)? as usize;
        if s.len() < private_len || private_len > MAX_PRIVATE_KEY_SIZE {
            return Err(TpmRc::FAILURE);
        }
        let mut private = [0u8; MAX_PRIVATE_KEY_SIZE];
        private[..private_len].copy_from_slice(&s[..private_len]);
        *s = &s[private_len..];
        let qualified_name = OwnedName::unmarshal(s).map_err(|_| TpmRc::FAILURE)?;
        let hierarchy = u32::unmarshal(s).map_err(|_| TpmRc::FAILURE)?;
        let flags = s.first().copied().unwrap_or(0);
        Ok(Self {
            seed,
            seed_len,
            name,
            auth,
            public,
            private,
            private_len,
            qualified_name,
            hierarchy,
            external: flags & 1 != 0,
            public_only: flags & 2 != 0,
        })
    }

    /// Reads the persistent object `handle` from `storage`: `TPM_RC_HANDLE` if it is not
    /// defined, `TPM_RC_FAILURE` if it cannot be read or decoded.
    pub fn read(storage: &mut (impl IndexState + ?Sized), handle: u32) -> Result<Self, TpmRc> {
        let storage_mgr = storage;
        let metadata = storage_mgr
            .get_metadata(handle)
            .map_err(|_| TpmRc::HANDLE.to_rc())?;
        let mut buf = [0u8; PERSISTENT_OBJECT_MAX_LEN];
        let len = metadata.data_size as usize;
        let buf = buf.get_mut(..len).ok_or(TpmRc::FAILURE)?;
        storage_mgr
            .read_item(handle, 0, buf)
            .map_err(|_| TpmRc::FAILURE)?;
        Self::decode(buf)
    }

    /// Defines and writes the persistent object `handle` (`TPM_RC_NV_SPACE` if there is no room;
    /// on a write failure the item is removed again).
    pub fn write(
        &self,
        storage: &mut (impl IndexState + ?Sized),
        handle: u32,
    ) -> Result<(), TpmRc> {
        let mut buf = [0u8; PERSISTENT_OBJECT_MAX_LEN];
        let len = self.encode(&mut buf)?;
        storage
            .define_space(handle, len as u16, 0)
            .map_err(|_| TpmRc::NV_SPACE)?;
        if storage.write_item(handle, 0, &buf[..len]).is_err() {
            let _ = storage.undefine_space(handle);
            return Err(TpmRc::FAILURE);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ram_storage_mock::RamStorageMock;

    fn auth(bytes: &[u8]) -> OwnedAuth {
        OwnedAuth::new(bytes).unwrap()
    }

    fn digest(bytes: &[u8]) -> OwnedDigest {
        OwnedDigest::new(bytes).unwrap()
    }

    /// A hierarchy record with every section.
    fn full_hierarchy_record() -> NvHierarchyRecord {
        let mut commands = [0u8; COMMAND_AUDIT_LIST_SIZE];
        commands[0] = 0x81;
        commands[COMMAND_AUDIT_LIST_SIZE - 1] = 0x02;
        NvHierarchyRecord {
            owner_auth: auth(b"owner"),
            endorsement_auth: auth(b"endorsement"),
            lockout_auth: auth(b"lockout"),
            owner_policy: digest(&[0x11; 32]),
            endorsement_policy: digest(&[0x22; 48]),
            lockout_policy: OwnedDigest::default(),
            owner_alg: Some(TpmiAlgHash::Sha256),
            endorsement_alg: Some(TpmiAlgHash::Sha384),
            lockout_alg: None,
            seeds: Some(NvHierarchySeeds {
                sp_seed: [0x01; 64],
                sp_seed_size: 32,
                sh_proof: [0x02; 64],
                sh_proof_size: 32,
                eh_proof: [0x03; 64],
                eh_proof_size: 48,
                clear_count: 7,
                pp_seed: [0x04; 64],
                pp_seed_size: 32,
                ph_proof: [0x05; 64],
                ph_proof_size: 32,
                ep_seed: [0x06; 64],
                ep_seed_size: 64,
                pcr_policy_alg: Some(Some(TpmiAlgHash::Sha256)),
                pcr_policy: Some(digest(&[0x07; 32])),
                pcr_auth_value: Some(auth(b"pcr")),
            }),
            lifecycle: Some(NvLifecycleExt {
                disable_clear: true,
                lockout_auth_enabled: false,
                max_tries: 32,
                recovery_time: 7200,
                lockout_recovery: 86400,
                clock: 0x0102_0304_0506_0708,
                clock_safe: true,
            }),
            audit: Some(NvAuditExt {
                hash_alg: 0x000B,
                counter: 99,
                commands,
            }),
        }
    }

    /// The reserved header survives `encode` -> `decode`, and its fields are at their offsets.
    #[test]
    fn header_round_trip_and_offsets() {
        let header = NvHeader {
            reset_count: 0x0102_0304,
            orderly_state: 0x8001,
            total_reset_count: 0x1112_1314_1516_1718,
            max_counter: 0x2122_2324_2526_2728,
            time_epoch: 0x3536_3738,
            failed_tries: 0x4142_4344,
            drbg: DrbgState::default(),
            self_heal_timer: -5,
            lockout_timer: 77,
        };
        let bytes = header.encode();
        assert_eq!(NvHeader::decode(&bytes), header);
        assert_eq!(&bytes[NvHeader::RESET_COUNT_OFFSET..][..4], &[1, 2, 3, 4]);
        assert_eq!(&bytes[NvHeader::ORDERLY_STATE_OFFSET..][..2], &[0x80, 0x01]);
        assert_eq!(bytes[NvHeader::FAILED_TRIES_OFFSET], 0x41);
        assert_eq!(
            &bytes[NvHeader::LOCKOUT_TIMER_OFFSET..],
            &77u64.to_be_bytes()
        );
    }

    /// A hierarchy record with seeds, the lifecycle and the audit extensions survives
    /// `encode` -> `decode`, and re-encoding the decoded record gives the same octets.
    #[test]
    fn hierarchy_record_round_trip() {
        let record = full_hierarchy_record();
        let mut buf = [0u8; HIERARCHY_RECORD_SIZE];
        let len = record.encode(&mut buf);
        let decoded = NvHierarchyRecord::decode(&buf[..len]).unwrap();
        let seeds = decoded.seeds.unwrap();
        assert_eq!(seeds, record.seeds.unwrap());
        let mut again = [0u8; HIERARCHY_RECORD_SIZE];
        assert_eq!(decoded.encode(&mut again), len);
        assert_eq!(buf[..len], again[..len]);
        assert_eq!(decoded.owner_auth, record.owner_auth);
        assert_eq!(decoded.lifecycle, record.lifecycle);
        assert_eq!(decoded.audit, record.audit);
        assert_eq!(decoded.endorsement_alg, Some(TpmiAlgHash::Sha384));
        assert_eq!(decoded.lockout_alg, None);
    }

    /// The optional sections: a record without seeds has no extensions, and a record without the
    /// lifecycle extension still has its audit extension.
    #[test]
    fn hierarchy_record_optional_sections() {
        let mut record = full_hierarchy_record();
        record.seeds = None;
        let mut buf = [0u8; HIERARCHY_RECORD_SIZE];
        let len = record.encode(&mut buf);
        let decoded = NvHierarchyRecord::decode(&buf[..len]).unwrap();
        assert!(decoded.seeds.is_none() && decoded.lifecycle.is_none() && decoded.audit.is_none());
        assert_eq!(decoded.lockout_auth, record.lockout_auth);

        let mut record = full_hierarchy_record();
        record.lifecycle = None;
        let len = record.encode(&mut buf);
        let decoded = NvHierarchyRecord::decode(&buf[..len]).unwrap();
        assert!(decoded.lifecycle.is_none());
        assert_eq!(decoded.audit, record.audit);

        // A truncated fixed part is malformed.
        assert!(NvHierarchyRecord::decode(&buf[..3]).is_none());
    }

    /// An invalid stored policy algorithm falls back to the algorithm of the policy's size.
    #[test]
    fn hierarchy_record_infers_invalid_policy_alg() {
        let record = full_hierarchy_record();
        let mut buf = [0u8; HIERARCHY_RECORD_SIZE];
        let len = record.encode(&mut buf);
        // The owner algorithm follows the three authorizations and the three policies.
        let owner_alg_offset = [
            &record.owner_auth,
            &record.endorsement_auth,
            &record.lockout_auth,
        ]
        .iter()
        .map(|a| 2 + a.get_size() as usize)
        .sum::<usize>()
            + [
                &record.owner_policy,
                &record.endorsement_policy,
                &record.lockout_policy,
            ]
            .iter()
            .map(|p| 2 + p.get_size() as usize)
            .sum::<usize>();
        buf[owner_alg_offset..owner_alg_offset + 2].copy_from_slice(&[0, 0]);
        let decoded = NvHierarchyRecord::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.owner_alg, Some(TpmiAlgHash::Sha256));
    }

    /// `write` defines the hierarchy record and `read` returns it.
    #[test]
    fn hierarchy_record_write_and_read() {
        let mut storage = RamStorageMock::<16384>::new();
        assert!(NvHierarchyRecord::read(&mut storage).is_none());
        let record = full_hierarchy_record();
        record.write(&mut storage);
        let read = NvHierarchyRecord::read(&mut storage).unwrap();
        assert_eq!(read.owner_auth, record.owner_auth);
        assert_eq!(read.audit, record.audit);
        assert_eq!(read.seeds.unwrap().clear_count, 7);
    }

    /// The platform settings record survives `encode` -> `decode` and `write` -> `read`.
    #[test]
    fn platform_settings_round_trip() {
        let record = NvPlatformSettingsRecord {
            pp_list: 0x0000_0123,
            algorithm_set: 5,
        };
        assert_eq!(NvPlatformSettingsRecord::decode(&record.encode()), record);
        let mut storage = RamStorageMock::<16384>::new();
        assert!(NvPlatformSettingsRecord::read(&mut storage).is_none());
        record.write(&mut storage);
        assert_eq!(NvPlatformSettingsRecord::read(&mut storage), Some(record));
    }

    /// The state-save record survives `encode` -> `decode` and `write` -> `read`.
    #[test]
    fn state_save_round_trip() {
        let mut saved_sessions = [None; MAX_ACTIVE_SESSIONS];
        saved_sessions[1] = Some(0x0200_0001);
        let mut saved_session_sequences = [0; MAX_ACTIVE_SESSIONS];
        saved_session_sequences[1] = 42;
        let record = NvStateSaveRecord {
            null_seed: [0x01; 64],
            null_seed_size: 64,
            null_proof: [0x02; 64],
            null_proof_size: 64,
            restart_count: 3,
            pcr_update_counter: 4,
            context_counter: 5,
            object_context_counter: 6,
            saved_sessions,
            saved_session_sequences,
            commit_counter: 0x0001_0000_0007,
            commit_nonce: [0x08; COMMIT_NONCE_SIZE],
            commit_array: [0x09; 16],
            sh_enable: true,
            eh_enable: false,
            ph_enable_nv: true,
            read_only: true,
            platform_auth: auth(b"platform"),
            platform_policy: digest(&[0x0A; 32]),
            platform_alg: Some(TpmiAlgHash::Sha256),
            command_audit_digest: digest(&[0x0B; 32]),
            act_saved_signaled: 1,
            act_saved_timeouts: [12; ACT_COUNT],
            act_policies: [ActPolicy::default(); ACT_COUNT],
        };
        let mut buf = [0u8; STATE_SAVE_MAX_LEN];
        let len = record.encode(&mut buf);
        assert_eq!(NvStateSaveRecord::decode(&buf[..len]), Some(record));
        let mut storage = RamStorageMock::<16384>::new();
        record.write(&mut storage).unwrap();
        assert_eq!(NvStateSaveRecord::read(&mut storage), Some(record));
    }
}
