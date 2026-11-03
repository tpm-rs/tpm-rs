//! The NV space accounting of the TCG reference implementation, so that `tpm-rs` runs out of NV
//! space (`TPM_RC_NV_SPACE`) exactly when the reference does.
//!
//! The capacity of NV memory is implementation-specific: TPM 2.0 Part 2, `TPM_PT_NV_COUNTERS_AVAIL`
//! / `TPM_PT_HR_PERSISTENT_AVAIL` "This value is an estimate", and Part 3 TPM2_NV_DefineSpace
//! and TPM2_EvictControl only say that `TPM_RC_NV_SPACE` is returned when there is "insufficient
//! space for the Index" / "no space in NV memory" for the object. `tpm-rs` therefore follows
//! `tcgtpm` (`NvDynamic.c`), whose NV layout and struct sizes (`ibmswtpm2` has the same values
//! with its profile patches) decide the capacity:
//!
//! * NV Indices and persistent ("evict") objects share the dynamic area from `NV_USER_DYNAMIC`
//!   to `s_evictNvEnd` (= `NV_MEMORY_SIZE`). Each entry is a `UINT32` forward pointer followed by
//!   the entry: an Index takes `sizeof(NV_INDEX)` plus its data (unless `TPMA_NV_ORDERLY`, whose
//!   data lives in RAM), an evict object `sizeof(TPM_HANDLE) + sizeof(OBJECT)`, independent of
//!   the key type (`NvAdd()`).
//! * A new entry must fit after reserving the next forward pointer and the list terminator, the
//!   space for `MIN_EVICT_OBJECTS` persistent objects (when adding an Index) and for
//!   `MIN_COUNTER_INDICES` counter Indices (when adding anything but a counter)
//!   (`NvTestSpace()`).
//! * The data of orderly Indices lives in the `RAM_INDEX_SPACE` bytes of `s_indexOrderlyRam`,
//!   each with an `NV_RAM_HEADER` (`NvRamTestSpaceIndex()`).
//!
//! The constants are the values of the reference build `testing` compiles (`tcgtpm` `public`
//! and `v185`, and `ibmswtpm2`, with the RSA and ECC profile of the build; `sizeof` taken from
//! the compiled C structures).

use super::manager::StorageManager;
use super::{StorageError, Tpm2Storage};

/// `NV_MEMORY_SIZE`: the size of the reference's NV memory image: 16384 octets (the TCG
/// reference profile), 32768 with the `nv-memory-size-32k` feature (`ibmswtpm2`) or 131072 with
/// the `nv-memory-size-128k` feature (the TCG reference implementation version 185). With both,
/// the larger applies.
pub const NV_MEMORY_SIZE: u32 = if cfg!(feature = "nv-memory-size-128k") {
    131072
} else if cfg!(feature = "nv-memory-size-32k") {
    32768
} else {
    16384
};
/// Whether this TPM implements SHA-512 (the `sha512` feature of `tpm2`), which enlarges every
/// digest-sized member of the reference's structures (64 instead of 48 octets).
const SHA512: bool = tpm2::TpmiAlgHash::MAX_DIGEST_BYTES == 64;

/// `NV_INDEX_RAM_DATA`: the offset of the orderly Index RAM image in NV (after `gp`, `gr`, `gc`
/// and `go`). Each implemented ACT (see [`crate::act`]) adds its `ACT_STATE` to `go` and an
/// unused `TPMT_HA` policy slot to `gc`: 4644 with `TPM_RH_ACT_0` (the TCG reference
/// implementation version 185), 4784 with `TPM_RH_ACT_0` and `TPM_RH_ACT_A` (the `act-a`
/// feature: the public TCG reference implementation and `ibmswtpm2`); without ACTs it would be
/// 4508. Without SHA-512 (the public TCG reference upstream): 3380, or 3488 with `act-a`. A TPM
/// with `TPM2_ReadOnlyControl` (the `cc-read-only-control` feature) has `gc.readOnly` (a 4-octet
/// `BOOL` of `STATE_CLEAR_DATA`, only with `CC_ReadOnlyControl`), which adds 4.
pub const NV_INDEX_RAM_DATA: u32 = match (SHA512, cfg!(feature = "act-a")) {
    (true, true) => 4784,
    (true, false) => 4644,
    (false, true) => 3488,
    (false, false) => 3380,
} + if cfg!(feature = "cc-read-only-control") {
    4
} else {
    0
};
/// `RAM_INDEX_SPACE`: the size of `s_indexOrderlyRam`, the RAM backing of orderly Indices.
pub const RAM_INDEX_SPACE: u32 = 512;
/// `NV_USER_DYNAMIC`: the start of the dynamic area of Indices and evict objects.
pub const NV_USER_DYNAMIC: u32 = NV_INDEX_RAM_DATA + RAM_INDEX_SPACE;
/// `s_evictNvEnd` (`NV_USER_DYNAMIC_END`): the end of the dynamic area.
pub const NV_USER_DYNAMIC_END: u32 = NV_MEMORY_SIZE;
/// `sizeof(UINT32)`: the forward pointer in front of every dynamic entry.
pub const SIZEOF_UINT32: u32 = 4;
/// `sizeof(TPM_HANDLE)`: the handle stored in front of an evict object.
pub const SIZEOF_TPM_HANDLE: u32 = 4;
/// `sizeof(UINT64)`: the counter value of a counter Index.
pub const SIZEOF_UINT64: u32 = 8;
/// `sizeof(OBJECT)`: an evict object, whatever its type. It grows with the largest RSA key
/// (`TPMT_PUBLIC` holds `MAX_RSA_KEY_BYTES` of modulus and `TPMT_SENSITIVE` `RSA_PRIVATE_SIZE` of
/// CRT values): 1280 with RSA-2048, 1728 with RSA-3072 (the `rsa3072` feature) and 2176 with
/// RSA-4096 (the `rsa4096` feature), the same in all three references; 80 octets less without
/// SHA-512 (1200, 1648 and 2096). With ML-KEM (`mlkem`, a 1568-octet encapsulation key) or ML-DSA
/// (`mldsa`, a 2592-octet verification key) the `unique` of the `TPMT_PUBLIC` is that key instead
/// of the RSA modulus (with RSA-2048: 2592 with ML-KEM and 3616 with ML-DSA; with RSA-4096 and
/// ML-DSA 4256, the version 185 reference's `sizeof(OBJECT)` in its target profile).
pub const SIZEOF_OBJECT: u32 = {
    let rsa_bytes = tpm2::TpmiRsaKeyBits::MAX_PUB_KEY_BITS as u32 / 8;
    let classical = match rsa_bytes * 8 {
        4096 => 2176,
        3072 => 1728,
        _ => 1280,
    } - if SHA512 { 0 } else { 80 };
    let unique = if cfg!(feature = "mldsa") {
        2592
    } else if cfg!(feature = "mlkem") {
        1568
    } else {
        0
    };
    if unique > rsa_bytes {
        classical + unique - rsa_bytes
    } else {
        classical
    }
};
/// `sizeof(NV_INDEX)`: the descriptor (public area and authValue) of an Index: 148, or 116
/// without SHA-512.
pub const SIZEOF_NV_INDEX: u32 = if SHA512 { 148 } else { 116 };
/// `sizeof(NV_LIST_TERMINATOR)`: the end marker of the dynamic list (with `maxCount`).
pub const SIZEOF_NV_LIST_TERMINATOR: u32 = 12;
/// `sizeof(NV_RAM_HEADER)`: the header of an orderly Index in `s_indexOrderlyRam`.
pub const SIZEOF_NV_RAM_HEADER: u32 = 12;
/// `MIN_EVICT_OBJECTS`: persistent objects the TPM keeps room for: 2 (the TCG reference profile),
/// 7 with the `min-evict-objects-7` feature (`ibmswtpm2`) or 9 with the `min-evict-objects-9`
/// feature (the TCG reference implementation version 185). With both, the larger applies.
pub const MIN_EVICT_OBJECTS: u32 = if cfg!(feature = "min-evict-objects-9") {
    9
} else if cfg!(feature = "min-evict-objects-7") {
    7
} else {
    2
};
/// `MIN_COUNTER_INDICES`: counter Indices the TPM keeps room for.
pub const MIN_COUNTER_INDICES: u32 = 8;
/// `NV_EVICT_OBJECT_SIZE`: the dynamic space of one evict object.
pub const NV_EVICT_OBJECT_SIZE: u32 = SIZEOF_UINT32 + SIZEOF_TPM_HANDLE + SIZEOF_OBJECT;
/// `NV_INDEX_COUNTER_SIZE`: the dynamic space of one counter Index.
pub const NV_INDEX_COUNTER_SIZE: u32 = SIZEOF_UINT32 + SIZEOF_NV_INDEX + SIZEOF_UINT64;

/// `TPMA_NV_ORDERLY`.
const TPMA_NV_ORDERLY: u32 = 1 << 26;
/// The `TPM_NT` field of `TPMA_NV` (bits 7:4).
const TPMA_NV_TPM_NT_SHIFT: u32 = 4;
/// `TPM_NT_COUNTER`.
const TPM_NT_COUNTER: u32 = 1;

/// Whether an Index with attributes `attributes` (`TPMA_NV`) is a counter (`IsNvCounterIndex()`).
pub fn is_counter(attributes: u32) -> bool {
    (attributes >> TPMA_NV_TPM_NT_SHIFT) & 0xF == TPM_NT_COUNTER
}

/// Whether an Index with attributes `attributes` keeps its data in RAM (`TPMA_NV_ORDERLY`).
pub fn is_orderly(attributes: u32) -> bool {
    attributes & TPMA_NV_ORDERLY != 0
}

/// The size of the entity `NvTestSpace()` is asked about for an Index (`NvDefineIndex()`'s
/// `entrySize`): the descriptor plus the data unless the Index is orderly.
pub fn index_entry_size(attributes: u32, data_size: u16) -> u32 {
    SIZEOF_NV_INDEX
        + if is_orderly(attributes) {
            0
        } else {
            u32::from(data_size)
        }
}

/// The use of the reference's NV areas by the defined Indices and persistent objects.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NvUsage {
    /// Bytes of the dynamic area in use (forward pointers and entries).
    pub dynamic_bytes: u32,
    /// Bytes of `s_indexOrderlyRam` in use (headers and data of orderly Indices).
    pub orderly_ram_bytes: u32,
    /// The number of persistent objects (`NvCapGetPersistentNumber()`).
    pub persistent: u32,
    /// The number of counter Indices (`NvCapGetCounterNumber()`).
    pub counters: u32,
}

impl NvUsage {
    /// Accounts for a defined Index with `attributes` and `data_size` (as `NvAdd()` /
    /// `NvAddRAM()` lay it out).
    pub fn add_index(&mut self, attributes: u32, data_size: u16) {
        self.dynamic_bytes += SIZEOF_UINT32 + index_entry_size(attributes, data_size);
        if is_orderly(attributes) {
            self.orderly_ram_bytes += SIZEOF_NV_RAM_HEADER + u32::from(data_size);
        }
        if is_counter(attributes) {
            self.counters += 1;
        }
    }

    /// Accounts for a persistent object.
    pub fn add_evict_object(&mut self) {
        self.dynamic_bytes += NV_EVICT_OBJECT_SIZE;
        self.persistent += 1;
    }

    /// `NvGetFreeBytes()`: the free bytes of the dynamic area.
    pub fn free_bytes(&self) -> u32 {
        (NV_USER_DYNAMIC_END - NV_USER_DYNAMIC).saturating_sub(self.dynamic_bytes)
    }

    /// `NvTestSpace(size, isIndex, isCounter)`: whether an entity of `size` bytes fits.
    pub fn test_space(&self, size: u32, is_index: bool, is_counter: bool) -> bool {
        let remain = self.free_bytes();
        let mut reserved = SIZEOF_UINT32 + SIZEOF_NV_LIST_TERMINATOR;
        if is_index && self.persistent < MIN_EVICT_OBJECTS {
            reserved += (MIN_EVICT_OBJECTS - self.persistent) * NV_EVICT_OBJECT_SIZE;
        }
        if (!is_index || !is_counter) && self.counters < MIN_COUNTER_INDICES {
            reserved += (MIN_COUNTER_INDICES - self.counters) * NV_INDEX_COUNTER_SIZE;
        }
        reserved < remain && size <= remain && size + reserved <= remain
    }

    /// Whether `NvAddEvictObject()` has room for one more persistent object.
    pub fn can_add_evict_object(&self) -> bool {
        self.test_space(SIZEOF_OBJECT + SIZEOF_TPM_HANDLE, false, false)
    }

    /// `TPM_PT_HR_PERSISTENT_AVAIL` (`NvCapGetPersistentAvail()`): the reference's estimate of
    /// the additional persistent objects, i.e. the free dynamic bytes, less the list terminator
    /// and the counter reservation, in units of `NV_EVICT_OBJECT_SIZE`. Part 2, TPM_PT:
    /// "TPM_PT_HR_PERSISTENT_AVAIL | PT_VAR + 9 | the number of additional persistent objects
    /// that could be loaded into NV memory [...] This value is an estimate."
    pub fn persistent_avail(&self) -> u32 {
        let mut avail = self.free_bytes();
        let mut reserved = SIZEOF_NV_LIST_TERMINATOR;
        if self.counters < MIN_COUNTER_INDICES {
            reserved += (MIN_COUNTER_INDICES - self.counters) * NV_INDEX_COUNTER_SIZE;
            avail = avail.saturating_sub(reserved);
        }
        avail / NV_EVICT_OBJECT_SIZE
    }

    /// `TPM_PT_NV_COUNTERS_AVAIL` (`NvCapGetCounterAvail()`): the reference's estimate of the
    /// additional counter Indices, the smaller of what the dynamic area (less the list terminator
    /// and the persistent-object reservation) and the orderly RAM (`NV_RAM_INDEX_COUNTER_SIZE`
    /// each) can hold. Part 2, TPM_PT: "TPM_PT_NV_COUNTERS_AVAIL | PT_VAR + 11 | the number of
    /// additional NV Indexes that can be defined with their TPM_NT of TPM_NV_COUNTER and the
    /// TPMA_NV_ORDERLY attribute SET [...] This value is an estimate."
    pub fn counter_avail(&self) -> u32 {
        /// `NV_RAM_INDEX_COUNTER_SIZE`: `sizeof(NV_RAM_HEADER) + sizeof(UINT64)`.
        const NV_RAM_INDEX_COUNTER_SIZE: u32 = SIZEOF_NV_RAM_HEADER + SIZEOF_UINT64;
        let mut avail = self.free_bytes();
        let mut reserved = SIZEOF_NV_LIST_TERMINATOR;
        if self.persistent < MIN_EVICT_OBJECTS {
            reserved += (MIN_EVICT_OBJECTS - self.persistent) * NV_EVICT_OBJECT_SIZE;
            avail = avail.saturating_sub(reserved);
        }
        let ram = RAM_INDEX_SPACE.saturating_sub(self.orderly_ram_bytes);
        (avail / NV_INDEX_COUNTER_SIZE).min(ram / NV_RAM_INDEX_COUNTER_SIZE)
    }

    /// Whether `NvDefineIndex()` has room for an Index with `attributes` and `data_size`: the
    /// dynamic area (`NvTestSpace()`) and, for an orderly Index, `s_indexOrderlyRam`
    /// (`NvRamTestSpaceIndex()`).
    pub fn can_define_index(&self, attributes: u32, data_size: u16) -> bool {
        if !self.test_space(
            index_entry_size(attributes, data_size),
            true,
            is_counter(attributes),
        ) {
            return false;
        }
        !is_orderly(attributes)
            || RAM_INDEX_SPACE.saturating_sub(self.orderly_ram_bytes)
                >= SIZEOF_NV_RAM_HEADER + u32::from(data_size)
    }
}

/// Parses the `TPMA_NV` attributes and `dataSize` of an Index from the start of its stored
/// record (`TPM2B_AUTH || TPM2B_NV_PUBLIC`, see `handler::nv_storage::marshal_nv_header`).
pub fn parse_index_record(record: &[u8]) -> Option<(u32, u16)> {
    let be16 = |at: usize| {
        record
            .get(at..at + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
    };
    let auth_size = usize::from(be16(0)?);
    // TPM2B_NV_PUBLIC: size, nvIndex (4), nameAlg (2), attributes (4), authPolicy, dataSize.
    let public = 2 + auth_size + 2;
    let attributes = record
        .get(public + 6..public + 10)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))?;
    let policy_size = usize::from(be16(public + 10)?);
    let data_size = be16(public + 12 + policy_size)?;
    Some((attributes, data_size))
}

/// The longest stored Index record prefix [`parse_index_record`] needs:
/// `TPM2B_AUTH` (2 + 64) and `TPM2B_NV_PUBLIC` up to `dataSize` (2 + 4 + 2 + 4 + 2 + 64 + 2).
const MAX_INDEX_RECORD_PREFIX: usize = 66 + 80;

/// Scans the stored NV Indices (`0x01xxxxxx`) and persistent objects (`0x81xxxxxx`) of
/// `storage` into the reference's [`NvUsage`]; other (internal) items do not occupy the
/// reference's dynamic area.
///
/// # Errors
/// A storage error, or [`StorageError::HardwareError`] for an Index record that does not parse.
pub fn scan(storage: &StorageManager<'_>) -> Result<NvUsage, StorageError> {
    let mut usage = NvUsage::default();
    for item in storage
        .read_toc()?
        .iter()
        .take_while(|item| item.in_use != 0)
    {
        match item.handle >> 24 {
            0x01 => {
                let mut record = [0u8; MAX_INDEX_RECORD_PREFIX];
                let len = usize::from(item.data_size).min(MAX_INDEX_RECORD_PREFIX);
                storage.read_item(item.handle, 0, &mut record[..len])?;
                let (attributes, data_size) =
                    parse_index_record(&record[..len]).ok_or(StorageError::HardwareError)?;
                usage.add_index(attributes, data_size);
            }
            0x81 => usage.add_evict_object(),
            _ => {}
        }
    }
    Ok(usage)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The free dynamic area of empty NV: 11228 octets with the TCG reference profile (11088
    /// with the `act-a` feature).
    const FREE: u32 = NV_USER_DYNAMIC_END - NV_USER_DYNAMIC;

    /// The persistent objects that fit into empty NV: the free area less the next forward pointer,
    /// the list terminator and the reservation for `MIN_COUNTER_INDICES` counters, in units of
    /// `NV_EVICT_OBJECT_SIZE` (seven with the TCG reference profile, four with RSA-4096).
    const PERSISTENT: u32 = (FREE
        - SIZEOF_UINT32
        - SIZEOF_NV_LIST_TERMINATOR
        - MIN_COUNTER_INDICES * NV_INDEX_COUNTER_SIZE)
        / NV_EVICT_OBJECT_SIZE;

    // The TCG reference profile (16 KiB of NV, `nv-memory-size-*` changes it).
    const _: () = assert!(SIZEOF_OBJECT != 1280 || NV_MEMORY_SIZE != 16384 || PERSISTENT == 7);

    /// The reference fits seven persistent objects into empty NV (four with RSA-4096; the next one
    /// would eat into the space reserved for `MIN_COUNTER_INDICES` counters), whatever the key
    /// type.
    #[test]
    fn seven_persistent_objects_fit_into_empty_nv() {
        let mut usage = NvUsage::default();
        for _ in 0..PERSISTENT {
            assert!(usage.can_add_evict_object());
            usage.add_evict_object();
        }
        assert!(!usage.can_add_evict_object());
        assert_eq!(usage.free_bytes(), FREE - PERSISTENT * NV_EVICT_OBJECT_SIZE);
    }

    /// Indices must leave room for `MIN_EVICT_OBJECTS` persistent objects and, unless they are
    /// counters, for `MIN_COUNTER_INDICES` counters; orderly Indices are also limited by
    /// `RAM_INDEX_SPACE`.
    #[test]
    fn index_reservations_and_orderly_ram() {
        let ordinary = 0u32;
        let counter = TPM_NT_COUNTER << TPMA_NV_TPM_NT_SHIFT;
        let usage = NvUsage::default();
        // An ordinary Index reserves 16 + 2 * 1288 + 8 * 160 = 3872 (with RSA-4096: 2 * 2184).
        let reserved = 16 + 2 * NV_EVICT_OBJECT_SIZE + 8 * NV_INDEX_COUNTER_SIZE;
        assert!(usage.can_define_index(ordinary, (FREE - reserved - SIZEOF_NV_INDEX) as u16));
        assert!(!usage.can_define_index(ordinary, (FREE - reserved - SIZEOF_NV_INDEX + 1) as u16));
        // A counter reserves no counter space.
        assert!(usage.can_define_index(counter, 8));
        let mut orderly = NvUsage::default();
        assert!(orderly.can_define_index(TPMA_NV_ORDERLY, 500));
        assert!(!orderly.can_define_index(TPMA_NV_ORDERLY, 501));
        orderly.add_index(TPMA_NV_ORDERLY, 100);
        assert_eq!(orderly.dynamic_bytes, 4 + SIZEOF_NV_INDEX);
        assert_eq!(orderly.orderly_ram_bytes, 112);
        assert!(!orderly.can_define_index(TPMA_NV_ORDERLY, 389));
        assert!(orderly.can_define_index(TPMA_NV_ORDERLY, 388));
    }

    /// `TPM_PT_HR_PERSISTENT_AVAIL` / `TPM_PT_NV_COUNTERS_AVAIL` estimates, as the reference's
    /// `NvCapGetPersistentAvail()` / `NvCapGetCounterAvail()` compute them.
    #[test]
    fn availability_estimates_match_the_reference() {
        // The orderly RAM limits the counters to 25 unless the `MIN_EVICT_OBJECTS` reservation
        // of a large `sizeof(OBJECT)` (ML-KEM or ML-DSA) leaves fewer in the dynamic area.
        let counters = |usage: &NvUsage, ram: u32| {
            let mut avail = usage.free_bytes() - SIZEOF_NV_LIST_TERMINATOR;
            if usage.persistent < MIN_EVICT_OBJECTS {
                avail = avail
                    .saturating_sub((MIN_EVICT_OBJECTS - usage.persistent) * NV_EVICT_OBJECT_SIZE);
            }
            (avail / NV_INDEX_COUNTER_SIZE).min(ram)
        };
        let mut usage = NvUsage::default();
        assert_eq!(
            (usage.persistent_avail(), usage.counter_avail()),
            (PERSISTENT, counters(&usage, 25))
        );
        if SIZEOF_OBJECT <= 2176 {
            assert_eq!(usage.counter_avail(), 25);
        }
        usage.add_index(
            TPMA_NV_ORDERLY | (TPM_NT_COUNTER << TPMA_NV_TPM_NT_SHIFT),
            8,
        );
        assert_eq!(
            (usage.persistent_avail(), usage.counter_avail()),
            (PERSISTENT, counters(&usage, 24))
        );
        // (Large `sizeof(OBJECT)`s, e.g. with ML-DSA, leave room for fewer than 3 objects.)
        let first = PERSISTENT.min(3);
        for _ in 0..first {
            usage.add_evict_object();
        }
        assert_eq!(
            (usage.persistent_avail(), usage.counter_avail()),
            (PERSISTENT - first, counters(&usage, 24))
        );
        if SIZEOF_OBJECT <= 2176 {
            assert_eq!(usage.counter_avail(), 24);
        }
        for _ in 0..PERSISTENT - first {
            usage.add_evict_object();
        }
        assert_eq!(usage.persistent_avail(), 0);
    }

    /// Counters and persistent objects reduce the reservations.
    #[test]
    fn counts_reduce_reservations() {
        let mut usage = NvUsage::default();
        for _ in 0..8 {
            usage.add_index(TPM_NT_COUNTER << TPMA_NV_TPM_NT_SHIFT, 8);
        }
        usage.add_evict_object();
        usage.add_evict_object();
        assert_eq!((usage.counters, usage.persistent), (8, 2));
        let free = usage.free_bytes();
        assert!(usage.test_space(free - 16, true, false));
        assert!(!usage.test_space(free - 15, true, false));
    }

    /// Index records parse to their attributes and data size; truncated ones don't.
    #[test]
    fn index_records_parse() {
        // TPM2B_AUTH (2 bytes) || TPM2B_NV_PUBLIC (16 bytes: nvIndex, nameAlg, attributes,
        // empty authPolicy, dataSize 32).
        let record: [u8; 22] = [
            0, 2, 0xAA, 0xBB, 0, 16, 0x01, 0x50, 0, 0, 0x00, 0x0B, 0x04, 0x06, 0x00, 0x04, 0, 0, 0,
            32, 0xEE, 0xEE,
        ];
        assert_eq!(parse_index_record(&record), Some((0x0406_0004, 32)));
        assert_eq!(parse_index_record(&record[..19]), None);
        assert!(is_orderly(0x0406_0004));
        assert!(!is_counter(0x0406_0004));
    }
}
