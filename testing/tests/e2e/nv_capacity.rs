//! NV capacity: TPM2_EvictControl and TPM2_NV_DefineSpace run out of NV space
//! (`TPM_RC_NV_SPACE`) exactly where the reference does. NV capacity is implementation-specific
//! (TPM 2.0 Part 2, `TPM_PT_HR_PERSISTENT_AVAIL`/`TPM_PT_NV_COUNTERS_AVAIL`: "This value is an
//! estimate"), so tpm-rs follows the reference's `NvTestSpace()` accounting
//! (`tpm2_impl::storage::nv_capacity`, whose model [`NvUsage`] gives the expected results): with
//! the default profile (`NV_MEMORY_SIZE` 16384, `MIN_EVICT_OBJECTS` 2), a dynamic area of 11228
//! bytes (11088 with the `act-a` feature: the ACT state moves `NV_INDEX_RAM_DATA`), every persistent object taking 1288 bytes whatever its key type, an Index `4 + 148`
//! bytes plus its data (orderly data in a 512-byte RAM area with 12-byte headers), and room
//! reserved for 2 persistent objects (when defining an Index) and 8 counter Indices (unless
//! defining a counter). The profile features of `tpm2-impl` (e.g. of a differential target)
//! change `NV_MEMORY_SIZE` and `MIN_EVICT_OBJECTS`.

use crate::_common::{create_ecc_parent_key, create_parent_key, evict_control_rc, try_define};
use testing::tpm::Tpm;
use tpm2::{Handle, TpmaNv, TpmiAlgHash, TpmsNvPublic};
use tpm2_impl::storage::nv_capacity::{
    MIN_EVICT_OBJECTS, NV_INDEX_RAM_DATA, NV_MEMORY_SIZE, NvUsage,
};

/// Whether the TPM has the default NV profile, whose results the tests also check literally.
const DEFAULT_NV_PROFILE: bool = NV_MEMORY_SIZE == 16384 && MIN_EVICT_OBJECTS == 2;

/// `TPM_RC_NV_SPACE`.
const RC_NV_SPACE: u32 = 0x14B;
/// `TPM_RH_OWNER`.
const OWNER: u32 = 0x4000_0001;

/// An ordinary Index (`AUTHWRITE | AUTHREAD | NO_DA`) plus `extra` attributes.
fn index(nv_index: u32, extra: TpmaNv, data_size: u16) -> TpmsNvPublic<'static> {
    TpmsNvPublic {
        nv_index: Handle(nv_index),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::AUTHWRITE | TpmaNv::AUTHREAD | TpmaNv::NO_DA | extra,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size,
    }
}

/// `TPM_NT_COUNTER` in `TPMA_NV`.
fn counter() -> TpmaNv {
    TpmaNv::from_bits_retain(1 << 4)
}

/// The number of persistent objects that fit into empty NV ([`NvUsage`]).
fn persistent_capacity() -> u32 {
    let mut usage = NvUsage::default();
    let mut count = 0;
    while usage.can_add_evict_object() {
        usage.add_evict_object();
        count += 1;
    }
    count
}

/// Evicts `object` to consecutive persistent handles until EvictControl fails; returns the
/// number of successes and the failing response code.
fn evict_until_full(tpm: &mut Tpm, object: Handle) -> (u32, u32) {
    for i in 0..=persistent_capacity() {
        let rc = evict_control_rc(tpm, Handle(OWNER), object.0, 0x8100_0300 + i);
        if rc != 0 {
            return (i, rc);
        }
    }
    panic!("NV never filled up");
}

/// Persistent copies of an ECC key fit into empty NV until the next one would use the space
/// reserved for the minimum number of counter Indices (`TPM_RC_NV_SPACE`): seven with the default
/// profile.
#[test]
fn ecc_persistent_objects_fill_nv() {
    let mut tpm = Tpm::new();
    let key = create_ecc_parent_key(&mut tpm);
    assert_eq!(
        evict_until_full(&mut tpm, key),
        (persistent_capacity(), RC_NV_SPACE)
    );
    if DEFAULT_NV_PROFILE {
        assert_eq!(persistent_capacity(), 7);
    }
}

/// A persistent RSA-2048 key takes as much NV space as an ECC key: as many fit.
#[test]
fn rsa_persistent_objects_fill_nv() {
    let mut tpm = Tpm::new();
    let key = create_parent_key(&mut tpm);
    assert_eq!(
        evict_until_full(&mut tpm, key),
        (persistent_capacity(), RC_NV_SPACE)
    );
}

/// Indices must leave room for `MIN_EVICT_OBJECTS` persistent objects and eight counters: after
/// as many 2048-byte Indices as fit, the next Index fits with at most the remaining data bytes
/// (with the default profile: three Indices, then 608 data bytes; 468 with the `act-a` feature).
#[test]
fn index_definition_reserves_persistent_and_counter_space() {
    let ordinary = TpmaNv::AUTHWRITE | TpmaNv::AUTHREAD | TpmaNv::NO_DA;
    let mut usage = NvUsage::default();
    let mut tpm = Tpm::new();
    let mut full = 0;
    while usage.can_define_index(ordinary.bits(), 2048) {
        try_define(
            &mut tpm,
            Handle(OWNER),
            b"",
            index(0x0150_0100 + full, TpmaNv::empty(), 2048),
        )
        .unwrap();
        usage.add_index(ordinary.bits(), 2048);
        full += 1;
    }
    let last = (0..2048u16)
        .rev()
        .find(|&size| usage.can_define_index(ordinary.bits(), size))
        .expect("room for a smaller Index");
    if DEFAULT_NV_PROFILE {
        // 744 data bytes in the reference's NV layout without ACTs (`NV_INDEX_RAM_DATA` 4508).
        assert_eq!((full, last), (3, (744 + 4508 - NV_INDEX_RAM_DATA) as u16));
    }
    assert_eq!(
        try_define(
            &mut tpm,
            Handle(OWNER),
            b"",
            index(0x0150_0000, TpmaNv::empty(), last + 1)
        )
        .err(),
        Some(RC_NV_SPACE)
    );
    try_define(
        &mut tpm,
        Handle(OWNER),
        b"",
        index(0x0150_0000, TpmaNv::empty(), last),
    )
    .unwrap();
    // A counter needs no room reserved for counters.
    try_define(
        &mut tpm,
        Handle(OWNER),
        b"",
        index(0x0150_0001, counter(), 8),
    )
    .unwrap();
}

/// Orderly Indices keep their data in a 512-byte RAM area with a 12-byte header each.
#[test]
fn orderly_index_data_is_limited_by_ram() {
    let mut tpm = Tpm::new();
    assert_eq!(
        try_define(
            &mut tpm,
            Handle(OWNER),
            b"",
            index(0x0150_0200, TpmaNv::ORDERLY, 501)
        )
        .err(),
        Some(RC_NV_SPACE)
    );
    try_define(
        &mut tpm,
        Handle(OWNER),
        b"",
        index(0x0150_0200, TpmaNv::ORDERLY, 488),
    )
    .unwrap();
    assert_eq!(
        try_define(
            &mut tpm,
            Handle(OWNER),
            b"",
            index(0x0150_0201, TpmaNv::ORDERLY, 1)
        )
        .err(),
        Some(RC_NV_SPACE)
    );
    try_define(
        &mut tpm,
        Handle(OWNER),
        b"",
        index(0x0150_0201, TpmaNv::ORDERLY, 0),
    )
    .unwrap();
}

/// TPM_PT_HR_PERSISTENT_AVAIL, TPM_PT_NV_COUNTERS and TPM_PT_NV_COUNTERS_AVAIL are the
/// reference's estimates from the same accounting (`NvCapGetPersistentAvail()`,
/// `NvCapGetCounterNumber()`, `NvCapGetCounterAvail()`).
#[test]
fn nv_availability_properties_follow_the_accounting() {
    use crate::_common::get_tpm_property;
    use tpm2::TpmPt;
    let mut tpm = Tpm::new();
    let props = |tpm: &mut Tpm| {
        (
            get_tpm_property(tpm, TpmPt::HR_PERSISTENT_AVAIL),
            get_tpm_property(tpm, TpmPt::NV_COUNTERS),
            get_tpm_property(tpm, TpmPt::NV_COUNTERS_AVAIL),
        )
    };
    let expected = |usage: &NvUsage| {
        (
            usage.persistent_avail(),
            usage.counters,
            usage.counter_avail(),
        )
    };
    let mut usage = NvUsage::default();
    // Empty NV, with the default profile (FREE = 11228 dynamic bytes): (FREE - 12 - 8 * 160) /
    // 1288 persistent objects; counters limited by the orderly RAM (512 / 20) rather than NV
    // ((FREE - 12 - 2 * 1288) / 160).
    assert_eq!(props(&mut tpm), expected(&usage));
    if DEFAULT_NV_PROFILE {
        assert_eq!(expected(&usage), (7, 0, 25));
    }
    let orderly_counter = counter() | TpmaNv::ORDERLY;
    try_define(
        &mut tpm,
        Handle(OWNER),
        b"",
        index(0x0150_0300, orderly_counter, 8),
    )
    .unwrap();
    usage.add_index(
        (orderly_counter | TpmaNv::AUTHWRITE | TpmaNv::AUTHREAD | TpmaNv::NO_DA).bits(),
        8,
    );
    assert_eq!(props(&mut tpm), expected(&usage));
    if DEFAULT_NV_PROFILE {
        assert_eq!(expected(&usage), (7, 1, 24));
    }
    let key = create_ecc_parent_key(&mut tpm);
    for i in 0..3 {
        assert_eq!(
            evict_control_rc(&mut tpm, Handle(OWNER), key.0, 0x8100_0400 + i),
            0
        );
        usage.add_evict_object();
    }
    // With the default profile: FREE - 152 - 3 * 1288 free; less 12 + 7 * 160 for counters.
    assert_eq!(props(&mut tpm), expected(&usage));
    if DEFAULT_NV_PROFILE {
        assert_eq!(expected(&usage), (4, 1, 24));
    }
}
