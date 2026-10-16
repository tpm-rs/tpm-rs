//! NV capacity: TPM2_EvictControl and TPM2_NV_DefineSpace run out of NV space
//! (`TPM_RC_NV_SPACE`) exactly where the reference does. NV capacity is implementation-specific
//! (TPM 2.0 Part 2, `TPM_PT_HR_PERSISTENT_AVAIL`/`TPM_PT_NV_COUNTERS_AVAIL`: "This value is an
//! estimate"), so tpm-rs follows the reference's `NvTestSpace()` accounting: a dynamic area of
//! 11364 bytes, every persistent object taking 1288 bytes whatever its key type, an Index
//! `4 + 148` bytes plus its data (orderly data in a 512-byte RAM area with 12-byte headers),
//! and room reserved for 2 persistent objects (when defining an Index) and 8 counter Indices
//! (unless defining a counter).

use crate::_common::{create_ecc_parent_key, create_parent_key, evict_control_rc, try_define};
use testing::tpm::Tpm;
use tpm2::{Handle, TpmaNv, TpmiAlgHash, TpmsNvPublic};

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

/// Evicts `object` to consecutive persistent handles until EvictControl fails; returns the
/// number of successes and the failing response code.
fn evict_until_full(tpm: &mut Tpm, object: Handle) -> (u32, u32) {
    for i in 0..16 {
        let rc = evict_control_rc(tpm, Handle(OWNER), object.0, 0x8100_0300 + i);
        if rc != 0 {
            return (i, rc);
        }
    }
    panic!("NV never filled up");
}

/// Seven persistent copies of an ECC key fit into empty NV; the eighth would use the space
/// reserved for the minimum number of counter Indices (`TPM_RC_NV_SPACE`).
#[test]
fn seven_ecc_persistent_objects_fit() {
    let mut tpm = Tpm::new();
    let key = create_ecc_parent_key(&mut tpm);
    assert_eq!(evict_until_full(&mut tpm, key), (7, RC_NV_SPACE));
}

/// A persistent RSA-2048 key takes as much NV space as an ECC key: seven fit as well.
#[test]
fn seven_rsa_persistent_objects_fit() {
    let mut tpm = Tpm::new();
    let key = create_parent_key(&mut tpm);
    assert_eq!(evict_until_full(&mut tpm, key), (7, RC_NV_SPACE));
}

/// Indices must leave room for two persistent objects and eight counters: after three
/// 2048-byte Indices, a fourth Index fits with at most 744 data bytes.
#[test]
fn index_definition_reserves_persistent_and_counter_space() {
    let mut tpm = Tpm::new();
    for i in 0..3 {
        try_define(
            &mut tpm,
            Handle(OWNER),
            b"",
            index(0x0150_0100 + i, TpmaNv::empty(), 2048),
        )
        .unwrap();
    }
    assert_eq!(
        try_define(
            &mut tpm,
            Handle(OWNER),
            b"",
            index(0x0150_0110, TpmaNv::empty(), 745)
        )
        .err(),
        Some(RC_NV_SPACE)
    );
    try_define(
        &mut tpm,
        Handle(OWNER),
        b"",
        index(0x0150_0110, TpmaNv::empty(), 744),
    )
    .unwrap();
    // A counter needs no room reserved for counters.
    try_define(
        &mut tpm,
        Handle(OWNER),
        b"",
        index(0x0150_0111, counter(), 8),
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
    // Empty NV: (11364 - 12 - 8 * 160) / 1288 persistent objects; counters limited by the
    // orderly RAM (512 / 20) rather than NV ((11364 - 12 - 2 * 1288) / 160).
    assert_eq!(props(&mut tpm), (7, 0, 25));
    try_define(
        &mut tpm,
        Handle(OWNER),
        b"",
        index(0x0150_0300, counter() | TpmaNv::ORDERLY, 8),
    )
    .unwrap();
    assert_eq!(props(&mut tpm), (7, 1, 24));
    let key = create_ecc_parent_key(&mut tpm);
    for i in 0..3 {
        assert_eq!(
            evict_control_rc(&mut tpm, Handle(OWNER), key.0, 0x8100_0400 + i),
            0
        );
    }
    // 11364 - 152 - 3 * 1288 free; less 12 + 7 * 160 for counters.
    assert_eq!(props(&mut tpm), (4, 1, 24));
}
