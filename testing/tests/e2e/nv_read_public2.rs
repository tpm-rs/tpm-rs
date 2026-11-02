//! TPM2_NV_ReadPublic2 (`tpm2-engine`'s `cc-nv-read-public2`): the public area of an NV
//! Index as a `TPM2B_NV_PUBLIC_2` (`handleType` `TPM_HT_NV_INDEX` and the `TPMS_NV_PUBLIC`)
//! with the same Name as TPM2_NV_ReadPublic, the handle checks (undefined Indexes, external
//! and permanent NV handles, other handle types), the command attributes, and that the command
//! is not implemented without the feature.
#![cfg_attr(not(feature = "cc-nv-read-public2"), allow(dead_code, unused_imports))]

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::errors::{Position, TpmRc};
#[cfg(feature = "cc-nv-read-public2")]
use tpm2::{
    Handle, Tpm2b, TpmaNv, TpmtNvPublic2, TpmuNvPublic2,
    commands::{NVReadPublic, NVReadPublic2},
};

/// `TPM_CC_NV_ReadPublic2`.
const CC_NV_READ_PUBLIC2: u32 = 0x0000_019E;

/// Sends `TPM2_NV_ReadPublic2(nv_index)` without sessions; returns the response code.
fn read_public2_rc(sim: &mut Tpm, nv_index: u32) -> u32 {
    let cmd = build(ST_NO_SESSIONS, CC_NV_READ_PUBLIC2, &[nv_index], None, &[]);
    mssim_rc_of(sim, &cmd)
}

/// Without the feature, `TPM2_NV_ReadPublic2` is not implemented (`TPM_RC_COMMAND_CODE`).
#[cfg(not(feature = "cc-nv-read-public2"))]
#[test]
fn not_implemented_without_feature() {
    let mut sim = Tpm::new();
    define_nv(&mut sim, 0x0100_0000, NV_RW, 8);
    assert_eq!(
        read_public2_rc(&mut sim, 0x0100_0000),
        TpmRc::COMMAND_CODE.get()
    );
}

/// `TPM_CAP_COMMANDS` reports `TPM2_NV_ReadPublic2` with one handle and no other attribute
/// (`TPMA_CC_INITIALIZER(0x019E, 0, 0, 0, 0, 1, 0, 0, 0)`).
#[cfg(feature = "cc-nv-read-public2")]
#[test]
fn command_attributes_have_one_handle() {
    let mut sim = Tpm::new();
    assert_eq!(
        command_attributes(&mut sim, CC_NV_READ_PUBLIC2),
        0x0200_019E
    );
}

/// The public area of an ordinary NV Index is the `TPM_HT_NV_INDEX` member with the Index's
/// `TPMS_NV_PUBLIC`, and its Name is the one TPM2_NV_ReadPublic reports (the hash of the
/// `TPMS_NV_PUBLIC`, without `handleType`), also after the Index was written (`WRITTEN`).
#[cfg(feature = "cc-nv-read-public2")]
#[test]
fn ordinary_index_public_area_and_name_match_nv_read_public() {
    let mut sim = Tpm::new();
    let index = 0x0140_0001;
    define_nv(
        &mut sim,
        index,
        NV_RW | TpmaNv::AUTHREAD | TpmaNv::NO_DA,
        12,
    );
    for write in [false, true] {
        if write {
            nv_write_index(&mut sim, index, b"hello world!").unwrap();
        }
        let legacy = sim
            .execute(NVReadPublic {
                nv_index: Handle(index),
            })
            .unwrap();
        let rsp = sim
            .execute(NVReadPublic2 {
                nv_index: Handle(index),
            })
            .unwrap();
        assert_eq!(
            rsp.nv_public,
            Tpm2b(TpmtNvPublic2::new(TpmuNvPublic2::NvIndex(
                legacy.nv_public.0
            )))
        );
        assert_eq!(rsp.nv_name, legacy.nv_name);
        assert_eq!(rsp.nv_name, nv_name(&legacy.nv_public.0));
        assert_eq!(
            legacy.nv_public.0.attributes.contains(TpmaNv::WRITTEN),
            write
        );
    }
}

/// An undefined NV Index is `TPM_RC_HANDLE` + H1; external and permanent NV handles (valid
/// `TPMI_RH_NV_INDEX` values that this TPM does not implement) are `TPM_RC_VALUE` + H1, as are
/// handles of other types.
#[cfg(feature = "cc-nv-read-public2")]
#[test]
fn nv_index_handle_is_checked() {
    let mut sim = Tpm::new();
    assert_eq!(
        read_public2_rc(&mut sim, 0x0100_0042),
        TpmRc::HANDLE.with(Position::handle(1)).get()
    );
    for handle in [
        0x1100_0000,
        0x1200_0000,
        0x8100_0000,
        0x4000_0001,
        0x0000_0000,
    ] {
        assert_eq!(
            read_public2_rc(&mut sim, handle),
            RC_VALUE_H1,
            "{handle:#x}"
        );
    }
}

/// An Index of a disabled hierarchy is not accessible: a platform Index while `phEnableNV` is
/// CLEAR is `TPM_RC_HANDLE` + H1, like with TPM2_NV_ReadPublic.
#[cfg(feature = "cc-nv-read-public2")]
#[test]
fn platform_index_is_hidden_while_platform_nv_is_disabled() {
    let mut sim = Tpm::new();
    let index = 0x0180_0003;
    define_platform(&mut sim, index, TpmaNv::PPWRITE | TpmaNv::PPREAD, 4, &[]);
    assert!(
        sim.execute(NVReadPublic2 {
            nv_index: Handle(index)
        })
        .is_ok()
    );
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_PLATFORM_NV, false).unwrap();
    assert_eq!(
        read_public2_rc(&mut sim, index),
        TpmRc::HANDLE.with(Position::handle(1)).get()
    );
}
