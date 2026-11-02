//! TPM2_NV_DefineSpace2 (`tpm2-engine`'s `cc-nv-define-space2`): an NV Index defined from a
//! `TPM2B_NV_PUBLIC_2` is the same as one defined by TPM2_NV_DefineSpace (public area, Name,
//! data), the public-area validation, the handle types this TPM does not support (external
//! and permanent NV Indexes: `TPM_RC_HANDLE` + `publicInfo`), the unmarshaling of the tagged
//! union, the command attributes, and that the command is not implemented without the feature.
#![cfg_attr(not(feature = "cc-nv-define-space2"), allow(dead_code, unused_imports))]

use crate::_common::*;
use testing::tpm::Tpm;
#[cfg(feature = "cc-nv-define-space2")]
use tpm2::commands::{NVDefineSpace2, NVReadPublic};
use tpm2::errors::{Position, TpmRc};
#[cfg(feature = "cc-nv-define-space2")]
use tpm2::{
    Handle, Tpm2b, Tpm2bAuth, Tpm2bDigest, TpmaNv, TpmiAlgHash, TpmsNvPublic, TpmtNvPublic2,
    TpmuNvPublic2,
};

/// `TPM_CC_NV_DefineSpace2`.
const CC_NV_DEFINE_SPACE2: u32 = 0x0000_019D;
/// `TPM_HT_NV_INDEX`.
const HT_NV_INDEX: u8 = 0x01;
/// `TPM_HT_EXTERNAL_NV`.
const HT_EXTERNAL_NV: u8 = 0x11;
/// `TPM_HT_PERMANENT_NV`.
const HT_PERMANENT_NV: u8 = 0x12;
/// `TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD`.
const OWNER_RW: u32 = 0x0002_0002;

/// The marshaled `TPMS_NV_PUBLIC` (nameAlg SHA-256, empty authPolicy).
fn nv_public_body(index: u32, attributes: u32, data_size: u16) -> Vec<u8> {
    let mut body = index.to_be_bytes().to_vec();
    body.extend_from_slice(&0x000Bu16.to_be_bytes());
    body.extend_from_slice(&attributes.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&data_size.to_be_bytes());
    body
}

/// The marshaled `TPMS_NV_PUBLIC_EXP_ATTR` (nameAlg SHA-256, empty authPolicy).
fn nv_public_exp_attr_body(index: u32, attributes: u64, data_size: u16) -> Vec<u8> {
    let mut body = index.to_be_bytes().to_vec();
    body.extend_from_slice(&0x000Bu16.to_be_bytes());
    body.extend_from_slice(&attributes.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&data_size.to_be_bytes());
    body
}

/// Sends `TPM2_NV_DefineSpace2(TPM_RH_OWNER)` with an empty authValue and the
/// `TPM2B_NV_PUBLIC_2` whose `handleType` is `handle_type` and whose union member is `body`,
/// authorized by an empty password; returns the response code.
fn define_space2_raw(sim: &mut Tpm, handle_type: u8, body: &[u8]) -> u32 {
    let mut params = 0u16.to_be_bytes().to_vec();
    params.extend_from_slice(&(body.len() as u16 + 1).to_be_bytes());
    params.push(handle_type);
    params.extend_from_slice(body);
    let cmd = build(
        ST_SESSIONS,
        CC_NV_DEFINE_SPACE2,
        &[0x4000_0001],
        Some(&PW_SESSION),
        &params,
    );
    mssim_rc_of(sim, &cmd)
}

/// `TPM_RC_<rc> + P2` (`publicInfo`).
fn rc_p2(rc: tpm2::errors::Fmt1) -> u32 {
    rc.with(Position::parameter(2)).get()
}

/// Without the feature, `TPM2_NV_DefineSpace2` is not implemented (`TPM_RC_COMMAND_CODE`).
#[cfg(not(feature = "cc-nv-define-space2"))]
#[test]
fn not_implemented_without_feature() {
    let mut sim = Tpm::new();
    let rc = define_space2_raw(
        &mut sim,
        HT_NV_INDEX,
        &nv_public_body(0x0100_0000, OWNER_RW, 8),
    );
    assert_eq!(rc, TpmRc::COMMAND_CODE.get());
}

/// `TPM_CAP_COMMANDS` reports `TPM2_NV_DefineSpace2` with the `nv` attribute and one handle
/// (`TPMA_CC_INITIALIZER(0x019D, 0, 1, 0, 0, 1, 0, 0, 0)`).
#[cfg(feature = "cc-nv-define-space2")]
#[test]
fn command_attributes_are_nv_with_one_handle() {
    let mut sim = Tpm::new();
    assert_eq!(
        command_attributes(&mut sim, CC_NV_DEFINE_SPACE2),
        0x0240_019D
    );
}

/// An ordinary NV Index defined with `TPM2_NV_DefineSpace2` (`handleType` =
/// `TPM_HT_NV_INDEX`) reads back through TPM2_NV_ReadPublic with the same public area and
/// Name as an Index defined by TPM2_NV_DefineSpace, and holds data.
#[cfg(feature = "cc-nv-define-space2")]
#[test]
fn ordinary_index_matches_nv_define_space() {
    let mut sim = Tpm::new();
    let public = TpmsNvPublic {
        nv_index: Handle(0x0150_0002),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::AUTHREAD,
        auth_policy: Tpm2bDigest::from_bytes(&[0x5A; 32]).unwrap(),
        data_size: 16,
    };
    let cmd = NVDefineSpace2 {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::from_bytes(b"index auth").unwrap(),
        public_info: Tpm2b(TpmtNvPublic2::new(TpmuNvPublic2::NvIndex(public))),
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    let rsp = sim
        .execute(NVReadPublic {
            nv_index: public.nv_index,
        })
        .unwrap();
    assert_eq!(rsp.nv_public, Tpm2b(public));
    assert_eq!(rsp.nv_name, nv_name(&public));

    nv_write_index(&mut sim, 0x0150_0002, b"0123456789abcdef").unwrap();
    assert_eq!(nv_read_status(&mut sim, 0x0150_0002, 16), Ok(()));
}

/// A platform-created Index (`TPMA_NV_PLATFORMCREATE`) is defined with platform
/// authorization, like with TPM2_NV_DefineSpace.
#[cfg(feature = "cc-nv-define-space2")]
#[test]
fn platform_index_is_defined_with_platform_authorization() {
    let mut sim = Tpm::new();
    let public = TpmsNvPublic {
        nv_index: Handle(0x0180_0001),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::PPWRITE | TpmaNv::PPREAD | TpmaNv::PLATFORMCREATE,
        auth_policy: Tpm2bDigest::default(),
        data_size: 4,
    };
    let cmd = NVDefineSpace2 {
        auth_handle: Handle::RH_PLATFORM,
        auth: Tpm2bAuth::default(),
        public_info: Tpm2b(TpmtNvPublic2::new(TpmuNvPublic2::NvIndex(public))),
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();
    let rsp = sim
        .execute(NVReadPublic {
            nv_index: public.nv_index,
        })
        .unwrap();
    assert_eq!(rsp.nv_public, Tpm2b(public));
}

/// The public area is validated like TPM2_NV_DefineSpace's (`NvDefineSpace()`), with the
/// same response codes and positions: inconsistent attributes, sizes and authValue, the
/// creator's hierarchy, and an Index that already exists.
#[cfg(feature = "cc-nv-define-space2")]
#[test]
fn public_area_is_validated_like_nv_define_space() {
    let mut sim = Tpm::new();
    // TPMA_NV_WRITTEN may not be SET.
    let rc = define_space2_raw(
        &mut sim,
        HT_NV_INDEX,
        &nv_public_body(0x0100_0001, OWNER_RW | (1 << 29), 8),
    );
    assert_eq!(rc, rc_p2(TpmRc::ATTRIBUTES));
    // A counter is 8 octets.
    let rc = define_space2_raw(
        &mut sim,
        HT_NV_INDEX,
        &nv_public_body(0x0100_0001, OWNER_RW | 0x10, 4),
    );
    assert_eq!(rc, rc_p2(TpmRc::SIZE));
    // An owner may not create a platform Index.
    let rc = define_space2_raw(
        &mut sim,
        HT_NV_INDEX,
        &nv_public_body(0x0100_0001, OWNER_RW | (1 << 30), 8),
    );
    assert_eq!(rc, TpmRc::ATTRIBUTES.with(Position::handle(1)).get());
    // An authValue longer than the nameAlg digest.
    let mut params = 33u16.to_be_bytes().to_vec();
    params.extend_from_slice(&[0x11; 33]);
    let body = nv_public_body(0x0100_0001, OWNER_RW, 8);
    params.extend_from_slice(&(body.len() as u16 + 1).to_be_bytes());
    params.push(HT_NV_INDEX);
    params.extend_from_slice(&body);
    let cmd = build(
        ST_SESSIONS,
        CC_NV_DEFINE_SPACE2,
        &[0x4000_0001],
        Some(&PW_SESSION),
        &params,
    );
    assert_eq!(
        mssim_rc_of(&mut sim, &cmd),
        TpmRc::SIZE.with(Position::parameter(1)).get()
    );
    // An Index that exists (defined by either command).
    define_nv(&mut sim, 0x0100_0002, NV_RW, 8);
    let rc = define_space2_raw(
        &mut sim,
        HT_NV_INDEX,
        &nv_public_body(0x0100_0002, OWNER_RW, 8),
    );
    assert_eq!(rc, TpmRc::NV_DEFINED.get());
}

/// External NV Indexes (`TPM_HT_EXTERNAL_NV`) are not implemented: a well-formed
/// `TPMS_NV_PUBLIC_EXP_ATTR` is rejected with `TPM_RC_HANDLE` + `publicInfo` (whatever its
/// expanded attributes), and no Index is defined.
#[cfg(feature = "cc-nv-define-space2")]
#[test]
fn external_nv_index_is_not_supported() {
    let mut sim = Tpm::new();
    for attributes in [
        OWNER_RW as u64,
        OWNER_RW as u64 | 1 << 32,
        OWNER_RW as u64 | 0x7 << 32,
    ] {
        let rc = define_space2_raw(
            &mut sim,
            HT_EXTERNAL_NV,
            &nv_public_exp_attr_body(0x1100_0001, attributes, 8),
        );
        assert_eq!(rc, rc_p2(TpmRc::HANDLE), "{attributes:#x}");
    }
    let (handles, _) = cap_handles(&mut sim, 0x0100_0000, 64).unwrap();
    assert!(handles.is_empty(), "{handles:x?}");
}

/// Permanent NV Indexes (`TPM_HT_PERMANENT_NV`) are architecturally defined, not by
/// TPM2_NV_DefineSpace2: `TPM_RC_HANDLE` + `publicInfo`.
#[cfg(feature = "cc-nv-define-space2")]
#[test]
fn permanent_nv_index_is_not_defined() {
    let mut sim = Tpm::new();
    let rc = define_space2_raw(
        &mut sim,
        HT_PERMANENT_NV,
        &nv_public_body(0x0100_0003, OWNER_RW, 8),
    );
    assert_eq!(rc, rc_p2(TpmRc::HANDLE));
}

/// The union member's `nvIndex` must be in the range of its interface type
/// (`TPMI_RH_NV_LEGACY_INDEX` for a `TPMS_NV_PUBLIC`, `TPMI_RH_NV_EXP_INDEX` for a
/// `TPMS_NV_PUBLIC_EXP_ATTR`), else `TPM_RC_VALUE` + `publicInfo`; reserved expanded attribute
/// bits are `TPM_RC_RESERVED_BITS`; an unknown `handleType` is `TPM_RC_SELECTOR`.
#[cfg(feature = "cc-nv-define-space2")]
#[test]
fn union_members_are_unmarshaled_by_handle_type() {
    let mut sim = Tpm::new();
    let cases: [(&str, u8, Vec<u8>, u32); 7] = [
        (
            "NV_INDEX with an external handle",
            HT_NV_INDEX,
            nv_public_body(0x1100_0000, OWNER_RW, 8),
            rc_p2(TpmRc::VALUE),
        ),
        (
            "NV_INDEX with a permanent NV handle",
            HT_NV_INDEX,
            nv_public_body(0x1200_0000, OWNER_RW, 8),
            rc_p2(TpmRc::VALUE),
        ),
        (
            "EXTERNAL_NV with an ordinary handle",
            HT_EXTERNAL_NV,
            nv_public_exp_attr_body(0x0100_0000, OWNER_RW as u64, 8),
            rc_p2(TpmRc::VALUE),
        ),
        (
            "PERMANENT_NV with a permanent NV handle",
            HT_PERMANENT_NV,
            nv_public_body(0x1200_0000, OWNER_RW, 8),
            rc_p2(TpmRc::VALUE),
        ),
        (
            "EXTERNAL_NV with reserved bit 35",
            HT_EXTERNAL_NV,
            nv_public_exp_attr_body(0x1100_0000, OWNER_RW as u64 | 1 << 35, 8),
            rc_p2(TpmRc::RESERVED_BITS),
        ),
        (
            "NV_INDEX with reserved bit 8",
            HT_NV_INDEX,
            nv_public_body(0x0100_0000, OWNER_RW | 1 << 8, 8),
            rc_p2(TpmRc::RESERVED_BITS),
        ),
        (
            "handleType TPM_HT_PERSISTENT",
            0x81,
            nv_public_body(0x0100_0000, OWNER_RW, 8),
            rc_p2(TpmRc::SELECTOR),
        ),
    ];
    for (name, handle_type, body, expected) in cases {
        assert_eq!(
            define_space2_raw(&mut sim, handle_type, &body),
            expected,
            "{name}"
        );
    }
}

/// The `TPM2B_NV_PUBLIC_2` size must be non-zero and match the unmarshaled
/// `TPMT_NV_PUBLIC_2` (`TPM_RC_SIZE` + `publicInfo`).
#[cfg(feature = "cc-nv-define-space2")]
#[test]
fn sized_public_area_must_match_its_contents() {
    let mut sim = Tpm::new();
    for size_delta in [-1i32, 1] {
        let body = nv_public_body(0x0100_0000, OWNER_RW, 8);
        let mut params = 0u16.to_be_bytes().to_vec();
        params.extend_from_slice(&((body.len() as i32 + 1 + size_delta) as u16).to_be_bytes());
        params.push(HT_NV_INDEX);
        params.extend_from_slice(&body);
        params.push(0);
        let cmd = build(
            ST_SESSIONS,
            CC_NV_DEFINE_SPACE2,
            &[0x4000_0001],
            Some(&PW_SESSION),
            &params,
        );
        assert_eq!(
            mssim_rc_of(&mut sim, &cmd),
            rc_p2(TpmRc::SIZE),
            "{size_delta}"
        );
    }
    let mut params = 0u16.to_be_bytes().to_vec();
    params.extend_from_slice(&0u16.to_be_bytes());
    let cmd = build(
        ST_SESSIONS,
        CC_NV_DEFINE_SPACE2,
        &[0x4000_0001],
        Some(&PW_SESSION),
        &params,
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), rc_p2(TpmRc::SIZE));
}

/// `authHandle` is a `TPMI_RH_PROVISION`, and a disabled platform NV (`phEnableNV`) cannot
/// define a platform Index (`TPM_RC_HIERARCHY` + H1).
#[cfg(feature = "cc-nv-define-space2")]
#[test]
fn auth_handle_is_provision() {
    let mut sim = Tpm::new();
    let mut params = 0u16.to_be_bytes().to_vec();
    let body = nv_public_body(0x0100_0000, OWNER_RW, 8);
    params.extend_from_slice(&(body.len() as u16 + 1).to_be_bytes());
    params.push(HT_NV_INDEX);
    params.extend_from_slice(&body);
    let cmd = build(
        ST_SESSIONS,
        CC_NV_DEFINE_SPACE2,
        &[0x4000_000B],
        Some(&PW_SESSION),
        &params,
    );
    assert_eq!(mssim_rc_of(&mut sim, &cmd), RC_VALUE_H1);

    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_PLATFORM_NV, false).unwrap();
    let mut params = 0u16.to_be_bytes().to_vec();
    let body = nv_public_body(0x0180_0000, 0x0001_0001 | 1 << 30, 8);
    params.extend_from_slice(&(body.len() as u16 + 1).to_be_bytes());
    params.push(HT_NV_INDEX);
    params.extend_from_slice(&body);
    let cmd = build(
        ST_SESSIONS,
        CC_NV_DEFINE_SPACE2,
        &[0x4000_000C],
        Some(&PW_SESSION),
        &params,
    );
    assert_eq!(
        mssim_rc_of(&mut sim, &cmd),
        TpmRc::HIERARCHY.with(Position::handle(1)).get()
    );
}
