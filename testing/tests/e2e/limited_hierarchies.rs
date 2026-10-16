//! Firmware-limited (`TPM_RH_FW_*`) and SVN-limited (`{SVN_*_FIRST:SVN_*_LAST}`) hierarchies:
//! valid `TPMI_RH_HIERARCHY`/`TPMI_DH_PARENT` values whose use fails because this TPM has no
//! firmware secret (`TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED`): at the handle's load status, as
//! a disabled hierarchy (`TPM2_LoadExternal`), or when a ticket needs the hierarchy's proof.

use crate::_common::{PW_SESSION, build, rc_h, rc_of, rc_p};
use testing::tpm::Tpm;
use tpm2::errors::{Fmt1, TpmRc};

/// `TPM_CC_CreatePrimary`.
const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
/// `TPM_CC_LoadExternal`.
const TPM_CC_LOAD_EXTERNAL: u32 = 0x0000_0167;
/// `TPM_CC_Hash`.
const TPM_CC_HASH: u32 = 0x0000_017D;
/// `TPM_CC_HashSequenceStart`.
const TPM_CC_HASH_SEQUENCE_START: u32 = 0x0000_0186;
/// `TPM_CC_SequenceComplete`.
const TPM_CC_SEQUENCE_COMPLETE: u32 = 0x0000_013E;
/// `TPM_CC_ContextLoad`.
const TPM_CC_CONTEXT_LOAD: u32 = 0x0000_0161;
/// `TPM_CC_CreateLoaded`.
const TPM_CC_CREATE_LOADED: u32 = 0x0000_0191;

/// An empty `TPM2B_SENSITIVE_CREATE`.
const EMPTY_SENSITIVE_CREATE: [u8; 6] = [0, 4, 0, 0, 0, 0];

/// An ECC NIST P-256 ECDSA/SHA-256 signing key template with an empty `unique` and the given
/// `objectAttributes`.
fn ecc_template(attributes: u32) -> Vec<u8> {
    let mut t = vec![0x00, 0x23, 0x00, 0x0B];
    t.extend_from_slice(&attributes.to_be_bytes());
    t.extend_from_slice(&[
        0x00, 0x00, // authPolicy
        0x00, 0x10, // symmetric: NULL
        0x00, 0x18, 0x00, 0x0B, // scheme: ECDSA, SHA-256
        0x00, 0x03, // curveID: NIST P-256
        0x00, 0x10, // kdf: NULL
        0x00, 0x00, 0x00, 0x00, // unique
    ]);
    t
}

/// A `TPM2B` of `bytes`.
fn tpm2b(bytes: &[u8]) -> Vec<u8> {
    let mut v = (bytes.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(bytes);
    v
}

/// Firmware-limited and SVN-limited hierarchy handles with the error of their use.
const LIMITED: [(u32, Fmt1); 6] = [
    (0x4000_0140, TpmRc::FW_LIMITED),  // TPM_RH_FW_OWNER
    (0x4000_0142, TpmRc::FW_LIMITED),  // TPM_RH_FW_PLATFORM
    (0x4000_0143, TpmRc::FW_LIMITED),  // TPM_RH_FW_NULL
    (0x4001_0000, TpmRc::SVN_LIMITED), // SVN_OWNER_FIRST
    (0x4002_0007, TpmRc::SVN_LIMITED), // an SVN-limited Endorsement hierarchy
    (0x4004_FFFF, TpmRc::SVN_LIMITED), // SVN_NULL_LAST
];

/// The handles are valid `TPMI_RH_HIERARCHY` (`TPM2_CreatePrimary.primaryHandle`) and
/// `TPMI_DH_PARENT` (`TPM2_CreateLoaded.parentHandle`) values (TPM 2.0 Part 2, Table
/// "Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY Type": "TPM_RH_FW_OWNER | Firmware-limited
/// Storage hierarchy", ..., "{SVN_OWNER_FIRST:SVN_OWNER_LAST} | SVN-limited Storage
/// hierarchies", ...), but the hierarchy is not available: "TPM_RC_FW_LIMITED | the hierarchy is
/// firmware-limited but the Firmware Secret is unavailable" / "TPM_RC_SVN_LIMITED | the hierarchy
/// is SVN-limited but the Firmware SVN Secret associated with the given SVN is unavailable", at
/// the handle (`+ H1`).
#[test]
fn limited_hierarchy_handles_fail_with_limited_errors() {
    let mut tpm = Tpm::new();
    let template = ecc_template(0x0004_0072);
    for (handle, rc) in LIMITED {
        let mut params = EMPTY_SENSITIVE_CREATE.to_vec();
        params.extend_from_slice(&tpm2b(&template));
        let create_loaded = build(
            0x8002,
            TPM_CC_CREATE_LOADED,
            &[handle],
            Some(&PW_SESSION),
            &params,
        );
        params.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // outsideInfo, creationPCR
        let create_primary = build(
            0x8002,
            TPM_CC_CREATE_PRIMARY,
            &[handle],
            Some(&PW_SESSION),
            &params,
        );
        let expected = rc_h(rc, 1);
        assert_eq!(rc_of(&tpm.send_command(0, &create_primary)), expected);
        assert_eq!(rc_of(&tpm.send_command(0, &create_loaded)), expected);
    }
}

/// As the `hierarchy` of `TPM2_LoadExternal` the handle is not an enabled hierarchy (TPM 2.0
/// Part 3, TPM2_LoadExternal: "TPM_RC_HIERARCHY | hierarchy is not enabled or valid"), and as
/// the `hierarchy` of a hash-check ticket (`TPM2_Hash`, `TPM2_SequenceComplete`) or of a saved
/// context (`TPM2_ContextLoad`) its proof is unavailable (`TPM_RC_FW_LIMITED`/
/// `TPM_RC_SVN_LIMITED`).
#[test]
fn limited_hierarchy_parameters_fail_at_use() {
    let mut tpm = Tpm::new();
    for (handle, rc) in LIMITED {
        let mut params = vec![0, 0]; // inPrivate
        params.extend_from_slice(&tpm2b(&ecc_template(0x0004_0040)));
        params.extend_from_slice(&handle.to_be_bytes());
        let cmd = build(0x8001, TPM_CC_LOAD_EXTERNAL, &[], None, &params);
        assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_p(TpmRc::HIERARCHY, 3));

        let mut params = tpm2b(b"abc");
        params.extend_from_slice(&[0x00, 0x0B]);
        params.extend_from_slice(&handle.to_be_bytes());
        let cmd = build(0x8001, TPM_CC_HASH, &[], None, &params);
        assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc.get());

        let start = build(
            0x8001,
            TPM_CC_HASH_SEQUENCE_START,
            &[],
            None,
            &[0, 0, 0x00, 0x0B],
        );
        let rsp = tpm.send_command(0, &start);
        assert_eq!(rc_of(&rsp), 0);
        let sequence = u32::from_be_bytes(rsp[10..14].try_into().unwrap());
        // At least 4 bytes, so the ticket is safe to compute (they do not start with
        // TPM_GENERATED_VALUE).
        let mut params = tpm2b(b"abcd");
        params.extend_from_slice(&handle.to_be_bytes());
        let cmd = build(
            0x8002,
            TPM_CC_SEQUENCE_COMPLETE,
            &[sequence],
            Some(&PW_SESSION),
            &params,
        );
        assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc.get());
        // The failed TPM2_SequenceComplete left the sequence unchanged (TPM 2.0 Part 3,
        // "Response Codes": "Any other value indicates that the command did not complete and
        // the state of the TPM is unchanged."): completing it without a ticket succeeds and
        // returns SHA-256("abcd").
        let mut params = tpm2b(b"abcd");
        params.extend_from_slice(&tpm2::Handle::RH_NULL.0.to_be_bytes());
        let cmd = build(
            0x8002,
            TPM_CC_SEQUENCE_COMPLETE,
            &[sequence],
            Some(&PW_SESSION),
            &params,
        );
        let rsp = tpm.send_command(0, &cmd);
        assert_eq!(rc_of(&rsp), 0);
        // SHA-256("abcd") follows the response's parameterSize and TPM2B size.
        assert_eq!(
            rsp[16..48],
            [
                0x88, 0xd4, 0x26, 0x6f, 0xd4, 0xe6, 0x33, 0x8d, 0x13, 0xb8, 0x45, 0xfc, 0xf2, 0x89,
                0x57, 0x9d, 0x20, 0x9c, 0x89, 0x78, 0x23, 0xb9, 0x21, 0x7d, 0xa3, 0xe1, 0x61, 0x93,
                0x6f, 0x03, 0x15, 0x89
            ]
        );

        // TPM2_ContextLoad of an object context in the hierarchy: its integrity needs the
        // hierarchy's proof.
        let mut params = 1u64.to_be_bytes().to_vec(); // sequence
        params.extend_from_slice(&0x8000_0000u32.to_be_bytes()); // savedHandle
        params.extend_from_slice(&handle.to_be_bytes());
        let mut blob = tpm2b(&[0x11; 64]); // integrity (SHA-512)
        blob.extend_from_slice(&[0x22; 10]);
        params.extend_from_slice(&tpm2b(&blob));
        let cmd = build(0x8001, TPM_CC_CONTEXT_LOAD, &[], None, &params);
        assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc.get());
    }
}

/// `TPM2_HierarchyControl`'s `authHandle` is a `TPMI_RH_BASE_HIERARCHY` (TPM 2.0 Part 3,
/// TPM2_HierarchyControl: "TPMI_RH_BASE_HIERARCHY | @authHandle"; Part 2, Table "Definition of
/// (TPM_HANDLE) TPMI_RH_BASE_HIERARCHY Type": "TPM_RH_OWNER", "TPM_RH_PLATFORM",
/// "TPM_RH_ENDORSEMENT", "#TPM_RC_VALUE"), so a firmware-limited or SVN-limited hierarchy there
/// fails to unmarshal (`TPM_RC_VALUE + H1`) instead of reaching its load status.
#[test]
fn hierarchy_control_rejects_limited_hierarchies() {
    let mut tpm = Tpm::new();
    for (handle, _) in LIMITED {
        let mut params = tpm2::Handle::RH_OWNER.0.to_be_bytes().to_vec(); // enable
        params.push(0); // state: NO
        let cmd = build(0x8002, 0x0000_0121, &[handle], Some(&PW_SESSION), &params);
        assert_eq!(
            rc_of(&tpm.send_command(0, &cmd)),
            rc_h(TpmRc::VALUE, 1),
            "{handle:#x}"
        );
    }
}

/// `TPM2_CertifyCreation` recomputes the creation ticket for the ticket's hierarchy before it
/// compares it (TPM 2.0 Part 3, TPM2_CertifyCreation: "The TPM will validate that the ticket was
/// produced by the TPM"), so a firmware-limited or SVN-limited ticket hierarchy fails with
/// `TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED`, also when the certified object is a sequence object
/// (which no ticket can match).
#[test]
fn certify_creation_ticket_of_limited_hierarchy_fails() {
    let mut tpm = Tpm::new();
    let start = build(
        0x8001,
        TPM_CC_HASH_SEQUENCE_START,
        &[],
        None,
        &[0, 0, 0x00, 0x0B],
    );
    let rsp = tpm.send_command(0, &start);
    assert_eq!(rc_of(&rsp), 0);
    let sequence = u32::from_be_bytes(rsp[10..14].try_into().unwrap());
    for (handle, rc) in LIMITED {
        let mut params = vec![0, 0]; // qualifyingData
        params.extend_from_slice(&[0, 0]); // creationHash
        params.extend_from_slice(&[0x00, 0x10]); // inScheme: TPM_ALG_NULL
        params.extend_from_slice(&[0x80, 0x21]); // creationTicket: TPM_ST_CREATION
        params.extend_from_slice(&handle.to_be_bytes());
        params.extend_from_slice(&[0, 0]); // empty digest
        let cmd = build(
            0x8002,
            0x0000_014A,
            &[tpm2::Handle::RH_NULL.0, sequence],
            Some(&PW_SESSION),
            &params,
        );
        assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc.get(), "{handle:#x}");
    }
}
