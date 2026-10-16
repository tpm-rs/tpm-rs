//! The position of the `userAuth` size check (`TPM_RC_SIZE` on `inSensitive`)
//! relative to the template checks in the object-creation commands. The
//! specification does not order these checks; `tpm-rs` and the references use
//! the TCG reference's order: TPM2_Create and TPM2_CreatePrimary validate the
//! template's attributes first, TPM2_CreateLoaded checks the `userAuth` size
//! first.

use crate::_common::{build_pw_cmd, rc_of, rc_p};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;

/// `TPM_CC_CreatePrimary`.
const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
/// `TPM_CC_CreateLoaded`.
const CC_CREATE_LOADED: u32 = 0x0000_0191;
/// `TPM_RH_OWNER`.
const RH_OWNER: u32 = 0x4000_0001;

/// Prefixes `body` with its `u16` size (a `TPM2B`).
fn tpm2b(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// An ECDSA-SHA256 NIST P-256 signing key template (nameAlg SHA-256) with
/// *fixedTPM* SET and *fixedParent* CLEAR, which TPM 2.0 Part 2, TPMA_OBJECT,
/// does not allow ("If fixedTPM is SET in the object's parent, then fixedTPM
/// shall equal fixedParent in template"): an attribute error on `inPublic`.
const FIXED_TPM_WITHOUT_FIXED_PARENT: [u8; 24] = [
    0x00, 0x23, 0x00, 0x0b, 0x00, 0x04, 0x00, 0x62, 0x00,
    0x00, // type, nameAlg, attrs, authPolicy
    0x00, 0x10, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x03, 0x00,
    0x10, // NULL sym, ECDSA-SHA256, P-256
    0x00, 0x00, 0x00, 0x00, // unique: empty point
];

/// `TPM2B_SENSITIVE_CREATE` with a 48-byte `userAuth`, larger than the
/// SHA-256 digest of the template's nameAlg, and no data.
fn oversized_auth_sensitive() -> Vec<u8> {
    let mut body = tpm2b(&[0x61; 48]);
    body.extend_from_slice(&tpm2b(&[]));
    tpm2b(&body)
}

/// TPM2_CreatePrimary reports the attribute error of the template
/// (`TPM_RC_ATTRIBUTES` on `inPublic`) before the oversized `userAuth`.
#[test]
fn create_primary_checks_attributes_before_auth_size() {
    let mut tpm = Tpm::new();
    let mut params = oversized_auth_sensitive();
    params.extend_from_slice(&tpm2b(&FIXED_TPM_WITHOUT_FIXED_PARENT));
    params.extend_from_slice(&tpm2b(&[])); // outsideInfo
    params.extend_from_slice(&[0, 0, 0, 0]); // creationPCR: empty
    let rsp = tpm.send_command(0, &build_pw_cmd(CC_CREATE_PRIMARY, &[RH_OWNER], 1, &params));
    assert_eq!(rc_of(&rsp), rc_p(TpmRc::ATTRIBUTES, 2));
}

/// TPM2_CreateLoaded checks the `userAuth` size first (`TPM_RC_SIZE` on
/// `inSensitive`), before the attribute error of the template.
#[test]
fn create_loaded_checks_auth_size_before_attributes() {
    let mut tpm = Tpm::new();
    let mut params = oversized_auth_sensitive();
    params.extend_from_slice(&tpm2b(&FIXED_TPM_WITHOUT_FIXED_PARENT));
    let rsp = tpm.send_command(0, &build_pw_cmd(CC_CREATE_LOADED, &[RH_OWNER], 1, &params));
    assert_eq!(rc_of(&rsp), rc_p(TpmRc::SIZE, 1));
}
