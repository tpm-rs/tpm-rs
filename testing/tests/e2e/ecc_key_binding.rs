//! ECC objects loaded or imported with their sensitive area: the public point
//! is checked against the private key (`TPM_RC_BINDING`), not on its own
//! (`TPM_RC_ECC_POINT` is for public-only keys), for TPM2_LoadExternal and for
//! TPM2_Import under a *fixedTPM* parent.
//!
//! TPM 2.0 Part 3, TPM2_Load: "Before use, a loaded object shall be checked to
//! validate that the public and sensitive portions are properly linked,
//! cryptographically. ... If the parts of the object are not properly linked,
//! the TPM shall return `TPM_RC_BINDING`." TPM2_LoadExternal: "If *nameAlg* is
//! not `TPM_ALG_NULL`, then the same consistency checks between *inPublic* and
//! *inPrivate* are made as for `TPM2_Load()`."

use crate::_common::{build, build_pw_cmd, get_ecc_srk_template, rc_of, try_create_owner_primary};
use testing::tpm::Tpm;
use tpm2::Handle;

/// `TPM_CC_LoadExternal`.
const TPM_CC_LOAD_EXTERNAL: u32 = 0x0000_0167;
/// `TPM_CC_Import`.
const TPM_CC_IMPORT: u32 = 0x0000_0156;
/// `TPM_RC_BINDING` (format one, no position).
const TPM_RC_BINDING: u32 = 0x0000_00A5;

/// Prefixes `body` with its `u16` size (a `TPM2B`).
fn tpm2b(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// A `TPM2B_SENSITIVE` of an ECC key with private scalar `d = 1` (P-256).
fn ecc_sensitive() -> Vec<u8> {
    let mut d = [0u8; 32];
    d[31] = 1;
    let mut sensitive = vec![0x00, 0x23]; // TPM_ALG_ECC
    sensitive.extend_from_slice(&tpm2b(&[])); // authValue
    sensitive.extend_from_slice(&tpm2b(&[])); // seedValue
    sensitive.extend_from_slice(&tpm2b(&d));
    tpm2b(&sensitive)
}

/// A `TPM2B_PUBLIC` of an unrestricted ECC P-256 signing key (SHA256 Name,
/// `sign | userWithAuth`) whose public point `(0x11.., 0x22..)` is not on the
/// curve.
fn ecc_public_off_curve() -> Vec<u8> {
    let mut public = vec![0x00, 0x23, 0x00, 0x0b]; // TPM_ALG_ECC, SHA256
    public.extend_from_slice(&0x0004_0040u32.to_be_bytes());
    public.extend_from_slice(&tpm2b(&[])); // authPolicy
    public.extend_from_slice(&[0x00, 0x10]); // symmetric: TPM_ALG_NULL
    public.extend_from_slice(&[0x00, 0x10]); // scheme: TPM_ALG_NULL
    public.extend_from_slice(&[0x00, 0x03]); // TPM_ECC_NIST_P256
    public.extend_from_slice(&[0x00, 0x10]); // kdf: TPM_ALG_NULL
    public.extend_from_slice(&tpm2b(&[0x11; 32]));
    public.extend_from_slice(&tpm2b(&[0x22; 32]));
    tpm2b(&public)
}

/// TPM2_LoadExternal of an ECC key with its sensitive area and a public point
/// that is not on the curve fails the binding check (`TPM_RC_BINDING`).
#[test]
fn load_external_off_curve_point_with_private_key_is_binding_error() {
    let mut tpm = Tpm::new();
    let mut params = ecc_sensitive();
    params.extend_from_slice(&ecc_public_off_curve());
    params.extend_from_slice(&Handle::RH_NULL.0.to_be_bytes());
    let cmd = build(0x8001, TPM_CC_LOAD_EXTERNAL, &[], None, &params);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), TPM_RC_BINDING);
}

/// TPM2_Import of an unwrapped ECC duplicate whose public point is not on the
/// curve, under a *fixedTPM* parent (which validates the object at import),
/// fails the binding check (`TPM_RC_BINDING`) after the duplicate is
/// unwrapped.
#[test]
fn import_off_curve_point_under_fixed_tpm_parent_is_binding_error() {
    let mut tpm = Tpm::new();
    let (parent, _) = try_create_owner_primary(&mut tpm, get_ecc_srk_template()).expect("parent");
    let mut params = tpm2b(&[]); // encryptionKey
    params.extend_from_slice(&ecc_public_off_curve());
    params.extend_from_slice(&tpm2b(&ecc_sensitive())); // duplicate: TPM2B_PRIVATE
    params.extend_from_slice(&tpm2b(&[])); // inSymSeed
    params.extend_from_slice(&[0x00, 0x10]); // symmetricAlg: TPM_ALG_NULL
    let cmd = build_pw_cmd(TPM_CC_IMPORT, &[parent.0], 1, &params);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), TPM_RC_BINDING);
}
