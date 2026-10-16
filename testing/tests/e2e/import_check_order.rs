//! TPM2_Import check order for inputs that fail before or at the validation of
//! the imported object: an outer wrapper (`inSymSeed`) under a symmetric
//! storage parent, and an ECC public point whose coordinate is larger than the
//! curve's key size. In both cases `tpm-rs` and the references return the
//! response code of the reference's check order (TCG `Import.c`,
//! `ObjectLoad()`), since the specification gives no response code table for
//! TPM2_Import.

use crate::_common::{build_pw_cmd, rc_bare, rc_h, rc_of};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;

/// `TPM_CC_CreatePrimary`.
const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
/// `TPM_CC_Import`.
const CC_IMPORT: u32 = 0x0000_0156;
/// `TPM_RH_OWNER`.
const RH_OWNER: u32 = 0x4000_0001;

/// Prefixes `body` with its `u16` size (a `TPM2B`).
fn tpm2b(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// Creates an owner primary from the marshaled `TPMT_PUBLIC` `template` (empty
/// auth and sensitive data) and returns its handle.
fn create_primary(tpm: &mut Tpm, template: &[u8]) -> u32 {
    let mut params = tpm2b(&[0, 0, 0, 0]); // inSensitive: empty userAuth and data
    params.extend_from_slice(&tpm2b(template));
    params.extend_from_slice(&[0, 0]); // outsideInfo
    params.extend_from_slice(&[0, 0, 0, 0]); // creationPCR: empty
    let rsp = tpm.send_command(0, &build_pw_cmd(CC_CREATE_PRIMARY, &[RH_OWNER], 1, &params));
    assert_eq!(rc_of(&rsp), 0, "CreatePrimary: {rsp:02x?}");
    u32::from_be_bytes(rsp[10..14].try_into().unwrap())
}

/// Sends TPM2_Import under `parent` with an empty `encryptionKey`, the given
/// `objectPublic` (`TPMT_PUBLIC`), `duplicate` (`TPM2B_PRIVATE` buffer) and
/// `inSymSeed`, and `symmetricAlg = TPM_ALG_NULL`; returns the response code.
fn import(tpm: &mut Tpm, parent: u32, public: &[u8], duplicate: &[u8], seed: &[u8]) -> u32 {
    let mut params = tpm2b(&[]); // encryptionKey
    params.extend_from_slice(&tpm2b(public));
    params.extend_from_slice(&tpm2b(duplicate));
    params.extend_from_slice(&tpm2b(seed));
    params.extend_from_slice(&[0x00, 0x10]); // symmetricAlg: TPM_ALG_NULL
    rc_of(&tpm.send_command(0, &build_pw_cmd(CC_IMPORT, &[parent], 1, &params)))
}

/// A restricted-decrypt AES-128-CFB `TPM_ALG_SYMCIPHER` storage key (SHA-256,
/// fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth).
const SYMCIPHER_STORAGE_TEMPLATE: [u8; 18] = [
    0x00, 0x25, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x72, 0x00,
    0x00, // type, nameAlg, attrs, authPolicy
    0x00, 0x06, 0x00, 0x80, 0x00, 0x43, // AES-128-CFB
    0x00, 0x00, // unique: empty
];

/// A restricted-decrypt ECC NIST P-256 storage key (SHA-256, AES-128-CFB,
/// fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth).
const ECC_STORAGE_TEMPLATE: [u8; 26] = [
    0x00, 0x23, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x72, 0x00,
    0x00, // type, nameAlg, attrs, authPolicy
    0x00, 0x06, 0x00, 0x80, 0x00, 0x43, // AES-128-CFB
    0x00, 0x10, 0x00, 0x03, 0x00, 0x10, // scheme NULL, NIST P-256, kdf NULL
    0x00, 0x00, 0x00, 0x00, // unique: empty point
];

/// A keyed-hash `objectPublic` that may be imported (userWithAuth, noDA,
/// SHA-256, NULL scheme, 32-byte `unique`).
fn keyed_hash_public() -> Vec<u8> {
    let mut public = vec![
        0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x04, 0x40, 0x00, 0x00, 0x00, 0x10,
    ];
    public.extend_from_slice(&tpm2b(&[0x5a; 32]));
    public
}

/// TPM2_Import with an outer wrapper (`inSymSeed` not empty) under a
/// `TPM_ALG_SYMCIPHER` storage parent is `TPM_RC_TYPE` on `parentHandle`,
/// before the seed is used: TPM 2.0 Part 3, TPM2_Import, recovers the seed with
/// "The asymmetric parameters and private key of *parentHandle*", which a
/// symmetric key does not have (the reference's response code, as the
/// specification gives none).
#[test]
fn outer_wrapper_under_symmetric_parent_is_parent_type_error() {
    let mut tpm = Tpm::new();
    let parent = create_primary(&mut tpm, &SYMCIPHER_STORAGE_TEMPLATE);
    let rc = import(
        &mut tpm,
        parent,
        &keyed_hash_public(),
        &[0x00, 0x02, 0, 0],
        &[0x11; 16],
    );
    assert_eq!(rc, rc_h(TpmRc::TYPE, 1));
}

/// Under a *fixedTPM* parent, an imported ECC key whose public `x` coordinate
/// is larger than the curve's key size fails the public/private binding check
/// (`TPM_RC_BINDING`, no position) after the attribute checks, not a size check
/// of the public area: the object is validated as if loaded with its sensitive
/// area (TPM 2.0 Part 3, TPM2_Load: "If the parts of the object are not
/// properly linked, the TPM shall return `TPM_RC_BINDING`.").
#[test]
fn oversized_ecc_coordinate_is_binding_error() {
    let mut tpm = Tpm::new();
    let parent = create_primary(&mut tpm, &ECC_STORAGE_TEMPLATE);
    // objectPublic: a restricted-decrypt P-256 storage key (sensitiveDataOrigin,
    // userWithAuth, not fixedTPM/fixedParent) with a 33-byte x coordinate.
    let mut public = vec![
        0x00, 0x23, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x60, 0x00, 0x00, // type .. authPolicy
        0x00, 0x06, 0x00, 0x80, 0x00, 0x43, 0x00, 0x10, 0x00, 0x03, 0x00, 0x10,
    ];
    public.extend_from_slice(&tpm2b(&[0x42; 33]));
    public.extend_from_slice(&tpm2b(&[0x24; 32]));
    // duplicate without wrappers: TPM2B_SENSITIVE { ECC, empty authValue, 32-byte
    // seedValue, private key d = 1 }.
    let mut sensitive = vec![0x00, 0x23, 0x00, 0x00];
    sensitive.extend_from_slice(&tpm2b(&[0x33; 32]));
    let mut d = [0u8; 32];
    d[31] = 1;
    sensitive.extend_from_slice(&tpm2b(&d));
    let rc = import(&mut tpm, parent, &public, &tpm2b(&sensitive), &[]);
    assert_eq!(rc, rc_bare(TpmRc::BINDING));
}

/// An imported ECC private key with leading zero octets that make it longer
/// than the curve's key size is still a valid key when its value is below the
/// group order: the key size is that of the number (TPM 2.0 Part 3, TPM2_Load:
/// "the size of the key in the sensitive area shall be consistent with the key
/// size indicated in the public area or the TPM shall return
/// `TPM_RC_KEY_SIZE`"), so the import fails only at the binding check
/// (`TPM_RC_BINDING`) for a public point that is not [d]G.
#[test]
fn zero_padded_ecc_private_key_reaches_binding_check() {
    let mut tpm = Tpm::new();
    let parent = create_primary(&mut tpm, &ECC_STORAGE_TEMPLATE);
    let mut public = vec![
        0x00, 0x23, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x60, 0x00, 0x00, // type .. authPolicy
        0x00, 0x06, 0x00, 0x80, 0x00, 0x43, 0x00, 0x10, 0x00, 0x03, 0x00, 0x10,
    ];
    public.extend_from_slice(&tpm2b(&[0x42; 32]));
    public.extend_from_slice(&tpm2b(&[0x24; 32]));
    // Private key d = 1 encoded in 36 octets (P-256 keys are 32 octets).
    let mut sensitive = vec![0x00, 0x23, 0x00, 0x00];
    sensitive.extend_from_slice(&tpm2b(&[0x33; 32]));
    let mut d = [0u8; 36];
    d[35] = 1;
    sensitive.extend_from_slice(&tpm2b(&d));
    let rc = import(&mut tpm, parent, &public, &tpm2b(&sensitive), &[]);
    assert_eq!(rc, rc_bare(TpmRc::BINDING));
}
