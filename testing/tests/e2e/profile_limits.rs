//! Unmarshal limits that depend on the TPM's profile rather than on every algorithm `tpm2` can
//! represent: the capacities of `TPM2B_TEMPLATE` (`sizeof(TPMT_PUBLIC)`, unpadded) and
//! `TPM2B_ECC_PARAMETER` (`MAX_ECC_KEY_BYTES`), `TPM2B_DIGEST` (the largest implemented digest),
//! and the `HASH_COUNT` bound of `TPML_PCR_SELECTION`. A larger value is `TPM_RC_SIZE` at its parameter, before any later
//! parameter is read.

use crate::_common::{PW_SESSION, build, rc_of, rc_p};
use testing::tpm::Tpm;
use tpm2::Handle;
use tpm2::errors::TpmRc;

/// `TPM_CC_CreatePrimary`.
const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
/// `TPM_CC_LoadExternal`.
const TPM_CC_LOAD_EXTERNAL: u32 = 0x0000_0167;
/// `TPM_CC_CreateLoaded`.
const TPM_CC_CREATE_LOADED: u32 = 0x0000_0191;

/// An empty `TPM2B_SENSITIVE_CREATE` (empty `userAuth` and `data`).
const EMPTY_SENSITIVE_CREATE: [u8; 6] = [0, 4, 0, 0, 0, 0];

/// An ECC NIST P-256 ECDSA/SHA-256 signing key template (`TPMT_PUBLIC`) with an empty `unique`.
const ECC_SIGNING_TEMPLATE: [u8; 24] = [
    0x00, 0x23, // type: TPM_ALG_ECC
    0x00, 0x0B, // nameAlg: TPM_ALG_SHA256
    0x00, 0x04, 0x00,
    0x72, // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign
    0x00, 0x00, // authPolicy
    0x00, 0x10, // symmetric: TPM_ALG_NULL
    0x00, 0x18, 0x00, 0x0B, // scheme: TPM_ALG_ECDSA, SHA-256
    0x00, 0x03, // curveID: TPM_ECC_NIST_P256
    0x00, 0x10, // kdf: TPM_ALG_NULL
    0x00, 0x00, 0x00, 0x00, // unique: empty x and y
];

/// The response code of `TPM2_CreateLoaded(TPM_RH_OWNER)` with an empty `inSensitive` and an
/// `inPublic` (`TPM2B_TEMPLATE`) of `len` zero bytes.
fn create_loaded_template_rc(tpm: &mut Tpm, len: u16) -> u32 {
    let mut params = EMPTY_SENSITIVE_CREATE.to_vec();
    params.extend_from_slice(&len.to_be_bytes());
    params.resize(params.len() + usize::from(len), 0);
    let cmd = build(
        0x8002,
        TPM_CC_CREATE_LOADED,
        &[Handle::RH_OWNER.0],
        Some(&PW_SESSION),
        &params,
    );
    rc_of(&tpm.send_command(0, &cmd))
}

/// `TPM2B_TEMPLATE` holds at most `sizeof(TPMT_PUBLIC)`, the unpadded size (350 bytes with RSA
/// 2048 and ECDAA): TPM 2.0 Part 2, Table "Definition of TPM2B_TEMPLATE Structure":
/// "buffer\[size\]{:sizeof(TPMT_PUBLIC)}", and Part 2, "Data Alignment": "When used in a table
/// to indicate a maximum size, the sizeof() function returns the octet-aligned size of the
/// structure, with no padding." The padded C size (356) is too large.
#[test]
fn template_larger_than_unpadded_tpmt_public_rejected() {
    let mut tpm = Tpm::new();
    for len in [351, 356, 357, 0x0400] {
        assert_eq!(
            create_loaded_template_rc(&mut tpm, len),
            rc_p(TpmRc::SIZE, 2),
            "template of {len} bytes"
        );
    }
    assert_ne!(
        create_loaded_template_rc(&mut tpm, 350),
        rc_p(TpmRc::SIZE, 2)
    );
}

/// A `TPM2B_ECC_PARAMETER` holds at most `MAX_ECC_KEY_BYTES` (66, NIST P-521): TPM 2.0 Part 2,
/// Table "Definition of (ECC) TPM2B_ECC_PARAMETER Structure": "buffer\[size\]
/// {:MAX_ECC_KEY_BYTES}". A 67-byte `unique.x` of a `TPM2_LoadExternal` public area is
/// `TPM_RC_SIZE` at `inPublic`.
#[test]
fn ecc_parameter_larger_than_max_ecc_key_bytes_rejected() {
    let mut tpm = Tpm::new();
    for (x_len, rejected) in [(66u16, false), (67, true), (80, true)] {
        let mut public = ECC_SIGNING_TEMPLATE[..20].to_vec();
        public.extend_from_slice(&x_len.to_be_bytes());
        public.resize(public.len() + usize::from(x_len), 0x11);
        public.extend_from_slice(&[0, 0]); // y
        let mut params = vec![0, 0]; // inPrivate: empty
        params.extend_from_slice(&(public.len() as u16).to_be_bytes());
        params.extend_from_slice(&public);
        params.extend_from_slice(&Handle::RH_NULL.0.to_be_bytes());
        let cmd = build(0x8001, TPM_CC_LOAD_EXTERNAL, &[], None, &params);
        let rc = rc_of(&tpm.send_command(0, &cmd));
        assert_eq!(
            rc == rc_p(TpmRc::SIZE, 2),
            rejected,
            "x of {x_len} bytes: {rc:#x}"
        );
    }
}

/// A `TPML_PCR_SELECTION` lists at most `HASH_COUNT` banks, the number of implemented hash
/// algorithms (4: SHA-1, SHA-256, SHA-384, SHA-512): TPM 2.0 Part 2, Table "Definition of
/// TPML_PCR_SELECTION Structure": "pcrSelections\[count\]{:HASH_COUNT}" and "#TPM_RC_SIZE |
/// response code when *count* is greater than the possible number of banks". A
/// `TPM2_CreatePrimary` `creationPCR` with 5 (complete) or 8 (truncated) selections is
/// `TPM_RC_SIZE` at `creationPCR`.
#[test]
fn pcr_selection_with_more_banks_than_hash_algorithms_rejected() {
    let mut tpm = Tpm::new();
    for (count, present) in [(5u32, 5), (8, 1)] {
        let mut params = EMPTY_SENSITIVE_CREATE.to_vec();
        params.extend_from_slice(&(ECC_SIGNING_TEMPLATE.len() as u16).to_be_bytes());
        params.extend_from_slice(&ECC_SIGNING_TEMPLATE);
        params.extend_from_slice(&[0, 0]); // outsideInfo
        params.extend_from_slice(&count.to_be_bytes());
        for _ in 0..present {
            params.extend_from_slice(&[0x00, 0x0B, 3, 0, 0, 0]);
        }
        let cmd = build(
            0x8002,
            TPM_CC_CREATE_PRIMARY,
            &[Handle::RH_OWNER.0],
            Some(&PW_SESSION),
            &params,
        );
        assert_eq!(
            rc_of(&tpm.send_command(0, &cmd)),
            rc_p(TpmRc::SIZE, 4),
            "count {count}"
        );
    }
}

/// The largest digest of this TPM's profile (SHA-512), in bytes.
const DIGEST_CAP: u16 = 64;

/// `TPM_CC_HashSequenceStart`.
const TPM_CC_HASH_SEQUENCE_START: u32 = 0x0000_0186;
/// `TPM_CC_PolicyTemplate`.
const TPM_CC_POLICY_TEMPLATE: u32 = 0x0000_0190;

/// A `TPM2B_DIGEST` (and `TPM2B_AUTH`) holds at most the largest digest of the TPM's hashes,
/// [`DIGEST_CAP`]: TPM 2.0 Part 2, Table "Definition of TPM2B_DIGEST Structure":
/// "buffer\[size\]{:sizeof(TPMU_HA)}" and "#TPM_RC_SIZE". A complete buffer of one byte more is
/// `TPM_RC_SIZE` at its parameter, before its bytes and the later parameters are read: the
/// `auth` of `TPM2_HashSequenceStart`, the `templateHash` of `TPM2_PolicyTemplate` and the
/// `authValue` in the `inPrivate` of `TPM2_LoadExternal`. Found by differential fuzzing.
#[test]
fn digest_larger_than_largest_hash_rejected() {
    let mut tpm = Tpm::new();
    let too_long = vec![0x42u8; usize::from(DIGEST_CAP) + 1];
    let sized = |bytes: &[u8]| {
        let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    };

    // TPM2_HashSequenceStart(auth, hashAlg = SHA-256).
    let mut params = sized(&too_long);
    params.extend_from_slice(&[0x00, 0x0B]);
    let cmd = build(0x8001, TPM_CC_HASH_SEQUENCE_START, &[], None, &params);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_p(TpmRc::SIZE, 1));

    // TPM2_PolicyTemplate(policySession, templateHash).
    let session = crate::_common::start_session_of_type(&mut tpm, tpm2::TpmSe::Policy);
    let cmd = build(
        0x8001,
        TPM_CC_POLICY_TEMPLATE,
        &[session.session_handle.0],
        None,
        &sized(&too_long),
    );
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_p(TpmRc::SIZE, 1));

    // TPM2_LoadExternal(inPrivate = {TPM_ALG_KEYEDHASH, authValue, seedValue, bits}, ...).
    let mut sensitive = vec![0x00, 0x08];
    sensitive.extend_from_slice(&sized(&too_long));
    sensitive.extend_from_slice(&sized(&[0x11; 32]));
    sensitive.extend_from_slice(&sized(&[0x22; 16]));
    let mut params = sized(&sensitive);
    params.extend_from_slice(&sized(&[
        0x00, 0x08, 0x00, 0x0B, 0, 0, 0, 0x40, 0, 0, 0, 0x10, 0, 0,
    ]));
    params.extend_from_slice(&Handle::RH_NULL.0.to_be_bytes());
    let cmd = build(0x8001, TPM_CC_LOAD_EXTERNAL, &[], None, &params);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_p(TpmRc::SIZE, 1));
}
