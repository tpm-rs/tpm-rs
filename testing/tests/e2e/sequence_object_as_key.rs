//! Sequence objects (hash and HMAC sequences) passed where a key or a
//! certified object is expected. A sequence object is a loaded object of type
//! `TPM_ALG_NULL` with only the *noDA* attribute (the reference keeps it in an
//! object slot, `AllocateSequenceSlot()`), so each command rejects it with the
//! response code of the check it fails, in the command's check order.

use crate::_common::{build, build_pw_cmd, rc_h, rc_of, rc_p};
use testing::tpm::Tpm;
use tpm2::Handle;
use tpm2::errors::TpmRc;

/// `TPM2_HashSequenceStart(auth = empty, hashAlg = SHA256)`.
const HASH_SEQUENCE_START: [u8; 14] = [0x80, 0x01, 0, 0, 0, 14, 0, 0, 0x01, 0x86, 0, 0, 0x00, 0x0b];

/// Starts a hash sequence and returns its handle.
fn hash_sequence(tpm: &mut Tpm) -> u32 {
    let rsp = tpm.send_command(0, &HASH_SEQUENCE_START);
    assert_eq!(rc_of(&rsp), 0, "HashSequenceStart: {rsp:02x?}");
    u32::from_be_bytes(rsp[10..14].try_into().unwrap())
}

/// Prefixes `body` with its `u16` size (a `TPM2B`).
fn tpm2b(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// An ECDSA-SHA256 `TPMT_SIGNATURE` with one-byte `r` and `s`.
fn ecdsa_signature() -> Vec<u8> {
    let mut sig = vec![0x00, 0x18, 0x00, 0x0b];
    sig.extend_from_slice(&tpm2b(&[1]));
    sig.extend_from_slice(&tpm2b(&[1]));
    sig
}

/// TPM2_MAC_Start with a sequence object is `TPM_RC_TYPE` on `handle` (TPM 2.0
/// Part 3, TPM2_MAC_Start: "If the key type is not `TPM_ALG_KEYEDHASH` or
/// `TPM_ALG_SYMCIPHER` then the TPM shall return `TPM_RC_TYPE`.").
#[test]
fn mac_start_with_sequence_object_is_type_error() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    let mut params = tpm2b(&[]);
    params.extend_from_slice(&[0x00, 0x0b]);
    let cmd = build_pw_cmd(0x0000_015B, &[sequence], 1, &params);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_h(TpmRc::TYPE, 1));
}

/// TPM2_MAC with a sequence object is `TPM_RC_TYPE` on `handle` (TPM 2.0 Part
/// 3, TPM2_MAC: "If the key type is neither `TPM_ALG_KEYEDHASH` nor
/// `TPM_ALG_SYMCIPHER` then the TPM shall return `TPM_RC_TYPE`.").
#[test]
fn mac_with_sequence_object_is_type_error() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    let mut params = tpm2b(&[0x61]);
    params.extend_from_slice(&[0x00, 0x0b]);
    let cmd = build_pw_cmd(0x0000_0155, &[sequence], 1, &params);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_h(TpmRc::TYPE, 1));
}

/// TPM2_VerifySignature with a sequence object is `TPM_RC_ATTRIBUTES` on
/// `keyHandle`: the object is not a signing key.
#[test]
fn verify_signature_with_sequence_object_is_attributes_error() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    let mut params = tpm2b(&[0x5a; 32]);
    params.extend_from_slice(&ecdsa_signature());
    let cmd = build(0x8001, 0x0000_0177, &[sequence], None, &params);
    assert_eq!(
        rc_of(&tpm.send_command(0, &cmd)),
        rc_h(TpmRc::ATTRIBUTES, 1)
    );
}

/// TPM2_Certify checks `signHandle` before it uses the certified object: a
/// sequence object as `signHandle` is not a signing key (`TPM_RC_KEY` on
/// handle 2), even when `objectHandle` is a sequence object too.
#[test]
fn certify_checks_sign_handle_first() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    let mut params = tpm2b(&[]); // qualifyingData
    params.extend_from_slice(&[0x00, 0x10]); // inScheme: TPM_ALG_NULL
    let cmd = build_pw_cmd(0x0000_0148, &[sequence, sequence], 2, &params);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_h(TpmRc::KEY, 2));
}

/// The parameters of TPM2_CertifyCreation after the handles: `qualifyingData`
/// empty, a 32-byte `creationHash`, `inScheme` `TPM_ALG_NULL` and a
/// `TPMT_TK_CREATION` for the owner hierarchy with a 32-byte digest.
fn certify_creation_params() -> Vec<u8> {
    let mut params = tpm2b(&[]);
    params.extend_from_slice(&tpm2b(&[0x11; 32]));
    params.extend_from_slice(&[0x00, 0x10]);
    params.extend_from_slice(&[0x80, 0x21]);
    params.extend_from_slice(&Handle::RH_OWNER.0.to_be_bytes());
    params.extend_from_slice(&tpm2b(&[0x22; 32]));
    params
}

/// TPM2_CertifyCreation rejects a sequence object as `objectHandle` before it
/// checks `signHandle`: `TPM_RC_TYPE` on handle 2, even when `signHandle` is a
/// sequence object too. TPM 2.0 Part 3, TPM2_CertifyCreation: "This command is
/// used to prove the association between an object and its creation data.", and
/// a sequence object has no creation data; the specification gives no response
/// code, so tpm-rs follows `mstpm20` version 185 ("Cannot certify creation of a
/// sequence object"; the other references are patched alike,
/// `bug-fix-certify-creation-sequence-object.patch`).
#[test]
fn certify_creation_checks_sequence_object_before_sign_handle() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    let cmd = build_pw_cmd(
        0x0000_014A,
        &[sequence, sequence],
        1,
        &certify_creation_params(),
    );
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_h(TpmRc::TYPE, 2));
}

/// TPM2_CertifyCreation checks `signHandle` before it uses a certified object
/// that is not a sequence object: a sequence object as `signHandle` is
/// `TPM_RC_KEY` on handle 1 (TPM 2.0 Part 3, TPM2_CertifyCreation:
/// "`TPM_RC_KEY` | key referenced by *signHandle* is not a signing key").
#[test]
fn certify_creation_checks_sign_handle_first() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    let (object, _) = crate::_common::try_create_owner_primary(
        &mut tpm,
        crate::_common::get_ecc_signing_key_template(),
    )
    .expect("signing key");
    let cmd = build_pw_cmd(
        0x0000_014A,
        &[sequence, object.0],
        1,
        &certify_creation_params(),
    );
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_h(TpmRc::KEY, 1));
}

/// TPM2_CertifyCreation of a sequence object (unsigned) is `TPM_RC_TYPE` on
/// `objectHandle`: a sequence object was not created with creation data (TPM
/// 2.0 Part 3, TPM2_CertifyCreation: "This command is used to prove the
/// association between an object and its creation data."), as in `mstpm20`
/// version 185.
#[test]
fn certify_creation_of_sequence_object_is_type_error() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    let cmd = build_pw_cmd(
        0x0000_014A,
        &[Handle::RH_NULL.0, sequence],
        1,
        &certify_creation_params(),
    );
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_h(TpmRc::TYPE, 2));
}

/// TPM2_PolicySigned with a sequence object as `authObject` checks the policy
/// parameters and then fails to validate `auth` with it (`TPM_RC_SCHEME` on
/// `auth`).
#[test]
fn policy_signed_with_sequence_object_is_scheme_error() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    // A policy session (TPM_SE_POLICY, no salt, no bind, SHA256).
    let mut start = vec![0, 16];
    start.extend_from_slice(&[0x33; 16]);
    start.extend_from_slice(&[0, 0, 0x01, 0x00, 0x10, 0x00, 0x0b]);
    let start = build(
        0x8001,
        0x0000_0176,
        &[Handle::RH_NULL.0, Handle::RH_NULL.0],
        None,
        &start,
    );
    let rsp = tpm.send_command(0, &start);
    assert_eq!(rc_of(&rsp), 0, "StartAuthSession: {rsp:02x?}");
    let session = u32::from_be_bytes(rsp[10..14].try_into().unwrap());
    let mut params = tpm2b(&[]); // nonceTPM
    params.extend_from_slice(&tpm2b(&[])); // cpHashA
    params.extend_from_slice(&tpm2b(&[])); // policyRef
    params.extend_from_slice(&0i32.to_be_bytes()); // expiration
    params.extend_from_slice(&ecdsa_signature());
    let cmd = build(0x8001, 0x0000_0160, &[sequence, session], None, &params);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_p(TpmRc::SCHEME, 5));
}

/// TPM2_Certify of a sequence object (with a valid signer key) fails with
/// `TPM_RC_TYPE` on `objectHandle` after the `signHandle` and scheme checks:
/// TPM 2.0 Part 3, TPM2_Certify: "The object may be any object that is loaded
/// with `TPM2_Load()` or `TPM2_CreatePrimary()`.", and a sequence object is
/// neither. The specification gives no response code; `TPM_RC_TYPE` is the
/// one of `mstpm20` version 185 (the other references are patched alike,
/// `bug-fix-certify-sequence-object.patch`).
#[test]
fn certify_of_sequence_object_is_type_error() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    let (signer, _) = crate::_common::try_create_owner_primary(
        &mut tpm,
        crate::_common::get_ecc_signing_key_template(),
    )
    .expect("signing key");
    let mut params = tpm2b(&[]); // qualifyingData
    // inScheme: TPM_ALG_ECDSA with SHA-256 (the signer's own scheme is NULL).
    params.extend_from_slice(&[0x00, 0x18, 0x00, 0x0B]);
    let cmd = build_pw_cmd(0x0000_0148, &[sequence, signer.0], 2, &params);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_h(TpmRc::TYPE, 1));
}

/// TPM2_PolicySecret authorized with a hash sequence object's authValue succeeds: a sequence
/// object is an entity with an authValue (TPM 2.0 Part 3, TPM2_PolicySecret: "*authHandle* |
/// handle for an entity providing the authorization"), and it is in the NULL hierarchy (TCG
/// reference `AllocateSequenceSlot()`: "A sequence object is considered to be in the NULL
/// hierarchy"), which the policy ticket's hierarchy check uses. Found by differential fuzzing.
#[test]
fn policy_secret_with_sequence_object_is_in_null_hierarchy() {
    let response_code = |rsp: &[u8]| u32::from_be_bytes(rsp[6..10].try_into().unwrap());
    let mut tpm = testing::tpm::Tpm::with_seed(testing::seed::ReferenceSeed {
        pid: 4242,
        realtime_ms: 1000000,
    });

    // Round 0: TPM2_HashSequenceStart.
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x86, 0x00, 0x00, 0x00, 0x0b,
        ],
    );
    assert_eq!(response_code(&rsp), 0x0);

    // Round 1: TPM2_NV_UndefineSpaceSpecial.
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x02, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x01, 0x1f, 0x40, 0x00, 0x01, 0x10,
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80, 0x00,
            0x00, 0x00,
        ],
    );
    assert_eq!(response_code(&rsp), 0x184);

    // Round 2: TPM2_StartAuthSession.
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x01, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07,
            0x40, 0x00, 0x00, 0x07, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00,
            0x0b,
        ],
    );
    assert_eq!(response_code(&rsp), 0x0);

    // Round 3: TPM2_PolicySecret.
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x02, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x01, 0x51, 0x80, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x74,
        ],
    );
    assert_eq!(response_code(&rsp), 0x0);
}
