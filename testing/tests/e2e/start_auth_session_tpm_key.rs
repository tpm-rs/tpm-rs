//! TPM2_StartAuthSession: `tpmKey` and `bind` checks that depend on what the
//! handle references (a sequence object instead of an asymmetric key or an
//! ordinary object), and their order against the parameter unmarshaling.

use crate::_common::{build, rc_h, rc_of, rc_p};
use testing::tpm::Tpm;
use tpm2::Handle;
use tpm2::errors::TpmRc;

/// `TPM_CC_StartAuthSession`.
const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;

/// `TPM2_HashSequenceStart(auth = empty, hashAlg = SHA256)`.
const HASH_SEQUENCE_START: [u8; 14] = [0x80, 0x01, 0, 0, 0, 14, 0, 0, 0x01, 0x86, 0, 0, 0x00, 0x0b];

/// Starts a hash sequence and returns its (sequence object) handle.
fn hash_sequence(tpm: &mut Tpm) -> u32 {
    let rsp = tpm.send_command(0, &HASH_SEQUENCE_START);
    assert_eq!(rc_of(&rsp), 0, "HashSequenceStart: {rsp:02x?}");
    u32::from_be_bytes(rsp[10..14].try_into().unwrap())
}

/// A raw `TPM2_StartAuthSession(tpm_key, TPM_RH_NULL)` of an HMAC session with
/// a 16-byte `nonceCaller`, a 1-byte `encryptedSalt`, the given `symmetric`
/// algorithm (with no further fields, so only `TPM_ALG_NULL` is complete) and
/// `authHash` SHA256; its response code.
fn start_auth_session_rc(tpm: &mut Tpm, tpm_key: u32, symmetric_alg: u16) -> u32 {
    let mut params = vec![0, 16];
    params.extend_from_slice(&[0x33; 16]);
    params.extend_from_slice(&[0, 1, 0x44]);
    params.push(0x00); // TPM_SE_HMAC
    params.extend_from_slice(&symmetric_alg.to_be_bytes());
    params.extend_from_slice(&[0x00, 0x0b]); // TPM_ALG_SHA256
    let cmd = build(
        0x8001,
        TPM_CC_START_AUTH_SESSION,
        &[tpm_key, Handle::RH_NULL.0],
        None,
        &params,
    );
    rc_of(&tpm.send_command(0, &cmd))
}

/// A sequence object is a loaded object but not an asymmetric key: as
/// `tpmKey` it is rejected with `TPM_RC_KEY` (TPM 2.0 Part 3,
/// TPM2_StartAuthSession: "The TPM shall return `TPM_RC_KEY` if *tpmKey* does
/// not reference an asymmetric key."), not as an unloaded handle.
#[test]
fn sequence_object_tpm_key_is_not_an_asymmetric_key() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    assert_eq!(
        start_auth_session_rc(&mut tpm, sequence, 0x0010),
        rc_h(TpmRc::KEY, 1)
    );
}

/// With a sequence object as `tpmKey`, an invalid `symmetric` algorithm is
/// reported first: the parameters are unmarshaled before the command checks
/// what `tpmKey` references (TPM 2.0 Part 3, "Parameter Unmarshaling":
/// "When an error is encountered while unmarshaling a command parameter, an
/// error response code is returned, and no command processing occurs.").
#[test]
fn symmetric_unmarshal_error_precedes_tpm_key_check() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    assert_eq!(
        start_auth_session_rc(&mut tpm, sequence, 0x0000),
        rc_p(TpmRc::SYMMETRIC, 4)
    );
}

/// A sequence object as `bind` is a loaded transient object, so the handle
/// area is valid and an oversized `encryptedSalt` is reported as a parameter
/// error (TPM 2.0 Part 3, "Handle Area Validation": "If the handle references
/// a transient object, the handle shall reference a loaded object
/// (`TPM_RC_REFERENCE_H0` + N ...)"; Part 1, "transient object": "object or
/// sequence object that can be explicitly loaded and unloaded from TPM memory
/// by the TRM"; Part 2, `TPM2B_ENCRYPTED_SECRET`:
/// `secret[size]{:sizeof(TPMU_ENCRYPTED_SECRET)}`).
#[test]
fn sequence_object_bind_is_loaded() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    let mut params = vec![0, 16];
    params.extend_from_slice(&[0x33; 16]);
    // encryptedSalt: 257 bytes, one more than sizeof(TPMU_ENCRYPTED_SECRET).
    params.extend_from_slice(&257u16.to_be_bytes());
    params.extend_from_slice(&[0x44; 257]);
    params.push(0x00); // TPM_SE_HMAC
    params.extend_from_slice(&[0x00, 0x10]); // TPM_ALG_NULL
    params.extend_from_slice(&[0x00, 0x0b]); // TPM_ALG_SHA256
    let cmd = build(
        0x8001,
        TPM_CC_START_AUTH_SESSION,
        &[Handle::RH_NULL.0, sequence],
        None,
        &params,
    );
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), rc_p(TpmRc::SIZE, 2));
}

/// A sequence object can be the `bind` entity of a session: it is a loaded
/// object with an *authValue* (the `auth` of its `TPM2_HashSequenceStart`),
/// so TPM2_StartAuthSession succeeds (TPM 2.0 Part 2, TPMI_DH_ENTITY: "The
/// TPMI_DH_ENTITY interface type is TPM-defined values that are used to
/// indicate that the handle refers to an *authValue*.").
#[test]
fn sequence_object_can_be_bind_entity() {
    let mut tpm = Tpm::new();
    let sequence = hash_sequence(&mut tpm);
    let mut params = vec![0, 16];
    params.extend_from_slice(&[0x33; 16]);
    params.extend_from_slice(&[0, 0]); // encryptedSalt: empty
    params.push(0x00); // TPM_SE_HMAC
    params.extend_from_slice(&[0x00, 0x10]); // TPM_ALG_NULL
    params.extend_from_slice(&[0x00, 0x0b]); // TPM_ALG_SHA256
    let cmd = build(
        0x8001,
        TPM_CC_START_AUTH_SESSION,
        &[Handle::RH_NULL.0, sequence],
        None,
        &params,
    );
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), 0);
}
