//! TPM2_StartAuthSession: starting HMAC/policy/trial sessions with bind entities and symmetric
//! definitions.

use crate::_common::{
    create_owner_primary, raw_rc, rsa_storage_template, start_auth_session,
    start_auth_session_request,
};
use testing::tpm::Tpm;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmSe, TpmiAlgHash};

/// Regression test for CPCTPM_TC2_4_13_01_03:
/// TPM2_StartAuthSession with symmetric = TPMT_SYM_DEF(AES, 0, NULL) and wrong salt sizes
/// must return TPM_RC_VALUE (Pos4, 0x0403 or Pos2, 0x0203).
#[test]
fn invalid_symmetric_and_salt_size_rejected() {
    let mut sim = Tpm::new();

    // Create RSA primary key
    let rsa_key_handle = create_owner_primary(&mut sim, rsa_storage_template());

    // STEP1: StartAuthSession with salt=16 bytes, symmetric = TPMT_SYM_DEF(AES, 0, NULL) -> TPM_RC_VALUE
    let req1 = start_auth_session_request(rsa_key_handle, &[2u8; 16]);
    let rc1 = raw_rc(&mut sim, &req1);
    assert_eq!(
        rc1,
        TpmRc::VALUE.with(Position::parameter(4)).get(),
        "Expected TPM_RC_VALUE (0x0403) for StartAuthSession with invalid symmetric parameter"
    );

    // STEP2: StartAuthSession with salt=128 bytes, symmetric = TPMT_SYM_DEF(AES, 0, NULL) -> TPM_RC_VALUE
    let req2 = start_auth_session_request(rsa_key_handle, &[2u8; 128]);
    let rc2 = raw_rc(&mut sim, &req2);
    assert_eq!(
        rc2,
        TpmRc::VALUE.with(Position::parameter(4)).get(),
        "Expected TPM_RC_VALUE (0x0403) for StartAuthSession with invalid symmetric parameter"
    );
}

/// Two HMAC sessions receive different TPM nonces.
#[test]
fn nonce_tpm_differs_between_sessions() {
    let mut sim = Tpm::new();
    let sess1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let sess2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    assert_ne!(sess1.nonce_tpm.get_buffer(), sess2.nonce_tpm.get_buffer());
}

/// An HMAC session with SHA-1 authHash starts.
#[test]
fn sha1_session_starts() {
    let mut sim = Tpm::new();
    let _sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha1,
    )
    .unwrap();
}

/// An HMAC session with SHA-384 authHash starts.
#[test]
fn sha384_session_starts() {
    let mut sim = Tpm::new();
    let _sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha384,
    )
    .unwrap();
}

/// An unbound, unsalted HMAC session has an empty session key.
#[test]
fn unbound_unsalted_session_key_is_empty() {
    let mut sim = Tpm::new();
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    assert!(sess.session_key.is_empty());
}
