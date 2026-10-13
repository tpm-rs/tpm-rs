//! Response HMACs: the client detects tampered response attributes, nonces and HMACs; error
//! responses carry no HMAC.

use crate::_common::{
    ResponseCorruption, create_primary_key, execute_with_hmac_sessions,
    execute_with_hmac_sessions_corrupt_response, sign_cmd_and_handles, start_auth_session,
};
use tpm2::commands::ReadPublic;
use tpm2::{Handle, TpmSe, TpmiAlgHash};
use tpm2_simulator::create_simulator;

/// The client detects corrupted response session attributes through the response HMAC (should_panic).
#[test]
#[should_panic(expected = "Response HMAC verification failed")]
fn corrupted_response_attributes_detected() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let auth_cmd = sign_cmd_and_handles(object_handle);
    execute_with_hmac_sessions_corrupt_response(
        &mut sim,
        &auth_cmd,
        &[],
        &mut [session],
        &[&[]],
        ResponseCorruption::Attributes,
    )
    .unwrap();
}

/// The client detects a corrupted response HMAC (should_panic).
#[test]
#[should_panic(expected = "Response HMAC verification failed")]
fn corrupted_response_hmac_detected() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let auth_cmd = sign_cmd_and_handles(object_handle);
    execute_with_hmac_sessions_corrupt_response(
        &mut sim,
        &auth_cmd,
        &[],
        &mut [session],
        &[&[]],
        ResponseCorruption::Hmac,
    )
    .unwrap();
}

/// The client detects a corrupted response TPM nonce through the response HMAC (should_panic).
#[test]
#[should_panic(expected = "Response HMAC verification failed")]
fn corrupted_response_nonce_tpm_detected() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let auth_cmd = sign_cmd_and_handles(object_handle);
    execute_with_hmac_sessions_corrupt_response(
        &mut sim,
        &auth_cmd,
        &[],
        &mut [session],
        &[&[]],
        ResponseCorruption::NonceTpm,
    )
    .unwrap();
}

/// ReadPublic of RH_NULL with an HMAC session fails with TPM_RC_VALUE + H1 (error responses carry no HMAC).
#[test]
fn null_object_handle_error_omits_response_hmac() {
    let mut sim = create_simulator!();
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let read_cmd = ReadPublic {
        object_handle: Handle::RH_NULL,
    }; // invalid handle
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        &[&Handle::RH_NULL.0.to_be_bytes()],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // C TPMI_DH_OBJECT_Unmarshal rejects TPM_RH_NULL with TPM_RC_VALUE, and
    // ParseHandleBuffer adds H1: VALUE+H1 (0x184).
    assert_eq!(err, 0x184);
}

/// The response HMAC of an HMAC-authorized TPM2_Sign verifies on the client.
#[test]
fn response_hmac_verifies_for_sign() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let auth_cmd = sign_cmd_and_handles(object_handle);
    let _ = execute_with_hmac_sessions(&mut sim, &auth_cmd, &[], &mut [session], &[&[]]).unwrap();
}

/// The response HMAC of a SHA-384 HMAC session verifies.
#[test]
fn sha384_session_response_hmac_verifies() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha384,
    )
    .unwrap();
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let auth_cmd = sign_cmd_and_handles(object_handle);
    let _ = execute_with_hmac_sessions(&mut sim, &auth_cmd, &[], &mut [session], &[&[]]).unwrap();
}
