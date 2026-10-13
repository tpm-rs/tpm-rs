//! TPM2_GetSessionAuditDigest: handle, authorization, signer and privacy-admin validation.

use crate::_common::Connection;
use crate::_common::{
    CmdHeader, RespHeader, create_non_signing_key_rsa, create_signing_key_ecc,
    execute_with_hmac_sessions_status, execute_with_password_sessions,
    execute_with_password_sessions_status, flush_context, marshal_to_slice, start_auth_session,
    start_session,
};
use testing::tpm::Tpm;
use tpm2::commands::{GetCapability, GetSessionAuditDigest};
use tpm2::{
    Handle, Marshal, Tpm2bAuth, Tpm2bData, Tpm2bNonce, TpmCap, TpmCc, TpmPt, TpmSe, TpmaSession,
    TpmiAlgHash, TpmiStCommandTag, TpmsAuthCommand, TpmtSigScheme, Unmarshal,
};

/// TPM2_GetSessionAuditDigest with a transient privacyAdminHandle fails with TPM_RC_VALUE + H1
#[test]
fn get_session_audit_digest_rejects_invalid_privacy_admin() {
    let mut sim = Tpm::new();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    // Start a session to audit
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

    let get_audit_cmd = GetSessionAuditDigest {
        // Use invalid privacy admin handle (e.g. transient 0x80000000)
        privacy_admin_handle: Handle(0x80000000),
        sign_handle: ak_handle,
        session_handle: sess.session_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let resp = execute_with_password_sessions_status(&mut sim, &get_audit_cmd, 2, &[]);
    // SPEC EXPECTS: TPM_RC_VALUE for handle 1 (0x184)
    assert_eq!(resp.err(), Some(0x184));

    flush_context(&mut sim, ak_handle).unwrap();
}

/// TPM2_GetSessionAuditDigest with one instead of two auth sessions fails with TPM_RC_AUTH_MISSING
#[test]
fn get_session_audit_digest_rejects_missing_authorization() {
    let mut sim = Tpm::new();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

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

    let get_audit_cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: ak_handle,
        session_handle: sess.session_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Provide only 1 authorization session instead of 2
    let resp = execute_with_password_sessions_status(&mut sim, &get_audit_cmd, 1, &[]);
    // Expect TPM_RC_AUTH_MISSING (0x125)
    assert_eq!(resp.err(), Some(0x125));

    flush_context(&mut sim, ak_handle).unwrap();
}

/// TPM2_GetSessionAuditDigest with a decrypt-only RSA signHandle fails
#[test]
fn get_session_audit_digest_rejects_non_signing_key() {
    let mut sim = Tpm::new();
    // Create a key that is NOT a signing key (e.g. DECRYPT only)
    let (non_sign_handle, _) = create_non_signing_key_rsa(&mut sim);

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

    let get_audit_cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: non_sign_handle,
        session_handle: sess.session_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let resp = execute_with_password_sessions_status(&mut sim, &get_audit_cmd, 2, &[]);
    assert!(resp.is_err());

    flush_context(&mut sim, non_sign_handle).unwrap();
}

/// Raw TPM2_GetSessionAuditDigest with 67-byte qualifyingData fails with TPM_RC_SIZE + P1
#[test]
fn get_session_audit_digest_rejects_oversized_qualifying_data() {
    let mut sim = Tpm::new();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

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

    // Handle area: privacyAdminHandle, signHandle, sessionHandle.
    let get_audit_handles = [Handle::RH_ENDORSEMENT, ak_handle, sess.session_handle];

    // Construct raw transaction bytes:
    let mut cmd_buffer = [0u8; 4096];
    let mut cmd_header = CmdHeader {
        tag: TpmiStCommandTag::Sessions,
        size: 0,
        code: TpmCc::GetSessionAuditDigest,
    };
    let mut written = cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());
    for handle in get_audit_handles {
        written += marshal_to_slice(&handle, &mut cmd_buffer[written..]);
    }

    // 2 password sessions
    let auth_cmd = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_buffer = [0u8; 1024];
    let mut auth_written = 0;
    for _ in 0..2 {
        auth_written += marshal_to_slice(&(auth_cmd), &mut auth_buffer[auth_written..]);
    }
    written += marshal_to_slice(&(auth_written as u32), &mut cmd_buffer[written..]);
    cmd_buffer[written..written + auth_written].copy_from_slice(&auth_buffer[..auth_written]);
    written += auth_written;

    // Parameters:
    // qualifying_data: size 67 (exceeds max size 66), followed by 67 bytes of zero
    let size_67 = 67u16;
    written += marshal_to_slice(&(size_67), &mut cmd_buffer[written..]);
    cmd_buffer[written..written + 67].fill(0);
    written += 67;
    // in_scheme: Null
    let in_scheme: Option<TpmtSigScheme> = None;
    written += marshal_to_slice(&(in_scheme), &mut cmd_buffer[written..]);

    // Update size in header
    cmd_header.size = written as u32;
    let mut header_buf = [0u8; 10];
    cmd_header.marshal(&mut header_buf);
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    // Transact
    let mut resp_buffer = [0u8; 4096];
    sim.transact(&cmd_buffer[..written], &mut resp_buffer)
        .unwrap();

    let mut slice = &resp_buffer[..];
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();

    assert_eq!(resp_header.rc, 0x1D5); // TPM_RC_SIZE + TPM_RC_P + TPM_RC_1 (0x1D5) because parameter 1 unmarshal failed

    flush_context(&mut sim, ak_handle).unwrap();
}

/// TPM2_GetSessionAuditDigest on a policy session handle fails with TPM_RC_VALUE + H3
#[test]
fn get_session_audit_digest_rejects_policy_session() {
    let mut sim = Tpm::new();
    let s = start_session(&mut sim, TpmSe::Policy, false);
    assert_eq!(s.handle >> 24, 0x03);

    let cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle::RH_NULL,
        session_handle: Handle(s.handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert_eq!(
        res.err(),
        Some(0x384), // TPMI_SH_HMAC rejects policy session handles (0x03xxxxxx) with TPM_RC_VALUE + TPM_RC_H + TPM_RC_3 (0x384)
        "Expected GetSessionAuditDigest to fail with VALUE error on a policy session handle"
    );
}

/// TPM2_GetSessionAuditDigest with an ECDSA signer and an RSASSA inScheme fails with TPM_RC_SCHEME + P2
#[test]
fn get_session_audit_digest_rejects_rsassa_scheme_for_ecc_key() {
    let mut sim = Tpm::new();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    let mut sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    sess.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;

    let get_cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };
    let mut sessions = [sess.clone()];
    execute_with_hmac_sessions_status(&mut sim, &get_cmd, &[], &mut sessions, &[&[]]).unwrap();
    let sess = &sessions[0];

    // Signer key is ECC (ECDSA), but we request RSASSA signature scheme!
    let get_audit_cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: ak_handle,
        session_handle: sess.session_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
    };

    let resp = execute_with_password_sessions_status(&mut sim, &get_audit_cmd, 2, &[]);
    assert!(resp.is_err());
    let err = resp.err().unwrap();
    // Signer key scheme mismatch.
    // TPM_RC_SCHEME + RC_GetSessionAuditDigest_inScheme (P2).
    assert_eq!(err, 0x2D2);

    flush_context(&mut sim, ak_handle).unwrap();
}

/// TPM2_GetSessionAuditDigest with an unloaded session handle fails with TPM_RC_REFERENCE_H2
#[test]
fn get_session_audit_digest_rejects_unloaded_session() {
    let mut sim = Tpm::new();
    let (ak_handle, _) = create_signing_key_ecc(&mut sim, &[]);

    let get_audit_cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: ak_handle,
        // Use non-existent session handle 0x0200000e
        session_handle: Handle(0x0200000e),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let resp = execute_with_password_sessions_status(&mut sim, &get_audit_cmd, 2, &[]);
    // C EntityGetLoadStatus: an unloaded HMAC session handle yields
    // TPM_RC_REFERENCE_H0 + 2 (0x912) for the third handle (Entity.c:146-149).
    assert_eq!(resp.err(), Some(0x912));

    flush_context(&mut sim, ak_handle).unwrap();
}

/// TPM2_GetSessionAuditDigest with a non-existent signHandle fails with TPM_RC_REFERENCE_H1
#[test]
fn get_session_audit_digest_rejects_unloaded_sign_key() {
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

    let get_audit_cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        // Use non-existent sign key handle 0x80ffffff
        sign_handle: Handle(0x8000000E),
        session_handle: sess.session_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let resp = execute_with_password_sessions_status(&mut sim, &get_audit_cmd, 2, &[]);
    // SPEC EXPECTS: TPM_RC_REFERENCE_Hx for invalid transient sign_handle (ReferenceH1 = 2321)
    assert_eq!(resp.err(), Some(2321));
}
