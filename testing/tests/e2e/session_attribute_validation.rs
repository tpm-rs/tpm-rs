//! Session attribute validation (AUDIT, DECRYPT, ENCRYPT, continueSession, reserved combinations).

use crate::_common::*;
use tpm2::commands::{CreatePrimary, FlushContext, ReadPublic};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bSensitiveData,
    TpmEccCurve, TpmSe, TpmaObject, TpmaSession, TpmiAlgHash, TpmsEccParms, TpmsEccPoint,
    TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtSymDefObject,
};
use tpm2_simulator::{Simulator, create_simulator};

/// An unassociated HMAC session with AUDIT set is accepted on ReadPublic.
///
/// 10. Attempting to authorize a command using an HMAC session handle should be rejected
#[test]
fn audit_session_on_read_public_succeeds() {
    use tpm2::commands::ReadPublic;

    let mut sim = create_simulator!();

    // Create a key so we have a valid handle to read
    let key_handle = create_rsa_decrypt_key(&mut sim);

    // Start a valid HMAC session
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // ReadPublic has no authorization handles, so the session is unassociated: C
    // ParseSessionBuffer requires it to be an audit, encrypt or decrypt session.
    session.attributes = tpm2::TpmaSession::CONTINUE_SESSION | tpm2::TpmaSession::AUDIT;

    // Now try to execute ReadPublic using the HMAC session.
    let read_cmd = ReadPublic {
        object_handle: key_handle,
    };

    let mut sessions = [session];
    let name = read_public_name(&mut sim, key_handle);
    let res = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        &[name.get_buffer()],
        &mut sessions,
        &[&[]],
    );

    assert!(
        res.is_ok(),
        "Attempting to authorize a command using an HMAC session handle should succeed, got: {:?}",
        res.err()
    );

    // Flush key and session
    flush_context(&mut sim, key_handle).unwrap();
    flush_context(&mut sim, sessions[0].session_handle).unwrap();
}

/// A DECRYPT session on ReadPublic (no decryptable parameter) fails with TPM_RC_ATTRIBUTES + S1.
#[test]
fn decrypt_on_command_without_parameter_returns_attributes() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT); // attribute not validated correctly
    let read_cmd = ReadPublic { object_handle };
    let err = match execute_with_hmac_sessions(&mut sim, &read_cmd, &[], &mut [session], &[&[]]) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err, 2434);
}

/// An ENCRYPT session started without a symmetric algorithm fails with TPM_RC_SYMMETRIC + S1.
#[test]
fn encrypt_without_symmetric_returns_symmetric() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::ENCRYPT);
    let read_cmd = ReadPublic { object_handle };
    let err = match execute_with_hmac_sessions(&mut sim, &read_cmd, &[], &mut [session], &[&[]]) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err, 2454);
}

/// FlushContext with a DECRYPT session fails with TPM_RC_AUTH_CONTEXT.
#[test]
fn flush_context_with_decrypt_session_returns_auth_context() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);
    let flush_cmd = FlushContext {
        flush_handle: Handle(0x02800001),
    };
    let err = match execute_with_hmac_sessions(&mut sim, &flush_cmd, &[], &mut [session], &[&[]]) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // C SessionProcess.c:1628: FlushContext allows no sessions, so any session
    // area is rejected with TPM_RC_AUTH_CONTEXT (0x145).
    assert_eq!(err, 0x145);
}

/// FlushContext with an ENCRYPT session fails with TPM_RC_AUTH_CONTEXT.
#[test]
fn flush_context_with_encrypt_session_returns_auth_context() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::ENCRYPT);
    let flush_cmd = FlushContext {
        flush_handle: Handle(0x02800001),
    };
    let err = match execute_with_hmac_sessions(&mut sim, &flush_cmd, &[], &mut [session], &[&[]]) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // C SessionProcess.c:1628: FlushContext allows no sessions, so any session
    // area is rejected with TPM_RC_AUTH_CONTEXT (0x145).
    assert_eq!(err, 0x145);
}

/// FlushContext with an HMAC session area fails with TPM_RC_AUTH_CONTEXT.
#[test]
fn flush_context_with_session_returns_auth_context() {
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
    let flush_cmd = FlushContext {
        flush_handle: Handle(0x0200003f),
    };
    let err = match execute_with_hmac_sessions(&mut sim, &flush_cmd, &[], &mut [session], &[&[]]) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // C SessionProcess.c:1628: FlushContext allows no sessions, so any session
    // area is rejected with TPM_RC_AUTH_CONTEXT (0x145) before the handle check.
    assert_eq!(err, 0x145);
}

/// DECRYPT/ENCRYPT may sit on any session but only once each and need a symmetric algorithm (ATTRIBUTES/SYMMETRIC errors).
#[test]
fn multi_session_decrypt_encrypt_constraints() {
    let mut sim = create_simulator!();

    // Start HMAC sessions
    let start_sess = |sim: &mut Simulator<'_>, sym: Option<TpmtSymDefObject>| {
        start_auth_session(
            sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            sym,
            TpmiAlgHash::Sha256,
        )
        .unwrap()
    };

    let aes_cfb = Some(AES128_CFB);
    let sym_null = None;

    // Setup CreatePrimary parameters
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"key_auth").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let err_pos3 = TpmRc::ATTRIBUTES.with(Position::session(3)).get();

    let err_sym_pos1 = TpmRc::SYMMETRIC.with(Position::session(1)).get();
    let err_sym_pos2 = TpmRc::SYMMETRIC.with(Position::session(2)).get();

    // 1. DECRYPT on 2nd session -> MUST SUCCEED
    {
        let mut s1 = start_sess(&mut sim, aes_cfb);
        let mut s2 = start_sess(&mut sim, aes_cfb);
        let mut s3 = start_sess(&mut sim, aes_cfb);
        s1.attributes.insert(TpmaSession::CONTINUE_SESSION);
        s2.attributes
            .insert(TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION);
        // Sessions that authorize no handle must be audit/decrypt/encrypt in C
        // (SessionProcess.c:1709-1712), so give the otherwise unused one a role.
        s3.attributes
            .insert(TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION);

        let res = execute_with_hmac_sessions(
            &mut sim,
            &cmd,
            &[],
            &mut [s1.clone(), s2.clone(), s3.clone()],
            &[&[], &[], &[]],
        );
        assert!(
            res.is_ok(),
            "Expected decrypt on 2nd session to succeed, got: {:?}",
            res.err()
        );
        flush_context(&mut sim, s1.session_handle).unwrap();
        flush_context(&mut sim, s2.session_handle).unwrap();
        flush_context(&mut sim, s3.session_handle).unwrap();
    }

    // 2. DECRYPT on 3rd session -> MUST SUCCEED
    {
        let mut s1 = start_sess(&mut sim, aes_cfb);
        let mut s2 = start_sess(&mut sim, aes_cfb);
        let mut s3 = start_sess(&mut sim, aes_cfb);
        s1.attributes.insert(TpmaSession::CONTINUE_SESSION);
        // Sessions that authorize no handle must be audit/decrypt/encrypt in C
        // (SessionProcess.c:1709-1712), so give the otherwise unused one a role.
        s2.attributes
            .insert(TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION);
        s3.attributes
            .insert(TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION);

        let res = execute_with_hmac_sessions(
            &mut sim,
            &cmd,
            &[],
            &mut [s1.clone(), s2.clone(), s3.clone()],
            &[&[], &[], &[]],
        );
        assert!(
            res.is_ok(),
            "Expected decrypt on 3rd session to succeed, got: {:?}",
            res.err()
        );
        flush_context(&mut sim, s1.session_handle).unwrap();
        flush_context(&mut sim, s2.session_handle).unwrap();
        flush_context(&mut sim, s3.session_handle).unwrap();
    }

    // 3. DECRYPT on 1st session, ENCRYPT on 3rd session -> MUST SUCCEED (valid combination)
    {
        let mut s1 = start_sess(&mut sim, aes_cfb);
        let mut s2 = start_sess(&mut sim, aes_cfb);
        let mut s3 = start_sess(&mut sim, aes_cfb);
        s1.attributes
            .insert(TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION);
        // Sessions that authorize no handle must be audit/decrypt/encrypt in C
        // (SessionProcess.c:1709-1712), so give the otherwise unused one a role.
        s2.attributes
            .insert(TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION);
        s3.attributes
            .insert(TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION);

        let res = execute_with_hmac_sessions(
            &mut sim,
            &cmd,
            &[],
            &mut [s1.clone(), s2.clone(), s3.clone()],
            &[&[], &[], &[]],
        );
        assert!(
            res.is_ok(),
            "Valid Decrypt (1st) + Encrypt (3rd) failed: {:?}",
            res.err()
        );
        if let Ok(rsp) = res {
            flush_context(&mut sim, rsp.object_handle).unwrap();
        }
        flush_context(&mut sim, s1.session_handle).unwrap();
        flush_context(&mut sim, s2.session_handle).unwrap();
        flush_context(&mut sim, s3.session_handle).unwrap();
    }

    // 4. Multiple ENCRYPT attributes (e.g. on 1st and 3rd session) -> MUST FAIL
    {
        let mut s1 = start_sess(&mut sim, aes_cfb);
        let s2 = start_sess(&mut sim, aes_cfb);
        let mut s3 = start_sess(&mut sim, aes_cfb);
        s1.attributes.insert(TpmaSession::ENCRYPT);
        s3.attributes.insert(TpmaSession::ENCRYPT);

        let res = execute_with_hmac_sessions(
            &mut sim,
            &cmd,
            &[],
            &mut [s1.clone(), s2.clone(), s3.clone()],
            &[&[], &[], &[]],
        );
        assert_eq!(
            res.err(),
            Some(err_pos3),
            "Expected Pos3 Session Attributes error (multiple encrypts)"
        );
        flush_context(&mut sim, s1.session_handle).unwrap();
        flush_context(&mut sim, s2.session_handle).unwrap();
        flush_context(&mut sim, s3.session_handle).unwrap();
    }

    // 5. DECRYPT on 1st session with incompatible symmetric parameter (Null symmetric) -> MUST FAIL
    {
        let mut s1 = start_sess(&mut sim, sym_null);
        let s2 = start_sess(&mut sim, aes_cfb);
        let s3 = start_sess(&mut sim, aes_cfb);
        s1.attributes.insert(TpmaSession::DECRYPT);

        let res = execute_with_hmac_sessions(
            &mut sim,
            &cmd,
            &[],
            &mut [s1.clone(), s2.clone(), s3.clone()],
            &[&[], &[], &[]],
        );
        assert_eq!(
            res.err(),
            Some(err_sym_pos1),
            "Expected Pos1 Session Symmetric error (Null symmetric)"
        );
        flush_context(&mut sim, s1.session_handle).unwrap();
        flush_context(&mut sim, s2.session_handle).unwrap();
        flush_context(&mut sim, s3.session_handle).unwrap();
    }

    // 6. ENCRYPT on 2nd session with incompatible symmetric parameter (Null symmetric) -> MUST FAIL
    {
        let s1 = start_sess(&mut sim, aes_cfb);
        let mut s2 = start_sess(&mut sim, sym_null);
        let s3 = start_sess(&mut sim, aes_cfb);
        s2.attributes.insert(TpmaSession::ENCRYPT);

        let res = execute_with_hmac_sessions(
            &mut sim,
            &cmd,
            &[],
            &mut [s1.clone(), s2.clone(), s3.clone()],
            &[&[], &[], &[]],
        );
        assert_eq!(
            res.err(),
            Some(err_sym_pos2),
            "Expected Pos2 Session Symmetric error (Null symmetric)"
        );
        flush_context(&mut sim, s1.session_handle).unwrap();
        flush_context(&mut sim, s2.session_handle).unwrap();
        flush_context(&mut sim, s3.session_handle).unwrap();
    }
}

/// A decrypt session without symmetric algorithm is SYMMETRIC+S1 before the unassociated-session attribute check.
///
/// session-area-validation-omissions-wrong-error-codes: ordering of the unassociated-session
/// attribute check (reported by triage, #135). C `RetrieveSessionData` checks every session's
/// decrypt/encrypt symmetric algorithm before `ParseSessionBuffer` rejects a plain unassociated
/// session.
#[test]
fn symmetric_checked_before_unassociated_session() {
    let mut sim = new_sim();
    let mut s1 = start_session(&mut sim, TpmSe::HMAC, false);
    let mut s2 = start_session(&mut sim, TpmSe::HMAC, false);
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [
            SessUse::hmac(&mut s1, ATTR_CONT | ATTR_DECRYPT, &[]),
            SessUse::hmac(&mut s2, ATTR_CONT, &[]),
        ],
        &[0x00, 0x00],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_SYMMETRIC));
}

/// Session area rejects unassociated password sessions, trial policy sessions and non-audit/encrypt/decrypt extra sessions.
///
/// session-area-validation-omissions-wrong-error-codes
#[test]
fn unused_password_trial_and_plain_sessions() {
    let mut sim = new_sim();
    let get_random = 8u16.to_be_bytes();

    // A password session that does not authorize any handle.
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::pw(&[])],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_HANDLE));

    // A trial policy session can never appear in the session area.
    // (Used to authorize a handle, so no other attribute rule applies first.)
    let mut trial = start_session(&mut sim, TpmSe::Trial, false);
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut trial, ATTR_CONT, &[])],
        &[0x00, 0x00],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_ATTRIBUTES));

    // A non-authorization session must be an audit, encrypt or decrypt session.
    let mut s = start_session(&mut sim, TpmSe::HMAC, false);
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(&mut s, ATTR_CONT, &[])],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_ATTRIBUTES));
}
