#![forbid(unsafe_code)]

use crate::test_utils::{
    execute_sign, execute_with_hmac_sessions, execute_with_password_sessions, flush_context,
    start_auth_session,
};
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, HierarchyChangeAuth, HierarchyChangeAuthHandles,
    VerifySignature, VerifySignatureHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmEccCurve, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bSensitiveData, TpmaObject,
    TpmaSession, TpmiAlgHash, TpmiAlgSymMode, TpmsEccParms, TpmsEccPoint, TpmsSensitiveCreate,
    TpmtEccScheme, TpmtPublic, TpmtSymDefObject,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn create_ecc_key(sim: &mut Simulator<'_>, auth: &[u8]) -> Handle {
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
        user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_ENDORSEMENT,
    };
    let (_, rsp_handles) = execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[])
        .expect("could not generate key");
    rsp_handles.object_handle
}

#[test]
fn test_decryption_handle_no_auth_requirement() {
    let mut sim = create_simulator!();

    // Create an ECC key with non-empty auth
    let key_auth = b"key_secret_auth";
    let key_handle = create_ecc_key(&mut sim, key_auth);

    // Start decryption session
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);

    let digest = Tpm2bDigest::from_bytes(&[0xBB; 32]).unwrap();
    let sign_cmd = tpm2::commands::Sign {
        digest,
        in_scheme: None,
        validation: tpm2::TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let (sign_rsp, _) = execute_sign(
        &mut sim,
        &sign_cmd,
        tpm2::commands::SignHandles { key_handle },
        1,
        key_auth,
        &mut resp_buffer,
    )
    .expect("could not sign digest");

    // VerifySignature parameter: digest (to be decrypted)
    let verify_cmd = VerifySignature {
        digest,
        signature: sign_rsp.signature,
    };
    let verify_handles = VerifySignatureHandles { key_handle };

    // Case A: Client uses Empty Auth (&[]). This must SUCCEED.
    let session_a = session.clone();
    let result_a = execute_with_hmac_sessions(
        &mut sim,
        &verify_cmd,
        verify_handles,
        &[],
        &mut [session_a],
        &[&[]], // Empty Auth
    );
    assert!(
        result_a.is_ok(),
        "VerifySignature decryption should succeed with Empty Auth, got {:?}",
        result_a.err()
    );

    // Case B: Client uses the key's auth value. This must FAIL because TPM uses Empty Auth, resulting in key mismatch.
    let session_b = session.clone();
    let result_b = execute_with_hmac_sessions(
        &mut sim,
        &verify_cmd,
        verify_handles,
        &[],
        &mut [session_b.clone()],
        &[key_auth], // Wrong Auth (for this decrypt-only session KDFa key derivation)
    );
    assert!(
        result_b.is_err(),
        "VerifySignature decryption should fail when client uses key's auth value"
    );

    flush_context(&mut sim, key_handle).unwrap();
}

#[test]
fn test_multiple_sessions_attributes_and_symmetric_constraints() {
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

    let aes_cfb = Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)));
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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
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
        s3.attributes.insert(TpmaSession::CONTINUE_SESSION);

        let res = execute_with_hmac_sessions(
            &mut sim,
            &cmd,
            handles.clone(),
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
        s2.attributes.insert(TpmaSession::CONTINUE_SESSION);
        s3.attributes
            .insert(TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION);

        let res = execute_with_hmac_sessions(
            &mut sim,
            &cmd,
            handles.clone(),
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
        s2.attributes.insert(TpmaSession::CONTINUE_SESSION);
        s3.attributes
            .insert(TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION);

        let res = execute_with_hmac_sessions(
            &mut sim,
            &cmd,
            handles.clone(),
            &[],
            &mut [s1.clone(), s2.clone(), s3.clone()],
            &[&[], &[], &[]],
        );
        assert!(
            res.is_ok(),
            "Valid Decrypt (1st) + Encrypt (3rd) failed: {:?}",
            res.err()
        );
        if let Ok((_, resp_handles)) = res {
            flush_context(&mut sim, resp_handles.object_handle).unwrap();
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
            handles.clone(),
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
            handles.clone(),
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
            handles.clone(),
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

#[test]
fn test_response_encryption_key_derivation_index_alignment_3_sessions() {
    let mut sim = create_simulator!();
    let owner_auth_value = b"owner_auth_password";

    // Set owner auth
    let cmd = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(owner_auth_value).unwrap(),
    };
    let handles = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    let aes_cfb = Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)));
    let sym_default = None;

    // Session 1: HMAC session, authorizes RHOwner
    let mut session1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        sym_default,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session1.attributes.insert(TpmaSession::CONTINUE_SESSION);

    // Session 2: HMAC session (no encrypt/decrypt)
    let mut session2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        sym_default,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session2.attributes.insert(TpmaSession::CONTINUE_SESSION);

    // Session 3: HMAC session (ENCRYPT)
    let mut session3 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        aes_cfb,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session3
        .attributes
        .insert(TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION);

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

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    // Case A: Client uses empty auth for session 3 (correct index 2 alignment). This must SUCCEED.
    let s1 = session1.clone();
    let s2 = session2.clone();
    let s3 = session3.clone();
    let result_a = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles.clone(),
        &[],
        &mut [s1.clone(), s2.clone(), s3.clone()],
        &[owner_auth_value, &[], &[]],
    );
    assert!(
        result_a.is_ok(),
        "CreatePrimary with 3 sessions should succeed: {:?}",
        result_a.err()
    );
    let (_, resp_handles) = result_a.unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();

    // Case B: Client uses owner_auth_value for session 3 (incorrect index alignment derivation). This must FAIL.
    let result_b = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [s1, s2, s3],
        &[owner_auth_value, &[], owner_auth_value], // Client derives using owner_auth_value for session 3
    );
    assert!(
        result_b.is_err(),
        "CreatePrimary should fail when client uses owner_auth for session 3 derivation"
    );

    flush_context(&mut sim, session1.session_handle).unwrap();
    flush_context(&mut sim, session2.session_handle).unwrap();
    flush_context(&mut sim, session3.session_handle).unwrap();
}
