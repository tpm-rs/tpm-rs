//! Response parameter encryption with ENCRYPT sessions (AES-CFB) on one or several sessions.

use crate::_common::{
    AES128_CFB, AES256_CFB, create_primary_key, create_primary_key_with_auth,
    execute_with_hmac_sessions, execute_with_hmac_sessions_custom,
    execute_with_hmac_sessions_custom_status, execute_with_password_sessions, flush_context,
    start_auth_session,
};
use sha2::{Digest as _, Sha256};
use testing::tpm::Tpm;
use tpm2::commands::{CreatePrimary, GetTime, HierarchyChangeAuth, ReadPublic};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bSensitiveData,
    TpmEccCurve, TpmSe, TpmaObject, TpmaSession, TpmiAlgHash, TpmsEccParms, TpmsEccPoint,
    TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic,
};

/// ReadPublic with an AES-128-CFB response-encryption session succeeds.
#[test]
fn aes128_cfb_read_public() {
    let mut sim = Tpm::new();
    let object_handle = create_primary_key(&mut sim);
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
    let read_cmd = ReadPublic { object_handle };
    let _ = execute_with_hmac_sessions(&mut sim, &read_cmd, &[], &mut [session], &[&[]]).unwrap();
}

/// ReadPublic with an AES-256-CFB response-encryption session succeeds.
#[test]
fn aes256_cfb_read_public() {
    let mut sim = Tpm::new();
    let object_handle = create_primary_key(&mut sim);
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES256_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::ENCRYPT);
    let read_cmd = ReadPublic { object_handle };
    let _ = execute_with_hmac_sessions(&mut sim, &read_cmd, &[], &mut [session], &[&[]]).unwrap();
}

/// CreatePrimary with an AES-128-CFB encrypt session returns a valid object handle.
#[test]
fn create_primary_response_encrypted() {
    let mut sim = Tpm::new();
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
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let resp_handles =
        execute_with_hmac_sessions(&mut sim, &create_cmd, &[], &mut [session], &[&[]]).unwrap();

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
    assert_ne!(resp_handles.object_handle.0, 0);
}

/// ReadPublic with an audit first session and an ENCRYPT second session decrypts correctly.
#[test]
fn encrypt_on_second_session() {
    let mut sim = Tpm::new();
    let object_handle = create_primary_key(&mut sim);

    let mut session1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut session2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Enable ENCRYPT on the second session (session2)
    session2.attributes.insert(TpmaSession::ENCRYPT);
    // ReadPublic has no auth handle, so C requires session1 to be
    // audit/encrypt/decrypt too (SessionProcess.c:1709-1712); make it audit.
    session1.attributes.insert(TpmaSession::AUDIT);

    let read_cmd = ReadPublic { object_handle };

    // Since neither session authorizes a handle requiring auth, both use empty auth.
    let resp = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        &[],
        &mut [session1, session2],
        &[&[], &[]],
    )
    .unwrap();

    let out_public_struct = resp.out_public.0;
    assert_eq!(out_public_struct.name_alg, Some(TpmiAlgHash::Sha256));

    flush_context(&mut sim, object_handle).unwrap();
}

/// CreatePrimary authorized by session 1 with owner auth and encrypted by session 2 succeeds.
#[test]
fn encrypt_on_second_session_with_owner_auth() {
    let mut sim = Tpm::new();
    let owner_auth_value = b"owner_auth_password";

    // Set owner auth to owner_auth_value
    use tpm2::commands::HierarchyChangeAuth;
    let cmd = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(owner_auth_value).unwrap(),
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    // Start Session 1: HMAC session, which will authorize Handle::RH_OWNER using the owner_auth_value password
    let session1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Start Session 2: HMAC session, which is an encrypt session (with empty auth value)
    let mut session2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session2.attributes.insert(TpmaSession::ENCRYPT);

    // Execute CreatePrimary to create a primary key.
    // Handles: primary_handle = Handle::RH_OWNER
    // Sessions: [session1, session2]
    // entity_auths: [owner_auth_value, &[]] (Session 1 authorizes handle 0, Session 2 is encrypt-only with empty auth)
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
        user_auth: Tpm2bAuth::from_bytes(b"key_auth_password").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let mut sessions = [session1, session2];
    let resp_handles = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        &[],
        &mut sessions,
        &[owner_auth_value, &[]],
    )
    .unwrap();

    let object_handle = resp_handles.object_handle;
    assert_ne!(object_handle.0, 0);

    flush_context(&mut sim, object_handle).unwrap();
}

/// TPM2_Hash with audit, decrypt and encrypt sessions: ENCRYPT on the third session encrypts the response.
#[test]
fn encrypt_on_third_session() {
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
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let sess3 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut sessions = [sess1, sess2, sess3];
    // Session 3 has ENCRYPT. None of the sessions authorizes a handle, so C
    // requires each to be audit, decrypt or encrypt (SessionProcess.c:1709-1712),
    // with at most one of each. GetRandom has no TPM2B command parameter, so use
    // TPM2_Hash (TPM2B data in, TPM2B digest out): audit, decrypt, encrypt.
    sessions[0].attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;
    sessions[1].attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;
    sessions[2].attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

    let cmd = tpm2::commands::Hash {
        data: tpm2::Tpm2bMaxBuffer::from_bytes(b"third session").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };
    let result = execute_with_hmac_sessions_custom(&mut sim, &cmd, &mut sessions, &[&[], &[], &[]]);

    assert!(
        result.is_ok(),
        "Hash with encrypt on 3rd session failed: {:?}",
        result.err()
    );
    let resp = result.unwrap();
    assert_eq!(
        resp.out_hash.as_ref(),
        Sha256::digest(b"third session").as_slice()
    );
}

/// ReadPublic with an encrypt first session and an audit second session succeeds.
#[test]
fn encrypt_session_with_audit_session() {
    let mut sim = Tpm::new();
    let object_handle = create_primary_key(&mut sim);
    let mut session1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let mut session2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session1.attributes.insert(TpmaSession::ENCRYPT);
    // ReadPublic has no auth handle, so C requires every session to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712); make session2 audit.
    session2.attributes.insert(TpmaSession::AUDIT);
    let read_cmd = ReadPublic { object_handle };
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        &[],
        &mut [session1, session2],
        &[&[], &[]],
    )
    .unwrap();
}

/// TPM2_GetRandom with an encrypt session returns an encrypted response that decrypts client-side
#[test]
fn get_random_response() {
    let mut sim = Tpm::new();
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

    let cmd = tpm2::commands::GetRandom {
        bytes_requested: 32,
    };

    let result = execute_with_hmac_sessions(&mut sim, &cmd, &[], &mut [session], &[&[]]);

    assert!(
        result.is_ok(),
        "GetRandom with encrypt session failed: {:?}",
        result.err()
    );
    let resp = result.unwrap();
    assert_eq!(resp.random_bytes.as_ref().len(), 32);
}

/// Encrypted newAuth of TPM2_HierarchyChangeAuth across CFB block-boundary sizes; empty newAuth fails with TPM_RC_SIZE + S1
#[test]
fn hierarchy_change_auth_sizes() {
    // Test different sizes of new_auth to verify CFB block boundaries and stream logic
    let sizes = [0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 64];

    for &size in &sizes {
        // Create a fresh simulator for each size to avoid persisting Owner Auth state modifications
        let mut sim = Tpm::new();

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
        session.attributes.insert(TpmaSession::DECRYPT);

        let new_auth_data = vec![0xABu8; size];
        let cmd = HierarchyChangeAuth {
            auth_handle: Handle::RH_OWNER,
            new_auth: Tpm2bAuth::from_bytes(&new_auth_data).unwrap(),
        };

        let result = execute_with_hmac_sessions(&mut sim, &cmd, &[], &mut [session], &[&[]]);

        if size == 0 {
            // C CryptParameterDecryption (CryptUtil.c:966-970) rejects an empty
            // remaining buffer (`bufferSize <= 0`) after the size field, so an
            // empty newAuth (the only parameter) fails with SIZE+S1 (0x995).
            assert_eq!(result.err(), Some(0x995), "size 0");
        } else if size <= 64 {
            // newAuth may be as large as the context-integrity digest (SHA-512).
            assert!(
                result.is_ok(),
                "Failed decryption boundary test for size {} with error {:?}",
                size,
                result.err()
            );
        } else {
            assert_eq!(
                result.err(),
                Some(0x1D5),
                "Expected TPM_RC_SIZE (0x1D5) for size {}, got {:?}",
                size,
                result.err()
            );
        }
    }
}

/// Encrypting ReadPublic of a key with an auth value derives the session key with empty auth.
#[test]
fn read_public_of_auth_key_uses_empty_auth() {
    let mut sim = Tpm::new();
    let auth_value = b"key_auth_password";
    let object_handle = create_primary_key_with_auth(&mut sim, auth_value);

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

    let read_cmd = ReadPublic { object_handle };

    // ReadPublic does not require authorization, so the entity auth for key derivation is empty.
    // Therefore, client uses empty auth (&[]) for the session.
    let resp =
        execute_with_hmac_sessions(&mut sim, &read_cmd, &[], &mut [session], &[&[]]).unwrap();

    let out_public_struct = resp.out_public.0;
    assert_eq!(out_public_struct.name_alg, Some(TpmiAlgHash::Sha256));

    flush_context(&mut sim, object_handle).unwrap();
}

/// GetTime with ENCRYPT on the second (key-bound) authorization session encrypts the response with the right key.
#[test]
fn response_encrypt_on_second_auth_session() {
    let mut sim = Tpm::new();

    // 1. Create a primary signing key with non-empty auth
    let rsa_parms = tpm2::TpmsRsaParms {
        symmetric: None,
        scheme: Some(tpm2::TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: tpm2::TpmiRsaKeyBits(2048),
        exponent: 0,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Rsa(rsa_parms, tpm2::Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let key_auth = b"keyauth";
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(key_auth).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_rsp_handles = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    let sign_handle = create_rsp_handles.object_handle;

    // 2. Start an unbound session for RH_ENDORSEMENT and a session bound to the signing key
    let admin_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // We bind to the signing key so that we can use HMAC authorization with the key's auth
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        sign_handle,
        key_auth,
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut sessions = [admin_session, session];
    sessions[0].attributes = TpmaSession::CONTINUE_SESSION;
    sessions[1].attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

    // 3. Execute GetTime
    // Handles: privacy_admin_handle = RH_ENDORSEMENT (index 0, auth required), sign_handle (index 1, auth required)
    // Sessions: session 0 authorizes RH_ENDORSEMENT, session 1 (with ENCRYPT) authorizes sign_handle using key_auth.
    let cmd = GetTime {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle,
        qualifying_data: tpm2::Tpm2bData::default(),
        in_scheme: None,
    };

    let result =
        execute_with_hmac_sessions_custom_status(&mut sim, &cmd, &mut sessions, &[&[], key_auth]);

    assert!(result.is_ok(), "GetTime failed: {:?}", result.err());
}

/// Response encryption on the third session uses that session's key (with owner auth on session 1).
#[test]
fn third_session_encrypt_key_derivation() {
    let mut sim = Tpm::new();
    let owner_auth_value = b"owner_auth_password";

    // Set owner auth
    let cmd = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(owner_auth_value).unwrap(),
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    let aes_cfb = Some(AES128_CFB);
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

    // Session 2: HMAC session (no encrypt/decrypt). It authorizes no handle, so
    // C requires it to be audit/decrypt/encrypt (SessionProcess.c:1709-1712):
    // make it the audit session.
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
    session2
        .attributes
        .insert(TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION);

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
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    // Case A: Client uses empty auth for session 3 (correct index 2 alignment). This must SUCCEED.
    let s1 = session1.clone();
    let s2 = session2.clone();
    let s3 = session3.clone();
    let result_a = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        &[],
        &mut [s1.clone(), s2.clone(), s3.clone()],
        &[owner_auth_value, &[], &[]],
    );
    assert!(
        result_a.is_ok(),
        "CreatePrimary with 3 sessions should succeed: {:?}",
        result_a.err()
    );
    let resp_handles = result_a.unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();

    // Case B: Client uses owner_auth_value for session 3 (incorrect index alignment derivation). This must FAIL.
    let result_b = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
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
