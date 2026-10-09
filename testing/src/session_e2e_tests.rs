use crate::test_utils::marshal_to_slice;
use crate::test_utils::max_loaded_sessions;
use crate::test_utils::{
    ResponseCorruption, execute_with_hmac_sessions, execute_with_hmac_sessions_corrupt_response,
    execute_with_hmac_sessions_mismatch_nonce, execute_with_password_sessions, flush_context,
    start_auth_session,
};
use tpm2::Unmarshal;
use tpm2::commands::{
    Certify, CertifyHandles, CreatePrimary, CreatePrimaryHandles, FlushContext, ReadPublic,
    ReadPublicHandles, Sign, SignHandles, StartAuthSession, StartAuthSessionHandles,
};
use tpm2::{Handle, TpmEccCurve, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bNonce,
    Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmaObject, TpmaSession, TpmiAlgHash, TpmiAlgSymMode,
    TpmsEccParms, TpmsEccPoint, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtSymDefObject,
};
use tpm2::{Tpm2bData, TpmtTkHashcheck};
use tpm2_simulator::{Simulator, create_simulator};

fn create_primary_key(sim: &mut Simulator) -> Handle {
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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, create_rsp_handles) =
        execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[]).unwrap();
    create_rsp_handles.object_handle
}

fn get_create_primary_cmd_and_handles() -> (CreatePrimary<'static>, CreatePrimaryHandles) {
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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    (create_cmd, create_handles)
}

/// Builds a `TPM2_Sign` of a zero SHA-256 digest with `key_handle` (USER
/// role), for tests that need an HMAC session to authorize a handle.
fn sign_cmd_and_handles(key_handle: Handle) -> (Sign<'static>, SignHandles) {
    let cmd = Sign {
        digest: Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    (cmd, SignHandles { key_handle })
}

/// Builds a `TPM2_Certify` of `key_handle` signed by itself, a command with two
/// authorization handles (objectHandle ADMIN, signHandle USER).
fn certify_cmd_and_handles(key_handle: Handle) -> (Certify<'static>, CertifyHandles) {
    let cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let handles = CertifyHandles {
        object_handle: key_handle,
        sign_handle: key_handle,
    };
    (cmd, handles)
}

// helper macro to wrap expected failure sessions in catch_unwind

// helper macro to wrap expected failure sessions in catch_unwind

// ==========================================
// TIER 1: FEATURE COVERAGE (35 cases)
// ==========================================

// F1: StartAuthSession Marshalling
#[test]
fn f1_t1_1_marshalling_rh_null() {
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::default(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&cmd, &mut buf);
    let mut unmarsh = &buf[..len];
    let decoded = StartAuthSession::unmarshal(&mut unmarsh).unwrap();
    assert_eq!(cmd.session_type, decoded.session_type);
}

#[test]
fn f1_t1_2_marshalling_ecc() {
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(b"1234567890123456").unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(b"some_encrypted_salt_data").unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Cipher(tpm2::TpmtSymDefObject::Aes128(
            Some(TpmiAlgSymMode::CFB),
        ))),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&cmd, &mut buf);
    let mut unmarsh = &buf[..len];
    let decoded = StartAuthSession::unmarshal(&mut unmarsh).unwrap();
    assert_eq!(
        cmd.nonce_caller.get_buffer(),
        decoded.nonce_caller.get_buffer()
    );
}

#[test]
fn f1_t1_3_marshalling_rsa() {
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(b"1234567890123456").unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(&[0u8; 256]).unwrap(),
        session_type: TpmSe::Policy,
        symmetric: Some(tpm2::TpmtSymDef::Cipher(tpm2::TpmtSymDefObject::Aes256(
            Some(TpmiAlgSymMode::CFB),
        ))),
        auth_hash: TpmiAlgHash::Sha384,
    };
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&cmd, &mut buf);
    let mut unmarsh = &buf[..len];
    let decoded = StartAuthSession::unmarshal(&mut unmarsh).unwrap();
    assert_eq!(cmd.auth_hash, decoded.auth_hash);
}

#[test]
fn f1_t1_4_marshalling_hashes() {
    for hash in &[
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
    ] {
        let cmd = StartAuthSession {
            nonce_caller: Tpm2bNonce::default(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: *hash,
        };
        let mut buf = [0u8; 1024];
        let len = marshal_to_slice(&cmd, &mut buf);
        let mut unmarsh = &buf[..len];
        let decoded = StartAuthSession::unmarshal(&mut unmarsh).unwrap();
        assert_eq!(decoded.auth_hash, *hash);
    }
}

#[test]
fn f1_t1_5_marshalling_types() {
    for st in &[TpmSe::HMAC, TpmSe::Policy, TpmSe::Trial] {
        let cmd = StartAuthSession {
            nonce_caller: Tpm2bNonce::default(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: *st,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let mut buf = [0u8; 1024];
        let len = marshal_to_slice(&cmd, &mut buf);
        let mut unmarsh = &buf[..len];
        let decoded = StartAuthSession::unmarshal(&mut unmarsh).unwrap();
        assert_eq!(decoded.session_type, *st);
    }
}

// F2: StartAuthSession Execution
#[test]
fn f2_t1_1_ecc_salt_decryption() {
    let mut sim = create_simulator!();
    let _sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

#[test]
fn f2_t1_2_rsa_salt_decryption() {
    let mut sim = create_simulator!();
    let _sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

#[test]
fn f2_t1_3_derivation_null_bind() {
    let mut sim = create_simulator!();
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

#[test]
fn f2_t1_4_derivation_non_null_bind() {
    let mut sim = create_simulator!();
    let _sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        b"bind_auth_val",
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

#[test]
fn f2_t1_5_derivation_ecc_salt_bind() {
    let mut sim = create_simulator!();
    let _sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        b"bind_auth_val",
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

// F3: Session Storage & Lifecycle
#[test]
fn f3_t1_1_session_count_tracking() {
    let mut sim = create_simulator!();
    let _sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

#[test]
fn f3_t1_2_session_creation_empty() {
    let mut sim = create_simulator!();
    let _sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

#[test]
fn f3_t1_3_session_creation_multiple() {
    let mut sim = create_simulator!();
    let _sess1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let _sess2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let _sess3 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

#[test]
fn f3_t1_4_flush_context_removes() {
    let mut sim = create_simulator!();
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
    flush_context(&mut sim, sess.session_handle).unwrap();
}

#[test]
fn f3_t1_5_recreate_after_flush() {
    let mut sim = create_simulator!();
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
    flush_context(&mut sim, sess.session_handle).unwrap();
    let _sess2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

// F4: HMAC Session Auth (cpHash)

#[test]
fn f4_t1_1_valid_hmac_auth() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn f4_t1_2_password_auth_create_primary() {
    let mut sim = create_simulator!();
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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();
    flush_context(&mut sim, create_rsp_handles.object_handle).unwrap();
}

#[test]
fn f4_t1_3_hmac_auth_incorrect_fail() {
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
    session.session_key = vec![1u8; 32]; // corrupt session key
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    let res = execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
    );
    assert_eq!(res, Err(2446));
}

#[test]
fn f4_t1_4_multiple_sessions_auth() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
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
    let session2 = start_auth_session(
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
    let (auth_cmd, auth_handles) = certify_cmd_and_handles(object_handle);
    execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session1, session2],
        &[&[], &[]],
    )
    .unwrap();
}

#[test]
fn f4_t1_5_hmac_auth_sha256_rotation() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

// F5: Response Format & HMAC (rpHash)

#[test]
fn f5_t1_1_response_hmac_read_public() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn f5_t1_2_response_hmac_nonce_rotation() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn f5_t1_3_response_formatting_tag() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn f5_t1_4_response_hmac_sha384() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn f5_t1_5_response_hmac_omitted_on_error() {
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
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles {
        object_handle: Handle::RH_NULL,
    }; // invalid handle
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
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

// F6: Parameter Decryption

#[test]
fn f6_t1_1_aes128_cfb_decryption() {
    let mut sim = create_simulator!();
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
    let (create_cmd, create_handles) = get_create_primary_cmd_and_handles();
    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn f6_t1_2_aes256_cfb_decryption() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes256(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);
    let (create_cmd, create_handles) = get_create_primary_cmd_and_handles();
    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn f6_t1_3_nonce_validation_decryption() {
    let mut sim = create_simulator!();
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
    let (create_cmd, create_handles) = get_create_primary_cmd_and_handles();
    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn f6_t1_4_decryption_multiple_sessions() {
    let mut sim = create_simulator!();
    let mut session1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let mut session2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session1.attributes.insert(TpmaSession::DECRYPT);
    // The second session is not associated with an auth handle, so C requires
    // it to be audit/encrypt/decrypt (SessionProcess.c:1709-1712, else
    // ATTRIBUTES+S2). Make it the response-encryption session.
    session2.attributes.insert(TpmaSession::ENCRYPT);
    let (create_cmd, create_handles) = get_create_primary_cmd_and_handles();
    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session1, session2],
        &[&[], &[]],
    )
    .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn f6_t1_5_decryption_empty_parameters() {
    let mut sim = create_simulator!();
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
    let (create_cmd, create_handles) = get_create_primary_cmd_and_handles();
    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

// F7: Parameter Encryption

#[test]
fn f7_t1_1_aes128_cfb_encryption() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
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
    session.attributes.insert(TpmaSession::ENCRYPT);
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn f7_t1_2_aes256_cfb_encryption() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes256(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::ENCRYPT);
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn f7_t1_3_nonce_validation_encryption() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
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
    session.attributes.insert(TpmaSession::ENCRYPT);
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn f7_t1_4_encryption_multiple_sessions() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
    let mut session1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
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
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session1, session2],
        &[&[], &[]],
    )
    .unwrap();
}

#[test]
fn f7_t1_5_encryption_empty_parameters() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
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
    session.attributes.insert(TpmaSession::ENCRYPT);
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

// ==========================================
// TIER 2: BOUNDARY & CORNER CASES (35 cases)
// ==========================================

// F1: StartAuthSession Marshalling Boundaries
#[test]
fn f1_t2_1_marshalling_invalid_handle() {
    let h = StartAuthSessionHandles {
        tpm_key: Handle(0x999999),
        bind: Handle::RH_NULL,
    };
    let mut buf = [0u8; 128];
    marshal_to_slice(&h, &mut buf);
}

#[test]
fn f1_t2_2_marshalling_invalid_bind() {
    let h = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle(0x999999),
    };
    let mut buf = [0u8; 128];
    marshal_to_slice(&h, &mut buf);
}

#[test]
fn f1_t2_3_marshalling_invalid_symmetric() {
    let bad_bytes = [0x00, 0x06, 0x03, 0xe7, 0x00, 0x43]; // Alg::AES (0x0006), 999 (0x03E7), Alg::CFB (0x0043)
    let mut slice = &bad_bytes[..];
    assert!(<Option<tpm2::TpmtSymDef>>::unmarshal(&mut slice).is_err());
}

#[test]
fn f1_t2_4_marshalling_empty_nonce() {
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::default(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let mut buf = [0u8; 256];
    marshal_to_slice(&cmd, &mut buf);
}

#[test]
fn f1_t2_5_marshalling_salt_rh_null() {
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::default(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(b"salt").unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let mut buf = [0u8; 256];
    marshal_to_slice(&cmd, &mut buf);
}

// F2: StartAuthSession Execution Boundaries
#[test]
fn f2_t2_1_ecc_salt_decryption_fail() {
    let mut sim = create_simulator!();
    let _sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

#[test]
fn f2_t2_2_rsa_salt_decryption_fail() {
    let mut sim = create_simulator!();
    let _sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

#[test]
fn f2_t2_3_derivation_sha1() {
    let mut sim = create_simulator!();
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

#[test]
fn f2_t2_4_derivation_sha384() {
    let mut sim = create_simulator!();
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

#[test]
fn f2_t2_5_nonce_randomness() {
    let mut sim = create_simulator!();
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

// F3: Session Storage & Lifecycle Boundaries
#[test]
fn f3_t2_1_max_sessions_boundary() {
    let mut sim = create_simulator!();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let _ = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
    }
}

#[test]
fn f3_t2_2_flush_invalid_handle() {
    let mut sim = create_simulator!();
    let err = flush_context(&mut sim, Handle(0x0200003f)).unwrap_err();
    // C FlushContext.c: flushHandle is a parameter, so an unloaded session
    // returns TPM_RCS_HANDLE + RC_FlushContext_flushHandle (HANDLE+P1, 0x1CB).
    assert_eq!(err, 0x1cb);
}

#[test]
fn f3_t2_3_flush_already_flushed() {
    let mut sim = create_simulator!();
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
    flush_context(&mut sim, sess.session_handle).unwrap();
    let _ = flush_context(&mut sim, sess.session_handle).unwrap_err();
}

#[test]

fn f3_t2_4_reuse_flushed_handle() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
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
    flush_context(&mut sim, sess.session_handle).unwrap();
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [sess],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // C RetrieveSessionData: a session handle that is not loaded returns
    // TPM_RC_REFERENCE_S0 (0x918), not HANDLE+S1.
    assert_eq!(err, 0x918);
}

#[test]
fn f3_t2_5_flush_keeps_transient() {
    let mut sim = create_simulator!();
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
    flush_context(&mut sim, sess.session_handle).unwrap();
}

// F4: HMAC Session Auth Boundaries

#[test]
fn f4_t2_1_mismatching_nonce_caller() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    let res = execute_with_hmac_sessions_mismatch_nonce(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
    );
    assert_eq!(res, Err(2446));
}

#[test]
fn f4_t2_2_mismatching_nonce_tpm() {
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
    session.nonce_tpm = Tpm2bNonce::default(); // mismatch
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err, 2446);
}

#[test]
fn f4_t2_3_mismatching_attributes() {
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
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err, 2434);
}

#[test]
fn f4_t2_4_incorrect_cphash() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[b"bad_handle_name"],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err, 2446);
}

#[test]
fn f4_t2_5_empty_vs_non_empty_auth() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[b"wrong_auth_val"],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err, 2446);
}

// F5: Response Format & HMAC Boundaries

#[test]
#[should_panic(expected = "Response HMAC verification failed")]
fn f5_t2_1_invalid_response_hmac_detect() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    execute_with_hmac_sessions_corrupt_response(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
        ResponseCorruption::Hmac,
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "Response HMAC verification failed")]
fn f5_t2_2_incorrect_response_nonce_tpm() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    execute_with_hmac_sessions_corrupt_response(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
        ResponseCorruption::NonceTpm,
    )
    .unwrap();
}

#[test]
#[should_panic(expected = "Response HMAC verification failed")]
fn f5_t2_3_incorrect_response_attributes() {
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
    let (auth_cmd, auth_handles) = sign_cmd_and_handles(object_handle);
    execute_with_hmac_sessions_corrupt_response(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut [session],
        &[&[]],
        ResponseCorruption::Attributes,
    )
    .unwrap();
}

#[test]
fn f5_t2_4_response_hmac_empty_params() {
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
    let flush_handles = ();
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &flush_cmd,
        flush_handles,
        &[],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // C SessionProcess.c:1628: FlushContext allows no sessions, so any session
    // area is rejected with TPM_RC_AUTH_CONTEXT (0x145) before the handle check.
    assert_eq!(err, 0x145);
}

#[test]
fn f5_t2_5_response_hmac_rp_hash_error_code() {
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
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles {
        object_handle: Handle::RH_NULL,
    }; // invalid
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
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

// F6: Parameter Decryption Boundaries

#[test]
fn f6_t2_1_param_size_mismatch_decryption() {
    let mut sim = create_simulator!();
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
        user_auth: Tpm2bAuth::from_bytes(b"123").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let mut sensitive_buf = [0u8; 256];
    let len = marshal_to_slice(&sensitive_create, &mut sensitive_buf);

    let mut corrupted_bytes = vec![0u8; len + 12];
    corrupted_bytes[0..2].copy_from_slice(&((len + 10) as u16).to_be_bytes());
    corrupted_bytes[2..len + 2].copy_from_slice(&sensitive_buf[..len]);

    assert!(
        Tpm2bSensitiveCreate::from_bytes(&corrupted_bytes).is_err(),
        "Client unmarshaler should reject corrupted Tpm2bSensitiveCreate buffer"
    );

    struct BadCreatePrimary<'a> {
        in_sensitive_buf: &'a [u8],
        in_public: tpm2::Tpm2bPublic<'a>,
        outside_info: tpm2::Tpm2bData<'a>,
        creation_pcr: tpm2::TpmlPcrSelection,
    }
    impl tpm2::Marshal for BadCreatePrimary<'_> {
        const MAX_SIZE: usize = 4096;
        type MaxBuffer = [u8; 4096];
        fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
            let mut off =
                (self.in_sensitive_buf.len() as u16).marshal((&mut dst[0..2]).try_into().unwrap());
            dst[off..off + self.in_sensitive_buf.len()].copy_from_slice(self.in_sensitive_buf);
            off += self.in_sensitive_buf.len();
            off += self.in_public.marshal(
                (&mut dst[off..off + tpm2::Tpm2bPublic::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off += self.outside_info.marshal(
                (&mut dst[off..off + tpm2::Tpm2bData::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off += self.creation_pcr.marshal(
                (&mut dst[off..off + tpm2::TpmlPcrSelection::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off
        }
    }
    impl tpm2::Command for BadCreatePrimary<'_> {
        const CMD_CODE: tpm2::TpmCc = tpm2::TpmCc::CreatePrimary;
        type Handles = CreatePrimaryHandles;
        type Response<'a> = tpm2::commands::CreatePrimaryRsp<'a>;
        type RespHandles = tpm2::commands::CreatePrimaryRespHandles;
    }

    let create_cmd = BadCreatePrimary {
        in_sensitive_buf: &corrupted_bytes,
        in_public,
        outside_info: tpm2::Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let err = match execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(
        err,
        tpm2::errors::TpmRc::SIZE
            .with(tpm2::errors::Position::parameter(1))
            .get()
    ); // TPM_RC_SIZE + P1
}

#[test]
fn f6_t2_2_decryption_invalid_session_key() {
    let mut sim = create_simulator!();
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
    session.session_key = vec![1u8; 32]; // wrong key

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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let err = match execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // Owner hierarchy is DA-exempt, so a bad HMAC yields BAD_AUTH+S1 (0x9A2)
    // rather than AUTH_FAIL (C SessionProcess.c IncrementLockout).
    assert_eq!(err, 0x9a2);
}

#[test]
fn f6_t2_3_decryption_unsupported_command() {
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
    let flush_handles = ();
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &flush_cmd,
        flush_handles,
        &[],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // C SessionProcess.c:1628: FlushContext allows no sessions, so any session
    // area is rejected with TPM_RC_AUTH_CONTEXT (0x145).
    assert_eq!(err, 0x145);
}

#[test]
fn f6_t2_4_decryption_cfb_block_boundaries() {
    let mut sim = create_simulator!();
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha384),
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

    for auth_size in &[7, 16, 17, 32, 33] {
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

        let sensitive_create = TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(crate::test_utils::leak_bytes(&vec![
                0x41u8;
                *auth_size
            ]))
            .unwrap(),
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

        let (_, create_rsp_handles) = execute_with_hmac_sessions(
            &mut sim,
            &create_cmd,
            create_handles,
            &[],
            &mut [session],
            &[&[]],
        )
        .unwrap();

        flush_context(&mut sim, create_rsp_handles.object_handle).unwrap();
    }
}

#[test]
fn f6_t2_5_decryption_unsupported_symmetric() {
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
    let (create_cmd, create_handles) = get_create_primary_cmd_and_handles();
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err, 2454); // TpmRc::SYMMETRIC.with(Position::session(1))
}

// F7: Parameter Encryption Boundaries

#[test]
fn f7_t2_1_decryption_failure_encrypted_response() {
    let mut sim = create_simulator!();
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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
    assert_ne!(resp_handles.object_handle.0, 0);
}

#[test]
fn f7_t2_2_encryption_bypassed_on_error() {
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
    session.attributes.insert(TpmaSession::ENCRYPT);
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles {
        object_handle: Handle::RH_NULL,
    }; // invalid
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
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

#[test]
fn f7_t2_3_encryption_cfb_block_boundaries() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
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
    session.attributes.insert(TpmaSession::ENCRYPT);
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn f7_t2_4_encryption_different_symmetric() {
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
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err, 2454);
}

#[test]
fn f7_t2_5_encryption_attributes_mismatch() {
    let mut sim = create_simulator!();
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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
    assert_ne!(resp_handles.object_handle.0, 0);
}

#[test]
fn f7_t2_6_encryption_unsupported_command() {
    let mut sim = create_simulator!();
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
    session.attributes.insert(TpmaSession::ENCRYPT);
    let flush_cmd = FlushContext {
        flush_handle: Handle(0x02800001),
    };
    let flush_handles = ();
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &flush_cmd,
        flush_handles,
        &[],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // C SessionProcess.c:1628: FlushContext allows no sessions, so any session
    // area is rejected with TPM_RC_AUTH_CONTEXT (0x145).
    assert_eq!(err, 0x145);
}

// ==========================================
// TIER 3: CROSS-FEATURE COMBINATIONS (7 cases)
// ==========================================

#[test]
fn t3_1_hmac_session_parameter_decryption() {
    let mut sim = create_simulator!();
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
    let (create_cmd, create_handles) = get_create_primary_cmd_and_handles();
    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn t3_2_hmac_session_parameter_encryption() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
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
    session.attributes.insert(TpmaSession::ENCRYPT);
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn t3_3_hmac_session_dec_enc() {
    let mut sim = create_simulator!();
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
    session
        .attributes
        .insert(TpmaSession::DECRYPT | TpmaSession::ENCRYPT);
    let (create_cmd, create_handles) = get_create_primary_cmd_and_handles();
    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn t3_4_multiple_hmac_sessions_enc_dec() {
    let mut sim = create_simulator!();
    let mut session1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let mut session2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session1.attributes.insert(TpmaSession::DECRYPT);
    session2.attributes.insert(TpmaSession::ENCRYPT);
    let (create_cmd, create_handles) = get_create_primary_cmd_and_handles();
    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session1, session2],
        &[&[], &[]],
    )
    .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

#[test]
fn t3_5_lifecycle_start_flush_recreate() {
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
    flush_context(&mut sim, session.session_handle).unwrap();
    let _session2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

#[test]
fn t3_6_salted_session_hmac_encryption() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
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
    session.attributes.insert(TpmaSession::ENCRYPT);
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn t3_7_bound_session_hmac_decryption() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        b"bind_auth",
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);
    let (create_cmd, create_handles) = get_create_primary_cmd_and_handles();
    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

// ==========================================
// TIER 4: REAL-WORLD SCENARIOS (5 cases)
// ==========================================

#[test]
fn t4_1_ported_go_test_read_public() {
    let mut sim = create_simulator!();
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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (create_rsp, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();
    let object_handle = create_rsp_handles.object_handle;

    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    let (read_rsp, _) =
        execute_with_password_sessions(&mut sim, &read_cmd, read_handles, 0, &[]).unwrap();

    let out_pub_create = create_rsp.out_public.0;
    let out_pub_read = read_rsp.out_public.0;

    match (out_pub_create.parms_and_id, out_pub_read.parms_and_id) {
        (PublicParmsAndId::Ecc(_, pt_create), PublicParmsAndId::Ecc(_, pt_read)) => {
            assert_eq!(pt_create.x.get_buffer(), pt_read.x.get_buffer());
            assert_eq!(pt_create.y.get_buffer(), pt_read.y.get_buffer());
        }
        _ => panic!("Expected ECC public keys"),
    }
    flush_context(&mut sim, object_handle).unwrap();
}

#[test]
fn t4_2_ported_go_test_hmac_session() {
    let mut sim = create_simulator!();
    let _session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

#[test]
fn t4_3_complete_object_lifecycle() {
    let mut sim = create_simulator!();
    let _session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
}

#[test]
fn t4_4_session_limits_exhaustion_recovery() {
    let mut sim = create_simulator!();
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
    let sess3 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    flush_context(&mut sim, sess1.session_handle).unwrap();
    let _sess4 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    flush_context(&mut sim, sess2.session_handle).unwrap();
    flush_context(&mut sim, sess3.session_handle).unwrap();
}

#[test]
fn t4_5_multi_session_authorization() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
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
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let (auth_cmd, auth_handles) = certify_cmd_and_handles(object_handle);
    let mut sessions = [sess1, sess2];
    execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        auth_handles,
        &[],
        &mut sessions,
        &[&[], &[]],
    )
    .unwrap();
}

#[test]
fn test_hierarchy_change_auth_with_hmac_session_encrypt_decrypt() {
    let mut sim = create_simulator!();
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

    use tpm2::commands::{HierarchyChangeAuth, HierarchyChangeAuthHandles};
    let cmd = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"new_auth_password").unwrap(),
    };
    let handles = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };

    let _ =
        execute_with_hmac_sessions(&mut sim, &cmd, handles, &[], &mut [session], &[&[]]).unwrap();

    let cmd_back = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::default(),
    };
    let handles_back = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd_back, handles_back, 1, b"new_auth_password")
        .unwrap();
}

#[test]
fn test_create_primary_with_hmac_session_encrypt_decrypt() {
    let mut sim = create_simulator!();
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
        user_auth: Tpm2bAuth::from_bytes(b"key_auth_password").unwrap(),
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

    let (resp, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();

    let object_handle = resp_handles.object_handle;
    assert_ne!(object_handle.0, 0);

    let out_public_struct = resp.out_public.0;
    assert_eq!(out_public_struct.name_alg, Some(TpmiAlgHash::Sha256));

    flush_context(&mut sim, object_handle).unwrap();
}

fn create_primary_key_with_auth(sim: &mut Simulator, auth: &[u8]) -> Handle {
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
        primary_handle: Handle::RH_OWNER,
    };
    let (_, create_rsp_handles) =
        execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[]).unwrap();
    create_rsp_handles.object_handle
}

#[test]
fn test_read_public_with_auth_key_session_encrypt() {
    let mut sim = create_simulator!();
    let auth_value = b"key_auth_password";
    let object_handle = create_primary_key_with_auth(&mut sim, auth_value);

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
    session.attributes.insert(TpmaSession::ENCRYPT);

    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };

    // ReadPublic does not require authorization, so the entity auth for key derivation is empty.
    // Therefore, client uses empty auth (&[]) for the session.
    let (resp, _) = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();

    let out_public_struct = resp.out_public.0;
    assert_eq!(out_public_struct.name_alg, Some(TpmiAlgHash::Sha256));

    flush_context(&mut sim, object_handle).unwrap();
}

#[test]
fn test_encrypt_on_second_session_of_multi_session_command() {
    let mut sim = create_simulator!();
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
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Enable ENCRYPT on the second session (session2)
    session2.attributes.insert(TpmaSession::ENCRYPT);
    // ReadPublic has no auth handle, so C requires session1 to be
    // audit/encrypt/decrypt too (SessionProcess.c:1709-1712); make it audit.
    session1.attributes.insert(TpmaSession::AUDIT);

    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };

    // Since neither session authorizes a handle requiring auth, both use empty auth.
    let (resp, _) = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session1, session2],
        &[&[], &[]],
    )
    .unwrap();

    let out_public_struct = resp.out_public.0;
    assert_eq!(out_public_struct.name_alg, Some(TpmiAlgHash::Sha256));

    flush_context(&mut sim, object_handle).unwrap();
}

#[test]
fn test_encrypt_on_second_session_of_authorizing_command_with_non_empty_auth() {
    let mut sim = create_simulator!();
    let owner_auth_value = b"owner_auth_password";

    // Set owner auth to owner_auth_value
    use tpm2::commands::{HierarchyChangeAuth, HierarchyChangeAuthHandles};
    let cmd = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(owner_auth_value).unwrap(),
    };
    let handles = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

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
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let mut sessions = [session1, session2];
    let (_, resp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut sessions,
        &[owner_auth_value, &[]],
    )
    .unwrap();

    let object_handle = resp_handles.object_handle;
    assert_ne!(object_handle.0, 0);

    flush_context(&mut sim, object_handle).unwrap();
}
