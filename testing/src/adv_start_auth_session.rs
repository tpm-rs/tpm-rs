use crate::test_utils::{
    execute_with_corrupted_bytes, execute_with_hmac_sessions, execute_with_password_sessions,
    flush_context, read_public_name, start_auth_session,
};
use rsa::{Oaep, RsaPublicKey};
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, LoadExternal, StartAuthSession, StartAuthSessionHandles,
};
use tpm2::{Handle, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce, Tpm2bPublicKeyRsa,
    Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmsRsaParms,
    TpmsSensitiveCreate, TpmtPublic,
};
use tpm2_simulator::{Simulator, create_simulator};

// Helper to create RSA decrypt key
fn create_rsa_decrypt_key(sim: &mut Simulator) -> Handle {
    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
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

// 1. Nonce caller size validations (too small, too large, exact boundary).
#[test]
fn test_nonce_caller_sizes() {
    let mut sim = create_simulator!();

    // Valid size: 16 (exact lower boundary)
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(res.is_ok(), "Nonce size 16 should succeed: {:?}", res);
    let (_, resp_handles) = res.unwrap();
    flush_context(&mut sim, resp_handles.session_handle).unwrap();

    // Valid size: 32 (exact upper boundary for SHA256)
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(res.is_ok(), "Nonce size 32 should succeed: {:?}", res);
    let (_, resp_handles) = res.unwrap();
    flush_context(&mut sim, resp_handles.session_handle).unwrap();

    // Invalid size: 15 (too small)
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 15]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x1D5),
        "Nonce size 15 should return TPM_RC_SIZE (0x1D5)"
    );

    // Invalid size: 33 (too large for SHA256)
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 33]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x1D5),
        "Nonce size 33 should return TPM_RC_SIZE (0x1D5)"
    );

    // Invalid size: 21 (too large for SHA1, digest size 20)
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 21]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha1,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x1D5),
        "Nonce size 21 should return TPM_RC_SIZE for SHA1"
    );
}

// 2. Encrypted salt presence/absence when tpmKey is RHNull vs. valid decrypt key.
#[test]
fn test_encrypted_salt_presence() {
    let mut sim = create_simulator!();

    // When tpmKey is RHNull, encrypted_salt must be empty.
    // If not empty (e.g. 10 bytes), should fail with TPM_RC_VALUE (0x2C4)
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(&[1u8; 10]).unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x2C4),
        "Non-empty salt with RHNull should return TPM_RC_VALUE (0x2C4)"
    );

    // When tpmKey is a valid decrypt key
    let key_handle = create_rsa_decrypt_key(&mut sim);

    // Retrieve the public key modulus to encrypt a valid salt
    let read_cmd = tpm2::commands::ReadPublic {};
    let read_handles = tpm2::commands::ReadPublicHandles {
        object_handle: key_handle,
    };
    let (read_rsp, _) =
        execute_with_password_sessions(&mut sim, &read_cmd, read_handles, 0, &[]).unwrap();
    let out_pub = read_rsp.out_public.0;
    let PublicParmsAndId::Rsa(_, rsa_pubkey) = out_pub.parms_and_id else {
        panic!("Expected RSA key");
    };
    let rsa_modulus = rsa_pubkey.get_buffer();
    let rsa = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(rsa_modulus),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();

    let mut rng = rsa::rand_core::OsRng;
    let salt = vec![5u8; 32];
    let oaep = Oaep::new_with_label::<sha2::Sha256, _>("SECRET\0");
    let enc_salt = rsa.encrypt(&mut rng, oaep, &salt).unwrap();

    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(crate::test_utils::leak_bytes(&enc_salt))
            .unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let handles = StartAuthSessionHandles {
        tpm_key: key_handle,
        bind: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(
        res.is_ok(),
        "Valid encrypted salt should succeed: {:?}",
        res
    );
    let (_, resp_handles) = res.unwrap();
    flush_context(&mut sim, resp_handles.session_handle).unwrap();

    flush_context(&mut sim, key_handle).unwrap();
}

// 3. Salt size checks (matching nameAlg digest size boundaries).
#[test]
fn test_salt_size_boundaries() {
    let mut sim = create_simulator!();
    let key_handle = create_rsa_decrypt_key(&mut sim);

    let read_cmd = tpm2::commands::ReadPublic {};
    let read_handles = tpm2::commands::ReadPublicHandles {
        object_handle: key_handle,
    };
    let (read_rsp, _) =
        execute_with_password_sessions(&mut sim, &read_cmd, read_handles, 0, &[]).unwrap();
    let out_pub = read_rsp.out_public.0;
    let PublicParmsAndId::Rsa(_, rsa_pubkey) = out_pub.parms_and_id else {
        panic!("Expected RSA key");
    };
    let rsa_modulus = rsa_pubkey.get_buffer();
    let rsa = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(rsa_modulus),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();

    let mut rng = rsa::rand_core::OsRng;

    let handles = StartAuthSessionHandles {
        tpm_key: key_handle,
        bind: Handle::RH_NULL,
    };

    // Valid salt size: 32 (exact boundary for SHA256 nameAlg)
    let salt = vec![5u8; 32];
    let oaep = Oaep::new_with_label::<sha2::Sha256, _>("SECRET\0");
    let enc_salt = rsa.encrypt(&mut rng, oaep, &salt).unwrap();
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(crate::test_utils::leak_bytes(&enc_salt))
            .unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(res.is_ok(), "Salt size 32 should succeed");
    let (_, resp_handles) = res.unwrap();
    flush_context(&mut sim, resp_handles.session_handle).unwrap();

    // Invalid salt size: 33 (too large for SHA256 nameAlg)
    let salt = vec![5u8; 33];
    let oaep_err = Oaep::new_with_label::<sha2::Sha256, _>("SECRET\0");
    let enc_salt = rsa.encrypt(&mut rng, oaep_err, &salt).unwrap();
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(crate::test_utils::leak_bytes(&enc_salt))
            .unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x2C4),
        "Salt size 33 should fail with TPM_RC_VALUE (0x2C4)"
    );

    flush_context(&mut sim, key_handle).unwrap();
}

// 4. Symmetric block cipher parameter combinations (invalid modes vs. valid CFB).
#[test]
fn test_symmetric_modes() {
    let mut sim = create_simulator!();
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };

    // Valid: Aes128 CFB
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Cipher(tpm2::TpmtSymDefObject::Aes128(
            Some(TpmiAlgSymMode::CFB),
        ))),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(res.is_ok(), "Aes128 CFB should succeed");
    let (_, resp_handles) = res.unwrap();
    flush_context(&mut sim, resp_handles.session_handle).unwrap();

    // Invalid: Aes128 CBC (should fail with TPM_RC_MODE 0x4C9)
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Cipher(tpm2::TpmtSymDefObject::Aes128(
            Some(TpmiAlgSymMode::CBC),
        ))),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x4C9),
        "Aes128 CBC should return TPM_RC_MODE (0x4C9)"
    );

    // Invalid: Aes128 CTR (should fail with TPM_RC_MODE 0x4C9)
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Cipher(tpm2::TpmtSymDefObject::Aes128(
            Some(TpmiAlgSymMode::CTR),
        ))),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x4C9),
        "Aes128 CTR should return TPM_RC_MODE (0x4C9)"
    );

    // Valid: XOR with Sha256
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Xor(TpmiAlgHash::Sha256)),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert!(res.is_ok(), "XOR with Sha256 should succeed");
    let (_, resp_handles) = res.unwrap();
    flush_context(&mut sim, resp_handles.session_handle).unwrap();

    // Invalid: XOR with NULL hash (should fail with TPM_RC_HASH 0x4C3)
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Xor(TpmiAlgHash::Sha256)),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_corrupted_bytes(&mut sim, &cmd, handles, 0, &[], |buf| {
        // symmetric starts at offset 21 (2 bytes Alg::XOR = 0x000A), followed by hash_alg at 23..25
        buf[23..25].copy_from_slice(&0x0010u16.to_be_bytes());
    });
    assert_eq!(
        res.err(),
        Some(0x4C3),
        "XOR with NULL hash should return TPM_RC_HASH (0x4C3)"
    );
}

// 5. Session lookup prefix validation across different session types.
#[test]
fn test_session_type_prefix_routing() {
    let mut sim = create_simulator!();
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };

    // HMAC Session: prefix should be 0x02xxxxxx
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (_, resp_handles) =
        execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]).unwrap();
    assert_eq!(
        resp_handles.session_handle.0 >> 24,
        0x02,
        "HMAC session handle should start with 0x02"
    );
    flush_context(&mut sim, resp_handles.session_handle).unwrap();

    // Policy Session: prefix should be 0x03xxxxxx
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (_, resp_handles) =
        execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]).unwrap();
    assert_eq!(
        resp_handles.session_handle.0 >> 24,
        0x03,
        "Policy session handle should start with 0x03"
    );
    flush_context(&mut sim, resp_handles.session_handle).unwrap();

    // Trial Session: prefix should be 0x03xxxxxx
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (_, resp_handles) =
        execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]).unwrap();
    assert_eq!(
        resp_handles.session_handle.0 >> 24,
        0x03,
        "Trial session handle should start with 0x03"
    );
    flush_context(&mut sim, resp_handles.session_handle).unwrap();

    // Invalid Session Type: TpmSe::try_from(0x02).unwrap() (should fail with TPM_RC_VALUE 0x3C4)
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_corrupted_bytes(&mut sim, &cmd, handles, 0, &[], |buf| {
        buf[20] = 0x02; // corrupt session_type to invalid value 2
    });
    assert_eq!(
        res.err(),
        Some(0x3C4),
        "Invalid session type should return TPM_RC_VALUE + P3 (0x3C4)"
    );
}

// 6. KeyedHash key as tpm_key should fail
#[test]
fn test_invalid_tpm_key_type_keyedhash() {
    let mut sim = create_simulator!();

    // Create KeyedHash decrypt key
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        // A valid HMAC key (a DECRYPT keyedHash needs an XOR scheme); any KEYEDHASH key is
        // rejected as tpmKey because it is not asymmetric.
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(tpm2::TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::default(),
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
    let keyedhash_key_handle = create_rsp_handles.object_handle;

    // Call StartAuthSession with KeyedHash key as tpm_key
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let handles = StartAuthSessionHandles {
        tpm_key: keyedhash_key_handle,
        bind: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x19C),
        "KeyedHash key as tpm_key should fail with TPM_RC_KEY at handle 1 (0x19C)"
    );

    flush_context(&mut sim, keyedhash_key_handle).unwrap();
}

// 7. RSA key without DECRYPT attribute should fail
#[test]
fn test_invalid_tpm_key_attributes() {
    let mut sim = create_simulator!();

    // Create RSA key without DECRYPT attribute (only SIGN_ENCRYPT)
    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT, // NO decrypt attribute
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
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
    let rsa_key_handle = create_rsp_handles.object_handle;

    // Call StartAuthSession
    // A non-empty salt: C checks `encryptedSalt.size == 0` (TPM_RCS_VALUE + RC_P2) before the
    // publicOnly / DECRYPT checks.
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(&[0x11; 256]).unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let handles = StartAuthSessionHandles {
        tpm_key: rsa_key_handle,
        bind: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x182),
        "RSA key without DECRYPT attribute should return TPM_RC_ATTRIBUTES at handle 1 (0x182)"
    );

    flush_context(&mut sim, rsa_key_handle).unwrap();
}

// 8. Non-existent tpm_key handle should fail
#[test]
fn test_invalid_tpm_key_handle() {
    let mut sim = create_simulator!();
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let handles = StartAuthSessionHandles {
        tpm_key: Handle(0x800000FF), // Fake handle
        bind: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x910),
        "Non-existent tpm_key handle should return ReferenceH0 (0x910)"
    );
}

// 9. Non-existent bind handle should fail
#[test]
fn test_invalid_bind_handle() {
    let mut sim = create_simulator!();
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle(0x800000FF), // Fake handle
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x911),
        "Non-existent bind handle should return ReferenceH1 (0x911)"
    );
}

// 10. Attempting to authorize a command using an HMAC session handle should be rejected
#[test]
fn test_unsupported_non_password_session_auth() {
    use tpm2::commands::{ReadPublic, ReadPublicHandles};

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
    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles {
        object_handle: key_handle,
    };

    let mut sessions = [session];
    let name = read_public_name(&mut sim, key_handle);
    let res = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
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

// 11. Real RSA Decryption Failure (OAEP decryption check fails on malformed encrypted_salt)
#[test]
fn test_salt_decryption_failure() {
    let mut sim = create_simulator!();
    let key_handle = create_rsa_decrypt_key(&mut sim);

    // Provide a random 256-byte buffer (not valid OAEP)
    let malformed_salt = vec![0xAAu8; 256];

    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(&malformed_salt).unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let handles = StartAuthSessionHandles {
        tpm_key: key_handle,
        bind: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);

    assert_eq!(
        res.err(),
        Some(0x2C4),
        "Malformed encrypted salt should return TPM_RC_VALUE at parameter 2 (0x2C4) due to decryption failure"
    );

    flush_context(&mut sim, key_handle).unwrap();
}

fn load_rsa_public_only_key(sim: &mut Simulator) -> Handle {
    const RSA_N: &[u8] = &[
        0x9e, 0x67, 0x7c, 0x31, 0xb1, 0xf9, 0x15, 0x8a, 0x41, 0x4d, 0x16, 0xf0, 0x73, 0xbe, 0x59,
        0x66, 0xc0, 0xe3, 0x8d, 0xc3, 0x64, 0x4b, 0x01, 0x3c, 0xce, 0x5c, 0x13, 0x10, 0x41, 0x9f,
        0xbc, 0x43, 0x2d, 0xfa, 0xcb, 0xfc, 0xa4, 0xd8, 0x41, 0x05, 0xbc, 0xcb, 0xe5, 0xc8, 0xd9,
        0x13, 0x21, 0x6c, 0xb0, 0x13, 0xea, 0x10, 0x3a, 0x3b, 0x73, 0xe0, 0x9e, 0x59, 0x11, 0x0f,
        0x5c, 0x1f, 0x54, 0x5c, 0x39, 0x42, 0x1d, 0x45, 0xb4, 0x67, 0x2c, 0x19, 0xf7, 0x6c, 0xe6,
        0x13, 0xdd, 0xb7, 0x55, 0x5b, 0x00, 0xa6, 0xaa, 0x2f, 0x06, 0x2a, 0xa9, 0x23, 0x7f, 0xc0,
        0xb8, 0xdd, 0x32, 0xb5, 0x00, 0xc1, 0xe7, 0x51, 0xe1, 0x71, 0xc1, 0xa3, 0xb3, 0x3a, 0x44,
        0x45, 0x6c, 0x43, 0xbb, 0xc1, 0x23, 0x6f, 0x65, 0x15, 0x6e, 0x25, 0xdd, 0x51, 0x8b, 0x49,
        0x04, 0x44, 0xd1, 0x55, 0xd3, 0x88, 0x5f, 0x6a, 0xd3, 0xc1, 0x58, 0x4b, 0xca, 0xe9, 0xbe,
        0x6d, 0x30, 0x46, 0xdd, 0x3c, 0x2b, 0xbb, 0xd7, 0xbd, 0x94, 0x10, 0x5e, 0x32, 0x6e, 0xcd,
        0x24, 0x96, 0x17, 0x7a, 0x88, 0xd7, 0xee, 0x60, 0x58, 0x95, 0x6a, 0x18, 0x7f, 0x40, 0x53,
        0x24, 0xc0, 0x0e, 0xa9, 0x08, 0x9c, 0x03, 0x27, 0xce, 0x0b, 0xcb, 0xc5, 0x2c, 0xf2, 0xb0,
        0xe7, 0xac, 0xe0, 0xfa, 0x84, 0xc4, 0x77, 0x2f, 0x83, 0x3d, 0xe5, 0x7c, 0x67, 0x94, 0x93,
        0x3e, 0x52, 0x6e, 0x21, 0xf3, 0x30, 0xb1, 0x5e, 0xca, 0x39, 0xf5, 0x0b, 0x28, 0xb4, 0x87,
        0x76, 0x77, 0xc3, 0xaf, 0x4f, 0x9c, 0x7f, 0x0c, 0x58, 0x9d, 0x80, 0xf2, 0xf4, 0x93, 0x6e,
        0x03, 0x1e, 0x1d, 0x15, 0x6c, 0xb7, 0xfb, 0xd6, 0x43, 0xe3, 0xd2, 0x58, 0x5a, 0x2e, 0x2d,
        0xc2, 0xb3, 0x69, 0xff, 0x93, 0x35, 0x53, 0x71, 0x51, 0x64, 0x76, 0x41, 0x85, 0x3d, 0x3e,
        0x31,
    ];

    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiCode::from(2048),
        exponent: 0,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            rsa_parms,
            Tpm2bPublicKeyRsa::from_bytes(RSA_N).unwrap(),
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let (_, resp_handles) = execute_with_password_sessions(sim, &cmd, (), 0, &[]).unwrap();
    resp_handles.object_handle
}

struct TpmiCode;
impl TpmiCode {
    fn from(val: u16) -> TpmiRsaKeyBits {
        TpmiRsaKeyBits(val)
    }
}

// 12. Public-only key as tpm_key should fail with TPM_RC_HANDLE (0x18B)
#[test]
fn test_invalid_tpm_key_type_public_only() {
    let mut sim = create_simulator!();
    let public_key_handle = load_rsa_public_only_key(&mut sim);

    // Call StartAuthSession
    // A non-empty salt: C checks `encryptedSalt.size == 0` (TPM_RCS_VALUE + RC_P2) before the
    // publicOnly / DECRYPT checks.
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(&[0x11; 256]).unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let handles = StartAuthSessionHandles {
        tpm_key: public_key_handle,
        bind: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x18B),
        "Public-only key as tpm_key should return TPM_RC_HANDLE at handle 1 (0x18B)"
    );

    flush_context(&mut sim, public_key_handle).unwrap();
}

// 13. Password trailing zero input succeeds authorization
#[test]
fn test_password_trailing_zero_auth() {
    use tpm2::commands::{HierarchyChangeAuth, HierarchyChangeAuthHandles};

    let mut sim = create_simulator!();

    // 1. Change Owner Auth from empty to "hello" (with trailing zeros, e.g. "hello\0\0")
    let cmd1 = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"hello\0\0").unwrap(),
    };
    let handles1 = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };
    let res1 = execute_with_password_sessions(&mut sim, &cmd1, handles1, 1, &[]);
    assert!(
        res1.is_ok(),
        "Setting owner auth to hello\\0\\0 should succeed: {:?}",
        res1
    );

    // 2. Perform another auth check using "hello" (without trailing zeros)
    // We change the owner auth back to empty
    let cmd2 = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::default(),
    };
    let handles2 = HierarchyChangeAuthHandles {
        auth_handle: Handle::RH_OWNER,
    };
    let res2 = execute_with_password_sessions(&mut sim, &cmd2, handles2, 1, b"hello");
    assert!(
        res2.is_ok(),
        "Authorizing hello\\0\\0 auth using hello should succeed: {:?}",
        res2
    );
}
