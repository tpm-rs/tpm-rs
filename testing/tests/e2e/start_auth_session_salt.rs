//! Salted sessions: tpmKey requirements and encryptedSalt validation.

use crate::_common::{
    client_rng, create_rsa_decrypt_key, execute_with_password_sessions, flush_context, leak_bytes,
    load_rsa_public_only_key,
};
use rsa::{Oaep, RsaPublicKey};
use testing::tpm::Tpm;
use tpm2::commands::{CreatePrimary, StartAuthSession};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmSe, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits,
    TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic,
};

/// A non-empty encryptedSalt with tpmKey RH_NULL fails with VALUE; with a decrypt key a valid salt is accepted.
///
/// 2. Encrypted salt presence/absence when tpmKey is RHNull vs. valid decrypt key.
#[test]
fn encrypted_salt_requires_tpm_key() {
    let mut sim = Tpm::new();

    // When tpmKey is RHNull, encrypted_salt must be empty.
    // If not empty (e.g. 10 bytes), should fail with TPM_RC_VALUE (0x2C4)
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(&[1u8; 10]).unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x2C4),
        "Non-empty salt with RHNull should return TPM_RC_VALUE (0x2C4)"
    );

    // When tpmKey is a valid decrypt key
    let key_handle = create_rsa_decrypt_key(&mut sim);

    // Retrieve the public key modulus to encrypt a valid salt
    let read_cmd = tpm2::commands::ReadPublic {
        object_handle: key_handle,
    };
    let read_rsp = execute_with_password_sessions(&mut sim, &read_cmd, 0, &[]).unwrap();
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

    let mut rng = client_rng();
    let salt = vec![5u8; 32];
    let oaep = Oaep::new_with_label::<sha2::Sha256, _>("SECRET\0");
    let enc_salt = rsa.encrypt(&mut rng, oaep, &salt).unwrap();

    let cmd = StartAuthSession {
        tpm_key: key_handle,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(leak_bytes(&enc_salt)).unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(
        res.is_ok(),
        "Valid encrypted salt should succeed: {:?}",
        res
    );
    let rsp = res.unwrap();
    flush_context(&mut sim, rsp.session_handle).unwrap();

    flush_context(&mut sim, key_handle).unwrap();
}

/// A keyed-hash object as tpmKey is rejected (not asymmetric).
///
/// 6. KeyedHash key as tpm_key should fail
#[test]
fn keyedhash_tpm_key_rejected() {
    let mut sim = Tpm::new();

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
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    let keyedhash_key_handle = create_rsp.object_handle;

    // Call StartAuthSession with KeyedHash key as tpm_key
    let cmd = StartAuthSession {
        tpm_key: keyedhash_key_handle,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x19C),
        "KeyedHash key as tpm_key should fail with TPM_RC_KEY at handle 1 (0x19C)"
    );

    flush_context(&mut sim, keyedhash_key_handle).unwrap();
}

/// A random 256-byte encryptedSalt that fails OAEP decryption is rejected.
///
/// 11. Real RSA Decryption Failure (OAEP decryption check fails on malformed encrypted_salt)
#[test]
fn malformed_encrypted_salt_rejected() {
    let mut sim = Tpm::new();
    let key_handle = create_rsa_decrypt_key(&mut sim);

    // Provide a random 256-byte buffer (not valid OAEP)
    let malformed_salt = vec![0xAAu8; 256];

    let cmd = StartAuthSession {
        tpm_key: key_handle,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(&malformed_salt).unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);

    assert_eq!(
        res.err(),
        Some(0x2C4),
        "Malformed encrypted salt should return TPM_RC_VALUE at parameter 2 (0x2C4) due to decryption failure"
    );

    flush_context(&mut sim, key_handle).unwrap();
}

/// A public-only RSA key as tpmKey is rejected.
///
/// 12. Public-only key as tpm_key should fail with TPM_RC_HANDLE (0x18B)
#[test]
fn public_only_tpm_key_rejected() {
    let mut sim = Tpm::new();
    let public_key_handle = load_rsa_public_only_key(&mut sim);

    // Call StartAuthSession
    // A non-empty salt: C checks `encryptedSalt.size == 0` (TPM_RCS_VALUE + RC_P2) before the
    // publicOnly / DECRYPT checks.
    let cmd = StartAuthSession {
        tpm_key: public_key_handle,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(&[0x11; 256]).unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x18B),
        "Public-only key as tpm_key should return TPM_RC_HANDLE at handle 1 (0x18B)"
    );

    flush_context(&mut sim, public_key_handle).unwrap();
}

/// A salt of the nameAlg digest size is accepted and a larger salt is rejected.
///
/// 3. Salt size checks (matching nameAlg digest size boundaries).
#[test]
fn salt_size_bounded_by_name_alg() {
    let mut sim = Tpm::new();
    let key_handle = create_rsa_decrypt_key(&mut sim);

    let read_cmd = tpm2::commands::ReadPublic {
        object_handle: key_handle,
    };
    let read_rsp = execute_with_password_sessions(&mut sim, &read_cmd, 0, &[]).unwrap();
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

    let mut rng = client_rng();

    // Valid salt size: 32 (exact boundary for SHA256 nameAlg)
    let salt = vec![5u8; 32];
    let oaep = Oaep::new_with_label::<sha2::Sha256, _>("SECRET\0");
    let enc_salt = rsa.encrypt(&mut rng, oaep, &salt).unwrap();
    let cmd = StartAuthSession {
        tpm_key: key_handle,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(leak_bytes(&enc_salt)).unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(res.is_ok(), "Salt size 32 should succeed");
    let rsp = res.unwrap();
    flush_context(&mut sim, rsp.session_handle).unwrap();

    // Invalid salt size: 33 (too large for SHA256 nameAlg)
    let salt = vec![5u8; 33];
    let oaep_err = Oaep::new_with_label::<sha2::Sha256, _>("SECRET\0");
    let enc_salt = rsa.encrypt(&mut rng, oaep_err, &salt).unwrap();
    let cmd = StartAuthSession {
        tpm_key: key_handle,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(leak_bytes(&enc_salt)).unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x2C4),
        "Salt size 33 should fail with TPM_RC_VALUE (0x2C4)"
    );

    flush_context(&mut sim, key_handle).unwrap();
}

/// An RSA key without the decrypt attribute as tpmKey is rejected.
///
/// 7. RSA key without DECRYPT attribute should fail
#[test]
fn tpm_key_without_decrypt_rejected() {
    let mut sim = Tpm::new();

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
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    let rsa_key_handle = create_rsp.object_handle;

    // Call StartAuthSession
    // A non-empty salt: C checks `encryptedSalt.size == 0` (TPM_RCS_VALUE + RC_P2) before the
    // publicOnly / DECRYPT checks.
    let cmd = StartAuthSession {
        tpm_key: rsa_key_handle,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(&[0x11; 256]).unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x182),
        "RSA key without DECRYPT attribute should return TPM_RC_ATTRIBUTES at handle 1 (0x182)"
    );

    flush_context(&mut sim, rsa_key_handle).unwrap();
}

/// A non-existent tpmKey handle is rejected.
///
/// 8. Non-existent tpm_key handle should fail
#[test]
fn unloaded_tpm_key_handle_rejected() {
    let mut sim = Tpm::new();
    let cmd = StartAuthSession {
        tpm_key: Handle::TRANSIENT_LAST, // Unloaded transient handle
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x910),
        "Non-existent tpm_key handle should return ReferenceH0 (0x910)"
    );
}
