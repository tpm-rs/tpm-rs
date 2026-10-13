//! TPM2_RSA_Encrypt / TPM2_RSA_Decrypt: key type/attribute checks, ciphertext sizes and error
//! positions.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{LoadExternal, RSADecrypt, RSAEncrypt};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bLabel, Tpm2bPublicKeyRsa,
    Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmtRsaScheme, TpmtSensitive,
    TpmuSensitiveComposite, *,
};

/// RSA_Encrypt accepts restricted keys; RSA_Decrypt checks type first, ciphertext size and reports label/scheme errors at parameter positions.
///
/// RSA_Encrypt accepts restricted decryption keys; RSA_Decrypt checks the type first, the
/// ciphertext size, and reports label / scheme errors at parameter positions.
#[test]
fn attribute_type_and_error_position_checks() {
    let mut sim = Tpm::new();

    // Restricted RSA storage key: RSA_Encrypt only uses the public part.
    let srk = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        rsa_template_with_symmetric(
            base_attrs() | TpmaObject::RESTRICTED | TpmaObject::DECRYPT,
            None,
            Some(AES128_CFB),
        ),
        b"",
    );
    let enc = RSAEncrypt {
        key_handle: srk,
        message: Tpm2bPublicKeyRsa::from_bytes(b"secret").unwrap(),
        in_scheme: Some(TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha256)),
        label: Tpm2bData::default(),
    };
    execute_with_password_sessions(&mut sim, &enc, 0, &[])
        .expect("RSA_Encrypt must accept a restricted decryption key");

    // Unterminated label -> TPM_RC_VALUE + RC_P3.
    let enc_bad_label = RSAEncrypt {
        key_handle: srk,
        message: Tpm2bPublicKeyRsa::from_bytes(b"secret").unwrap(),
        in_scheme: Some(TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha256)),
        label: Tpm2bData::from_bytes(b"abc").unwrap(),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &enc_bad_label, 0, &[]).unwrap_err(),
        rc_at(TpmRc::VALUE, Position::parameter(3))
    );

    // Unrestricted RSA decryption key with an OAEP-SHA256 scheme.
    let dec_key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        rsa_template_with_symmetric(
            base_attrs() | TpmaObject::DECRYPT,
            Some(TpmtRsaScheme::Oaep(TpmiAlgHash::Sha256)),
            None,
        ),
        b"",
    );
    // Scheme mismatch -> TPM_RC_SCHEME + RC_P2.
    let dec_bad_scheme = RSADecrypt {
        key_handle: dec_key,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[1u8; 256]).unwrap(),
        in_scheme: Some(TpmtRsaDecrypt::Rsaes),
        label: Tpm2bData::default(),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &dec_bad_scheme, 1, &[]).unwrap_err(),
        rc_at(TpmRc::SCHEME, Position::parameter(2))
    );
    // Ciphertext not the size of the modulus -> bare TPM_RC_SIZE.
    let dec_short = RSADecrypt {
        key_handle: dec_key,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[1u8; 16]).unwrap(),
        in_scheme: None,
        label: Tpm2bData::default(),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &dec_short, 1, &[]).unwrap_err(),
        rc_bare(TpmRc::SIZE)
    );

    // Restricted ECC key: not an RSA key -> TPM_RC_KEY + RC_H1 (type before attributes).
    let ecc_srk = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_storage_template_derived(),
        b"",
    );
    let dec = RSADecrypt {
        key_handle: ecc_srk,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[1u8; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bData::default(),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &dec, 1, &[]).unwrap_err(),
        rc_at(TpmRc::KEY, Position::handle(1))
    );
    // Restricted RSA key -> TPM_RC_ATTRIBUTES + RC_H1.
    assert_eq!(
        execute_with_password_sessions(
            &mut sim,
            &RSADecrypt {
                key_handle: srk,
                ..dec
            },
            1,
            &[]
        )
        .unwrap_err(),
        rc_at(TpmRc::ATTRIBUTES, Position::handle(1))
    );
}

/// TPM2_RSA_Decrypt with a loaded signing-only RSA key fails with TPM_RC_ATTRIBUTES
///
/// Test RSADecrypt fails with TPM_RC_KEY if key lacks DECRYPT attribute.
#[test]
fn rsa_decrypt_rejects_key_without_decrypt() {
    let mut sim = Tpm::new();

    let object_handle = load_rsa_with_private(&mut sim, TpmaObject::SIGN_ENCRYPT, None);

    let decrypt_cmd = LocalRSADecryptCmd {
        key_handle: object_handle,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bLabel::default(),
    };
    let res = exec_pw(&mut sim, decrypt_cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    // RSA_Decrypt.c: restricted || !decrypt -> TPM_RCS_ATTRIBUTES + RC_RSA_Decrypt_keyHandle.
    assert_eq!(err.get(), TpmRc::ATTRIBUTES.with(Position::handle(1)).get());

    flush_context(&mut sim, object_handle).unwrap();
}

/// TPM2_RSA_Decrypt with a keyed-hash key fails with TPM_RC_KEY on keyHandle
///
/// 9. Test RSADecrypt with non-RSA key type (e.g. KeyedHash key).
///
/// Expected: TPM_RC_KEY.
#[test]
fn rsa_decrypt_rejects_keyed_hash_key() {
    let mut sim = Tpm::new();

    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::DECRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: Some(tpm2::Tpm2b(TpmtSensitive {
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
            sensitive: TpmuSensitiveComposite::KeyedHash(
                Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
            ),
        })),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let object_handle = sim.execute(load_cmd).unwrap().object_handle;

    let decrypt_cmd = LocalRSADecryptCmd {
        key_handle: object_handle,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bLabel::default(),
    };
    let res = exec_pw(&mut sim, decrypt_cmd);
    assert!(
        res.is_err(),
        "RSADecrypt should fail when key type is not RSA"
    );
    let err = res.err().unwrap();
    // RSA_Decrypt.c: TPM_RCS_KEY + RC_RSA_Decrypt_keyHandle.
    assert_eq!(err.get(), TpmRc::KEY.with(Position::handle(1)).get());

    flush_context(&mut sim, object_handle).unwrap();
}

/// TPM2_RSA_Decrypt with a restricted RSA storage key fails with TPM_RC_ATTRIBUTES
///
/// Test RSADecrypt fails on a restricted key handle returning TPM_RC_ATTRIBUTES.
#[test]
fn rsa_decrypt_rejects_restricted_key() {
    let mut sim = Tpm::new();

    // LoadExternal can't load a restricted key with its sensitive area (and a public-only key
    // fails USER authorization), so let the TPM create a restricted RSA storage key.
    let mut public = make_rsa_public_area(
        &[],
        TpmiAlgHash::Sha256,
        TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN,
    );
    if let PublicParmsAndId::Rsa(parms, _) = &mut public.parms_and_id {
        parms.symmetric = Some(AES128_CFB);
    }
    let object_handle = create_primary_null(&mut sim, public);

    let decrypt_cmd = LocalRSADecryptCmd {
        key_handle: object_handle,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bLabel::default(),
    };
    let res = exec_pw(&mut sim, decrypt_cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    // RSA_Decrypt.c: TPM_RCS_ATTRIBUTES + RC_RSA_Decrypt_keyHandle.
    assert_eq!(err.get(), TpmRc::ATTRIBUTES.with(Position::handle(1)).get());

    flush_context(&mut sim, object_handle).unwrap();
}

/// Raw TPM2_RSA_Decrypt with a restricted RSA decryption primary fails with TPM_RC_ATTRIBUTES
#[test]
fn rsa_decrypt_rejects_restricted_key_raw() {
    let mut sim = Tpm::new();
    // A restricted decryption key needs a symmetric algorithm to be creatable.
    let (key, _) = create_primary_returning_public(
        &mut sim,
        rsa_public_with_symmetric(
            TpmaObject::DECRYPT | TpmaObject::RESTRICTED | sdo_user(),
            Some(AES128_CFB),
        ),
        &[],
    );

    let error_code = send_key_command(&mut sim, CC_RSA_DECRYPT, key, true, &rsa_decrypt_params());
    assert_eq!(
        error_code,
        0x00000182, // TPM_RC_ATTRIBUTES + RC_RSA_Decrypt_keyHandle (RSA_Decrypt.c)
        "Expected TPM_RC_ATTRIBUTES + H1 (0x182) for restricted key decrypt! error_code = 0x{:08X}",
        error_code
    );
}

/// Raw TPM2_RSA_Decrypt with a signing-only RSA primary fails with TPM_RC_ATTRIBUTES
#[test]
fn rsa_decrypt_rejects_signing_only_key_raw() {
    let mut sim = Tpm::new();
    let (key, _) = create_primary_returning_public(
        &mut sim,
        rsa_public_with_symmetric(TpmaObject::SIGN_ENCRYPT | sdo_user(), None),
        &[],
    );

    let error_code = send_key_command(&mut sim, CC_RSA_DECRYPT, key, true, &rsa_decrypt_params());
    assert_eq!(
        error_code,
        0x00000182, // TPM_RC_ATTRIBUTES + RC_RSA_Decrypt_keyHandle (RSA_Decrypt.c)
        "Expected TPM_RC_ATTRIBUTES + H1 (0x182), got error_code = 0x{:08X}",
        error_code
    );
}

/// TPM2_RSA_Decrypt on a non-existent key handle fails with TPM_RC_REFERENCE_H0
///
/// 10. Test RSADecrypt with an invalid handle.
///
/// Expected: TPM_RC_HANDLE.
#[test]
fn rsa_decrypt_rejects_unloaded_key_handle() {
    let mut sim = Tpm::new();
    let decrypt_cmd = LocalRSADecryptCmd {
        key_handle: Handle(0x8000000E),
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bLabel::default(),
    };
    let res = exec_pw(&mut sim, decrypt_cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::REFERENCE_H0.get());
}
