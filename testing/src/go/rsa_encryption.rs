#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::{Create, CreatePrimary, Load, RSADecrypt, RSAEncrypt};
use tpm2::*;
use tpm2_simulator::create_simulator;

/// go-tpm's `RSASRKTemplate`.
fn get_rsa_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                }),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&[0u8; 256]).unwrap(),
        ),
    }
}

// Original Go test: rsa_encryption_test.go - TestRSAEncryption
#[test]
fn test_rsa_encryption() {
    let mut sim = create_simulator!();

    // 1. Create Primary Key (RSA SRK)
    let srk_pub = get_rsa_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
        ..Default::default()
    };
    let create_primary_resp = execute_with_password_sessions(&mut sim, &create_primary_cmd, 1, &[])
        .expect("CreatePrimary failed");
    let srk_handle = create_primary_resp.object_handle;

    // 2. Create Child RSA Decrypt Key
    let child_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&[0u8; 256]).unwrap(),
        ),
    };
    let create_cmd = Create {
        parent_handle: srk_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(child_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_resp =
        execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).expect("Create failed");

    // 3. Load the Child Key
    let load_cmd = Load {
        parent_handle: srk_handle,
        in_private: create_resp.out_private,
        in_public: create_resp.out_public,
    };
    let load_resp =
        execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]).expect("Load failed");
    let key_handle = load_resp.object_handle;

    // 4. RSA Encrypt a message
    let message_bytes = b"secret";
    let message = Tpm2bPublicKeyRsa::from_bytes(message_bytes).unwrap();
    let encrypt_cmd = RSAEncrypt {
        key_handle,
        message,
        in_scheme: Some(TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha256)),
        label: Tpm2bData::default(),
    };
    let encrypt_resp =
        execute_with_password_sessions(&mut sim, &encrypt_cmd, 0, &[]).expect("RSAEncrypt failed");

    // 5. RSA Decrypt the ciphertext
    let decrypt_cmd = RSADecrypt {
        key_handle,
        cipher_text: encrypt_resp.out_data,
        in_scheme: Some(TpmtRsaDecrypt::Oaep(TpmiAlgHash::Sha256)),
        label: Tpm2bData::default(),
    };
    let decrypt_resp =
        execute_with_password_sessions(&mut sim, &decrypt_cmd, 1, &[]).expect("RSADecrypt failed");

    assert_eq!(
        decrypt_resp.message.get_buffer(),
        message_bytes,
        "Decrypted message does not match original message"
    );

    // Cleanup
    flush_context(&mut sim, key_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}
