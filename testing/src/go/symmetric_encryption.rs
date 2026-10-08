#![forbid(unsafe_code)]

use crate::test_utils::{execute_with_password_sessions, flush_context};
use rand::{RngCore, thread_rng};
use tpm2::Handle;
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, EncryptDecrypt2, EncryptDecrypt2Handles,
};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bIv, Tpm2bMaxBuffer, Tpm2bSensitiveData,
    TpmaObject, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmsSensitiveCreate, TpmtPublic,
    TpmtSymDefObject,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn encrypt_decrypt_symmetric(
    sim: &mut Simulator<'_>,
    key_handle: Handle,
    mut iv: Vec<u8>,
    data: &[u8],
    mode: TpmiAlgCipherMode,
    decrypt: bool,
) -> Result<Vec<u8>, u32> {
    const MAX_DIGEST_BUFFER: usize = 1024;
    let mut out = Vec::new();
    let mut rest = data;

    while !rest.is_empty() {
        let (block, next_rest) = if rest.len() > MAX_DIGEST_BUFFER {
            (&rest[..MAX_DIGEST_BUFFER], &rest[MAX_DIGEST_BUFFER..])
        } else {
            (rest, &[][..])
        };
        rest = next_rest;

        let cmd = EncryptDecrypt2 {
            in_data: Tpm2bMaxBuffer::from_bytes(block).unwrap(),
            decrypt,
            mode: Some(mode),
            iv_in: Tpm2bIv::from_bytes(&iv).unwrap(),
        };
        let handles = EncryptDecrypt2Handles { key_handle };
        let (resp, _) = execute_with_password_sessions(sim, &cmd, handles, 1, &[])?;

        let out_block = resp.out_data.get_buffer();
        out.extend_from_slice(out_block);
        iv = resp.iv_out.get_buffer().to_vec();
    }
    Ok(out)
}

// Original Go test: symmetric_encryption_test.go - TestAESEncryption
#[test]
fn test_aes_encryption() {
    let mut sim = create_simulator!();

    // 1. Create Primary Key (AES)
    let sym_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::default(),
        ),
    };
    let create_primary_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(sym_template),
        ..Default::default()
    };
    let create_primary_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, create_primary_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_cmd,
        create_primary_handles,
        0,
        &[],
    )
    .expect("CreatePrimary failed");
    let primary_handle = create_primary_resp_handles.object_handle;

    let message = b"secret";

    let mut iv = [0u8; 16];
    thread_rng().fill_bytes(&mut iv);

    // test encryption
    let encrypt_cmd = EncryptDecrypt2 {
        in_data: Tpm2bMaxBuffer::from_bytes(message).unwrap(),
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::CFB),
        iv_in: Tpm2bIv::from_bytes(&iv).unwrap(),
    };
    let encrypt_handles = EncryptDecrypt2Handles {
        key_handle: primary_handle,
    };
    let (encrypt_resp, _) =
        execute_with_password_sessions(&mut sim, &encrypt_cmd, encrypt_handles, 1, &[])
            .expect("EncryptDecrypt2 encryption failed");

    // test decryption
    let decrypt_cmd = EncryptDecrypt2 {
        in_data: encrypt_resp.out_data,
        decrypt: true,
        mode: Some(TpmiAlgCipherMode::CFB),
        iv_in: Tpm2bIv::from_bytes(&iv).unwrap(),
    };
    let decrypt_handles = EncryptDecrypt2Handles {
        key_handle: primary_handle,
    };
    let (decrypt_resp, _) =
        execute_with_password_sessions(&mut sim, &decrypt_cmd, decrypt_handles, 1, &[])
            .expect("EncryptDecrypt2 decryption failed");

    assert_eq!(
        decrypt_resp.out_data.get_buffer(),
        message,
        "Decrypted message does not match original"
    );

    flush_context(&mut sim, primary_handle).unwrap();
}

// Original Go test: symmetric_encryption_test.go - TestAESEncryptionBlock
#[test]
fn test_aes_encryption_block() {
    let mut sim = create_simulator!();

    // 1. Create Primary Key (AES)
    let sym_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::default(),
        ),
    };
    let create_primary_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(sym_template),
        ..Default::default()
    };
    let create_primary_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, create_primary_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_cmd,
        create_primary_handles,
        0,
        &[],
    )
    .expect("CreatePrimary failed");
    let primary_handle = create_primary_resp_handles.object_handle;

    let mut message = vec![0u8; 2048];
    thread_rng().fill_bytes(&mut message);

    let mut iv = vec![0u8; 16];
    thread_rng().fill_bytes(&mut iv);

    let encrypted = encrypt_decrypt_symmetric(
        &mut sim,
        primary_handle,
        iv.clone(),
        &message,
        TpmiAlgCipherMode::CFB,
        false,
    )
    .expect("Symmetric encryption failed");

    let decrypted = encrypt_decrypt_symmetric(
        &mut sim,
        primary_handle,
        iv,
        &encrypted,
        TpmiAlgCipherMode::CFB,
        true,
    )
    .expect("Symmetric decryption failed");

    assert_eq!(
        message, decrypted,
        "Decrypted message does not match original"
    );

    flush_context(&mut sim, primary_handle).unwrap();
}
