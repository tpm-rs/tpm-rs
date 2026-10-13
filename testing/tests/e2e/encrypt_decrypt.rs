//! TPM2_EncryptDecrypt / TPM2_EncryptDecrypt2: mode and decrypt-flag validation, public-only keys
//! and IV handling.

#![allow(deprecated)] // TPM2_EncryptDecrypt is deprecated upstream but still implemented.

use crate::_common::{
    AES128_CFB, create_aes_key, execute_with_corrupted_bytes, execute_with_corrupted_bytes_status,
    execute_with_password_sessions, load_public_only_sym_key, try_create_aes_key,
};
use tpm2::commands::{CreatePrimary, EncryptDecrypt, EncryptDecrypt2};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bIv, Tpm2bMaxBuffer, Tpm2bSensitiveData,
    TpmaObject, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmsSensitiveCreate, TpmtPublic,
};
use tpm2_simulator::create_simulator;

/// CMAC is not implemented: an AES key with CMAC mode is rejected by CreatePrimary
/// (TPM_RC_MODE + RC_P2) and CMAC as EncryptDecrypt(2) mode parameter fails to unmarshal
/// (TPM_RC_MODE)
#[test]
fn cmac_mode_rejected() {
    let mut sim = create_simulator!();
    // 1. `TPMI_ALG_SYM_MODE` excludes unimplemented modes, so the CMAC key template of
    //    TPM2_CreatePrimary (parameter 2, inPublic) fails with TPM_RC_MODE + TPM_RC_P + TPM_RC_2.
    assert_eq!(
        try_create_aes_key(&mut sim, TpmiAlgSymMode::Cmac).unwrap_err(),
        TpmRc::MODE.with(Position::parameter(2)).get()
    );
    let key_handle = create_aes_key(&mut sim, TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb));

    let cmd = EncryptDecrypt {
        key_handle,
        decrypt: false,
        mode: None,
        iv_in: Tpm2bIv::from_bytes(&[0u8; 16]).unwrap(),
        in_data: Tpm2bMaxBuffer::from_bytes(&[0u8; 16]).unwrap(),
    };
    // 2. EncryptDecrypt with mode parameter corrupted to TPM_ALG_CMAC (0x003F) -> unmarshalling fails with TPM_RC_MODE + TPM_RC_P + TPM_RC_2
    let res_param = execute_with_corrupted_bytes_status(&mut sim, &cmd, 1, b"password", |buf| {
        // decrypt is at index 0 (1 byte); mode is at index 1..3 (2 bytes)
        buf[1..3].copy_from_slice(&0x003Fu16.to_be_bytes());
    });
    assert_eq!(
        res_param.err().unwrap(),
        TpmRc::MODE.with(Position::parameter(2)).get()
    );

    // 3. EncryptDecrypt2 with mode parameter corrupted to TPM_ALG_CMAC (0x003F) -> unmarshalling fails with TPM_RC_MODE + TPM_RC_P + TPM_RC_3
    let cmd2 = EncryptDecrypt2 {
        key_handle,
        in_data: Tpm2bMaxBuffer::from_bytes(&[0u8; 16]).unwrap(),
        decrypt: false,
        mode: None,
        iv_in: Tpm2bIv::from_bytes(&[0u8; 16]).unwrap(),
    };
    let res_param2 = execute_with_corrupted_bytes_status(&mut sim, &cmd2, 1, b"password", |buf| {
        // in_data size is 2 bytes (16) + 16 bytes = 18 bytes; decrypt is at index 18 (1 byte); mode is at index 19..21 (2 bytes)
        buf[19..21].copy_from_slice(&0x003Fu16.to_be_bytes());
    });
    assert_eq!(
        res_param2.err().unwrap(),
        TpmRc::MODE.with(Position::parameter(3)).get()
    );
}

/// EncryptDecrypt2 with decrypt byte corrupted to a non-boolean is TPM_RC_VALUE + RC_P2
#[test]
fn encrypt_decrypt2_decrypt_flag_value_rejected() {
    let mut sim = create_simulator!();
    let key_handle = create_aes_key(&mut sim, TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb));

    let cmd = EncryptDecrypt2 {
        key_handle,
        in_data: Tpm2bMaxBuffer::default(),
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::Cfb),
        iv_in: Tpm2bIv::default(),
    };

    let res = execute_with_corrupted_bytes_status(&mut sim, &cmd, 1, b"password", |buf| {
        buf[2] = 2; // in_data is empty (2 bytes size = 0), decrypt is at index 2 (1 byte)
    });
    // Since bool unmarshalling fails, it returns TPM_RC_VALUE + TPM_RC_P + TPM_RC_2 (0x2C4)
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE.with(Position::parameter(2)).get()
    );
}

/// TPM2_EncryptDecrypt2 with a decrypt TPMI_YES_NO value other than 0/1 fails with TPM_RC_VALUE + P2
#[test]
fn encrypt_decrypt2_rejects_invalid_decrypt_flag() {
    let mut sim = create_simulator!();

    // Create a symmetric key first
    let sym_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(AES128_CFB, Tpm2bDigest::default()),
    };
    let create_primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(sym_template),
        ..Default::default()
    };
    let cp_resp = execute_with_password_sessions(&mut sim, &create_primary_cmd, 1, &[]).unwrap();
    let key_handle = cp_resp.object_handle;

    let cmd = EncryptDecrypt2 {
        key_handle,
        in_data: Tpm2bMaxBuffer::default(),
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::Cfb),
        iv_in: Tpm2bIv::default(),
    };

    let res = execute_with_corrupted_bytes(&mut sim, &cmd, 1, &[], |buf| {
        buf[2] = 2; // in_data is empty (2 bytes size = 0), decrypt is at index 2 (1 byte)
    });
    // Expected unmarshal error: Value + parameter 2 (708 / 0x02C4)
    assert_eq!(
        res.err(),
        Some(
            tpm2::errors::TpmRc::VALUE
                .with(tpm2::errors::Position::parameter(2))
                .get()
        ),
        "EncryptDecrypt2 with invalid decrypt should return TPM_RC_VALUE + TPM_RC_P + TPM_RC_2"
    );
}

/// EncryptDecrypt with decrypt byte corrupted to a non-boolean is TPM_RC_VALUE + RC_P1
#[test]
fn encrypt_decrypt_decrypt_flag_value_rejected() {
    let mut sim = create_simulator!();
    let key_handle = create_aes_key(&mut sim, TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb));

    let cmd = EncryptDecrypt {
        key_handle,
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::Cfb),
        iv_in: Tpm2bIv::default(),
        in_data: Tpm2bMaxBuffer::default(),
    };

    let res = execute_with_corrupted_bytes_status(&mut sim, &cmd, 1, b"password", |buf| {
        buf[0] = 2; // decrypt is the first parameter (1 byte)
    });
    // Since bool unmarshalling fails, it returns TPM_RC_VALUE + TPM_RC_P + TPM_RC_1 (0x1C4)
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
}

/// TPM2_EncryptDecrypt and TPM2_EncryptDecrypt2 with mode TPM_ALG_CMAC fail with TPM_RC_MODE
#[test]
fn encrypt_decrypt_rejects_cmac_mode() {
    let mut sim = create_simulator!();

    // Create a valid symmetric key
    let sym_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(AES128_CFB, Tpm2bDigest::default()),
    };
    let create_primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(sym_template),
        ..Default::default()
    };
    let cp_resp = execute_with_password_sessions(&mut sim, &create_primary_cmd, 1, &[]).unwrap();
    let key_handle = cp_resp.object_handle;

    // 1. EncryptDecrypt with mode corrupted to TPM_ALG_CMAC (0x003F)
    let cmd = EncryptDecrypt {
        key_handle,
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::Cfb),
        iv_in: Tpm2bIv::from_bytes(&[0u8; 16]).unwrap(),
        in_data: Tpm2bMaxBuffer::from_bytes(&[0u8; 16]).unwrap(),
    };
    let res = execute_with_corrupted_bytes(&mut sim, &cmd, 1, &[], |buf| {
        // decrypt is 1 byte at offset 0; mode is 2 bytes at offset 1..3
        buf[1..3].copy_from_slice(&0x003Fu16.to_be_bytes());
    });
    assert_eq!(
        res.err(),
        Some(
            tpm2::errors::TpmRc::MODE
                .with(tpm2::errors::Position::parameter(2))
                .get()
        ),
        "EncryptDecrypt with TPM_ALG_CMAC mode should return TPM_RC_MODE + TPM_RC_P + TPM_RC_2"
    );

    // 2. EncryptDecrypt2 with mode corrupted to TPM_ALG_CMAC (0x003F)
    let cmd2 = EncryptDecrypt2 {
        key_handle,
        in_data: Tpm2bMaxBuffer::default(),
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::Cfb),
        iv_in: Tpm2bIv::from_bytes(&[0u8; 16]).unwrap(),
    };
    let res2 = execute_with_corrupted_bytes(&mut sim, &cmd2, 1, &[], |buf| {
        // in_data size is 2 bytes (0) at offset 0..2; decrypt is 1 byte at offset 2; mode is 2 bytes at offset 3..5
        buf[3..5].copy_from_slice(&0x003Fu16.to_be_bytes());
    });
    assert_eq!(
        res2.err(),
        Some(
            tpm2::errors::TpmRc::MODE
                .with(tpm2::errors::Position::parameter(3))
                .get()
        ),
        "EncryptDecrypt2 with TPM_ALG_CMAC mode should return TPM_RC_MODE + TPM_RC_P + TPM_RC_3"
    );
}

/// TPM2_EncryptDecrypt with a decrypt TPMI_YES_NO value other than 0/1 fails with TPM_RC_VALUE + P1
#[test]
fn encrypt_decrypt_rejects_invalid_decrypt_flag() {
    let mut sim = create_simulator!();

    // Create a symmetric key first
    let sym_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(AES128_CFB, Tpm2bDigest::default()),
    };
    let create_primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(sym_template),
        ..Default::default()
    };
    let cp_resp = execute_with_password_sessions(&mut sim, &create_primary_cmd, 1, &[]).unwrap();
    let key_handle = cp_resp.object_handle;

    let cmd = EncryptDecrypt {
        key_handle,
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::Cfb),
        iv_in: Tpm2bIv::default(),
        in_data: Tpm2bMaxBuffer::default(),
    };

    let res = execute_with_corrupted_bytes(&mut sim, &cmd, 1, &[], |buf| {
        buf[0] = 2; // decrypt is the first parameter (1 byte)
    });
    // Expected unmarshal error: Value + parameter 1 (452 / 0x01C4)
    assert_eq!(
        res.err(),
        Some(
            tpm2::errors::TpmRc::VALUE
                .with(tpm2::errors::Position::parameter(1))
                .get()
        ),
        "EncryptDecrypt with invalid decrypt should return TPM_RC_VALUE + TPM_RC_P + TPM_RC_1"
    );
}

/// EncryptDecrypt with a public-only symmetric key fails with TPM_RC_AUTH_UNAVAILABLE.
///
/// EncryptDecrypt with a public-only key never runs the cipher with an empty key: C rejects the
/// authorization with `TPM_RC_AUTH_UNAVAILABLE` (the handler additionally refuses an empty key
/// with `TPM_RC_KEY + RC_H1`) instead of returning `TPM_RC_FAILURE`.
#[test]
fn public_only_key_returns_auth_unavailable() {
    let mut sim = create_simulator!();
    let key = load_public_only_sym_key(&mut sim);
    let cmd = EncryptDecrypt {
        key_handle: key,
        decrypt: false,
        mode: None,
        iv_in: Tpm2bIv::from_bytes(&[0u8; 16]).unwrap(),
        in_data: Tpm2bMaxBuffer::from_bytes(&[0u8; 16]).unwrap(),
    };
    let rc = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap_err();
    // C IsAuthValueAvailable: a public-only object can't be authorized (bare, fmt-0 RC).
    assert_eq!(rc, TpmRc::AUTH_UNAVAILABLE.get());
}
