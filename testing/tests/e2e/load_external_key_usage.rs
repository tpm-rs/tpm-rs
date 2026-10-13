//! Keys loaded with TPM2_LoadExternal used for Sign, VerifySignature and HMAC.
#![allow(deprecated)] // TPM2_Sign and TPM2_VerifySignature are deprecated upstream.

use crate::_common::{
    ECC_D, ECC_X, ECC_Y, LocalHmacCmd, LocalRSADecryptCmd, RSA_N, RSA_P, execute_sign,
    execute_with_password_sessions_status, flush_context, make_ecc_public_area,
    make_keyed_hash_public_area_obfuscated, make_rsa_public_area_opt_name_alg,
};
use testing::tpm::Tpm;
use tpm2::commands::{LoadExternal, Sign, VerifySignature};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bLabel, Tpm2bMaxBuffer,
    Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject, TpmiAlgHash,
    TpmtSensitive, TpmtTkHashcheck, TpmuSensitiveComposite,
};

/// An externally loaded ECC private key can be used with TPM2_Sign.
#[test]
fn ecc_external_key_signs() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let sign_cmd = Sign {
        key_handle: resp_handles.object_handle,
        digest: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    let res = execute_with_password_sessions_status(&mut sim, &sign_cmd, 0, &[]);
    assert!(res.is_err());
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// A loaded external ECC public key verifies a signature produced by the TPM.
#[test]
fn ecc_public_key_verifies_tpm_signature() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let sign_load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let sign_handles = sim.execute(sign_load_cmd).unwrap();

    let digest = Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap();
    let sign_cmd = Sign {
        key_handle: sign_handles.object_handle,
        digest,
        in_scheme: Some(tpm2::TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let sign_rsp = execute_sign(&mut sim, &sign_cmd, 1, &[], &mut resp_buffer).unwrap();
    flush_context(&mut sim, sign_handles.object_handle).unwrap();

    let load_cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let verify_cmd = VerifySignature {
        key_handle: resp_handles.object_handle,
        digest,
        signature: sign_rsp.signature,
    };
    let _verify_resp = sim.execute(verify_cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// An externally loaded keyedHash key computes a TPM2_HMAC.
#[test]
fn keyed_hash_external_key_computes_hmac() {
    let mut sim = Tpm::new();
    let seed_value = Tpm2bDigest::from_bytes(b"obfuscation is my middle name!!!").unwrap();
    let sensitive_data = Tpm2bSensitiveData::from_bytes(b"secrets").unwrap();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value,
        sensitive: TpmuSensitiveComposite::KeyedHash(sensitive_data),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let unique_bytes = [0x01; 32];
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area_obfuscated(
        &unique_bytes,
        TpmaObject::SIGN_ENCRYPT,
    ));

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let hmac_cmd = LocalHmacCmd {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let _hmac_resp = sim.execute(hmac_cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// An externally loaded RSA private key decrypts with TPM2_RSA_Decrypt.
#[test]
fn rsa_external_key_decrypts() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(RSA_P).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area_opt_name_alg(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::DECRYPT,
    ));

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let decrypt_cmd = LocalRSADecryptCmd {
        key_handle: resp_handles.object_handle,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(&[0x01; 256]).unwrap(),
        in_scheme: None,
        label: Tpm2bLabel::default(),
    };
    let _decrypt_resp = sim.execute(decrypt_cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// A loaded external RSA public key verifies a signature produced by the TPM.
#[test]
fn rsa_public_key_verifies_tpm_signature() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(RSA_P).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area_opt_name_alg(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));
    let sign_load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let sign_handles = sim.execute(sign_load_cmd).unwrap();

    let digest = Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap();
    let sign_cmd = Sign {
        key_handle: sign_handles.object_handle,
        digest,
        in_scheme: Some(tpm2::TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let sign_rsp = execute_sign(&mut sim, &sign_cmd, 1, &[], &mut resp_buffer).unwrap();
    flush_context(&mut sim, sign_handles.object_handle).unwrap();

    let load_cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let verify_cmd = VerifySignature {
        key_handle: resp_handles.object_handle,
        digest,
        signature: sign_rsp.signature,
    };
    let _verify_resp = sim.execute(verify_cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}
