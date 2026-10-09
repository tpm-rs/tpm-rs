#![allow(unused_imports, dead_code)]
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256};
use tpm2::Handle;
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, Sign, SignHandles, VerifySignature, VerifySignatureHandles,
};
use tpm2::errors::TpmRc;
use tpm2::*;
use tpm2_simulator::{Simulator, create_simulator};

use crate::test_utils::*;

#[test]
fn test_sign_edge_cases() {
    let mut sim = create_simulator!();

    let in_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let create_primary_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(in_public),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
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

    let object_handle = create_primary_resp_handles.object_handle;

    let data_to_sign = b"migrationpains";
    let digest = Sha256::digest(data_to_sign);

    // 1. Test signing with mismatched/invalid scheme hash algorithm
    let sign_cmd_mismatched = Sign {
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha1)), // Mismatched hash algorithm
        validation: TpmtTkHashcheck::default(),
    };
    let sign_handles = SignHandles {
        key_handle: object_handle,
    };

    let res_mismatched =
        execute_with_password_sessions_status(&mut sim, &sign_cmd_mismatched, sign_handles, 1, &[]);
    assert!(
        res_mismatched.is_err(),
        "Expected sign with mismatched scheme to fail"
    );

    // 2. Test successful sign
    let sign_cmd = Sign {
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let (sign_resp, _) = execute_sign(&mut sim, &sign_cmd, sign_handles, 1, &[], &mut resp_buffer)
        .expect("Sign failed");

    // 3. Test VerifySignature command (Success)
    let verify_cmd = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        signature: sign_resp.signature,
    };
    let verify_handles = VerifySignatureHandles {
        key_handle: object_handle,
    };
    let (verify_resp, _) =
        execute_with_password_sessions(&mut sim, &verify_cmd, verify_handles, 0, &[])
            .expect("VerifySignature failed");
    // Verify that the ticket is returned indicating success
    assert_eq!(verify_resp.validation.tag(), (tpm2::TpmSt::VERIFIED.id()));

    // 4. Test VerifySignature with modified digest
    let mut modified_digest = digest;
    modified_digest[0] ^= 1;
    let verify_cmd_mod_digest = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&modified_digest).unwrap(),
        signature: sign_resp.signature,
    };
    let res_mod_digest =
        execute_with_password_sessions(&mut sim, &verify_cmd_mod_digest, verify_handles, 0, &[]);
    assert!(
        res_mod_digest.is_err(),
        "VerifySignature should fail when digest is modified"
    );

    // 5. Test VerifySignature with modified signature
    let mut modified_sig = sign_resp.signature;
    match &mut modified_sig {
        TpmtSignature::Rsassa(rsassa) => {
            let mut sig_bytes = rsassa.sig.get_buffer().to_vec();
            sig_bytes[0] ^= 1;
            rsassa.sig =
                Tpm2bPublicKeyRsa::from_bytes(crate::test_utils::leak_bytes(&sig_bytes)).unwrap();
        }
        _ => panic!("Expected RSASSA signature"),
    }
    let verify_cmd_mod_sig = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        signature: modified_sig,
    };
    let res_mod_sig =
        execute_with_password_sessions(&mut sim, &verify_cmd_mod_sig, verify_handles, 0, &[]);
    assert!(
        res_mod_sig.is_err(),
        "VerifySignature should fail when signature is modified"
    );

    // Cleanup key
    flush_context(&mut sim, object_handle).unwrap();
}

#[test]
fn test_sign_with_non_sign_key() {
    let mut sim = create_simulator!();

    // Create a key with DECRYPT attribute only (no SIGN_ENCRYPT)
    let in_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let create_primary_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(in_public),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
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

    let object_handle = create_primary_resp_handles.object_handle;

    let data_to_sign = b"migrationpains";
    let digest = Sha256::digest(data_to_sign);

    let sign_cmd = Sign {
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let sign_handles = SignHandles {
        key_handle: object_handle,
    };

    let res = execute_with_password_sessions_status(&mut sim, &sign_cmd, sign_handles, 1, &[]);
    assert!(
        res.is_err(),
        "Sign should fail when using a key without SIGN attribute"
    );
    let err = res.err().unwrap();
    assert_eq!(err, TpmRc::KEY.get());

    // Cleanup key
    flush_context(&mut sim, object_handle).unwrap();
}

#[test]
fn test_verify_with_non_verify_key() {
    let mut sim = create_simulator!();

    // 1. Create a sign/verify key
    let in_public_sign = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let create_sign_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(in_public_sign),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let (_, sign_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_sign_cmd,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        0,
        &[],
    )
    .expect("CreatePrimary sign key failed");
    let sign_key_handle = sign_resp_handles.object_handle;

    // 2. Create a decrypt-only key
    let in_public_decrypt = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let create_decrypt_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(in_public_decrypt),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let (_, decrypt_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_decrypt_cmd,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        0,
        &[],
    )
    .expect("CreatePrimary decrypt key failed");
    let decrypt_key_handle = decrypt_resp_handles.object_handle;

    // 3. Sign a digest with the signing key
    let data_to_sign = b"migrationpains";
    let digest = Sha256::digest(data_to_sign);
    let sign_cmd = Sign {
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let (sign_resp, _) = execute_sign(
        &mut sim,
        &sign_cmd,
        SignHandles {
            key_handle: sign_key_handle,
        },
        1,
        &[],
        &mut resp_buffer,
    )
    .expect("Sign failed");

    // 4. Attempt to verify signature with the decryption-only key
    let verify_cmd = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        signature: sign_resp.signature,
    };
    let verify_handles = VerifySignatureHandles {
        key_handle: decrypt_key_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &verify_cmd, verify_handles, 0, &[]);
    assert!(
        res.is_err(),
        "VerifySignature should fail when key lacks SIGN attribute"
    );
    let err = res.err().unwrap();
    assert_eq!(err, TpmRc::ATTRIBUTES.get());

    // 5. Attempt to verify with a mismatched signature scheme type (e.g. ECDSA signature)
    let verify_cmd_mismatched = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        signature: TpmtSignature::Ecdsa(TpmsSignatureEcc {
            hash: TpmiAlgHash::Sha256,
            signature_r: Tpm2bEccParameter::default(),
            signature_s: Tpm2bEccParameter::default(),
        }),
    };
    let verify_handles_sign = VerifySignatureHandles {
        key_handle: sign_key_handle,
    };
    let res_mismatched = execute_with_password_sessions(
        &mut sim,
        &verify_cmd_mismatched,
        verify_handles_sign,
        0,
        &[],
    );
    assert!(
        res_mismatched.is_err(),
        "VerifySignature should fail with mismatched scheme (ECDSA on RSA key)"
    );
    let err_mismatched = res_mismatched.err().unwrap();
    assert_eq!(err_mismatched, TpmRc::SIGNATURE.get());

    // 6. Attempt to verify with a mismatched hash algorithm in signature (SHA1 vs key's SHA256)
    let mut signature_mismatched_hash = sign_resp.signature;
    match &mut signature_mismatched_hash {
        TpmtSignature::Rsassa(rsassa) => {
            rsassa.hash = TpmiAlgHash::Sha1;
        }
        _ => panic!("Expected RSASSA signature"),
    }
    let verify_cmd_mismatched_hash = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        signature: signature_mismatched_hash,
    };
    let res_mismatched_hash = execute_with_password_sessions(
        &mut sim,
        &verify_cmd_mismatched_hash,
        verify_handles_sign,
        0,
        &[],
    );
    assert!(
        res_mismatched_hash.is_err(),
        "VerifySignature should fail with mismatched hash algorithm"
    );
    let err_mismatched_hash = res_mismatched_hash.err().unwrap();
    // We expect TPM_RC_SCHEME or TPM_RC_SIGNATURE
    assert!(
        err_mismatched_hash == TpmRc::SCHEME.get() || err_mismatched_hash == TpmRc::SIGNATURE.get(),
        "Expected TPM_RC_SCHEME or TPM_RC_SIGNATURE, got {}",
        err_mismatched_hash
    );

    // Cleanup keys
    flush_context(&mut sim, sign_key_handle).unwrap();
    flush_context(&mut sim, decrypt_key_handle).unwrap();
}
