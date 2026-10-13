//! Sessions combining command parameter decryption and response parameter encryption.

use crate::_common::{
    AES128_CFB, AES256_CFB, ALG_SHA256, ATTR_CONT, ATTR_DECRYPT, ATTR_ENCRYPT, CC_ENCRYPT_DECRYPT,
    CC_GET_RANDOM, CC_HASH_SEQUENCE_START, CC_POLICY_GET_DIGEST, RC_ATTRIBUTES, SessUse,
    create_primary_ecc, exec, execute_with_hmac_sessions, execute_with_hmac_sessions_custom,
    flush_context, get_create_primary_cmd_and_handles, new_sim, rc_s1, start_auth_session,
    start_session,
};
use tpm2::commands::{CreatePrimary, GetRandom, HierarchyChangeAuth};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bSensitiveData,
    TpmEccCurve, TpmSe, TpmaObject, TpmaSession, TpmiAlgHash, TpmsEccParms, TpmsEccPoint,
    TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic,
};
use tpm2_simulator::create_simulator;

// parameter-encryption-decryption-command-table-discrepancies
/// Encrypt/decrypt allowed per command table: PolicyGetDigest encrypt, HashSequenceStart decrypt, EncryptDecrypt no decrypt.
#[test]
fn command_table_encrypt_decrypt_support() {
    let mut sim = new_sim();
    let mut s = start_session(&mut sim, TpmSe::HMAC, true);

    // ENCRYPT_2: TPM2_PolicyGetDigest.
    let p = start_session(&mut sim, TpmSe::Policy, false);
    let r = exec(
        &mut sim,
        CC_POLICY_GET_DIGEST,
        &[p.handle],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &[],
        0,
    );
    assert_eq!(r.rc, 0);

    // DECRYPT_2: TPM2_HashSequenceStart (auth is a TPM2B).
    let mut params = vec![0x00, 0x04, 1, 2, 3, 4];
    params.extend_from_slice(&ALG_SHA256.to_be_bytes());
    let r = exec(
        &mut sim,
        CC_HASH_SEQUENCE_START,
        &[],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[])],
        &params,
        1,
    );
    assert_eq!(r.rc, 0);

    // TPM2_EncryptDecrypt has no DECRYPT_2 (its first parameter is a TPMI_YES_NO).
    let key = create_primary_ecc(&mut sim);
    let rc = exec(
        &mut sim,
        CC_ENCRYPT_DECRYPT,
        &[key],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[])],
        &[0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_ATTRIBUTES));
}

/// CreatePrimary with non-empty userAuth through a DECRYPT+ENCRYPT session returns a SHA-256 key.
#[test]
fn create_primary_with_auth_decrypt_and_encrypt() {
    let mut sim = create_simulator!();
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
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let resp =
        execute_with_hmac_sessions(&mut sim, &create_cmd, &[], &mut [session], &[&[]]).unwrap();

    let object_handle = resp.object_handle;
    assert_ne!(object_handle.0, 0);

    let out_public_struct = resp.out_public.0;
    assert_eq!(out_public_struct.name_alg, Some(TpmiAlgHash::Sha256));

    flush_context(&mut sim, object_handle).unwrap();
}

/// HierarchyChangeAuth parameter decryption and GetRandom response encryption across session hash algorithms; empty newAuth is SIZE+S1.
#[test]
fn decrypt_and_encrypt_across_session_hashes() {
    let algs = [
        (TpmiAlgHash::Sha256, 128),
        (TpmiAlgHash::Sha256, 256),
        (TpmiAlgHash::Sha384, 128),
        (TpmiAlgHash::Sha384, 256),
        (TpmiAlgHash::Sha512, 128),
        (TpmiAlgHash::Sha512, 256),
    ];

    let sizes = [0, 1, 4, 15, 16, 17, 31, 32];

    for &(hash_alg, aes_bits) in &algs {
        for &size in &sizes {
            println!(
                "RUNNING: hash={:?} aes={} size={}",
                hash_alg, aes_bits, size
            );
            let mut sim = create_simulator!();

            let sym_def = match aes_bits {
                128 => Some(AES128_CFB),
                256 => Some(AES256_CFB),
                _ => None,
            };

            let session = match start_auth_session(
                &mut sim,
                Handle::RH_NULL,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                sym_def,
                hash_alg,
            ) {
                Ok(s) => s,
                Err(e) => {
                    // If SHA384/SHA512 is not supported, we skip it
                    if hash_alg == TpmiAlgHash::Sha384 || hash_alg == TpmiAlgHash::Sha512 {
                        println!("SKIPPED hash={:?} (not supported by simulator)", hash_alg);
                        continue;
                    }
                    panic!("failed to start session: {:?}", e);
                }
            };

            let mut sessions = [session];

            // 1. Stress Test Parameter Decryption via HierarchyChangeAuth
            sessions[0].attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;
            let new_auth_data = vec![0xEEu8; size];

            let cmd = HierarchyChangeAuth {
                auth_handle: Handle::RH_OWNER,
                new_auth: Tpm2bAuth::from_bytes(&new_auth_data).unwrap(),
            };

            let result = execute_with_hmac_sessions_custom(&mut sim, &cmd, &mut sessions, &[&[]]);

            if size == 0 {
                // C CryptParameterDecryption (CryptUtil.c:966-970) rejects an
                // empty remaining buffer after the size field, so an empty
                // newAuth (the only parameter) fails with SIZE+S1 (0x995).
                assert_eq!(result.err(), Some(0x995), "size 0");
            } else {
                assert!(
                    result.is_ok(),
                    "HierarchyChangeAuth failed for hash {:?} aes_bits {} size {} with error {:?}",
                    hash_alg,
                    aes_bits,
                    size,
                    result.err()
                );
                result.unwrap();
            }

            // 2. Stress Test Response Encryption via GetRandom
            // session has updated nonces internally
            sessions[0].attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            let get_random_cmd = GetRandom {
                bytes_requested: size as u16,
            };

            let result =
                execute_with_hmac_sessions_custom(&mut sim, &get_random_cmd, &mut sessions, &[&[]]);

            assert!(
                result.is_ok(),
                "GetRandom failed for hash {:?} aes_bits {} size {} with error {:?}",
                hash_alg,
                aes_bits,
                size,
                result.err()
            );

            let resp = result.unwrap();
            assert_eq!(resp.random_bytes.as_ref().len(), size);
        }
    }
}

/// CreatePrimary with a decrypt first session and an encrypt second session succeeds.
#[test]
fn decrypt_first_session_encrypt_second() {
    let mut sim = create_simulator!();
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
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session1.attributes.insert(TpmaSession::DECRYPT);
    // The second session is not associated with an auth handle, so C requires
    // it to be audit/encrypt/decrypt (SessionProcess.c:1709-1712, else
    // ATTRIBUTES+S2). Make it the response-encryption session.
    session2.attributes.insert(TpmaSession::ENCRYPT);
    let create_cmd = get_create_primary_cmd_and_handles();
    let resp_handles = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        &[],
        &mut [session1, session2],
        &[&[], &[]],
    )
    .unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

// build-response-sessions-strips-encrypt-decrypt-attributes-and-corrupts-response-hmacs
/// Response session attributes keep ENCRYPT/DECRYPT bits and the response HMAC covers them.
#[test]
fn response_keeps_encrypt_decrypt_attributes() {
    let mut sim = new_sim();
    let mut s = start_session(&mut sim, TpmSe::HMAC, true);
    let r = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &8u16.to_be_bytes(),
        0,
    );
    assert_eq!(r.rc, 0);
    assert_eq!(r.session_attrs, vec![ATTR_CONT | ATTR_ENCRYPT]);
    // The response HMAC covers the attribute byte as returned.
    assert!(r.response_hmac_ok);

    let mut params = vec![0x00, 0x04, 1, 2, 3, 4];
    params.extend_from_slice(&ALG_SHA256.to_be_bytes());
    let r = exec(
        &mut sim,
        CC_HASH_SEQUENCE_START,
        &[],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[])],
        &params,
        1,
    );
    assert_eq!(r.rc, 0);
    assert_eq!(r.session_attrs, vec![ATTR_CONT | ATTR_DECRYPT]);
    assert!(r.response_hmac_ok);
}

/// One HMAC session with both DECRYPT and ENCRYPT authorizes CreatePrimary.
#[test]
fn single_session_decrypts_and_encrypts() {
    let mut sim = create_simulator!();
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
    session
        .attributes
        .insert(TpmaSession::DECRYPT | TpmaSession::ENCRYPT);
    let create_cmd = get_create_primary_cmd_and_handles();
    let resp_handles =
        execute_with_hmac_sessions(&mut sim, &create_cmd, &[], &mut [session], &[&[]]).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}
