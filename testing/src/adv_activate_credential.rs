#![forbid(unsafe_code)]

use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::{
    ActivateCredential, ActivateCredentialHandles, CreatePrimary, CreatePrimaryHandles,
    MakeCredential, MakeCredentialHandles, PolicySecret, PolicySecretHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bSensitiveData, TpmSe,
    TpmaObject, TpmiAlgHash, TpmiAlgSymMode, TpmsEccParms, TpmsEccPoint, TpmsSensitiveCreate,
    TpmtEccScheme, TpmtPublic, TpmtSymDefObject,
};
use tpm2_simulator::create_simulator;

fn get_ecc_ek_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::ADMIN_WITH_POLICY
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::from_bytes(&[
            // PolicyA SHA256 value from TCG EK Profile
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5,
            0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B,
            0x33, 0x14, 0x69, 0xAA,
        ])
        .unwrap(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

fn get_ecc_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

// 1. Create a key that is DECRYPT but not RESTRICTED
fn get_ecc_decrypt_unrestricted_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT, // No RESTRICTED
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

// 2. Create a key that is RESTRICTED but SIGN (not DECRYPT)
fn get_ecc_sign_restricted_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::SIGN_ENCRYPT, // SIGN instead of DECRYPT
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

#[test]
fn test_make_credential_invalid_protector_handle() {
    let mut sim = create_simulator!();

    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let create_primary_srk = CreatePrimary {
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let (srk_resp, _) = execute_with_password_sessions(
        &mut sim,
        &create_primary_srk,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("could not generate SRK");

    let secret = Tpm2bDigest::from_bytes(b"Secrets!!!").unwrap();
    let mc = MakeCredential {
        credential: secret,
        object_name: srk_resp.name,
    };
    // Non-existent transient handle
    let mc_handles = MakeCredentialHandles {
        handle: Handle(0x8000000E),
    };
    let res = execute_with_password_sessions(&mut sim, &mc, mc_handles, 0, &[]);
    assert_eq!(res.err().unwrap(), TpmRc::REFERENCE_H0.get());
}

#[test]
fn test_make_credential_protector_not_decrypt() {
    let mut sim = create_simulator!();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    // 1. Create a protector key that is restricted sign-only
    let protector_template = get_ecc_sign_restricted_template();
    let in_public_p = tpm2::Tpm2b(protector_template);
    let create_primary_p = CreatePrimary {
        in_sensitive,
        in_public: in_public_p,
        ..Default::default()
    };
    let (_, p_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_p,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("could not generate protector key");

    // 2. Create target SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let (srk_resp, _) = execute_with_password_sessions(
        &mut sim,
        &create_primary_srk,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("could not generate SRK");

    // 3. MakeCredential should fail because protector key does not have DECRYPT attribute
    let secret = Tpm2bDigest::from_bytes(b"Secrets!!!").unwrap();
    let mc = MakeCredential {
        credential: secret,
        object_name: srk_resp.name,
    };
    let mc_handles = MakeCredentialHandles {
        handle: p_resp_handles.object_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &mc, mc_handles, 0, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::TYPE.with(Position::handle(1)).get()
    );
}

#[test]
fn test_make_credential_protector_not_restricted() {
    let mut sim = create_simulator!();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    // 1. Create a protector key that is decrypt but not restricted
    let protector_template = get_ecc_decrypt_unrestricted_template();
    let in_public_p = tpm2::Tpm2b(protector_template);
    let create_primary_p = CreatePrimary {
        in_sensitive,
        in_public: in_public_p,
        ..Default::default()
    };
    let (_, p_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_p,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("could not generate protector key");

    // 2. Create target SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let (srk_resp, _) = execute_with_password_sessions(
        &mut sim,
        &create_primary_srk,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("could not generate SRK");

    // 3. MakeCredential should fail because protector key does not have RESTRICTED attribute
    let secret = Tpm2bDigest::from_bytes(b"Secrets!!!").unwrap();
    let mc = MakeCredential {
        credential: secret,
        object_name: srk_resp.name,
    };
    let mc_handles = MakeCredentialHandles {
        handle: p_resp_handles.object_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &mc, mc_handles, 0, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::TYPE.with(Position::handle(1)).get()
    );
}

#[test]
fn test_make_credential_credential_too_large() {
    let mut sim = create_simulator!();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    // 1. Create ECC EK (name_alg is SHA256, digest size is 32 bytes)
    let ek_pub = get_ecc_ek_template();
    let in_public_ek = tpm2::Tpm2b(ek_pub);
    let create_primary_ek = CreatePrimary {
        in_sensitive,
        in_public: in_public_ek,
        ..Default::default()
    };
    let (_, ek_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_ek,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_ENDORSEMENT,
        },
        1,
        &[],
    )
    .expect("could not generate EK");

    // 2. Create target SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let (srk_resp, _) = execute_with_password_sessions(
        &mut sim,
        &create_primary_srk,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("could not generate SRK");

    // 3. Credential size of 33 bytes exceeds SHA256 digest size of 32 bytes.
    let secret = Tpm2bDigest::from_bytes(&[0u8; 33]).unwrap();
    let mc = MakeCredential {
        credential: secret,
        object_name: srk_resp.name,
    };
    let mc_handles = MakeCredentialHandles {
        handle: ek_resp_handles.object_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &mc, mc_handles, 0, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::SIZE.with(Position::parameter(1)).get()
    );
}

#[test]
fn test_activate_credential_invalid_key_handle() {
    let mut sim = create_simulator!();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    // 1. Create target SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let (_, srk_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_srk,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("could not generate SRK");

    // 2. Call ActivateCredential with invalid key handle
    let ac_cmd = ActivateCredential {
        credential_blob: tpm2::Tpm2bIdObject::default(),
        secret: tpm2::Tpm2bEncryptedSecret::default(),
    };
    let ac_handles = ActivateCredentialHandles {
        activate_handle: srk_resp_handles.object_handle,
        key_handle: Handle(0x8000000E), // Invalid handle
    };
    let res = execute_with_password_sessions(&mut sim, &ac_cmd, ac_handles, 0, &[]);
    assert_eq!(res.err().unwrap(), TpmRc::REFERENCE_H1.get());
}

#[test]
fn test_activate_credential_key_not_decrypt() {
    let mut sim = create_simulator!();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    // 1. Create a key that is restricted sign-only (not decrypt)
    let protector_template = get_ecc_sign_restricted_template();
    let in_public_p = tpm2::Tpm2b(protector_template);
    let create_primary_p = CreatePrimary {
        in_sensitive,
        in_public: in_public_p,
        ..Default::default()
    };
    let (_, p_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_p,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("could not generate key");

    // 2. Create target SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let (_, srk_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_srk,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("could not generate SRK");

    // 3. Call ActivateCredential
    let ac_cmd = ActivateCredential {
        credential_blob: tpm2::Tpm2bIdObject::default(),
        secret: tpm2::Tpm2bEncryptedSecret::default(),
    };
    let ac_handles = ActivateCredentialHandles {
        activate_handle: srk_resp_handles.object_handle,
        key_handle: p_resp_handles.object_handle, // Sign key as decryption key
    };
    // Both activateHandle (ADMIN) and keyHandle (USER) need a session. C
    // ActivateCredential.c:41-44 rejects a non-decrypt key with TYPE+H2.
    let res = execute_with_password_sessions(&mut sim, &ac_cmd, ac_handles, 2, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::TYPE.with(Position::handle(2)).get()
    );
}

#[test]
fn test_activate_credential_integrity_corrupted() {
    let mut sim = create_simulator!();

    // 1. Create ECC EK under Endorsement Hierarchy
    let ek_pub = get_ecc_ek_template();
    let in_public = tpm2::Tpm2b(ek_pub);
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let create_primary_ek = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let (ek_resp, ek_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_ek,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_ENDORSEMENT,
        },
        1,
        &[],
    )
    .expect("could not generate EK");

    // 2. Create ECC SRK under Owner Hierarchy
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let (srk_resp, srk_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_srk,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("could not generate SRK");

    // 3. MakeCredential
    let secret = Tpm2bDigest::from_bytes(b"Secrets!!!").unwrap();
    let mc = MakeCredential {
        credential: secret,
        object_name: srk_resp.name,
    };
    let mc_handles = MakeCredentialHandles {
        handle: ek_resp_handles.object_handle,
    };
    let (mc_resp, _) = execute_with_password_sessions(&mut sim, &mc, mc_handles, 0, &[])
        .expect("MakeCredential failed");

    // Corrupt the credential blob (flip a byte)
    let mut corrupted_blob_bytes = mc_resp.credential_blob.get_buffer().to_vec();
    if corrupted_blob_bytes.len() > 10 {
        corrupted_blob_bytes[10] ^= 0xFF;
    }
    let corrupted_blob = tpm2::Tpm2bIdObject::from_bytes(&corrupted_blob_bytes).unwrap();

    // 4. ActivateCredential with corrupted blob
    // Policy session to satisfy EK policy
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("start policy session failed");

    let policy_secret_cmd = PolicySecret {
        nonce_tpm: active_session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let policy_secret_handles = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_secret_cmd, policy_secret_handles, 1, &[])
            .expect("PolicySecret failed");

    let hmac_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("start HMAC session failed");

    let ac_cmd = ActivateCredential {
        credential_blob: corrupted_blob,
        secret: mc_resp.secret,
    };
    let ac_handles = ActivateCredentialHandles {
        activate_handle: srk_resp_handles.object_handle,
        key_handle: ek_resp_handles.object_handle,
    };

    let mut sessions = [hmac_session, active_session];
    let res = execute_with_hmac_sessions(
        &mut sim,
        &ac_cmd,
        ac_handles,
        &[srk_resp.name.get_buffer(), ek_resp.name.get_buffer()], // Names
        &mut sessions,
        &[&[], &[]],
    );

    // C ActivateCredential.c:69-70 adds RC_ActivateCredential_credentialBlob
    // (P1) to the CredentialToSecret INTEGRITY error.
    assert_eq!(
        res.err().unwrap(),
        TpmRc::INTEGRITY.with(Position::parameter(1)).get()
    );
}

#[test]
fn test_policy_secret_invalid_session() {
    let mut sim = create_simulator!();

    let cmd = PolicySecret {
        nonce_tpm: tpm2::Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let handles = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: Handle(0x020000FF), // Non-existent session
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    // policySession is a TPMI_SH_POLICY: a non-policy (0x02) handle fails handle unmarshaling
    // with TPM_RCS_VALUE + RC_H2 (C TPMI_SH_POLICY_Unmarshal), before any session processing.
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );
}

#[test]
fn test_policy_secret_invalid_session_type() {
    let mut sim = create_simulator!();

    // Start an HMAC session
    let hmac_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC, // HMAC instead of Policy
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("start HMAC session failed");

    let cmd = PolicySecret {
        nonce_tpm: hmac_session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let handles = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: hmac_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    // policySession is a TPMI_SH_POLICY: a non-policy (0x02) handle fails handle unmarshaling
    // with TPM_RCS_VALUE + RC_H2 (C TPMI_SH_POLICY_Unmarshal), before any session processing.
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );
}

#[test]
fn test_policy_secret_trial_session() {
    let mut sim = create_simulator!();

    // Start a Trial session
    let trial_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("start Trial session failed");

    let cmd = PolicySecret {
        nonce_tpm: trial_session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let handles = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: trial_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert!(res.is_ok(), "PolicySecret on Trial session failed");
}

#[test]
fn test_policy_secret_nonce_tpm_mismatch() {
    let mut sim = create_simulator!();

    // Start Policy session
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Generate a mismatched nonce
    let mut bad_nonce_bytes = active_session.nonce_tpm.get_buffer().to_vec();
    if !bad_nonce_bytes.is_empty() {
        bad_nonce_bytes[0] ^= 0xFF;
    }
    let bad_nonce = tpm2::Tpm2bNonce::from_bytes(&bad_nonce_bytes).unwrap();

    let cmd = PolicySecret {
        nonce_tpm: bad_nonce,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let handles = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::NONCE.with(Position::parameter(1)).get()
    );
}

#[test]
fn test_policy_secret_cphash_size_mismatch() {
    let mut sim = create_simulator!();

    // Start Policy session
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // cpHashA with size 20 (SHA1 digest size) instead of 32 (SHA256 session digest size)
    let bad_cp_hash = Tpm2bDigest::from_bytes(&[0xAA; 20]).unwrap();

    let cmd = PolicySecret {
        nonce_tpm: active_session.nonce_tpm,
        cp_hash_a: bad_cp_hash,
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let handles = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::SIZE.with(Position::parameter(2)).get()
    );
}

#[test]
fn test_policy_secret_ticket_generation() {
    let mut sim = create_simulator!();

    // Start Policy session
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let cmd = PolicySecret {
        nonce_tpm: active_session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: -1, // Negative expiration!
    };
    let handles = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
    };
    let (resp, _) = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]).unwrap();

    assert_eq!(resp.policy_ticket.tag(), 0x8023);
    assert!(!resp.policy_ticket.digest().get_buffer().is_empty());
}

#[test]
fn test_policy_secret_cphash_mismatch() {
    let mut sim = create_simulator!();

    // Start Policy session
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let cp_hash_1 = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let cp_hash_2 = Tpm2bDigest::from_bytes(&[0x22; 32]).unwrap();

    // First call sets temp_cp_hash to cp_hash_1
    let cmd1 = PolicySecret {
        nonce_tpm: active_session.nonce_tpm,
        cp_hash_a: cp_hash_1,
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let handles1 = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
    };
    let _ = execute_with_password_sessions(&mut sim, &cmd1, handles1, 1, &[]).unwrap();

    // Second call with cp_hash_2 should fail with CpHash error
    let cmd2 = PolicySecret {
        nonce_tpm: active_session.nonce_tpm,
        cp_hash_a: cp_hash_2,
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let handles2 = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd2, handles2, 1, &[]);
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH.get());
}
