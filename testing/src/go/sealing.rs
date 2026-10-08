#![forbid(unsafe_code)]
use crate::test_utils::marshal_to_slice;
use tpm2::errors::{Position, TpmRc};

use crate::test_utils::{
    ActiveSession, execute_with_hmac_sessions, execute_with_password_sessions, flush_context,
};
use tpm2::commands::{
    Create, CreateHandles, CreatePrimary, CreatePrimaryHandles, StartAuthSession,
    StartAuthSessionHandles, Unseal, UnsealHandles,
};
use tpm2::crypto::Rng;
use tpm2::{Handle, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret,
    Tpm2bName, Tpm2bNonce, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject, TpmaSession,
    TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmlPcrSelection, TpmsEccParms, TpmsEccPoint,
    TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic, TpmtSymDefObject,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

// =========================================================================
// Helper Functions
// =========================================================================

fn get_rsa_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
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
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    }
}

fn create_srk(
    sim: &mut Simulator<'_>,
    srk_template: &TpmtPublic,
    srk_auth: &[u8],
) -> (Handle, Tpm2bName<'static>) {
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(srk_auth).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(*srk_template);
    let create_primary = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &create_primary, create_handles, 0, &[])
            .expect("could not call TPM2_CreatePrimary");

    (rsp_handles.object_handle, rsp.name)
}

fn kdfa_generic(
    tpm: &mut Simulator<'_>,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> Vec<u8> {
    let required_bytes = bits.div_ceil(8) as usize;
    let mut derived = vec![0u8; required_bytes];
    tpm2::crypto::kdf::kdfa(
        tpm.context.platform.crypto,
        auth_hash,
        key,
        label,
        context_u,
        context_v,
        bits,
        &mut derived,
    )
    .unwrap();
    derived
}

#[allow(clippy::too_many_arguments)]
fn start_auth_session_full(
    tpm: &mut Simulator<'_>,
    tpm_key: Handle,
    srk_public: Option<&TpmtPublic>,
    bind: Handle,
    bind_auth: &[u8],
    session_type: TpmSe,
    symmetric: Option<TpmtSymDefObject>,
    auth_hash: TpmiAlgHash,
) -> ActiveSession {
    let mut nonce_bytes = [0u8; 16];
    tpm.context
        .platform
        .crypto
        .get_random(&mut nonce_bytes)
        .unwrap();
    let nonce_caller = Tpm2bNonce::from_bytes(crate::test_utils::leak_bytes(&nonce_bytes)).unwrap();

    let (encrypted_salt, salt) = if tpm_key != Handle::RH_NULL {
        let pub_area = srk_public.expect("must provide SRK public info for salted session");
        match &pub_area.parms_and_id {
            PublicParmsAndId::Rsa(_, pub_key_rsa) => {
                let mut salt = [0u8; 32];
                tpm.context.platform.crypto.get_random(&mut salt).unwrap();

                let mut ciphertext = [0u8; 256];
                use tpm2::crypto::Asymmetric;
                let encrypted_len = tpm
                    .context
                    .platform
                    .crypto
                    .encrypt(
                        tpm2::Alg::OAEP,
                        pub_area.name_alg.unwrap().into(),
                        pub_key_rsa.get_buffer(),
                        &salt,
                        &mut ciphertext,
                        b"SECRET\0",
                    )
                    .unwrap();

                let encrypted_salt = Tpm2bEncryptedSecret::from_bytes(
                    crate::test_utils::leak_bytes(&ciphertext[..encrypted_len]),
                )
                .unwrap();
                (encrypted_salt, salt.to_vec())
            }
            PublicParmsAndId::Ecc(_ecc_parms, ecc_unique) => {
                use p256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};

                // Generate SW P-256 key pair
                let sw_priv = SecretKey::random(&mut rand::thread_rng());
                let sw_pub = sw_priv.public_key();
                let sw_encoded = sw_pub.to_encoded_point(false);
                let sw_x = sw_encoded.x().unwrap();
                let sw_y = sw_encoded.y().unwrap();

                // TPM public key
                let tpm_x = ecc_unique.x.get_buffer();
                let tpm_y = ecc_unique.y.get_buffer();
                let mut tpm_sec1 = [0u8; 65];
                tpm_sec1[0] = 0x04;
                tpm_sec1[1..33].copy_from_slice(tpm_x);
                tpm_sec1[33..65].copy_from_slice(tpm_y);
                let tpm_pub_key = PublicKey::from_sec1_bytes(&tpm_sec1).unwrap();

                // Shared secret
                let shared_secret = p256::ecdh::diffie_hellman(
                    sw_priv.to_nonzero_scalar(),
                    tpm_pub_key.as_affine(),
                );
                let z = shared_secret.raw_secret_bytes();

                // Derivation
                let mut derived_salt = [0u8; 32];

                let mut padded_sw_x = [0u8; 32];
                padded_sw_x[32 - sw_x.len()..].copy_from_slice(sw_x);

                let mut padded_tpm_x = [0u8; 32];
                padded_tpm_x[32 - tpm_x.len()..].copy_from_slice(tpm_x);

                // Determine HashAlg for KDFe
                match pub_area.name_alg {
                    Some(TpmiAlgHash::Sha256) => {
                        tpm2::crypto::kdf::kdfe(
                            tpm.context.platform.crypto,
                            TpmiAlgHash::Sha256,
                            z.as_slice(),
                            b"SECRET",
                            &padded_sw_x,
                            &padded_tpm_x,
                            256,
                            &mut derived_salt,
                        )
                        .unwrap();
                    }
                    _ => unimplemented!("Only SHA256 KDFe is supported"),
                }

                let sw_point = TpmsEccPoint {
                    x: Tpm2bEccParameter::from_bytes(sw_x).unwrap(),
                    y: Tpm2bEccParameter::from_bytes(sw_y).unwrap(),
                };
                let mut sw_point_buf = [0u8; 1024];
                let sw_point_len = marshal_to_slice(&sw_point, &mut sw_point_buf);
                let encrypted_salt = Tpm2bEncryptedSecret::from_bytes(
                    crate::test_utils::leak_bytes(&sw_point_buf[..sw_point_len]),
                )
                .unwrap();

                (encrypted_salt, derived_salt.to_vec())
            }
            _ => panic!("unsupported SRK type"),
        }
    } else {
        (Tpm2bEncryptedSecret::default(), Vec::new())
    };

    let cmd = StartAuthSession {
        nonce_caller,
        encrypted_salt,
        session_type,
        symmetric: symmetric.map(tpm2::TpmtSymDef::from),
        auth_hash,
    };
    let handles = StartAuthSessionHandles { tpm_key, bind };
    let (resp, resp_handles) = execute_with_password_sessions(tpm, &cmd, handles, 0, &[]).unwrap();

    // Derivation: Part 1, 19.6
    let session_key = if bind == Handle::RH_NULL && tpm_key == Handle::RH_NULL {
        Vec::new()
    } else {
        let key = [bind_auth, &salt].concat();
        let hash_size = match auth_hash {
            TpmiAlgHash::Sha1 => 20,
            TpmiAlgHash::Sha256 => 32,
            TpmiAlgHash::Sha384 => 48,
            TpmiAlgHash::Sha512 => 64,
            _ => 32,
        };
        let session_key_bits = (hash_size as u32) * 8;
        kdfa_generic(
            tpm,
            auth_hash,
            &key,
            b"ATH",
            resp.nonce_tpm.get_buffer(),
            nonce_caller.get_buffer(),
            session_key_bits,
        )
    };

    ActiveSession {
        session_handle: resp_handles.session_handle,
        nonce_caller,
        nonce_tpm: resp.nonce_tpm,
        session_key,
        auth_hash,
        symmetric,
        attributes: TpmaSession::from_bits_retain(0),
        bind_auth: bind_auth.to_vec(),
        bind_entity: bind,
    }
}

fn read_public(sim: &mut Simulator<'_>, handle: Handle) -> TpmtPublic<'static> {
    let cmd = tpm2::commands::ReadPublic {};
    let handles = tpm2::commands::ReadPublicHandles {
        object_handle: handle,
    };
    let (rsp, _) = execute_with_password_sessions(sim, &cmd, handles, 0, &[]).unwrap();
    rsp.out_public.0
}

fn run_sealing_test_full<
    FCreate: FnOnce(&mut Simulator<'_>, Handle, &TpmtPublic, &mut Vec<ActiveSession>, &mut Vec<Vec<u8>>),
    FUnseal: FnOnce(
        &mut Simulator<'_>,
        Handle,
        &TpmtPublic,
        Handle,
        &mut Vec<ActiveSession>,
        &mut Vec<Vec<u8>>,
    ),
    FVerify: FnOnce(
        &mut Simulator<'_>,
        Handle,
        &mut [ActiveSession],
        &[&[u8]],
        &[u8],
        &[u8],
    ) -> Result<(), u32>,
>(
    is_ecc: bool,
    setup_create_sessions: FCreate,
    setup_unseal_sessions: FUnseal,
    execute_and_verify_unseal: FVerify,
) {
    let mut sim = create_simulator!();
    let srk_template = if is_ecc {
        get_ecc_srk_template()
    } else {
        get_rsa_srk_template()
    };
    let srk_auth = b"mySRK";
    let (srk_handle, _srk_name) = create_srk(&mut sim, &srk_template, srk_auth);
    let srk_public = read_public(&mut sim, srk_handle);

    let data = b"secrets";
    let auth = b"p@ssw0rd\x00\x00";

    // 1. Create the sealed blob
    let mut create_sessions = Vec::new();
    let mut create_entity_auths = Vec::new();
    setup_create_sessions(
        &mut sim,
        srk_handle,
        &srk_public,
        &mut create_sessions,
        &mut create_entity_auths,
    );

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
        data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
    });
    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    });

    let create_cmd = Create {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_handles = CreateHandles {
        parent_handle: srk_handle,
    };

    let create_rsp = if create_sessions.is_empty() {
        let (rsp, _) =
            execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, srk_auth)
                .unwrap();
        rsp
    } else {
        let auth_refs: Vec<&[u8]> = create_entity_auths.iter().map(|v| v.as_slice()).collect();
        let (rsp, _) = execute_with_hmac_sessions(
            &mut sim,
            &create_cmd,
            create_handles,
            &[],
            &mut create_sessions,
            &auth_refs,
        )
        .unwrap();
        rsp
    };

    // 2. Load the blob
    let load_cmd = tpm2::commands::Load {
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_handles = tpm2::commands::LoadHandles {
        parent_handle: srk_handle,
    };
    let (_load_rsp, load_rsp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, srk_auth).unwrap();

    // 3. Set up unseal sessions
    let mut unseal_sessions = Vec::new();
    let mut unseal_entity_auths = Vec::new();
    setup_unseal_sessions(
        &mut sim,
        srk_handle,
        &srk_template,
        load_rsp_handles.object_handle,
        &mut unseal_sessions,
        &mut unseal_entity_auths,
    );

    // 4. Execute and verify unseal
    let verify_auths: Vec<&[u8]> = unseal_entity_auths.iter().map(|v| v.as_slice()).collect();
    execute_and_verify_unseal(
        &mut sim,
        load_rsp_handles.object_handle,
        &mut unseal_sessions,
        &verify_auths,
        auth,
        data,
    )
    .unwrap();

    // 5. Clean up
    for sess in create_sessions {
        let _ = flush_context(&mut sim, sess.session_handle);
    }
    for sess in unseal_sessions {
        let _ = flush_context(&mut sim, sess.session_handle);
    }
    flush_context(&mut sim, load_rsp_handles.object_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

fn std_unseal_verify(
    sim: &mut Simulator<'_>,
    blob_handle: Handle,
    _sessions: &mut [ActiveSession],
    _auths: &[&[u8]],
    auth: &[u8],
    expected_data: &[u8],
) -> Result<(), u32> {
    let unseal_cmd = Unseal {};
    let unseal_handles = UnsealHandles {
        item_handle: blob_handle,
    };
    let (unseal_rsp, _) =
        execute_with_password_sessions(sim, &unseal_cmd, unseal_handles, 1, auth)?;
    assert_eq!(unseal_rsp.out_data.get_buffer(), expected_data);
    Ok(())
}

fn hmac_unseal_verify(
    sim: &mut Simulator<'_>,
    blob_handle: Handle,
    sessions: &mut [ActiveSession],
    auths: &[&[u8]],
    _auth: &[u8],
    expected_data: &[u8],
) -> Result<(), u32> {
    let unseal_cmd = Unseal {};
    let unseal_handles = UnsealHandles {
        item_handle: blob_handle,
    };
    let (unseal_rsp, _) =
        execute_with_hmac_sessions(sim, &unseal_cmd, unseal_handles, &[], sessions, auths)?;
    assert_eq!(unseal_rsp.out_data.get_buffer(), expected_data);
    Ok(())
}

fn persistent_hmac_unseal_verify(
    sim: &mut Simulator<'_>,
    blob_handle: Handle,
    sessions: &mut [ActiveSession],
    auths: &[&[u8]],
    _auth: &[u8],
    expected_data: &[u8],
) -> Result<(), u32> {
    let unseal_cmd = Unseal {};
    let unseal_handles = UnsealHandles {
        item_handle: blob_handle,
    };
    for _ in 0..3 {
        let (unseal_rsp, _) =
            execute_with_hmac_sessions(sim, &unseal_cmd, unseal_handles, &[], sessions, auths)?;
        assert_eq!(unseal_rsp.out_data.get_buffer(), expected_data);
    }
    Ok(())
}

// =========================================================================
// RSA Sealing / Unsealing Tests
// =========================================================================

// Original Go test: sealing_test.go - TestUnseal/RSA/Create
#[test]
fn test_unseal_rsa_create() {
    run_sealing_test_full(
        false,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateAudit
#[test]
fn test_unseal_rsa_create_audit() {
    run_sealing_test_full(
        false,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess.attributes =
                TpmaSession::AUDIT | TpmaSession::AUDIT_EXCLUSIVE | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecrypt
#[test]
fn test_unseal_rsa_create_decrypt() {
    run_sealing_test_full(
        false,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateEncrypt
#[test]
fn test_unseal_rsa_create_encrypt() {
    run_sealing_test_full(
        false,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncrypt
#[test]
fn test_unseal_rsa_create_decrypt_encrypt() {
    run_sealing_test_full(
        false,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes =
                TpmaSession::DECRYPT | TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncryptAudit
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_audit() {
    run_sealing_test_full(
        false,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::DECRYPT
                | TpmaSession::ENCRYPT
                | TpmaSession::AUDIT
                | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncryptSalted
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_salted() {
    run_sealing_test_full(
        false,
        |sim, srk_handle, srk_public, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                srk_handle,
                Some(srk_public),
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes =
                TpmaSession::DECRYPT | TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncryptSeparate
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_separate() {
    run_sealing_test_full(
        false,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess2.attributes =
                TpmaSession::DECRYPT | TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            entity_auths.push(b"mySRK".to_vec());
            entity_auths.push(Vec::new());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncryptAuditSeparate
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_audit_separate() {
    run_sealing_test_full(
        false,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess2.attributes =
                TpmaSession::DECRYPT | TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            let mut sess3 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess3.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            sessions.push(sess3);
            entity_auths.push(b"mySRK".to_vec());
            entity_auths.push(Vec::new());
            entity_auths.push(Vec::new());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncryptAuditExclusiveSeparate
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_audit_exclusive_separate() {
    run_sealing_test_full(
        false,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess2.attributes =
                TpmaSession::DECRYPT | TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            let mut sess3 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess3.attributes =
                TpmaSession::AUDIT | TpmaSession::AUDIT_EXCLUSIVE | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            sessions.push(sess3);
            entity_auths.push(b"mySRK".to_vec());
            entity_auths.push(Vec::new());
            entity_auths.push(Vec::new());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncrypt2Separate#00
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_2_separate_1() {
    run_sealing_test_full(
        false,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha1,
            );
            sess2.attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;

            let mut sess3 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha384,
            );
            sess3.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            sessions.push(sess3);
            entity_auths.push(b"mySRK".to_vec());
            entity_auths.push(Vec::new());
            entity_auths.push(Vec::new());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncrypt2Separate#01
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_2_separate_2() {
    run_sealing_test_full(
        false,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha1,
            );
            sess2.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            let mut sess3 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess3.attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            sessions.push(sess3);
            entity_auths.push(b"mySRK".to_vec());
            entity_auths.push(Vec::new());
            entity_auths.push(Vec::new());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithPassword
#[test]
fn test_unseal_rsa_with_password() {
    run_sealing_test_full(
        false,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithWrongPassword
#[test]
fn test_unseal_rsa_with_wrong_password() {
    run_sealing_test_full(
        false,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        |sim, blob_handle, _sessions, _auths, _auth, _expected_data| {
            let unseal_cmd = Unseal {};
            let unseal_handles = UnsealHandles {
                item_handle: blob_handle,
            };
            let err = execute_with_password_sessions(
                sim,
                &unseal_cmd,
                unseal_handles,
                1,
                b"NotThePassword",
            )
            .unwrap_err();
            assert_eq!(err, TpmRc::BAD_AUTH.with(Position::session(1)).get());
            Ok(())
        },
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithHMAC
#[test]
fn test_unseal_rsa_with_hmac() {
    run_sealing_test_full(
        false,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |sim, _srk, _srk_pub, _blob, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"p@ssw0rd".to_vec()); // Trimmed auth2
        },
        hmac_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithHMACEncrypt
#[test]
fn test_unseal_rsa_with_hmac_encrypt() {
    run_sealing_test_full(
        false,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |sim, _srk, _srk_pub, _blob, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"p@ssw0rd".to_vec()); // Trimmed auth2
        },
        hmac_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithHMACSession
#[test]
fn test_unseal_rsa_with_hmac_session() {
    run_sealing_test_full(
        false,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |sim, _srk, _srk_pub, _blob, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha1,
            );
            sess.attributes = TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"p@ssw0rd".to_vec()); // Trimmed auth2
        },
        persistent_hmac_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithHMACSessionEncrypt
#[test]
fn test_unseal_rsa_with_hmac_session_encrypt() {
    run_sealing_test_full(
        false,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |sim, srk_handle, _srk_pub, _blob, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                srk_handle,
                b"mySRK",
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"p@ssw0rd".to_vec());
        },
        persistent_hmac_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithHMACSessionEncryptSeparate
#[test]
fn test_unseal_rsa_with_hmac_session_encrypt_separate() {
    run_sealing_test_full(
        false,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |sim, srk_handle, _srk_pub, _blob, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha1,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                srk_handle,
                b"mySRK",
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha384,
            );
            sess2.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            entity_auths.push(b"p@ssw0rd".to_vec());
            entity_auths.push(b"mySRK".to_vec());
        },
        persistent_hmac_unseal_verify,
    );
}

// =========================================================================
// ECC Sealing / Unsealing Tests
// =========================================================================

// Original Go test: sealing_test.go - TestUnseal/ECC/Create
#[test]
fn test_unseal_ecc_create() {
    run_sealing_test_full(
        true,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateAudit
#[test]
fn test_unseal_ecc_create_audit() {
    run_sealing_test_full(
        true,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess.attributes =
                TpmaSession::AUDIT | TpmaSession::AUDIT_EXCLUSIVE | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecrypt
#[test]
fn test_unseal_ecc_create_decrypt() {
    run_sealing_test_full(
        true,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateEncrypt
#[test]
fn test_unseal_ecc_create_encrypt() {
    run_sealing_test_full(
        true,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncrypt
#[test]
fn test_unseal_ecc_create_decrypt_encrypt() {
    run_sealing_test_full(
        true,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes =
                TpmaSession::DECRYPT | TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncryptAudit
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_audit() {
    run_sealing_test_full(
        true,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::DECRYPT
                | TpmaSession::ENCRYPT
                | TpmaSession::AUDIT
                | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncryptSalted
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_salted() {
    run_sealing_test_full(
        true,
        |sim, srk_handle, srk_public, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                srk_handle,
                Some(srk_public),
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes =
                TpmaSession::DECRYPT | TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"mySRK".to_vec());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncryptSeparate
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_separate() {
    run_sealing_test_full(
        true,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess2.attributes =
                TpmaSession::DECRYPT | TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            entity_auths.push(b"mySRK".to_vec());
            entity_auths.push(Vec::new());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncryptAuditSeparate
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_audit_separate() {
    run_sealing_test_full(
        true,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess2.attributes =
                TpmaSession::DECRYPT | TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            let mut sess3 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess3.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            sessions.push(sess3);
            entity_auths.push(b"mySRK".to_vec());
            entity_auths.push(Vec::new());
            entity_auths.push(Vec::new());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncryptAuditExclusiveSeparate
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_audit_exclusive_separate() {
    run_sealing_test_full(
        true,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess2.attributes =
                TpmaSession::DECRYPT | TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            let mut sess3 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess3.attributes =
                TpmaSession::AUDIT | TpmaSession::AUDIT_EXCLUSIVE | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            sessions.push(sess3);
            entity_auths.push(b"mySRK".to_vec());
            entity_auths.push(Vec::new());
            entity_auths.push(Vec::new());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncrypt2Separate#00
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_2_separate_1() {
    run_sealing_test_full(
        true,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha1,
            );
            sess2.attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;

            let mut sess3 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha384,
            );
            sess3.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            sessions.push(sess3);
            entity_auths.push(b"mySRK".to_vec());
            entity_auths.push(Vec::new());
            entity_auths.push(Vec::new());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncrypt2Separate#01
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_2_separate_2() {
    run_sealing_test_full(
        true,
        |sim, _srk, _srk_pub, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha1,
            );
            sess2.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            let mut sess3 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess3.attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            sessions.push(sess3);
            entity_auths.push(b"mySRK".to_vec());
            entity_auths.push(Vec::new());
            entity_auths.push(Vec::new());
        },
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithPassword
#[test]
fn test_unseal_ecc_with_password() {
    run_sealing_test_full(
        true,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        std_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithWrongPassword
#[test]
fn test_unseal_ecc_with_wrong_password() {
    run_sealing_test_full(
        true,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |_sim, _srk, _srk_pub, _blob, _sess, _auths| {},
        |sim, blob_handle, _sessions, _auths, _auth, _expected_data| {
            let unseal_cmd = Unseal {};
            let unseal_handles = UnsealHandles {
                item_handle: blob_handle,
            };
            let err = execute_with_password_sessions(
                sim,
                &unseal_cmd,
                unseal_handles,
                1,
                b"NotThePassword",
            )
            .unwrap_err();
            assert_eq!(err, TpmRc::BAD_AUTH.with(Position::session(1)).get());
            Ok(())
        },
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithHMAC
#[test]
fn test_unseal_ecc_with_hmac() {
    run_sealing_test_full(
        true,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |sim, _srk, _srk_pub, _blob, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"p@ssw0rd".to_vec()); // Trimmed auth2
        },
        hmac_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithHMACEncrypt
#[test]
fn test_unseal_ecc_with_hmac_encrypt() {
    run_sealing_test_full(
        true,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |sim, _srk, _srk_pub, _blob, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"p@ssw0rd".to_vec()); // Trimmed auth2
        },
        hmac_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithHMACSession
#[test]
fn test_unseal_ecc_with_hmac_session() {
    run_sealing_test_full(
        true,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |sim, _srk, _srk_pub, _blob, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha1,
            );
            sess.attributes = TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"p@ssw0rd".to_vec()); // Trimmed auth2
        },
        persistent_hmac_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithHMACSessionEncrypt
#[test]
fn test_unseal_ecc_with_hmac_session_encrypt() {
    run_sealing_test_full(
        true,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |sim, srk_handle, _srk_pub, _blob, sessions, entity_auths| {
            let mut sess = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                srk_handle,
                b"mySRK",
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha256,
            );
            sess.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;
            sessions.push(sess);
            entity_auths.push(b"p@ssw0rd".to_vec());
        },
        persistent_hmac_unseal_verify,
    );
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithHMACSessionEncryptSeparate
#[test]
fn test_unseal_ecc_with_hmac_session_encrypt_separate() {
    run_sealing_test_full(
        true,
        |_sim, _srk, _srk_pub, _sess, _auths| {},
        |sim, srk_handle, _srk_pub, _blob, sessions, entity_auths| {
            let mut sess1 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                None,
                TpmiAlgHash::Sha1,
            );
            sess1.attributes = TpmaSession::CONTINUE_SESSION;

            let mut sess2 = start_auth_session_full(
                sim,
                Handle::RH_NULL,
                None,
                srk_handle,
                b"mySRK",
                TpmSe::HMAC,
                Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                TpmiAlgHash::Sha384,
            );
            sess2.attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            sessions.push(sess1);
            sessions.push(sess2);
            entity_auths.push(b"p@ssw0rd".to_vec());
            entity_auths.push(b"mySRK".to_vec());
        },
        persistent_hmac_unseal_verify,
    );
}
