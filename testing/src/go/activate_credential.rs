#![forbid(unsafe_code)]
use crate::test_utils::marshal_to_slice;
// Ported from tpm-go/tpm2/test/activate_credential_test.go

use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, MakeCredential, MakeCredentialHandles};
use tpm2::crypto::Rng;
use tpm2::crypto::asymmetric::KeyParams;
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{Asymmetric, Ecc};
use tpm2::{
    Alg, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret,
    Tpm2bIdObject, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmiAlgSymMode,
    TpmiRsaKeyBits, TpmsEccParms, TpmsEccPoint, TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic,
    TpmtSymDefObject,
};
use tpm2_platform_linux::{LinuxRng, PlatformCryptoProvider};
use tpm2_simulator::{Simulator, create_simulator};

/// Returns the TPM 2.0 public template for an ECC Endorsement Key (EK)
/// using the SHA-256 name algorithm and NIST P-256 curve.
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

/// Returns the TPM 2.0 public template for an ECC Storage Root Key (SRK)
/// using the SHA-256 name algorithm and NIST P-256 curve.
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

/// Returns the TPM 2.0 public template for an RSA Storage Root Key (SRK)
/// using the SHA-256 name algorithm and 2048-bit key size.
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

/// Returns the TPM 2.0 public template for an ECC key using the SHA-384
/// name algorithm and NIST P-384 curve.
fn get_p384_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha384),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::Aes256(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP384,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

/// Software implementation for creating a credential challenge.
fn create_credential_software(
    ek_pub: &TpmtPublic,
    subject_name: &[u8],
    plaintext: &[u8],
) -> (Tpm2bIdObject<'static>, Tpm2bEncryptedSecret<'static>) {
    let crypto = PlatformCryptoProvider;
    let rng = LinuxRng::new();

    let name_alg = ek_pub.name_alg.unwrap();
    let digest_size = name_alg.digest_size();

    let (seed, secret) = match &ek_pub.parms_and_id {
        PublicParmsAndId::Rsa(_, pub_key) => {
            let mut seed = [0u8; 64];
            rng.get_random(&mut seed[..digest_size]).unwrap();

            let mut encrypted_seed = [0u8; 512];
            let encrypted_seed_len = crypto
                .encrypt(
                    Alg::OAEP,
                    Alg::from(name_alg),
                    pub_key.get_buffer(),
                    &seed[..digest_size],
                    &mut encrypted_seed,
                    b"IDENTITY\0",
                )
                .unwrap();
            let secret = Tpm2bEncryptedSecret::from_bytes(crate::test_utils::leak_bytes(
                &encrypted_seed[..encrypted_seed_len],
            ))
            .unwrap();
            (seed, secret)
        }
        PublicParmsAndId::Ecc(parms, point) => {
            let param_size = match parms.curve_id {
                tpm2::TpmEccCurve::NistP224 => 28,
                tpm2::TpmEccCurve::NistP256 | tpm2::TpmEccCurve::BNP256 => 32,
                tpm2::TpmEccCurve::NistP384 => 48,
                tpm2::TpmEccCurve::NistP521 => 66,
                _ => panic!("Unsupported curve {:?}", parms.curve_id),
            };

            let mut parent_ecc_pub_point = [0u8; 256];
            parent_ecc_pub_point[0..param_size].copy_from_slice(point.x.get_buffer());
            parent_ecc_pub_point[param_size..param_size * 2].copy_from_slice(point.y.get_buffer());

            let mut eph_pub = [0u8; 256];
            let mut eph_priv = [0u8; 128];
            let (_pub_len, priv_len) = crypto
                .generate_key(
                    Alg::ECDH,
                    Some(KeyParams::Ecc(parms.curve_id)),
                    &mut eph_pub,
                    &mut eph_priv,
                    None,
                )
                .unwrap();

            let mut ecdh_point = [0u8; 256];
            crypto
                .point_multiply(
                    parms.curve_id,
                    &eph_priv[..priv_len],
                    &parent_ecc_pub_point[..param_size * 2],
                    &mut ecdh_point[..param_size * 2],
                )
                .unwrap();

            let mut ex = [0u8; 128];
            ex[..param_size].copy_from_slice(&eph_pub[0..param_size]);
            let mut ey = [0u8; 128];
            ey[..param_size].copy_from_slice(&eph_pub[param_size..param_size * 2]);

            let eph_point = tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::from_bytes(&ex[..param_size]).unwrap(),
                y: tpm2::Tpm2bEccParameter::from_bytes(&ey[..param_size]).unwrap(),
            };

            let mut secret_buf = [0u8; 512];
            let secret_len = marshal_to_slice(&eph_point, &mut secret_buf);
            let secret = Tpm2bEncryptedSecret::from_bytes(crate::test_utils::leak_bytes(
                &secret_buf[..secret_len],
            ))
            .unwrap();

            let mut seed = [0u8; 64];
            let total_bits = (digest_size * 8) as u32;
            tpm2::crypto::kdf::kdfe(
                &crypto,
                name_alg,
                &ecdh_point[..param_size],
                b"IDENTITY",
                &eph_pub[..param_size],
                &parent_ecc_pub_point[..param_size],
                total_bits,
                &mut seed,
            )
            .unwrap();
            (seed, secret)
        }
        _ => panic!("Unsupported key type"),
    };

    let sym_alg = match &ek_pub.parms_and_id {
        PublicParmsAndId::Rsa(parms, _) => parms.symmetric,
        PublicParmsAndId::Ecc(parms, _) => parms.symmetric,
        _ => panic!("Unsupported key type"),
    };
    let sym_key_bits = match sym_alg {
        Some(TpmtSymDefObject::Aes128(_)) => 128,
        Some(TpmtSymDefObject::Aes256(_)) => 256,
        _ => 0,
    };
    let outer_key_len = (sym_key_bits / 8) as usize;

    let mut sym_key_iv = [0u8; 64];
    let mut integrity_key = [0u8; 64];

    kdfa(
        &crypto,
        name_alg,
        &seed[..digest_size],
        b"STORAGE",
        subject_name,
        &[],
        sym_key_bits,
        &mut sym_key_iv,
    )
    .unwrap();
    kdfa(
        &crypto,
        name_alg,
        &seed[..digest_size],
        b"INTEGRITY",
        &[],
        &[],
        (digest_size * 8) as u32,
        &mut integrity_key,
    )
    .unwrap();

    let mut credential_to_encrypt = [0u8; 68];
    let cred_len = plaintext.len();
    if cred_len > digest_size {
        panic!("Credential too long");
    }
    credential_to_encrypt[0..2].copy_from_slice(&(cred_len as u16).to_be_bytes());
    credential_to_encrypt[2..2 + cred_len].copy_from_slice(plaintext);
    let encrypt_len = 2 + cred_len;

    let mut iv = [0u8; 16];
    let sym_alg = sym_alg.expect("Unsupported symmetric algorithm");
    tpm2::crypto::encrypt(
        &crypto,
        sym_alg,
        &sym_key_iv[..outer_key_len],
        &mut iv,
        &mut credential_to_encrypt[..encrypt_len],
    )
    .unwrap();

    let mut hmac_state =
        tpm2::crypto::HmacCtx::new(&crypto, name_alg, &integrity_key[..digest_size]).unwrap();
    hmac_state
        .update(&credential_to_encrypt[..encrypt_len])
        .unwrap();
    hmac_state.update(subject_name).unwrap();
    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let hmac_digest = hmac_state.finalize(&mut hmac_buf).unwrap();
    let integrity_hmac = Tpm2bDigest::from_bytes(hmac_digest.digest()).unwrap();

    let id_obj =
        tpm2::TpmsIdObject::new(integrity_hmac, &credential_to_encrypt[..encrypt_len]).unwrap();
    let credential_blob = Tpm2bIdObject::from_bytes(crate::test_utils::leak_bytes(
        &crate::test_utils::marshal_to_vec(&id_obj),
    ))
    .unwrap();

    (credential_blob, secret)
}

// Original Go test: activate_credential_test.go - TestActivateTPMCredential
#[test]
fn test_activate_tpm_credential() {
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
    let create_handles_ek = CreatePrimaryHandles {
        primary_handle: Handle::RH_ENDORSEMENT,
    };
    let (ek_resp, ek_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_primary_ek, create_handles_ek, 0, &[])
            .expect("could not generate EK");

    // 2. Create ECC SRK under Owner Hierarchy
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let create_handles_srk = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (srk_resp, srk_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_primary_srk, create_handles_srk, 0, &[])
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

    // 4. ActivateCredential
    // Start policy session to satisfy EK policy
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        tpm2::TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("start policy session failed");

    // PolicySecret targeting the policy session and endorsement hierarchy
    use tpm2::commands::{PolicySecret, PolicySecretHandles};
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

    if let Some(sess) = sim.global_state.session(active_session.session_handle.0) {
        println!(
            "DEBUG session policy digest: {:02x?}",
            &sess.policy_digest[..sess.policy_digest_len]
        );
    }

    // Start an HMAC session for the activate_handle (SRK)
    let hmac_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        tpm2::TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("start HMAC session failed");

    use tpm2::commands::{ActivateCredential, ActivateCredentialHandles};
    let ac_cmd = ActivateCredential {
        credential_blob: mc_resp.credential_blob,
        secret: mc_resp.secret,
    };
    let ac_handles = ActivateCredentialHandles {
        activate_handle: srk_resp_handles.object_handle,
        key_handle: ek_resp_handles.object_handle,
    };

    let mut sessions = [hmac_session, active_session];
    let (ac_resp, _) = execute_with_hmac_sessions(
        &mut sim,
        &ac_cmd,
        ac_handles,
        &[srk_resp.name.get_buffer(), ek_resp.name.get_buffer()],
        &mut sessions,
        &[&[], &[]],
    )
    .expect("ActivateCredential failed");

    assert_eq!(ac_resp.cert_info.get_buffer(), secret.get_buffer());

    // Clean up
    flush_context(&mut sim, ek_resp_handles.object_handle).expect("flush EK failed");
    flush_context(&mut sim, srk_resp_handles.object_handle).expect("flush SRK failed");
}

fn run_activate_sw_credential_test(pub_template: TpmtPublic, sub_template: TpmtPublic) {
    let mut sim = create_simulator!();

    // 1. Create Primary (Storage Key that decrypts the credential challenge)
    let in_public = tpm2::Tpm2b(pub_template);
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    let create_primary_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let (_primary_resp, primary_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_cmd,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        0,
        &[],
    )
    .expect("CreatePrimary failed");

    // 2. Create the key that is going to be named in the challenge (Subject Key)
    let in_public_sub = tpm2::Tpm2b(sub_template);
    let create_primary_sub = CreatePrimary {
        in_sensitive,
        in_public: in_public_sub,
        ..Default::default()
    };
    let (sub_resp, sub_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_sub,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        0,
        &[],
    )
    .expect("CreatePrimary subject failed");

    // 3. Create the challenge in software
    let plaintext = Tpm2bDigest::from_bytes(b"hello, credential").unwrap();
    let primary_pub = _primary_resp.out_public.0;
    let (credential_blob, secret) = create_credential_software(
        &primary_pub,
        sub_resp.name.get_buffer(),
        plaintext.get_buffer(),
    );

    // 4. ActivateCredential
    use tpm2::commands::{ActivateCredential, ActivateCredentialHandles};
    let ac_cmd = ActivateCredential {
        credential_blob,
        secret,
    };
    let ac_handles = ActivateCredentialHandles {
        activate_handle: sub_resp_handles.object_handle,
        key_handle: primary_resp_handles.object_handle,
    };
    let (ac_resp, _) = execute_with_password_sessions(&mut sim, &ac_cmd, ac_handles, 2, &[])
        .expect("ActivateCredential failed");

    assert_eq!(ac_resp.cert_info.get_buffer(), plaintext.get_buffer());

    // Clean up
    flush_context(&mut sim, primary_resp_handles.object_handle).expect("flush primary failed");
    flush_context(&mut sim, sub_resp_handles.object_handle).expect("flush subject failed");
}

// Original Go test: activate_credential_test.go - TestActivateSWCredential/ECDH-P256 SRK activating RSA SRK
#[test]
fn test_activate_sw_credential_ecdh_p256_activating_rsa_srk() {
    run_activate_sw_credential_test(get_ecc_srk_template(), get_rsa_srk_template());
}

// Original Go test: activate_credential_test.go - TestActivateSWCredential/RSA-2048 SRK activating P256 SRK
#[test]
fn test_activate_sw_credential_rsa_2048_activating_p256_srk() {
    run_activate_sw_credential_test(get_rsa_srk_template(), get_ecc_srk_template());
}

// Original Go test: activate_credential_test.go - TestActivateSWCredential/ECDH-P256 SRK activating P384 key
#[test]
fn test_activate_sw_credential_ecdh_p256_activating_p384_key() {
    run_activate_sw_credential_test(get_ecc_srk_template(), get_p384_template());
}

// Original Go test: activate_credential_test.go - TestActivateSWCredential/RSA-2048 SRK activating P384 key
#[test]
fn test_activate_sw_credential_rsa_2048_activating_p384_key() {
    run_activate_sw_credential_test(get_rsa_srk_template(), get_p384_template());
}

// Original Go test: activate_credential_test.go - TestActivateSWCredential/P384 key activating P256 SRK
#[test]
fn test_activate_sw_credential_p384_key_activating_p256_srk() {
    run_activate_sw_credential_test(get_p384_template(), get_ecc_srk_template());
}

// Original Go test: activate_credential_test.go - TestActivateSWCredential/P384 key activating RSA SRK
#[test]
fn test_activate_sw_credential_p384_key_activating_rsa_srk() {
    run_activate_sw_credential_test(get_p384_template(), get_rsa_srk_template());
}
