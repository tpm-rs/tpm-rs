use crate::test_utils::*;
use tpm2::commands::{
    Create, CreateHandles, CreatePrimary, CreatePrimaryHandles, PolicyGetDigest,
    PolicyGetDigestHandles, PolicySecret, PolicySecretHandles, ReadPublic, ReadPublicHandles,
};
use tpm2::{Handle, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bSensitiveData,
    TpmaNv, TpmaObject, TpmiAlgHash, TpmsNvPublic, TpmsSensitiveCreate, TpmtPublic,
    TpmtSymDefObject,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn hex_decode(s: &str) -> Vec<u8> {
    let mut res = Vec::with_capacity(s.len() / 2);
    let mut iter = s.chars().filter(|c| !c.is_whitespace());
    while let (Some(c1), Some(c2)) = (iter.next(), iter.next()) {
        let hex_str = format!("{}{}", c1, c2);
        res.push(u8::from_str_radix(&hex_str, 16).unwrap());
    }
    res
}

fn compute_hash(alg: TpmiAlgHash, data: &[&[u8]]) -> Vec<u8> {
    use sha1::Sha1;
    use sha2::{Digest, Sha256, Sha384, Sha512};
    match alg {
        TpmiAlgHash::Sha1 => {
            let mut hasher = Sha1::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha256 => {
            let mut hasher = Sha256::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha384 => {
            let mut hasher = Sha384::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha512 => {
            let mut hasher = Sha512::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        _ => panic!("Unsupported hash"),
    }
}

fn policy_or_go(alg: TpmiAlgHash, digests: &[&[u8]]) -> Vec<u8> {
    let digest_size = match alg {
        TpmiAlgHash::Sha1 => 20,
        TpmiAlgHash::Sha256 => 32,
        TpmiAlgHash::Sha384 => 48,
        TpmiAlgHash::Sha512 => 64,
        _ => panic!("Unsupported hash"),
    };
    let zero_digest = vec![0u8; digest_size];
    let cc_bytes = (tpm2::TpmCc::PolicyOR.code()).to_be_bytes();
    let mut updates = vec![zero_digest.as_slice(), &cc_bytes];
    for d in digests {
        updates.push(*d);
    }
    compute_hash(alg, &updates)
}

// Original Go test: ek_test.go - TestCalculatePolicyA
#[test]
fn test_calculate_policy_a() {
    let cases = vec![
        (
            TpmiAlgHash::Sha256,
            hex_decode("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa"),
        ),
        (
            TpmiAlgHash::Sha384,
            hex_decode(
                "8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53",
            ),
        ),
        (
            TpmiAlgHash::Sha512,
            hex_decode(
                "1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee",
            ),
        ),
    ];

    for (alg, expected_policy) in cases {
        let mut pol = PolicyCalculator::new(alg);
        let auth_name = Handle::RH_ENDORSEMENT.0.to_be_bytes();
        pol.policy_secret(&auth_name, &[]);
        assert_eq!(pol.policy_digest, expected_policy);
    }
}

// Original Go test: ek_test.go - TestCalculatePolicyIndexName
#[test]
fn test_calculate_policy_index_name() {
    let cases = vec![
        (
            TpmiAlgHash::Sha256,
            Handle(0x01C07F01),
            hex_decode("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa"),
            hex_decode("000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f"),
            34,
        ),
        (
            TpmiAlgHash::Sha384,
            Handle(0x01C07F02),
            hex_decode(
                "8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53",
            ),
            hex_decode(
                "000cdb62fca346612c976732ff4e8621fb4e858be82586486504f7d02e621f8d7d61ae32cfc60c4d120609ed6768afcf090c",
            ),
            50,
        ),
        (
            TpmiAlgHash::Sha512,
            Handle(0x01C07F03),
            hex_decode(
                "1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee",
            ),
            hex_decode(
                "000d1c47c0bbcbd3cf7d7cae6987d31937c171015dde3b7f0d3c869bca1f7e8a223b9acfadb49b7c9cf14d450f41e9327de34d9291eece2c58ab1dc10e9059cce560",
            ),
            66,
        ),
    ];

    for (alg, nv_index, auth_policy, expected_name, data_size) in cases {
        let nv_pub = TpmsNvPublic {
            nv_index,
            name_alg: alg,
            attributes: TpmaNv::POLICYWRITE
                | TpmaNv::WRITEALL
                | TpmaNv::PPREAD
                | TpmaNv::OWNERREAD
                | TpmaNv::AUTHREAD
                | TpmaNv::POLICYREAD
                | TpmaNv::NO_DA
                | TpmaNv::WRITTEN,
            auth_policy: Tpm2bDigest::from_bytes(&auth_policy).unwrap(),
            data_size,
        };
        let computed_name = nv_name(&nv_pub);
        assert_eq!(computed_name.get_buffer(), expected_name);
    }
}

// Original Go test: ek_test.go - TestCalculatePolicyC
#[test]
fn test_calculate_policy_c() {
    let cases = vec![
        (
            TpmiAlgHash::Sha256,
            hex_decode("000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f"),
            hex_decode("3767e2edd43ff45a3a7e1eaefcef78643dca964632e7aad82c673a30d8633fde"),
        ),
        (
            TpmiAlgHash::Sha384,
            hex_decode(
                "000cdb62fca346612c976732ff4e8621fb4e858be82586486504f7d02e621f8d7d61ae32cfc60c4d120609ed6768afcf090c",
            ),
            hex_decode(
                "d6032ce61f2fb3c240eb3cf6a33237ef2b6a16f4293c22b455e261cffd217ad5b4947c2d73e63005eed2dc2b3593d165",
            ),
        ),
        (
            TpmiAlgHash::Sha512,
            hex_decode(
                "000d1c47c0bbcbd3cf7d7cae6987d31937c171015dde3b7f0d3c869bca1f7e8a223b9acfadb49b7c9cf14d450f41e9327de34d9291eece2c58ab1dc10e9059cce560",
            ),
            hex_decode(
                "589ee1e146544716e8deafe6db247b01b81e9f9c7dd16b814aa159138749105fba5388dd1dea702f35240c184933121e2c61b8f50d3ef91393a49a38c3f73fc8",
            ),
        ),
    ];

    for (alg, nv_name, expected_policy) in cases {
        let mut pol = PolicyCalculator::new(alg);
        let name = Tpm2bName::from_bytes(&nv_name).unwrap();
        pol.policy_authorize_nv(&name);
        assert_eq!(pol.policy_digest, expected_policy);
    }
}

// Original Go test: ek_test.go - TestCalculatePolicyB
#[test]
fn test_calculate_policy_b() {
    let cases = vec![
        (
            TpmiAlgHash::Sha256,
            hex_decode("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa"),
            hex_decode("3767e2edd43ff45a3a7e1eaefcef78643dca964632e7aad82c673a30d8633fde"),
            hex_decode("ca3d0a99a2b93906f7a3342414efcfb3a385d44cd1fd459089d19b5071c0b7a0"),
        ),
        (
            TpmiAlgHash::Sha384,
            hex_decode(
                "8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53",
            ),
            hex_decode(
                "d6032ce61f2fb3c240eb3cf6a33237ef2b6a16f4293c22b455e261cffd217ad5b4947c2d73e63005eed2dc2b3593d165",
            ),
            hex_decode(
                "b26e7d28d11a50bc53d882bcf5fd3a1a074148bb35d3b4e4cb1c0ad9bde419cacb47ba09699646150f9fc000f3f80e12",
            ),
        ),
        (
            TpmiAlgHash::Sha512,
            hex_decode(
                "1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee",
            ),
            hex_decode(
                "589ee1e146544716e8deafe6db247b01b81e9f9c7dd16b814aa159138749105fba5388dd1dea702f35240c184933121e2c61b8f50d3ef91393a49a38c3f73fc8",
            ),
            hex_decode(
                "b8221ca69e8550a4914de3faa6a18c072cc01208073a928d5d66d59ef79e49a429c41a6b269571d57edb25fbdb1838425608b413cd616a5f6db5b6071af99bea",
            ),
        ),
    ];

    for (alg, policy_a, policy_c, expected_policy) in cases {
        let computed = policy_or_go(alg, &[&policy_a, &policy_c]);
        assert_eq!(computed, expected_policy);
    }
}

fn test_ek_policy_with_template(ek_template: TpmtPublic) {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(ek_template);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let create_primary_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_primary_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_ENDORSEMENT,
    };
    let (create_primary_resp, create_primary_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_cmd,
        create_primary_handles,
        1,
        &[],
    )
    .unwrap();

    let ek_handle = create_primary_resp_handles.object_handle;
    let ek_name = create_primary_resp.name;

    let read_pub_cmd = ReadPublic {};
    let read_pub_handles = ReadPublicHandles {
        object_handle: ek_handle,
    };
    let (read_pub_resp, _) =
        execute_with_password_sessions(&mut sim, &read_pub_cmd, read_pub_handles, 0, &[]).unwrap();
    assert_eq!(
        read_pub_resp.out_public.0.auth_policy,
        ek_template.auth_policy
    );

    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let policy_secret_cmd = PolicySecret {
        nonce_tpm: session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    let policy_secret_handles = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: session.session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_secret_cmd, policy_secret_handles, 1, &[])
            .unwrap();

    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: session.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();
    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        ek_template.auth_policy.get_buffer()
    );

    let create_cmd = Create {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_handles = CreateHandles {
        parent_handle: ek_handle,
    };

    let mut sessions = [session];
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[ek_name.get_buffer()],
        &mut sessions,
        &[&[]],
    )
    .unwrap();

    flush_context(&mut sim, ek_handle).unwrap();
}

struct EkTestCase {
    name: String,
    jit: bool,
    decrypt_policy_session: bool,
    decrypt_another_session: bool,
    bound: bool,
    salted: bool,
}

fn run_ek_policy(sim: &mut Simulator<'_>, session: &ActiveSession) {
    let policy_secret_cmd = PolicySecret {
        nonce_tpm: session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    let policy_secret_handles = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: session.session_handle,
    };
    let _ = execute_with_password_sessions(sim, &policy_secret_cmd, policy_secret_handles, 1, &[])
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn start_policy_session_opt(
    tpm: &mut Simulator<'_>,
    tpm_key: Handle,
    tpm_key_pub: Option<&TpmtPublic>,
    bind: Handle,
    bind_auth: &[u8],
    symmetric: Option<TpmtSymDefObject>,
    auth_hash: TpmiAlgHash,
    salted: bool,
) -> Result<ActiveSession, u32> {
    use tpm2::crypto::Rng;

    let mut nonce_bytes = [0u8; 16];
    tpm.context
        .platform
        .crypto
        .get_random(&mut nonce_bytes)
        .unwrap();
    let nonce_caller = Tpm2bNonce::from_bytes(crate::test_utils::leak_bytes(&nonce_bytes)).unwrap();

    let mut encrypted_salt = tpm2::Tpm2bEncryptedSecret::default();
    let mut salt_opt = None;
    let mut ecc_info_opt = None;

    if salted && tpm_key != Handle::RH_NULL {
        let pub_area = tpm_key_pub.expect("tpm_key_pub is required if salted is true");
        let mut rng = rand::rngs::OsRng;
        match &pub_area.parms_and_id {
            PublicParmsAndId::Rsa(rsa_parms, rsa_unique) => {
                let mut salt = [0u8; 32];
                tpm.context.platform.crypto.get_random(&mut salt).unwrap();

                let modulus = rsa_unique.get_buffer();
                let exponent = if rsa_parms.exponent == 0 {
                    65537
                } else {
                    rsa_parms.exponent
                };

                use rsa::{Oaep, RsaPublicKey};
                let rsa_key = RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(modulus),
                    rsa::BigUint::from(exponent),
                )
                .unwrap();
                let enc_salt = rsa_key
                    .encrypt(
                        &mut rng,
                        Oaep::new_with_label::<sha2::Sha256, _>("SECRET\0"),
                        &salt,
                    )
                    .unwrap();
                encrypted_salt = tpm2::Tpm2bEncryptedSecret::from_bytes(
                    crate::test_utils::leak_bytes(&enc_salt),
                )
                .unwrap();
                salt_opt = Some(salt.to_vec());
            }
            PublicParmsAndId::Ecc(_, ecc_unique) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                let eph_private = p256::SecretKey::random(&mut rng);
                let eph_public = eph_private.public_key();
                let eph_encoded = eph_public.to_encoded_point(false);
                let eph_xy = eph_encoded.as_bytes(); // starts with 0x04, length 65
                assert_eq!(eph_xy[0], 0x04);

                let x_2b = tpm2::Tpm2bEccParameter::from_bytes(&eph_xy[1..33]).unwrap();
                let y_2b = tpm2::Tpm2bEccParameter::from_bytes(&eph_xy[33..65]).unwrap();
                let eph_point = tpm2::TpmsEccPoint { x: x_2b, y: y_2b };
                let mut enc_salt_bytes = [0u8; 1024];
                let len = marshal_to_slice(&eph_point, &mut enc_salt_bytes);
                encrypted_salt = tpm2::Tpm2bEncryptedSecret::from_bytes(
                    crate::test_utils::leak_bytes(&enc_salt_bytes[..len]),
                )
                .unwrap();

                // Compute ECDH shared secret
                let ek_x = ecc_unique.x.get_buffer();
                let ek_y = ecc_unique.y.get_buffer();
                let mut ek_xy_full = [0u8; 65];
                ek_xy_full[0] = 0x04;
                ek_xy_full[33 - ek_x.len()..33].copy_from_slice(ek_x);
                ek_xy_full[65 - ek_y.len()..65].copy_from_slice(ek_y);

                let ek_public = p256::PublicKey::from_sec1_bytes(&ek_xy_full).unwrap();
                let shared_secret = p256::ecdh::diffie_hellman(
                    eph_private.to_nonzero_scalar(),
                    ek_public.as_affine(),
                );
                let z_x = shared_secret.raw_secret_bytes(); // X coordinate (32 bytes)
                salt_opt = Some(z_x.to_vec());
                ecc_info_opt = Some((eph_xy[1..33].to_vec(), ecc_unique.x.get_buffer().to_vec()));
            }
            _ => panic!("Unsupported key type for salting"),
        }
    }

    let cmd = tpm2::commands::StartAuthSession {
        nonce_caller,
        encrypted_salt,
        session_type: TpmSe::Policy,
        symmetric: symmetric.map(tpm2::TpmtSymDef::from),
        auth_hash,
    };
    let handles = tpm2::commands::StartAuthSessionHandles { tpm_key, bind };

    let (resp, resp_handles) = execute_with_password_sessions(tpm, &cmd, handles, 0, &[])?;

    let mut secret = Vec::new();
    if salted && tpm_key != Handle::RH_NULL {
        let pub_area = tpm_key_pub.unwrap();
        let z_x = salt_opt.unwrap();
        match &pub_area.parms_and_id {
            PublicParmsAndId::Rsa(_, _) => {
                secret = z_x;
            }
            PublicParmsAndId::Ecc(_, _) => {
                let (eph_x, ek_x) = ecc_info_opt.as_ref().unwrap();
                let mut padded_ek_x = [0u8; 32];
                padded_ek_x[32 - ek_x.len()..].copy_from_slice(ek_x);

                let mut derived_salt = [0u8; 32];
                tpm2::crypto::kdf::kdfe(
                    tpm.context.platform.crypto,
                    TpmiAlgHash::Sha256,
                    &z_x,
                    b"SECRET",
                    eph_x,
                    &padded_ek_x,
                    256,
                    &mut derived_salt,
                )
                .unwrap();
                secret = derived_salt.to_vec();
            }
            _ => {}
        }
    }

    let session_key = if bind == Handle::RH_NULL && tpm_key == Handle::RH_NULL {
        Vec::new()
    } else {
        let mut key = secret;
        key.extend_from_slice(bind_auth);

        let hash_size = match auth_hash {
            TpmiAlgHash::Sha1 => 20,
            TpmiAlgHash::Sha256 => 32,
            TpmiAlgHash::Sha384 => 48,
            TpmiAlgHash::Sha512 => 64,
            _ => 32,
        };
        let session_key_bits = (hash_size as u32) * 8;
        let mut derived = vec![0u8; (session_key_bits.div_ceil(8)) as usize];

        tpm2::crypto::kdf::kdfa(
            tpm.context.platform.crypto,
            auth_hash,
            &key,
            b"ATH",
            resp.nonce_tpm.get_buffer(),
            nonce_caller.get_buffer(),
            session_key_bits,
            &mut derived,
        )
        .unwrap();
        derived
    };

    Ok(ActiveSession {
        session_handle: resp_handles.session_handle,
        nonce_caller,
        nonce_tpm: resp.nonce_tpm,
        session_key,
        auth_hash,
        symmetric,
        attributes: tpm2::TpmaSession::from_bits_retain(0),
        bind_auth: bind_auth.to_vec(),
        bind_entity: bind,
    })
}

fn run_ek_test_case(ek_template: TpmtPublic, case: &EkTestCase) {
    let mut sim = create_simulator!();

    // 1. Create EK
    let in_public = tpm2::Tpm2b(ek_template);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let create_primary_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_primary_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_ENDORSEMENT,
    };
    let (create_primary_resp, create_primary_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_cmd,
        create_primary_handles,
        1,
        &[],
    )
    .unwrap();

    let ek_handle = create_primary_resp_handles.object_handle;
    let ek_name = create_primary_resp.name;
    let ek_public = create_primary_resp.out_public.0;

    // 2. Setup sessions
    let mut decrypt_session = None;

    if case.decrypt_another_session {
        let dec_sess = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            Some(tpm2::TpmtSymDefObject::Aes128(Some(
                tpm2::TpmiAlgSymMode::CFB,
            ))),
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        std::println!(
            "DEBUG: dec_sess started: handle={:x?}, nonce_tpm={:x?}",
            dec_sess.session_handle,
            dec_sess.nonce_tpm
        );
        decrypt_session = Some(dec_sess);
    }

    let bind_handle = if case.bound {
        ek_handle
    } else {
        Handle::RH_NULL
    };
    let tpm_key_handle = if case.salted {
        ek_handle
    } else {
        Handle::RH_NULL
    };

    let sym_def = if case.decrypt_policy_session {
        Some(tpm2::TpmtSymDefObject::Aes128(Some(
            tpm2::TpmiAlgSymMode::CFB,
        )))
    } else {
        None
    };

    let mut policy_session = start_policy_session_opt(
        &mut sim,
        tpm_key_handle,
        Some(&ek_public),
        bind_handle,
        &[],
        sym_def,
        TpmiAlgHash::Sha256,
        case.salted,
    )
    .unwrap();
    std::println!(
        "DEBUG: policy_session started: handle={:x?}, nonce_tpm={:x?}",
        policy_session.session_handle,
        policy_session.nonce_tpm
    );

    run_ek_policy(&mut sim, &policy_session);

    let create_cmd = Create {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_handles = CreateHandles {
        parent_handle: ek_handle,
    };

    let mut cmd_sessions = vec![policy_session.clone()];
    if let Some(ref dec_sess) = decrypt_session {
        let mut d = dec_sess.clone();
        d.attributes.insert(tpm2::TpmaSession::DECRYPT);
        d.attributes.insert(tpm2::TpmaSession::CONTINUE_SESSION);
        cmd_sessions.push(d);
    }
    if case.decrypt_policy_session {
        cmd_sessions[0]
            .attributes
            .insert(tpm2::TpmaSession::DECRYPT);
    }
    cmd_sessions[0]
        .attributes
        .insert(tpm2::TpmaSession::CONTINUE_SESSION);

    let mut entity_auths = vec![&[][..]];
    if case.decrypt_another_session {
        entity_auths.push(&[]);
    }

    let res = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[ek_name.get_buffer()],
        &mut cmd_sessions,
        &entity_auths,
    );
    assert!(res.is_ok(), "First execute failed: {:?}", res.err());

    policy_session = cmd_sessions[0].clone();
    if decrypt_session.is_some() {
        decrypt_session = Some(cmd_sessions[1].clone());
    }

    if case.jit {
        run_ek_policy(&mut sim, &policy_session);

        let mut cmd_sessions2 = vec![policy_session.clone()];
        if let Some(ref dec_sess) = decrypt_session {
            let mut d = dec_sess.clone();
            d.attributes.insert(tpm2::TpmaSession::DECRYPT);
            d.attributes.insert(tpm2::TpmaSession::CONTINUE_SESSION);
            cmd_sessions2.push(d);
        }
        if case.decrypt_policy_session {
            cmd_sessions2[0]
                .attributes
                .insert(tpm2::TpmaSession::DECRYPT);
        }
        cmd_sessions2[0]
            .attributes
            .insert(tpm2::TpmaSession::CONTINUE_SESSION);

        let res2 = execute_with_hmac_sessions(
            &mut sim,
            &create_cmd,
            create_handles,
            &[ek_name.get_buffer()],
            &mut cmd_sessions2,
            &entity_auths,
        );
        assert!(
            res2.is_ok(),
            "Second execute (JIT) failed: {:?}",
            res2.err()
        );
    } else {
        let mut cmd_sessions2 = vec![policy_session.clone()];
        if let Some(ref dec_sess) = decrypt_session {
            let mut d = dec_sess.clone();
            d.attributes.insert(tpm2::TpmaSession::DECRYPT);
            d.attributes.insert(tpm2::TpmaSession::CONTINUE_SESSION);
            cmd_sessions2.push(d);
        }
        if case.decrypt_policy_session {
            cmd_sessions2[0]
                .attributes
                .insert(tpm2::TpmaSession::DECRYPT);
        }
        cmd_sessions2[0]
            .attributes
            .insert(tpm2::TpmaSession::CONTINUE_SESSION);

        let res2 = execute_with_hmac_sessions(
            &mut sim,
            &create_cmd,
            create_handles,
            &[ek_name.get_buffer()],
            &mut cmd_sessions2,
            &entity_auths,
        );
        assert!(
            res2.is_err(),
            "Expected failure without PolicySecret, but succeeded!"
        );
        let err_code = res2.err().unwrap();
        assert_eq!(
            err_code, 0x99D,
            "Expected error 0x99D, got 0x{:03X}",
            err_code
        );

        run_ek_policy(&mut sim, &policy_session);

        let res3 = execute_with_hmac_sessions(
            &mut sim,
            &create_cmd,
            create_handles,
            &[ek_name.get_buffer()],
            &mut cmd_sessions2,
            &entity_auths,
        );
        assert!(
            res3.is_ok(),
            "Third execute (after restart) failed: {:?}",
            res3.err()
        );
    }

    flush_context(&mut sim, ek_handle).unwrap();
    if let Some(dec_sess) = decrypt_session {
        flush_context(&mut sim, dec_sess.session_handle).unwrap();
    }
    flush_context(&mut sim, policy_session.session_handle).unwrap();
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone
#[test]
fn test_ek_policy_standalone_dec_none_unbound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_none_unbound_unsalted".to_string(),
        jit: false,
        decrypt_policy_session: false,
        decrypt_another_session: false,
        bound: false,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone-salted
#[test]
fn test_ek_policy_standalone_dec_none_unbound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_none_unbound_salted".to_string(),
        jit: false,
        decrypt_policy_session: false,
        decrypt_another_session: false,
        bound: false,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone-bound
#[test]
fn test_ek_policy_standalone_dec_none_bound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_none_bound_unsalted".to_string(),
        jit: false,
        decrypt_policy_session: false,
        decrypt_another_session: false,
        bound: true,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone-bound-salted
#[test]
fn test_ek_policy_standalone_dec_none_bound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_none_bound_salted".to_string(),
        jit: false,
        decrypt_policy_session: false,
        decrypt_another_session: false,
        bound: true,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone-decrypt-another
#[test]
fn test_ek_policy_standalone_dec_another_unbound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_another_unbound_unsalted".to_string(),
        jit: false,
        decrypt_policy_session: false,
        decrypt_another_session: true,
        bound: false,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone-decrypt-another-salted
#[test]
fn test_ek_policy_standalone_dec_another_unbound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_another_unbound_salted".to_string(),
        jit: false,
        decrypt_policy_session: false,
        decrypt_another_session: true,
        bound: false,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone-decrypt-another-bound
#[test]
fn test_ek_policy_standalone_dec_another_bound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_another_bound_unsalted".to_string(),
        jit: false,
        decrypt_policy_session: false,
        decrypt_another_session: true,
        bound: true,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone-decrypt-another-bound-salted
#[test]
fn test_ek_policy_standalone_dec_another_bound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_another_bound_salted".to_string(),
        jit: false,
        decrypt_policy_session: false,
        decrypt_another_session: true,
        bound: true,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone-decrypt-same
#[test]
fn test_ek_policy_standalone_dec_same_unbound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_same_unbound_unsalted".to_string(),
        jit: false,
        decrypt_policy_session: true,
        decrypt_another_session: false,
        bound: false,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone-decrypt-same-salted
#[test]
fn test_ek_policy_standalone_dec_same_unbound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_same_unbound_salted".to_string(),
        jit: false,
        decrypt_policy_session: true,
        decrypt_another_session: false,
        bound: false,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone-decrypt-same-bound
#[test]
fn test_ek_policy_standalone_dec_same_bound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_same_bound_unsalted".to_string(),
        jit: false,
        decrypt_policy_session: true,
        decrypt_another_session: false,
        bound: true,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-standalone-decrypt-same-bound-salted
#[test]
fn test_ek_policy_standalone_dec_same_bound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_standalone_dec_same_bound_salted".to_string(),
        jit: false,
        decrypt_policy_session: true,
        decrypt_another_session: false,
        bound: true,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit
#[test]
fn test_ek_policy_jit_dec_none_unbound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_none_unbound_unsalted".to_string(),
        jit: true,
        decrypt_policy_session: false,
        decrypt_another_session: false,
        bound: false,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit-salted
#[test]
fn test_ek_policy_jit_dec_none_unbound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_none_unbound_salted".to_string(),
        jit: true,
        decrypt_policy_session: false,
        decrypt_another_session: false,
        bound: false,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit-bound
#[test]
fn test_ek_policy_jit_dec_none_bound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_none_bound_unsalted".to_string(),
        jit: true,
        decrypt_policy_session: false,
        decrypt_another_session: false,
        bound: true,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit-bound-salted
#[test]
fn test_ek_policy_jit_dec_none_bound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_none_bound_salted".to_string(),
        jit: true,
        decrypt_policy_session: false,
        decrypt_another_session: false,
        bound: true,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit-decrypt-another
#[test]
fn test_ek_policy_jit_dec_another_unbound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_another_unbound_unsalted".to_string(),
        jit: true,
        decrypt_policy_session: false,
        decrypt_another_session: true,
        bound: false,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit-decrypt-another-salted
#[test]
fn test_ek_policy_jit_dec_another_unbound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_another_unbound_salted".to_string(),
        jit: true,
        decrypt_policy_session: false,
        decrypt_another_session: true,
        bound: false,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit-decrypt-another-bound
#[test]
fn test_ek_policy_jit_dec_another_bound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_another_bound_unsalted".to_string(),
        jit: true,
        decrypt_policy_session: false,
        decrypt_another_session: true,
        bound: true,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit-decrypt-another-bound-salted
#[test]
fn test_ek_policy_jit_dec_another_bound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_another_bound_salted".to_string(),
        jit: true,
        decrypt_policy_session: false,
        decrypt_another_session: true,
        bound: true,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit-decrypt-same
#[test]
fn test_ek_policy_jit_dec_same_unbound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_same_unbound_unsalted".to_string(),
        jit: true,
        decrypt_policy_session: true,
        decrypt_another_session: false,
        bound: false,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit-decrypt-same-salted
#[test]
fn test_ek_policy_jit_dec_same_unbound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_same_unbound_salted".to_string(),
        jit: true,
        decrypt_policy_session: true,
        decrypt_another_session: false,
        bound: false,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit-decrypt-same-bound
#[test]
fn test_ek_policy_jit_dec_same_bound_unsalted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_same_bound_unsalted".to_string(),
        jit: true,
        decrypt_policy_session: true,
        decrypt_another_session: false,
        bound: true,
        salted: false,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}

// Original Go test: ek_test.go - TestEKPolicy/test-jit-decrypt-same-bound-salted
#[test]
fn test_ek_policy_jit_dec_same_bound_salted() {
    let case = EkTestCase {
        name: "test_ek_policy_jit_dec_same_bound_salted".to_string(),
        jit: true,
        decrypt_policy_session: true,
        decrypt_another_session: false,
        bound: true,
        salted: true,
    };
    run_ek_test_case(rsa_ek_template(), &case);
    run_ek_test_case(ecc_ek_template(), &case);
}
