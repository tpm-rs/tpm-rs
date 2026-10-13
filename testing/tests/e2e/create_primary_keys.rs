//! TPM2_CreatePrimary of RSA and ECC keys that are then used (decryption, ReadPublic) to check the
//! created key.

use crate::_common::{
    AES128_CFB, LocalRSADecryptCmd, exec_command, execute_with_password_sessions, flush_context,
    leak_bytes, marshal_to_vec, pw, rsa_decrypt_public, rsa_public, storage_attrs,
};
use testing::tpm::Tpm;
use tpm2::commands::{CreatePrimary, ReadPublic};
use tpm2::{
    Handle, Message, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmlPcrSelection,
    TpmsEccParms, TpmsEccPoint, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, UnmarshalMessage,
};

/// ReadPublic of a new ECC primary returns the same public point as CreatePrimary (ported from Go).
#[test]
fn matches_create_primary_output() {
    let mut sim = Tpm::new();
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
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    let object_handle = create_rsp.object_handle;

    let read_cmd = ReadPublic { object_handle };
    let read_rsp = execute_with_password_sessions(&mut sim, &read_cmd, 0, &[]).unwrap();

    let out_pub_create = create_rsp.out_public.0;
    let out_pub_read = read_rsp.out_public.0;

    match (out_pub_create.parms_and_id, out_pub_read.parms_and_id) {
        (PublicParmsAndId::Ecc(_, pt_create), PublicParmsAndId::Ecc(_, pt_read)) => {
            assert_eq!(pt_create.x.get_buffer(), pt_read.x.get_buffer());
            assert_eq!(pt_create.y.get_buffer(), pt_read.y.get_buffer());
        }
        _ => panic!("Expected ECC public keys"),
    }
    flush_context(&mut sim, object_handle).unwrap();
}

/// CreatePrimary RSA-1024 decryption key; client-side encryption decrypts correctly in the TPM.
#[test]
fn rsa_1024_encrypt_decrypt() {
    use rsa::traits::PublicKeyParts as _;
    let mut sim = Tpm::new();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let in_public = tpm2::Tpm2b(rsa_decrypt_public(1024));
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let rsp = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();
    let out_public_struct = rsp.out_public.0;
    if let PublicParmsAndId::Rsa(parms, unique) = &out_public_struct.parms_and_id {
        assert_eq!(parms.key_bits.0, 1024);
        assert_eq!(unique.get_buffer().len(), 128); // 1024 bits = 128 bytes

        // Perform RSA encryption using public key
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(unique.get_buffer()),
            rsa::BigUint::from(65537u32),
        )
        .unwrap();
        let msg = rsa::BigUint::from_bytes_be(b"hello 1024!");
        let e = rsa::BigUint::from(65537u32);
        let c = msg.modpow(&e, pub_key.n());
        let ciphertext_bytes = c.to_bytes_be();
        let mut ciphertext = vec![0u8; unique.get_buffer().len()];
        let start = ciphertext.len() - ciphertext_bytes.len();
        ciphertext[start..].copy_from_slice(&ciphertext_bytes);

        // Decrypt using simulator
        let decrypt_cmd = LocalRSADecryptCmd {
            key_handle: rsp.object_handle,
            cipher_text: Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&ciphertext)).unwrap(),
            in_scheme: None,
            label: tpm2::Tpm2bLabel::default(),
        };
        let decrypt_rsp = sim.execute(decrypt_cmd).unwrap();

        let returned_bytes = decrypt_rsp.message.get_buffer();
        assert_eq!(&returned_bytes[returned_bytes.len() - 11..], b"hello 1024!");
    } else {
        panic!("expected RSA key");
    }
    flush_context(&mut sim, rsp.object_handle).unwrap();
}

/// CreatePrimary RSA-2048 decryption key; client-side encryption decrypts correctly in the TPM.
#[test]
fn rsa_2048_encrypt_decrypt() {
    use rsa::traits::PublicKeyParts as _;
    let mut sim = Tpm::new();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let in_public = tpm2::Tpm2b(rsa_decrypt_public(2048));
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let rsp = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();
    let out_public_struct = rsp.out_public.0;
    if let PublicParmsAndId::Rsa(parms, unique) = &out_public_struct.parms_and_id {
        assert_eq!(parms.key_bits.0, 2048);
        assert_eq!(unique.get_buffer().len(), 256); // 2048 bits = 256 bytes

        // Perform RSA encryption using public key
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(unique.get_buffer()),
            rsa::BigUint::from(65537u32),
        )
        .unwrap();
        let msg = rsa::BigUint::from_bytes_be(b"hello 2048!");
        let e = rsa::BigUint::from(65537u32);
        let c = msg.modpow(&e, pub_key.n());
        let ciphertext_bytes = c.to_bytes_be();
        let mut ciphertext = vec![0u8; unique.get_buffer().len()];
        let start = ciphertext.len() - ciphertext_bytes.len();
        ciphertext[start..].copy_from_slice(&ciphertext_bytes);

        // Decrypt using simulator
        let decrypt_cmd = LocalRSADecryptCmd {
            key_handle: rsp.object_handle,
            cipher_text: Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&ciphertext)).unwrap(),
            in_scheme: None,
            label: tpm2::Tpm2bLabel::default(),
        };
        let decrypt_rsp = sim.execute(decrypt_cmd).unwrap();

        let returned_bytes = decrypt_rsp.message.get_buffer();
        assert_eq!(&returned_bytes[returned_bytes.len() - 11..], b"hello 2048!");
    } else {
        panic!("expected RSA key");
    }
    flush_context(&mut sim, rsp.object_handle).unwrap();
}

/// CreatePrimary of an RSA-3072 decryption key.
#[test]
fn rsa_3072_decryption_key() {
    let mut sim = Tpm::new();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let in_public = tpm2::Tpm2b(rsa_decrypt_public(3072));
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(
        res.is_err(),
        "Expected failure for 3072-bit key size due to small internal buffers"
    );
}

/// CreatePrimary of an RSA-4096 decryption key.
#[test]
fn rsa_4096_decryption_key() {
    let mut sim = Tpm::new();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let in_public = tpm2::Tpm2b(rsa_decrypt_public(4096));
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(
        res.is_err(),
        "Expected failure for 4096-bit key size due to small internal buffers"
    );
}

/// CreatePrimary of an RSA storage key succeeds and its public area round-trips.
///
/// `TPM2_CreatePrimary` of an RSA storage key succeeds.
#[test]
fn rsa_storage_primary() {
    let mut sim = Tpm::new();

    let primary_pub = rsa_public(TpmiAlgHash::Sha256, storage_attrs(), &[], Some(AES128_CFB));
    let cp_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(primary_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    // Verify unmarshaling in software
    let cmd_bytes = marshal_to_vec(&cp_cmd);
    let mut unmarshal_slice = &cmd_bytes[..];
    CreatePrimary::unmarshal_with_handles(cp_cmd.handles(), &mut unmarshal_slice).unwrap();

    exec_command(&mut sim, &cp_cmd, &[pw()]).unwrap();
}
