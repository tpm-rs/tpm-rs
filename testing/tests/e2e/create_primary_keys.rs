//! TPM2_CreatePrimary of RSA and ECC keys that are then used (decryption, ReadPublic) to check the
//! created key.

use crate::_common::{
    AES128_CFB, LocalRSADecryptCmd, exec_command, execute_with_password_sessions, flush_context,
    leak_bytes, marshal_to_vec, pw, rsa_decrypt_public, rsa_public, storage_attrs,
};
#[cfg(not(all(feature = "rsa3072", feature = "rsa4096")))]
use crate::_common::{execute_with_corrupted_bytes_status, put_u16};
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
        outside_info: Default::default(),
        creation_pcr: Default::default(),
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
        outside_info: Default::default(),
        creation_pcr: Default::default(),
    };
    let rsp = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();
    let out_public_struct = rsp.out_public.0;
    if let PublicParmsAndId::Rsa(parms, unique) = &out_public_struct.parms_and_id {
        assert_eq!(parms.key_bits.as_u16(), 1024);
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

/// Creates a primary RSA decryption key of `bits` bits, encrypts a message to its public key on
/// the client side (raw RSA) and checks that the TPM decrypts it.
fn decryption_key_round_trip(bits: u16) {
    use rsa::traits::PublicKeyParts as _;
    let mut sim = Tpm::new();

    let sensitive_create = tpm2::TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let in_public = tpm2::Tpm2b(rsa_decrypt_public(bits));
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        outside_info: Default::default(),
        creation_pcr: Default::default(),
    };
    let rsp = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();
    let out_public_struct = rsp.out_public.0;
    let PublicParmsAndId::Rsa(parms, unique) = &out_public_struct.parms_and_id else {
        panic!("expected RSA key");
    };
    assert_eq!(parms.key_bits.as_u16(), bits);
    assert_eq!(unique.get_buffer().len(), usize::from(bits) / 8);
    assert!(
        unique.get_buffer()[0] >= 0x80,
        "the modulus has exactly {bits} bits"
    );

    // Perform RSA encryption using public key
    let pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(unique.get_buffer()),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();
    let message = format!("hello {bits}!");
    let msg = rsa::BigUint::from_bytes_be(message.as_bytes());
    let c = msg.modpow(pub_key.e(), pub_key.n());
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
    assert_eq!(returned_bytes.len(), usize::from(bits) / 8);
    assert_eq!(
        &returned_bytes[returned_bytes.len() - message.len()..],
        message.as_bytes()
    );
    flush_context(&mut sim, rsp.object_handle).unwrap();
}

/// CreatePrimary of an RSA decryption key whose size is not in the TPM's profile fails to
/// unmarshal `inPublic.parameters.keyBits`: `TPM_RC_VALUE + P2` (TPM 2.0 Part 2, Table
/// "Definition of (RSA) (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type": "#TPM_RC_VALUE | error when key
/// size is not supported").
#[cfg(not(all(feature = "rsa3072", feature = "rsa4096")))]
fn unsupported_key_size_rejected(bits: u16) {
    let mut sim = Tpm::new();
    // An unimplemented key size is not a `TpmiRsaKeyBits` value, so the key size of an RSA-2048
    // template is patched in the marshaled parameters.
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(tpm2::TpmsSensitiveCreate::default()),
        in_public: tpm2::Tpm2b(rsa_decrypt_public(2048)),
        outside_info: Default::default(),
        creation_pcr: Default::default(),
    };
    // keyBits follows inSensitive (6 octets), the size of inPublic, type, nameAlg,
    // objectAttributes, the empty authPolicy, and the NULL symmetric definition and scheme.
    const KEY_BITS_OFFSET: usize = 6 + 2 + 2 + 2 + 4 + 2 + 2 + 2;
    assert_eq!(
        execute_with_corrupted_bytes_status(&mut sim, &cmd, 1, &[], |params| {
            assert_eq!(
                params[KEY_BITS_OFFSET..KEY_BITS_OFFSET + 2],
                2048u16.to_be_bytes()
            );
            put_u16(params, KEY_BITS_OFFSET, bits);
        })
        .map(|_| ())
        .unwrap_err(),
        tpm2::errors::TpmRc::VALUE
            .with(tpm2::errors::Position::parameter(2))
            .get()
    );
}

/// CreatePrimary RSA-2048 decryption key; client-side encryption decrypts correctly in the TPM.
#[test]
fn rsa_2048_encrypt_decrypt() {
    decryption_key_round_trip(2048);
}

/// CreatePrimary RSA-3072 decryption key (the `rsa3072` feature); client-side encryption
/// decrypts correctly in the TPM.
#[cfg(feature = "rsa3072")]
#[test]
fn rsa_3072_encrypt_decrypt() {
    decryption_key_round_trip(3072);
}

/// Without the `rsa3072` feature, RSA-3072 is not a key size of the TPM.
#[cfg(not(feature = "rsa3072"))]
#[test]
fn rsa_3072_key_size_unsupported() {
    unsupported_key_size_rejected(3072);
}

/// CreatePrimary RSA-4096 decryption key (the `rsa4096` feature); client-side encryption
/// decrypts correctly in the TPM.
#[cfg(feature = "rsa4096")]
#[test]
fn rsa_4096_encrypt_decrypt() {
    decryption_key_round_trip(4096);
}

/// Without the `rsa4096` feature, RSA-4096 is not a key size of the TPM.
#[cfg(not(feature = "rsa4096"))]
#[test]
fn rsa_4096_key_size_unsupported() {
    unsupported_key_size_rejected(4096);
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
