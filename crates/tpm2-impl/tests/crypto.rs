mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bPublicKeyRsa, TpmaObject,
    TpmiAlgHash, TpmtPublic,
};
use tpm2_impl::handler::TransientObject;

fn setup_tpm_with_fake_platform<'a>(
    crypto: &'a mut FakeCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup first
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

#[test]
fn test_adv_mac_key_type_confusion() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    // Populate transient object 0 with an RSA public key (NOT a KeyedHash or HMAC key).
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xaa; 1536], // fake private RSA key parts
        private_len: 256,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "00000017"
        "00000155"
        "80000001"
        "0005 68656c6c6f" // "hello"
        "000b"
    );

    let mut response = [0u8; 256];
    let _size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert!(
        error_code != 0,
        "MAC command succeeded on an RSA key handle! Type confusion bug detected. error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_adv_rsa_decrypt_signing_only() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xbb; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "0000001c"
        "00000159"
        "80000001"
        "0008 6369706865723132"
        "0010"
        "0000"
    );

    let mut response = [0u8; 256];
    let _size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code, 0x0000009C,
        "Expected TPM_RC_KEY (0x9C), got error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_adv_sign_storage_only() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xcc; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "00000022"
        "0000015d"
        "80000001"
        "0008 6469676573743132"
        "0010"
        "8024 40000007 0000"
    );

    let mut response = [0u8; 256];
    let _size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code, 0x0000009C,
        "Expected TPM_RC_KEY (0x9C), got error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_adv_verify_signature_keyed_hash_success() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xdd; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let mut hmac_buf = [0u8; 64];
    let expected_ha = tpm2::crypto::hmac(
        &FakeCrypto,
        TpmiAlgHash::Sha256,
        &[0xdd; 256],
        b"digest12",
        &mut hmac_buf,
    )
    .unwrap();

    let mut request = hex!(
        "8001"
        "0000003c"
        "00000177"
        "80000001"
        "0008 6469676573743132"
        "0005 000b"
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    request[28..60].copy_from_slice(expected_ha.digest());

    let mut response = [0u8; 256];
    let _size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code, 0,
        "VerifySignature command failed using a KeyedHash object handle! error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_adv_mac_unsupported_hash() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xee; 1536],
        private_len: 32,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "00000017"
        "00000155"
        "80000001"
        "0005 68656c6c6f" // "hello"
        "0012"            // SM3256 (unsupported by fake crypto)
    );

    let mut response = [0u8; 256];
    let _size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code, 0x000002C3,
        "Expected TPM_RC_HASH with parameter 2 (0x2C3), got 0x{:08X}",
        error_code
    );
}

#[test]
fn test_adv_crypt_ops_missing_handle() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let _missing_handle = 0x800000FFu32; // Non-existent transient key handle.

    // 1. MAC Command
    let mac_request = hex!(
        "8001"
        "00000017"
        "00000155"
        "800000FF"
        "0005 68656c6c6f"
        "000b"
    );
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &mac_request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_eq!(
        error_code, 0x00000910,
        "Expected ReferenceH0 (0x910) for missing handle in MAC"
    );

    // 2. VerifySignature Command
    let verify_request = hex!(
        "8001"
        "0000001a"
        "00000177"
        "800000FF"
        "0008 6469676573743132"
        "0010"
    );
    tpm.execute_command_separate(&mut global_state, &verify_request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_eq!(
        error_code, 0x00000910,
        "Expected ReferenceH0 (0x910) for missing handle in VerifySignature"
    );

    // 3. Sign Command
    let sign_request = hex!(
        "8001"
        "00000022"
        "0000015d"
        "800000FF"
        "0008 6469676573743132"
        "0010"
        "8024 40000007 0000"
    );
    tpm.execute_command_separate(&mut global_state, &sign_request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_eq!(
        error_code, 0x00000910,
        "Expected ReferenceH0 (0x910) for missing handle in Sign"
    );

    // 4. RSADecrypt Command
    let decrypt_request = hex!(
        "8001"
        "0000001c"
        "00000159"
        "800000FF"
        "0008 6369706865723132"
        "0010"
        "0000"
    );
    tpm.execute_command_separate(&mut global_state, &decrypt_request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_eq!(
        error_code, 0x00000910,
        "Expected ReferenceH0 (0x910) for missing handle in RSADecrypt"
    );
}

#[test]
fn test_adv_rsa_decrypt_restricted_key() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xbb; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "0000001c"
        "00000159"
        "80000001"
        "0008 6369706865723132"
        "0010"
        "0000"
    );

    let mut response = [0u8; 256];
    let _size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code,
        0x00000082, // TPM_RC_ATTRIBUTES
        "Expected TPM_RC_ATTRIBUTES (0x82) for restricted key decrypt! error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_adv_verify_signature_missing_sign_attribute() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    // Key has DECRYPT but lacks SIGN_ENCRYPT
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xbb; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "0000003c"
        "00000177" // VerifySignature
        "80000001"
        "0008 6469676573743132"
        "0005 000b"
        "0000000000000000000000000000000000000000000000000000000000000000"
    );

    let mut response = [0u8; 256];
    let _size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code,
        0x00000082, // TPM_RC_ATTRIBUTES
        "Expected TPM_RC_ATTRIBUTES (0x82) for verify signature with key lacking SIGN_ENCRYPT! error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_adv_verify_signature_keyed_hash_public_only() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    // KeyedHash key with SIGN_ENCRYPT but private_len = 0 (public-only)
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "0000003c"
        "00000177"
        "80000001"
        "0008 6469676573743132"
        "0005 000b"
        "0000000000000000000000000000000000000000000000000000000000000000"
    );

    let mut response = [0u8; 256];
    let _size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code,
        0x0000008b, // TPM_RC_HANDLE
        "Expected TPM_RC_HANDLE (0x8B) for public-only KeyedHash! error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_ecdh_zgen_success() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0x55; 1536],
        private_len: 32,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "00000054"
        "00000154"
        "80000001"
        "0044"
        "0020"
        "3561244d853489754cf0710d875a7ba4b2aca9cc38a5d02985d4ceb83bcbd0a2"
        "0020"
        "f8f0b6850f0925254ff63a19a01125a88994fc866060354d9305a711686d7177"
    );

    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code, 0,
        "ECDH_ZGen failed! error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_ecdh_zgen_key_attributes_error() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    // Key with RESTRICTED attribute set (invalid for ECDH_ZGen)
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xbb; 1536],
        private_len: 32,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "00000054"
        "00000154"
        "80000001"
        "0044"
        "0020"
        "3561244d853489754cf0710d875a7ba4b2aca9cc38a5d02985d4ceb83bcbd0a2"
        "0020"
        "f8f0b6850f0925254ff63a19a01125a88994fc866060354d9305a711686d7177"
    );

    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code,
        0x00000182, // TPM_RC_ATTRIBUTES | Position::Handle | Position::handle(1)
        "Expected TPM_RC_ATTRIBUTES + Handle + Pos1 (0x182), got error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_ecdh_zgen_scheme_error() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    // Key with ECDSA scheme (invalid for ECDH_ZGen)
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: Some(tpm2::TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xbb; 1536],
        private_len: 32,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "00000054"
        "00000154"
        "80000001"
        "0044"
        "0020"
        "3561244d853489754cf0710d875a7ba4b2aca9cc38a5d02985d4ceb83bcbd0a2"
        "0020"
        "f8f0b6850f0925254ff63a19a01125a88994fc866060354d9305a711686d7177"
    );

    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code,
        0x00000192, // TPM_RC_SCHEME | Position::Handle | Position::handle(1)
        "Expected TPM_RC_SCHEME + Handle + Pos1 (0x192), got error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_ecdh_zgen_key_type_error() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    // RSA key instead of ECC key
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xbb; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "00000054"
        "00000154"
        "80000001"
        "0044"
        "0020"
        "3561244d853489754cf0710d875a7ba4b2aca9cc38a5d02985d4ceb83bcbd0a2"
        "0020"
        "f8f0b6850f0925254ff63a19a01125a88994fc866060354d9305a711686d7177"
    );

    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code,
        0x0000019C, // TPM_RC_KEY | Position::Handle | Position::handle(1)
        "Expected TPM_RC_KEY + Handle + Pos1 (0x19C), got error_code = 0x{:08X}",
        error_code
    );
}

#[test]
fn test_ecdh_zgen_public_only_key_error() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_fake_platform(&mut crypto, &mut storage, &mut timer, &rng);
    let key_handle = 0x80000001;

    // ECC key but private_len = 0
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    };

    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let request = hex!(
        "8001"
        "00000054"
        "00000154"
        "80000001"
        "0044"
        "0020"
        "3561244d853489754cf0710d875a7ba4b2aca9cc38a5d02985d4ceb83bcbd0a2"
        "0020"
        "f8f0b6850f0925254ff63a19a01125a88994fc866060354d9305a711686d7177"
    );

    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let error_code = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);

    assert_eq!(
        error_code,
        0x0000019C, // TPM_RC_KEY | Position::Handle | Position::handle(1)
        "Expected TPM_RC_KEY + Handle + Pos1 (0x19C) for public-only key! error_code = 0x{:08X}",
        error_code
    );
}
