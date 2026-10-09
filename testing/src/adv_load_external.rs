#![forbid(unsafe_code)]

use crate::test_utils::execute_with_password_sessions;
use tpm2::commands::LoadExternal;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmEccCurve};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bPrivateKeyRsa,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsEccParms,
    TpmsEccPoint, TpmsRsaParms, TpmtKeyedHashScheme, TpmtPublic, TpmtSensitive,
    TpmuSensitiveComposite,
};
use tpm2_simulator::create_simulator;

// 2048-bit RSA Modulus N, Prime P, Prime Q, Private Exponent D
pub const RSA_N: &[u8] = &[
    0x9e, 0x67, 0x7c, 0x31, 0xb1, 0xf9, 0x15, 0x8a, 0x41, 0x4d, 0x16, 0xf0, 0x73, 0xbe, 0x59, 0x66,
    0xc0, 0xe3, 0x8d, 0xc3, 0x64, 0x4b, 0x01, 0x3c, 0xce, 0x5c, 0x13, 0x10, 0x41, 0x9f, 0xbc, 0x43,
    0x2d, 0xfa, 0xcb, 0xfc, 0xa4, 0xd8, 0x41, 0x05, 0xbc, 0xcb, 0xe5, 0xc8, 0xd9, 0x13, 0x21, 0x6c,
    0xb0, 0x13, 0xea, 0x10, 0x3a, 0x3b, 0x73, 0xe0, 0x9e, 0x59, 0x11, 0x0f, 0x5c, 0x1f, 0x54, 0x5c,
    0x39, 0x42, 0x1d, 0x45, 0xb4, 0x67, 0x2c, 0x19, 0xf7, 0x6c, 0xe6, 0x13, 0xdd, 0xb7, 0x55, 0x5b,
    0x00, 0xa6, 0xaa, 0x2f, 0x06, 0x2a, 0xa9, 0x23, 0x7f, 0xc0, 0xb8, 0xdd, 0x32, 0xb5, 0x00, 0xc1,
    0xe7, 0x51, 0xe1, 0x71, 0xc1, 0xa3, 0xb3, 0x3a, 0x44, 0x45, 0x6c, 0x43, 0xbb, 0xc1, 0x23, 0x6f,
    0x65, 0x15, 0x6e, 0x25, 0xdd, 0x51, 0x8b, 0x49, 0x04, 0x44, 0xd1, 0x55, 0xd3, 0x88, 0x5f, 0x6a,
    0xd3, 0xc1, 0x58, 0x4b, 0xca, 0xe9, 0xbe, 0x6d, 0x30, 0x46, 0xdd, 0x3c, 0x2b, 0xbb, 0xd7, 0xbd,
    0x94, 0x10, 0x5e, 0x32, 0x6e, 0xcd, 0x24, 0x96, 0x17, 0x7a, 0x88, 0xd7, 0xee, 0x60, 0x58, 0x95,
    0x6a, 0x18, 0x7f, 0x40, 0x53, 0x24, 0xc0, 0x0e, 0xa9, 0x08, 0x9c, 0x03, 0x27, 0xce, 0x0b, 0xcb,
    0xc5, 0x2c, 0xf2, 0xb0, 0xe7, 0xac, 0xe0, 0xfa, 0x84, 0xc4, 0x77, 0x2f, 0x83, 0x3d, 0xe5, 0x7c,
    0x67, 0x94, 0x93, 0x3e, 0x52, 0x6e, 0x21, 0xf3, 0x30, 0xb1, 0x5e, 0xca, 0x39, 0xf5, 0x0b, 0x28,
    0xb4, 0x87, 0x76, 0x77, 0xc3, 0xaf, 0x4f, 0x9c, 0x7f, 0x0c, 0x58, 0x9d, 0x80, 0xf2, 0xf4, 0x93,
    0x6e, 0x03, 0x1e, 0x1d, 0x15, 0x6c, 0xb7, 0xfb, 0xd6, 0x43, 0xe3, 0xd2, 0x58, 0x5a, 0x2e, 0x2d,
    0xc2, 0xb3, 0x69, 0xff, 0x93, 0x35, 0x53, 0x71, 0x51, 0x64, 0x76, 0x41, 0x85, 0x3d, 0x3e, 0x31,
];

// NIST P-256 ECC Coordinates and Private Scalar
pub const ECC_X: &[u8] = &[
    0x35, 0x61, 0x24, 0x4d, 0x85, 0x34, 0x89, 0x75, 0x4c, 0xf0, 0x71, 0x0d, 0x87, 0x5a, 0x7b, 0xa4,
    0xb2, 0xac, 0xa9, 0xcc, 0x38, 0xa5, 0xd0, 0x29, 0x85, 0xd4, 0xce, 0xb8, 0x3b, 0xcb, 0xd0, 0xa2,
];
pub const ECC_Y: &[u8] = &[
    0xf8, 0xf0, 0xb6, 0x85, 0x0f, 0x09, 0x25, 0x25, 0x4f, 0xf6, 0x3a, 0x19, 0xa0, 0x11, 0x25, 0xa8,
    0x89, 0x94, 0xfc, 0x86, 0x60, 0x60, 0x35, 0x4d, 0x93, 0x05, 0xa7, 0x11, 0x68, 0x6d, 0x71, 0x77,
];
pub const ECC_D: &[u8] = &[
    0xcb, 0x53, 0x36, 0x6e, 0xee, 0x57, 0xf7, 0xed, 0x84, 0x8e, 0xc5, 0x88, 0xa2, 0x61, 0xbd, 0xfb,
    0xae, 0x21, 0x65, 0x46, 0x6e, 0x43, 0x45, 0xc5, 0xb5, 0x80, 0xcf, 0x95, 0xd4, 0x84, 0xfa, 0x5b,
];

// Helper functions for public areas
fn make_ecc_public_area(x: &[u8], y: &[u8], attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(x)).unwrap(),
                y: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(y)).unwrap(),
            },
        ),
    }
}

fn make_rsa_public_area(n: &[u8], name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiCode::from(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(crate::test_utils::leak_bytes(n)).unwrap(),
        ),
    }
}

// Helper code to map TpmiRsaKeyBits which has transparent u16 representation
struct TpmiCode;
impl TpmiCode {
    fn from(val: u16) -> TpmiRsaKeyBits {
        TpmiRsaKeyBits(val)
    }
}

fn make_keyed_hash_public_area(unique: &[u8], attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            None,
            Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(unique)).unwrap(),
        ),
    }
}

#[test]
fn adv_load_external_auth_value_too_large() {
    let mut sim = create_simulator!();
    // Digest size for SHA256 is 32. We set auth_value to 33 bytes.
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::from_bytes(&[0x01; 33]).unwrap(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, (), 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::SIZE.with(Position::parameter(1)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn adv_load_external_rsa_primes_key_size_mismatch() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(
            Tpm2bPrivateKeyRsa::from_bytes(&[0x01; 64]).unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, (), 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY_SIZE.with(Position::parameter(1)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn adv_load_external_rsa_prime_zero() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(
            Tpm2bPrivateKeyRsa::from_bytes(&[0x00; 128]).unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, (), 0, &[]);
    // C CryptValidateKeys (CryptUtil.c:1724-1726): a prime whose top byte is
    // below 0x80 is rejected with KEY_SIZE + blameSensitive (P1).
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY_SIZE.with(Position::parameter(1)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn adv_load_external_rsa_prime_unbalanced() {
    let mut sim = create_simulator!();
    let mut p_bytes = [0u8; 128];
    p_bytes[127] = 1;
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(&p_bytes).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, (), 0, &[]);
    // C CryptValidateKeys (CryptUtil.c:1724-1726): a prime whose top byte is
    // below 0x80 is rejected with KEY_SIZE + blameSensitive (P1) before any
    // binding check.
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY_SIZE.with(Position::parameter(1)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn adv_load_external_ecc_scalar_too_large() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(&[0x01; 33]).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, (), 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY_SIZE.with(Position::parameter(1)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn adv_load_external_keyed_hash_sensitive_too_large() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(&[0x01; 65]).unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    // An HMAC scheme is only valid on a sign-only keyedhash object (C SchemeChecks,
    // Object_spt.c:429-439, else SCHEME+P2), so set SIGN.
    let mut pub_area = make_keyed_hash_public_area(&[0x01; 32], TpmaObject::SIGN_ENCRYPT);
    if let PublicParmsAndId::KeyedHash(ref mut scheme, _) = pub_area.parms_and_id {
        *scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    }
    let in_public = tpm2::Tpm2b(pub_area);
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, (), 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY_SIZE.with(Position::parameter(1)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn adv_load_external_rsa_public_modulus_size_mismatch() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        &[0x01; 255],
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, (), 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY.with(Position::parameter(2)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn adv_load_external_ecc_public_coord_size_mismatch() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(
        &[0x01; 31],
        ECC_Y,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, (), 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY.with(Position::parameter(2)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn adv_load_external_unsupported_name_alg() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_rsa_public_area(
        RSA_N,
        TpmiAlgHash::Sm3_256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, (), 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::HASH.with(Position::parameter(2)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

#[test]
fn adv_load_external_object_memory_exhaustion() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    // Load MAX_LOADED_OBJECTS objects
    for i in 0..tpm2::TPM2_MAX_LOADED_OBJECTS as usize {
        let cmd = LoadExternal {
            in_private: None,
            in_public,
            hierarchy: Handle::RH_NULL,
        };
        let res = execute_with_password_sessions(&mut sim, &cmd, (), 0, &[]);
        assert!(res.is_ok(), "Failed to load object {}", i);
    }

    // Next load should fail with ObjectMemory
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, (), 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::OBJECT_MEMORY.get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}
