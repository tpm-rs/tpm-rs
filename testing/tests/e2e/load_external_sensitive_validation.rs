//! TPM2_LoadExternal sensitive area validation: private key sizes, authValue limits and
//! public/sensitive consistency.

use crate::_common::{
    AES128_CFB, ECC_D, ECC_X, ECC_Y, RSA_N, RSA_P, ecc_sign_template,
    execute_with_password_sessions, leak_bytes, load_external, make_ecc_public_area,
    make_ecc_public_area_exact_attrs, make_keyed_hash_public_area_no_scheme,
    make_keyed_hash_public_area_obfuscated, make_rsa_public_area_exact_attrs,
    make_rsa_public_area_opt_name_alg, rc_p, rc1, rsa_storage_template_with, sym_template_with,
};
use testing::tpm::Tpm;
use tpm2::commands::LoadExternal;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bPrivateKeyRsa,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bSymKey, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits,
    TpmsRsaParms, TpmtKeyedHashScheme, TpmtPublic, TpmtSensitive, TpmuSensitiveComposite,
};

/// LoadExternal with a 33-byte authValue for a SHA-256 key fails with TPM_RC_SIZE.
#[test]
fn auth_value_longer_than_digest_rejected() {
    let mut sim = Tpm::new();
    // Digest size for SHA256 is 32. We set auth_value to 33 bytes.
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::from_bytes(&[0x01; 33]).unwrap(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area_exact_attrs(
        ECC_X,
        ECC_Y,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::SIZE.with(Position::parameter(1)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// An ECC private scalar larger than the curve order size fails with TPM_RC_KEY_SIZE.
#[test]
fn ecc_oversized_private_scalar_rejected() {
    let mut sim = Tpm::new();
    let bad_d = [0x01; 33];
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(&bad_d).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::KEY_SIZE.to_rc();
    assert_eq!(err.get(), expected.get());
}

/// LoadExternal with an oversized ECC private scalar fails with TPM_RC_KEY_SIZE.
#[test]
fn ecc_scalar_too_large_rejected() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(&[0x01; 33]).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area_exact_attrs(
        ECC_X,
        ECC_Y,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY_SIZE.to_rc().get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// A 16-byte private scalar for a P-256 key is rejected.
#[test]
fn ecc_short_private_scalar_rejected() {
    let mut sim = Tpm::new();
    // ECC key requires 32-byte scalar D. We provide a 16-byte one.
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(&[0x01; 16]).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
}

/// Loading a sensitive area with FIXED_PARENT set fails with TPM_RC_ATTRIBUTES.
#[test]
fn fixed_parent_with_sensitive_rejected() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::FIXED_PARENT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::ATTRIBUTES.with(Position::parameter(2));
    assert_eq!(err.get(), expected.get());
}

/// Loading a sensitive area with FIXED_TPM set is rejected.
#[test]
fn fixed_tpm_with_sensitive_rejected() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    // Load with FIXED_TPM set. Since sensitive is loaded, this must be rejected.
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::FIXED_TPM));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
}

/// An HMAC keyedHash sensitive key larger than allowed fails with TPM_RC_KEY_SIZE.
#[test]
fn keyed_hash_oversized_key_rejected() {
    let mut sim = Tpm::new();
    let bad_sensitive_data = [0x01; 65];
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(&bad_sensitive_data).unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let unique_bytes = [0x01; 32];
    // An HMAC scheme is only valid on a sign-only keyedhash object (C SchemeChecks,
    // Object_spt.c:429-439, else SCHEME+P2), so set SIGN.
    let mut pub_area =
        make_keyed_hash_public_area_obfuscated(&unique_bytes, TpmaObject::SIGN_ENCRYPT);
    if let PublicParmsAndId::KeyedHash(ref mut scheme, _) = pub_area.parms_and_id {
        *scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    }
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::KEY_SIZE.with(Position::parameter(1));
    assert_eq!(err.get(), expected.get());
}

/// LoadExternal with an oversized keyed-hash sensitive value fails with TPM_RC_KEY_SIZE.
#[test]
fn keyedhash_sensitive_too_large_rejected() {
    let mut sim = Tpm::new();
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
    let mut pub_area = make_keyed_hash_public_area_no_scheme(&[0x01; 32], TpmaObject::SIGN_ENCRYPT);
    if let PublicParmsAndId::KeyedHash(ref mut scheme, _) = pub_area.parms_and_id {
        *scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    }
    let in_public = tpm2::Tpm2b(pub_area);
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY_SIZE.with(Position::parameter(1)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// A sensitive authValue larger than the nameAlg digest fails with TPM_RC_SIZE.
#[test]
fn oversized_auth_value_rejected() {
    let mut sim = Tpm::new();

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
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::SIZE.with(Position::parameter(1));
    assert_eq!(err.get(), expected.get());
}

/// Loading a sensitive area of a RESTRICTED key fails with TPM_RC_ATTRIBUTES.
#[test]
fn restricted_with_sensitive_rejected() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::RESTRICTED));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::ATTRIBUTES.with(Position::parameter(2));
    assert_eq!(err.get(), expected.get());
}

/// LoadExternal rejects RSA moduli without MSB, ECC scalars outside (0,n) and reports public/sensitive mismatch as bare BINDING.
#[test]
fn rsa_modulus_ecc_scalar_and_binding_checks() {
    let mut sim = Tpm::new();
    // RSA modulus without its most significant bit SET.
    let mut modulus = [0x5au8; 256];
    modulus[0] = 0x01;
    let mut t = rsa_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.object_attributes.remove(TpmaObject::RESTRICTED);
    t.parms_and_id = PublicParmsAndId::Rsa(
        TpmsRsaParms {
            symmetric: None,
            scheme: None,
            key_bits: TpmiRsaKeyBits(2048),
            exponent: 0,
        },
        Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&modulus)).unwrap(),
    );
    assert_eq!(
        load_external(&mut sim, t, None, Handle::RH_OWNER).unwrap_err(),
        rc_p(TpmRc::KEY, 2)
    );

    // ECC private scalars outside 0 < d < n are rejected even with a NULL nameAlg.
    let ecc_ext = |d: &[u8]| {
        let mut t = ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty());
        t.name_alg = None;
        t.object_attributes
            .remove(TpmaObject::SENSITIVE_DATA_ORIGIN);
        let s = TpmtSensitive {
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::default(),
            sensitive: TpmuSensitiveComposite::Ecc(
                Tpm2bEccParameter::from_bytes(leak_bytes(d)).unwrap(),
            ),
        };
        (t, s)
    };
    let (t, s) = ecc_ext(&[0u8; 32]);
    assert_eq!(
        load_external(&mut sim, t, Some(s), Handle::RH_NULL).unwrap_err(),
        rc1(TpmRc::KEY_SIZE)
    );
    let (t, s) = ecc_ext(&crate::_common::p256_order());
    assert_eq!(
        load_external(&mut sim, t, Some(s), Handle::RH_NULL).unwrap_err(),
        rc1(TpmRc::KEY_SIZE)
    );
    let (t, s) = ecc_ext(&[1u8; 32]);
    load_external(&mut sim, t, Some(s), Handle::RH_NULL).expect("valid scalar");

    // A public/sensitive binding mismatch is a bare TPM_RC_BINDING (CryptValidateKeys and
    // CryptRsaLoadPrivateExponent return it without blame).
    let mut t = sym_template_with(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.object_attributes
        .remove(TpmaObject::SENSITIVE_DATA_ORIGIN);
    t.parms_and_id =
        PublicParmsAndId::Sym(AES128_CFB, Tpm2bDigest::from_bytes(&[0xee; 32]).unwrap());
    let s = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[1; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(&[2; 16]).unwrap()),
    };
    assert_eq!(
        load_external(&mut sim, t, Some(s), Handle::RH_NULL).unwrap_err(),
        rc1(TpmRc::BINDING)
    );
}

/// A random prime that does not factor the RSA modulus is rejected.
#[test]
fn rsa_prime_not_matching_modulus_rejected() {
    let mut sim = Tpm::new();
    // Provide a random 128-byte prime P that doesn't correspond to modulus RSA_N
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(
            Tpm2bPrivateKeyRsa::from_bytes(&[0x01; 128]).unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area_opt_name_alg(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
}

/// An RSA prime of the wrong bit size fails with TPM_RC_BINDING (no parameter number).
#[test]
fn rsa_prime_size_mismatch_binding_error() {
    let mut sim = Tpm::new();

    let mut p_bytes = [0u8; 128];
    p_bytes[0] = 0x80;
    p_bytes[127] = 0x01;

    let mut n_bytes = [0u8; 256];
    // The modulus must have its top bit set, or C rejects the public area first
    // with KEY+P2 (CryptUtil.c:1715-1717).
    n_bytes[0] = 0x90;
    n_bytes[128] = 0xa0;
    n_bytes[255] = 0x01;

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(&p_bytes).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let in_public = tpm2::Tpm2b(make_rsa_public_area_opt_name_alg(
        &n_bytes,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    ));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    // C ObjectLoad returns CryptRsaLoadPrivateExponent's TPM_RC_BINDING without
    // a parameter number (Object.c:381-383, CryptRsa.c:969).
    assert_eq!(err.get(), TpmRc::BINDING.get());
}

/// LoadExternal with an RSA prime of the wrong size fails with TPM_RC_KEY_SIZE.
#[test]
fn rsa_prime_size_mismatch_rejected() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(
            Tpm2bPrivateKeyRsa::from_bytes(&[0x01; 64]).unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area_exact_attrs(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY_SIZE.with(Position::parameter(1)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// LoadExternal with an RSA prime whose top byte is below 0x80 fails with KEY_SIZE + P1.
#[test]
fn rsa_small_prime_rejected() {
    let mut sim = Tpm::new();
    let mut p_bytes = [0u8; 128];
    p_bytes[127] = 1;
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(&p_bytes).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area_exact_attrs(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    // C CryptValidateKeys (CryptUtil.c:1724-1726): a prime whose top byte is
    // below 0x80 is rejected with KEY_SIZE + blameSensitive (P1) before any
    // binding check.
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY_SIZE.with(Position::parameter(1)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// LoadExternal with an all-zero RSA prime fails with KEY_SIZE + P1.
#[test]
fn rsa_zero_prime_rejected() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(
            Tpm2bPrivateKeyRsa::from_bytes(&[0x00; 128]).unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_rsa_public_area_exact_attrs(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    // C CryptValidateKeys (CryptUtil.c:1724-1726): a prime whose top byte is
    // below 0x80 is rejected with KEY_SIZE + blameSensitive (P1).
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY_SIZE.with(Position::parameter(1)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// An ECC public area paired with a symmetric sensitive area is rejected.
#[test]
fn sensitive_type_differs_from_public_rejected() {
    let mut sim = Tpm::new();
    // Public is ECC, but Sensitive is Sym (symmetric)
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(&[0x01; 16]).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
}

/// A symmetric key with empty key material is rejected.
#[test]
fn symcipher_empty_key_rejected() {
    let mut sim = Tpm::new();
    // Symmetric key with empty key material
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(&[]).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(AES128_CFB, Tpm2bDigest::default()),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
}

/// `TPM2_LoadExternal` of a SYMCIPHER object whose `unique` does not match the
/// sensitive key data fails with a bare `TPM_RC_BINDING`.
#[test]
fn symcipher_unique_binding_mismatch() {
    let mut sim = Tpm::new();

    // Mismatched unique in inPublic vs sensitive key data in inPrivate
    let sym_key_bytes = [0xAAu8; 16];
    let wrong_unique_bytes = [0xBBu8; 20]; // SHA-1 size is 20 bytes

    let tpmt_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha1),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            AES128_CFB,
            Tpm2bDigest::from_bytes(leak_bytes(&wrong_unique_bytes)).unwrap(),
        ),
    };

    let tpmt_sensitive = TpmtSensitive {
        auth_value: tpm2::Tpm2bAuth::default(),
        // A nameAlg-sized seedValue, so that the binding (not the seed size, TPM_RC_KEY_SIZE)
        // is what fails (C `CryptValidateKeys()`).
        seed_value: Tpm2bDigest::from_bytes(leak_bytes(&[0xCC; 20])).unwrap(),
        sensitive: TpmuSensitiveComposite::Sym(
            Tpm2bSymKey::from_bytes(leak_bytes(&sym_key_bytes)).unwrap(),
        ),
    };

    let cmd = LoadExternal {
        in_private: Some(tpm2::Tpm2b(tpmt_sensitive)),
        in_public: tpm2::Tpm2b(tpmt_public),
        hierarchy: Handle::RH_NULL,
    };

    let rc = execute_with_password_sessions(&mut sim, &cmd, 0, &[])
        .expect_err("expected LoadExternal to fail");
    // C `CryptValidateKeys()` returns a bare TPM_RC_BINDING for a SYMCIPHER/KEYEDHASH binding
    // mismatch (no parameter position).
    assert_eq!(rc, TpmRc::BINDING.get());
}

/// LoadExternal of a KEYEDHASH object with a sensitive area checks the `seedValue` size
/// (32 octets for a SHA-512 nameAlg: `TPM_RC_KEY_SIZE + P1`) before anything about the
/// `unique` digest, whose size does not match the nameAlg either; `unique` is only compared with the digest computed from the
/// sensitive area (`TPM_RC_BINDING`). `tpm-rs` returned `TPM_RC_KEY + P2` for the `unique` size
/// (found by differential fuzzing). TPM 2.0 Part 3, TPM2_LoadExternal: "If *nameAlg* is not
/// `TPM_ALG_NULL`, then the same consistency checks between *inPublic* and *inPrivate* are made
/// as for `TPM2_Load()`."
#[test]
fn keyed_hash_seed_size_checked_before_unique_size() {
    let mut tpm = Tpm::new();
    let cmd = crate::_common::hex(concat!(
        "80010000007300000167",
        // inPrivate: KEYEDHASH, empty authValue, 32-byte seedValue, 7-byte data.
        "002f",
        "0008",
        "0000",
        "0020",
        "0202020202740000000000000002020202020202020202020202020202020202",
        "0007",
        "73656372657473",
        // inPublic: KEYEDHASH, SHA-512, sign|userWithAuth, empty authPolicy,
        // XOR(SHA-256, KDF1_SP800_108), 32-byte unique.
        "0032",
        "0008000d000200400000",
        "000a000b0022",
        "0020",
        "8897eebe4000000700000039810101010146caf16abe01000000000000b2eebe",
        // hierarchy: TPM_RH_NULL.
        "40000007",
    ));
    let (rc, _) = crate::_common::send_with_rc(&mut tpm, &cmd);
    assert_eq!(rc, rc_p(TpmRc::KEY_SIZE, 1), "TPM_RC_KEY_SIZE + P1");
}

/// An RSA key whose prime factors the modulus but whose public exponent is not coprime to
/// phi(n) (here the even exponent 256) has no private exponent: TPM_RC_BINDING without a
/// parameter number (Part 3 TPM2_LoadExternal: "TPM_RC_BINDING | the inPublic and inPrivate
/// structures are not cryptographically bound"), never TPM_RC_FAILURE. The same key with the
/// default exponent loads.
#[test]
fn rsa_exponent_without_private_exponent_is_binding_error() {
    let mut sim = Tpm::new();
    let load = |sim: &mut Tpm, exponent: u32| {
        let mut public = make_rsa_public_area_opt_name_alg(
            RSA_N,
            Some(TpmiAlgHash::Sha256),
            TpmaObject::SIGN_ENCRYPT,
        );
        if let PublicParmsAndId::Rsa(parms, _) = &mut public.parms_and_id {
            parms.exponent = exponent;
        }
        let sensitive = TpmtSensitive {
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::default(),
            sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(RSA_P).unwrap()),
        };
        load_external(sim, public, Some(sensitive), Handle::RH_NULL)
    };
    assert_eq!(load(&mut sim, 256).unwrap_err(), rc1(TpmRc::BINDING));
    load(&mut sim, 0).expect("the key with the default exponent loads");
}

/// An RSA private key one octet larger than the TPM's `TPM2B_PRIVATE_KEY_RSA` capacity is
/// `TPM_RC_SIZE + RC_LoadExternal_inPrivate` (TPM 2.0 Part 2, Table "Definition of
/// TPM2B_PRIVATE_KEY_RSA Structure": "buffer[size]{:RSA_PRIVATE_SIZE }" and "`RSA_PRIVATE_SIZE`
/// is a vendor specific value that can be (`MAX_RSA_KEY_BYTES` / 2) or ((`MAX_RSA_KEY_BYTES` \*
/// 5) / 2)"). tpm-rs uses the larger value (640 octets for RSA 2048).
#[test]
fn rsa_private_key_larger_than_capacity_rejected() {
    const RSA_PRIVATE_KEY_CAP: usize = 640;
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(
            Tpm2bPrivateKeyRsa::from_bytes(&[0x01; RSA_PRIVATE_KEY_CAP]).unwrap(),
        ),
    };
    assert_eq!(Tpm2bPrivateKeyRsa::CAP, RSA_PRIVATE_KEY_CAP);
    let cmd = LoadExternal {
        in_private: Some(tpm2::Tpm2b(sensitive_create)),
        in_public: tpm2::Tpm2b(make_rsa_public_area_exact_attrs(
            RSA_N,
            TpmiAlgHash::Sha256,
            TpmaObject::SIGN_ENCRYPT,
        )),
        hierarchy: Handle::RH_NULL,
    };
    // The `tpm2` types cannot hold the larger key, so it is grown by one octet in the raw
    // command: inPrivate's size, then its sensitiveType, authValue (empty), seedValue (empty)
    // and the private key.
    let (mut raw, params) = crate::_common::build_cmd_with_param_offset(&cmd, &[]);
    let key = params + 2 + 2 + 2 + 2;
    let key_end = crate::_common::tpm2b_end(&raw, key);
    crate::_common::grow_command(&mut raw, &[params, key], key_end, &[0x01]);
    assert_eq!(
        crate::_common::raw_rc(&mut sim, &raw),
        TpmRc::SIZE.with(Position::parameter(1)).get()
    );
}
