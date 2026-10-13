//! TPM2_LoadExternal public area validation: points, sizes, name algorithms and attributes.

use crate::_common::{
    AES128_CFB, ECC_X, ECC_Y, RSA_N, ecc_sign_template, execute_with_password_sessions, hash_parts,
    leak_bytes, load_external, make_ecc_public_area, make_ecc_public_area_exact_attrs,
    make_rsa_public_area_exact_attrs, make_rsa_public_area_opt_name_alg, rc_p, sealed_template,
    sym_template_with,
};
use tpm2::commands::LoadExternal;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bPublic, Tpm2bPublicKeyRsa, Tpm2bSymKey,
    TpmEccCurve, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsRsaParms, TpmtPublic, TpmtSensitive,
    TpmuSensitiveComposite,
};
use tpm2_simulator::create_simulator;

/// LoadExternal of an ECC public key with a wrong-size coordinate fails with TPM_RC_KEY.
#[test]
fn ecc_coordinate_size_mismatch_rejected() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_ecc_public_area_exact_attrs(
        &[0x01; 31],
        ECC_Y,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY.with(Position::parameter(2)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// An ECC public point with a wrongly sized coordinate fails with TPM_RC_KEY.
#[test]
fn ecc_oversized_coordinate_rejected() {
    let mut sim = create_simulator!();
    let bad_x = [0u8; 31];
    let in_public = tpm2::Tpm2b(make_ecc_public_area(
        &bad_x,
        ECC_Y,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::KEY.with(Position::parameter(2));
    assert_eq!(err.get(), expected.get());
}

/// An ECC public point that is not on the curve is rejected.
#[test]
fn ecc_point_not_on_curve_rejected() {
    let mut sim = create_simulator!();
    let mut bad_y = ECC_Y.to_vec();
    bad_y[0] ^= 0xff; // corrupt coordinate
    let in_public = tpm2::Tpm2b(make_ecc_public_area(
        ECC_X,
        &bad_y,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
}

/// An ECC public area with an unsupported curve is rejected.
#[test]
fn ecc_unsupported_curve_rejected() {
    let mut sim = create_simulator!();
    let mut pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    if let PublicParmsAndId::Ecc(ref mut parms, _) = pub_struct.parms_and_id {
        parms.curve_id = TpmEccCurve::BNP638;
    }
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
}

/// A raw command whose TPM2B_PUBLIC size disagrees with its contents is rejected.
#[test]
fn inconsistent_public_size_rejected() {
    let mut sim = create_simulator!();
    assert!(
        Tpm2bPublic::from_bytes(&[0; 10]).is_err(),
        "Client unmarshaler should reject invalid Tpm2bPublic buffer"
    );

    struct BadLoadExternal<'a> {
        in_public_buf: &'a [u8],
        hierarchy: Handle,
    }
    impl tpm2::Marshal for BadLoadExternal<'_> {
        const MAX_SIZE: usize = 256;
        type MaxBuffer = [u8; 256];
        fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
            let mut off = 0u16.marshal((&mut dst[0..2]).try_into().unwrap()); // in_private = None (0 size)
            off += (self.in_public_buf.len() as u16)
                .marshal((&mut dst[off..off + 2]).try_into().unwrap());
            dst[off..off + self.in_public_buf.len()].copy_from_slice(self.in_public_buf);
            off += self.in_public_buf.len();
            off += self
                .hierarchy
                .marshal((&mut dst[off..off + 4]).try_into().unwrap());
            off
        }
    }
    impl tpm2::commands::Message for BadLoadExternal<'_> {
        type Handles = [Handle; 0];
        fn handles(&self) -> Self::Handles {
            []
        }
    }
    impl tpm2::Command for BadLoadExternal<'_> {
        const CMD_CODE: tpm2::TpmCc = tpm2::TpmCc::LoadExternal;
        type Response<'a> = ();
    }

    let cmd = BadLoadExternal {
        in_public_buf: &[0; 10],
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
}

/// An RSA public area with an invalid public exponent is rejected.
#[test]
fn rsa_invalid_exponent_rejected() {
    let mut sim = create_simulator!();
    let mut pub_struct = make_rsa_public_area_opt_name_alg(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    );
    if let PublicParmsAndId::Rsa(ref mut parms, _) = pub_struct.parms_and_id {
        parms.exponent = 3; // invalid exponent (unsupported by TPM)
    }
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
}

/// LoadExternal of an RSA public key whose modulus mismatches keyBits fails with TPM_RC_KEY.
#[test]
fn rsa_modulus_size_mismatch_rejected() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_rsa_public_area_exact_attrs(
        &[0x01; 255],
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::KEY.with(Position::parameter(2)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// LoadExternal runs SchemeChecks, digest-sized seed/unique checks and accepts RSA-3072 public keys.
#[test]
fn scheme_seed_unique_and_key_size_checks() {
    let mut sim = create_simulator!();
    // 1. SchemeChecks run for public-only keys: a restricted signing key needs a scheme.
    let mut t = ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::RESTRICTED);
    if let PublicParmsAndId::Ecc(parms, point) = &mut t.parms_and_id {
        parms.scheme = None;
        *point = crate::_common::p256_generator();
    }
    assert_eq!(
        load_external(&mut sim, t, None, Handle::RH_OWNER).unwrap_err(),
        rc_p(TpmRc::SCHEME, 2)
    );

    // 2. seedValue must be digest-sized for SYMCIPHER/KEYEDHASH keys with a sensitive area.
    let key = [9u8; 16];
    let seed = [1u8; 16];
    let unique = hash_parts(TpmiAlgHash::Sha256, &[&seed, &key]);
    let mut t = sym_template_with(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.object_attributes
        .remove(TpmaObject::SENSITIVE_DATA_ORIGIN);
    t.parms_and_id = PublicParmsAndId::Sym(
        AES128_CFB,
        Tpm2bDigest::from_bytes(leak_bytes(&unique)).unwrap(),
    );
    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(leak_bytes(&seed)).unwrap(),
        sensitive: TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(leak_bytes(&key)).unwrap()),
    };
    assert_eq!(
        load_external(&mut sim, t, Some(sensitive), Handle::RH_NULL).unwrap_err(),
        rc_p(TpmRc::KEY_SIZE, 1)
    );

    // 3. A public-only KEYEDHASH object needs a digest-sized unique.
    let t = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    assert_eq!(
        load_external(&mut sim, t, None, Handle::RH_OWNER).unwrap_err(),
        rc_p(TpmRc::KEY, 2)
    );

    // 4. RSA-3072 public keys are accepted like in create_loaded.
    let mut modulus = [0x33u8; 384];
    modulus[0] = 0xd5;
    let t = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(3072),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&modulus)).unwrap(),
        ),
    };
    load_external(&mut sim, t, None, Handle::RH_OWNER).expect("RSA-3072 public key");
}

/// A public-only symmetric key whose unique size mismatches nameAlg fails with TPM_RC_KEY.
#[test]
fn symcipher_unique_size_mismatch_rejected() {
    let mut sim = create_simulator!();

    let sym_unique = [0x01; 16];
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            AES128_CFB,
            Tpm2bDigest::from_bytes(&sym_unique).unwrap(),
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::KEY.with(Position::parameter(2));
    assert_eq!(err.get(), expected.get());
}

/// LoadExternal with an unsupported nameAlg fails with TPM_RC_HASH.
#[test]
fn unsupported_name_alg_rejected() {
    let mut sim = create_simulator!();
    let in_public = tpm2::Tpm2b(make_rsa_public_area_exact_attrs(
        RSA_N,
        TpmiAlgHash::Sm3_256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    match res {
        Err(e) => assert_eq!(e, TpmRc::HASH.with(Position::parameter(2)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// A public area with an unsupported nameAlg fails with TPM_RC_HASH.
#[test]
fn unsupported_name_alg_returns_hash() {
    let mut sim = create_simulator!();
    let mut pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    pub_struct.name_alg = Some(TpmiAlgHash::Sm3_256);
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    let expected = TpmRc::HASH.with(Position::parameter(2));
    assert_eq!(err.get(), expected.get());
}
