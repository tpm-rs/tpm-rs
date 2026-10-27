//! TPM2_LoadExternal public area validation: points, sizes, name algorithms and attributes.

use crate::_common::{
    AES128_CFB, ECC_X, ECC_Y, RSA_N, ecc_sign_template, execute_with_password_sessions, hash_parts,
    leak_bytes, load_external, make_ecc_public_area, make_ecc_public_area_exact_attrs,
    make_rsa_public_area_exact_attrs, make_rsa_public_area_opt_name_alg, rc_p, sealed_template,
    sym_template_with,
};
use testing::tpm::Tpm;
use tpm2::commands::LoadExternal;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bPublic, Tpm2bPublicKeyRsa, Tpm2bSymKey,
    TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsRsaParms, TpmtPublic, TpmtSensitive,
    TpmuSensitiveComposite,
};

/// LoadExternal of an ECC public key with a wrong-size coordinate fails with TPM_RC_KEY.
#[test]
fn ecc_coordinate_size_mismatch_rejected() {
    let mut sim = Tpm::new();
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
    let mut sim = Tpm::new();
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
    let mut sim = Tpm::new();
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
    let mut sim = Tpm::new();
    let pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    let PublicParmsAndId::Ecc(parms, _) = pub_struct.parms_and_id else {
        unreachable!("an ECC public area");
    };
    // curveID = TPM_ECC_BN_P638, which this TPM does not implement (not a `TpmEccCurve` of
    // this TPM). It follows nameAlg, objectAttributes, authPolicy, symmetric and scheme.
    let curve_offset = 4
        + crate::_common::marshal_to_vec(&pub_struct.auth_policy).len()
        + crate::_common::marshal_to_vec(&parms.symmetric).len()
        + crate::_common::marshal_to_vec(&parms.scheme).len();
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let res = crate::_common::execute_with_corrupted_bytes_status(&mut sim, &cmd, 0, &[], |p| {
        let name_alg = crate::_common::tpm2b_public_name_alg(crate::_common::tpm2b_end(p, 0));
        crate::_common::put_u16(p, name_alg + 2 + curve_offset, 0x0011);
    });
    assert!(res.is_err());
}

/// A raw command whose TPM2B_PUBLIC size disagrees with its contents is rejected.
#[test]
fn inconsistent_public_size_rejected() {
    let mut sim = Tpm::new();
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
    let mut sim = Tpm::new();
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
    let mut sim = Tpm::new();
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

/// LoadExternal runs SchemeChecks and digest-sized seed/unique checks, and rejects RSA-3072 public
/// keys (a key size outside this TPM's profile).
#[test]
fn scheme_seed_unique_and_key_size_checks() {
    let mut sim = Tpm::new();
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

    // 4. RSA-3072 is not a key size of this TPM's profile (1024 and 2048 bits), so `keyBits`
    //    fails to unmarshal: VALUE + P2. TPM 2.0 Part 2, Table "Definition of (RSA)
    //    (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type": "$RSA_KEY_SIZES_BITS | the number of bits in
    //    the supported key", "#TPM_RC_VALUE | error when key size is not supported". (Its note
    //    allows "limited support for smaller RSA key sizes" in `TPM2_LoadExternal()`, not larger
    //    ones.)
    //    The `tpm2` types of this TPM cannot hold an RSA-3072 key, so a 2048-bit key is
    //    marshaled, its keyBits replaced and its modulus grown to 384 octets.
    let mut modulus = [0x33u8; 256];
    modulus[0] = 0xd5;
    let t = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&modulus)).unwrap(),
        ),
    };
    let cmd = tpm2::commands::LoadExternal {
        in_private: None,
        in_public: tpm2::Tpm2b(t),
        hierarchy: Handle::RH_OWNER,
    };
    let (mut raw, params) = crate::_common::build_cmd_with_param_offset(&cmd, &[]);
    // inPrivate (empty), then inPublic: size, type, nameAlg, objectAttributes, authPolicy
    // (empty), symmetric (NULL), scheme (NULL), keyBits, exponent and the modulus.
    let in_public = params + 2;
    let key_bits = crate::_common::tpm2b_public_name_alg(in_public) + 2 + 4 + 2 + 2 + 2;
    crate::_common::put_u16(&mut raw, key_bits, 3072);
    let modulus_end = crate::_common::tpm2b_end(&raw, key_bits + 2 + 4);
    crate::_common::grow_command(
        &mut raw,
        &[in_public, key_bits + 6],
        modulus_end,
        &[0x33; 128],
    );
    assert_eq!(
        crate::_common::raw_rc(&mut sim, &raw),
        rc_p(TpmRc::VALUE, 2)
    );
}

/// A public-only symmetric key whose unique size mismatches nameAlg fails with TPM_RC_KEY.
#[test]
fn symcipher_unique_size_mismatch_rejected() {
    let mut sim = Tpm::new();

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
    let mut sim = Tpm::new();
    let in_public = tpm2::Tpm2b(make_rsa_public_area_exact_attrs(
        RSA_N,
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    // nameAlg = SM3_256, which this TPM does not implement (not a `TpmiAlgHash` of this TPM).
    let res = crate::_common::execute_with_corrupted_bytes_status(&mut sim, &cmd, 0, &[], |p| {
        let name_alg = crate::_common::tpm2b_public_name_alg(crate::_common::tpm2b_end(p, 0));
        crate::_common::put_u16(p, name_alg, tpm2::Alg::SM3_256.id());
    });
    match res {
        Err(e) => assert_eq!(e, TpmRc::HASH.with(Position::parameter(2)).get()),
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// A public area with an unsupported nameAlg fails with TPM_RC_HASH.
#[test]
fn unsupported_name_alg_returns_hash() {
    let mut sim = Tpm::new();
    let pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    // nameAlg = SM3_256, which this TPM does not implement (not a `TpmiAlgHash` of this TPM).
    let res = crate::_common::execute_with_corrupted_bytes_status(&mut sim, &cmd, 0, &[], |p| {
        let name_alg = crate::_common::tpm2b_public_name_alg(crate::_common::tpm2b_end(p, 0));
        crate::_common::put_u16(p, name_alg, tpm2::Alg::SM3_256.id());
    });
    let expected = TpmRc::HASH.with(Position::parameter(2));
    assert_eq!(res.err(), Some(expected.get()));
}

/// A `nameAlg` the TPM does not implement (SM3-256) is `TPM_RC_HASH + P2` and a curve it does not
/// implement (BN P-638) is `TPM_RC_CURVE + P2`, before the invalid `hierarchy` (parameter 3) is
/// examined. TPM 2.0 Part 2, `TPMI_ALG_HASH`: "`TPMI_ALG_HASH` is an interface type of all the hash
/// algorithms implemented on a specific TPM" with "#TPM_RC_HASH"; `TPMI_ECC_CURVE`: "enumerates
/// the ECC curves implemented by the TPM", Table "Definition of (ECC) (TPM_ECC_CURVE)
/// TPMI_ECC_CURVE Type": "#TPM_RC_CURVE | error when curve is not supported". Found by
/// differential fuzzing.
#[test]
fn name_alg_and_curve_outside_the_profile_rejected_at_unmarshal() {
    let mut tpm = testing::tpm::Tpm::new();
    let steps: [(&str, u32); 3] = [
        (
            concat!(
                "80010000006800000167000000560023000b000400400000001000100011001000203561244d853489754cf0710d875a",
                "7ba4b2aca9cc38a5d02985d4ceb83bcbd0a20020f8f0017d0000000000000013823d0402018200040004010004000000",
                "1000000052820201",
            ),
            0x2e6,
        ),
        (
            concat!(
                "800100000068000001670000005600230012000400400000001000100003001000203561244d853489754cf0710d875a",
                "7ba4b2aca9cc38a5d02985d4ceb83bcbd0a20020f8f0b6850f0925254ff63a19a01125a88994fc866060354d9305a711",
                "686dfc8640000007",
            ),
            0x2c3,
        ),
        (
            concat!(
                "800100000068000001670000005600230012000400400000001000100003001000203561244d853489754cf0710d875a",
                "7ba4b2aca9cc38a5d02985d4ceb83bcbd0a20020f8f0b6850f0925254ff63a19a01125a88994fc866060354d9305a740",
                "11686d7177400000",
            ),
            0x2c3,
        ),
    ];
    for (i, (cmd, rc)) in steps.into_iter().enumerate() {
        let rsp = tpm.send_command(0, &crate::_common::hex_checked(cmd));
        assert_eq!(
            u32::from_be_bytes(rsp[6..10].try_into().unwrap()),
            rc,
            "step {i}: {rsp:02x?}"
        );
    }
}
