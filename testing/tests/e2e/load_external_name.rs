//! Names returned by TPM2_LoadExternal match nameAlg || H(public area).

use crate::_common::{
    ECC_D, ECC_X, ECC_Y, RSA_N, flush_context, make_ecc_public_area,
    make_keyed_hash_public_area_obfuscated, make_rsa_public_area_opt_name_alg, marshal_to_slice,
};
use tpm2::commands::LoadExternal;
use tpm2::{
    Alg, Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bName, TpmaObject, TpmiAlgHash,
    TpmtSensitive, TpmuSensitiveComposite,
};
use tpm2_platform_linux::PlatformCryptoProvider;
use tpm2_simulator::create_simulator;

/// The returned Name of a loaded ECC key equals nameAlg || H(public area).
#[test]
fn ecc_name_matches_public_digest() {
    let mut sim = create_simulator!();
    let pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let resp = sim.execute(cmd).unwrap();

    // Compute expected name
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&pub_struct, &mut buf);
    let provider = PlatformCryptoProvider;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(&provider, TpmiAlgHash::Sha256, &buf[..len], &mut digest_buf)
        .unwrap()
        .digest();
    let mut name_bytes = Vec::new();
    name_bytes.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes.extend_from_slice(digest);
    let expected_name = Tpm2bName::from_bytes(crate::_common::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(resp.name, expected_name);
    flush_context(&mut sim, resp.object_handle).unwrap();
}

/// The returned Name of a loaded keyedHash object equals nameAlg || H(public area).
#[test]
fn keyed_hash_name_matches_public_digest() {
    let mut sim = create_simulator!();
    let unique_bytes = [0x01; 32];
    let pub_struct = make_keyed_hash_public_area_obfuscated(&unique_bytes, TpmaObject::default());
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let resp = sim.execute(cmd).unwrap();

    // Compute expected name
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&pub_struct, &mut buf);
    let provider = PlatformCryptoProvider;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(&provider, TpmiAlgHash::Sha256, &buf[..len], &mut digest_buf)
        .unwrap()
        .digest();
    let mut name_bytes = Vec::new();
    name_bytes.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes.extend_from_slice(digest);
    let expected_name = Tpm2bName::from_bytes(crate::_common::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(resp.name, expected_name);
    flush_context(&mut sim, resp.object_handle).unwrap();
}

/// The Name of a key loaded with its sensitive area is still computed from the public area.
#[test]
fn name_with_sensitive_matches_public_digest() {
    let mut sim = create_simulator!();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    let in_public = tpm2::Tpm2b(pub_struct);

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let resp = sim.execute(cmd).unwrap();

    // Compute expected name
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&pub_struct, &mut buf);
    let provider = PlatformCryptoProvider;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(&provider, TpmiAlgHash::Sha256, &buf[..len], &mut digest_buf)
        .unwrap()
        .digest();
    let mut name_bytes = Vec::new();
    name_bytes.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes.extend_from_slice(digest);
    let expected_name = Tpm2bName::from_bytes(crate::_common::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(resp.name, expected_name);
    flush_context(&mut sim, resp.object_handle).unwrap();
}

/// A public area with nameAlg TPM_ALG_NULL loads and yields a handle-only Name.
#[test]
fn null_name_alg_name_is_handle() {
    let mut sim = create_simulator!();
    let pub_struct = make_rsa_public_area_opt_name_alg(RSA_N, None, TpmaObject::SIGN_ENCRYPT);
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let resp = sim.execute(cmd).unwrap();
    assert_eq!(resp.name, Tpm2bName::default());
    flush_context(&mut sim, resp.object_handle).unwrap();
}

/// The returned Name of a loaded RSA key equals nameAlg || H(public area).
#[test]
fn rsa_name_matches_public_digest() {
    let mut sim = create_simulator!();
    let pub_struct = make_rsa_public_area_opt_name_alg(
        RSA_N,
        Some(TpmiAlgHash::Sha256),
        TpmaObject::SIGN_ENCRYPT,
    );
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let resp = sim.execute(cmd).unwrap();

    // Compute expected name
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&pub_struct, &mut buf);
    let provider = PlatformCryptoProvider;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(&provider, TpmiAlgHash::Sha256, &buf[..len], &mut digest_buf)
        .unwrap()
        .digest();
    let mut name_bytes = Vec::new();
    name_bytes.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes.extend_from_slice(digest);
    let expected_name = Tpm2bName::from_bytes(crate::_common::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(resp.name, expected_name);
    flush_context(&mut sim, resp.object_handle).unwrap();
}

/// A key with SHA-512 nameAlg loads and its Name is the SHA-512 public digest.
#[test]
fn sha512_name_alg_name() {
    let mut sim = create_simulator!();
    let mut pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    pub_struct.name_alg = Some(TpmiAlgHash::Sha512);
    let in_public = tpm2::Tpm2b(pub_struct);
    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp = sim.execute(cmd).unwrap();

    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&pub_struct, &mut buf);
    let provider = PlatformCryptoProvider;
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(&provider, TpmiAlgHash::Sha512, &buf[..len], &mut digest_buf)
        .unwrap()
        .digest();
    let mut name_bytes = Vec::new();
    name_bytes.extend_from_slice(&Alg::from(TpmiAlgHash::Sha512).id().to_be_bytes());
    name_bytes.extend_from_slice(digest);
    let expected_name = Tpm2bName::from_bytes(crate::_common::leak_bytes(&name_bytes)).unwrap();

    assert_eq!(resp.name, expected_name);
    flush_context(&mut sim, resp.object_handle).unwrap();
}
