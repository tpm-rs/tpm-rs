//! TPM2_LoadExternal of keys together with their sensitive area.

use crate::_common::{
    AES128_CFB, ECC_X, ECC_Y, RSA_N, RSA_P, flush_context, make_ecc_public_area,
    make_keyed_hash_public_area_obfuscated, make_rsa_public_area_opt_name_alg,
};
use sha2::{Digest as _, Sha256};
use testing::tpm::Tpm;
use tpm2::commands::LoadExternal;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bPrivateKeyRsa,
    Tpm2bSensitiveData, Tpm2bSymKey, TpmaObject, TpmiAlgHash, TpmtPublic, TpmtSensitive,
    TpmuSensitiveComposite,
};

/// Loads an ECC key with nameAlg TPM_ALG_NULL (no sensitive area).
#[test]
fn ecc_null_name_alg_public_only() {
    let mut sim = Tpm::new();
    let mut pub_struct = make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT);
    pub_struct.name_alg = None;
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

/// Loads a keyedHash object (with sensitive) whose public area carries an authPolicy.
#[test]
fn keyed_hash_with_auth_policy() {
    let mut sim = Tpm::new();
    let seed_value = Tpm2bDigest::from_bytes(b"obfuscation is my middle name!!!").unwrap();
    let sensitive_data = Tpm2bSensitiveData::from_bytes(b"secrets").unwrap();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value,
        sensitive: TpmuSensitiveComposite::KeyedHash(sensitive_data),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let unique_bytes = [0x02; 32];
    let mut pub_struct =
        make_keyed_hash_public_area_obfuscated(&unique_bytes, TpmaObject::default());
    pub_struct.auth_policy = Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap();
    let in_public = tpm2::Tpm2b(pub_struct);

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Loads a keyedHash object with its sensitive area (public + private).
#[test]
fn keyed_hash_with_sensitive() {
    let mut sim = Tpm::new();
    let seed_value = Tpm2bDigest::from_bytes(b"obfuscation is my middle name!!!").unwrap();
    let sensitive_data = Tpm2bSensitiveData::from_bytes(b"secrets").unwrap();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value,
        sensitive: TpmuSensitiveComposite::KeyedHash(sensitive_data),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let unique_bytes = [
        0xed, 0x4f, 0xe8, 0xe2, 0xbf, 0xf9, 0x76, 0x65, 0xe7, 0xbf, 0xbe, 0x27, 0xc2, 0x36, 0x5d,
        0x07, 0xa9, 0xbe, 0x91, 0xdd, 0x92, 0xd9, 0x97, 0xcd, 0x91, 0xcc, 0x70, 0x6b, 0x60, 0x74,
        0xeb, 0x08,
    ];
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area_obfuscated(
        &unique_bytes,
        TpmaObject::default(),
    ));

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Loads an RSA key together with its private prime.
#[test]
fn rsa_with_private_prime() {
    let mut sim = Tpm::new();
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(RSA_P).unwrap()),
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
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Loads a symmetric key with digest-sized seedValue and unique = H(seed || key).
#[test]
fn symcipher_with_seed_and_key() {
    let mut sim = Tpm::new();
    // With a nameAlg, C requires a digest-sized seedValue (CryptUtil.c, else
    // KEY_SIZE+P1) and unique = H(seedValue || key).
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(&[0x01; 16]).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let mut hasher = Sha256::new();
    hasher.update([0x02; 32]);
    hasher.update([0x01; 16]);
    let sym_unique = hasher.finalize().to_vec();

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            AES128_CFB,
            Tpm2bDigest::from_bytes(&sym_unique).unwrap(),
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(cmd).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}
