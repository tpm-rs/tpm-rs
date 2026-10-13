//! TPM2_HMAC: buffer sizes, key and scheme validation, and HMAC results.

use crate::_common::{
    AES128_CFB, CC_MAC, LocalHmacCmdExplicitNullAlg, create_primary_null,
    create_primary_returning_public, exec_pw, flush_context, get_bound_unique,
    load_ecc_with_private, load_rsa_with_private, load_with_private, mac_params,
    make_keyed_hash_public_area, make_keyed_hash_public_area_with_sensitive,
    rsa_public_with_symmetric, sdo_user, send_key_command,
};
use tpm2::commands::LoadExternal;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bMaxBuffer, Tpm2bSensitiveData,
    Tpm2bSymKey, TpmaObject, TpmiAlgHash, TpmtKeyedHashScheme, TpmtPublic, TpmtSensitive,
    TpmuSensitiveComposite,
};
use tpm2_simulator::create_simulator;

/// 7. Test MAC with an empty input buffer (0 bytes).
///
/// Expected: TPM_RC_SUCCESS.
#[test]
fn hmac_accepts_empty_buffer() {
    let mut sim = create_simulator!();

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::default(), // 0-length buffer
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(
        res.is_ok(),
        "MAC calculation on empty buffer should succeed"
    );

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 8. Test MAC with maximum-sized input buffer (1024 bytes).
///
/// Expected: TPM_RC_SUCCESS.
#[test]
fn hmac_accepts_max_buffer() {
    let mut sim = create_simulator!();

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let max_data = [0x55u8; 1024];
    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(crate::_common::leak_bytes(&max_data)).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(
        res.is_ok(),
        "MAC calculation on maximum buffer size should succeed"
    );

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with key default scheme HMAC-SHA256 and command hash_alg Null.
/// It should use SHA256 and succeed.
///
/// Expected: TPM_RC_SUCCESS.
#[test]
fn hmac_null_hash_uses_key_scheme_hash() {
    let mut sim = create_simulator!();

    let scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(scheme, get_bound_unique(b"secrets")),
    });

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: None, // Null command hash
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(
        res.is_ok(),
        "MAC should succeed using key's default scheme when command hash is Null: {:?}",
        res.err()
    );

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with Null key scheme and multiple different supported command hash algorithms.
///
/// Expected: TPM_RC_SUCCESS for all and matching local HMAC results.
#[test]
fn hmac_null_scheme_uses_requested_hash() {
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384};

    let mut sim = create_simulator!();
    let key_bytes = b"my hmac key material";

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(key_bytes).unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area_with_sensitive(
        &[0x01; 32],
        // sign+decrypt: the only keyed-hash form with a NULL scheme.
        TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        key_bytes,
    ));

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let data = b"some message to hmac";

    // Test with SHA256
    let hmac_cmd_256 = LocalHmacCmdExplicitNullAlg {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res_256 = exec_pw(&mut sim, hmac_cmd_256).unwrap();

    type HmacSha256 = Hmac<Sha256>;
    let mut mac_256 = HmacSha256::new_from_slice(key_bytes).unwrap();
    mac_256.update(data);
    let expected_256 = mac_256.finalize().into_bytes();
    assert_eq!(expected_256.as_slice(), res_256.out_hmac.as_ref());

    // Test with SHA384
    let hmac_cmd_384 = LocalHmacCmdExplicitNullAlg {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha384),
    };
    let res_384 = exec_pw(&mut sim, hmac_cmd_384).unwrap();

    type HmacSha384 = Hmac<Sha384>;
    let mut mac_384 = HmacSha384::new_from_slice(key_bytes).unwrap();
    mac_384.update(data);
    let expected_384 = mac_384.finalize().into_bytes();
    assert_eq!(expected_384.as_slice(), res_384.out_hmac.as_ref());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with an invalid key type (ECC key).
///
/// Expected: TPM_RC_TYPE.
#[test]
fn hmac_rejects_ecc_key() {
    let mut sim = create_simulator!();

    let object_handle = load_ecc_with_private(&mut sim, TpmaObject::SIGN_ENCRYPT);

    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(
        res.is_err(),
        "MAC should fail for non-keyedhash/non-symcipher key types (ECC)"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::TYPE.with(Position::handle(1)).get());

    flush_context(&mut sim, object_handle).unwrap();
}

/// Test MAC with mismatched command hash algorithm (command SHA384 vs key Hmac(SHA256)).
///
/// Expected: TPM_RC_VALUE.
#[test]
fn hmac_rejects_hash_mismatching_key_scheme() {
    let mut sim = create_simulator!();

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            get_bound_unique(b"secrets"),
        ),
    });

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha384), // Mismatched command hash alg
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::VALUE.with(Position::parameter(2)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 3. Test MAC with a key that does not have the 'sign' attribute set.
///
/// Expected: TPM_RC_KEY.
#[test]
fn hmac_rejects_key_without_sign() {
    let mut sim = create_simulator!();

    // Load a keyed hash key with NO attributes (or DECRYPT only)
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::DECRYPT, // NOT sign/encrypt
    ));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(
        res.is_err(),
        "MAC should fail when the key does not have the sign attribute"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::KEY.with(Position::handle(1)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with Null key scheme and Null command hash algorithm.
///
/// Expected: TPM_RC_VALUE.
#[test]
fn hmac_rejects_null_scheme_and_null_hash() {
    let mut sim = create_simulator!();

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        // sign+decrypt: the only keyed-hash form with a NULL scheme.
        TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
    ));

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: None, // Null command hash alg
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::VALUE.with(Position::parameter(2)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 6. Test MAC with a public-only key (no private key data loaded).
///
/// Expected: TPM_RC_KEY or TPM_RC_AUTH_UNAVAILABLE.
#[test]
fn hmac_rejects_public_only_key() {
    let mut sim = create_simulator!();

    // Load a public-only keyed hash key (in_private is default/empty)
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: None, // Empty sensitive area
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(
        res.is_err(),
        "MAC should fail when sensitive area is missing"
    );
    let err = res.err().unwrap();
    // C IsAuthValueAvailable: a public-only object can't be authorized.
    assert_eq!(err.get(), TpmRc::AUTH_UNAVAILABLE.get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// 4. Test MAC with a restricted key.
///
/// Expected: TPM_RC_ATTRIBUTES.
#[test]
fn hmac_rejects_restricted_key() {
    let mut sim = create_simulator!();

    // LoadExternal can't load a restricted key with its sensitive area, and a public-only key
    // fails USER authorization (TPM_RC_AUTH_UNAVAILABLE), so let the TPM create the key.
    let object_handle = create_primary_null(
        &mut sim,
        make_keyed_hash_public_area(
            &[],
            TpmaObject::SIGN_ENCRYPT
                | TpmaObject::RESTRICTED
                | TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN,
        ),
    );

    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(res.is_err(), "MAC should fail for a restricted key");
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::ATTRIBUTES.with(Position::handle(1)).get());

    flush_context(&mut sim, object_handle).unwrap();
}

/// 5. Test MAC with an invalid key type (e.g. RSA key).
///
/// Expected: TPM_RC_TYPE.
#[test]
fn hmac_rejects_rsa_key() {
    let mut sim = create_simulator!();

    // Private part loaded so that authorization succeeds and the type check is reached.
    let object_handle = load_rsa_with_private(&mut sim, TpmaObject::SIGN_ENCRYPT, None);

    // Try to perform MAC using the RSA key
    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(
        res.is_err(),
        "MAC should fail for non-keyedhash/non-symcipher key types"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::TYPE.with(Position::handle(1)).get());

    flush_context(&mut sim, object_handle).unwrap();
}

/// Raw TPM2_HMAC with an RSA signing primary key is rejected
#[test]
fn hmac_rejects_rsa_signing_key_raw() {
    let mut sim = create_simulator!();

    // An RSA signing key (NOT a KeyedHash or HMAC key).
    let (key, _) = create_primary_returning_public(
        &mut sim,
        rsa_public_with_symmetric(TpmaObject::SIGN_ENCRYPT | sdo_user(), None),
        &[],
    );

    let error_code = send_key_command(&mut sim, CC_MAC, key, true, &mac_params(0x000b));
    assert!(
        error_code != 0,
        "MAC command succeeded on an RSA key handle! Type confusion bug detected. error_code = 0x{:08X}",
        error_code
    );
}

/// Test MAC with a symmetric cipher key (invalid key type).
///
/// Expected: TPM_RC_TYPE.
#[test]
fn hmac_rejects_symcipher_key() {
    let mut sim = create_simulator!();

    let key = [0x11u8; 16];
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            AES128_CFB,
            get_bound_unique(crate::_common::leak_bytes(&key)),
        ),
    };
    let object_handle = load_with_private(
        &mut sim,
        public,
        TpmuSensitiveComposite::Sym(
            Tpm2bSymKey::from_bytes(crate::_common::leak_bytes(&key)).unwrap(),
        ),
        &[0x02; 32],
    );

    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(
        res.is_err(),
        "MAC should fail for non-keyedhash key types (symmetric cipher)"
    );
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::TYPE.with(Position::handle(1)).get());

    flush_context(&mut sim, object_handle).unwrap();
}

/// 1. Test MAC with an invalid or non-existent handle.
///
/// Expected: TPM_RC_HANDLE (Error position Pos1 / Parameter-specific).
#[test]
fn hmac_rejects_unloaded_key_handle() {
    let mut sim = create_simulator!();
    let cmd = LocalHmacCmdExplicitNullAlg {
        handle: Handle(0x8000000E), // Arbitrary unused handle
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = sim.execute(cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::REFERENCE_H0.get());
}

/// 2. Test MAC with unsupported/non-SHA256 hash algorithm (e.g. SHA384).
///
/// Expected: TPM_RC_HASH.
#[test]
fn hmac_rejects_unsupported_hash_alg() {
    let mut sim = create_simulator!();

    // Load a valid keyed hash key
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area(
        &[0x01; 32],
        // sign+decrypt: the only keyed-hash form with a NULL scheme, so hashAlg is used.
        TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
    ));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    // Send MAC command with SM3256 hash alg (unsupported)
    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sm3_256),
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err.get(), TpmRc::HASH.with(Position::parameter(2)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// Test MAC with a KeyedHash key using XOR scheme.
///
/// Expected: TPM_RC_KEY (the XOR key is a keyed hash but cannot sign).
#[test]
fn hmac_rejects_xor_key_kdf2() {
    let mut sim = create_simulator!();

    let scheme = TpmtKeyedHashScheme::ExclusiveOr(tpm2::TpmsSchemeXor {
        hash_alg: TpmiAlgHash::Sha256,
        kdf: Some(tpm2::TpmiAlgKdf::Kdf2),
    });
    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(Some(scheme), get_bound_unique(b"secrets")),
    });

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        ),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);

    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let resp_handles = sim.execute(load_cmd).unwrap();

    let hmac_cmd = LocalHmacCmdExplicitNullAlg {
        handle: resp_handles.object_handle,
        in_buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = exec_pw(&mut sim, hmac_cmd);
    assert!(
        res.is_err(),
        "MAC should fail for KeyedHash keys with XOR scheme"
    );
    let err = res.err().unwrap();
    // HMAC.c: the key is a keyed hash (no TYPE error) but lacks `sign` -> TPM_RCS_KEY + H1.
    assert_eq!(err.get(), TpmRc::KEY.with(Position::handle(1)).get());

    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}
