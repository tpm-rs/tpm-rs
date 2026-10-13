//! TPM2_Import validation: seeds, inner/outer wrappers, encryptedDuplication and parent
//! requirements.
#![allow(deprecated)] // TPM2_CreateLoaded is deprecated upstream, but the TPM implements it.

use crate::_common::{
    AES128_CFB, command_rc, compute_object_name, create_and_load, create_dup_target,
    create_duplicate_challenged, create_owner_primary, create_parent, create_srk,
    create_storage_primary, create_test_primary, create_unwrap, derivation_parent_template,
    duplicable_sign_template, duplicate_alg, duplicate_command, duplicate_command_with_name_alg,
    ecc_public_with_policy, ecc_sign_template, empty_password_auth, exec_command,
    execute_tpm_command_offsets, execute_with_password_sessions,
    execute_with_password_sessions_status, expected_inner_wrapper_rc, flush_context,
    get_ecc_srk_template, get_rsa_srk_template, hex_checked, import, import_command,
    import_encapsulation_key, import_request, leak_bytes, load_with_name, make_sealed_blob,
    marshal_to_slice, owner_srk, pw, raw_rc, rc_h, rc_p, read_public, rewrap, rsa_dup_target,
    rsa_public, rsa_storage_template, rsa_storage_template_with, storage_attrs,
    try_create_owner_primary, try_create_primary_in,
};
use testing::tpm::Tpm;
use tpm2::commands::{CreateLoaded, CreatePrimary, Import, Load, Unseal, *};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Marshal, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret,
    Tpm2bPrivate, Tpm2bPublic, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmEccCurve, TpmaObject,
    TpmiAlgHash, TpmiRsaKeyBits, TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic, *,
};

/// `TPM2_Import` with an empty `inSymSeed` and empty `duplicate` under a
/// parent with a symmetric algorithm fails.
#[test]
fn empty_seed_and_duplicate_rejected() {
    let mut sim = Tpm::new();

    // 1. A parent ECC storage key with symmetric encryption enabled (AES-128 CFB)
    let (parent, _) = try_create_owner_primary(
        &mut sim,
        ecc_public_with_policy(
            TpmiAlgHash::Sha256,
            storage_attrs(),
            &[],
            TpmEccCurve::NistP256,
            Some(AES128_CFB),
        ),
    )
    .unwrap();

    // 2. A target signing key public area
    let target = create_unwrap(
        &mut sim,
        parent,
        rsa_dup_target(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    );

    // 3. Call Import with empty in_sym_seed
    let res = import_command(
        &mut sim,
        parent,
        &Import {
            parent_handle: parent,
            encryption_key: Tpm2bData::default(),
            object_public: target.out_public,
            duplicate: Tpm2bPrivate::default(),
            in_sym_seed: Tpm2bEncryptedSecret::default(), // Empty!
            symmetric_alg: None,
        },
    );
    assert!(
        res.is_err(),
        "Expected Import to fail because in_sym_seed is empty but parent symmetric is not Null"
    );
}

/// `TPM2_Import` of an `encryptedDuplication` object without an inner wrapper
/// key fails with `TPM_RC_ATTRIBUTES` on `encryptionKey`.
#[test]
fn encrypted_duplication_without_inner_key_rejected() {
    let mut sim = Tpm::new();

    // 1. A parent storage key
    let parent = create_srk(&mut sim);

    // 2. A target signing key with the ENCRYPTED_DUPLICATION attribute
    let target = create_unwrap(
        &mut sim,
        parent,
        rsa_dup_target(TpmiAlgHash::Sha256, TpmaObject::ENCRYPTED_DUPLICATION),
        &[],
    );

    // 3. Try to Import it with empty in_sym_seed / empty encryptionKey -> should fail
    let res = import_command(
        &mut sim,
        parent,
        &Import {
            parent_handle: parent,
            encryption_key: Tpm2bData::default(), // Empty!
            object_public: target.out_public,
            duplicate: Tpm2bPrivate::default(),
            in_sym_seed: Tpm2bEncryptedSecret::default(), // Empty!
            symmetric_alg: None,
        },
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(1)).get())
    );
}

/// Import with a wrong encryption key size fails with TPM_RC_SIZE and with fixedTPM set fails with TPM_RC_ATTRIBUTES.
#[test]
fn encryption_key_size_and_fixed_tpm() {
    let mut sim = Tpm::new();

    // 1. Create a primary parent key
    let parent_handle = create_parent(&mut sim);

    // 2. Test Import with invalid encryption key size
    let child_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&[0x22; 256]).unwrap(),
        ),
    };
    let import_cmd_bad_size = Import {
        parent_handle,
        encryption_key: Tpm2bData::from_bytes(&[0u8; 32]).unwrap(), // 32 bytes instead of 16 for AES 128
        object_public: tpm2::Tpm2b(child_pub),
        duplicate: Tpm2bPrivate::from_bytes(&[0x11; 32]).unwrap(),
        in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&[0x22; 256]).unwrap(),
        symmetric_alg: Some(AES128_CFB),
    };
    let res_size =
        execute_tpm_command_offsets(&mut sim, &import_cmd_bad_size, &[empty_password_auth()]);
    assert_eq!(
        res_size.err(),
        Some(TpmRc::SIZE.with(Position::parameter(1)).get()),
        "TPM2_Import with invalid encryption_key size must return TPM_RC_SIZE at Pos1"
    );

    // 3. Test Import with fixedTPM attribute set (must be CLEAR for imported objects)
    let child_pub_bad_attrs = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::FIXED_TPM, // Invalid for import
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&[0x22; 256]).unwrap(),
        ),
    };
    let import_cmd_bad_attrs = Import {
        parent_handle,
        encryption_key: Tpm2bData::from_bytes(&[0u8; 16]).unwrap(),
        object_public: tpm2::Tpm2b(child_pub_bad_attrs),
        duplicate: Tpm2bPrivate::from_bytes(&[0x11; 32]).unwrap(),
        in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&[0x22; 256]).unwrap(),
        symmetric_alg: Some(AES128_CFB),
    };
    let res_attrs =
        execute_tpm_command_offsets(&mut sim, &import_cmd_bad_attrs, &[empty_password_auth()]);
    assert_eq!(
        res_attrs.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get()),
        "TPM2_Import with fixedTPM set must return TPM_RC_ATTRIBUTES at Pos2"
    );
}

/// Import with fixedTPM set on objectPublic fails with TPM_RC_ATTRIBUTES + P2.
#[test]
fn fixed_tpm_attribute_precedence() {
    let mut sim = Tpm::new();

    let parent_handle = create_test_primary(&mut sim);

    // Construct TPM2_Import command with fixedTPM attribute set on object_public (Pos2)
    // Table 31 mandates that fixedTPM MUST be clear for imported objects, returning
    // TPM_RC_ATTRIBUTES at Pos2 (0x240)
    let bad_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let import_cmd = Import {
        parent_handle,
        encryption_key: Tpm2bData::from_bytes(&[0u8; 16]).unwrap(),
        object_public: Tpm2b(bad_pub),
        duplicate: Tpm2bPrivate::default(),
        in_sym_seed: Tpm2bEncryptedSecret::default(),
        symmetric_alg: Some(AES128_CFB),
    };

    let rc = execute_with_password_sessions_status(&mut sim, &import_cmd, 1, &[]).err();
    assert_eq!(
        rc,
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get()),
        "TPM2_Import with fixedTPM set must return TPM_RC_ATTRIBUTES at Pos2 per Table 31"
    );
}

/// `TPM2_Import` of an object with `fixedTPM` set fails with
/// `TPM_RC_ATTRIBUTES` on `objectPublic`.
#[test]
fn fixed_tpm_object_rejected() {
    let mut sim = Tpm::new();

    let parent = create_srk(&mut sim);

    // Target key public area with the FIXED_TPM attribute set
    let target_public = rsa_public(
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::FIXED_TPM,
        &[],
        None,
    );

    let res = import_command(
        &mut sim,
        parent,
        &Import {
            parent_handle: parent,
            encryption_key: Tpm2bData::default(),
            object_public: Tpm2b(target_public),
            duplicate: Tpm2bPrivate::default(),
            in_sym_seed: Tpm2bEncryptedSecret::default(),
            symmetric_alg: None,
        },
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get())
    );
}

/// `TPM2_Import` checks the size of `inSymSeed` (parameter 4) before the attributes of
/// `objectPublic` (parameter 2).
#[test]
fn import_checks_seed_size_before_attributes() {
    let mut sim = Tpm::new();

    // 1. Create primary RSA storage key
    let primary_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(AES128_CFB),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let create_primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: tpm2::Tpm2bAuth::default(),
            data: tpm2::Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(primary_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let resp_handles =
        execute_with_password_sessions(&mut sim, &create_primary_cmd, 1, &[]).unwrap();
    let parent_handle = resp_handles.object_handle;

    // 2. Prepare import command where object_public has FIXED_TPM (attributes error on Pos2)
    // AND in_sym_seed is 512 bytes while parent is 2048-bit (size error on Pos4).
    // Spec order requires size check on in_sym_seed (Pos4) to fail BEFORE attributes check (Pos2).
    let target_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM, // FIXED_TPM triggers TPM_RC_ATTRIBUTES if reached
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(AES128_CFB, Tpm2bDigest::default()),
    };

    let import_cmd = Import {
        parent_handle,
        encryption_key: Tpm2bData::default(),
        object_public: tpm2::Tpm2b(target_pub),
        duplicate: Tpm2bPrivate::from_bytes(&[0u8; 10]).unwrap(),
        in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&[0x55u8; 512]).unwrap(), // 512 bytes > 256
        symmetric_alg: None,
    };

    let rc = execute_with_password_sessions(&mut sim, &import_cmd, 1, &[]).unwrap_err();
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(4)).get());
}

/// Import under a derivation parent or a non-storage signing key fails with TYPE+H1.
#[test]
fn import_rejects_derivation_and_signing_parents() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let (deriver, _) = create_and_load(
        &mut sim,
        srk,
        derivation_parent_template(TpmiAlgHash::Sha256, TpmaObject::SENSITIVE_DATA_ORIGIN),
        &[],
        &[],
    );
    let (signer, _) = create_and_load(
        &mut sim,
        srk,
        ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    );
    let import_rc = |sim: &mut Tpm, parent: Handle| {
        import(
            sim,
            parent,
            Tpm2b(ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty())),
            Tpm2bPrivate::from_bytes(&[0, 2, 0, 0]).unwrap(),
            Tpm2bEncryptedSecret::default(),
        )
        .unwrap_err()
    };
    // Derivation parents and non-storage keys are not parents for Import.
    assert_eq!(import_rc(&mut sim, deriver), rc_h(TpmRc::TYPE, 1));
    assert_eq!(import_rc(&mut sim, signer), rc_h(TpmRc::TYPE, 1));
}

/// `TPM2_Import` rejects malformed outer- and inner-wrapped `duplicate` blobs
/// (too short, oversized integrity, truncated sensitive area, integer overflow
/// of the integrity size) with the C reference's response codes.
#[test]
fn malformed_outer_and_inner_duplicate_blobs() {
    let mut sim = Tpm::new();

    // 1. Parent storage key
    let parent = create_storage_primary(&mut sim, TpmiAlgHash::Sha256);

    // 2. Target signing key
    let (target, object_public) = create_dup_target(&mut sim, parent);

    // 3. Generate a valid duplicate output to get a valid seed.
    let dup_resp = duplicate_command(
        &mut sim,
        target,
        parent,
        &Duplicate {
            object_handle: target,
            new_parent_handle: parent,
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: None,
        },
    )
    .unwrap();

    let import = |sim: &mut Tpm, cmd: Import<'_>| exec_command(sim, &cmd, &[pw()]).map(|_| ());

    // Scenario A: No inner wrapper, duplicate_bytes length < 2 (only 1 byte)
    let res = import(
        &mut sim,
        Import {
            parent_handle: parent,
            encryption_key: Tpm2bData::default(),
            object_public,
            duplicate: Tpm2bPrivate::from_bytes(&[0x00]).unwrap(),
            in_sym_seed: dup_resp.out_sym_seed,
            symmetric_alg: None,
        },
    );
    // inSymSeed is not empty, so the outer wrapper is removed first: C `UnwrapOuter()` cannot
    // unmarshal the TPM2B integrity from 1 byte (TPM_RC_INSUFFICIENT), which TPM2_Import
    // reports against `duplicate` (RcSafeAddToResult(result, RC_Import_duplicate)).
    assert_eq!(
        res.err(),
        Some(TpmRc::INSUFFICIENT.with(Position::parameter(3)).get())
    );

    // Scenario B: No inner wrapper, 2 + sensitive_size > duplicate_bytes length
    // (sensitive_size = 256 (0x0100), but total length is only 3 bytes)
    let res = import(
        &mut sim,
        Import {
            parent_handle: parent,
            encryption_key: Tpm2bData::default(),
            object_public,
            duplicate: Tpm2bPrivate::from_bytes(&[0x01, 0x00, 0x99]).unwrap(),
            in_sym_seed: dup_resp.out_sym_seed,
            symmetric_alg: None,
        },
    );
    // C: outer integrity TPM2B size 256 exceeds TPM2B_DIGEST (TPM_RC_SIZE in UnwrapOuter);
    // TPM2_Import adds RC_Import_duplicate (+P3) via RcSafeAddToResult.
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(Position::parameter(3)).get())
    );

    // Scenario C: Inner wrapper active (AES-128 CFB), but the decrypted inner blob is too short
    // (< 2 bytes). With an empty inSymSeed no outer wrapper is removed.
    let res = import(
        &mut sim,
        Import {
            parent_handle: parent,
            encryption_key: Tpm2bData::from_bytes(&[0u8; 16]).unwrap(),
            object_public,
            duplicate: Tpm2bPrivate::from_bytes(&[0xaa]).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::default(), // Empty seed
            symmetric_alg: Some(AES128_CFB),
        },
    );
    // C: the inner integrity TPM2B cannot be unmarshaled from 1 byte (CheckInnerIntegrity);
    // TPM2_Import adds RC_Import_duplicate (+P3) via RcSafeAddToResult.
    assert_eq!(
        res.err(),
        Some(TpmRc::INSUFFICIENT.with(Position::parameter(3)).get())
    );

    // Scenarios D-F: inner wrapper active with garbage blobs whose (pre-XOR) plaintext encodes
    // D: inner_integrity_len = 100 in a 10-byte blob,
    // E: inner_integrity_len = 4 and sensitive_size = 500 in a 10-byte blob,
    // F: inner_integrity_len = 65535 (integer overflow check).
    let mut plain_d = [0u8; 10];
    plain_d[0..2].copy_from_slice(&100u16.to_be_bytes());
    let mut plain_e = [0u8; 10];
    plain_e[0..2].copy_from_slice(&4u16.to_be_bytes());
    plain_e[6..8].copy_from_slice(&500u16.to_be_bytes());
    let mut plain_f = [0u8; 10];
    plain_f[0..2].copy_from_slice(&65535u16.to_be_bytes());

    for (key_byte, mut blob) in [(0x55u8, plain_d), (0xcc, plain_e), (0x11, plain_f)] {
        for byte in &mut blob {
            *byte ^= key_byte;
        }
        let key = [key_byte; 16];
        let res = import(
            &mut sim,
            Import {
                parent_handle: parent,
                encryption_key: Tpm2bData::from_bytes(&key).unwrap(),
                object_public,
                duplicate: Tpm2bPrivate::from_bytes(&blob).unwrap(),
                in_sym_seed: Tpm2bEncryptedSecret::default(),
                symmetric_alg: Some(AES128_CFB),
            },
        );
        // C: see `expected_inner_wrapper_rc` (the decrypted integrity size is pseudo-random).
        assert_eq!(res.err(), Some(expected_inner_wrapper_rc(&key, &blob)));
    }
}

/// Import: corrupted outer integrity INTEGRITY+P3, inner integrity size/check order, truncated duplicate INSUFFICIENT+P3.
#[test]
fn outer_and_inner_integrity_errors() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let parent = try_create_primary_in(
        &mut sim,
        Handle::RH_OWNER,
        rsa_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    )
    .unwrap()
    .0;
    let (obj, obj_rsp) = create_and_load(
        &mut sim,
        srk,
        duplicable_sign_template(TpmiAlgHash::Sha512),
        &[],
        &[],
    );
    let name = read_public(&mut sim, obj).unwrap().name;
    let dup = duplicate_alg(&mut sim, obj, parent, None, TpmiAlgHash::Sha512).unwrap();
    rewrap(
        &mut sim,
        parent,
        Handle::RH_NULL,
        dup.duplicate,
        name,
        dup.out_sym_seed,
    )
    .expect("outer wrapper hash must be the parent's nameAlg");

    // Corrupted outer integrity -> INTEGRITY + RC_P3 (RC_Import_duplicate).
    let dup = duplicate_alg(&mut sim, obj, parent, None, TpmiAlgHash::Sha512).unwrap();
    let mut blob = dup.duplicate.get_buffer().to_vec();
    blob[4] ^= 0x80;
    assert_eq!(
        import(
            &mut sim,
            parent,
            obj_rsp.out_public,
            Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
            dup.out_sym_seed,
        )
        .unwrap_err(),
        rc_p(TpmRc::INTEGRITY, 3)
    );
    // Inner wrapper: the integrity TPM2B_DIGEST is unmarshaled (size > 64 -> SIZE) and checked
    // (INTEGRITY) before the TPM2B_SENSITIVE is looked at (C CheckInnerIntegrity).
    let key = [0x24u8; 16];
    let inner_import = |sim: &mut Tpm, plain: &[u8]| {
        let mut blob = plain.to_vec();
        crate::_common::aes128_cfb_zero_iv_encrypt(&key, &mut blob);
        command_rc(
            sim,
            &Import {
                parent_handle: parent,
                encryption_key: Tpm2bData::from_bytes(leak_bytes(&key)).unwrap(),
                object_public: obj_rsp.out_public,
                duplicate: Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
                in_sym_seed: Tpm2bEncryptedSecret::default(),
                symmetric_alg: Some(AES128_CFB),
            },
            1,
        )
    };
    let mut plain = vec![0x00, 0x41];
    plain.extend([0u8; 8]);
    assert_eq!(inner_import(&mut sim, &plain), rc_p(TpmRc::SIZE, 3));
    let mut plain = vec![0x00, 0x40];
    plain.extend([0u8; 64 + 8]);
    assert_eq!(inner_import(&mut sim, &plain), rc_p(TpmRc::INTEGRITY, 3));

    // Truncated duplicate -> INSUFFICIENT + RC_P3.
    assert_eq!(
        import(
            &mut sim,
            parent,
            obj_rsp.out_public,
            Tpm2bPrivate::from_bytes(&[0]).unwrap(),
            dup.out_sym_seed,
        )
        .unwrap_err(),
        rc_p(TpmRc::INSUFFICIENT, 3)
    );
}

/// `TPM2_Import` of a valid outer-wrapped duplicate with its `inSymSeed`
/// stripped fails.
#[test]
fn outer_wrapped_duplicate_without_seed_rejected() {
    let mut sim = Tpm::new();

    // 1. A parent ECC storage key with symmetric encryption enabled (AES-128 CFB)
    let (parent, _) = try_create_owner_primary(
        &mut sim,
        ecc_public_with_policy(
            TpmiAlgHash::Sha256,
            storage_attrs(),
            &[],
            TpmEccCurve::NistP256,
            Some(AES128_CFB),
        ),
    )
    .unwrap();

    // 2. A target signing key
    let srk = create_srk(&mut sim);
    let target = create_unwrap(
        &mut sim,
        srk,
        rsa_dup_target(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    );
    let (target_handle, _) =
        load_with_name(&mut sim, srk, target.out_private, target.out_public).unwrap();

    // 3. Execute Duplicate on target under parent
    let dup_resp = duplicate_command_with_name_alg(
        &mut sim,
        target_handle,
        parent,
        &Duplicate {
            object_handle: target_handle,
            new_parent_handle: parent,
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: None,
        },
        TpmiAlgHash::Sha256,
    )
    .expect("Duplicate failed");

    // 4. Call Import with valid duplicate buffer but empty in_sym_seed
    let res = import_command(
        &mut sim,
        parent,
        &Import {
            parent_handle: parent,
            encryption_key: Tpm2bData::default(),
            object_public: target.out_public,
            duplicate: dup_resp.duplicate, // Valid duplicate!
            in_sym_seed: Tpm2bEncryptedSecret::default(), // Empty!
            symmetric_alg: None,
        },
    );
    assert!(
        res.is_err(),
        "Expected Import to fail because in_sym_seed is empty but parent symmetric is not Null"
    );
}

/// `TPM2_Import` under an ECC parent with an `inSymSeed` whose point
/// coordinate is oversized fails with `TPM_RC_ECC_POINT` (and does not panic).
#[test]
fn oversized_ecc_seed_point_rejected() {
    let mut sim = Tpm::new();

    // 1. A parent ECC storage key
    let (parent, _) = try_create_owner_primary(
        &mut sim,
        ecc_public_with_policy(
            TpmiAlgHash::Sha256,
            storage_attrs(),
            &[],
            TpmEccCurve::NistP256,
            Some(AES128_CFB),
        ),
    )
    .unwrap();

    // 2. A target signing key public area
    let target = create_unwrap(
        &mut sim,
        parent,
        rsa_dup_target(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
    );

    // 3. Construct a malformed in_sym_seed with x.size = 33 (larger than 32)
    let mut bad_seed_bytes = Vec::new();
    bad_seed_bytes.extend_from_slice(&33u16.to_be_bytes()); // x size
    bad_seed_bytes.extend_from_slice(&[0u8; 33]); // x buffer
    bad_seed_bytes.extend_from_slice(&32u16.to_be_bytes()); // y size
    bad_seed_bytes.extend_from_slice(&[0u8; 32]); // y buffer

    let res = import_command(
        &mut sim,
        parent,
        &Import {
            parent_handle: parent,
            encryption_key: Tpm2bData::default(),
            object_public: target.out_public,
            duplicate: Tpm2bPrivate::default(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&bad_seed_bytes).unwrap(),
            symmetric_alg: None,
        },
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::ECC_POINT.with(Position::parameter(4)).get())
    );
}

/// Regression test for CPCTPM_TC2_2_15_03_06:
/// TPM2_Import parameter validation:
/// 1. symmetricAlg with invalid mode/keyBits returns TPM_RC_VALUE (Pos5, 0x0503)
/// 2. objectPublic with FIXED_TPM | SENSITIVE_DATA_ORIGIN returns TPM_RC_ATTRIBUTES (Pos2, 0x0282)
/// 3. inSymSeed with oversized buffer returns TPM_RC_SIZE (Pos4, 0x04D5)
#[test]
fn symmetric_attributes_and_seed_size() {
    let mut sim = Tpm::new();

    // Create RSA primary storage parent key under Owner hierarchy
    let parent_handle = create_owner_primary(&mut sim, rsa_storage_template());

    let child_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_TPM,
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: Some(AES128_CFB),
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0x00010001,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    };
    let child_pub_2b = tpm2::Tpm2b(child_pub);
    let mut child_pub_buf = [0u8; Tpm2bPublic::MAX_SIZE];
    let child_pub_len = child_pub_2b.marshal(&mut child_pub_buf);
    let child_pub_bytes = &child_pub_buf[..child_pub_len];

    // 1. Step 1: Import with symmetricAlg = AES with mode 0 (invalid) -> TPM_RC_VALUE (Pos5, 0x0503)
    // inSymSeed: 256 bytes (matching RSA 2048); symmetricAlg: AES (0x0006), keyBits=0, mode=0
    let req1 = import_request(
        parent_handle,
        child_pub_bytes,
        &[0u8; 256],
        &hex_checked("0006 0000 0000"),
    );
    let rc1 = raw_rc(&mut sim, &req1);
    assert_eq!(
        rc1,
        TpmRc::VALUE.with(Position::parameter(5)).get(),
        "Expected TPM_RC_VALUE (0x0503) for Import with invalid symmetricAlg"
    );

    // 2. Step 2: Import with valid symmetricAlg (Null) and invalid attributes (FixedTPM) -> TPM_RC_ATTRIBUTES (Pos2, 0x0282)
    let req2 = import_request(
        parent_handle,
        child_pub_bytes,
        &[0u8; 256],
        &hex_checked("0010"),
    );
    let rc2 = raw_rc(&mut sim, &req2);
    assert_eq!(
        rc2,
        TpmRc::ATTRIBUTES.with(Position::parameter(2)).get(),
        "Expected TPM_RC_ATTRIBUTES (0x0282) for Import with FixedTPM / SensitiveDataOrigin attributes"
    );

    // 3. Step 3: Import with inSymSeed of 512 bytes (oversized for RSA 2048) -> TPM_RC_SIZE (Pos4, 0x04D5)
    let req3 = import_request(
        parent_handle,
        child_pub_bytes,
        &[0u8; 512],
        &hex_checked("0010"),
    );
    let rc3 = raw_rc(&mut sim, &req3);
    assert_eq!(
        rc3,
        TpmRc::SIZE.with(Position::parameter(4)).get(),
        "Expected TPM_RC_SIZE (0x04D5) for Import with oversized inSymSeed"
    );
}

/// Import of duplicates with tampered outer HMAC, seeds, sizes and inner data fails with integrity/size errors (RSA and ECC parents)
#[test]
fn tampered_duplicate_blobs_rejected() {
    let mut sim = Tpm::new();

    fn is_integrity_error(rc: u32) -> bool {
        (rc & 0xBF) == 0x9F
    }

    fn is_value_or_ecc_point_error(rc: u32) -> bool {
        let err = rc & 0xBF;
        err == 0x84 || err == 0xA7 || err == 0x95 || err == 0x9F
    }

    for tc in &[
        ("ECDH-P256", get_ecc_srk_template()),
        ("RSA-2048", get_rsa_srk_template()),
    ] {
        let name = tc.0;
        let pub_template = &tc.1;
        std::println!("Running adversarial import test cases: {}", name);

        // 1. Create Primary (SRK)
        let in_public = crate::_common::make_template(pub_template);
        let create_srk_cmd = CreateLoaded {
            parent_handle: Handle(0x40000001), // TPMRH_OWNER
            in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public,
        };
        let srk_resp = execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
        let srk_handle = srk_resp.object_handle;

        let parent_public = srk_resp.out_public.0;
        let enc_key = import_encapsulation_key(&parent_public);

        let plaintext = b"secure message";
        let (sealed_pub, sealed_priv) =
            make_sealed_blob(TpmiAlgHash::Sha256, &[0u8; 32], plaintext);
        let sealed_name = compute_object_name(&sealed_pub);

        let mut rng = crate::_common::client_rng();

        // Challenge 1: Tampered outer HMAC
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            None,
            None,
            true, // tamper outer hmac
            false,
            false,
            None,
            false,
        );
        let import_cmd = Import {
            parent_handle: srk_handle,
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(&mut sim, &import_cmd, 1, &[]);
        assert!(res.is_err(), "Expected tampered outer HMAC to fail");
        let err = res.unwrap_err();
        assert!(
            is_integrity_error(err),
            "Expected TPM_RC_INTEGRITY error, got: 0x{:X}",
            err
        );

        // Challenge 2: Tampered outer ciphertext
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            None,
            None,
            false,
            true, // tamper ciphertext
            false,
            None,
            false,
        );
        let import_cmd = Import {
            parent_handle: srk_handle,
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(&mut sim, &import_cmd, 1, &[]);
        std::println!("Challenge 2 result: {:?}", res);
        assert!(res.is_err(), "Expected tampered outer ciphertext to fail");
        let err = res.unwrap_err();
        assert!(
            is_integrity_error(err),
            "Expected TPM_RC_INTEGRITY error, got: 0x{:X}",
            err
        );

        // Challenge 3: Tampered seed
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            None,
            None,
            false,
            false,
            true, // tamper seed
            None,
            false,
        );
        let import_cmd = Import {
            parent_handle: srk_handle,
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(&mut sim, &import_cmd, 1, &[]);
        assert!(res.is_err(), "Expected tampered seed to fail");
        let err = res.unwrap_err();
        assert!(
            is_value_or_ecc_point_error(err) || err == 0x01 || err == 0x101,
            "Expected seed decryption/parsing/integrity error, got: 0x{:X}",
            err
        );

        // Challenge 4: Wrong Name in HMAC
        let wrong_name = vec![0u8; sealed_name.get_size() as usize];
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            None,
            None,
            false,
            false,
            false,
            Some(&wrong_name),
            false,
        );
        let import_cmd = Import {
            parent_handle: srk_handle,
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(&mut sim, &import_cmd, 1, &[]);
        assert!(res.is_err(), "Expected wrong Name in HMAC to fail");
        let err = res.unwrap_err();
        assert!(
            is_integrity_error(err),
            "Expected TPM_RC_INTEGRITY error, got: 0x{:X}",
            err
        );

        // Challenge 5: Inner wrapper AES-128 CFB with no encryptionKey (inner key
        // "derived" from the seed). C has no such derivation: with a non-NULL
        // symmetricAlg, encryptionKey must be exactly keyBits/8 bytes, else
        // TPM_RCS_SIZE + RC_Import_encryptionKey (SIZE+P1, Import.c:99-103).
        let inner_sym_def = Some(AES128_CFB);
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            inner_sym_def,
            None, // derive inner key from seed
            false,
            false,
            false,
            None,
            false,
        );
        let import_cmd = Import {
            parent_handle: srk_handle,
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: inner_sym_def,
        };
        let res = execute_with_password_sessions(&mut sim, &import_cmd, 1, &[]);
        assert_eq!(
            res.err(),
            Some(
                tpm2::errors::TpmRc::SIZE
                    .with(tpm2::errors::Position::parameter(1))
                    .get()
            ),
            "Import with an inner wrapper but no encryptionKey must fail"
        );

        // Challenge 6: Inner wrapper AES-128 CFB (explicit inner key) - Success
        let explicit_inner_key = b"0123456789abcdef"; // 16 bytes
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            inner_sym_def,
            Some(explicit_inner_key),
            false,
            false,
            false,
            None,
            false,
        );
        let import_cmd = Import {
            parent_handle: srk_handle,
            encryption_key: Tpm2bData::from_bytes(explicit_inner_key).unwrap(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: inner_sym_def,
        };
        let import_resp = execute_with_password_sessions(&mut sim, &import_cmd, 1, &[]).unwrap();
        let load_cmd = Load {
            parent_handle: srk_handle,
            in_private: import_resp.out_private,
            in_public: tpm2::Tpm2b(sealed_pub),
        };
        let load_resp_handles =
            execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]).unwrap();
        let loaded_handle = load_resp_handles.object_handle;
        let unseal_resp = execute_with_password_sessions(
            &mut sim,
            &Unseal {
                item_handle: loaded_handle,
            },
            1,
            &[],
        )
        .unwrap();
        assert_eq!(unseal_resp.out_data.get_buffer(), plaintext);
        flush_context(&mut sim, loaded_handle).unwrap();

        // Challenge 7: Inner wrapper AES-128 CFB with tampered inner HMAC - Failure
        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            inner_sym_def,
            // C needs the inner key in encryptionKey (no seed derivation,
            // Import.c:99-103), so use the explicit key from challenge 6.
            Some(explicit_inner_key),
            false,
            false,
            false,
            None,
            true, // tamper inner hmac
        );
        let import_cmd = Import {
            parent_handle: srk_handle,
            encryption_key: Tpm2bData::from_bytes(explicit_inner_key).unwrap(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: inner_sym_def,
        };
        let res = execute_with_password_sessions(&mut sim, &import_cmd, 1, &[]);
        assert!(res.is_err(), "Expected tampered inner HMAC to fail");
        let err = res.unwrap_err();
        assert!(
            is_integrity_error(err),
            "Expected TPM_RC_INTEGRITY error, got: 0x{:X}",
            err
        );

        // Challenge 8: Wrong Parental Key Attributes - Failure
        let sign_parent_pub = TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SIGN_ENCRYPT, // lacks RESTRICTED and DECRYPT
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                TpmsEccParms {
                    symmetric: None,
                    scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                TpmsEccPoint {
                    x: Tpm2bEccParameter::default(),
                    y: Tpm2bEccParameter::default(),
                },
            ),
        };
        let in_public_sign = crate::_common::make_template(&sign_parent_pub);
        let create_sign_parent_cmd = CreateLoaded {
            parent_handle: Handle(0x40000001),
            in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: in_public_sign,
        };
        let sign_parent_handles =
            execute_with_password_sessions(&mut sim, &create_sign_parent_cmd, 1, &[]).unwrap();
        let sign_parent_handle = sign_parent_handles.object_handle;

        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &sealed_priv,
            None,
            None,
            false,
            false,
            false,
            None,
            false,
        );
        let import_cmd = Import {
            parent_handle: sign_parent_handle,
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(&mut sim, &import_cmd, 1, &[]);
        assert!(
            res.is_err(),
            "Expected Import to fail with parent lacking DECRYPT/RESTRICTED"
        );
        let err = res.unwrap_err();
        // C Import.c: a parent that is not a storage parent is rejected with
        // TPM_RCS_TYPE + RC_Import_parentHandle (TYPE+H1, 0x18A).
        assert_eq!(
            err, 0x18a,
            "Expected Type error for Handle 1 (0x18A), got 0x{:03X}",
            err
        );

        flush_context(&mut sim, sign_parent_handle).unwrap();

        // Challenge 9: Mismatched Key Type (Type mismatch) - Failure
        let ecc_sensitive = TpmtSensitive {
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap(),
            sensitive: TpmuSensitiveComposite::Ecc(
                Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
            ),
        };
        let mut ecc_sens_buf = vec![0u8; 1024];
        let ecc_sens_len = marshal_to_slice(&ecc_sensitive, &mut ecc_sens_buf);
        ecc_sens_buf.truncate(ecc_sens_len);

        let (dup_bytes, enc_seed) = create_duplicate_challenged(
            &mut rng,
            &enc_key,
            sealed_name.get_buffer(),
            &ecc_sens_buf, // mismatched sensitive area
            None,
            None,
            false,
            false,
            false,
            None,
            false,
        );
        let import_cmd = Import {
            parent_handle: srk_handle,
            encryption_key: Tpm2bData::default(),
            object_public: tpm2::Tpm2b(sealed_pub),
            duplicate: Tpm2bPrivate::from_bytes(&dup_bytes).unwrap(),
            in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&enc_seed).unwrap(),
            symmetric_alg: None,
        };
        let res = execute_with_password_sessions(&mut sim, &import_cmd, 1, &[]);
        assert!(
            res.is_err(),
            "Expected Import to fail with mismatched key type"
        );
        let err = res.unwrap_err();
        assert_eq!(
            err, 0x3CA,
            "Expected Type error for Parameter 3 (0x3CA), got 0x{:03X}",
            err
        );

        // Cleanup
        flush_context(&mut sim, srk_handle).unwrap();
    }
}
