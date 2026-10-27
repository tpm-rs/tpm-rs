//! TPM2_Create validation: parent handles, object attributes, schemes, name algorithms and creation
//! PCRs.

#![allow(deprecated)] // TPM2_CreateLoaded is deprecated upstream but still implemented.

use crate::_common::{
    AES128_CFB, command_rc, create, create_ecc_parent_key, create_owner_primary, create_parent,
    create_parent_key, ecc_sign_template, ecc_storage_template_with, empty_password_auth,
    empty_sensitive, execute_tpm_command_offsets, execute_tpm_command_uncorrupted,
    execute_tpm_command_with_corrupted_bytes, execute_with_password_sessions, finish,
    get_ecc_signing_key_template, get_ecc_template, get_test_template, hash_parts, leak_bytes,
    load, make_template, owner_srk, rc_h, rc_p, rsa_storage_template_with, run, run_raw,
    sealed_template, sensitive_create, sym_template_with, try_create_primary_in,
};
use testing::tpm::Tpm;
use tpm2::commands::{Create, CreateLoaded, CreatePrimary, ObjectChangeAuth};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Marshal, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPrivate,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits,
    TpmlPcrSelection, TpmsAuthCommand, TpmsPcrSelection, TpmsRsaParms, TpmsSensitiveCreate,
    TpmtEccScheme, TpmtKeyedHashScheme, TpmtPublic,
};

/// Create of an ECC child under a primary parent succeeds.
#[test]
fn create_child_under_primary() {
    let mut sim = Tpm::new();
    let parent_handle = create_parent_key(&mut sim);
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let pub_area = get_ecc_template();
    let in_public = tpm2::Tpm2b(pub_area);
    let cmd = Create {
        parent_handle,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert!(res.is_ok(), "Create failed: {:?}", res.err());
}

/// Create with TPM_RH_OWNER as parent fails with VALUE+H1 (permanent handles are not TPMI_DH_OBJECT).
#[test]
fn create_rejects_permanent_parent_handle() {
    let mut sim = Tpm::new();
    let rc = create(
        &mut sim,
        Handle::RH_OWNER,
        ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, rc_h(TpmRc::VALUE, 1));
}

/// TPM2_Create with TPM_RH_OWNER as parent fails.
#[test]
fn create_with_hierarchy_parent_rejected() {
    let mut sim = Tpm::new();

    // Create a key under TPM_RH_OWNER using Create (should fail)
    let sealed_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sealed_sensitive);
    let sealed_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    };
    let in_public = tpm2::Tpm2b(sealed_public);
    let create_cmd = Create {
        parent_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let res = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]);

    assert!(
        res.is_err(),
        "Create with a hierarchy parent handle should have failed but succeeded!"
    );
}

/// Create under a non-existent parent fails with REFERENCE_H0.
#[test]
fn create_with_unloaded_parent_fails() {
    let mut sim = Tpm::new();
    let t_sens = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let in_public = tpm2::Tpm2b(get_ecc_template());
    let cmd = Create {
        parent_handle: Handle::TRANSIENT_LAST, // non-existent transient handle
        in_sensitive: t_sens,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    // Should return ReferenceH0 error since parent doesn't exist
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));
}

/// Create accepts a SHA-1/SHA-512 creationPCR; unallocated banks are filtered and pcrDigest is the empty hash.
#[test]
fn creation_pcr_filters_unallocated_banks() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let selection = TpmlPcrSelection::from_slice(&[
        TpmsPcrSelection::new(TpmiAlgHash::Sha1, &[0x01, 0x00, 0x00]).unwrap(),
        TpmsPcrSelection::new(TpmiAlgHash::Sha512, &[0x01, 0x00, 0x00]).unwrap(),
    ])
    .unwrap();
    let cmd = Create {
        parent_handle: srk,
        in_sensitive: sensitive_create(&[], b"x"),
        in_public: Tpm2b(sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty())),
        outside_info: Tpm2bData::default(),
        creation_pcr: selection,
    };
    let rsp = run(&mut sim, &cmd, 1).expect("SHA-512 creationPCR must be accepted");
    let creation = rsp.creation_data.0;
    // Both banks are unallocated by default: their bits are filtered out and nothing is hashed.
    for sel in creation.pcr_select.pcr_selections() {
        assert!(
            sel.pcr_select().iter().all(|&b| b == 0),
            "unfiltered selection: {sel:?}"
        );
    }
    assert_eq!(
        creation.pcr_digest.get_buffer(),
        hash_parts(TpmiAlgHash::Sha256, &[]).as_slice()
    );
}

/// Create with fixedTPM but not fixedParent fails with ATTRIBUTES+P2.
#[test]
fn fixed_tpm_without_fixed_parent_rejected() {
    let mut sim = Tpm::new();
    let parent_handle = create_parent_key(&mut sim);
    let t_sens = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let mut pub_area = get_ecc_template();
    // fixedTPM without fixedParent (violates TPM rules)
    pub_area.object_attributes = TpmaObject::FIXED_TPM;
    let in_public = tpm2::Tpm2b(pub_area);
    let cmd = Create {
        parent_handle,
        in_sensitive: t_sens,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    // Should fail with Attributes error for Parameter 2 (inPublic)
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get())
    );
}

/// Create with RH_OWNER as parent is TPM_RC_VALUE + RC_H1 (parentHandle is TPMI_DH_OBJECT)
#[test]
fn hierarchy_parent_rejected() {
    let mut sim = Tpm::new();

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let pub_area = get_ecc_signing_key_template();
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = Create {
        parent_handle: Handle::RH_OWNER, // Hierarchy handle!
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    // parentHandle is TPMI_DH_OBJECT, so C rejects RH_OWNER at handle unmarshal
    // with TPM_RC_VALUE + H1 (0x184).
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get()),
        "BUG: Create succeeded (or failed with wrong error) when using RH_OWNER directly as parent!"
    );
}

/// Create keyedHash with an HMAC scheme using a non-hash alg -> HASH + P2; decrypt-only with HMAC -> SCHEME + P2 (TC2_2_14_01_06).
///
/// Regression test for CPCTPM_TC2_2_14_01_06:
/// TPM2_Create for a KeyedHash object specifying an unsupported hash algorithm (TPM_ALG_AES = 0x0006) in HMAC scheme
/// must return TPM_RC_HASH (Parameter 2, 0x02C3), and KeyedHash with Decrypt only rejecting HMAC scheme
/// must return TPM_RC_SCHEME (Parameter 2, 0x02D9).
#[test]
fn keyed_hash_invalid_scheme() {
    let mut sim = Tpm::new();

    // Create Primary object under Owner hierarchy first
    let primary_obj_handle = create_owner_primary(&mut sim, get_test_template());
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };

    // 1. Create KeyedHash with HMAC scheme where hashAlg = TPM_ALG_AES (0x0006)
    let keyed_hash_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            tpm2::Tpm2bDigest::default(),
        ),
    };
    let child_create_cmd = tpm2::commands::Create {
        parent_handle: primary_obj_handle,
        in_sensitive: tpm2::Tpm2b(t_sens),
        in_public: tpm2::Tpm2b(keyed_hash_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let err = execute_tpm_command_with_corrupted_bytes::<tpm2::commands::Create>(
        &mut sim,
        &child_create_cmd,
        &[empty_password_auth()],
        |payload| {
            // Find scheme hashAlg in in_public payload (0x0005 0x000B) and replace 0x000B with TPM_ALG_AES (0x0006)
            for i in 0..payload.len().saturating_sub(3) {
                if payload[i..i + 2] == [0x00, 0x05] && payload[i + 2..i + 4] == [0x00, 0x0B] {
                    payload[i + 2] = 0x00;
                    payload[i + 3] = 0x06;
                    break;
                }
            }
        },
    )
    .unwrap_err();
    assert_eq!(
        err,
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Expected TPM_RC_HASH (0x02C3) for Create KeyedHash with invalid HMAC hash algorithm"
    );

    // 2. Create KeyedHash with Decrypt only (no Sign) and HMAC scheme -> TPM_RC_SCHEME (Pos2, 0x02D9)
    let decrypt_hmac_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            tpm2::Tpm2bDigest::default(),
        ),
    };
    let decrypt_hmac_cmd = tpm2::commands::Create {
        parent_handle: primary_obj_handle,
        in_sensitive: tpm2::Tpm2b(t_sens),
        in_public: tpm2::Tpm2b(decrypt_hmac_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let err2 =
        execute_tpm_command_uncorrupted(&mut sim, &decrypt_hmac_cmd, &[empty_password_auth()])
            .unwrap_err();
    assert_eq!(
        err2,
        TpmRc::SCHEME.with(Position::parameter(2)).get(),
        "Expected TPM_RC_SCHEME (0x02D9) for Create KeyedHash decrypt-only object with HMAC scheme"
    );
}

/// Create under a non-existent transient parent handle fails
#[test]
fn missing_transient_parent_rejected() {
    let mut sim = Tpm::new();

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let pub_area = get_ecc_signing_key_template();
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = Create {
        parent_handle: Handle::TRANSIENT_LAST, // Unloaded transient handle
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert!(
        res.is_err(),
        "BUG: Create succeeded with invalid parent handle!"
    );
}

/// Create under a parent that is not a decrypt (storage) key fails
#[test]
fn non_decrypt_parent_rejected() {
    let mut sim = Tpm::new();

    // 1. Create a non-decrypt key under Owner
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let pub_area = get_ecc_signing_key_template();
    let in_public_template = make_template(&pub_area);

    let load_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_template,
    };
    let load_rsp = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]).unwrap();
    let bad_parent_handle = load_rsp.object_handle;

    // 2. Try to create a new key under this non-decrypt parent
    let in_public = tpm2::Tpm2b(pub_area);
    let cmd = Create {
        parent_handle: bad_parent_handle,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert!(
        res.is_err(),
        "BUG: Create succeeded using a non-decrypt / non-parent key as parent!"
    );
}

/// A raw TPM2_Create with public type TPM_ALG_NULL fails with TPM_RC_TYPE.
#[test]
fn null_public_type_rejected() {
    let mut sim = Tpm::new();

    let parent_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
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
    let cp_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: empty_sensitive(),
        in_public: tpm2::Tpm2b(parent_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let cp_resp = execute_tpm_command_offsets(&mut sim, &cp_cmd, &[empty_password_auth()]).unwrap();

    let parent_handle = cp_resp.object_handle;
    // Build TPM2_Create request
    let mut raw_req = Vec::new();
    raw_req.extend_from_slice(&0x8002u16.to_be_bytes()); // TPM_ST_SESSIONS
    raw_req.extend_from_slice(&0u32.to_be_bytes()); // placeholder size
    raw_req.extend_from_slice(&0x00000153u32.to_be_bytes()); // TPM_CC_Create (0x153)
    raw_req.extend_from_slice(&parent_handle.0.to_be_bytes()); // parentHandle

    // Auth session (Password session: handle 0x40000009, nonce 0, attrs 0, auth 0)
    let auth = TpmsAuthCommand {
        session_handle: tpm2::Handle(0x40000009),
        nonce: Tpm2bDigest::default(),
        session_attributes: tpm2::TpmaSession(0),
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_buf = [0u8; TpmsAuthCommand::MAX_SIZE];
    let auth_len = auth.marshal(&mut auth_buf);
    raw_req.extend_from_slice(&(auth_len as u32).to_be_bytes());
    raw_req.extend_from_slice(&auth_buf[..auth_len]);

    // inSensitive: TPM2B_SENSITIVE_CREATE (size = 4, userAuth = 0, data = 0)
    raw_req.extend_from_slice(&4u16.to_be_bytes()); // size of sensitive data
    raw_req.extend_from_slice(&0u16.to_be_bytes()); // userAuth size
    raw_req.extend_from_slice(&0u16.to_be_bytes()); // data size

    // inPublic: TPM2B_PUBLIC with type = TPM_ALG_NULL (0x0010), nameAlg = SHA1 (0x0004), attrs = Sign (0x00040000), policy = 0, params...
    let mut pub_body = Vec::new();
    pub_body.extend_from_slice(&0x0010u16.to_be_bytes()); // type = TPM_ALG_NULL
    pub_body.extend_from_slice(&0x0004u16.to_be_bytes()); // nameAlg = SHA1
    pub_body.extend_from_slice(&0x00040000u32.to_be_bytes()); // objectAttributes = Sign
    pub_body.extend_from_slice(&0u16.to_be_bytes()); // authPolicy size = 0
    pub_body.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric = NULL
    pub_body.extend_from_slice(&0x0018u16.to_be_bytes()); // scheme = ECDSA
    pub_body.extend_from_slice(&0x0004u16.to_be_bytes()); // scheme hash = SHA1
    pub_body.extend_from_slice(&0x0003u16.to_be_bytes()); // curveID = NIST_P256
    pub_body.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf = NULL
    pub_body.extend_from_slice(&0u16.to_be_bytes()); // unique x size = 0
    pub_body.extend_from_slice(&0u16.to_be_bytes()); // unique y size = 0

    raw_req.extend_from_slice(&(pub_body.len() as u16).to_be_bytes());
    raw_req.extend_from_slice(&pub_body);

    // outsideInfo: TPM2B_DATA (size = 0)
    raw_req.extend_from_slice(&0u16.to_be_bytes());

    // creationPCR: TPML_PCR_SELECTION (count = 0)
    raw_req.extend_from_slice(&0u32.to_be_bytes());

    let resp = run_raw(&mut sim, &finish(raw_req));
    let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    assert_eq!(
        rc,
        TpmRc::TYPE.with(Position::parameter(2)).get(),
        "Expected TPM_RC_TYPE at Pos2 (0x28A), got 0x{:03X}",
        rc
    );
}

/// Create/CreatePrimary SchemeChecks: sealed scheme, keyedhash NULL scheme, decrypt symmetric, storage symmetric, fixedParent nameAlg, dual-use scheme.
#[test]
fn object_attribute_and_scheme_consistency_checks() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let p2 = |rc| rc_p(rc, 2);

    // Sealed data object with a non-NULL scheme.
    let mut t = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.parms_and_id = PublicParmsAndId::KeyedHash(
        Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        Tpm2bDigest::default(),
    );
    assert_eq!(
        create(&mut sim, srk, t, &[], b"x").unwrap_err(),
        p2(TpmRc::SCHEME)
    );

    // KEYEDHASH signing key with a NULL scheme.
    let mut t = sealed_template(
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::SENSITIVE_DATA_ORIGIN,
    );
    t.parms_and_id = PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default());
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::SCHEME)
    );

    // Unrestricted RSA decryption key with a symmetric algorithm.
    let mut t = rsa_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.object_attributes.remove(TpmaObject::RESTRICTED);
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::SYMMETRIC)
    );

    // Storage parent without a symmetric algorithm.
    let mut t = ecc_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty());
    if let PublicParmsAndId::Ecc(parms, _) = &mut t.parms_and_id {
        parms.symmetric = None;
    }
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::SYMMETRIC)
    );

    // A fixedParent storage child must use its parent's nameAlg.
    let t = ecc_storage_template_with(
        TpmiAlgHash::Sha384,
        TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
    );
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::HASH)
    );

    // Dual-use asymmetric key with a scheme.
    let mut t = ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::DECRYPT);
    assert!(matches!(t.parms_and_id, PublicParmsAndId::Ecc(..)));
    if let PublicParmsAndId::Ecc(parms, _) = &mut t.parms_and_id {
        parms.scheme = Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256));
    }
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::SCHEME)
    );

    // A sealed data object can not have sensitiveDataOrigin SET.
    let t = sealed_template(TpmiAlgHash::Sha256, TpmaObject::SENSITIVE_DATA_ORIGIN);
    assert_eq!(
        create(&mut sim, srk, t, &[], &[]).unwrap_err(),
        p2(TpmRc::ATTRIBUTES)
    );

    // A SYMCIPHER decryption key may use the NULL mode.
    let mut t = sym_template_with(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.parms_and_id = PublicParmsAndId::Sym(AES128_CFB.with_mode(None), Tpm2bDigest::default());
    create(&mut sim, srk, t, &[], &[]).expect("SYMCIPHER decrypt key with NULL mode");

    // A primary object with sensitiveDataOrigin may get inSensitive.data (extra KDF input).
    try_create_primary_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_sign_template(
            TpmiAlgHash::Sha256,
            TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
        ),
        b"entropy",
    )
    .expect("primary with sensitiveDataOrigin and data");
}

/// Create/Load/ObjectChangeAuth reject permanent parent handles; a corrupted outer integrity on Load is INTEGRITY+P1.
#[test]
fn permanent_parent_and_corrupted_private_rejected() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let child = create(
        &mut sim,
        srk,
        sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        b"s",
    )
    .unwrap();

    // Permanent parent handles are invalid TPMI_DH_OBJECT values.
    assert_eq!(
        create(
            &mut sim,
            Handle::RH_OWNER,
            sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
            &[],
            b"s"
        )
        .unwrap_err(),
        rc_h(TpmRc::VALUE, 1)
    );
    assert_eq!(
        load(
            &mut sim,
            Handle::RH_OWNER,
            child.out_private,
            child.out_public
        )
        .unwrap_err(),
        rc_h(TpmRc::VALUE, 1)
    );
    let rc = command_rc(
        &mut sim,
        &ObjectChangeAuth {
            object_handle: srk,
            parent_handle: Handle::RH_OWNER,
            new_auth: Tpm2bAuth::from_bytes(b"new").unwrap(),
        },
        1,
    );
    assert_eq!(rc, rc_h(TpmRc::VALUE, 2));

    // A corrupted outer integrity value is TPM_RC_INTEGRITY + RC_P1 (RC_Load_inPrivate).
    let mut blob = child.out_private.get_buffer().to_vec();
    blob[5] ^= 0xff;
    let corrupted = Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap();
    assert_eq!(
        load(&mut sim, srk, corrupted, child.out_public).unwrap_err(),
        rc_p(TpmRc::INTEGRITY, 1)
    );
}

/// Create of an RSA child with both SIGN_ENCRYPT and DECRYPT (NULL scheme) is checked for TPM_RC_ATTRIBUTES rules.
#[test]
fn rsa_sign_and_decrypt_with_null_scheme() {
    let mut sim = Tpm::new();

    // 1. Create a primary parent key
    let parent_handle = create_parent(&mut sim);

    // 2. Create child key under parent with both SIGN_ENCRYPT and DECRYPT set on RSA (scheme=TPM_ALG_NULL)
    let child_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::DECRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
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
    let create_cmd = Create {
        parent_handle,
        in_sensitive: empty_sensitive(),
        in_public: tpm2::Tpm2b(child_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let res = execute_tpm_command_offsets(&mut sim, &create_cmd, &[empty_password_auth()]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get()),
        "TPM2_Create with both sign and decrypt set on RSA must fail with TPM_RC_ATTRIBUTES at Pos2"
    );
}

/// Create with an unsupported nameAlg fails with HASH+P2.
#[test]
fn unsupported_ecc_child_name_alg_rejected() {
    let mut sim = Tpm::new();
    let parent_handle = create_parent_key(&mut sim);
    let t_sens = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let mut pub_area = get_ecc_template();
    pub_area.name_alg = Some(TpmiAlgHash::Sm3_256); // unsupported hash alg for name
    let in_public = tpm2::Tpm2b(pub_area);
    let cmd = Create {
        parent_handle,
        in_sensitive: t_sens,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    // C TPMI_ALG_HASH unmarshal of nameAlg in inPublic returns TPM_RC_HASH,
    // reported as HASH+P2 (0x2C3).
    assert_eq!(
        res.err(),
        Some(TpmRc::HASH.with(tpm2::errors::Position::parameter(2)).get())
    );
}

/// Create with nameAlg SM3-256 fails with TPM_RC_HASH + RC_P2
#[test]
fn unsupported_name_alg_rejected() {
    let mut sim = Tpm::new();
    let parent_handle = create_ecc_parent_key(&mut sim);

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let mut pub_area = get_ecc_signing_key_template();
    pub_area.name_alg = Some(TpmiAlgHash::Sm3_256); // unsupported hash alg for name!
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = Create {
        parent_handle,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    // C TPMI_ALG_HASH unmarshal of nameAlg in inPublic returns TPM_RC_HASH,
    // reported as HASH+P2 (0x2C3).
    assert_eq!(
        res.err(),
        Some(TpmRc::HASH.with(tpm2::errors::Position::parameter(2)).get()),
        "BUG: Create succeeded (or failed with wrong error) with unsupported name alg SM3256!"
    );
}

/// A malformed `inSensitive` (parameter 1, inner `data` size beyond the buffer) is reported as
/// `TPM_RC_SIZE + P1` even when `inPublic` (parameter 2) is invalid as well: the parameters are
/// unmarshaled in order. TPM 2.0 Part 3, "Unmarshaling Errors": "When an error is encountered
/// while unmarshaling a command parameter, an error response code is returned, and no command
/// processing occurs." Found by differential fuzzing.
#[test]
fn malformed_in_sensitive_reported_before_in_public() {
    let mut tpm = testing::tpm::Tpm::new();
    let steps: [(&str, u32); 2] = [
        (
            concat!(
                "800200000043000001314000000100000009400000090000010000000400000000001a0023000b000300720000000600",
                "80004300100003001000000000000000000000",
            ),
            0x000,
        ),
        (
            concat!(
                "800200000048000001538000000000000009400000090000010000000b0007000081000401002d000b00076f6c646175",
                "7468000000180001000b00040072000000106f6c64617574",
            ),
            0x1d5,
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

/// TPM2_Create of an RSA key with an unsupported public exponent fails at key generation with
/// `TPM_RC_RANGE` (see `create_primary_validation::unsupported_rsa_exponent_fails_key_generation_with_range`).
/// Found by differential fuzzing.
#[test]
fn unsupported_rsa_exponent_fails_child_key_generation_with_range() {
    let mut tpm = testing::tpm::Tpm::new();
    let steps: [(&str, u32); 2] = [
        (
            concat!(
                "800200000043000001314000000100000009400000090000010000000400000000001a0023000b000300720000000600",
                "80004300100003001000000000000000000000",
            ),
            0x000,
        ),
        (
            concat!(
                "80020000005f00000153800000000000000940000009000000000000040000000000360001000b000400600020bef56b",
                "8c1cc84e11edd717528d2cd99356bd2bbf8f015209c3f84aeeaba8e8a200100010080000003a300000000000000000",
            ),
            0x08d,
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
