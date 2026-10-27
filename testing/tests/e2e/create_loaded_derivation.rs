//! TPM2_CreateLoaded with derivation parents and primary-seed derivation (label/context, template
//! binding).

use crate::_common::{
    create_and_load, derivation_parent_template, ecc_point, ecc_sign_template,
    execute_with_password_sessions, flush_context, make_derive_template, make_template,
    marshal_to_slice, owner_srk, run, sensitive_create, try_create_primary_in,
};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::CreateLoaded;
use tpm2::{
    AlgSym, Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bLabel,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bTemplate, TpmEccCurve, TpmaObject,
    TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmsDerive, TpmsEccParms, TpmsEccPoint,
    TpmsRsaParms, TpmsSensitiveCreate, TpmtKeyedHashScheme, TpmtPublic, TpmtRsaScheme,
    TpmtSymDefObject,
};

/// A derived ECC template with an extra appended TPM2B_LABEL (IBM TSS format) fails with SIZE + P2.
#[test]
#[allow(deprecated)]
fn derived_ecc_with_appended_label_rejected() {
    let mut sim = Tpm::new();

    // Create deriver
    let deriver_pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::ExclusiveOr(tpm2::TpmsSchemeXor {
                hash_alg: TpmiAlgHash::Sha256,
                kdf: Some(tpm2::TpmiAlgKdf::Kdf1Sp800_108),
            })),
            Tpm2bDigest::default(),
        ),
    };
    let deriver_in_public = make_template(&deriver_pub_area);
    let deriver_cmd = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: deriver_in_public,
    };
    let deriver_rsp_handles =
        execute_with_password_sessions(&mut sim, &deriver_cmd, 1, &[]).unwrap();

    // Create derived ECC key using IBM TSS TSS_TPMT_PUBLIC_D_Marshal wire format:
    // TPMT_PUBLIC with unique.ecc.x = label, unique.ecc.y = empty, followed by appended TPM2B_LABEL context.
    let tpms_derive = TpmsDerive {
        label: Tpm2bLabel::from_bytes(b"label").unwrap(),
        context: Tpm2bLabel::from_bytes(b"context").unwrap(),
    };
    let mut derive_buf = [0u8; 1024];
    let derive_len = marshal_to_slice(&tpms_derive, &mut derive_buf);

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"p@ssw0rd").unwrap(),
        data: Tpm2bSensitiveData::from_bytes(&derive_buf[..derive_len]).unwrap(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    // 1. ECC template with a 3rd appended TPM2B_LABEL after TPMS_ECC_POINT (which already has 2 TPM2Bs: x and y)
    // has trailing bytes after TPMS_DERIVE and must be rejected with TPM_RC_SIZE + TPM_RC_P + TPM_RC_2.
    let pub_area_empty_y = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(b"label").unwrap(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let mut pub_bytes = [0u8; 1024];
    let pub_len = marshal_to_slice(&pub_area_empty_y, &mut pub_bytes);

    let context_label = Tpm2bLabel::from_bytes(b"context").unwrap();
    let mut context_bytes = [0u8; 64];
    let context_len = marshal_to_slice(&context_label, &mut context_bytes);

    let mut template_buffer = [0u8; 1024];
    template_buffer[..pub_len].copy_from_slice(&pub_bytes[..pub_len]);
    template_buffer[pub_len..pub_len + context_len].copy_from_slice(&context_bytes[..context_len]);
    let total_template_len = pub_len + context_len;

    let bad_in_public = Tpm2bTemplate::from_bytes(&template_buffer[..total_template_len]).unwrap();
    let bad_cmd = CreateLoaded {
        parent_handle: deriver_rsp_handles.object_handle,
        in_sensitive,
        in_public: bad_in_public,
    };
    let err = execute_with_password_sessions(&mut sim, &bad_cmd, 1, &[]).unwrap_err();
    assert_eq!(
        err,
        tpm2::errors::TpmRc::SIZE
            .with(tpm2::errors::Position::parameter(2))
            .get(),
        "ECC derivation template with trailing 3rd TPM2B_LABEL must fail with TPM_RC_SIZE + P2"
    );

    // 2. Valid ECC derivation template has x = label and y = context (exactly 2 TPM2Bs = TPMS_DERIVE).
    let valid_ecc_pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(b"label").unwrap(),
                y: Tpm2bEccParameter::from_bytes(b"context").unwrap(),
            },
        ),
    };
    let valid_in_public = make_template(&valid_ecc_pub_area);
    let valid_cmd = CreateLoaded {
        parent_handle: deriver_rsp_handles.object_handle,
        in_sensitive,
        in_public: valid_in_public,
    };
    let derived_rsp_handles = execute_with_password_sessions(&mut sim, &valid_cmd, 1, &[]).unwrap();

    // Flush derived key
    flush_context(&mut sim, derived_rsp_handles.object_handle).unwrap();

    // Flush deriver
    flush_context(&mut sim, deriver_rsp_handles.object_handle).unwrap();
}

/// CreateLoaded under derivation parents derives from the parent sensitive bits, not its random seedValue.
#[test]
#[allow(deprecated)]
fn derived_key_uses_parent_sensitive_bits() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    // Two derivation parents with the same sensitive bits (but different random seeds).
    let parent_t = derivation_parent_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    let derived = |sim: &mut Tpm, parent: Handle| {
        let child = ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::FIXED_PARENT);
        let mut child = child;
        child
            .object_attributes
            .remove(TpmaObject::SENSITIVE_DATA_ORIGIN);
        let template = make_derive_template(
            &child,
            &TpmsDerive {
                label: Tpm2bLabel::from_bytes(b"label").unwrap(),
                context: Tpm2bLabel::from_bytes(b"context").unwrap(),
            },
        );
        let rsp = run(
            sim,
            &CreateLoaded {
                parent_handle: parent,
                in_sensitive: sensitive_create(&[], &[]),
                in_public: template,
            },
            1,
        )
        .expect("derived CreateLoaded");
        flush_context(sim, rsp.object_handle).unwrap();
        ecc_point(&rsp.out_public.0)
    };
    // Each parent is flushed before the next one is loaded, so that the SRK, one parent and its
    // derived child fit into the TPM's object slots.
    let (p1, _) = create_and_load(&mut sim, srk, parent_t, &[], &[0x77; 32]);
    let from_p1 = derived(&mut sim, p1);
    flush_context(&mut sim, p1).unwrap();
    let (p2, _) = create_and_load(&mut sim, srk, parent_t, &[], &[0x77; 32]);
    let from_p2 = derived(&mut sim, p2);
    flush_context(&mut sim, p2).unwrap();
    // The derivation secret is the parent's sensitive bits, not its seedValue.
    assert_eq!(from_p1, from_p2);
}

/// Derived keyed-hash/symmetric children merge label/context per SetLabelAndContext; invalid derivations are rejected.
#[test]
#[allow(deprecated)]
fn derived_keyedhash_label_context_precedence() {
    let mut sim = Tpm::new();

    // 1. Create derivation parent (KeyedHash with XOR scheme + KDF1_SP800_108)
    let deriver_pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::ExclusiveOr(tpm2::TpmsSchemeXor {
                hash_alg: TpmiAlgHash::Sha256,
                kdf: Some(tpm2::TpmiAlgKdf::Kdf1Sp800_108),
            })),
            Tpm2bDigest::default(),
        ),
    };
    let deriver_cmd = CreateLoaded {
        parent_handle: Handle(0x40000001),
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: make_template(&deriver_pub_area),
    };
    let deriver_handles = execute_with_password_sessions(&mut sim, &deriver_cmd, 1, &[]).unwrap();
    let parent_handle = deriver_handles.object_handle;

    // 2. Derive a KeyedHash child where `inPublic` (`TPM2B_TEMPLATE`) contains `TPMS_DERIVE` (label + context)
    let pub_derive = TpmsDerive {
        label: Tpm2bLabel::from_bytes(b"pub_label").unwrap(),
        context: Tpm2bLabel::from_bytes(b"pub_context").unwrap(),
    };
    let kh_pub_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::default(),
        ),
    };
    let kh_cmd = CreateLoaded {
        parent_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: make_derive_template(&kh_pub_template, &pub_derive),
    };
    let kh_rsp = execute_with_password_sessions(&mut sim, &kh_cmd, 1, &[]).unwrap();

    // 3. Test `SetLabelAndContext` precedence (`Object_spt.c:1552-1584`):
    // - `inPublic` has `label = "pub_label"`, `context = ""` (empty)
    // - `inSensitive.data` has `label = "ignored_sens_label"`, `context = "pub_context"`
    // The merged label/context MUST be `("pub_label", "pub_context")`, producing the exact same derived key & unique!
    let partial_pub_derive = TpmsDerive {
        label: Tpm2bLabel::from_bytes(b"pub_label").unwrap(),
        context: Tpm2bLabel::default(),
    };
    let sens_derive = TpmsDerive {
        label: Tpm2bLabel::from_bytes(b"ignored_sens_label").unwrap(),
        context: Tpm2bLabel::from_bytes(b"pub_context").unwrap(),
    };
    let mut sens_derive_buf = [0u8; 128];
    let sens_derive_len = marshal_to_slice(&sens_derive, &mut sens_derive_buf);
    let kh_merged_cmd = CreateLoaded {
        parent_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(&sens_derive_buf[..sens_derive_len]).unwrap(),
        }),
        in_public: make_derive_template(&kh_pub_template, &partial_pub_derive),
    };
    let kh_merged_rsp = execute_with_password_sessions(&mut sim, &kh_merged_cmd, 1, &[]).unwrap();
    assert_eq!(
        kh_rsp.out_public.0.parms_and_id, kh_merged_rsp.out_public.0.parms_and_id,
        "SetLabelAndContext must merge non-empty label from inPublic with fallback context from inSensitive.data"
    );
    // Free the object slots of both keyed-hash children for the next derivations.
    flush_context(&mut sim, kh_rsp.object_handle).unwrap();
    flush_context(&mut sim, kh_merged_rsp.object_handle).unwrap();

    // 4. Derive a Symmetric (AES-128 CFB) child under the derivation parent
    let sym_pub_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
            },
            Tpm2bDigest::default(),
        ),
    };
    let sym_cmd = CreateLoaded {
        parent_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: make_derive_template(&sym_pub_template, &pub_derive),
    };
    let sym_handles = execute_with_password_sessions(&mut sim, &sym_cmd, 1, &[]).unwrap();

    // 5. Reject deriving an RSA key under a derivation parent with `TPM_RC_TYPE + P2` (`CreateLoaded.c:108-109`)
    let rsa_pub_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let rsa_cmd = CreateLoaded {
        parent_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: make_derive_template(&rsa_pub_template, &pub_derive),
    };
    let rsa_err = execute_with_password_sessions(&mut sim, &rsa_cmd, 1, &[]).unwrap_err();
    assert_eq!(
        rsa_err,
        tpm2::errors::TpmRc::TYPE
            .with(tpm2::errors::Position::parameter(2))
            .get(),
        "Deriving RSA key under derivation parent must fail with TPM_RC_TYPE + P2"
    );

    // 6. Reject ECC derivation template whose label exceeds 32 bytes (`TPM2_LABEL_MAX_BUFFER`)
    // with `TPM_RC_SIZE + P2` (even though 33 bytes is valid for `Tpm2bEccParameter`).
    let ecc_oversized_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&[0x41; 33]).unwrap(),
                y: Tpm2bEccParameter::from_bytes(b"ctx").unwrap(),
            },
        ),
    };
    let ecc_oversized_cmd = CreateLoaded {
        parent_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: make_template(&ecc_oversized_pub),
    };
    let ecc_size_err =
        execute_with_password_sessions(&mut sim, &ecc_oversized_cmd, 1, &[]).unwrap_err();
    assert_eq!(
        ecc_size_err,
        tpm2::errors::TpmRc::SIZE
            .with(tpm2::errors::Position::parameter(2))
            .get(),
        "ECC derivation template with >32 byte label must fail with TPM_RC_SIZE + P2"
    );

    // Flush the remaining created handles
    for handle in [sym_handles.object_handle, parent_handle] {
        flush_context(&mut sim, handle).unwrap();
    }
}

/// CreatePrimary is deterministic per template but bound to the whole template and inSensitive.data; CreateLoaded on a hierarchy derives the same key.
#[test]
#[allow(deprecated)]
fn primary_derivation_bound_to_template_and_sensitive() {
    let mut sim = Tpm::new();
    let plain = ecc_sign_template(
        TpmiAlgHash::Sha256,
        TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
    );
    let mut with_policy = plain;
    with_policy
        .object_attributes
        .remove(TpmaObject::USER_WITH_AUTH);
    with_policy.auth_policy = Tpm2bDigest::from_bytes(&[0x42; 32]).unwrap();

    let key = |sim: &mut Tpm, t: TpmtPublic<'static>, data: &[u8]| {
        let (h, rsp) = try_create_primary_in(sim, Handle::RH_OWNER, t, data).unwrap();
        flush_context(sim, h).unwrap();
        ecc_point(&rsp.out_public.0)
    };
    let a = key(&mut sim, plain, &[]);
    // Deterministic for the same template...
    assert_eq!(a, key(&mut sim, plain, &[]));
    // ...but bound to the whole template and to inSensitive.data.
    assert_ne!(
        a,
        key(&mut sim, with_policy, &[]),
        "template not bound into the primary seed"
    );
    assert_ne!(
        a,
        key(&mut sim, plain, b"extra"),
        "inSensitive.data not bound into the seed"
    );

    // CreateLoaded with a hierarchy parent derives the same primary object as CreatePrimary.
    let rsp = run(
        &mut sim,
        &CreateLoaded {
            parent_handle: Handle::RH_OWNER,
            in_sensitive: sensitive_create(&[], &[]),
            in_public: make_template(&with_policy),
        },
        1,
    )
    .unwrap();
    assert_eq!(
        ecc_point(&rsp.out_public.0),
        key(&mut sim, with_policy, &[])
    );
}

/// A template with `sensitiveDataOrigin` SET under a Derivation Parent is `TPM_RC_ATTRIBUTES`
/// without a parameter number, as in the TCG reference (found by differential fuzzing). TPM 2.0
/// Part 3, TPM2_CreateLoaded: "when *parentHandle* references a Derivation Parent, then
/// *sensitiveDataOrigin* in *inPublic* is required to be CLEAR."
#[test]
fn derived_template_with_sensitive_data_origin_rejected() {
    let mut tpm = Tpm::new();
    // CreateLoaded(owner): KEYEDHASH derivation parent (restricted|decrypt, XOR/SHA-256/KDF1_SP800_108).
    let parent = crate::_common::hex(
        "80020000003500000191400000010000000940000009000001000000040000000000120008000b000300600000000a000b00220000",
    );
    let rsp = tpm.send_command(0, &parent);
    assert_eq!(&rsp[6..10], [0, 0, 0, 0], "derivation parent: {rsp:02x?}");
    let mut child = crate::_common::hex(
        "800200000041000001918000000000000009400000090000010000000c00087040737377307264000000160023000b000400600000001000100003001000000000",
    );
    child[10..14].copy_from_slice(&rsp[10..14]);
    let rsp = tpm.send_command(0, &child);
    assert_eq!(&rsp[6..10], 0x082u32.to_be_bytes(), "{rsp:02x?}");
}

/// A derivation label larger than `LABEL_MAX_BUFFER` is `TPM_RC_SIZE + P2` (inPublic) even
/// when fewer bytes than its size follow in the template: the size is checked before the
/// label is read (Part 2 `TPM2B_LABEL`: `buffer[size] {:LABEL_MAX_BUFFER}`).
#[test]
fn derived_label_size_checked_before_label_bytes() {
    use crate::_common::{PW_SESSION_CONTINUE, ST_SESSIONS, build_raw_cmd, mssim_rc_of};
    const CC_CREATE_LOADED: u32 = 0x191;
    let mut sim = Tpm::new();
    // inSensitive (empty) || inPublic.
    let params = |template: &[u8]| {
        let mut p = vec![0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        p.extend_from_slice(&(template.len() as u16).to_be_bytes());
        p.extend_from_slice(template);
        p
    };
    // A derivation parent: restricted decrypt KEYEDHASH with the XOR scheme (SHA-256, KDF1
    // SP800-108) in the owner hierarchy.
    let parent_template = [
        0x00, 0x08, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x60, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00,
        0x22, 0x00, 0x00,
    ];
    let cmd = build_raw_cmd(
        ST_SESSIONS,
        CC_CREATE_LOADED,
        &[0x4000_0001],
        Some(&PW_SESSION_CONTINUE),
        &params(&parent_template),
    );
    let (rc, rsp) = crate::_common::send_with_rc(&mut sim, &cmd);
    assert_eq!(rc, 0);
    let parent = u32::from_be_bytes(rsp[10..14].try_into().unwrap());
    // A derived HMAC key (sign | userWithAuth | fixedParent, HMAC-SHA-256) whose label claims
    // 49 bytes.
    let derived = |label_bytes: usize| {
        let mut t = vec![
            0x00, 0x08, 0x00, 0x0b, 0x00, 0x04, 0x00, 0x50, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0b,
            0x00, 49,
        ];
        t.extend(std::iter::repeat_n(0x6c, label_bytes));
        t.extend_from_slice(&[0x00, 0x07]);
        t.extend_from_slice(b"context");
        t
    };
    for label_bytes in [9, 49] {
        let cmd = build_raw_cmd(
            ST_SESSIONS,
            CC_CREATE_LOADED,
            &[parent],
            Some(&PW_SESSION_CONTINUE),
            &params(&derived(label_bytes)),
        );
        assert_eq!(
            mssim_rc_of(&mut sim, &cmd),
            0x2D5,
            "{label_bytes} label bytes"
        );
    }
}
