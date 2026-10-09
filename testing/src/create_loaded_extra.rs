//! Extra (non-Go-parity) tests for create_loaded, moved out of src/go.

use crate::test_utils::*;
use tpm2::commands::{CreateLoaded, CreateLoadedHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_simulator::create_simulator;

#[test]
fn test_create_loaded_derived_ecc_with_ibm_tss_appended_context() {
    let mut sim = create_simulator!();

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
    let deriver_in_public = crate::test_utils::make_template(&deriver_pub_area);
    let deriver_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: deriver_in_public,
    };
    let deriver_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
    };
    let (_, deriver_rsp_handles) =
        execute_with_password_sessions(&mut sim, &deriver_cmd, deriver_handles, 1, &[]).unwrap();

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
        in_sensitive,
        in_public: bad_in_public,
    };
    let handles = CreateLoadedHandles {
        parent_handle: deriver_rsp_handles.object_handle,
    };
    let err =
        execute_with_password_sessions(&mut sim, &bad_cmd, handles.clone(), 1, &[]).unwrap_err();
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
    let valid_in_public = crate::test_utils::make_template(&valid_ecc_pub_area);
    let valid_cmd = CreateLoaded {
        in_sensitive,
        in_public: valid_in_public,
    };
    let (_, derived_rsp_handles) =
        execute_with_password_sessions(&mut sim, &valid_cmd, handles, 1, &[]).unwrap();

    // Flush derived key
    flush_context(&mut sim, derived_rsp_handles.object_handle).unwrap();

    // Flush deriver
    flush_context(&mut sim, deriver_rsp_handles.object_handle).unwrap();
}

#[test]
fn test_create_loaded_derived_keyedhash_sym_and_set_label_context() {
    let mut sim = create_simulator!();

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
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_template(&deriver_pub_area),
    };
    let (_, deriver_handles) = execute_with_password_sessions(
        &mut sim,
        &deriver_cmd,
        CreateLoadedHandles {
            parent_handle: Handle(0x40000001),
        },
        1,
        &[],
    )
    .unwrap();
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
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_derive_template(&kh_pub_template, &pub_derive),
    };
    let (kh_rsp, kh_handles) = execute_with_password_sessions(
        &mut sim,
        &kh_cmd,
        CreateLoadedHandles { parent_handle },
        1,
        &[],
    )
    .unwrap();

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
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(&sens_derive_buf[..sens_derive_len]).unwrap(),
        }),
        in_public: crate::test_utils::make_derive_template(&kh_pub_template, &partial_pub_derive),
    };
    let (kh_merged_rsp, kh_merged_handles) = execute_with_password_sessions(
        &mut sim,
        &kh_merged_cmd,
        CreateLoadedHandles { parent_handle },
        1,
        &[],
    )
    .unwrap();
    assert_eq!(
        kh_rsp.out_public.0.parms_and_id, kh_merged_rsp.out_public.0.parms_and_id,
        "SetLabelAndContext must merge non-empty label from inPublic with fallback context from inSensitive.data"
    );

    // 4. Derive a Symmetric (AES-128 CFB) child under the derivation parent
    let sym_pub_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::default(),
        ),
    };
    let sym_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_derive_template(&sym_pub_template, &pub_derive),
    };
    let (_, sym_handles) = execute_with_password_sessions(
        &mut sim,
        &sym_cmd,
        CreateLoadedHandles { parent_handle },
        1,
        &[],
    )
    .unwrap();

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
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_derive_template(&rsa_pub_template, &pub_derive),
    };
    let rsa_err = execute_with_password_sessions(
        &mut sim,
        &rsa_cmd,
        CreateLoadedHandles { parent_handle },
        1,
        &[],
    )
    .unwrap_err();
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
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_template(&ecc_oversized_pub),
    };
    let ecc_size_err = execute_with_password_sessions(
        &mut sim,
        &ecc_oversized_cmd,
        CreateLoadedHandles { parent_handle },
        1,
        &[],
    )
    .unwrap_err();
    assert_eq!(
        ecc_size_err,
        tpm2::errors::TpmRc::SIZE
            .with(tpm2::errors::Position::parameter(2))
            .get(),
        "ECC derivation template with >32 byte label must fail with TPM_RC_SIZE + P2"
    );

    // Flush all created handles
    for handle in [
        kh_handles.object_handle,
        kh_merged_handles.object_handle,
        sym_handles.object_handle,
        parent_handle,
    ] {
        flush_context(&mut sim, handle).unwrap();
    }
}
