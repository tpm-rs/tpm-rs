#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::commands::{CreateLoaded, CreateLoadedHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_simulator::{Simulator, create_simulator};

/// go-tpm's `ECCEKTemplate`: the TCG default ECC NIST P-256 EK template
/// (AES-128-CFB restricted decryption key, PolicySecret(RH_ENDORSEMENT)
/// auth policy, and 32-byte zero-filled unique X/Y coordinates).
fn get_ecc_ek_template() -> TpmtPublic<'static> {
    static AUTH_POLICY: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7,
        0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
        0x69, 0xAA,
    ];
    static ZEROS: [u8; 32] = [0u8; 32];
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::ADMIN_WITH_POLICY
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::from_bytes(&AUTH_POLICY).unwrap(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&ZEROS).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&ZEROS).unwrap(),
            },
        ),
    }
}

/// Port of Go's `getDeriver`: creates (under TPM_RH_OWNER, empty password) a
/// restricted-decrypt KeyedHash derivation parent using the XOR scheme with
/// SHA-256 and KDF1_SP800_108, and returns its handle.
fn get_deriver(sim: &mut Simulator<'_>) -> Handle {
    let deriver_pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED,
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
    let deriver_handles = CreateLoadedHandles {
        parent_handle: Handle::RH_OWNER,
    };
    let (_, rsp_handles) =
        execute_with_password_sessions(sim, &deriver_cmd, deriver_handles, 1, &[])
            .expect("could not create derivation parent");
    rsp_handles.object_handle
}

/// Body shared by every `TestCreateLoaded` subtest: executes `cmd` under
/// `parent_handle` (empty password auth, as go-tpm does for plain handles)
/// and flushes the resulting object.
fn run_create_loaded(sim: &mut Simulator<'_>, cmd: &CreateLoaded<'_>, parent_handle: Handle) {
    let (_, rsp_handles) =
        execute_with_password_sessions(sim, cmd, CreateLoadedHandles { parent_handle }, 1, &[])
            .expect("error from CreateLoaded");
    flush_context(sim, rsp_handles.object_handle).expect("error from FlushContext");
}

// Original Go test: create_loaded_test.go - TestCreateLoaded/PrimaryKey
#[test]
fn test_create_loaded_primary_key() {
    let mut sim = create_simulator!();
    let _deriver = get_deriver(&mut sim);

    let cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_template(&get_ecc_ek_template()),
    };
    run_create_loaded(&mut sim, &cmd, Handle::RH_ENDORSEMENT);
}

// Original Go test: create_loaded_test.go - TestCreateLoaded/NoParentPrimaryKey
#[test]
fn test_create_loaded_no_parent_primary_key() {
    let mut sim = create_simulator!();
    let _deriver = get_deriver(&mut sim);

    // go-tpm marshals an omitted (nil) parent handle as TPM_RH_NULL.
    let cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_template(&get_ecc_ek_template()),
    };
    run_create_loaded(&mut sim, &cmd, Handle::RH_NULL);
}

// Original Go test: create_loaded_test.go - TestCreateLoaded/OrdinaryKey
#[test]
fn test_create_loaded_ordinary_key() {
    let mut sim = create_simulator!();
    let _deriver = get_deriver(&mut sim);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
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
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(b"p@ssw0rd").unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_template(&pub_area),
    };
    run_create_loaded(&mut sim, &cmd, Handle::RH_OWNER);
}

// Original Go test: create_loaded_test.go - TestCreateLoaded/DataBlob
#[test]
fn test_create_loaded_data_blob() {
    let mut sim = create_simulator!();
    let _deriver = get_deriver(&mut sim);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    };
    let cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(b"p@ssw0rd").unwrap(),
            data: Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        }),
        in_public: crate::test_utils::make_template(&pub_area),
    };
    run_create_loaded(&mut sim, &cmd, Handle::RH_OWNER);
}

// Original Go test: create_loaded_test.go - TestCreateLoaded/Derived
#[test]
fn test_create_loaded_derived() {
    let mut sim = create_simulator!();
    let deriver = get_deriver(&mut sim);

    // go-tpm's `NewTPMUSensitiveCreate(&derive)` places the marshaled
    // TPMS_DERIVE (label, context) in the sensitive data buffer.
    let tpms_derive = TpmsDerive {
        label: Tpm2bLabel::from_bytes(b"label").unwrap(),
        context: Tpm2bLabel::from_bytes(b"context").unwrap(),
    };
    let mut derive_buf = [0u8; 1024];
    let derive_len = marshal_to_slice(&tpms_derive, &mut derive_buf);

    let pub_area = TpmtPublic {
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
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(b"p@ssw0rd").unwrap(),
            data: Tpm2bSensitiveData::from_bytes(&derive_buf[..derive_len]).unwrap(),
        }),
        in_public: crate::test_utils::make_template(&pub_area),
    };
    run_create_loaded(&mut sim, &cmd, deriver);
}
