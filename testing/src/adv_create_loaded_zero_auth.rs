use crate::test_utils::*;
use tpm2::commands::{CreateLoaded, CreateLoadedHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_simulator::create_simulator;

#[test]
fn test_create_loaded_zero_auth_bypass() {
    let mut sim = create_simulator!();

    let password = b"parent_secret";

    // 1. Create a parent object WITHOUT USER_WITH_AUTH
    let parent_in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    });

    // MISSING USER_WITH_AUTH
    let parent_pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
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

    let create_parent = CreateLoaded {
        in_sensitive: parent_in_sensitive,
        in_public: crate::test_utils::make_template(&parent_pub_area),
    };

    let parent_handles = CreateLoadedHandles {
        parent_handle: Handle(tpm2::Handle::RH_OWNER.0),
    };

    let (_rsp_cp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_parent, parent_handles, 1, &[]).unwrap();
    let parent_handle = rsp_handles.object_handle;

    // 2. Try to create a child under this parent WITH NO SESSIONS AT ALL (num_sessions = 0)
    let child_in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    let child_pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                    hash_alg: TpmiAlgHash::Sha256,
                    count: 0,
                })),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    let create_child = CreateLoaded {
        in_sensitive: child_in_sensitive,
        in_public: crate::test_utils::make_template(&child_pub_area),
    };

    let child_handles = CreateLoadedHandles { parent_handle };

    let result =
        execute_with_password_sessions(&mut sim, &create_child, child_handles, 0, password);
    if result.is_ok() {
        panic!(
            "VULNERABILITY: CreateLoaded allowed 0 sessions for parent when USER_WITH_AUTH was 0, bypassing authorization completely!"
        );
    }
}
