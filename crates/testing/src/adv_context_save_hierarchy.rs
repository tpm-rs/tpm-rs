use crate::test_utils::*;
use tpm2::commands::{ContextSave, ContextSaveHandles, CreateLoaded, CreateLoadedHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_context_save_hierarchy_bug() {
    let mut sim = create_simulator!();

    // 1. CreateLoaded (in Owner hierarchy)
    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"pass").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
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
    let in_public = crate::test_utils::make_template(&pub_area);
    let create = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001),
    }; // TPM_RH_OWNER

    let (_create_resp, create_resp_handles) =
        execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[]).unwrap();
    let object_handle = create_resp_handles.object_handle;

    // 2. ContextSave
    let save = ContextSave {};
    let save_handles = ContextSaveHandles {
        save_handle: object_handle,
    };
    let (save_resp, _) =
        execute_with_password_sessions(&mut sim, &save, save_handles, 0, &[]).unwrap();

    // Bug 1: Hierarchy is hardcoded to 0 instead of TPM_RH_OWNER (0x40000001)
    assert_ne!(
        save_resp.context.hierarchy.0, 0,
        "BUG: Hierarchy is hardcoded to 0 in ContextSave!"
    );
}
