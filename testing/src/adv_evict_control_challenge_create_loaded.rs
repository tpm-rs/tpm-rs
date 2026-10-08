#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::commands::{CreateLoaded, CreateLoadedHandles, CreatePrimary, CreatePrimaryHandles};
use tpm2::commands::{EvictControl, EvictControlHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn get_ecc_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
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
    }
}

#[test]
fn test_evict_control_stclear_ancestor() {
    let mut sim = create_simulator!();

    // 1. Create a Primary Key with stClear SET
    let mut primary_public = get_ecc_srk_template();
    // SET stClear
    primary_public.object_attributes |= TpmaObject::ST_CLEAR;

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };

    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(primary_public);

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let (_, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();

    let primary_handle = rsp_handles.object_handle;

    // 2. Create a child key (without stClear) under the Primary Key using CreateLoaded
    let child_public = get_ecc_srk_template(); // Child has NO stClear
    let in_public_child = crate::test_utils::make_template(&child_public);

    let create_loaded_handles = CreateLoadedHandles {
        parent_handle: primary_handle,
    };
    let create_loaded_cmd = CreateLoaded {
        in_sensitive,
        in_public: in_public_child,
    };

    let (_, rsp_child) =
        execute_with_password_sessions(&mut sim, &create_loaded_cmd, create_loaded_handles, 1, &[])
            .unwrap();

    let child_handle = rsp_child.object_handle;

    // 3. Try to EvictControl the child key.
    // The child key doesn't have stClear, BUT its ancestor (the primary key) does.
    // The TPM 2.0 spec says this MUST return TPM_RC_ATTRIBUTES.
    let evict_handles = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: child_handle,
    };
    let evict_cmd = EvictControl {
        persistent_handle: Handle(0x81000001),
    };

    let res = execute_with_password_sessions(&mut sim, &evict_cmd, evict_handles, 1, &[]);

    assert!(
        res.is_err(),
        "EvictControl MUST fail if an ancestor key has stClear SET. Expected TPM_RC_ATTRIBUTES."
    );

    // Also check it is TPM_RC_ATTRIBUTES
    let err = res.unwrap_err();
    println!("Error was: 0x{:08X}", err);
}
