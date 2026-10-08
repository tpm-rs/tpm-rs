use crate::test_utils::*;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, EvictControl, EvictControlHandles};
use tpm2::errors::{Position, TpmRc};
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
fn test_evict_control_owner_evict_platform_wrong_error() {
    let mut sim = create_simulator!();

    // 1. Platform creates an object and makes it persistent
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_ecc_srk_template());

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_PLATFORM,
    };
    let (_, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();

    let persistent_handle = Handle(0x81800000);
    let evict_cmd = EvictControl { persistent_handle };
    let evict_handles = EvictControlHandles {
        auth: Handle::RH_PLATFORM,
        object_handle: rsp_handles.object_handle,
    };
    execute_with_password_sessions(&mut sim, &evict_cmd, evict_handles, 1, &[]).unwrap();

    // 2. Owner tries to evict it
    let evict_cmd_owner = EvictControl { persistent_handle };
    let evict_handles_owner = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: persistent_handle,
    };
    let res =
        execute_with_password_sessions(&mut sim, &evict_cmd_owner, evict_handles_owner, 1, &[]);

    let expected_rc = TpmRc::HIERARCHY.with(Position::handle(2)).get();

    assert_eq!(res.unwrap_err(), expected_rc);
}
