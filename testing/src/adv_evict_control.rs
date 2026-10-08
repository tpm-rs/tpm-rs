#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles};
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
fn test_evict_control_auth_bypass() {
    let mut sim = create_simulator!();

    // 1. CreatePrimary in Platform hierarchy
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };

    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_ecc_srk_template());
    let outside_info = Tpm2bData::default();
    let creation_pcr = TpmlPcrSelection::default();

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_PLATFORM, // Platform hierarchy!
    };
    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let (_, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();

    // 2. Make it persistent with Platform auth
    let evict_handles = EvictControlHandles {
        auth: Handle::RH_PLATFORM,
        object_handle: rsp_handles.object_handle,
    };
    let evict_cmd = EvictControl {
        persistent_handle: Handle(0x81800000),
    };
    execute_with_password_sessions(&mut sim, &evict_cmd, evict_handles, 1, &[]).unwrap();

    // 3. Try to evict it using Owner auth - this should FAIL!
    let evict_handles2 = EvictControlHandles {
        auth: Handle::RH_OWNER, // Wrong hierarchy auth!
        object_handle: Handle(0x81800000),
    };
    let evict_cmd2 = EvictControl {
        persistent_handle: Handle(0x81800000),
    };
    let res = execute_with_password_sessions(&mut sim, &evict_cmd2, evict_handles2, 1, &[]);

    assert!(
        res.is_err(),
        "EvictControl should fail when trying to evict Platform object with Owner auth"
    );
}
