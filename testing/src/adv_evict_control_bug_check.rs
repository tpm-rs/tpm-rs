#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, EvictControl, EvictControlHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_simulator::create_simulator;

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
fn test_platform_can_evict_owner_object() {
    let mut sim = create_simulator!();

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

    let create_handles_owner = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, rsp_owner) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles_owner, 1, &[])
            .unwrap();
    let owner_transient_handle = rsp_owner.object_handle;

    let persistent_handle = Handle(0x81000000);
    let make_pers_handles = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: owner_transient_handle,
    };
    let make_pers_cmd = EvictControl { persistent_handle };
    execute_with_password_sessions(&mut sim, &make_pers_cmd, make_pers_handles, 1, &[]).unwrap();

    let evict_handles = EvictControlHandles {
        auth: Handle::RH_PLATFORM,
        object_handle: persistent_handle,
    };
    let evict_cmd = EvictControl { persistent_handle };
    let evict_res = execute_with_password_sessions(&mut sim, &evict_cmd, evict_handles, 1, &[]);
    assert!(
        evict_res.is_ok(),
        "Platform failed to evict owner persistent object! Error code: {:?}",
        evict_res.err()
    );
}
