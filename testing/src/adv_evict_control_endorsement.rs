#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, EvictControl, EvictControlHandles};
use tpm2::errors::{Position, TpmRc};
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
fn test_platform_cannot_persist_endorsement_object() {
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

    // Create a transient object in Endorsement hierarchy
    let create_handles_end = CreatePrimaryHandles {
        primary_handle: Handle::RH_ENDORSEMENT,
    };
    let (_, rsp_end) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles_end, 1, &[]).unwrap();
    let end_transient_handle = rsp_end.object_handle;

    // Try to persist with Platform auth
    let handles = EvictControlHandles {
        auth: Handle::RH_PLATFORM,
        object_handle: end_transient_handle,
    };
    let cmd = EvictControl {
        persistent_handle: Handle(0x81800005),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 1, &[]);

    assert!(
        res.is_err(),
        "Platform auth should not be able to persist an Endorsement object!"
    );
    let err = res.unwrap_err();
    assert_eq!(
        err,
        TpmRc::HIERARCHY.with(Position::handle(2)).get(),
        "Should return TPM_RC_HIERARCHY"
    );
}
