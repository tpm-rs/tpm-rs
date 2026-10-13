#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::commands::CreatePrimary;
use tpm2::commands::EvictControl;
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
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                }),
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

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_PLATFORM, // Platform hierarchy!
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();

    // 2. Make it persistent with Platform auth
    let evict_cmd = EvictControl {
        auth: Handle::RH_PLATFORM,
        object_handle: rsp_handles.object_handle,
        persistent_handle: Handle(0x81800000),
    };
    execute_with_password_sessions(&mut sim, &evict_cmd, 1, &[]).unwrap();

    // 3. Try to evict it using Owner auth - this should FAIL!
    let evict_cmd2 = EvictControl {
        auth: Handle::RH_OWNER, // Wrong hierarchy auth!
        object_handle: Handle(0x81800000),
        persistent_handle: Handle(0x81800000),
    };
    let res = execute_with_password_sessions(&mut sim, &evict_cmd2, 1, &[]);

    assert!(
        res.is_err(),
        "EvictControl should fail when trying to evict Platform object with Owner auth"
    );
}
