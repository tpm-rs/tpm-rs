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
fn test_evict_control_critic() {
    let mut sim = create_simulator!();

    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };

    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_ecc_srk_template());
    let outside_info = Tpm2bData::default();
    let creation_pcr = TpmlPcrSelection::default();

    // 1. CreatePrimary in Endorsement hierarchy
    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let rsp_handles_ek = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();

    // 2. Platform Auth should NOT be able to make Endorsement object persistent.
    // The current Rust implementation will ALLOW this!
    let evict_cmd = EvictControl {
        auth: Handle::RH_PLATFORM,
        object_handle: rsp_handles_ek.object_handle,
        persistent_handle: Handle(0x81800001),
    };
    let res = execute_with_password_sessions(&mut sim, &evict_cmd, 1, &[]);
    // It should be Err, but it's probably Ok right now due to the bug!
    println!("{:?}", res);
    assert!(
        res.is_err(),
        "Platform auth should NOT be able to persist Endorsement objects (bug 1)"
    );

    // 3. CreatePrimary in Owner hierarchy
    let create_cmd_owner = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let rsp_handles_owner =
        execute_with_password_sessions(&mut sim, &create_cmd_owner, 1, &[]).unwrap();

    // 4. Owner Auth makes it persistent
    let evict_owner_cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: rsp_handles_owner.object_handle,
        persistent_handle: Handle(0x81000001),
    };
    execute_with_password_sessions(&mut sim, &evict_owner_cmd, 1, &[]).unwrap();

    // 5. Platform Auth should BE ABLE to evict an Owner hierarchy persistent object!
    // The current Rust implementation will FAIL this!
    let evict_plat_cmd = EvictControl {
        auth: Handle::RH_PLATFORM,
        object_handle: Handle(0x81000001),
        persistent_handle: Handle(0x81000001),
    };
    let res2 = execute_with_password_sessions(&mut sim, &evict_plat_cmd, 1, &[]);
    assert!(
        res2.is_ok(),
        "Platform auth should be able to evict Owner persistent objects (bug 2)"
    );
}
