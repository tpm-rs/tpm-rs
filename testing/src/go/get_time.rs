use tpm2::Handle;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, GetTime, GetTimeHandles};
use tpm2_platform_linux::LinuxRng;

use crate::test_utils::*;
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublicKeyRsa, Tpm2bSensitiveData,
    TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic,
    TpmtRsaScheme,
};
use tpm2_simulator::{Simulator, create_simulator};

fn create_test_key(sim: &mut Simulator<'_>, auth: &[u8], scheme: Option<TpmtRsaScheme>) -> Handle {
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let mut user_auth = Tpm2bAuth::default();
    if !auth.is_empty() {
        user_auth = Tpm2bAuth::from_bytes(auth).unwrap();
    }

    let sensitive_create = TpmsSensitiveCreate {
        user_auth,
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_ENDORSEMENT,
    };
    let (_, rsp_handles) = execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[])
        .expect("could not generate key");

    rsp_handles.object_handle
}

// Original Go test: get_time_test.go - TestGetTime
#[test]
fn test_get_time() {
    let mut sim = create_simulator!();
    let scheme = Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256));
    let key_handle = create_test_key(&mut sim, &[], scheme);

    let qualifying_data_bytes = b"migrationpains";
    let qualifying_data = Tpm2bData::from_bytes(qualifying_data_bytes).unwrap();

    let get_time_cmd = GetTime {
        qualifying_data,
        in_scheme: None,
    };

    let get_time_handles = GetTimeHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key_handle,
    };

    let mut resp_buffer = [0u8; 4096];
    let (get_time_resp, _) = execute_get_time(
        &mut sim,
        &get_time_cmd,
        get_time_handles,
        2,
        &[],
        &mut resp_buffer,
    )
    .expect("GetTime failed");

    let tpms_attest = get_time_resp
        .time_info
        .to_struct()
        .expect("failed to unmarshal time_info");

    let _tpms_time_attest_info = match tpms_attest.attested {
        tpm2::TpmuAttest::Time(info) => info,
        _ => panic!("union typed field did not have expected concrete type"),
    };

    assert_eq!(
        tpms_attest.extra_data.get_buffer(),
        qualifying_data_bytes,
        "extra_data mismatch"
    );
}
