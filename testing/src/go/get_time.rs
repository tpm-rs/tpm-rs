//! Rust port of `get_time_test.go`.

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

// Original Go test: get_time_test.go - TestGetTime
#[test]
fn test_get_time() {
    let mut sim = create_simulator!();

    // RSA-2048 RSASSA-SHA256 signing key in the endorsement hierarchy.
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let create_primary = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(public_area),
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_ENDORSEMENT,
    };
    let (_, rsp_cp_handles) =
        execute_with_password_sessions(&mut sim, &create_primary, create_handles, 1, &[])
            .expect("could not create key");
    let key_handle = rsp_cp_handles.object_handle;

    let qualifying_data: &[u8] = b"migrationpains";

    let get_time_cmd = GetTime {
        qualifying_data: Tpm2bData::from_bytes(qualifying_data).unwrap(),
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
        .expect("failed to unmarshal response");

    let tpms_time_attest_info = match tpms_attest.attested {
        tpm2::TpmuAttest::Time(info) => info,
        _ => panic!("union typed field did not have expected concrete type"),
    };

    assert_eq!(
        tpms_time_attest_info.time.clock_info.clock, tpms_attest.clock_info.clock,
        "clockInfo does not match in tpmsTimeAttestInfo vs tpmsAttest"
    );
    assert_eq!(
        tpms_time_attest_info.time.clock_info.reset_count, tpms_attest.clock_info.reset_count,
        "resetCount does not match in tpmsTimeAttestInfo vs tpmsAttest"
    );
    assert_eq!(
        tpms_time_attest_info.time.clock_info.restart_count, tpms_attest.clock_info.restart_count,
        "restartCount does not match in tpmsTimeAttestInfo vs tpmsAttest"
    );
    assert_eq!(
        tpms_attest.extra_data.get_buffer(),
        qualifying_data,
        "extraData does not match"
    );

    // Deferred FlushContext in Go.
    let _ = flush_context(&mut sim, key_handle);
}
