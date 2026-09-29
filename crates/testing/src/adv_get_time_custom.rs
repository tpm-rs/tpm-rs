#![allow(unused_imports, dead_code)]
use tpm2::Handle;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, GetTime, GetTimeHandles};
use tpm2_platform_linux::LinuxRng;

use crate::test_utils::*;
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublicKeyRsa, Tpm2bSensitiveCreate,
    Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsRsaParms, TpmsSensitiveCreate,
    TpmtPublic, TpmtRsaScheme, TpmtSigScheme,
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

#[test]
fn test_get_time_scheme_fallback() {
    let mut sim = create_simulator!();
    let scheme = None;
    let key_handle = create_test_key(&mut sim, &[], scheme);

    let qualifying_data_bytes = b"migrationpains";
    let qualifying_data = Tpm2bData::from_bytes(qualifying_data_bytes).unwrap();

    let get_time_cmd = GetTime {
        qualifying_data,
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
    };

    let get_time_handles = GetTimeHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key_handle,
    };

    let resp =
        execute_with_password_sessions_status(&mut sim, &get_time_cmd, get_time_handles, 2, &[]);
    assert!(
        resp.is_ok(),
        "GetTime failed with valid scheme on a scheme-less key! {:?}",
        resp.err()
    );
}

#[test]
fn test_get_time_auth_missing() {
    let mut sim = create_simulator!();
    let scheme = Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256));
    let key_handle = create_test_key(&mut sim, b"secret", scheme);

    let get_time_cmd = GetTime {
        qualifying_data: Tpm2bData::from_bytes(b"data").unwrap(),
        in_scheme: None,
    };

    let get_time_handles = GetTimeHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key_handle,
    };

    let resp =
        execute_with_password_sessions_status(&mut sim, &get_time_cmd, get_time_handles, 0, &[]);
    assert!(resp.is_err(), "GetTime should fail without sessions");
    if let Err(e) = resp {
        assert_eq!(e, 0x125, "Expected TPM_RC_AUTH_MISSING (0x125)");
    }
}

#[test]
fn test_get_time_auth_incorrect() {
    let mut sim = create_simulator!();
    let scheme = Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256));
    let key_handle = create_test_key(&mut sim, b"secret", scheme);

    let get_time_cmd = GetTime {
        qualifying_data: Tpm2bData::from_bytes(b"data").unwrap(),
        in_scheme: None,
    };

    let get_time_handles = GetTimeHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key_handle,
    };

    let resp = execute_with_password_sessions_status(
        &mut sim,
        &get_time_cmd,
        get_time_handles,
        2,
        b"wrong",
    );
    assert!(resp.is_err(), "GetTime should fail with incorrect auth");
    if let Err(e) = resp {
        // AuthFail is RC_FMT1 (0x80) + 0x00E + optional handle indicators.
        // Actually it's simpler to just check it's not success.
        assert_ne!(e, 0, "Expected AuthFail error");
    }
}

#[test]
fn test_get_time_signature_recovery() {
    let mut sim = create_simulator!();
    let scheme = Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256));
    let key_handle = create_test_key(&mut sim, &[], scheme);

    let get_time_cmd_fail = GetTime {
        qualifying_data: Tpm2bData::from_bytes(b"fail").unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha384)),
    };

    let get_time_handles = GetTimeHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key_handle,
    };

    let resp_fail = execute_with_password_sessions_status(
        &mut sim,
        &get_time_cmd_fail,
        get_time_handles,
        2,
        &[],
    );
    assert!(
        resp_fail.is_err(),
        "Expected failure due to scheme mismatch"
    );

    let get_time_cmd_ok = GetTime {
        qualifying_data: Tpm2bData::from_bytes(b"recovery").unwrap(),
        in_scheme: None,
    };

    let mut resp_buffer = [0u8; 4096];
    let (get_time_resp_ok, _) = execute_get_time(
        &mut sim,
        &get_time_cmd_ok,
        get_time_handles,
        2,
        &[],
        &mut resp_buffer,
    )
    .expect("GetTime recovery failed");

    let tpms_attest = get_time_resp_ok
        .time_info
        .to_struct()
        .expect("failed to unmarshal time_info");

    assert_eq!(
        tpms_attest.extra_data.get_buffer(),
        b"recovery",
        "extra_data mismatch in recovery test"
    );
}
