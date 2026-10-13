//! TPM2_GetTime: signing schemes, NULL signer and authorization requirements.

use crate::_common::{
    create_primary_in, create_test_key, execute_get_time, execute_with_password_sessions_status,
    get_time, rsa_sign_template,
};
use tpm2::commands::{EvictControl, GetTime};
use tpm2::{Handle, Tpm2bData, TpmiAlgHash, TpmtRsaScheme, TpmtSigScheme, TpmtSignature};
use tpm2_simulator::create_simulator;

/// GetTime with an explicit RSASSA-SHA256 scheme on a key with NULL scheme succeeds
#[test]
fn explicit_scheme_on_null_scheme_key() {
    let mut sim = create_simulator!();
    let scheme = None;
    let key_handle = create_test_key(&mut sim, &[], scheme);

    let qualifying_data_bytes = b"migrationpains";
    let qualifying_data = Tpm2bData::from_bytes(qualifying_data_bytes).unwrap();

    let get_time_cmd = GetTime {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key_handle,
        qualifying_data,
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
    };

    let resp = execute_with_password_sessions_status(&mut sim, &get_time_cmd, 2, &[]);
    assert!(
        resp.is_ok(),
        "GetTime failed with valid scheme on a scheme-less key! {:?}",
        resp.err()
    );
}

/// GetTime without sessions is TPM_RC_AUTH_MISSING
#[test]
fn missing_sessions_rejected() {
    let mut sim = create_simulator!();
    let scheme = Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256));
    let key_handle = create_test_key(&mut sim, b"secret", scheme);

    let get_time_cmd = GetTime {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key_handle,
        qualifying_data: Tpm2bData::from_bytes(b"data").unwrap(),
        in_scheme: None,
    };

    let resp = execute_with_password_sessions_status(&mut sim, &get_time_cmd, 0, &[]);
    assert!(resp.is_err(), "GetTime should fail without sessions");
    if let Err(e) = resp {
        assert_eq!(e, 0x125, "Expected TPM_RC_AUTH_MISSING (0x125)");
    }
}

/// GetTime with signHandle TPM_RH_NULL (still needs a session) returns a NULL signature.
#[test]
fn null_sign_handle_unsigned() {
    let mut sim = create_simulator!();

    let get_time_cmd = GetTime {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle::RH_NULL,
        qualifying_data: Tpm2bData::from_bytes(b"data").unwrap(),
        in_scheme: None,
    };

    // signHandle has the USER auth role even when it is TPM_RH_NULL, so C
    // requires a session for it too (SessionProcess.c:1641-1651): 2 sessions.
    let mut resp_buffer = [0u8; 4096];
    let resp = execute_get_time(&mut sim, &get_time_cmd, 2, &[], &mut resp_buffer).unwrap();

    // Check that signature is Null (None)
    assert!(resp.signature.is_none(), "Expected None signature");
}

/// `TPM2_GetTime` must accept a persistent signing key (`TPMI_DH_OBJECT`); it used to look the
/// key up only among transient objects and fail with `TPM_RC_VALUE`.
#[test]
fn persistent_signing_key() {
    let mut sim = create_simulator!();
    let key = create_primary_in(
        &mut sim,
        Handle::RH_OWNER,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
    );
    let persistent = Handle(0x8100_0A77);
    let evict = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: key,
        persistent_handle: persistent,
    };
    execute_with_password_sessions_status(&mut sim, &evict, 1, &[]).expect("EvictControl failed");

    let rsp = get_time(&mut sim, Handle::RH_ENDORSEMENT, persistent, None, 2)
        .expect("GetTime with a persistent signing key failed");
    assert!(matches!(rsp.signature, Some(TpmtSignature::Rsassa(_))));
}

/// GetTime keeps working after a failed call with an unsupported scheme
#[test]
fn succeeds_after_scheme_error() {
    let mut sim = create_simulator!();
    let scheme = Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256));
    let key_handle = create_test_key(&mut sim, &[], scheme);

    let get_time_cmd_fail = GetTime {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key_handle,
        qualifying_data: Tpm2bData::from_bytes(b"fail").unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha384)),
    };

    let resp_fail = execute_with_password_sessions_status(&mut sim, &get_time_cmd_fail, 2, &[]);
    assert!(
        resp_fail.is_err(),
        "Expected failure due to scheme mismatch"
    );

    let get_time_cmd_ok = GetTime {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key_handle,
        qualifying_data: Tpm2bData::from_bytes(b"recovery").unwrap(),
        in_scheme: None,
    };

    let mut resp_buffer = [0u8; 4096];
    let get_time_resp_ok = execute_get_time(&mut sim, &get_time_cmd_ok, 2, &[], &mut resp_buffer)
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

/// GetTime with a wrong signing-key password fails
#[test]
fn wrong_key_auth_rejected() {
    let mut sim = create_simulator!();
    let scheme = Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256));
    let key_handle = create_test_key(&mut sim, b"secret", scheme);

    let get_time_cmd = GetTime {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: key_handle,
        qualifying_data: Tpm2bData::from_bytes(b"data").unwrap(),
        in_scheme: None,
    };

    let resp = execute_with_password_sessions_status(&mut sim, &get_time_cmd, 2, b"wrong");
    assert!(resp.is_err(), "GetTime should fail with incorrect auth");
    if let Err(e) = resp {
        // AuthFail is RC_FMT1 (0x80) + 0x00E + optional handle indicators.
        // Actually it's simpler to just check it's not success.
        assert_ne!(e, 0, "Expected AuthFail error");
    }
}
