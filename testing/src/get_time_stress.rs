use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, GetTime, GetTimeHandles};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublicKeyRsa, Tpm2bSensitiveData,
    TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic,
    TpmtRsaScheme,
};
use tpm2_simulator::{Simulator, create_simulator};

fn create_test_key(
    sim: &mut Simulator<'_>,
    auth: &[u8],
    scheme: Option<TpmtRsaScheme>,
    is_restricted: bool,
    name_alg: TpmiAlgHash,
) -> Handle {
    let mut attrs = TpmaObject::SIGN_ENCRYPT
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::FIXED_PARENT
        | TpmaObject::FIXED_TPM;
    if is_restricted {
        attrs |= TpmaObject::RESTRICTED;
    }
    let public_area = TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme,
                key_bits: TpmiRsaKeyBits(1024),
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
fn test_rh_null_privacy_admin() {
    let mut sim = create_simulator!();
    let scheme = Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256));
    let key_handle = create_test_key(&mut sim, &[], scheme, false, TpmiAlgHash::Sha256);

    let get_time_cmd = GetTime {
        qualifying_data: Tpm2bData::from_bytes(b"data").unwrap(),
        in_scheme: None,
    };

    // Per TPM 2.0 Spec Part 3 Section 18.7, privacyAdminHandle has type TPMI_RH_ENDORSEMENT
    // (non-nullable). Passing TPM_RH_NULL, TPM_RH_OWNER, or TPM_RH_PLATFORM must fail
    // during handle unmarshalling with TPM_RC_VALUE + TPM_RC_H + TPM_RC_1 (0x184).
    for bad_privacy_handle in [Handle::RH_NULL, Handle::RH_OWNER, Handle::RH_PLATFORM] {
        let get_time_handles = GetTimeHandles {
            privacy_admin_handle: bad_privacy_handle,
            sign_handle: key_handle,
        };

        let resp = execute_with_password_sessions_status(
            &mut sim,
            &get_time_cmd,
            get_time_handles,
            1,
            &[],
        );
        assert_eq!(
            resp,
            Err(0x184),
            "GetTime must reject non-endorsement privacy_admin_handle {bad_privacy_handle:?} with 0x184"
        );
    }
}

#[test]
fn test_rh_null_sign_handle() {
    let mut sim = create_simulator!();

    let get_time_cmd = GetTime {
        qualifying_data: Tpm2bData::from_bytes(b"data").unwrap(),
        in_scheme: None,
    };

    let get_time_handles = GetTimeHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle::RH_NULL,
    };

    // signHandle has the USER auth role even when it is TPM_RH_NULL, so C
    // requires a session for it too (SessionProcess.c:1641-1651): 2 sessions.
    let mut resp_buffer = [0u8; 4096];
    let (resp, _) = execute_get_time(
        &mut sim,
        &get_time_cmd,
        get_time_handles,
        2,
        &[],
        &mut resp_buffer,
    )
    .unwrap();

    // Check that signature is Null (None)
    assert!(resp.signature.is_none(), "Expected None signature");
}
