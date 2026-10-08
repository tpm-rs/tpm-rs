use crate::test_utils::{execute_with_password_sessions, flush_context};
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, ReadPublic, ReadPublicHandles};
use tpm2::{Handle, TpmEccCurve};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bSensitiveData, TpmaObject,
    TpmiAlgHash, TpmiAlgSymMode, TpmsEccParms, TpmsEccPoint, TpmsSensitiveCreate, TpmtEccScheme,
    TpmtPublic, TpmtSymDefObject,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

use crate::test_utils::{execute_with_hmac_sessions, start_auth_session};
use tpm2::TpmSe;
use tpm2::TpmaSession;

// Original Go test: read_public_test.go - TestReadPublicKey
#[test]
fn test_read_public_key() {
    let mut sim = create_simulator!();

    // Create ECC key template
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (create_rsp, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 0, &[]).unwrap();

    let object_handle = create_rsp_handles.object_handle;

    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };

    let (read_rsp, _) =
        execute_with_password_sessions(&mut sim, &read_cmd, read_handles, 0, &[]).unwrap();

    let out_pub_create = create_rsp.out_public.0;
    let out_pub_read = read_rsp.out_public.0;

    match (out_pub_create.parms_and_id, out_pub_read.parms_and_id) {
        (PublicParmsAndId::Ecc(_, pt_create), PublicParmsAndId::Ecc(_, pt_read)) => {
            assert_eq!(pt_create.x.get_buffer(), pt_read.x.get_buffer());
            assert_eq!(pt_create.y.get_buffer(), pt_read.y.get_buffer());
        }
        _ => panic!("Expected ECC public keys"),
    }

    flush_context(&mut sim, object_handle).unwrap();
}

// Original Go test: read_public_test.go - TestReadPublicWithHMACSession/ReadPublic with HMAC session
#[test]
fn test_read_public_with_hmac_session() {
    let mut sim = create_simulator!();

    // Standard SRK ECC Template
    let ecc_parms = TpmsEccParms {
        symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (create_rsp, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 0, &[]).unwrap();

    let object_handle = create_rsp_handles.object_handle;
    let name = create_rsp.name;

    let sym_def = Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)));
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        sym_def,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    session.attributes.insert(TpmaSession::ENCRYPT); // Encrypt output parameter (response)

    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };

    execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[name.get_buffer()],
        &mut [session],
        &[&[]],
    )
    .unwrap();

    flush_context(&mut sim, object_handle).unwrap();
}

// Original Go test: read_public_test.go - TestReadPublicWithHMACSession/ReadPublic without HMAC session
#[test]
fn test_read_public_with_password_session() {
    let mut sim = create_simulator!();

    // Standard SRK ECC Template
    let ecc_parms = TpmsEccParms {
        symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (_create_rsp, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 0, &[]).unwrap();

    let object_handle = create_rsp_handles.object_handle;

    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };

    let (_read_rsp, _) =
        execute_with_password_sessions(&mut sim, &read_cmd, read_handles, 0, &[]).unwrap();

    flush_context(&mut sim, object_handle).unwrap();
}
