use crate::test_utils::{execute_with_password_sessions, flush_context};
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, ReadPublic, ReadPublicHandles};
use tpm2::{Handle, TpmEccCurve};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bName, Tpm2bSensitiveData,
    TpmaObject, TpmiAlgHash, TpmiAlgSymMode, TpmsEccParms, TpmsEccPoint, TpmsSensitiveCreate,
    TpmtEccScheme, TpmtPublic, TpmtSymDefObject,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

use crate::test_utils::{execute_with_hmac_sessions, start_auth_session};
use tpm2::TpmSe;
use tpm2::TpmaSession;

/// go-tpm's `ECCSRKTemplate`.
fn ecc_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
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
                x: Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
            },
        ),
    }
}

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
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[])
            .expect("CreatePrimary failed");

    let object_handle = create_rsp_handles.object_handle;

    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };

    let (read_rsp, _) = execute_with_password_sessions(&mut sim, &read_cmd, read_handles, 0, &[])
        .expect("ReadPublic failed");

    let out_pub_create = create_rsp.out_public.0;
    let out_pub_read = read_rsp.out_public.0;

    // The Go test compares only the X coordinate of the unique field.
    match (out_pub_create.parms_and_id, out_pub_read.parms_and_id) {
        (PublicParmsAndId::Ecc(_, pt_create), PublicParmsAndId::Ecc(_, pt_read)) => {
            assert_eq!(
                pt_create.x.get_buffer(),
                pt_read.x.get_buffer(),
                "Mismatch between public returned from CreatePrimary & ReadPublic"
            );
        }
        _ => panic!("Expected ECC public keys"),
    }

    flush_context(&mut sim, object_handle).unwrap();
}

/// Shared setup of the `TestReadPublicWithHMACSession` subtests: creates an
/// owner primary key from go-tpm's `ECCSRKTemplate` and returns its handle and
/// name.
fn read_public_with_hmac_session_setup(sim: &mut Simulator<'_>) -> (Handle, Tpm2bName<'static>) {
    let create_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(ecc_srk_template()),
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (create_rsp, create_rsp_handles) =
        execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[])
            .expect("CreatePrimary failed");
    (create_rsp_handles.object_handle, create_rsp.name)
}

// Original Go test: read_public_test.go - TestReadPublicWithHMACSession/ReadPublic with HMAC session
#[test]
fn test_read_public_with_hmac_session_read_public_with_hmac_session() {
    let mut sim = create_simulator!();
    let (object_handle, name) = read_public_with_hmac_session_setup(&mut sim);

    // HMAC(TPMAlgSHA256, 16, AESEncryption(128, EncryptOut)): a one-off,
    // unbound, unsalted HMAC session encrypting the response parameter.
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
    .expect("ReadPublic failed");

    flush_context(&mut sim, object_handle).expect("FlushContext failed");
}

// Original Go test: read_public_test.go - TestReadPublicWithHMACSession/ReadPublic without HMAC session
#[test]
fn test_read_public_with_hmac_session_read_public_without_hmac_session() {
    let mut sim = create_simulator!();
    let (object_handle, _name) = read_public_with_hmac_session_setup(&mut sim);

    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };

    execute_with_password_sessions(&mut sim, &read_cmd, read_handles, 0, &[])
        .expect("ReadPublic failed");

    flush_context(&mut sim, object_handle).expect("FlushContext failed");
}
