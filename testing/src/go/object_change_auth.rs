#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::{
    Create, CreateHandles, CreateLoaded, CreateLoadedHandles, Load, LoadHandles, ObjectChangeAuth,
    ObjectChangeAuthHandles, Unseal, UnsealHandles,
};
use tpm2::*;
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

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
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

// TC-1.1: Password Rotation on Sealed Data Object (Happy Path)
// Original Go test: object_change_auth_test.go - TestObjectChangeAuth
#[test]
fn test_object_change_auth_sealed_data() {
    let mut sim = create_simulator!();

    // 1. Create the SRK (Parent key)
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let create_srk_handles = CreateLoadedHandles {
        parent_handle: Handle::RH_OWNER,
    };
    let (_, srk_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, create_srk_handles, 1, &[])
            .expect("could not generate SRK");
    let srk_handle = srk_resp_handles.object_handle;

    // 2. Create the sealed data object under the SRK
    let data = b"secrets";
    let auth = b"oldauth";
    let newauth = b"newauth";

    let sealed_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
        data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
    };
    let in_sensitive = tpm2::Tpm2b(sealed_sensitive);
    let sealed_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    };
    let in_public = tpm2::Tpm2b(sealed_public);
    let create_cmd = Create {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_handles = CreateHandles {
        parent_handle: srk_handle,
    };
    let (create_rsp, _) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[])
            .expect("failed to create sealed data");

    // 3. Load the sealed blob
    let load_cmd = Load {
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_handles = LoadHandles {
        parent_handle: srk_handle,
    };
    let (_, load_resp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[])
            .expect("failed to load sealed data");
    let blob_handle = load_resp_handles.object_handle;

    // 4. Verify unsealing with "oldauth" password session succeeds
    let unseal_cmd = Unseal {};
    let unseal_handles = UnsealHandles {
        item_handle: blob_handle,
    };
    let (unseal_rsp, _) =
        execute_with_password_sessions(&mut sim, &unseal_cmd, unseal_handles, 1, auth)
            .expect("unseal with old auth failed");
    assert_eq!(unseal_rsp.out_data.get_buffer(), data);

    // 5. Change authorization to "newauth"
    let oca_cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(newauth).unwrap(),
    };
    let oca_handles = ObjectChangeAuthHandles {
        object_handle: blob_handle,
        parent_handle: srk_handle,
    };
    let (oca_rsp, _) = execute_with_password_sessions(&mut sim, &oca_cmd, oca_handles, 1, auth)
        .expect("ObjectChangeAuth failed");

    // 6. Flush the old handle and load the new private area
    flush_context(&mut sim, blob_handle).unwrap();

    let load_new_cmd = Load {
        in_private: oca_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_new_handles = LoadHandles {
        parent_handle: srk_handle,
    };
    let (_, load_new_resp_handles) =
        execute_with_password_sessions(&mut sim, &load_new_cmd, load_new_handles, 1, &[]).unwrap();
    let new_blob_handle = load_new_resp_handles.object_handle;

    // 7. Verify unsealing with "oldauth" fails with TPM_RC_BAD_AUTH
    let unseal_handles_new = UnsealHandles {
        item_handle: new_blob_handle,
    };
    let unseal_err =
        execute_with_password_sessions(&mut sim, &unseal_cmd, unseal_handles_new, 1, auth)
            .unwrap_err();
    assert_eq!(
        unseal_err, 0x9A2,
        "Expected TPM_RC_BAD_AUTH (0x9A2) on session 1"
    );

    // 8. Verify unsealing with "newauth" succeeds
    let (unseal_rsp2, _) =
        execute_with_password_sessions(&mut sim, &unseal_cmd, unseal_handles_new, 1, newauth)
            .expect("unseal with new auth failed");
    assert_eq!(unseal_rsp2.out_data.get_buffer(), data);

    flush_context(&mut sim, new_blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}
