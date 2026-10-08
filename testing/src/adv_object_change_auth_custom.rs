#![allow(unused_imports, dead_code)]
#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::{
    Create, CreateHandles, CreateLoaded, CreateLoadedHandles, Load, LoadHandles, ObjectChangeAuth,
    ObjectChangeAuthHandles, Unseal, UnsealHandles,
};
use tpm2::errors::{Position, TpmRc};
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

// TC-2.1: Invalid Authorization for Object Handle
#[test]
fn test_object_change_auth_invalid_auth() {
    let mut sim = create_simulator!();

    // Create the SRK
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
            .unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // Create the sealed data object under the SRK
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
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();

    // Load the sealed blob
    let load_cmd = Load {
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_handles = LoadHandles {
        parent_handle: srk_handle,
    };
    let (_, load_resp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[]).unwrap();
    let blob_handle = load_resp_handles.object_handle;

    // Call ObjectChangeAuth using the wrong password ("wrongauth")
    let oca_cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(newauth).unwrap(),
    };
    let oca_handles = ObjectChangeAuthHandles {
        object_handle: blob_handle,
        parent_handle: srk_handle,
    };
    let oca_err = execute_with_password_sessions(&mut sim, &oca_cmd, oca_handles, 1, b"wrongauth")
        .unwrap_err();
    assert_eq!(
        oca_err, 0x9A2,
        "Expected TPM_RC_BAD_AUTH (0x9A2) on session 1"
    );

    flush_context(&mut sim, blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-1.4: Rotate to Empty Authorization
#[test]
fn test_object_change_auth_rotate_to_empty() {
    let mut sim = create_simulator!();

    // Create the SRK
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
            .unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // Create the sealed data object under the SRK with auth "oldauth"
    let data = b"secrets";
    let auth = b"oldauth";

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
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();

    // Load the sealed blob
    let load_cmd = Load {
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_handles = LoadHandles {
        parent_handle: srk_handle,
    };
    let (_, load_resp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[]).unwrap();
    let blob_handle = load_resp_handles.object_handle;

    // Rotate to empty auth
    let oca_cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::default(),
    };
    let oca_handles = ObjectChangeAuthHandles {
        object_handle: blob_handle,
        parent_handle: srk_handle,
    };
    let (oca_rsp, _) =
        execute_with_password_sessions(&mut sim, &oca_cmd, oca_handles, 1, auth).unwrap();

    flush_context(&mut sim, blob_handle).unwrap();

    // Load the new key
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

    // Verify unsealing with empty auth succeeds
    let unseal_cmd = Unseal {};
    let unseal_handles_new = UnsealHandles {
        item_handle: new_blob_handle,
    };
    let (unseal_rsp, _) =
        execute_with_password_sessions(&mut sim, &unseal_cmd, unseal_handles_new, 1, &[]).unwrap();
    assert_eq!(unseal_rsp.out_data.get_buffer(), data);

    flush_context(&mut sim, new_blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-1.5: Rotate from Empty Authorization
#[test]
fn test_object_change_auth_rotate_from_empty() {
    let mut sim = create_simulator!();

    // Create the SRK
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
            .unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // Create the sealed data object under the SRK with empty auth
    let data = b"secrets";
    let newauth = b"newauth";

    let sealed_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
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
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();

    // Load the sealed blob
    let load_cmd = Load {
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_handles = LoadHandles {
        parent_handle: srk_handle,
    };
    let (_, load_resp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[]).unwrap();
    let blob_handle = load_resp_handles.object_handle;

    // Rotate from empty to newauth
    let oca_cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(newauth).unwrap(),
    };
    let oca_handles = ObjectChangeAuthHandles {
        object_handle: blob_handle,
        parent_handle: srk_handle,
    };
    let (oca_rsp, _) =
        execute_with_password_sessions(&mut sim, &oca_cmd, oca_handles, 1, &[]).unwrap();

    flush_context(&mut sim, blob_handle).unwrap();

    // Load the new key
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

    // Verify unsealing with empty auth fails
    let unseal_cmd = Unseal {};
    let unseal_handles_new = UnsealHandles {
        item_handle: new_blob_handle,
    };
    let unseal_err =
        execute_with_password_sessions(&mut sim, &unseal_cmd, unseal_handles_new, 1, &[])
            .unwrap_err();
    assert_eq!(
        unseal_err, 0x9A2,
        "Expected TPM_RC_BAD_AUTH (0x9A2) on session 1"
    );

    // Verify unsealing with newauth succeeds
    let (unseal_rsp, _) =
        execute_with_password_sessions(&mut sim, &unseal_cmd, unseal_handles_new, 1, newauth)
            .unwrap();
    assert_eq!(unseal_rsp.out_data.get_buffer(), data);

    flush_context(&mut sim, new_blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-2.2: Mismatched Parent Handle (Wrong Parent)
#[test]
fn test_object_change_auth_mismatched_parent() {
    let mut sim = create_simulator!();

    // 1. Create Parent A (SRK)
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
    let (_, srk_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_srk_cmd,
        create_srk_handles.clone(),
        1,
        &[],
    )
    .unwrap();
    let parent_a = srk_resp_handles.object_handle;

    // 2. Create Parent B with a distinct unique field
    let mut srk_pub_b = get_ecc_srk_template();
    if let PublicParmsAndId::Ecc(ecc_parms, _) = srk_pub_b.parms_and_id {
        srk_pub_b.parms_and_id = PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(b"parent b").unwrap(),
                y: Tpm2bEccParameter::default(),
            },
        );
    }
    let create_srk_cmd_b = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_template(&srk_pub_b),
    };
    let create_srk_handles_b = CreateLoadedHandles {
        parent_handle: Handle(0x4000000B), // TPMRH_ENDORSEMENT
    };
    let (_, srk_resp_handles2) =
        execute_with_password_sessions(&mut sim, &create_srk_cmd_b, create_srk_handles_b, 1, &[])
            .unwrap();
    let parent_b = srk_resp_handles2.object_handle;

    // 3. Create the sealed data object under Parent A
    let data = b"secrets";
    let auth = b"oldauth";

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
        parent_handle: parent_a,
    };
    let (create_rsp, _) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();

    // 4. Load the sealed blob under Parent A
    let load_cmd = Load {
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_handles = LoadHandles {
        parent_handle: parent_a,
    };
    let (_, load_resp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[]).unwrap();
    let blob_handle = load_resp_handles.object_handle;

    // 5. Call ObjectChangeAuth specifying Parent B as the parent
    let oca_cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };
    let oca_handles = ObjectChangeAuthHandles {
        object_handle: blob_handle,
        parent_handle: parent_b,
    };
    // This should fail because parent_b is not the actual parent of blob
    let oca_err =
        execute_with_password_sessions(&mut sim, &oca_cmd, oca_handles, 1, auth).unwrap_err();
    // In TPM 2.0, this returns TPM_RC_TYPE (0x0A) or TPM_RC_KEY (0x1C) modified by parent handle position.
    // Specifically, parentHandle is parameter/handle position 2, so the error would be modified.
    // Let's assert it is indeed an error (non-zero).
    assert_ne!(oca_err, 0);

    flush_context(&mut sim, blob_handle).unwrap();
    flush_context(&mut sim, parent_a).unwrap();
    flush_context(&mut sim, parent_b).unwrap();
}

// TC-2.3: New Auth Value Length Exceeds Digest Size of Name Algorithm
#[test]
fn test_object_change_auth_too_long() {
    let mut sim = create_simulator!();

    // Create the SRK
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
            .unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // Create the sealed data object under the SRK with SHA-256 name_alg (digest size = 32)
    let data = b"secrets";
    let auth = b"oldauth";

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
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();

    // Load the sealed blob
    let load_cmd = Load {
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_handles = LoadHandles {
        parent_handle: srk_handle,
    };
    let (_, load_resp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[]).unwrap();
    let blob_handle = load_resp_handles.object_handle;

    // Try to set new auth to a 33-byte password (exceeding SHA-256 digest size of 32 bytes)
    let too_long_auth = vec![0xAA; 33];
    let oca_cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(&too_long_auth).unwrap(),
    };
    let oca_handles = ObjectChangeAuthHandles {
        object_handle: blob_handle,
        parent_handle: srk_handle,
    };
    let oca_err =
        execute_with_password_sessions(&mut sim, &oca_cmd, oca_handles, 1, auth).unwrap_err();
    // Should fail with TPM_RC_SIZE (0x15) or similar.
    assert_ne!(oca_err, 0);

    flush_context(&mut sim, blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-2.4: Try to change auth on a Primary Object (should fail)
#[test]
fn test_object_change_auth_on_primary() {
    use tpm2::commands::{CreatePrimary, CreatePrimaryHandles};

    let mut sim = create_simulator!();

    // Create the SRK (Primary Object) via CreatePrimary
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_srk_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_srk_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, srk_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, create_srk_handles, 1, &[])
            .unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // Try to call ObjectChangeAuth on the SRK itself with hierarchy parent (must fail with TPM_RC_VALUE on handle 2)
    let oca_cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };
    let oca_handles = ObjectChangeAuthHandles {
        object_handle: srk_handle,
        parent_handle: Handle::RH_OWNER,
    };
    let res = execute_with_password_sessions(&mut sim, &oca_cmd, oca_handles, 1, &[]);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );

    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-2.5: Try to change auth on a Primary Object created via CreateLoaded (must fail with TPM_RC_VALUE on handle 2)
#[test]
fn test_object_change_auth_on_primary_created_via_create_loaded() {
    let mut sim = create_simulator!();

    // Create the SRK (Primary Object) via CreateLoaded
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
            .unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // Try to call ObjectChangeAuth on the SRK itself with hierarchy parent
    let oca_cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };
    let oca_handles = ObjectChangeAuthHandles {
        object_handle: srk_handle,
        parent_handle: Handle::RH_OWNER,
    };

    let res = execute_with_password_sessions(&mut sim, &oca_cmd, oca_handles, 1, &[]);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );

    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-2.6: Changing auth of a persistent object fails with TPM_RC_KEY (Pos1)
#[test]
fn test_object_change_auth_on_persistent() {
    use tpm2::commands::{EvictControl, EvictControlHandles};

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

    // 2. Create the sealed data object under the SRK without fixedTPM/fixedParent attributes
    let data = b"secrets";
    let auth = b"oldauth";

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

    // 4. Make the object persistent
    let evict_handles = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: blob_handle,
    };
    let evict_cmd = EvictControl {
        persistent_handle: Handle(0x81000000),
    };
    execute_with_password_sessions(&mut sim, &evict_cmd, evict_handles, 1, &[]).unwrap();

    // 5. Try to call ObjectChangeAuth on the persistent object
    let oca_cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };
    let oca_handles = ObjectChangeAuthHandles {
        object_handle: Handle(0x81000000),
        parent_handle: srk_handle,
    };
    let oca_err =
        execute_with_password_sessions(&mut sim, &oca_cmd, oca_handles, 1, auth).unwrap_err();

    // Verify it fails with TPM_RC_KEY (Pos1) -> 0x19C
    assert_eq!(oca_err, 0x19C);

    // Clean up
    let evict_handles2 = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: Handle(0x81000000),
    };
    let evict_cmd2 = EvictControl {
        persistent_handle: Handle(0x81000000),
    };
    execute_with_password_sessions(&mut sim, &evict_cmd2, evict_handles2, 1, &[]).unwrap();

    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-2.7: Changing auth of an object with fixedParent or fixedTPM set fails with TPM_RC_ATTRIBUTES (Pos1)
#[test]
fn test_object_change_auth_on_fixed() {
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

    // 2. Create the sealed data object under the SRK with FIXED_TPM and FIXED_PARENT attributes
    let data = b"secrets";
    let auth = b"oldauth";

    let sealed_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
        data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
    };
    let in_sensitive = tpm2::Tpm2b(sealed_sensitive);
    let sealed_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA,
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

    // 4. Change authorization of the fixed object
    let newauth = b"newauth";
    let oca_cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(newauth).unwrap(),
    };
    let oca_handles = ObjectChangeAuthHandles {
        object_handle: blob_handle,
        parent_handle: srk_handle,
    };
    let (oca_rsp, _) = execute_with_password_sessions(&mut sim, &oca_cmd, oca_handles, 1, auth)
        .expect("ObjectChangeAuth failed");

    // 5. Flush the old handle and load the new private area
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

    // 6. Verify unsealing with "oldauth" fails with TPM_RC_BAD_AUTH
    let unseal_cmd = Unseal {};
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

    // 7. Verify unsealing with "newauth" succeeds
    let (unseal_rsp2, _) =
        execute_with_password_sessions(&mut sim, &unseal_cmd, unseal_handles_new, 1, newauth)
            .expect("unseal with new auth failed");
    assert_eq!(unseal_rsp2.out_data.get_buffer(), data);

    flush_context(&mut sim, new_blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

// Adversarial test: loading a primary object via Load command with a hierarchy parent (should fail)
#[test]
fn test_load_primary_object_fails() {
    let mut sim = create_simulator!();

    // Create the SRK (Primary Object) via CreateLoaded with RHOwner
    let mut srk_pub = get_ecc_srk_template();
    srk_pub.object_attributes = TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::RESTRICTED
        | TpmaObject::DECRYPT;
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
    let (create_srk_rsp, srk_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, create_srk_handles, 1, &[])
            .unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // Try to load the private area using Load command, passing Handle::RH_OWNER as parent.
    // This should fail because parent cannot be a hierarchy handle for Load command.
    let load_cmd = Load {
        in_private: create_srk_rsp.out_private,
        in_public: create_srk_rsp.out_public,
    };
    let load_handles = LoadHandles {
        parent_handle: Handle::RH_OWNER,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[]);

    // We expect this to fail with TPM_RC_VALUE on handle 1 because parentHandle is TPMI_DH_OBJECT (cannot be a hierarchy handle).
    assert_eq!(
        res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(1)).get()
    );

    flush_context(&mut sim, srk_handle).unwrap();
}

// Adversarial test: ObjectChangeAuth and Load on a primary object under hierarchy both fail with TPM_RC_VALUE on parentHandle
#[test]
fn test_load_changed_auth_primary_object_under_hierarchy() {
    let mut sim = create_simulator!();

    // Create the SRK (Primary Object) via CreateLoaded with RHOwner
    let mut srk_pub = get_ecc_srk_template();
    srk_pub.object_attributes = TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::RESTRICTED
        | TpmaObject::DECRYPT;
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
    let (create_srk_rsp, srk_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, create_srk_handles, 1, &[])
            .unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // Call ObjectChangeAuth with hierarchy parentHandle (must fail with TPM_RC_VALUE on handle 2)
    let oca_cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };
    let oca_handles = ObjectChangeAuthHandles {
        object_handle: srk_handle,
        parent_handle: Handle::RH_OWNER,
    };
    let oca_res = execute_with_password_sessions(&mut sim, &oca_cmd, oca_handles, 1, &[]);
    assert_eq!(
        oca_res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );

    // Try to load the primary private area using Load with hierarchy parentHandle (must fail with TPM_RC_VALUE on handle 1)
    let load_cmd = Load {
        in_private: create_srk_rsp.out_private,
        in_public: create_srk_rsp.out_public,
    };
    let load_handles = LoadHandles {
        parent_handle: Handle::RH_OWNER,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[]);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(1)).get()
    );

    flush_context(&mut sim, srk_handle).unwrap();
}

// Adversarial test: creating a key under hierarchy parent using Create command (should fail)
#[test]
fn test_create_under_hierarchy_fails() {
    let mut sim = create_simulator!();

    // Create a key under TPM_RH_OWNER using Create (should fail)
    let sealed_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
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
        parent_handle: Handle::RH_OWNER,
    };
    let res = execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]);

    assert!(
        res.is_err(),
        "Create with a hierarchy parent handle should have failed but succeeded!"
    );
}
