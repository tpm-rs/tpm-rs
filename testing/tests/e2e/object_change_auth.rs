//! TPM2_ObjectChangeAuth: parent/object handle checks, authorization and use of the new auth.

use crate::_common::{command_rc as rc_of, *};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{
    Certify, Create, CreateLoaded, FlushContext, HashSequenceStart, Load, ObjectChangeAuth, Unseal,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

// TC-2.5: Try to change auth on a Primary Object created via CreateLoaded (must fail with TPM_RC_VALUE on handle 2)
/// ObjectChangeAuth on a primary created by CreateLoaded fails with TPM_RC_VALUE + H2.
#[test]
#[allow(deprecated)]
fn create_loaded_primary_rejected() {
    let mut sim = Tpm::new();

    // Create the SRK (Primary Object) via CreateLoaded
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let srk_resp_handles =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // Try to call ObjectChangeAuth on the SRK itself with hierarchy parent
    let oca_cmd = ObjectChangeAuth {
        object_handle: srk_handle,
        parent_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };

    let res = execute_with_password_sessions(&mut sim, &oca_cmd, 1, &[]);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );

    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-2.7: Changing auth of an object with fixedParent or fixedTPM set fails with TPM_RC_ATTRIBUTES (Pos1)
/// A fixedTPM/fixedParent sealed object's auth can change; old auth then fails and new auth unseals.
#[test]
#[allow(deprecated)]
fn fixed_object_auth_changes() {
    let mut sim = Tpm::new();

    // 1. Create the SRK (Parent key)
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let srk_resp_handles = execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[])
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
        parent_handle: srk_handle,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[])
        .expect("failed to create sealed data");

    // 3. Load the sealed blob
    let load_cmd = Load {
        parent_handle: srk_handle,
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_resp_handles = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[])
        .expect("failed to load sealed data");
    let blob_handle = load_resp_handles.object_handle;

    // 4. Change authorization of the fixed object
    let newauth = b"newauth";
    let oca_cmd = ObjectChangeAuth {
        object_handle: blob_handle,
        parent_handle: srk_handle,
        new_auth: Tpm2bAuth::from_bytes(newauth).unwrap(),
    };
    let oca_rsp = execute_with_password_sessions(&mut sim, &oca_cmd, 1, auth)
        .expect("ObjectChangeAuth failed");

    // 5. Flush the old handle and load the new private area
    flush_context(&mut sim, blob_handle).unwrap();

    let load_new_cmd = Load {
        parent_handle: srk_handle,
        in_private: oca_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_new_resp_handles =
        execute_with_password_sessions(&mut sim, &load_new_cmd, 1, &[]).unwrap();
    let new_blob_handle = load_new_resp_handles.object_handle;

    // 6. Verify unsealing with "oldauth" fails with TPM_RC_BAD_AUTH
    let unseal_cmd = Unseal {
        item_handle: new_blob_handle,
    };
    let unseal_err = execute_with_password_sessions(&mut sim, &unseal_cmd, 1, auth).unwrap_err();
    assert_eq!(
        unseal_err, 0x9A2,
        "Expected TPM_RC_BAD_AUTH (0x9A2) on session 1"
    );

    // 7. Verify unsealing with "newauth" succeeds
    let unseal_rsp2 = execute_with_password_sessions(&mut sim, &unseal_cmd, 1, newauth)
        .expect("unseal with new auth failed");
    assert_eq!(unseal_rsp2.out_data.get_buffer(), data);

    flush_context(&mut sim, new_blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

/// ObjectChangeAuth with a parent that is not the object parent fails.
#[test]
fn mismatched_parent_handle_rejected() {
    let mut sim = Tpm::new();
    let parent_handle = create_storage_parent(&mut sim, Handle::RH_OWNER);
    let object_handle =
        create_and_load_child(&mut sim, parent_handle, keyed_hash_template(), b"oldauth");
    // A different storage key (primary seeds differ per hierarchy, so its Name differs).
    let wrong_parent_handle = create_storage_parent(&mut sim, Handle::RH_ENDORSEMENT);

    let cmd = ObjectChangeAuth {
        object_handle,
        parent_handle: wrong_parent_handle,
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };

    let res = execute_tpm_command(&mut sim, &cmd, &[password_auth(b"oldauth")]);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::TYPE.with(Position::handle(2)).get()
    );
}

// TC-2.3: New Auth Value Length Exceeds Digest Size of Name Algorithm
/// A new auth longer than the nameAlg digest (33 bytes for SHA-256) is rejected.
#[test]
#[allow(deprecated)]
fn new_auth_longer_than_name_alg_digest_rejected() {
    let mut sim = Tpm::new();

    // Create the SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let srk_resp_handles =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
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
        parent_handle: srk_handle,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();

    // Load the sealed blob
    let load_cmd = Load {
        parent_handle: srk_handle,
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_resp_handles = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]).unwrap();
    let blob_handle = load_resp_handles.object_handle;

    // Try to set new auth to a 33-byte password (exceeding SHA-256 digest size of 32 bytes)
    let too_long_auth = vec![0xAA; 33];
    let oca_cmd = ObjectChangeAuth {
        object_handle: blob_handle,
        parent_handle: srk_handle,
        new_auth: Tpm2bAuth::from_bytes(&too_long_auth).unwrap(),
    };
    let oca_err = execute_with_password_sessions(&mut sim, &oca_cmd, 1, auth).unwrap_err();
    // Should fail with TPM_RC_SIZE (0x15) or similar.
    assert_ne!(oca_err, 0);

    flush_context(&mut sim, blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

// object-change-auth-validation-order-and-non-storage-parent-error-code
/// ObjectChangeAuth: newAuth size is checked before the parent; non-storage parent is TYPE+H2; correct parent works.
#[test]
fn new_auth_size_checked_before_parent_type() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let (obj, _) = create_and_load(
        &mut sim,
        srk,
        sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        b"x",
    );
    let (signer, _) = create_and_load(
        &mut sim,
        srk,
        ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    );
    let oca = |sim: &mut Tpm, parent: Handle, auth: &[u8]| {
        rc_of(
            sim,
            &ObjectChangeAuth {
                object_handle: obj,
                parent_handle: parent,
                new_auth: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
            },
            1,
        )
    };
    // A non-storage parentHandle is blamed on handle 2.
    assert_eq!(oca(&mut sim, signer, b"new"), rc_h(TpmRc::TYPE, 2));
    // newAuth size is checked before the parent.
    assert_eq!(oca(&mut sim, signer, &[7u8; 33]), rc_p(TpmRc::SIZE, 1));
    // Correct parent works.
    assert_eq!(oca(&mut sim, srk, b"new"), 0);
}

/// ObjectChangeAuth returns a new private area that loads with the unchanged public area and same Name.
#[test]
fn new_private_keeps_name() {
    let mut sim = Tpm::new();
    let parent_handle = create_storage_parent(&mut sim, Handle::RH_OWNER);

    let (private, public) =
        create_child(&mut sim, parent_handle, rsa_signing_template(), b"oldauth");
    let (object_handle, obj_name) = load_child(&mut sim, parent_handle, private, public);

    let cmd = ObjectChangeAuth {
        object_handle,
        parent_handle,
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };
    let rsp = execute_tpm_command(&mut sim, &cmd, &[password_auth(b"oldauth")]).unwrap();

    let flush_cmd = FlushContext {
        flush_handle: object_handle,
    };
    execute_tpm_command(&mut sim, &flush_cmd, &[]).unwrap();

    // Load the new private area with the unchanged public area: the Name is the same.
    let (new_handle, new_name) = load_child(&mut sim, parent_handle, rsp.out_private, public);
    assert_eq!(new_name, obj_name);

    let target_handle = create_and_load_child(&mut sim, parent_handle, keyed_hash_template(), &[]);

    let certify_cmd = Certify {
        object_handle: target_handle,
        sign_handle: new_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let certify_res = execute_tpm_command(
        &mut sim,
        &certify_cmd,
        &[password_auth(b""), password_auth(b"newauth")],
    );
    if let Err(e) = certify_res {
        panic!(
            "Failed to authenticate with new auth value! Error: 0x{:X}",
            e
        );
    }
}

// tpm2-objectchangeauth-handle2-error-positions-and-seedvalue-corruption
/// ObjectChangeAuth with a signing parent is TYPE+H2; a SHA-512 sealed object keeps its 64-byte seed and unseals after reload.
#[test]
fn non_storage_parent_and_sha512_seed_preserved() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    // SHA-512 sealed object: the re-encrypted sensitive area must keep the 64-byte seedValue,
    // otherwise the reloaded object fails its binding check.
    let (obj, obj_rsp) = create_and_load(
        &mut sim,
        srk,
        sealed_template(TpmiAlgHash::Sha512, TpmaObject::empty()),
        &[],
        b"payload",
    );
    let (signer, _) = create_and_load(
        &mut sim,
        srk,
        ecc_sign_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        &[],
        &[],
    );
    let run_oca = |sim: &mut Tpm, parent: Handle| {
        run(
            sim,
            &ObjectChangeAuth {
                object_handle: obj,
                parent_handle: parent,
                new_auth: Tpm2bAuth::from_bytes(b"pw").unwrap(),
            },
            1,
        )
    };
    assert_eq!(run_oca(&mut sim, signer).unwrap_err(), rc_h(TpmRc::TYPE, 2));
    let rsp = run_oca(&mut sim, srk).unwrap();
    let reloaded = load(&mut sim, srk, rsp.out_private, obj_rsp.out_public).expect("Load");
    let unsealed = execute_with_password_sessions(
        &mut sim,
        &Unseal {
            item_handle: reloaded,
        },
        1,
        b"pw",
    )
    .unwrap();
    assert_eq!(unsealed.out_data.get_buffer(), b"payload");
}

/// ObjectChangeAuth with an NV index as objectHandle fails.
#[test]
fn nv_index_handle_rejected() {
    let mut sim = Tpm::new();

    let parent_handle = Handle(0x40000001);
    let object_handle = Handle(0x01400001); // NV Index

    let cmd = ObjectChangeAuth {
        object_handle,
        parent_handle,
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };

    let res = execute_tpm_command(&mut sim, &cmd, &[]);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(1)).get()
    );
}

/// ObjectChangeAuth with a newAuth larger than the nameAlg digest fails.
#[test]
fn oversized_new_auth_rejected() {
    let mut sim = Tpm::new();
    let parent_handle = create_storage_parent(&mut sim, Handle::RH_OWNER);
    let object_handle =
        create_and_load_child(&mut sim, parent_handle, keyed_hash_template(), b"oldauth");

    let cmd = ObjectChangeAuth {
        object_handle,
        parent_handle,
        new_auth: Tpm2bAuth::from_bytes(&[1u8; 33]).unwrap(),
    };

    let res = execute_tpm_command(&mut sim, &cmd, &[password_auth(b"oldauth")]);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::SIZE.with(Position::parameter(1)).get()
    );
}

// TC-2.6: Changing auth of a persistent object fails with TPM_RC_KEY (Pos1)
/// ObjectChangeAuth on a persistent object succeeds and returns a new private area (as in C).
#[test]
#[allow(deprecated)]
fn persistent_object_allowed() {
    use tpm2::commands::EvictControl;

    let mut sim = Tpm::new();

    // 1. Create the SRK (Parent key)
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let srk_resp_handles = execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[])
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
        parent_handle: srk_handle,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[])
        .expect("failed to create sealed data");

    // 3. Load the sealed blob
    let load_cmd = Load {
        parent_handle: srk_handle,
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_resp_handles = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[])
        .expect("failed to load sealed data");
    let blob_handle = load_resp_handles.object_handle;

    // 4. Make the object persistent
    let evict_cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: blob_handle,
        persistent_handle: Handle(0x81000000),
    };
    execute_with_password_sessions(&mut sim, &evict_cmd, 1, &[]).unwrap();

    // 5. Try to call ObjectChangeAuth on the persistent object
    let oca_cmd = ObjectChangeAuth {
        object_handle: Handle(0x81000000),
        parent_handle: srk_handle,
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };
    // C ObjectChangeAuth.c has no persistent-object restriction: the evict copy
    // is loaded like any object and a new private area is returned.
    let oca_rsp = execute_with_password_sessions(&mut sim, &oca_cmd, 1, auth)
        .expect("ObjectChangeAuth on a persistent object succeeds in C");
    assert!(oca_rsp.out_private.get_size() > 0);

    // Clean up
    let evict_cmd2 = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: Handle(0x81000000),
        persistent_handle: Handle(0x81000000),
    };
    execute_with_password_sessions(&mut sim, &evict_cmd2, 1, &[]).unwrap();

    flush_context(&mut sim, srk_handle).unwrap();
}

// tpm2-objectchangeauth-explicitly-rejects-persistent-objects
/// ObjectChangeAuth on a persistent object succeeds with a PolicyCommandCode admin policy; reloaded object unseals with new auth.
#[test]
fn persistent_object_with_admin_policy() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    // ADMIN role on a persistent object always needs a policy session (C
    // IsPolicySessionRequired), so the object's authPolicy is PolicyCommandCode(ObjectChangeAuth).
    let mut t = sealed_template(
        TpmiAlgHash::Sha256,
        TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
    );
    t.auth_policy = policy_command_code_digest(TpmiAlgHash::Sha256, TpmCc::ObjectChangeAuth);
    let (obj, obj_rsp) = create_and_load(&mut sim, srk, t, b"old", b"sealed");
    evict_control(&mut sim, Handle::RH_OWNER, obj, Handle(0x8100_0300)).unwrap();
    let sess = policy_command_code_session(&mut sim, TpmiAlgHash::Sha256, TpmCc::ObjectChangeAuth);
    let rsp = execute_with_hmac_sessions(
        &mut sim,
        &ObjectChangeAuth {
            object_handle: Handle(0x8100_0300),
            parent_handle: srk,
            new_auth: Tpm2bAuth::from_bytes(b"new").unwrap(),
        },
        &[],
        &mut [sess],
        &[&[]],
    )
    .expect("ObjectChangeAuth on a persistent object");
    let new_obj = load(&mut sim, srk, rsp.out_private, obj_rsp.out_public).unwrap();
    let unsealed = execute_with_password_sessions(
        &mut sim,
        &Unseal {
            item_handle: new_obj,
        },
        1,
        b"new",
    )
    .expect("Unseal with the new auth");
    assert_eq!(unsealed.out_data.get_buffer(), b"sealed");
}

// Adversarial test: ObjectChangeAuth and Load on a primary object under hierarchy both fail with TPM_RC_VALUE on parentHandle
/// ObjectChangeAuth (VALUE + H2) and Load (VALUE + H1) of a primary under a hierarchy parent both fail.
#[test]
#[allow(deprecated)]
fn primary_change_auth_and_load_under_hierarchy_rejected() {
    let mut sim = Tpm::new();

    // Create the SRK (Primary Object) via CreateLoaded with RHOwner
    let mut srk_pub = get_ecc_srk_template();
    srk_pub.object_attributes = TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::RESTRICTED
        | TpmaObject::DECRYPT;
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let create_srk_rsp = execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
    let srk_handle = create_srk_rsp.object_handle;

    // Call ObjectChangeAuth with hierarchy parentHandle (must fail with TPM_RC_VALUE on handle 2)
    let oca_cmd = ObjectChangeAuth {
        object_handle: srk_handle,
        parent_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };
    let oca_res = execute_with_password_sessions(&mut sim, &oca_cmd, 1, &[]);
    assert_eq!(
        oca_res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );

    // Try to load the primary private area using Load with hierarchy parentHandle (must fail with TPM_RC_VALUE on handle 1)
    let load_cmd = Load {
        parent_handle: Handle::RH_OWNER,
        in_private: create_srk_rsp.out_private,
        in_public: create_srk_rsp.out_public,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(1)).get()
    );

    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-2.4: Try to change auth on a Primary Object (should fail)
/// ObjectChangeAuth on a CreatePrimary object with a hierarchy parent fails with TPM_RC_VALUE + H2.
#[test]
fn primary_object_rejected() {
    use tpm2::commands::CreatePrimary;

    let mut sim = Tpm::new();

    // Create the SRK (Primary Object) via CreatePrimary
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_srk_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let srk_resp_handles =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // Try to call ObjectChangeAuth on the SRK itself with hierarchy parent (must fail with TPM_RC_VALUE on handle 2)
    let oca_cmd = ObjectChangeAuth {
        object_handle: srk_handle,
        parent_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };
    let res = execute_with_password_sessions(&mut sim, &oca_cmd, 1, &[]);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );

    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-1.5: Rotate from Empty Authorization
/// Changing a sealed object's empty auth to a new value makes empty-auth unseal fail.
#[test]
#[allow(deprecated)]
fn rotate_from_empty_auth() {
    let mut sim = Tpm::new();

    // Create the SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let srk_resp_handles =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
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
        parent_handle: srk_handle,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();

    // Load the sealed blob
    let load_cmd = Load {
        parent_handle: srk_handle,
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_resp_handles = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]).unwrap();
    let blob_handle = load_resp_handles.object_handle;

    // Rotate from empty to newauth
    let oca_cmd = ObjectChangeAuth {
        object_handle: blob_handle,
        parent_handle: srk_handle,
        new_auth: Tpm2bAuth::from_bytes(newauth).unwrap(),
    };
    let oca_rsp = execute_with_password_sessions(&mut sim, &oca_cmd, 1, &[]).unwrap();

    flush_context(&mut sim, blob_handle).unwrap();

    // Load the new key
    let load_new_cmd = Load {
        parent_handle: srk_handle,
        in_private: oca_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_new_resp_handles =
        execute_with_password_sessions(&mut sim, &load_new_cmd, 1, &[]).unwrap();
    let new_blob_handle = load_new_resp_handles.object_handle;

    // Verify unsealing with empty auth fails
    let unseal_cmd = Unseal {
        item_handle: new_blob_handle,
    };
    let unseal_err = execute_with_password_sessions(&mut sim, &unseal_cmd, 1, &[]).unwrap_err();
    assert_eq!(
        unseal_err, 0x9A2,
        "Expected TPM_RC_BAD_AUTH (0x9A2) on session 1"
    );

    // Verify unsealing with newauth succeeds
    let unseal_rsp = execute_with_password_sessions(&mut sim, &unseal_cmd, 1, newauth).unwrap();
    assert_eq!(unseal_rsp.out_data.get_buffer(), data);

    flush_context(&mut sim, new_blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-1.4: Rotate to Empty Authorization
/// Changing a sealed object's auth to empty lets it unseal with empty auth.
#[test]
#[allow(deprecated)]
fn rotate_to_empty_auth() {
    let mut sim = Tpm::new();

    // Create the SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let srk_resp_handles =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
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
        parent_handle: srk_handle,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();

    // Load the sealed blob
    let load_cmd = Load {
        parent_handle: srk_handle,
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_resp_handles = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]).unwrap();
    let blob_handle = load_resp_handles.object_handle;

    // Rotate to empty auth
    let oca_cmd = ObjectChangeAuth {
        object_handle: blob_handle,
        parent_handle: srk_handle,
        new_auth: Tpm2bAuth::default(),
    };
    let oca_rsp = execute_with_password_sessions(&mut sim, &oca_cmd, 1, auth).unwrap();

    flush_context(&mut sim, blob_handle).unwrap();

    // Load the new key
    let load_new_cmd = Load {
        parent_handle: srk_handle,
        in_private: oca_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_new_resp_handles =
        execute_with_password_sessions(&mut sim, &load_new_cmd, 1, &[]).unwrap();
    let new_blob_handle = load_new_resp_handles.object_handle;

    // Verify unsealing with empty auth succeeds
    let unseal_cmd = Unseal {
        item_handle: new_blob_handle,
    };
    let unseal_rsp = execute_with_password_sessions(&mut sim, &unseal_cmd, 1, &[]).unwrap();
    assert_eq!(unseal_rsp.out_data.get_buffer(), data);

    flush_context(&mut sim, new_blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

/// ObjectChangeAuth on an active hash/HMAC sequence object fails.
#[test]
fn sequence_object_rejected() {
    let mut sim = Tpm::new();
    let parent_handle = create_storage_parent(&mut sim, Handle::RH_OWNER);

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_handles = execute_tpm_command(&mut sim, &start_cmd, &[]).unwrap();
    let object_handle = start_handles.sequence_handle;

    let cmd = ObjectChangeAuth {
        object_handle,
        parent_handle,
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };

    let res = execute_tpm_command(&mut sim, &cmd, &[password_auth(b"")]);
    assert_eq!(
        res.unwrap_err(),
        TpmRc::TYPE.with(Position::handle(1)).get()
    );
}

// TC-2.1: Invalid Authorization for Object Handle
/// ObjectChangeAuth on a sealed object with the wrong password fails.
#[test]
#[allow(deprecated)]
fn wrong_object_auth_rejected() {
    let mut sim = Tpm::new();

    // Create the SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let srk_resp_handles =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
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
        parent_handle: srk_handle,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();

    // Load the sealed blob
    let load_cmd = Load {
        parent_handle: srk_handle,
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_resp_handles = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]).unwrap();
    let blob_handle = load_resp_handles.object_handle;

    // Call ObjectChangeAuth using the wrong password ("wrongauth")
    let oca_cmd = ObjectChangeAuth {
        object_handle: blob_handle,
        parent_handle: srk_handle,
        new_auth: Tpm2bAuth::from_bytes(newauth).unwrap(),
    };
    let oca_err = execute_with_password_sessions(&mut sim, &oca_cmd, 1, b"wrongauth").unwrap_err();
    assert_eq!(
        oca_err, 0x9A2,
        "Expected TPM_RC_BAD_AUTH (0x9A2) on session 1"
    );

    flush_context(&mut sim, blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

// TC-2.2: Mismatched Parent Handle (Wrong Parent)
/// ObjectChangeAuth naming a parent other than the object's parent fails.
#[test]
#[allow(deprecated)]
fn wrong_parent_rejected() {
    let mut sim = Tpm::new();

    // 1. Create Parent A (SRK)
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let srk_resp_handles =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
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
        parent_handle: Handle(0x4000000B), // TPMRH_ENDORSEMENT,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_template(&srk_pub_b),
    };
    let srk_resp_handles2 =
        execute_with_password_sessions(&mut sim, &create_srk_cmd_b, 1, &[]).unwrap();
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
        parent_handle: parent_a,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();

    // 4. Load the sealed blob under Parent A
    let load_cmd = Load {
        parent_handle: parent_a,
        in_private: create_rsp.out_private,
        in_public: create_rsp.out_public,
    };
    let load_resp_handles = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]).unwrap();
    let blob_handle = load_resp_handles.object_handle;

    // 5. Call ObjectChangeAuth specifying Parent B as the parent
    let oca_cmd = ObjectChangeAuth {
        object_handle: blob_handle,
        parent_handle: parent_b,
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };
    // This should fail because parent_b is not the actual parent of blob
    let oca_err = execute_with_password_sessions(&mut sim, &oca_cmd, 1, auth).unwrap_err();
    // In TPM 2.0, this returns TPM_RC_TYPE (0x0A) or TPM_RC_KEY (0x1C) modified by parent handle position.
    // Specifically, parentHandle is parameter/handle position 2, so the error would be modified.
    // Let's assert it is indeed an error (non-zero).
    assert_ne!(oca_err, 0);

    flush_context(&mut sim, blob_handle).unwrap();
    flush_context(&mut sim, parent_a).unwrap();
    flush_context(&mut sim, parent_b).unwrap();
}
