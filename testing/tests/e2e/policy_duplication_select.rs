//! TPM2_PolicyDuplicationSelect: includeObject, name sizes and digest updates.

use crate::_common::*;
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{
    CreateLoaded, Duplicate, PolicyCommandCode, PolicyCpHash, PolicyDuplicationSelect,
    StartAuthSession,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret,
    Tpm2bName, Tpm2bNonce, Tpm2bSensitiveData, TpmCc, TpmEccCurve, TpmSe, TpmaObject, TpmiAlgHash,
    TpmsEccParms, TpmsEccPoint, TpmsSensitiveCreate, TpmtPublic, *,
};

/// PolicyDuplicationSelect: includeObject=2 is TPM_RC_VALUE + RC_P3, malformed names accepted, repeat is TPM_RC_CPHASH
#[test]
fn invalid_include_object_and_name_inputs() {
    let mut sim = Tpm::new();
    let session = policy_session(&mut sim);

    // 1. Invalid include_object (e.g. 2) -> TPM_RC_VALUE + P3
    let cmd_invalid_include = PolicyDuplicationSelect {
        policy_session: session,
        object_name: Tpm2bName::default(),
        new_parent_name: Tpm2bName::default(),
        include_object: true,
    };
    let res = execute_with_corrupted_bytes_status(&mut sim, &cmd_invalid_include, 0, &[], |buf| {
        buf[4] = 2;
    });
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE.with(Position::parameter(3)).get()
    );

    // 2. Malformed object_name (size 3)
    let cmd_malformed_object_name = PolicyDuplicationSelect {
        policy_session: session,
        object_name: Tpm2bName::from_bytes(&[0, 1, 2]).unwrap(),
        new_parent_name: Tpm2bName::default(),
        include_object: true,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd_malformed_object_name, 0, &[]);
    // C does not validate the structure of the names (TPM2B_NAME_Unmarshal only bounds the
    // size, and PolicyDuplicationSelect.c just hashes them), so this succeeds.
    assert!(
        res.is_ok(),
        "Malformed object_name must be accepted like C, got {:?}",
        res.err()
    );

    // 3. Malformed new_parent_name (size 3)
    let cmd_malformed_parent_name = PolicyDuplicationSelect {
        policy_session: session,
        object_name: Tpm2bName::default(),
        new_parent_name: Tpm2bName::from_bytes(&[0, 1, 2]).unwrap(),
        include_object: true,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd_malformed_parent_name, 0, &[]);
    // The names are not validated (see above), but case 2 already set the session's nameHash,
    // so C returns bare TPM_RC_CPHASH (PolicyDuplicationSelect.c: `nameHash.t.size != 0`).
    assert_eq!(res.err(), Some(TpmRc::CPHASH.get()));
}

/// PolicyDuplicationSelect with includeObject corrupted to 2 fails unmarshalling
#[test]
fn invalid_include_object_rejected() {
    let mut sim = Tpm::new();
    let (_sk, sk_name) = create_signing_key_empty_unique(&mut sim);
    let (_ek, ek_name) = create_signing_key_empty_unique(&mut sim);

    // 1. Setup a trial session.
    let start_auth = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_rsp_handles = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // 2. Call PolicyDuplicationSelect with include_object = 2 (invalid value).
    let policy_dup = PolicyDuplicationSelect {
        policy_session: session_handle,
        object_name: sk_name,
        new_parent_name: ek_name,
        include_object: false,
    };
    let res = execute_with_corrupted_bytes(&mut sim, &policy_dup, 0, &[], |buf| {
        let last_idx = buf.len() - 1;
        buf[last_idx] = 2; // corrupt to 2 (invalid)
    });
    assert!(
        res.is_err(),
        "Expected PolicyDuplicationSelect to fail with invalid bool"
    );
    assert_eq!(res.err().unwrap(), 0x3C4);

    flush_context(&mut sim, session_handle).unwrap();
}

/// PolicyDuplicationSelect with 66- and 65-byte names and includeObject=NO succeeds
#[test]
fn name_size_limits_without_include_object() {
    let mut sim = Tpm::new();

    // 1. A 66-byte name (SHA512 Name) when include_object is NO should succeed.
    let session_1 = policy_session(&mut sim);
    let mut sha512_name = [0u8; 66];
    sha512_name[0..2].copy_from_slice(&0x0012u16.to_be_bytes()); // SHA512 alg id
    sha512_name[2..66].fill(0xaa);
    let cmd_66 = PolicyDuplicationSelect {
        policy_session: session_1,
        object_name: Tpm2bName::from_bytes(&sha512_name).unwrap(),
        new_parent_name: Tpm2bName::default(),
        include_object: false,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd_66, 0, &[]);
    assert!(
        res.is_ok(),
        "66-byte name failed when include_object is NO: {:?}",
        res.err()
    );

    // 2. A 65-byte name should also succeed on a fresh session.
    let session_2 = policy_session(&mut sim);
    let mut name_65 = [0u8; 65];
    name_65[0..2].copy_from_slice(&0x0012u16.to_be_bytes()); // SHA512 alg id
    name_65[2..65].fill(0xbb);
    let cmd_65 = PolicyDuplicationSelect {
        policy_session: session_2,
        object_name: Tpm2bName::from_bytes(&name_65).unwrap(),
        new_parent_name: Tpm2bName::default(),
        include_object: false,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd_65, 0, &[]);
    assert!(
        res.is_ok(),
        "65-byte name failed when include_object is NO: {:?}",
        res.err()
    );
}

/// PolicyDuplicationSelect accepts names with unknown algorithm/length and matches the C reference digest.
///
/// Names are opaque TPM2B_NAME values: no algorithm-prefix/length validation.
#[test]
fn names_are_opaque() {
    let mut sim = Tpm::new();
    let s = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    // 0xFFFF is not a hash algorithm; the length matches no digest.
    let object_name = [0xFF, 0xFF, 1, 2, 3];
    let new_parent_name = [0x00, 0x0B, 9, 9, 9];
    policy_duplication_select(&mut sim, s, &object_name, &new_parent_name, true).unwrap();

    // The policy digest matches the C reference computation.
    let name_digest = sha(
        TpmiAlgHash::Sha256,
        &[
            &[0u8; 32],
            &TpmCc::PolicyDuplicationSelect.code().to_be_bytes(),
            &object_name,
            &new_parent_name,
            &[1],
        ],
    );
    assert_eq!(policy_digest(&mut sim, s), name_digest);
}

/// Raw PolicyDuplicationSelect with a 67-byte name fails unmarshalling with TPM_RC_SIZE + RC_P1
#[test]
fn oversized_name_rejected() {
    let mut sim = Tpm::new();
    let session_handle = start_policy_session(&mut sim).session_handle;

    // Construct raw byte stream for the command.
    let mut request = Vec::new();
    request.extend_from_slice(&0x8001u16.to_be_bytes()); // Tag
    request.extend_from_slice(&[0u8; 4]); // Size, patched below
    request.extend_from_slice(&0x00000188u32.to_be_bytes()); // Command code TPM_CC_PolicyDuplicationSelect
    request.extend_from_slice(&session_handle.0.to_be_bytes()); // Handle: policy_session

    // object_name: size 67; first 2 bytes are the SHA512 alg id, then dummy bytes
    request.extend_from_slice(&67u16.to_be_bytes());
    let mut object_name = [0u8; 67];
    object_name[..2].copy_from_slice(&Alg::SHA512.id().to_be_bytes());
    request.extend_from_slice(&object_name);

    // new_parent_name: size 34
    request.extend_from_slice(&34u16.to_be_bytes());
    let mut parent_name = [0u8; 34];
    parent_name[..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    request.extend_from_slice(&parent_name);

    // include_object: false (0)
    request.push(0);

    // Fill total command length field
    let size = request.len() as u32;
    request[2..6].copy_from_slice(&size.to_be_bytes());

    let mut response = [0u8; 256];
    let response = sim.transact(&request, &mut response).unwrap();
    assert!(
        response.len() >= 10,
        "Response is too short: {}",
        response.len()
    );

    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_ne!(
        rc, 0,
        "Expected PolicyDuplicationSelect to fail, but it succeeded!"
    );

    // We expect 0x1D5 (TPM_RC_SIZE + TPM_RC_P + TPM_RC_1) because Tpm2bName max size is 66, so 67 bytes fails during request parameter 1 unmarshalling.
    assert_eq!(
        rc, 0x1D5,
        "Expected error code 0x1D5 (TPM_RC_SIZE + TPM_RC_P + TPM_RC_1), but got: 0x{:X}",
        rc
    );
}

/// TPM2_PolicyDuplicationSelect treats Names as opaque: a truncated SHA-256 Name is accepted
#[test]
fn policy_duplication_select_accepts_opaque_short_name() {
    let mut sim = Tpm::new();
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Construct an invalid name: SHA256 header but only 10 bytes of digest instead of 32
    let object_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 10].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = PolicyDuplicationSelect {
        policy_session: sess.session_handle,
        object_name,
        new_parent_name,
        include_object: true,
    };

    let res = execute_with_password_sessions(&mut sim, &dup_cmd, 0, &[]);
    // Names are opaque TPM2B_NAME values: C TPM2_PolicyDuplicationSelect only bounds their size
    // (unmarshaling) and hashes them, so a Name with an unexpected internal structure is accepted.
    assert!(
        res.is_ok(),
        "PolicyDuplicationSelect accepts any TPM2B_NAME: {:?}",
        res.err()
    );
}

/// TPM2_PolicyDuplicationSelect accepts a maximum-size 66-byte SHA-512 Name with includeObject=NO
#[test]
fn policy_duplication_select_accepts_sha512_name() {
    let mut sim = Tpm::new();

    // Start policy session
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // A SHA512 Name structure is 66 bytes: 2 bytes alg ID (0x000D) + 64 bytes digest
    let mut name_bytes = [0x11u8; 66];
    name_bytes[0..2].copy_from_slice(&Alg::SHA512.id().to_be_bytes());

    let object_name = Tpm2bName::from_bytes(leak_bytes(&name_bytes)).unwrap();
    let new_parent_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = PolicyDuplicationSelect {
        policy_session: sess.session_handle,
        object_name,
        new_parent_name,
        include_object: false,
    };

    let res = execute_with_password_sessions(&mut sim, &dup_cmd, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyDuplicationSelect failed with a valid 66-byte SHA-512 name: {:?}",
        res.err()
    );
}

/// A PolicyDuplicationSelect (includeObject=NO) policy authorizes TPM2_Duplicate of an object to a new parent end to end
#[test]
#[allow(deprecated)]
fn policy_duplication_select_authorizes_duplicate() {
    let mut sim = Tpm::new();

    // 1. Create ECC Owner SRK (to load our object under)
    let srk_pub = get_ecc_srk_template_unique0();
    let in_public = make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public,
    };
    let srk_resp_handles =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // 2. Create ECC Endorsement SRK (as new parent for duplication)
    let ecc_srk_pub = get_ecc_srk_template_with_unique(1);
    let ecc_in_public = make_template(&ecc_srk_pub);
    let create_ecc_srk_cmd = CreateLoaded {
        parent_handle: Handle(0x4000000B), // TPMRH_ENDORSEMENT
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: ecc_in_public,
    };
    let ecc_srk_resp_handles =
        execute_with_password_sessions(&mut sim, &create_ecc_srk_cmd, 1, &[]).unwrap();
    let new_parent_handle = ecc_srk_resp_handles.object_handle;
    let new_parent_name = read_public_name(&mut sim, new_parent_handle);

    // 3. Compute expected cpHash for:
    // Duplicate { encryption_key_in: default, symmetric_alg: Null }
    // Handles: object_handle: obj_handle, new_parent_handle: new_parent_handle.
    // Wait, since we don't have obj_handle yet, we must create a template first to compute its name!
    // The name of a transient key is computed as: hash(publicArea).
    // Let's define the public area of the object to be duplicated.
    let obj_auth = b"foo";
    let mut obj_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(), // Will be updated
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    // Calculate public area bytes to get name before creation?
    // Wait, the TPM modifies the public area (assigns public coordinates) upon creation!
    // So the name can only be retrieved AFTER creation.
    // But how can we set `auth_policy` on creation if the policy depends on the object's own name?
    // Ah!
    // Does `PolicyCpHash` depend on the object's name?
    // Yes, because the command being authorized is `Duplicate`, whose handle 1 is `object_handle`.
    // The handle 1's name is part of the cpHash!
    // So the cpHash contains `object_name`.
    // If the policy contains `PolicyCpHash`, the policy digest depends on the `object_name`.
    // But the `object_name` depends on the public key, which is randomly generated upon creation!
    // Wait, how can we solve this chicken-and-egg problem?
    // In TPM 2.0, if a policy depends on the object's own name, we cannot set the policy at creation time
    // unless we pre-generate/calculate the key coordinates (which is hard), OR
    // we use `PolicyDuplicationSelect`!
    // Indeed, `PolicyDuplicationSelect` is designed specifically to solve this!
    // It compares `nameHash` which is computed as `hash(objectName || newParentName)`.
    // Wait! Does `PolicyDuplicationSelect` policy digest depend on the object's name?
    // Only if `includeObject` is `YES`!
    // If `includeObject` is `NO`, the policy digest is `hash(policyDigest || TPM_CC_PolicyDuplicationSelect || newParentName || includeObject)`.
    // This policy digest does NOT depend on the object's own name!
    // So we can set this policy at creation time!
    // Then, during execution of `PolicyDuplicationSelect` in the policy session, the caller passes the `objectName`.
    // The TPM computes `nameHash = hash(objectName || newParentName)` and compares it at execution time.
    // That is brilliant and exactly why `PolicyDuplicationSelect` has the `includeObject` flag!
    // So we can easily test `PolicyDuplicationSelect` with `includeObject = NO` E2E!
    // Let's do that!
    // Let's compute policy digest for `PolicyDuplicationSelect(new_parent_name, includeObject = NO)`:
    let mut calc = PolicyCalculator::new(TpmiAlgHash::Sha256);
    calc.policy_duplication_select(&[], new_parent_name.get_buffer(), false);
    let policy_digest = Tpm2bDigest::from_bytes(&calc.policy_digest).unwrap();

    // Now create the object with this policy
    obj_pub.auth_policy = policy_digest;
    let obj_in_public = make_template(&obj_pub);
    let create_obj_cmd = CreateLoaded {
        parent_handle: srk_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(obj_auth).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: obj_in_public,
    };
    let obj_resp_handles =
        execute_with_password_sessions(&mut sim, &create_obj_cmd, 1, &[]).unwrap();
    let obj_handle = obj_resp_handles.object_handle;
    let object_name = read_public_name(&mut sim, obj_handle);

    // Flush owner SRK
    flush_context(&mut sim, srk_handle).unwrap();

    // Now start a policy session to authorize duplication
    let policy_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Run PolicyDuplicationSelect (with correct names)
    let dup_select_cmd = PolicyDuplicationSelect {
        policy_session: policy_sess.session_handle,
        object_name,
        new_parent_name,
        include_object: false,
    };
    assert!(
        execute_with_password_sessions(&mut sim, &dup_select_cmd, 0, &[]).is_ok(),
        "PolicyDuplicationSelect failed"
    );

    // Execute Duplicate using this policy session. It should succeed!
    let dup_cmd = Duplicate {
        object_handle: obj_handle,
        new_parent_handle,
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let mut sessions = [policy_sess.clone()];
    let res = execute_with_hmac_sessions(&mut sim, &dup_cmd, &[], &mut sessions, &[&[]]);
    assert!(
        res.is_ok(),
        "Duplicate failed with policy auth: {:?}",
        res.err()
    );

    // Clean up sessions and handles
    flush_context(&mut sim, obj_handle).unwrap();
    flush_context(&mut sim, new_parent_handle).unwrap();
}

/// TPM2_PolicyDuplicationSelect on sessions of each hash alg updates the digest as PolicyCalculator predicts
#[test]
fn policy_duplication_select_digest_for_every_hash_alg() {
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha1, true);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha1, false);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha256, true);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha256, false);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha384, true);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha384, false);
    #[cfg(feature = "sha512")]
    {
        run_policy_dup_select_for_alg(TpmiAlgHash::Sha512, true);
        run_policy_dup_select_for_alg(TpmiAlgHash::Sha512, false);
    }
}

/// TPM2_PolicyDuplicationSelect succeeds on a policy session started with a bind entity
#[test]
#[allow(deprecated)]
fn policy_duplication_select_on_bound_policy_session() {
    let mut sim = Tpm::new();

    // 1. Create a transient key to bind the session to
    let srk_pub = get_ecc_srk_template_unique0();
    let in_public = make_template(&srk_pub);
    let create_cmd = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public,
    };
    let create_rsp_handles = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    let key_handle = create_rsp_handles.object_handle;

    // 2. Start session bound to key_handle
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        key_handle,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // 3. Executing PolicyDuplicationSelect on bound session must fail with TPM_RC_CPHASH (0x151).
    let object_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();
    let dup_cmd = PolicyDuplicationSelect {
        policy_session: sess.session_handle,
        object_name,
        new_parent_name,
        include_object: true,
    };
    let res = execute_with_password_sessions(&mut sim, &dup_cmd, 0, &[]);
    // C SessionCreate (Session.c) only binds HMAC sessions ("Policy session is not bound to an
    // entity"), so the cpHash union of a policy/trial session started with a bind entity is
    // free and the command succeeds.
    assert!(
        res.is_ok(),
        "PolicyDuplicationSelect on bound session must succeed (policy sessions are never bound): {:?}",
        res.err()
    );

    // Clean up
    flush_context(&mut sim, sess.session_handle).unwrap();
    flush_context(&mut sim, key_handle).unwrap();
}

/// TPM2_PolicyDuplicationSelect succeeds on a trial session started with a bind entity
#[test]
#[allow(deprecated)]
fn policy_duplication_select_on_bound_trial_session() {
    let mut sim = Tpm::new();

    // 1. Create a transient key to bind the session to
    let srk_pub = get_ecc_srk_template_unique0();
    let in_public = make_template(&srk_pub);
    let create_cmd = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public,
    };
    let create_rsp_handles = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    let key_handle = create_rsp_handles.object_handle;

    // 2. Start TRIAL session bound to key_handle
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        key_handle,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // 3. Executing PolicyDuplicationSelect on bound trial session must fail with TPM_RC_CPHASH (0x151).
    let object_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();
    let dup_cmd = PolicyDuplicationSelect {
        policy_session: sess.session_handle,
        object_name,
        new_parent_name,
        include_object: true,
    };
    let res = execute_with_password_sessions(&mut sim, &dup_cmd, 0, &[]);
    // C SessionCreate (Session.c) only binds HMAC sessions ("Policy session is not bound to an
    // entity"), so the cpHash union of a policy/trial session started with a bind entity is
    // free and the command succeeds.
    assert!(
        res.is_ok(),
        "PolicyDuplicationSelect on bound trial session must succeed (policy sessions are never bound): {:?}",
        res.err()
    );

    // Clean up
    flush_context(&mut sim, sess.session_handle).unwrap();
    flush_context(&mut sim, key_handle).unwrap();
}

/// TPM2_PolicyDuplicationSelect after TPM2_PolicyCommandCode fails with TPM_RC_COMMAND_CODE
#[test]
fn policy_duplication_select_rejects_after_policy_command_code() {
    let mut sim = Tpm::new();
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // 1. Execute PolicyCommandCode first (e.g. set to TpmCc::Duplicate)
    let cmd_code = PolicyCommandCode {
        policy_session: sess.session_handle,
        code: TpmCc::Duplicate,
    };
    assert!(execute_with_password_sessions(&mut sim, &cmd_code, 0, &[]).is_ok());

    // 2. Executing PolicyDuplicationSelect now must fail with TPM_RC_COMMAND_CODE (0x143)
    let object_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();
    let dup_cmd = PolicyDuplicationSelect {
        policy_session: sess.session_handle,
        object_name,
        new_parent_name,
        include_object: true,
    };

    let res = execute_with_password_sessions(&mut sim, &dup_cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x143),
        "PolicyDuplicationSelect should fail with TPM_RC_COMMAND_CODE (0x143) when command code is already set"
    );
}

/// TPM2_PolicyDuplicationSelect with a 67-byte Name fails with TPM_RC_SIZE + P1
#[test]
fn policy_duplication_select_rejects_oversized_name() {
    let mut sim = Tpm::new();

    // Start policy session
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // A name structure of 67 bytes (greater than 66)
    let mut name_bytes = vec![0x11u8; 67];
    // Write hash alg ID (e.g. SHA-512 = 0x000D)
    name_bytes[0..2].copy_from_slice(&Alg::SHA512.id().to_be_bytes());

    let object_name = OversizedTpm2bName {
        size: 67,
        buffer: name_bytes,
    };
    let new_parent_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = TestPolicyDuplicationSelectOversizedCmd {
        policy_session: sess.session_handle,
        object_name,
        new_parent_name,
        include_object: false,
    };
    let res = execute_with_password_sessions(&mut sim, &dup_cmd, 0, &[]);

    // We expect it to be rejected.
    // The TPM 2.0 specification requires TPM_RC_SIZE + TPM_RC_P + TPM_RC_1 (Format-1 error 0x01D5) for name size > 66.
    assert_eq!(
        res.err(),
        Some(0x01D5),
        "Expected TPM_RC_SIZE + TPM_RC_P + TPM_RC_1 (0x01D5), got: {:?}",
        res.err()
    );
}

/// A second TPM2_PolicyDuplicationSelect on the same session fails with TPM_RC_CPHASH
#[test]
fn policy_duplication_select_rejects_second_call() {
    let mut sim = Tpm::new();

    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let object_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = PolicyDuplicationSelect {
        policy_session: sess.session_handle,
        object_name,
        new_parent_name,
        include_object: true,
    };

    assert!(
        execute_with_password_sessions(&mut sim, &dup_cmd, 0, &[]).is_ok(),
        "First PolicyDuplicationSelect failed"
    );

    let res = execute_with_password_sessions(&mut sim, &dup_cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x151),
        "Should fail with TPM_RC_CPHASH (0x151) on second call"
    );
}

/// TPM2_PolicyDuplicationSelect sent with TPM_ST_SESSIONS and an unassociated HMAC session
#[test]
fn policy_duplication_select_with_unassociated_hmac_session() {
    let mut sim = Tpm::new();
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let hmac_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let object_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = PolicyDuplicationSelect {
        policy_session: sess.session_handle,
        object_name,
        new_parent_name,
        include_object: true,
    };

    // The command has no authorization handles, so the session is unassociated: C
    // ParseSessionBuffer requires it to be an audit, encrypt or decrypt session.
    let mut sessions = [hmac_sess.clone()];
    sessions[0].attributes = tpm2::TpmaSession::CONTINUE_SESSION | tpm2::TpmaSession::AUDIT;
    let res = execute_with_hmac_sessions(&mut sim, &dup_cmd, &[], &mut sessions, &[&[]]);
    assert!(
        res.is_ok(),
        "PolicyDuplicationSelect under tag 0x8002 failed: {:?}",
        res.err()
    );
}

/// A second PolicyDuplicationSelect, or PolicyCpHash after it, fails with TPM_RC_CPHASH since the name hash is already set
#[test]
fn repeat_and_cp_hash_after_select_rejected() {
    let mut sim = Tpm::new();
    let (_sk, sk_name) = create_signing_key_empty_unique(&mut sim);
    let (_ek, ek_name) = create_signing_key_empty_unique(&mut sim);

    // 1. Setup a trial session.
    let start_auth = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_rsp_handles = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // 2. Call PolicyDuplicationSelect.
    let policy_dup = PolicyDuplicationSelect {
        policy_session: session_handle,
        object_name: sk_name,
        new_parent_name: ek_name,
        include_object: true,
    };
    execute_with_password_sessions(&mut sim, &policy_dup, 0, &[]).unwrap();

    // 3. Try calling PolicyDuplicationSelect again (should fail because is_name_hash_defined is true).
    let res = sim.execute(policy_dup);
    assert!(
        res.is_err(),
        "Expected second PolicyDuplicationSelect to fail"
    );
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH);

    // 4. Try calling PolicyCpHash on the same session.
    // It should fail because is_name_hash_defined is true.
    let dummy_cp_hash = [0x55; 32];
    let policy_cp_hash = PolicyCpHash {
        policy_session: session_handle,
        cp_hash_a: Tpm2bDigest::from_bytes(&dummy_cp_hash).unwrap(),
    };
    let res = sim.execute(policy_cp_hash);
    assert!(
        res.is_err(),
        "Expected PolicyCpHash to fail when nameHash is defined"
    );
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH);

    flush_context(&mut sim, session_handle).unwrap();
}

/// PolicyDuplicationSelect with a 66-byte (SHA-512) object name succeeds
#[test]
fn sha512_object_name_accepted() {
    let res = policy_duplication_select_66(false);
    assert!(
        res.is_ok(),
        "Expected PolicyDuplicationSelect to succeed for 66-byte name with include_object=NO, but failed: {:?}",
        res.err()
    );
}

/// PolicyDuplicationSelect with a 66-byte object name and includeObject=YES succeeds
#[test]
fn sha512_object_name_with_include_object() {
    let res = policy_duplication_select_66(true);
    assert!(
        res.is_ok(),
        "Expected PolicyDuplicationSelect to succeed for 66-byte name with include_object=YES, but failed: {:?}",
        res.err()
    );
}

/// A SHA-256-prefixed name with a truncated digest is accepted (no SIZE+P2).
#[test]
fn truncated_digest_name_accepted() {
    let mut sim = Tpm::new();
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    // A 2-byte SHA-256 prefix with a truncated digest was rejected with TPM_RC_SIZE + RC_P2.
    policy_duplication_select(&mut sim, s, &[], &[0x00, 0x0B, 1, 2], false).unwrap();
}
