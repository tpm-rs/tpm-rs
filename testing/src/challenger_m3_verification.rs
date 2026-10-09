#![forbid(unsafe_code)]
use tpm2::Alg;

use crate::test_utils::*;
use tpm2::commands::{
    CreateLoaded, CreateLoadedHandles, CreatePrimary, CreatePrimaryHandles, Duplicate,
    DuplicateHandles, EncryptDecrypt, EncryptDecrypt2, EncryptDecrypt2Handles,
    EncryptDecryptHandles, PolicyAuthorize, PolicyAuthorizeHandles, PolicyCommandCode,
    PolicyCommandCodeHandles, PolicyCpHash, PolicyCpHashHandles, PolicyDuplicationSelect,
    PolicyDuplicationSelectHandles, PolicyGetDigest, PolicyGetDigestHandles,
};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve, TpmSe};
use tpm2_simulator::create_simulator;

fn get_ecc_srk_template() -> TpmtPublic<'static> {
    get_ecc_srk_template_with_unique(0)
}

fn get_ecc_srk_template_with_unique(unique: u8) -> TpmtPublic<'static> {
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
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(&[unique; 32]))
                    .unwrap(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

fn run_policy_cphash_for_alg(alg: TpmiAlgHash, cp_hash_len: usize) {
    let mut sim = create_simulator!();

    // Start policy session
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        alg,
    )
    .unwrap();

    let cp_hash_val = vec![0xaa; cp_hash_len];
    let cp_hash_a = Tpm2bDigest::from_bytes(&cp_hash_val).unwrap();

    let cp_hash_cmd = PolicyCpHash { cp_hash_a };
    let cp_hash_handles = PolicyCpHashHandles {
        policy_session: sess.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cp_hash_cmd, cp_hash_handles, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyCpHash failed for {:?} with: {:?}",
        alg,
        res.err()
    );

    // Verify policy digest against PolicyCalculator
    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: sess.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();

    let mut calc = PolicyCalculator::new(alg);
    calc.policy_cp_hash(&cp_hash_val);

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        calc.policy_digest.as_slice(),
        "PolicyCpHash digest mismatch for {:?}",
        alg
    );
}

fn run_policy_dup_select_for_alg(alg: TpmiAlgHash, include_obj: bool) {
    let mut sim = create_simulator!();

    // Start policy session
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        alg,
    )
    .unwrap();

    let object_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = PolicyDuplicationSelect {
        object_name,
        new_parent_name,
        include_object: include_obj,
    };
    let dup_handles = PolicyDuplicationSelectHandles {
        policy_session: sess.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &dup_cmd, dup_handles, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyDuplicationSelect failed for {:?}, include={:?}: {:?}",
        alg,
        include_obj,
        res.err()
    );

    // Verify policy digest against PolicyCalculator
    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: sess.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();

    let mut calc = PolicyCalculator::new(alg);
    calc.policy_duplication_select(
        object_name.get_buffer(),
        new_parent_name.get_buffer(),
        include_obj,
    );

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        calc.policy_digest.as_slice(),
        "PolicyDuplicationSelect digest mismatch for {:?}, include={}",
        alg,
        include_obj
    );
}

#[test]
fn test_policy_cphash_all_algorithms() {
    run_policy_cphash_for_alg(TpmiAlgHash::Sha1, 20);
    run_policy_cphash_for_alg(TpmiAlgHash::Sha256, 32);
    run_policy_cphash_for_alg(TpmiAlgHash::Sha384, 48);
    run_policy_cphash_for_alg(TpmiAlgHash::Sha512, 64);
}

#[test]
fn test_policy_duplication_select_all_algorithms() {
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha1, true);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha1, false);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha256, true);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha256, false);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha384, true);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha384, false);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha512, true);
    run_policy_dup_select_for_alg(TpmiAlgHash::Sha512, false);
}

#[test]
fn test_policy_cphash_collision_and_overwriting() {
    let mut sim = create_simulator!();

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

    let cp_hash_1 = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let cp_hash_2 = Tpm2bDigest::from_bytes(&[0x22; 32]).unwrap();

    let cp_hash_cmd_1 = PolicyCpHash {
        cp_hash_a: cp_hash_1,
    };
    let cp_hash_handles = PolicyCpHashHandles {
        policy_session: sess.session_handle,
    };
    assert!(
        execute_with_password_sessions(&mut sim, &cp_hash_cmd_1, cp_hash_handles, 0, &[]).is_ok(),
        "First PolicyCpHash failed"
    );

    let cp_hash_cmd_same = PolicyCpHash {
        cp_hash_a: cp_hash_1,
    };
    assert!(
        execute_with_password_sessions(&mut sim, &cp_hash_cmd_same, cp_hash_handles, 0, &[])
            .is_ok(),
        "Second PolicyCpHash with same cpHash failed"
    );

    let cp_hash_cmd_diff = PolicyCpHash {
        cp_hash_a: cp_hash_2,
    };
    let res = execute_with_password_sessions(&mut sim, &cp_hash_cmd_diff, cp_hash_handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x151),
        "Should fail with TPM_RC_CPHASH (0x151)"
    );
}

#[test]
fn test_policy_duplication_select_collision_and_overwriting() {
    let mut sim = create_simulator!();

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

    let object_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = PolicyDuplicationSelect {
        object_name,
        new_parent_name,
        include_object: true,
    };
    let dup_handles = PolicyDuplicationSelectHandles {
        policy_session: sess.session_handle,
    };

    assert!(
        execute_with_password_sessions(&mut sim, &dup_cmd, dup_handles, 0, &[]).is_ok(),
        "First PolicyDuplicationSelect failed"
    );

    let res = execute_with_password_sessions(&mut sim, &dup_cmd, dup_handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x151),
        "Should fail with TPM_RC_CPHASH (0x151) on second call"
    );
}

#[test]
fn test_policy_mixed_collision_and_overwriting() {
    let mut sim = create_simulator!();

    let sess_a = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let cp_hash = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let cp_hash_cmd = PolicyCpHash { cp_hash_a: cp_hash };
    let cp_hash_handles = PolicyCpHashHandles {
        policy_session: sess_a.session_handle,
    };
    assert!(
        execute_with_password_sessions(&mut sim, &cp_hash_cmd, cp_hash_handles, 0, &[]).is_ok()
    );

    let object_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();
    let dup_cmd = PolicyDuplicationSelect {
        object_name,
        new_parent_name,
        include_object: true,
    };
    let dup_handles = PolicyDuplicationSelectHandles {
        policy_session: sess_a.session_handle,
    };
    let res_a = execute_with_password_sessions(&mut sim, &dup_cmd, dup_handles, 0, &[]);
    assert_eq!(
        res_a.err(),
        Some(0x151),
        "PolicyDuplicationSelect after PolicyCpHash should fail with TPM_RC_CPHASH"
    );

    let sess_b = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let cp_hash_handles_b = PolicyCpHashHandles {
        policy_session: sess_b.session_handle,
    };
    let dup_handles_b = PolicyDuplicationSelectHandles {
        policy_session: sess_b.session_handle,
    };
    assert!(execute_with_password_sessions(&mut sim, &dup_cmd, dup_handles_b, 0, &[]).is_ok());

    let res_b = execute_with_password_sessions(&mut sim, &cp_hash_cmd, cp_hash_handles_b, 0, &[]);
    assert_eq!(
        res_b.err(),
        Some(0x151),
        "PolicyCpHash after PolicyDuplicationSelect should fail with TPM_RC_CPHASH"
    );
}

#[test]
fn test_policy_cphash_incorrect_inputs() {
    let mut sim = create_simulator!();

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

    let cp_hash_handles = PolicyCpHashHandles {
        policy_session: sess.session_handle,
    };

    let cp_hash_bad_1 = Tpm2bDigest::from_bytes(&[0x11; 20]).unwrap();
    let cp_hash_cmd_bad_1 = PolicyCpHash {
        cp_hash_a: cp_hash_bad_1,
    };
    let res1 =
        execute_with_password_sessions(&mut sim, &cp_hash_cmd_bad_1, cp_hash_handles, 0, &[]);
    assert_eq!(
        res1.err(),
        Some(0x1D5),
        "Should fail with parameter 1 size error (0x1D5)"
    );

    let cp_hash_bad_2 = Tpm2bDigest::from_bytes(&[0x11; 48]).unwrap();
    let cp_hash_cmd_bad_2 = PolicyCpHash {
        cp_hash_a: cp_hash_bad_2,
    };
    let res2 =
        execute_with_password_sessions(&mut sim, &cp_hash_cmd_bad_2, cp_hash_handles, 0, &[]);
    assert_eq!(
        res2.err(),
        Some(0x1D5),
        "Should fail with parameter 1 size error (0x1D5)"
    );
}

#[test]
fn test_policy_session_reuse_and_enforcement() {
    let mut sim = create_simulator!();

    // 1. Create ECC Owner SRK (to load our object under)
    let srk_pub = get_ecc_srk_template();
    let in_public = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public,
    };
    let create_srk_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
    };
    let (_, srk_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, create_srk_handles, 1, &[])
            .unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // 2. Create ECC Endorsement SRK (as new parent for duplication)
    let ecc_srk_pub = get_ecc_srk_template_with_unique(1);
    let ecc_in_public = crate::test_utils::make_template(&ecc_srk_pub);
    let create_ecc_srk_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: ecc_in_public,
    };
    let create_ecc_srk_handles = CreateLoadedHandles {
        parent_handle: Handle(0x4000000B), // TPMRH_ENDORSEMENT
    };
    let (_, ecc_srk_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_ecc_srk_cmd,
        create_ecc_srk_handles,
        1,
        &[],
    )
    .unwrap();
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
    let obj_in_public = crate::test_utils::make_template(&obj_pub);
    let create_obj_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(obj_auth).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: obj_in_public,
    };
    let create_obj_handles = CreateLoadedHandles {
        parent_handle: srk_handle,
    };
    let (_obj_resp, obj_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_obj_cmd, create_obj_handles, 1, &[])
            .unwrap();
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
        object_name,
        new_parent_name,
        include_object: false,
    };
    let dup_select_handles = PolicyDuplicationSelectHandles {
        policy_session: policy_sess.session_handle,
    };
    assert!(
        execute_with_password_sessions(&mut sim, &dup_select_cmd, dup_select_handles, 0, &[])
            .is_ok(),
        "PolicyDuplicationSelect failed"
    );

    // Execute Duplicate using this policy session. It should succeed!
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let dup_handles = DuplicateHandles {
        object_handle: obj_handle,
        new_parent_handle,
    };
    let mut sessions = [policy_sess.clone()];
    let res =
        execute_with_hmac_sessions(&mut sim, &dup_cmd, dup_handles, &[], &mut sessions, &[&[]]);
    assert!(
        res.is_ok(),
        "Duplicate failed with policy auth: {:?}",
        res.err()
    );

    // Clean up sessions and handles
    flush_context(&mut sim, obj_handle).unwrap();
    flush_context(&mut sim, new_parent_handle).unwrap();
}

#[test]
fn test_policy_cphash_on_bound_session() {
    let mut sim = create_simulator!();

    // 1. Create a transient key to bind the session to
    let srk_pub = get_ecc_srk_template();
    let in_public = crate::test_utils::make_template(&srk_pub);
    let create_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
    };
    let (_, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();
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

    // 3. Executing PolicyCpHash on bound session must fail with TPM_RC_CPHASH (0x151)
    let cp_hash = Tpm2bDigest::from_bytes(&[0xaa; 32]).unwrap();
    let cp_hash_cmd = PolicyCpHash { cp_hash_a: cp_hash };
    let cp_hash_handles = PolicyCpHashHandles {
        policy_session: sess.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cp_hash_cmd, cp_hash_handles, 0, &[]);
    // C SessionCreate (Session.c) only binds HMAC sessions ("Policy session is not bound to an
    // entity"), so the cpHash union of a policy/trial session started with a bind entity is
    // free and the command succeeds.
    assert!(
        res.is_ok(),
        "PolicyCpHash on bound session must succeed (policy sessions are never bound): {:?}",
        res.err()
    );

    // Clean up
    flush_context(&mut sim, sess.session_handle).unwrap();
    flush_context(&mut sim, key_handle).unwrap();
}

#[test]
fn test_policy_duplication_select_on_bound_session() {
    let mut sim = create_simulator!();

    // 1. Create a transient key to bind the session to
    let srk_pub = get_ecc_srk_template();
    let in_public = crate::test_utils::make_template(&srk_pub);
    let create_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
    };
    let (_, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();
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
    let object_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();
    let dup_cmd = PolicyDuplicationSelect {
        object_name,
        new_parent_name,
        include_object: true,
    };
    let dup_handles = PolicyDuplicationSelectHandles {
        policy_session: sess.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &dup_cmd, dup_handles, 0, &[]);
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

#[test]
fn test_policy_cphash_on_bound_trial_session() {
    let mut sim = create_simulator!();

    // 1. Create a transient key to bind the session to
    let srk_pub = get_ecc_srk_template();
    let in_public = crate::test_utils::make_template(&srk_pub);
    let create_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
    };
    let (_, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();
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

    // 3. Executing PolicyCpHash on bound trial session must fail with TPM_RC_CPHASH (0x151)
    let cp_hash = Tpm2bDigest::from_bytes(&[0xaa; 32]).unwrap();
    let cp_hash_cmd = PolicyCpHash { cp_hash_a: cp_hash };
    let cp_hash_handles = PolicyCpHashHandles {
        policy_session: sess.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &cp_hash_cmd, cp_hash_handles, 0, &[]);
    // C SessionCreate (Session.c) only binds HMAC sessions ("Policy session is not bound to an
    // entity"), so the cpHash union of a policy/trial session started with a bind entity is
    // free and the command succeeds.
    assert!(
        res.is_ok(),
        "PolicyCpHash on bound trial session must succeed (policy sessions are never bound): {:?}",
        res.err()
    );

    // Clean up
    flush_context(&mut sim, sess.session_handle).unwrap();
    flush_context(&mut sim, key_handle).unwrap();
}

#[test]
fn test_policy_duplication_select_on_bound_trial_session() {
    let mut sim = create_simulator!();

    // 1. Create a transient key to bind the session to
    let srk_pub = get_ecc_srk_template();
    let in_public = crate::test_utils::make_template(&srk_pub);
    let create_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
    };
    let (_, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();
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
    let object_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();
    let dup_cmd = PolicyDuplicationSelect {
        object_name,
        new_parent_name,
        include_object: true,
    };
    let dup_handles = PolicyDuplicationSelectHandles {
        policy_session: sess.session_handle,
    };
    let res = execute_with_password_sessions(&mut sim, &dup_cmd, dup_handles, 0, &[]);
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

#[test]
fn test_policy_cphash_with_session() {
    let mut sim = create_simulator!();
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

    let cp_hash_cmd = PolicyCpHash {
        cp_hash_a: Tpm2bDigest::from_bytes(&[0xaa; 32]).unwrap(),
    };
    let cp_hash_handles = PolicyCpHashHandles {
        policy_session: sess.session_handle,
    };

    // The command has no authorization handles, so the session is unassociated: C
    // ParseSessionBuffer requires it to be an audit, encrypt or decrypt session.
    let mut sessions = [hmac_sess.clone()];
    sessions[0].attributes = tpm2::TpmaSession::CONTINUE_SESSION | tpm2::TpmaSession::AUDIT;
    let res = execute_with_hmac_sessions(
        &mut sim,
        &cp_hash_cmd,
        cp_hash_handles,
        &[],
        &mut sessions,
        &[&[]],
    );
    assert!(
        res.is_ok(),
        "PolicyCpHash with HMAC session (tag 0x8002) failed: {:?}",
        res.err()
    );
}

#[test]
fn test_policy_duplication_select_with_session_tag_0x8002() {
    let mut sim = create_simulator!();
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

    let object_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = PolicyDuplicationSelect {
        object_name,
        new_parent_name,
        include_object: true,
    };
    let dup_handles = PolicyDuplicationSelectHandles {
        policy_session: sess.session_handle,
    };

    // The command has no authorization handles, so the session is unassociated: C
    // ParseSessionBuffer requires it to be an audit, encrypt or decrypt session.
    let mut sessions = [hmac_sess.clone()];
    sessions[0].attributes = tpm2::TpmaSession::CONTINUE_SESSION | tpm2::TpmaSession::AUDIT;
    let res =
        execute_with_hmac_sessions(&mut sim, &dup_cmd, dup_handles, &[], &mut sessions, &[&[]]);
    assert!(
        res.is_ok(),
        "PolicyDuplicationSelect under tag 0x8002 failed: {:?}",
        res.err()
    );
}

#[test]
fn test_policy_duplication_select_command_code_gate() {
    let mut sim = create_simulator!();
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
        code: TpmCc::Duplicate,
    };
    let handles_code = PolicyCommandCodeHandles {
        policy_session: sess.session_handle,
    };
    assert!(execute_with_password_sessions(&mut sim, &cmd_code, handles_code, 0, &[]).is_ok());

    // 2. Executing PolicyDuplicationSelect now must fail with TPM_RC_COMMAND_CODE (0x143)
    let object_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();
    let dup_cmd = PolicyDuplicationSelect {
        object_name,
        new_parent_name,
        include_object: true,
    };
    let dup_handles = PolicyDuplicationSelectHandles {
        policy_session: sess.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &dup_cmd, dup_handles, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x143),
        "PolicyDuplicationSelect should fail with TPM_RC_COMMAND_CODE (0x143) when command code is already set"
    );
}

#[test]
fn test_policy_cphash_with_self_authorization() {
    let mut sim = create_simulator!();
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

    let cp_hash_cmd = PolicyCpHash {
        cp_hash_a: Tpm2bDigest::from_bytes(&[0xaa; 32]).unwrap(),
    };
    let cp_hash_handles = PolicyCpHashHandles {
        policy_session: sess.session_handle,
    };

    // Try to authorize PolicyCpHash with the policy_session itself (in sessions area under tag 0x8002)
    let mut sessions = [sess.clone()];
    let res = execute_with_hmac_sessions(
        &mut sim,
        &cp_hash_cmd,
        cp_hash_handles,
        &[],
        &mut sessions,
        &[&[]],
    );
    // Since policy session is not yet matched or it is a policy session being modified,
    // this self-authorization should either fail or behave correctly according to TPM spec.
    assert!(
        res.is_err(),
        "PolicyCpHash with self-authorization should fail"
    );
}

#[test]
fn test_policy_duplication_select_invalid_name_structure() {
    let mut sim = create_simulator!();
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
    let object_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 10].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = PolicyDuplicationSelect {
        object_name,
        new_parent_name,
        include_object: true,
    };
    let dup_handles = PolicyDuplicationSelectHandles {
        policy_session: sess.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &dup_cmd, dup_handles, 0, &[]);
    // Names are opaque TPM2B_NAME values: C TPM2_PolicyDuplicationSelect only bounds their size
    // (unmarshaling) and hashes them, so a Name with an unexpected internal structure is accepted.
    assert!(
        res.is_ok(),
        "PolicyDuplicationSelect accepts any TPM2B_NAME: {:?}",
        res.err()
    );
}

#[test]
fn test_policy_authorize_invalid_ticket_hierarchy() {
    let mut sim = create_simulator!();
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

    let approved_policy = Tpm2bDigest::from_bytes(&[0x00; 32]).unwrap();
    let key_sign = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();

    let cmd = PolicyAuthorize {
        approved_policy,
        policy_ref: Tpm2bNonce::default(),
        key_sign,
        check_ticket: TpmtTkVerified::Verified(Handle(0x1234), Tpm2bDigest::default()),
    };

    let handles = PolicyAuthorizeHandles {
        policy_session: sess.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, handles, 0, &[]);
    // Expected value error: value_for(Position::parameter(4))
    // 0x04C4 = 0x0004 (Value) + 0x0080 (Format 1) + 0x0040 (Parameter) + 0x0400 (Pos4)
    assert_eq!(
        res.err(),
        Some(0x04C4),
        "PolicyAuthorize with invalid hierarchy should fail with TPM_RC_VALUE on parameter 4"
    );
}

#[test]
fn test_encrypt_decrypt_invalid_yes_no() {
    let mut sim = create_simulator!();

    // Create a symmetric key first
    let sym_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::default(),
        ),
    };
    let create_primary_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(sym_template),
        ..Default::default()
    };
    let cp_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, cp_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_primary_cmd, cp_handles, 1, &[]).unwrap();
    let key_handle = cp_resp_handles.object_handle;

    let cmd = EncryptDecrypt {
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::CFB),
        iv_in: Tpm2bIv::default(),
        in_data: Tpm2bMaxBuffer::default(),
    };
    let handles = EncryptDecryptHandles { key_handle };

    let res = execute_with_corrupted_bytes(&mut sim, &cmd, handles, 1, &[], |buf| {
        buf[0] = 2; // decrypt is the first parameter (1 byte)
    });
    // Expected unmarshal error: Value + parameter 1 (452 / 0x01C4)
    assert_eq!(
        res.err(),
        Some(
            tpm2::errors::TpmRc::VALUE
                .with(tpm2::errors::Position::parameter(1))
                .get()
        ),
        "EncryptDecrypt with invalid decrypt should return TPM_RC_VALUE + TPM_RC_P + TPM_RC_1"
    );
}

#[test]
fn test_encrypt_decrypt_2_invalid_yes_no() {
    let mut sim = create_simulator!();

    // Create a symmetric key first
    let sym_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::default(),
        ),
    };
    let create_primary_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(sym_template),
        ..Default::default()
    };
    let cp_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, cp_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_primary_cmd, cp_handles, 1, &[]).unwrap();
    let key_handle = cp_resp_handles.object_handle;

    let cmd = EncryptDecrypt2 {
        in_data: Tpm2bMaxBuffer::default(),
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::CFB),
        iv_in: Tpm2bIv::default(),
    };
    let handles = EncryptDecrypt2Handles { key_handle };

    let res = execute_with_corrupted_bytes(&mut sim, &cmd, handles, 1, &[], |buf| {
        buf[2] = 2; // in_data is empty (2 bytes size = 0), decrypt is at index 2 (1 byte)
    });
    // Expected unmarshal error: Value + parameter 2 (708 / 0x02C4)
    assert_eq!(
        res.err(),
        Some(
            tpm2::errors::TpmRc::VALUE
                .with(tpm2::errors::Position::parameter(2))
                .get()
        ),
        "EncryptDecrypt2 with invalid decrypt should return TPM_RC_VALUE + TPM_RC_P + TPM_RC_2"
    );
}

#[test]
fn test_policy_duplication_select_sha512_name_include_object_no() {
    let mut sim = create_simulator!();

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
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha512).id().to_be_bytes());

    let object_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap();
    let new_parent_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = PolicyDuplicationSelect {
        object_name,
        new_parent_name,
        include_object: false,
    };
    let dup_handles = PolicyDuplicationSelectHandles {
        policy_session: sess.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &dup_cmd, dup_handles, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyDuplicationSelect failed with a valid 66-byte SHA-512 name: {:?}",
        res.err()
    );
}

#[derive(Clone, PartialEq, Debug)]
pub struct OversizedTpm2bName {
    pub size: u16,
    pub buffer: Vec<u8>,
}

impl tpm2::Marshal for OversizedTpm2bName {
    const MAX_SIZE: usize = 2048;
    type MaxBuffer = [u8; 2048];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let written = self.size.marshal((&mut dst[0..2]).try_into().unwrap());
        dst[written..written + self.buffer.len()].copy_from_slice(&self.buffer);
        written + self.buffer.len()
    }
}

impl<'a> tpm2::Unmarshal<'a> for OversizedTpm2bName {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let size = u16::unmarshal(src)?;
        if src.len() < size as usize {
            return Err(tpm2::errors::UnmarshalError::INSUFFICIENT);
        }
        let (sized_buffer, rest) = src.split_at(size as usize);
        *src = rest;
        Ok(OversizedTpm2bName {
            size,
            buffer: sized_buffer.to_vec(),
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct TestPolicyDuplicationSelectOversizedCmd {
    pub object_name: OversizedTpm2bName,
    pub new_parent_name: Tpm2bName<'static>,
    pub include_object: bool,
}

impl tpm2::Marshal for TestPolicyDuplicationSelectOversizedCmd {
    const MAX_SIZE: usize = 2048 + Tpm2bName::MAX_SIZE + bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self
            .object_name
            .marshal((&mut dst[0..2048]).try_into().unwrap());
        offset += self.new_parent_name.marshal(
            (&mut dst[offset..offset + Tpm2bName::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += self.include_object.marshal(
            (&mut dst[offset..offset + bool::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset
    }
}

impl<'a> tpm2::Unmarshal<'a> for TestPolicyDuplicationSelectOversizedCmd {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = crate::test_utils::leak_bytes(src);
        let object_name = OversizedTpm2bName::unmarshal(&mut leaked)?;
        let new_parent_name = Tpm2bName::unmarshal(&mut leaked)?;
        let include_object = bool::unmarshal(&mut leaked)?;
        let consumed = orig_len - leaked.len();
        *src = &src[consumed..];
        Ok(Self {
            object_name,
            new_parent_name,
            include_object,
        })
    }
}

impl tpm2::commands::Command for TestPolicyDuplicationSelectOversizedCmd {
    const CMD_CODE: TpmCc = TpmCc::PolicyDuplicationSelect;
    type Handles = PolicyDuplicationSelectHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[test]
fn test_policy_duplication_select_name_oversized_rejected() {
    let mut sim = create_simulator!();

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
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha512).id().to_be_bytes());

    let object_name = OversizedTpm2bName {
        size: 67,
        buffer: name_bytes,
    };
    let new_parent_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = TestPolicyDuplicationSelectOversizedCmd {
        object_name,
        new_parent_name,
        include_object: false,
    };
    let dup_handles = PolicyDuplicationSelectHandles {
        policy_session: sess.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &dup_cmd, dup_handles, 0, &[]);

    // We expect it to be rejected.
    // The TPM 2.0 specification requires TPM_RC_SIZE + TPM_RC_P + TPM_RC_1 (Format-1 error 0x01D5) for name size > 66.
    assert_eq!(
        res.err(),
        Some(0x01D5),
        "Expected TPM_RC_SIZE + TPM_RC_P + TPM_RC_1 (0x01D5), got: {:?}",
        res.err()
    );
}

#[test]
fn test_encrypt_decrypt_rejects_cmac_mode() {
    let mut sim = create_simulator!();

    // Create a valid symmetric key
    let sym_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::default(),
        ),
    };
    let create_primary_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(sym_template),
        ..Default::default()
    };
    let cp_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, cp_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_primary_cmd, cp_handles, 1, &[]).unwrap();
    let key_handle = cp_resp_handles.object_handle;

    // 1. EncryptDecrypt with mode corrupted to TPM_ALG_CMAC (0x003F)
    let cmd = EncryptDecrypt {
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::CFB),
        iv_in: Tpm2bIv::from_bytes(&[0u8; 16]).unwrap(),
        in_data: Tpm2bMaxBuffer::from_bytes(&[0u8; 16]).unwrap(),
    };
    let handles = EncryptDecryptHandles { key_handle };
    let res = execute_with_corrupted_bytes(&mut sim, &cmd, handles, 1, &[], |buf| {
        // decrypt is 1 byte at offset 0; mode is 2 bytes at offset 1..3
        buf[1..3].copy_from_slice(&0x003Fu16.to_be_bytes());
    });
    assert_eq!(
        res.err(),
        Some(
            tpm2::errors::TpmRc::MODE
                .with(tpm2::errors::Position::parameter(2))
                .get()
        ),
        "EncryptDecrypt with TPM_ALG_CMAC mode should return TPM_RC_MODE + TPM_RC_P + TPM_RC_2"
    );

    // 2. EncryptDecrypt2 with mode corrupted to TPM_ALG_CMAC (0x003F)
    let cmd2 = EncryptDecrypt2 {
        in_data: Tpm2bMaxBuffer::default(),
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::CFB),
        iv_in: Tpm2bIv::from_bytes(&[0u8; 16]).unwrap(),
    };
    let handles2 = EncryptDecrypt2Handles { key_handle };
    let res2 = execute_with_corrupted_bytes(&mut sim, &cmd2, handles2, 1, &[], |buf| {
        // in_data size is 2 bytes (0) at offset 0..2; decrypt is 1 byte at offset 2; mode is 2 bytes at offset 3..5
        buf[3..5].copy_from_slice(&0x003Fu16.to_be_bytes());
    });
    assert_eq!(
        res2.err(),
        Some(
            tpm2::errors::TpmRc::MODE
                .with(tpm2::errors::Position::parameter(3))
                .get()
        ),
        "EncryptDecrypt2 with TPM_ALG_CMAC mode should return TPM_RC_MODE + TPM_RC_P + TPM_RC_3"
    );
}
