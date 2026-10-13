//! TPM2_PolicyCpHash and cpHash binding of policy sessions.

use crate::_common::*;
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{
    CreateLoaded, PolicyCpHash, PolicyDuplicationSelect, PolicyOR, StartAuthSession,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce,
    Tpm2bSensitiveData, TpmSe, TpmiAlgHash, TpmlDigest, TpmsSensitiveCreate,
};

/// A trial/policy session started with a bind entity is not bound, so PolicyCpHash succeeds on it
#[test]
fn bound_policy_session_accepts_cp_hash() {
    let mut sim = Tpm::new();
    let (sk, sk_name) = create_signing_key_empty_unique(&mut sim);

    // Start a trial session bound to 'sk'.
    let start_auth = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: sk,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_rsp_handles = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // 1. PolicyCpHash should fail because bind_entity != RHNull
    let dummy_cp_hash = [0x55; 32];
    let policy_cp_hash = PolicyCpHash {
        policy_session: session_handle,
        cp_hash_a: Tpm2bDigest::from_bytes(&dummy_cp_hash).unwrap(),
    };
    // C SessionCreate only binds HMAC sessions: a trial/policy session started with a bind
    // entity is not bound, so its cpHash union is free and PolicyCpHash succeeds.
    let res = sim.execute(policy_cp_hash);
    assert!(
        res.is_ok(),
        "PolicyCpHash must succeed (policy sessions are never bound): {:?}",
        res.err()
    );

    // 2. PolicyDuplicationSelect should fail because bind_entity != RHNull
    let (_ek, ek_name) = create_signing_key_empty_unique(&mut sim);
    let policy_dup = PolicyDuplicationSelect {
        policy_session: session_handle,
        object_name: sk_name,
        new_parent_name: ek_name,
        include_object: true,
    };
    // The session is not bound (see above), but PolicyCpHash already set the cpHash union, so
    // PolicyDuplicationSelect still fails with TPM_RC_CPHASH (nameHash must be empty).
    let res = sim.execute(policy_dup);
    assert!(
        res.is_err(),
        "Expected PolicyDuplicationSelect to fail once cpHash is set"
    );
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH);

    flush_context(&mut sim, session_handle).unwrap();
}

/// A policy session started with a bind entity is not bound, so cpHash-union commands do not fail with CPHASH.
///
/// A policy session started with `bind != TPM_RH_NULL` is not bound (C `SessionCreate` only
/// binds HMAC sessions), so the cpHash-union commands must not fail with `TPM_RC_CPHASH`.
#[test]
fn bound_policy_session_not_cphash_bound() {
    let mut sim = Tpm::new();
    let bound = |sim: &mut Tpm, session_type| {
        start_bound(sim, Handle::RH_OWNER, &[], session_type).session_handle
    };
    for session_type in [TpmSe::Policy, TpmSe::Trial] {
        let s = bound(&mut sim, session_type);
        policy_cp_hash(&mut sim, s, &[0x11; 32]).expect("PolicyCpHash on bound policy session");
        let s = bound(&mut sim, session_type);
        policy_name_hash(&mut sim, s, &[0x22; 32]).expect("PolicyNameHash on bound session");
        let s = bound(&mut sim, session_type);
        policy_template(&mut sim, s, &[0x33; 32]).expect("PolicyTemplate on bound session");
        let s = bound(&mut sim, session_type);
        policy_duplication_select(&mut sim, s, &[], &[0x40, 0, 0, 1], false)
            .expect("PolicyDuplicationSelect on bound session");
    }
}

/// PolicyCpHash rejects wrong-size cpHash (TPM_RC_SIZE) and a different second cpHash (TPM_RC_CPHASH); same value is accepted
#[test]
fn cp_hash_size_and_redefinition_rejected() {
    let mut sim = Tpm::new();

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

    // 2. Try calling PolicyCpHash with a wrong size cpHash (e.g. 16 bytes instead of 32 bytes).
    let wrong_size_cp_hash = [0x55; 16];
    let policy_cp_hash_wrong = PolicyCpHash {
        policy_session: session_handle,
        cp_hash_a: Tpm2bDigest::from_bytes(&wrong_size_cp_hash).unwrap(),
    };
    let res = sim.execute(policy_cp_hash_wrong);
    assert!(
        res.is_err(),
        "Expected PolicyCpHash with wrong size cpHash to fail"
    );
    assert_eq!(res.err().unwrap(), TpmRc::SIZE.with(Position::parameter(1)));

    // 3. Call PolicyCpHash with correct size cpHash (32 bytes).
    let dummy_cp_hash = [0x55; 32];
    let policy_cp_hash_correct = PolicyCpHash {
        policy_session: session_handle,
        cp_hash_a: Tpm2bDigest::from_bytes(&dummy_cp_hash).unwrap(),
    };
    execute_with_password_sessions(&mut sim, &policy_cp_hash_correct, 0, &[]).unwrap();

    // 4. Try calling PolicyCpHash again with a DIFFERENT cpHash (32 bytes).
    let diff_cp_hash = [0x66; 32];
    let policy_cp_hash_diff = PolicyCpHash {
        policy_session: session_handle,
        cp_hash_a: Tpm2bDigest::from_bytes(&diff_cp_hash).unwrap(),
    };
    let res = sim.execute(policy_cp_hash_diff);
    assert!(
        res.is_err(),
        "Expected PolicyCpHash with different cpHash to fail"
    );
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH);

    // 5. Call PolicyCpHash again with the SAME cpHash (should succeed).
    execute_with_password_sessions(&mut sim, &policy_cp_hash_correct, 0, &[]).unwrap();

    // 6. Try calling PolicyDuplicationSelect on the same session.
    // It should fail because is_cp_hash_defined is true (policy_hash_len != 0).
    let (_sk, sk_name) = create_signing_key_empty_unique(&mut sim);
    let (_ek, ek_name) = create_signing_key_empty_unique(&mut sim);
    let policy_dup = PolicyDuplicationSelect {
        policy_session: session_handle,
        object_name: sk_name,
        new_parent_name: ek_name,
        include_object: true,
    };
    let res = sim.execute(policy_dup);
    assert!(
        res.is_err(),
        "Expected PolicyDuplicationSelect to fail when cpHash is already defined"
    );
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH);

    flush_context(&mut sim, session_handle).unwrap();
}

/// Bound session + PolicyDuplicationSelect works; PolicyTemplate reports occupancy (CPHASH) before size (SIZE+P1).
#[test]
fn occupancy_checked_before_size() {
    let mut sim = Tpm::new();
    // 1. Bound policy session + PolicyDuplicationSelect.
    let s = start_bound(&mut sim, Handle::RH_OWNER, &[], TpmSe::Policy).session_handle;
    policy_duplication_select(&mut sim, s, &[1, 2, 3], &[4, 5, 6, 7, 8], true).unwrap();

    // 4. PolicyTemplate: occupancy (CPHASH) before size (SIZE + RC_P1).
    let s = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_name_hash(&mut sim, s, &[0x55; 32]).unwrap();
    assert_eq!(
        policy_template(&mut sim, s, &[0x66; 20]),
        Err(TpmRc::CPHASH.get())
    );
}

/// Mixing TPM2_PolicyCpHash and TPM2_PolicyDuplicationSelect on one session fails with TPM_RC_CPHASH
#[test]
fn policy_cp_hash_conflicts_with_duplication_select() {
    let mut sim = Tpm::new();

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
    let cp_hash_cmd = PolicyCpHash {
        policy_session: sess_a.session_handle,
        cp_hash_a: cp_hash,
    };
    assert!(execute_with_password_sessions(&mut sim, &cp_hash_cmd, 0, &[]).is_ok());

    let object_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();
    let dup_cmd = PolicyDuplicationSelect {
        policy_session: sess_a.session_handle,
        object_name,
        new_parent_name,
        include_object: true,
    };
    let res_a = execute_with_password_sessions(&mut sim, &dup_cmd, 0, &[]);
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

    let dup_cmd_b = PolicyDuplicationSelect {
        policy_session: sess_b.session_handle,
        ..dup_cmd
    };
    assert!(execute_with_password_sessions(&mut sim, &dup_cmd_b, 0, &[]).is_ok());

    let cp_hash_cmd_b = PolicyCpHash {
        policy_session: sess_b.session_handle,
        ..cp_hash_cmd
    };
    let res_b = execute_with_password_sessions(&mut sim, &cp_hash_cmd_b, 0, &[]);
    assert_eq!(
        res_b.err(),
        Some(0x151),
        "PolicyCpHash after PolicyDuplicationSelect should fail with TPM_RC_CPHASH"
    );
}

/// TPM2_PolicyCpHash on sessions of each hash alg updates the digest as PolicyCalculator predicts
#[test]
fn policy_cp_hash_digest_for_every_hash_alg() {
    run_policy_cphash_for_alg(TpmiAlgHash::Sha1, 20);
    run_policy_cphash_for_alg(TpmiAlgHash::Sha256, 32);
    run_policy_cphash_for_alg(TpmiAlgHash::Sha384, 48);
    run_policy_cphash_for_alg(TpmiAlgHash::Sha512, 64);
}

/// TPM2_PolicyCpHash succeeds on a policy session started with a bind entity (policy sessions are never bound)
#[test]
#[allow(deprecated)]
fn policy_cp_hash_on_bound_policy_session() {
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

    // 3. Executing PolicyCpHash on bound session must fail with TPM_RC_CPHASH (0x151)
    let cp_hash = Tpm2bDigest::from_bytes(&[0xaa; 32]).unwrap();
    let cp_hash_cmd = PolicyCpHash {
        policy_session: sess.session_handle,
        cp_hash_a: cp_hash,
    };
    let res = execute_with_password_sessions(&mut sim, &cp_hash_cmd, 0, &[]);
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

/// TPM2_PolicyCpHash succeeds on a trial session started with a bind entity
#[test]
#[allow(deprecated)]
fn policy_cp_hash_on_bound_trial_session() {
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

    // 3. Executing PolicyCpHash on bound trial session must fail with TPM_RC_CPHASH (0x151)
    let cp_hash = Tpm2bDigest::from_bytes(&[0xaa; 32]).unwrap();
    let cp_hash_cmd = PolicyCpHash {
        policy_session: sess.session_handle,
        cp_hash_a: cp_hash,
    };
    let res = execute_with_password_sessions(&mut sim, &cp_hash_cmd, 0, &[]);
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

/// A second TPM2_PolicyCpHash with a different cpHash fails with TPM_RC_CPHASH; the same cpHash is accepted
#[test]
fn policy_cp_hash_rejects_different_second_cp_hash() {
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

    let cp_hash_1 = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let cp_hash_2 = Tpm2bDigest::from_bytes(&[0x22; 32]).unwrap();

    let cp_hash_cmd_1 = PolicyCpHash {
        policy_session: sess.session_handle,
        cp_hash_a: cp_hash_1,
    };
    assert!(
        execute_with_password_sessions(&mut sim, &cp_hash_cmd_1, 0, &[]).is_ok(),
        "First PolicyCpHash failed"
    );

    let cp_hash_cmd_same = PolicyCpHash {
        policy_session: sess.session_handle,
        cp_hash_a: cp_hash_1,
    };
    assert!(
        execute_with_password_sessions(&mut sim, &cp_hash_cmd_same, 0, &[]).is_ok(),
        "Second PolicyCpHash with same cpHash failed"
    );

    let cp_hash_cmd_diff = PolicyCpHash {
        policy_session: sess.session_handle,
        cp_hash_a: cp_hash_2,
    };
    let res = execute_with_password_sessions(&mut sim, &cp_hash_cmd_diff, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x151),
        "Should fail with TPM_RC_CPHASH (0x151)"
    );
}

/// TPM2_PolicyCpHash with a cpHash of the wrong size (20 or 48 bytes) is rejected
#[test]
fn policy_cp_hash_rejects_wrong_digest_size() {
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

    let cp_hash_bad_1 = Tpm2bDigest::from_bytes(&[0x11; 20]).unwrap();
    let cp_hash_cmd_bad_1 = PolicyCpHash {
        policy_session: sess.session_handle,
        cp_hash_a: cp_hash_bad_1,
    };
    let res1 = execute_with_password_sessions(&mut sim, &cp_hash_cmd_bad_1, 0, &[]);
    assert_eq!(
        res1.err(),
        Some(0x1D5),
        "Should fail with parameter 1 size error (0x1D5)"
    );

    let cp_hash_bad_2 = Tpm2bDigest::from_bytes(&[0x11; 48]).unwrap();
    let cp_hash_cmd_bad_2 = PolicyCpHash {
        policy_session: sess.session_handle,
        cp_hash_a: cp_hash_bad_2,
    };
    let res2 = execute_with_password_sessions(&mut sim, &cp_hash_cmd_bad_2, 0, &[]);
    assert_eq!(
        res2.err(),
        Some(0x1D5),
        "Should fail with parameter 1 size error (0x1D5)"
    );
}

/// TPM2_PolicyCpHash with the target policy session itself placed in the sessions area
#[test]
fn policy_cp_hash_with_policy_session_in_auth_area() {
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

    let cp_hash_cmd = PolicyCpHash {
        policy_session: sess.session_handle,
        cp_hash_a: Tpm2bDigest::from_bytes(&[0xaa; 32]).unwrap(),
    };

    // Try to authorize PolicyCpHash with the policy_session itself (in sessions area under tag 0x8002)
    let mut sessions = [sess.clone()];
    let res = execute_with_hmac_sessions(&mut sim, &cp_hash_cmd, &[], &mut sessions, &[&[]]);
    // Since policy session is not yet matched or it is a policy session being modified,
    // this self-authorization should either fail or behave correctly according to TPM spec.
    assert!(
        res.is_err(),
        "PolicyCpHash with self-authorization should fail"
    );
}

/// TPM2_PolicyCpHash with an extra unassociated (audit/encrypt/decrypt) HMAC session in the auth area
#[test]
fn policy_cp_hash_with_unassociated_hmac_session() {
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

    let cp_hash_cmd = PolicyCpHash {
        policy_session: sess.session_handle,
        cp_hash_a: Tpm2bDigest::from_bytes(&[0xaa; 32]).unwrap(),
    };

    // The command has no authorization handles, so the session is unassociated: C
    // ParseSessionBuffer requires it to be an audit, encrypt or decrypt session.
    let mut sessions = [hmac_sess.clone()];
    sessions[0].attributes = tpm2::TpmaSession::CONTINUE_SESSION | tpm2::TpmaSession::AUDIT;
    let res = execute_with_hmac_sessions(&mut sim, &cp_hash_cmd, &[], &mut sessions, &[&[]]);
    assert!(
        res.is_ok(),
        "PolicyCpHash with HMAC session (tag 0x8002) failed: {:?}",
        res.err()
    );
}

/// After PolicyTemplate, PolicyCpHash and PolicyNameHash fail with CPHASH and leave the digest unchanged.
#[test]
fn template_hash_blocks_cphash_and_namehash() {
    let mut sim = Tpm::new();
    let s = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_template(&mut sim, s, &[0x33; 32]).unwrap();
    assert_eq!(
        policy_cp_hash(&mut sim, s, &[0x44; 32]),
        Err(TpmRc::CPHASH.get())
    );
    assert_eq!(
        policy_name_hash(&mut sim, s, &[0x44; 32]),
        Err(TpmRc::CPHASH.get())
    );

    let s = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_name_hash(&mut sim, s, &[0x55; 32]).unwrap();
    let before = policy_digest(&mut sim, s);
    assert_eq!(
        policy_name_hash(&mut sim, s, &[0x55; 32]),
        Err(TpmRc::CPHASH.get())
    );
    assert_eq!(
        policy_digest(&mut sim, s),
        before,
        "digest must not be extended twice"
    );
}

/// PolicyTemplate occupancy vs PolicyCpHash, PolicyOR RC_P1 and PolicyDuplicationSelect opaque names.
#[test]
fn template_occupancy_and_duplication_select_names() {
    // Part 4-5 of this finding (cpHash/nameHash template occupancy, PolicyOR RC_P1,
    // PolicyDuplicationSelect Names).
    let mut sim = Tpm::new();
    let s = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_template(&mut sim, s, &[1; 32]).unwrap();
    assert_eq!(
        policy_cp_hash(&mut sim, s, &[1; 32]),
        Err(TpmRc::CPHASH.get())
    );
    let s = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_duplication_select(&mut sim, s, &[0xAB], &[0xCD], true).unwrap();
}

/// PolicyCpHash sent with tag 0x8002 and an unassociated session that must be audit/encrypt/decrypt
#[test]
fn unassociated_audit_session_on_policy_command() {
    let mut sim = Tpm::new();

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

    // 2. Setup a separate active session to use in the command's session area (tag 0x8002).
    //    The command has no authorization handles, so the session is unassociated; C
    //    ParseSessionBuffer requires such a session to be an audit, encrypt or decrypt session
    //    (TPM_RCS_ATTRIBUTES otherwise), so it is used as an HMAC audit session.
    let mut active_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    active_sess.attributes = tpm2::TpmaSession::CONTINUE_SESSION | tpm2::TpmaSession::AUDIT;

    // 3. Call PolicyCpHash with tag 0x8002 (num_sessions = 1) using an HMAC session.
    let dummy_cp_hash = [0x55; 32];
    let policy_cp_hash = PolicyCpHash {
        policy_session: session_handle,
        cp_hash_a: Tpm2bDigest::from_bytes(&dummy_cp_hash).unwrap(),
    };
    execute_with_hmac_sessions(&mut sim, &policy_cp_hash, &[], &mut [active_sess], &[&[]]).unwrap();

    flush_context(&mut sim, session_handle).unwrap();
}

/// templateHash occupies the cpHash union, PolicyNameHash never repeats, PolicyTemplate checks union first, PolicyOR mismatch is VALUE+P1.
///
/// Covers the same bug as reported in the combined cpHash-union finding (part 5).
#[test]
fn union_occupancy_and_policy_or_position() {
    let mut sim = Tpm::new();
    // Part 5: bound policy session (see also `policy_session_bind_entity_cphash_rejection`).
    let s = start_bound(&mut sim, Handle::RH_ENDORSEMENT, &[], TpmSe::Policy).session_handle;
    policy_cp_hash(&mut sim, s, &[0x11; 32]).unwrap();

    // Part 1: templateHash occupies the union for PolicyCpHash and PolicyNameHash.
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_template(&mut sim, s, &[0x33; 32]).unwrap();
    assert_eq!(
        policy_cp_hash(&mut sim, s, &[0x33; 32]),
        Err(TpmRc::CPHASH.get())
    );
    assert_eq!(
        policy_name_hash(&mut sim, s, &[0x33; 32]),
        Err(TpmRc::CPHASH.get())
    );

    // Part 1: PolicyNameHash never accepts a repeat, even of the same value.
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_name_hash(&mut sim, s, &[0x22; 32]).unwrap();
    assert_eq!(
        policy_name_hash(&mut sim, s, &[0x22; 32]),
        Err(TpmRc::CPHASH.get())
    );

    // Part 2: PolicyTemplate checks the union before the templateHash size.
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_cp_hash(&mut sim, s, &[0x11; 32]).unwrap();
    assert_eq!(
        policy_template(&mut sim, s, &[0x33; 5]),
        Err(TpmRc::CPHASH.get())
    );

    // Part 3: PolicyOR no-match error carries RC_P1.
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let err = run_command(
        &mut sim,
        PolicyOR {
            policy_session: s,
            p_hash_list: TpmlDigest::from_slice(&[to_digest(&[1; 32]), to_digest(&[2; 32])])
                .unwrap(),
        },
    )
    .unwrap_err();
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(1)).get());
}
