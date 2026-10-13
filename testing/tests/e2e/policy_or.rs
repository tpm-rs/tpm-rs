//! TPM2_PolicyOR: digest list validation and policy branches.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{CreatePrimary, NVDefineSpace, PolicyGetDigest, PolicyOR, PolicySecret};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, Tpm2bSensitiveData, TpmCc, TpmSe, TpmaNv,
    TpmiAlgHash, TpmlDigest, TpmlPcrSelection, TpmsNvPublic, TpmsSensitiveCreate, *,
};

/// ECC-EK salted policy session, PolicySecret with an NV index auth handle, then PolicyOR; digests match expectations.
#[test]
fn ecc_salted_session_policy_secret_nv_and_or() {
    let mut sim = Tpm::new();

    // -------------------------------------------------------------
    // Step 1: Create ECC Endorsement Key (used for ECC KDFe salting)
    // -------------------------------------------------------------
    let ecc_ek = ecc_ek_template();
    let in_public = tpm2::Tpm2b(ecc_ek);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let create_primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let cp_resp = execute_with_password_sessions(&mut sim, &create_primary_cmd, 1, &[]).unwrap();

    let ek_handle = cp_resp.object_handle;
    let _ek_public_struct = cp_resp.out_public.0;

    // -------------------------------------------------------------
    // Step 2: Define an NV Index (used for PolicySecret name resolution)
    // -------------------------------------------------------------
    let nv_index_val = 0x01600099;
    let nv_pub = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    };
    let public_info = tpm2::Tpm2b(nv_pub);
    let define_cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        public_info,
        auth: Tpm2bAuth::default(),
    };
    execute_with_password_sessions(&mut sim, &define_cmd, 1, &[]).unwrap();

    // -------------------------------------------------------------
    // Step 3: Start a salted policy session using the ECC EK (ECC KDFe Salting)
    // -------------------------------------------------------------
    let mut rng = client_rng();
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    // Generate ephemeral key pair
    let eph_private = p256::SecretKey::random(&mut rng);
    let eph_public = eph_private.public_key();
    let eph_encoded = eph_public.to_encoded_point(false);
    let eph_xy = eph_encoded.as_bytes(); // starts with 0x04, length 65
    assert_eq!(eph_xy[0], 0x04);

    let eph_point = tpm2::TpmsEccPoint {
        x: tpm2::Tpm2bEccParameter::from_bytes(&eph_xy[1..33]).unwrap(),
        y: tpm2::Tpm2bEccParameter::from_bytes(&eph_xy[33..65]).unwrap(),
    };
    let mut enc_salt_bytes = [0u8; 1024];
    let len = marshal_to_slice(&eph_point, &mut enc_salt_bytes);
    let encrypted_salt =
        tpm2::Tpm2bEncryptedSecret::from_bytes(leak_bytes(&enc_salt_bytes[..len])).unwrap();

    // Start auth session command
    let nonce_caller = Tpm2bNonce::from_bytes(&[5u8; 32]).unwrap();
    let start_sess_cmd = tpm2::commands::StartAuthSession {
        tpm_key: ek_handle,
        bind: Handle::RH_NULL,
        nonce_caller,
        encrypted_salt,
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_sess_resp =
        execute_with_password_sessions(&mut sim, &start_sess_cmd, 0, &[]).unwrap();

    let policy_session_handle = start_sess_resp.session_handle;

    // -------------------------------------------------------------
    // Step 4: Execute PolicySecret with NV Index handle as auth_handle
    // -------------------------------------------------------------
    let policy_secret_cmd = PolicySecret {
        auth_handle: Handle(nv_index_val),
        policy_session: policy_session_handle,
        nonce_tpm: start_sess_resp.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    execute_with_password_sessions(&mut sim, &policy_secret_cmd, 1, &[]).unwrap();

    // Get current policy digest after PolicySecret
    let get_digest_cmd = PolicyGetDigest {
        policy_session: policy_session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();

    // Calculate expected digest after PolicySecret
    let nv_name = nv_name(&nv_pub);
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_secret(nv_name.get_buffer(), &[]);

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        pol.policy_digest.as_slice(),
        "PolicySecret digest should match after NV Index Name resolution"
    );

    // -------------------------------------------------------------
    // Step 5: Execute PolicyOR with concatenated hash updates
    // -------------------------------------------------------------
    let current_digest = get_digest_rsp.policy_digest;
    let dummy_digest = Tpm2bDigest::from_bytes(&[8u8; 32]).unwrap();

    let p_hash_list = TpmlDigest::from_slice(&[current_digest, dummy_digest]).unwrap();
    let policy_or_cmd = PolicyOR {
        policy_session: policy_session_handle,
        p_hash_list,
    };
    execute_with_password_sessions(&mut sim, &policy_or_cmd, 0, &[]).unwrap();

    // Get policy digest after PolicyOR
    let get_digest_rsp_2 =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();

    let expected_or = policy_or_expected(
        TpmiAlgHash::Sha256,
        &[current_digest.get_buffer(), dummy_digest.get_buffer()],
    );

    assert_eq!(
        get_digest_rsp_2.policy_digest.get_buffer(),
        expected_or.as_slice(),
        "PolicyOR digest should match after concatenated hash updates"
    );
}

/// PolicyOR with an empty pHashList fails
#[test]
fn empty_hash_list_rejected() {
    let mut sim = Tpm::new();

    // Start a Trial session
    let trial_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let p_hash_list = TpmlDigest::from_slice(&[]).unwrap(); // Empty list!
    let cmd = PolicyOR {
        policy_session: trial_session.session_handle,
        p_hash_list,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(
        res.is_err(),
        "BUG: PolicyOR succeeded with an empty digest list! Spec requires size >= 2."
    );
}

/// PolicyOR with an empty digest list fails with SIZE+P1.
#[test]
fn empty_list_rejected() {
    let mut sim = Tpm::new();
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let p_hash_list = TpmlDigest::from_slice(&[]).unwrap();
    let cmd = PolicyOR {
        policy_session: active_session.session_handle,
        p_hash_list,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    // Empty list should fail with Size error on parameter 1 according to spec
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(tpm2::errors::Position::parameter(1)).get())
    );
}

/// PolicyOR succeeds when the current digest is in the list and can be chained again
#[test]
fn matching_digest_chains_policy_or() {
    let mut sim = Tpm::new();

    // Start Policy session
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Initial policy digest is Zero Digest (32 bytes of 0)
    let zero_digest = Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap();
    let dummy_digest = Tpm2bDigest::from_bytes(&[1u8; 32]).unwrap();

    // 1. Call PolicyOR with list containing zero_digest and dummy_digest. Should succeed.
    let p_hash_list = TpmlDigest::from_slice(&[zero_digest, dummy_digest]).unwrap();
    let cmd = PolicyOR {
        policy_session: policy_session.session_handle,
        p_hash_list,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyOR failed with valid digest list containing current digest"
    );

    // 2. Call PolicyOR again. The current digest is now: hash(zero_digest || TPM_CC_PolicyOR || pHashList)
    // If we call PolicyOR with a list NOT containing this new digest, it should fail.
    let bad_list = TpmlDigest::from_slice(&[zero_digest, dummy_digest]).unwrap();
    let cmd_bad = PolicyOR {
        policy_session: policy_session.session_handle,
        p_hash_list: bad_list,
    };
    let res_bad = execute_with_password_sessions(&mut sim, &cmd_bad, 0, &[]);
    assert!(
        res_bad.is_err(),
        "BUG/Anomaly: PolicyOR did not fail when current digest is missing from list"
    );
}

/// PolicyOR without a matching digest fails with VALUE+P1; a matching digest is accepted.
#[test]
fn mismatch_reports_parameter_one() {
    let mut sim = Tpm::new();
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let err = run_command(
        &mut sim,
        PolicyOR {
            policy_session: s,
            p_hash_list: TpmlDigest::from_slice(&[to_digest(&[7; 32]), to_digest(&[8; 32])])
                .unwrap(),
        },
    )
    .unwrap_err();
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(1)).get());

    // A matching digest is still accepted.
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    run_command(
        &mut sim,
        PolicyOR {
            policy_session: s,
            p_hash_list: TpmlDigest::from_slice(&[to_digest(&[0; 32]), to_digest(&[8; 32])])
                .unwrap(),
        },
    )
    .unwrap();
}

/// PolicyOR with digests of different sizes is TPM_RC_VALUE + RC_P1 in a policy session
#[test]
fn mixed_digest_sizes_rejected() {
    let mut sim = Tpm::new();

    // Start a Trial session
    let trial_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Elements with different sizes: 20 bytes (SHA1) and 32 bytes (SHA256)
    let digest1 = Tpm2bDigest::from_bytes(&[1u8; 20]).unwrap();
    let digest2 = Tpm2bDigest::from_bytes(&[2u8; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[digest1, digest2]).unwrap();
    let cmd = PolicyOR {
        policy_session: trial_session.session_handle,
        p_hash_list,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(
        res.is_ok(),
        "Trial session should succeed when digest sizes are mismatching"
    );

    // Policy session should fail with Value
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let cmd = PolicyOR {
        policy_session: policy_session.session_handle,
        ..cmd
    };
    let res_policy = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    // TPM_RCS_VALUE + RC_PolicyOR_pHashList (C PolicyOR.c).
    assert_eq!(
        res_policy.err(),
        Some(0x1C4),
        "Policy session should fail with Value (+RC_P1) when digest sizes are mismatching"
    );
}

/// PolicyOR in a policy session succeeds when the current digest is in the list.
#[test]
fn policy_session_with_matching_digest() {
    let mut sim = Tpm::new();
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Get current policy digest (starts at zero digest)
    let get_digest_cmd = PolicyGetDigest {
        policy_session: active_session.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();
    let current_digest = get_digest_rsp.policy_digest;

    // Use current_digest in the list
    let digest2 = Tpm2bDigest::from_bytes(&[2; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[current_digest, digest2]).unwrap();

    let cmd = PolicyOR {
        policy_session: active_session.session_handle,
        p_hash_list,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyOR on Policy session failed: {:?}",
        res.err()
    );
}

/// PolicyOR in a policy session fails with VALUE+P1 when the current digest is not listed.
#[test]
fn policy_session_without_matching_digest() {
    let mut sim = Tpm::new();
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Digests in list do not match current zero digest
    let digest1 = Tpm2bDigest::from_bytes(&[1; 32]).unwrap();
    let digest2 = Tpm2bDigest::from_bytes(&[2; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[digest1, digest2]).unwrap();

    let cmd = PolicyOR {
        policy_session: active_session.session_handle,
        p_hash_list,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    // Should return Value error since current digest is not in list:
    // TPM_RCS_VALUE + RC_PolicyOR_pHashList (VALUE+P1, PolicyOR.c:63).
    assert_eq!(
        res.err(),
        Some(
            TpmRc::VALUE
                .with(tpm2::errors::Position::parameter(1))
                .get()
        )
    );
}

/// PolicyOR with a single-entry pHashList fails
#[test]
fn single_entry_hash_list_rejected() {
    let mut sim = Tpm::new();

    // Start a Trial session
    let trial_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let digest = Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[digest]).unwrap(); // Single element!
    let cmd = PolicyOR {
        policy_session: trial_session.session_handle,
        p_hash_list,
    };

    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(
        res.is_err(),
        "BUG: PolicyOR succeeded with a single digest list! Spec requires size >= 2."
    );
}

/// PolicyOR in a trial session updates the digest to H(0 || TPM_CC_PolicyOR || digests)
#[test]
fn trial_digest_update() {
    let mut sim = Tpm::new();

    // Start a Trial session
    let trial_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let digest1 = Tpm2bDigest::from_bytes(&[1u8; 32]).unwrap();
    let digest2 = Tpm2bDigest::from_bytes(&[2u8; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[digest1, digest2]).unwrap();
    let cmd = PolicyOR {
        policy_session: trial_session.session_handle,
        p_hash_list,
    };

    execute_with_password_sessions(&mut sim, &cmd, 0, &[]).unwrap();

    // Verify policy digest is updated to H(0 || TPM_CC_PolicyOR || p_hash_list)
    let get_digest_cmd = PolicyGetDigest {
        policy_session: trial_session.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Zero digest (32 bytes)
    hasher.update([0u8; 32]);
    // TPM_CC_PolicyOR
    hasher.update((TpmCc::PolicyOR.code()).to_be_bytes());
    // Concatenated raw digests from p_hash_list
    for digest in p_hash_list.digests() {
        hasher.update(digest.get_buffer());
    }
    let expected_digest = hasher.finalize();

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        expected_digest.as_slice()
    );
}

/// PolicyOR in a trial session succeeds with arbitrary digests.
#[test]
fn trial_session_accepts_any_list() {
    let mut sim = Tpm::new();
    let active_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let digest1 = Tpm2bDigest::from_bytes(&[1; 32]).unwrap();
    let digest2 = Tpm2bDigest::from_bytes(&[2; 32]).unwrap();
    let p_hash_list = TpmlDigest::from_slice(&[digest1, digest2]).unwrap();

    let cmd = PolicyOR {
        policy_session: active_session.session_handle,
        p_hash_list,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyOR on Trial session failed: {:?}",
        res.err()
    );
}

/// PolicyOR on a trial session succeeds even when the current digest is not in the list.
#[test]
fn trial_session_skips_digest_match() {
    let mut sim = Tpm::new();

    // Start a Trial session
    let trial_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // For a Trial session, PolicyOR should bypass size and matching checks.
    let digest1 = Tpm2bDigest::from_bytes(&[10u8; 32]).unwrap();
    let digest2 = Tpm2bDigest::from_bytes(&[20u8; 32]).unwrap();

    let p_hash_list = TpmlDigest::from_slice(&[digest1, digest2]).unwrap();
    let policy_or_cmd = PolicyOR {
        policy_session: trial_session.session_handle,
        p_hash_list,
    };
    // This should succeed even though the current policy digest is NOT in the list!
    let res = execute_with_password_sessions(&mut sim, &policy_or_cmd, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyOR on Trial session should bypass checks and succeed, got: {:?}",
        res.err()
    );

    // Get policy digest after PolicyOR
    let get_digest_cmd = PolicyGetDigest {
        policy_session: trial_session.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();

    let expected_or = policy_or_expected(
        TpmiAlgHash::Sha256,
        &[digest1.get_buffer(), digest2.get_buffer()],
    );

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        expected_or.as_slice(),
        "Trial session policy digest should be updated correctly"
    );
}
