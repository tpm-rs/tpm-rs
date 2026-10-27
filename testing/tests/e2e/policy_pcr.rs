//! TPM2_PolicyPCR: PCR selection hashing and digest checks.

use crate::_common::get_expected_pcr_digest;
use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{
    CreatePrimary, PolicyAuthValue, PolicyGetDigest, PolicyPCR, StartAuthSession,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce,
    Tpm2bSensitiveData, TpmCc, TpmSe, TpmaObject, TpmiAlgHash, TpmlPcrSelection, TpmsEccParms,
    TpmsPcrSelection, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic,
};

/// PolicyPCR hashes banks in caller order, uses the computed digest in SHA-1 trial sessions and reports pcrDigest as P1.
#[test]
fn banks_in_caller_order_and_sha1_trial() {
    let mut sim = Tpm::new();
    // Banks deliberately not in algorithm-ID order: SHA-384 (0x0C) before SHA-256 (0x0B).
    let pcrs = [
        pcr_sel(TpmiAlgHash::Sha384, &[1, 0, 0]),
        pcr_sel(TpmiAlgHash::Sha256, &[1, 0, 0]),
    ];
    // PCR 0 is all-zero after TPM2_Startup(CLEAR).
    let expected = expected_policy_pcr(TpmiAlgHash::Sha256, &pcrs, &[&[0; 48], &[0; 32]]);

    let trial = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_pcr(&mut sim, trial, &[], &pcrs).unwrap();
    assert_eq!(policy_digest(&mut sim, trial), expected);

    let policy =
        start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_pcr(&mut sim, policy, &[], &pcrs).unwrap();
    assert_eq!(policy_digest(&mut sim, policy), expected);

    // SHA-1 trial session with an empty pcrDigest uses the computed PCR digest.
    let pcrs1 = [pcr_sel(TpmiAlgHash::Sha256, &[1, 0, 0])];
    let trial = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha1).session_handle;
    policy_pcr(&mut sim, trial, &[], &pcrs1).unwrap();
    assert_eq!(
        policy_digest(&mut sim, trial),
        expected_policy_pcr(TpmiAlgHash::Sha1, &pcrs1, &[&[0; 32]])
    );

    // pcrDigest is parameter 1.
    let policy =
        start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_pcr(&mut sim, policy, &[0xEE; 32], &pcrs1),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}

/// PolicyPCR accepts a selection listing the SHA-256 bank twice (each selection hashed in order, like C)
#[test]
fn duplicate_hash_bank_selection_accepted() {
    let mut sim = Tpm::new();

    // Start a policy session
    let active_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Create a selection with duplicate SHA256 bank
    let mut select_bytes_1 = [0u8; 3];
    select_bytes_1[0] = 0x01; // PCR 0
    let mut select_bytes_2 = [0u8; 3];
    select_bytes_2[0] = 0x02; // PCR 1

    let selection = TpmlPcrSelection::from_slice(&[
        TpmsPcrSelection::new(TpmiAlgHash::Sha256, &select_bytes_1).unwrap(),
        TpmsPcrSelection::new(TpmiAlgHash::Sha256, &select_bytes_2).unwrap(),
    ])
    .unwrap();

    let policy_pcr = PolicyPCR {
        policy_session: active_sess.session_handle,
        pcr_digest: Tpm2bDigest::default(),
        pcrs: selection,
    };

    // C (TPML_PCR_SELECTION_Unmarshal / PCRComputeCurrentDigest) does not reject a repeated
    // bank: each selection is hashed in order.
    let res = sim.execute(policy_pcr);
    assert!(res.is_ok(), "duplicate banks are accepted: {:?}", res.err());

    let _ = flush_context(&mut sim, active_sess.session_handle);
}

/// PolicyPCR with an empty PCR selection succeeds on a policy session
#[test]
fn empty_pcr_selection_accepted() {
    let mut sim = Tpm::new();

    let active_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let selection = TpmlPcrSelection::from_slice(&[]).unwrap();

    let policy_pcr = PolicyPCR {
        policy_session: active_sess.session_handle,
        pcr_digest: Tpm2bDigest::default(),
        pcrs: selection,
    };

    let res = sim.execute(policy_pcr);
    assert!(
        res.is_ok(),
        "Expected PolicyPCR with empty selection to succeed"
    );

    let _ = flush_context(&mut sim, active_sess.session_handle);
}

/// PolicyPCR with an unsupported hash in the PCR selection fails with TPM_RC_HASH on pcrs (TC2_1_25_19_02).
///
/// Regression test for CPCTPM_TC2_1_25_19_02:
/// TPM2_PolicyPCR with an unsupported hash algorithm in pcrs (0xFFFF)
/// must return TPM_RC_HASH (Parameter 1, 0x01C3).
#[test]
fn invalid_selection_hash_rejected() {
    let mut sim = Tpm::new();

    // Start a trial policy session
    let session_handle = start_trial_session(&mut sim);

    // Send PolicyPCR with invalid hash algorithm 0xFFFF in PCR selection
    let mut policy_pcr_req = hex_checked(concat!(
        "8001",     // NO_SESSIONS
        "0000001a", // size: 26 bytes
        "0000017f", // TPM_CC_PolicyPCR
        "03000000", // sessionHandle
        "0000",     // pcrDigest size: 0
        "00000001", // count: 1
        "ffff",     // hash: 0xFFFF (invalid)
        "03",       // sizeofSelect: 3
        "010000",   // pcrSelect
    ));
    let len = policy_pcr_req.len() as u32;
    policy_pcr_req[2..6].copy_from_slice(&len.to_be_bytes());
    policy_pcr_req[10..14].copy_from_slice(&session_handle.0.to_be_bytes());

    let rc = raw_rc(&mut sim, &policy_pcr_req);
    // pcrs is the second parameter of TPM2_PolicyPCR (pcrDigest is the first).
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(2)).get(),
        "Expected TPM_RC_HASH + RC_P2 for PolicyPCR with invalid hash algorithm in PCR selection"
    );
}

/// PolicyPCR with a PCR selection count above `HASH_COUNT` fails with TPM_RC_SIZE on pcrs, even
/// if the first selection's hash is also invalid (the count is checked first; found by
/// differential fuzzing). Part 2 `TPML_PCR_SELECTION`: `count` has `#TPM_RC_SIZE` and is unmarshaled
/// before `pcrSelections`.
#[test]
fn oversized_selection_count_rejected_before_hash() {
    let mut sim = Tpm::new();
    let session_handle = start_trial_session(&mut sim);
    let mut req = hex_checked(concat!(
        "8001",     // NO_SESSIONS
        "0000001a", // size: 26 bytes
        "0000017f", // TPM_CC_PolicyPCR
        "03000000", // sessionHandle
        "0000",     // pcrDigest size: 0
        "5f545241", // count: far above HASH_COUNT
        "ffff",     // hash: 0xFFFF (invalid)
        "03",       // sizeofSelect: 3
        "010000",   // pcrSelect
    ));
    req[10..14].copy_from_slice(&session_handle.0.to_be_bytes());
    // A count far above HASH_COUNT, and one just above this TPM's HASH_COUNT (4 banks).
    for count in [0x5f54_5241u32, 5] {
        req[16..20].copy_from_slice(&count.to_be_bytes());
        assert_eq!(
            raw_rc(&mut sim, &req),
            TpmRc::SIZE.with(Position::parameter(2)).get(),
            "count {count:#x}"
        );
    }
}

/// PolicyPCR with a pcrDigest not matching current PCR values fails with TPM_RC_VALUE + RC_P1
#[test]
fn pcr_digest_mismatch_rejected() {
    let mut sim = Tpm::new();

    let active_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut select_bytes = [0u8; 3];
    select_bytes[0] = 0x01; // PCR 0
    let selection =
        TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha256, &select_bytes).unwrap()
        ])
        .unwrap();

    let policy_pcr = PolicyPCR {
        policy_session: active_sess.session_handle,
        pcr_digest: Tpm2bDigest::from_bytes(&[0xcd; 32]).unwrap(),
        pcrs: selection,
    };

    let res = sim.execute(policy_pcr);
    assert!(res.is_err(), "Expected PolicyPCR with wrong digest to fail");
    // pcrDigest is parameter 1 (TPM_RCS_VALUE + RC_PolicyPCR_pcrDigest).
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE.with(Position::parameter(1))
    );

    let _ = flush_context(&mut sim, active_sess.session_handle);
}

/// Key gated by PolicyPCR(PCR0): extending the PCR after PolicyPCR makes use of the policy session fail with TPM_RC_PCR_CHANGED
#[test]
#[allow(deprecated)]
fn pcr_extend_after_policy_pcr_fails_with_pcr_changed() {
    let mut sim = Tpm::new();
    let password = b"foo";

    // Step 1: Calculate policy digest of PolicyPCR using trial session
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

    let mut select_bytes = [0u8; 3];
    select_bytes[0] = 0x01; // PCR 0
    let selection =
        TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha256, &select_bytes).unwrap()
        ])
        .unwrap();

    let expected_digest = get_expected_pcr_digest(&mut sim, &selection);

    let policy_pcr = PolicyPCR {
        policy_session: start_rsp_handles.session_handle,
        pcr_digest: Tpm2bDigest::from_bytes(&expected_digest).unwrap(),
        pcrs: selection,
    };
    execute_with_password_sessions(&mut sim, &policy_pcr, 0, &[]).unwrap();

    let get_digest = PolicyGetDigest {
        policy_session: start_rsp_handles.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest, 0, &[]).unwrap();

    // Step 2: Create a primary key with this authPolicy
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: tpm2::TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: get_digest_rsp.policy_digest,
        parms_and_id: PublicParmsAndId::Ecc(ecc_parms, tpm2::TpmsEccPoint::default()),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_primary = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create_primary, 1, &[])
        .expect("could not call TPM2_CreatePrimary");

    // Flush trial session
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);

    // Step 3: Start real policy session
    let active_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Step 4: PolicyPCR gating
    let policy_pcr_real = PolicyPCR {
        policy_session: active_sess.session_handle,
        pcr_digest: Tpm2bDigest::from_bytes(&expected_digest).unwrap(),
        pcrs: selection,
    };
    sim.execute(policy_pcr_real).unwrap();

    // Step 5: Extend PCR 0, incrementing the PCR update counter
    let mut digests = tpm2::TpmlDigestValues::default();
    digests.add(&tpm2::TpmtHa::Sha256(&[0xaa; 32])).unwrap();
    let extend_cmd = tpm2::commands::PCRExtend {
        pcr_handle: Handle(0),
        digests,
    };
    execute_with_password_sessions(&mut sim, &extend_cmd, 1, &[]).unwrap();

    // Step 6: Attempt to Sign with the session
    let mut final_session = active_sess.clone();
    final_session.bind_auth = password.to_vec();
    final_session.attributes = tpm2::TpmaSession::from_bits_retain(1);

    let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let sign_cmd = tpm2::commands::Sign {
        key_handle: rsp_handles.object_handle,
        digest: digest_to_sign,
        in_scheme: None,
        validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };

    let res = execute_with_hmac_sessions_status(
        &mut sim,
        &sign_cmd,
        &[],
        &mut [final_session],
        &[password],
    );

    // The sign command SHOULD fail with TPM_RC_PCR_CHANGED (0x128) because PCR 0 was extended
    // after calling PolicyPCR on this session!
    assert!(
        res.is_err(),
        "Expected Sign to fail because PCR was extended after gating!"
    );
    let err = res.err().unwrap();
    assert_eq!(err, TpmRc::PCR_CHANGED.get());

    // Flush the session
    let _ = flush_context(&mut sim, active_sess.session_handle);
}

/// Key policy PolicyPCR+PolicyAuthValue: digest computed in trial session; use succeeds only with correct authValue HMAC and unchanged PCR
#[test]
#[allow(deprecated)]
fn policy_pcr_combined_with_policy_auth_value() {
    let mut sim = Tpm::new();
    let password = b"barpassword";

    // 1. Calculate combined policy digest: PolicyPCR followed by PolicyAuthValue
    let mut select_bytes = [0u8; 3];
    select_bytes[0] = 0x02; // PCR 1
    let selection =
        TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha256, &select_bytes).unwrap()
        ])
        .unwrap();

    let pcr_digest_val = get_expected_pcr_digest(&mut sim, &selection);

    // Compute expected policy digest using trial session
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

    // Call PolicyPCR
    let policy_pcr = PolicyPCR {
        policy_session: start_rsp_handles.session_handle,
        pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
        pcrs: selection,
    };
    execute_with_password_sessions(&mut sim, &policy_pcr, 0, &[]).unwrap();

    // Call PolicyAuthValue
    let pav = PolicyAuthValue {
        policy_session: start_rsp_handles.session_handle,
    };
    execute_with_password_sessions(&mut sim, &pav, 0, &[]).unwrap();

    // Get the final digest
    let get_digest = PolicyGetDigest {
        policy_session: start_rsp_handles.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest, 0, &[]).unwrap();

    // Flush trial session
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);

    // 2. Create key with this combined policy
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: tpm2::TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: get_digest_rsp.policy_digest,
        parms_and_id: PublicParmsAndId::Ecc(ecc_parms, tpm2::TpmsEccPoint::default()),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_primary = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create_primary, 1, &[])
        .expect("could not call TPM2_CreatePrimary");

    // 3. Sub-tests for verifying various authorization paths

    // Sub-test A: Correct sequence (PolicyPCR then PolicyAuthValue) + Correct Password -> Sign succeeds
    {
        let active_sess = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::Policy,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();

        let policy_pcr_real = PolicyPCR {
            policy_session: active_sess.session_handle,
            pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
            pcrs: selection,
        };
        sim.execute(policy_pcr_real).unwrap();

        let pav_real = PolicyAuthValue {
            policy_session: active_sess.session_handle,
        };
        sim.execute(pav_real).unwrap();

        let mut final_session = active_sess.clone();
        final_session.bind_auth = password.to_vec();
        // TPM2_PolicyAuthValue was executed on this session above.
        final_session.mark_policy_auth_value();

        let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
        let sign_cmd = tpm2::commands::Sign {
            key_handle: rsp_handles.object_handle,
            digest: digest_to_sign,
            in_scheme: None,
            validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
        };

        let res = execute_with_hmac_sessions_status(
            &mut sim,
            &sign_cmd,
            &[],
            &mut [final_session],
            &[password],
        );
        assert!(
            res.is_ok(),
            "Expected Sign to succeed with correct combined policy and password"
        );

        let _ = flush_context(&mut sim, active_sess.session_handle);
    }

    // Sub-test B: Correct sequence + INCORRECT Password -> Sign fails
    {
        let active_sess = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::Policy,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();

        let policy_pcr_real = PolicyPCR {
            policy_session: active_sess.session_handle,
            pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
            pcrs: selection,
        };
        sim.execute(policy_pcr_real).unwrap();

        let pav_real = PolicyAuthValue {
            policy_session: active_sess.session_handle,
        };
        sim.execute(pav_real).unwrap();

        let mut final_session = active_sess.clone();
        final_session.bind_auth = b"wrongpwd".to_vec();
        // TPM2_PolicyAuthValue was executed on this session above.
        final_session.mark_policy_auth_value();

        let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
        let sign_cmd = tpm2::commands::Sign {
            key_handle: rsp_handles.object_handle,
            digest: digest_to_sign,
            in_scheme: None,
            validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
        };

        let res = execute_with_hmac_sessions_status(
            &mut sim,
            &sign_cmd,
            &[],
            &mut [final_session],
            &[b"wrongpwd"],
        );
        assert!(res.is_err(), "Expected Sign to fail with wrong password");

        let _ = flush_context(&mut sim, active_sess.session_handle);
    }

    // Sub-test C: Incomplete sequence (only PolicyPCR called) -> Sign fails
    {
        let active_sess = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::Policy,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();

        let policy_pcr_real = PolicyPCR {
            policy_session: active_sess.session_handle,
            pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
            pcrs: selection,
        };
        sim.execute(policy_pcr_real).unwrap();

        let mut final_session = active_sess.clone();
        final_session.bind_auth = password.to_vec();

        let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
        let sign_cmd = tpm2::commands::Sign {
            key_handle: rsp_handles.object_handle,
            digest: digest_to_sign,
            in_scheme: None,
            validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
        };

        let res = execute_with_hmac_sessions_status(
            &mut sim,
            &sign_cmd,
            &[],
            &mut [final_session],
            &[password],
        );
        assert!(
            res.is_err(),
            "Expected Sign to fail because PolicyAuthValue was not called"
        );

        let _ = flush_context(&mut sim, active_sess.session_handle);
    }

    // Sub-test D: Wrong order (PolicyAuthValue then PolicyPCR) -> Sign fails
    {
        let active_sess = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::Policy,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();

        let pav_real = PolicyAuthValue {
            policy_session: active_sess.session_handle,
        };
        sim.execute(pav_real).unwrap();

        let policy_pcr_real = PolicyPCR {
            policy_session: active_sess.session_handle,
            pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
            pcrs: selection,
        };
        sim.execute(policy_pcr_real).unwrap();

        let mut final_session = active_sess.clone();
        final_session.bind_auth = password.to_vec();
        // TPM2_PolicyAuthValue was executed on this session above.
        final_session.mark_policy_auth_value();

        let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
        let sign_cmd = tpm2::commands::Sign {
            key_handle: rsp_handles.object_handle,
            digest: digest_to_sign,
            in_scheme: None,
            validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
        };

        let res = execute_with_hmac_sessions_status(
            &mut sim,
            &sign_cmd,
            &[],
            &mut [final_session],
            &[password],
        );
        assert!(
            res.is_err(),
            "Expected Sign to fail due to wrong order of policy commands"
        );

        let _ = flush_context(&mut sim, active_sess.session_handle);
    }

    // Sub-test E: Attempt to authorize using a Trial session -> fails
    {
        let active_sess = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::Trial,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();

        let policy_pcr_real = PolicyPCR {
            policy_session: active_sess.session_handle,
            pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
            pcrs: selection,
        };
        sim.execute(policy_pcr_real).unwrap();

        let pav_real = PolicyAuthValue {
            policy_session: active_sess.session_handle,
        };
        sim.execute(pav_real).unwrap();

        let mut final_session = active_sess.clone();
        final_session.bind_auth = password.to_vec();
        // TPM2_PolicyAuthValue was executed on this session above.
        final_session.mark_policy_auth_value();

        let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
        let sign_cmd = tpm2::commands::Sign {
            key_handle: rsp_handles.object_handle,
            digest: digest_to_sign,
            in_scheme: None,
            validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
        };

        let res = execute_with_hmac_sessions_status(
            &mut sim,
            &sign_cmd,
            &[],
            &mut [final_session],
            &[password],
        );
        assert!(
            res.is_err(),
            "Expected Sign to fail when using a Trial session for authorization"
        );

        let _ = flush_context(&mut sim, active_sess.session_handle);
    }
}

/// Extending a PCR inside the PolicyPCR selection after gating makes the session fail with TPM_RC_PCR_CHANGED
///
/// A PCR in the policy selection is extended after `TPM2_PolicyPCR` gated the
/// session; using the session afterwards must fail with `TPM_RC_PCR_CHANGED`
/// (the TPM's `pcrUpdateCounter` no longer matches the session's snapshot).
#[test]
#[allow(deprecated)]
fn selected_pcr_extended_after_gating_fails() {
    let mut sim = Tpm::new();
    let password = b"barpassword";

    // 1-2. Create key with policy PolicyPCR for PCR 0
    let mut select_bytes = [0u8; 3];
    select_bytes[0] = 0x01; // PCR 0
    let selection =
        TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha256, &select_bytes).unwrap()
        ])
        .unwrap();

    let pcr_digest_val = get_expected_pcr_digest(&mut sim, &selection);

    // Compute expected policy digest using trial session
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

    let policy_pcr = PolicyPCR {
        policy_session: start_rsp_handles.session_handle,
        pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
        pcrs: selection,
    };
    execute_with_password_sessions(&mut sim, &policy_pcr, 0, &[]).unwrap();

    let get_digest = PolicyGetDigest {
        policy_session: start_rsp_handles.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest, 0, &[]).unwrap();

    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);

    // Create ECC key with the policy
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: tpm2::TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: get_digest_rsp.policy_digest,
        parms_and_id: PublicParmsAndId::Ecc(ecc_parms, tpm2::TpmsEccPoint::default()),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_primary = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create_primary, 1, &[]).unwrap();

    // 3. Start a policy session to authorize command
    let active_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // 4. Gate using PolicyPCR. This snapshots the TPM's pcrUpdateCounter.
    let policy_pcr_real = PolicyPCR {
        policy_session: active_sess.session_handle,
        pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
        pcrs: selection,
    };
    sim.execute(policy_pcr_real).unwrap();

    // 5. Extend PCR 0, incrementing pcrUpdateCounter
    let mut digests = tpm2::TpmlDigestValues::default();
    digests.add(&tpm2::TpmtHa::Sha256(&[0xaa; 32])).unwrap();
    let extend_cmd = tpm2::commands::PCRExtend {
        pcr_handle: Handle(0),
        digests,
    };
    execute_with_password_sessions(&mut sim, &extend_cmd, 1, &[]).unwrap();

    // 6. Attempt to Sign. It MUST fail with PcrChanged because PCR changed since gating
    let mut final_session = active_sess.clone();
    final_session.bind_auth = password.to_vec();

    let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let sign_cmd = tpm2::commands::Sign {
        key_handle: rsp_handles.object_handle,
        digest: digest_to_sign,
        in_scheme: None,
        validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };

    let res = execute_with_hmac_sessions_status(
        &mut sim,
        &sign_cmd,
        &[],
        &mut [final_session],
        &[password],
    );

    assert!(
        res.is_err(),
        "Expected Sign to fail with PcrChanged after the gated PCR was extended!"
    );
    assert_eq!(res.err().unwrap(), TpmRc::PCR_CHANGED.get());

    let _ = flush_context(&mut sim, active_sess.session_handle);
}

/// PolicyPCR in a SHA-1 trial session with empty pcrDigest uses the current PCR digest
#[test]
fn trial_empty_digest_uses_current_pcrs_sha1() {
    let mut sim = Tpm::new();

    // 1. Test SHA1 trial session with empty pcr_digest. Like C (PolicyPCR.c: the trial branch
    // only overrides pcrDigest when one is provided), the digest of the current PCR values
    // (PCRComputeCurrentDigest) is used.
    let session = start_session_with_nonce(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha1, &[1; 20]);

    let pcr_selection_sha1 = TpmlPcrSelection::from_slice(&[
        TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x00, 0x00, 0x01]).unwrap(), // PCR 16
    ])
    .unwrap();

    execute_with_password_sessions(
        &mut sim,
        &PolicyPCR {
            policy_session: session,
            pcr_digest: Tpm2bDigest::default(),
            pcrs: pcr_selection_sha1,
        },
        0,
        &[],
    )
    .expect("PolicyPCR SHA1 on trial session should succeed");

    let policy_digest = policy_get_digest_checked(&mut sim, session);

    // Expected for SHA1: H_SHA1(zeros_20 || TPM_CC_PolicyPCR || pcrs || digestTPM), where
    // digestTPM = H_SHA1(PCR16 in the SHA256 bank, which is all zeros after Startup; the SHA1
    // bank is not allocated by default).
    let digest_tpm_sha1 = hash_bytes(TpmiAlgHash::Sha1, &[0u8; 32]);
    let mut data_to_hash_sha1 = Vec::new();
    data_to_hash_sha1.extend_from_slice(&[0u8; 20]);
    data_to_hash_sha1.extend_from_slice(&(TpmCc::PolicyPCR.code()).to_be_bytes());
    data_to_hash_sha1.extend_from_slice(&marshal_to_vec(&pcr_selection_sha1));
    data_to_hash_sha1.extend_from_slice(&digest_tpm_sha1);
    let expected_digest_sha1 = hash_bytes(TpmiAlgHash::Sha1, &data_to_hash_sha1);

    assert_eq!(
        policy_digest, expected_digest_sha1,
        "SHA1 trial session with empty pcr_digest must substitute digestTPM"
    );
}

/// PolicyPCR in a SHA-256 trial session with empty pcrDigest substitutes the current PCR digest
#[test]
fn trial_empty_digest_uses_current_pcrs_sha256() {
    let mut sim = Tpm::new();

    // 2. Test SHA256 trial session with empty pcr_digest (must substitute digestTPM)
    let session = start_session_with_nonce(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256, &[1; 32]);

    let pcr_selection_sha256 = TpmlPcrSelection::from_slice(&[
        TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x8F, 0x00, 0x00]).unwrap(), // PCRs 0, 1, 2, 3, 7
    ])
    .unwrap();

    execute_with_password_sessions(
        &mut sim,
        &PolicyPCR {
            policy_session: session,
            pcr_digest: Tpm2bDigest::default(),
            pcrs: pcr_selection_sha256,
        },
        0,
        &[],
    )
    .expect("PolicyPCR SHA256 on trial session should succeed");

    let policy_digest = policy_get_digest_checked(&mut sim, session);

    // Expected for SHA256: H_SHA256(zeros_32 || TPM_CC_PolicyPCR || pcrs || digestTPM)
    let digest_tpm_sha256 = hash_bytes(TpmiAlgHash::Sha256, &[0u8; 32 * 5]);

    let mut data_to_hash_sha256 = Vec::new();
    data_to_hash_sha256.extend_from_slice(&[0u8; 32]);
    data_to_hash_sha256.extend_from_slice(&(TpmCc::PolicyPCR.code()).to_be_bytes());
    data_to_hash_sha256.extend_from_slice(&marshal_to_vec(&pcr_selection_sha256));
    data_to_hash_sha256.extend_from_slice(&digest_tpm_sha256);
    let expected_digest_sha256 = hash_bytes(TpmiAlgHash::Sha256, &data_to_hash_sha256);

    assert_eq!(
        policy_digest, expected_digest_sha256,
        "SHA256 trial session with empty pcr_digest must substitute digestTPM"
    );
}

/// PolicyPCR filters unallocated banks and hashes repeated banks in order like the C reference.
#[test]
fn unallocated_and_repeated_banks() {
    let mut sim = Tpm::new();
    // The SHA-1 bank is not allocated by default: FilterPcr clears its selection, so both the
    // hashed selection and the PCR digest are those of an empty selection.
    let requested = [pcr_sel(TpmiAlgHash::Sha1, &[0x81, 0, 0])];
    let filtered = [pcr_sel(TpmiAlgHash::Sha1, &[0, 0, 0])];
    let expected = expected_policy_pcr(TpmiAlgHash::Sha256, &filtered, &[]);
    for session_type in [TpmSe::Trial, TpmSe::Policy] {
        let s = start_session_with_hash(&mut sim, session_type, TpmiAlgHash::Sha256).session_handle;
        policy_pcr(&mut sim, s, &[], &requested).unwrap();
        assert_eq!(policy_digest(&mut sim, s), expected);
    }

    // Like C (TPML_PCR_SELECTION_Unmarshal / PCRComputeCurrentDigest), a repeated bank is not
    // an error: each selection is hashed in order.
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let dup = [
        pcr_sel(TpmiAlgHash::Sha256, &[1, 0, 0]),
        pcr_sel(TpmiAlgHash::Sha256, &[2, 0, 0]),
    ];
    policy_pcr(&mut sim, s, &[], &dup).unwrap();
    assert_eq!(
        policy_digest(&mut sim, s),
        expected_policy_pcr(TpmiAlgHash::Sha256, &dup, &[&[0; 32], &[0; 32]])
    );
}

/// PolicyPCR with an implemented but unallocated SHA-512 bank is accepted (selection filtered) and the trial digest matches
#[test]
fn unallocated_sha512_bank_is_filtered() {
    let mut sim = Tpm::new();

    let start_auth = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_rsp_handles = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();

    let mut select_bytes = [0u8; 3];
    select_bytes[0] = 0x01; // PCR 0
    let selection =
        TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha512, &select_bytes).unwrap()
        ])
        .unwrap();

    let policy_pcr = PolicyPCR {
        policy_session: start_rsp_handles.session_handle,
        pcr_digest: Tpm2bDigest::default(),
        pcrs: selection,
    };

    // SHA-512 is an implemented hash: C accepts the selection and FilterPcr clears it because
    // the SHA-512 bank is not allocated by default.
    let res = execute_with_password_sessions(&mut sim, &policy_pcr, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyPCR with an unallocated SHA-512 bank selection succeeds: {:?}",
        res.err()
    );

    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
}

/// Extending a PCR outside the PolicyPCR selection still fails with TPM_RC_PCR_CHANGED (pcrUpdateCounter is global)
///
/// A PCR *outside* the policy selection is extended after `TPM2_PolicyPCR`
/// gated the session. `pcrUpdateCounter` is global, so the session must still
/// be rejected with `TPM_RC_PCR_CHANGED` (TPM 2.0 Part 3, TPM2_PolicyPCR).
#[test]
#[allow(deprecated)]
fn unselected_pcr_extended_after_gating_fails() {
    let mut sim = Tpm::new();
    let password = b"barpassword";

    // 1-2. Create key with policy PolicyPCR for PCR 0
    let mut select_bytes = [0u8; 3];
    select_bytes[0] = 0x01; // PCR 0
    let selection =
        TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha256, &select_bytes).unwrap()
        ])
        .unwrap();

    let pcr_digest_val = get_expected_pcr_digest(&mut sim, &selection);

    // Compute expected policy digest using trial session
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

    let policy_pcr = PolicyPCR {
        policy_session: start_rsp_handles.session_handle,
        pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
        pcrs: selection,
    };
    execute_with_password_sessions(&mut sim, &policy_pcr, 0, &[]).unwrap();

    let get_digest = PolicyGetDigest {
        policy_session: start_rsp_handles.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest, 0, &[]).unwrap();

    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);

    // Create ECC key with the policy
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: tpm2::TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: get_digest_rsp.policy_digest,
        parms_and_id: PublicParmsAndId::Ecc(ecc_parms, tpm2::TpmsEccPoint::default()),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_primary = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create_primary, 1, &[]).unwrap();

    // 3. Start a policy session to authorize command
    let active_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // 4. Gate using PolicyPCR. This snapshots the TPM's pcrUpdateCounter.
    let policy_pcr_real = PolicyPCR {
        policy_session: active_sess.session_handle,
        pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
        pcrs: selection,
    };
    sim.execute(policy_pcr_real).unwrap();

    // 5. Extend PCR 1, which is not part of the policy selection.
    let mut digests = tpm2::TpmlDigestValues::default();
    digests.add(&tpm2::TpmtHa::Sha256(&[0xbb; 32])).unwrap();
    let extend_cmd = tpm2::commands::PCRExtend {
        pcr_handle: Handle(1),
        digests,
    };
    execute_with_password_sessions(&mut sim, &extend_cmd, 1, &[]).unwrap();

    // 6. Attempt to Sign. It MUST fail with PcrChanged because pcrUpdateCounter changed since gating
    let mut final_session = active_sess.clone();
    final_session.bind_auth = password.to_vec();
    final_session.attributes = tpm2::TpmaSession::from_bits_retain(1);

    let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let sign_cmd = tpm2::commands::Sign {
        key_handle: rsp_handles.object_handle,
        digest: digest_to_sign,
        in_scheme: None,
        validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };

    let res = execute_with_hmac_sessions_status(
        &mut sim,
        &sign_cmd,
        &[],
        &mut [final_session],
        &[password],
    );

    // This assertion will FAIL if the bypass vulnerability exists, because the Sign command
    // will succeed (or return a different error, e.g. success), instead of returning PcrChanged!
    assert!(
        res.is_err(),
        "Expected Sign to fail because pcrUpdateCounter changed since gating!"
    );
    assert_eq!(res.err().unwrap(), TpmRc::PCR_CHANGED.get());

    let _ = flush_context(&mut sim, active_sess.session_handle);
}

/// A policy session saved across a TPM Restart fails PolicyPCR with TPM_RC_PCR_CHANGED, even if
/// the PCRs were then extended as often as before the Restart.
///
/// `pcrUpdateCounter` is reset only on TPM Reset (TPM 2.0 Part 1: it "is not reset until the
/// context protections for saved session contexts are changed"), and reinitializing the PCRs
/// at `TPM2_Startup` counts as a PCR change (C `PCRStartup` calls `PCRChanged`).
#[test]
fn saved_session_detects_pcr_reinit_on_restart() {
    let mut sim = Tpm::new();
    // PCR 16 is not state-saved, so it is reinitialized by a TPM Restart.
    let pcrs = [pcr_sel(TpmiAlgHash::Sha256, &[0, 0, 1])];
    assert_eq!(
        pcr_extend_at(&mut sim, 0, 16, &[(ALG_SHA256, vec![0xAA; 32])]),
        0
    );
    let counter_before = pcr_read(&mut sim, &[(ALG_SHA256, [0, 0, 1])]).update_counter;

    let session =
        start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_pcr(&mut sim, session, &[], &pcrs).unwrap();
    let saved = context_save(&mut sim, session);

    // TPM Restart: Shutdown(STATE) + Startup(CLEAR).
    assert_eq!(power_cycle_with(&mut sim, Some(SU_STATE), SU_CLEAR), 0);
    let counter_after = pcr_read(&mut sim, &[(ALG_SHA256, [0, 0, 1])]).update_counter;
    assert!(
        counter_after > counter_before,
        "pcrUpdateCounter must survive TPM Restart and count the PCR reinitialization \
         (before {counter_before}, after {counter_after})"
    );

    // Extend PCR 16 once more with a different value: the same number of extends since
    // power-on as before the Restart.
    assert_eq!(
        pcr_extend_at(&mut sim, 0, 16, &[(ALG_SHA256, vec![0xBB; 32])]),
        0
    );
    let session = context_load(&mut sim, saved).unwrap();
    assert_eq!(
        policy_pcr(&mut sim, session, &[], &pcrs),
        Err(TpmRc::PCR_CHANGED.get())
    );
}
