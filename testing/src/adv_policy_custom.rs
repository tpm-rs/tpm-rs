#![allow(unused_imports, dead_code)]
use crate::go::policy::get_expected_pcr_digest;
// Ported from tpm-go/tpm2/test/policy_test.go

use crate::test_utils::*;
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, PolicyAuthValue, PolicyAuthValueHandles, PolicyAuthorize,
    PolicyAuthorizeHandles, PolicyCommandCode, PolicyCommandCodeHandles, PolicyCpHash,
    PolicyCpHashHandles, PolicyDuplicationSelect, PolicyDuplicationSelectHandles, PolicyGetDigest,
    PolicyGetDigestHandles, PolicyNV, PolicyNVHandles, PolicyNvWritten, PolicyNvWrittenHandles,
    PolicyOR, PolicyORHandles, PolicyPCR, PolicyPCRHandles, PolicySecret, PolicySecretHandles,
    PolicySigned, PolicySignedHandles, StartAuthSession, StartAuthSessionHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce,
    Tpm2bOperand, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmaNv, TpmaObject, TpmiAlgHash,
    TpmlDigest, TpmlPcrSelection, TpmsEccParms, TpmsNvPublic, TpmsPcrSelection,
    TpmsSensitiveCreate, TpmsSignatureEcc, TpmtEccScheme, TpmtPublic, TpmtSignature,
    TpmtTkVerified,
};
use tpm2_simulator::{Simulator, create_simulator};

fn create_signing_key(sim: &mut Simulator<'_>) -> (Handle, Tpm2bName<'static>) {
    create_signing_key_with_unique(sim, &[])
}

fn create_signing_key_with_unique(
    sim: &mut Simulator<'_>,
    unique_id: &[u8],
) -> (Handle, Tpm2bName<'static>) {
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
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::from_bytes(unique_id).unwrap_or_default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_primary = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &create_primary, create_handles, 0, &[])
            .expect("could not call TPM2_CreatePrimary");
    (rsp_handles.object_handle, rsp.name)
}

fn create_nv_index(sim: &mut Simulator<'_>) -> (Handle, Tpm2bName<'static>) {
    let nv_public = TpmsNvPublic {
        nv_index: Handle(0x01800001),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE
            | TpmaNv::AUTHREAD
            | TpmaNv::POLICYREAD
            | TpmaNv::POLICYWRITE,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    };
    let in_public = tpm2::Tpm2b(nv_public);
    let def_space = tpm2::commands::NVDefineSpace {
        public_info: in_public,
        auth: Tpm2bAuth::default(),
    };
    let def_space_handles = tpm2::commands::NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    let _ = execute_with_password_sessions(sim, &def_space, def_space_handles, 1, &[])
        .expect("could not define NV space");

    // Read the NV index Name
    let read_pub = tpm2::commands::NVReadPublic {};
    let read_pub_handles = tpm2::commands::NVReadPublicHandles {
        nv_index: Handle(0x01800001),
    };
    let (read_pub_rsp, _) =
        execute_with_password_sessions(sim, &read_pub, read_pub_handles, 0, &[])
            .expect("could not read NV public");

    (Handle(0x01800001), read_pub_rsp.nv_name)
}

#[test]
fn test_policy_pcr_counter_changed() {
    let mut sim = create_simulator!();
    let password = b"foo";

    // Step 1: Calculate policy digest of PolicyPCR using trial session
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();

    let mut select_bytes = [0u8; 3];
    select_bytes[0] = 0x01; // PCR 0
    let selection =
        TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha256, &select_bytes).unwrap()
        ])
        .unwrap();

    let expected_digest = get_expected_pcr_digest(&mut sim, &selection);

    let policy_pcr = PolicyPCR {
        pcr_digest: Tpm2bDigest::from_bytes(&expected_digest).unwrap(),
        pcrs: selection,
    };
    let policy_pcr_handles = PolicyPCRHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_pcr, policy_pcr_handles, 0, &[]).unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (_rsp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_primary, create_handles, 0, &[])
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
        pcr_digest: Tpm2bDigest::from_bytes(&expected_digest).unwrap(),
        pcrs: selection,
    };
    let policy_pcr_real_handles = PolicyPCRHandles {
        policy_session: active_sess.session_handle,
    };
    let _ = sim
        .execute_with_handles(policy_pcr_real, policy_pcr_real_handles)
        .unwrap();

    // Step 5: Extend PCR 0, incrementing the PCR update counter
    let mut digests = tpm2::TpmlDigestValues::default();
    digests.add(&tpm2::TpmtHa::Sha256(&[0xaa; 32])).unwrap();
    let extend_cmd = tpm2::commands::PCRExtend { digests };
    let extend_handles = tpm2::commands::PCRExtendHandles {
        pcr_handle: Handle(0),
    };
    let _ = execute_with_password_sessions(&mut sim, &extend_cmd, extend_handles, 1, &[]).unwrap();

    // Step 6: Attempt to Sign with the session
    let mut final_session = active_sess.clone();
    final_session.bind_auth = password.to_vec();
    final_session.attributes = tpm2::TpmaSession::from_bits_retain(1);

    let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let sign_cmd = tpm2::commands::Sign {
        digest: digest_to_sign,
        in_scheme: None,
        validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    let sign_handles = tpm2::commands::SignHandles {
        key_handle: rsp_handles.object_handle,
    };

    let res = execute_with_hmac_sessions_status(
        &mut sim,
        &sign_cmd,
        sign_handles,
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

#[test]
fn test_policy_pcr_unsupported_hash() {
    let mut sim = create_simulator!();

    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();

    let mut select_bytes = [0u8; 3];
    select_bytes[0] = 0x01; // PCR 0
    let selection =
        TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha512, &select_bytes).unwrap()
        ])
        .unwrap();

    let policy_pcr = PolicyPCR {
        pcr_digest: Tpm2bDigest::default(),
        pcrs: selection,
    };
    let policy_pcr_handles = PolicyPCRHandles {
        policy_session: start_rsp_handles.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &policy_pcr, policy_pcr_handles, 0, &[]);
    assert!(
        res.is_err(),
        "Expected PolicyPCR to fail with SHA512 (unsupported PCR hash alg)"
    );
    let err = res.err().unwrap();
    assert_eq!(err, TpmRc::HASH.with(Position::parameter(1)).get());

    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
}

#[test]
fn test_policy_auth_value_and_pcr_combination() {
    let mut sim = create_simulator!();
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
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();

    // Call PolicyPCR
    let policy_pcr = PolicyPCR {
        pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
        pcrs: selection,
    };
    let policy_pcr_handles = PolicyPCRHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_pcr, policy_pcr_handles, 0, &[]).unwrap();

    // Call PolicyAuthValue
    let pav = PolicyAuthValue {};
    let pav_handles = PolicyAuthValueHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let _ = execute_with_password_sessions(&mut sim, &pav, pav_handles, 0, &[]).unwrap();

    // Get the final digest
    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (_rsp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_primary, create_handles, 0, &[])
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
            pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
            pcrs: selection,
        };
        let policy_pcr_real_handles = PolicyPCRHandles {
            policy_session: active_sess.session_handle,
        };
        let _ = sim
            .execute_with_handles(policy_pcr_real, policy_pcr_real_handles)
            .unwrap();

        let pav_real = PolicyAuthValue {};
        let pav_real_handles = PolicyAuthValueHandles {
            policy_session: active_sess.session_handle,
        };
        let _ = sim
            .execute_with_handles(pav_real, pav_real_handles)
            .unwrap();

        let mut final_session = active_sess.clone();
        final_session.bind_auth = password.to_vec();
        // TPM2_PolicyAuthValue was executed on this session above.
        final_session.mark_policy_auth_value();

        let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
        let sign_cmd = tpm2::commands::Sign {
            digest: digest_to_sign,
            in_scheme: None,
            validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
        };
        let sign_handles = tpm2::commands::SignHandles {
            key_handle: rsp_handles.object_handle,
        };

        let res = execute_with_hmac_sessions_status(
            &mut sim,
            &sign_cmd,
            sign_handles,
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
            pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
            pcrs: selection,
        };
        let policy_pcr_real_handles = PolicyPCRHandles {
            policy_session: active_sess.session_handle,
        };
        let _ = sim
            .execute_with_handles(policy_pcr_real, policy_pcr_real_handles)
            .unwrap();

        let pav_real = PolicyAuthValue {};
        let pav_real_handles = PolicyAuthValueHandles {
            policy_session: active_sess.session_handle,
        };
        let _ = sim
            .execute_with_handles(pav_real, pav_real_handles)
            .unwrap();

        let mut final_session = active_sess.clone();
        final_session.bind_auth = b"wrongpwd".to_vec();
        // TPM2_PolicyAuthValue was executed on this session above.
        final_session.mark_policy_auth_value();

        let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
        let sign_cmd = tpm2::commands::Sign {
            digest: digest_to_sign,
            in_scheme: None,
            validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
        };
        let sign_handles = tpm2::commands::SignHandles {
            key_handle: rsp_handles.object_handle,
        };

        let res = execute_with_hmac_sessions_status(
            &mut sim,
            &sign_cmd,
            sign_handles,
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
            pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
            pcrs: selection,
        };
        let policy_pcr_real_handles = PolicyPCRHandles {
            policy_session: active_sess.session_handle,
        };
        let _ = sim
            .execute_with_handles(policy_pcr_real, policy_pcr_real_handles)
            .unwrap();

        let mut final_session = active_sess.clone();
        final_session.bind_auth = password.to_vec();

        let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
        let sign_cmd = tpm2::commands::Sign {
            digest: digest_to_sign,
            in_scheme: None,
            validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
        };
        let sign_handles = tpm2::commands::SignHandles {
            key_handle: rsp_handles.object_handle,
        };

        let res = execute_with_hmac_sessions_status(
            &mut sim,
            &sign_cmd,
            sign_handles,
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

        let pav_real = PolicyAuthValue {};
        let pav_real_handles = PolicyAuthValueHandles {
            policy_session: active_sess.session_handle,
        };
        let _ = sim
            .execute_with_handles(pav_real, pav_real_handles)
            .unwrap();

        let policy_pcr_real = PolicyPCR {
            pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
            pcrs: selection,
        };
        let policy_pcr_real_handles = PolicyPCRHandles {
            policy_session: active_sess.session_handle,
        };
        let _ = sim
            .execute_with_handles(policy_pcr_real, policy_pcr_real_handles)
            .unwrap();

        let mut final_session = active_sess.clone();
        final_session.bind_auth = password.to_vec();
        // TPM2_PolicyAuthValue was executed on this session above.
        final_session.mark_policy_auth_value();

        let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
        let sign_cmd = tpm2::commands::Sign {
            digest: digest_to_sign,
            in_scheme: None,
            validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
        };
        let sign_handles = tpm2::commands::SignHandles {
            key_handle: rsp_handles.object_handle,
        };

        let res = execute_with_hmac_sessions_status(
            &mut sim,
            &sign_cmd,
            sign_handles,
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
            pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
            pcrs: selection,
        };
        let policy_pcr_real_handles = PolicyPCRHandles {
            policy_session: active_sess.session_handle,
        };
        let _ = sim
            .execute_with_handles(policy_pcr_real, policy_pcr_real_handles)
            .unwrap();

        let pav_real = PolicyAuthValue {};
        let pav_real_handles = PolicyAuthValueHandles {
            policy_session: active_sess.session_handle,
        };
        let _ = sim
            .execute_with_handles(pav_real, pav_real_handles)
            .unwrap();

        let mut final_session = active_sess.clone();
        final_session.bind_auth = password.to_vec();
        // TPM2_PolicyAuthValue was executed on this session above.
        final_session.mark_policy_auth_value();

        let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
        let sign_cmd = tpm2::commands::Sign {
            digest: digest_to_sign,
            in_scheme: None,
            validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
        };
        let sign_handles = tpm2::commands::SignHandles {
            key_handle: rsp_handles.object_handle,
        };

        let res = execute_with_hmac_sessions_status(
            &mut sim,
            &sign_cmd,
            sign_handles,
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

/// A PCR in the policy selection is extended after `TPM2_PolicyPCR` gated the
/// session; using the session afterwards must fail with `TPM_RC_PCR_CHANGED`
/// (the TPM's `pcrUpdateCounter` no longer matches the session's snapshot).
#[test]
fn test_policy_pcr_gated_pcr_extended_fails() {
    let mut sim = create_simulator!();
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
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();

    let policy_pcr = PolicyPCR {
        pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
        pcrs: selection,
    };
    let policy_pcr_handles = PolicyPCRHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_pcr, policy_pcr_handles, 0, &[]).unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (_rsp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_primary, create_handles, 0, &[]).unwrap();

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
        pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
        pcrs: selection,
    };
    let policy_pcr_real_handles = PolicyPCRHandles {
        policy_session: active_sess.session_handle,
    };
    let _ = sim
        .execute_with_handles(policy_pcr_real, policy_pcr_real_handles)
        .unwrap();

    // 5. Extend PCR 0, incrementing pcrUpdateCounter
    let mut digests = tpm2::TpmlDigestValues::default();
    digests.add(&tpm2::TpmtHa::Sha256(&[0xaa; 32])).unwrap();
    let extend_cmd = tpm2::commands::PCRExtend { digests };
    let extend_handles = tpm2::commands::PCRExtendHandles {
        pcr_handle: Handle(0),
    };
    let _ = execute_with_password_sessions(&mut sim, &extend_cmd, extend_handles, 1, &[]).unwrap();

    // 6. Attempt to Sign. It MUST fail with PcrChanged because PCR changed since gating
    let mut final_session = active_sess.clone();
    final_session.bind_auth = password.to_vec();

    let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let sign_cmd = tpm2::commands::Sign {
        digest: digest_to_sign,
        in_scheme: None,
        validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    let sign_handles = tpm2::commands::SignHandles {
        key_handle: rsp_handles.object_handle,
    };

    let res = execute_with_hmac_sessions_status(
        &mut sim,
        &sign_cmd,
        sign_handles,
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

/// A PCR *outside* the policy selection is extended after `TPM2_PolicyPCR`
/// gated the session. `pcrUpdateCounter` is global, so the session must still
/// be rejected with `TPM_RC_PCR_CHANGED` (TPM 2.0 Part 3, TPM2_PolicyPCR).
#[test]
fn test_policy_pcr_other_pcr_extended_fails() {
    let mut sim = create_simulator!();
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
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();

    let policy_pcr = PolicyPCR {
        pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
        pcrs: selection,
    };
    let policy_pcr_handles = PolicyPCRHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_pcr, policy_pcr_handles, 0, &[]).unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (_rsp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_primary, create_handles, 0, &[]).unwrap();

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
        pcr_digest: Tpm2bDigest::from_bytes(&pcr_digest_val).unwrap(),
        pcrs: selection,
    };
    let policy_pcr_real_handles = PolicyPCRHandles {
        policy_session: active_sess.session_handle,
    };
    let _ = sim
        .execute_with_handles(policy_pcr_real, policy_pcr_real_handles)
        .unwrap();

    // 5. Extend PCR 1, which is not part of the policy selection.
    let mut digests = tpm2::TpmlDigestValues::default();
    digests.add(&tpm2::TpmtHa::Sha256(&[0xbb; 32])).unwrap();
    let extend_cmd = tpm2::commands::PCRExtend { digests };
    let extend_handles = tpm2::commands::PCRExtendHandles {
        pcr_handle: Handle(1),
    };
    let _ = execute_with_password_sessions(&mut sim, &extend_cmd, extend_handles, 1, &[]).unwrap();

    // 6. Attempt to Sign. It MUST fail with PcrChanged because pcrUpdateCounter changed since gating
    let mut final_session = active_sess.clone();
    final_session.bind_auth = password.to_vec();
    final_session.attributes = tpm2::TpmaSession::from_bits_retain(1);

    let digest_to_sign = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let sign_cmd = tpm2::commands::Sign {
        digest: digest_to_sign,
        in_scheme: None,
        validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    let sign_handles = tpm2::commands::SignHandles {
        key_handle: rsp_handles.object_handle,
    };

    let res = execute_with_hmac_sessions_status(
        &mut sim,
        &sign_cmd,
        sign_handles,
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

#[test]
fn test_policy_pcr_duplicate_algorithms() {
    let mut sim = create_simulator!();

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
        pcr_digest: Tpm2bDigest::default(),
        pcrs: selection,
    };
    let policy_pcr_handles = PolicyPCRHandles {
        policy_session: active_sess.session_handle,
    };

    let res = sim.execute_with_handles(policy_pcr, policy_pcr_handles);
    assert!(res.is_err());
    let expected_err = TpmRc::VALUE.with(Position::parameter(1));
    assert_eq!(res.err().unwrap(), expected_err);

    let _ = flush_context(&mut sim, active_sess.session_handle);
}

#[test]
fn test_policy_pcr_empty_selection() {
    let mut sim = create_simulator!();

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
        pcr_digest: Tpm2bDigest::default(),
        pcrs: selection,
    };
    let policy_pcr_handles = PolicyPCRHandles {
        policy_session: active_sess.session_handle,
    };

    let res = sim.execute_with_handles(policy_pcr, policy_pcr_handles);
    assert!(
        res.is_ok(),
        "Expected PolicyPCR with empty selection to succeed"
    );

    let _ = flush_context(&mut sim, active_sess.session_handle);
}

#[test]
fn test_policy_pcr_digest_mismatch() {
    let mut sim = create_simulator!();

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
        pcr_digest: Tpm2bDigest::from_bytes(&[0xcd; 32]).unwrap(),
        pcrs: selection,
    };
    let policy_pcr_handles = PolicyPCRHandles {
        policy_session: active_sess.session_handle,
    };

    let res = sim.execute_with_handles(policy_pcr, policy_pcr_handles);
    assert!(res.is_err(), "Expected PolicyPCR with wrong digest to fail");
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE.with(Position::parameter(2))
    );

    let _ = flush_context(&mut sim, active_sess.session_handle);
}

#[test]
fn test_policy_cp_hash_adversarial() {
    let mut sim = create_simulator!();

    // 1. Setup a trial session.
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // 2. Try calling PolicyCpHash with a wrong size cpHash (e.g. 16 bytes instead of 32 bytes).
    let wrong_size_cp_hash = [0x55; 16];
    let policy_cp_hash_wrong = PolicyCpHash {
        cp_hash_a: Tpm2bDigest::from_bytes(&wrong_size_cp_hash).unwrap(),
    };
    let policy_cp_hash_handles = PolicyCpHashHandles {
        policy_session: session_handle,
    };
    let res = sim.execute_with_handles(policy_cp_hash_wrong, policy_cp_hash_handles);
    assert!(
        res.is_err(),
        "Expected PolicyCpHash with wrong size cpHash to fail"
    );
    assert_eq!(res.err().unwrap(), TpmRc::SIZE.with(Position::parameter(1)));

    // 3. Call PolicyCpHash with correct size cpHash (32 bytes).
    let dummy_cp_hash = [0x55; 32];
    let policy_cp_hash_correct = PolicyCpHash {
        cp_hash_a: Tpm2bDigest::from_bytes(&dummy_cp_hash).unwrap(),
    };
    let _ = execute_with_password_sessions(
        &mut sim,
        &policy_cp_hash_correct,
        policy_cp_hash_handles,
        0,
        &[],
    )
    .unwrap();

    // 4. Try calling PolicyCpHash again with a DIFFERENT cpHash (32 bytes).
    let diff_cp_hash = [0x66; 32];
    let policy_cp_hash_diff = PolicyCpHash {
        cp_hash_a: Tpm2bDigest::from_bytes(&diff_cp_hash).unwrap(),
    };
    let res = sim.execute_with_handles(policy_cp_hash_diff, policy_cp_hash_handles);
    assert!(
        res.is_err(),
        "Expected PolicyCpHash with different cpHash to fail"
    );
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH);

    // 5. Call PolicyCpHash again with the SAME cpHash (should succeed).
    let _ = execute_with_password_sessions(
        &mut sim,
        &policy_cp_hash_correct,
        policy_cp_hash_handles,
        0,
        &[],
    )
    .unwrap();

    // 6. Try calling PolicyDuplicationSelect on the same session.
    // It should fail because is_cp_hash_defined is true (policy_hash_len != 0).
    let (_sk, sk_name) = create_signing_key(&mut sim);
    let (_ek, ek_name) = create_signing_key(&mut sim);
    let policy_dup = PolicyDuplicationSelect {
        object_name: sk_name,
        new_parent_name: ek_name,
        include_object: true,
    };
    let policy_dup_handles = PolicyDuplicationSelectHandles {
        policy_session: session_handle,
    };
    let res = sim.execute_with_handles(policy_dup, policy_dup_handles);
    assert!(
        res.is_err(),
        "Expected PolicyDuplicationSelect to fail when cpHash is already defined"
    );
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH);

    flush_context(&mut sim, session_handle).unwrap();
}

#[test]
fn test_policy_duplication_select_adversarial() {
    let mut sim = create_simulator!();
    let (_sk, sk_name) = create_signing_key(&mut sim);
    let (_ek, ek_name) = create_signing_key(&mut sim);

    // 1. Setup a trial session.
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // 2. Call PolicyDuplicationSelect.
    let policy_dup = PolicyDuplicationSelect {
        object_name: sk_name,
        new_parent_name: ek_name,
        include_object: true,
    };
    let policy_dup_handles = PolicyDuplicationSelectHandles {
        policy_session: session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_dup, policy_dup_handles, 0, &[]).unwrap();

    // 3. Try calling PolicyDuplicationSelect again (should fail because is_name_hash_defined is true).
    let res = sim.execute_with_handles(policy_dup, policy_dup_handles);
    assert!(
        res.is_err(),
        "Expected second PolicyDuplicationSelect to fail"
    );
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH);

    // 4. Try calling PolicyCpHash on the same session.
    // It should fail because is_name_hash_defined is true.
    let dummy_cp_hash = [0x55; 32];
    let policy_cp_hash = PolicyCpHash {
        cp_hash_a: Tpm2bDigest::from_bytes(&dummy_cp_hash).unwrap(),
    };
    let policy_cp_hash_handles = PolicyCpHashHandles {
        policy_session: session_handle,
    };
    let res = sim.execute_with_handles(policy_cp_hash, policy_cp_hash_handles);
    assert!(
        res.is_err(),
        "Expected PolicyCpHash to fail when nameHash is defined"
    );
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH);

    flush_context(&mut sim, session_handle).unwrap();
}

#[test]
fn test_policy_commands_with_session_tag_0x8002() {
    let mut sim = create_simulator!();

    // 1. Setup a trial session.
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // 2. Setup a separate active session to use in the command's session area (tag 0x8002).
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

    // 3. Call PolicyCpHash with tag 0x8002 (num_sessions = 1) using an HMAC session.
    let dummy_cp_hash = [0x55; 32];
    let policy_cp_hash = PolicyCpHash {
        cp_hash_a: Tpm2bDigest::from_bytes(&dummy_cp_hash).unwrap(),
    };
    let policy_cp_hash_handles = PolicyCpHashHandles {
        policy_session: session_handle,
    };
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &policy_cp_hash,
        policy_cp_hash_handles,
        &[],
        &mut [active_sess],
        &[&[]],
    )
    .unwrap();

    flush_context(&mut sim, session_handle).unwrap();
}

#[test]
fn test_policy_commands_bind_entity_fail() {
    let mut sim = create_simulator!();
    let (sk, sk_name) = create_signing_key(&mut sim);

    // Start a trial session bound to 'sk'.
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: sk,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // 1. PolicyCpHash should fail because bind_entity != RHNull
    let dummy_cp_hash = [0x55; 32];
    let policy_cp_hash = PolicyCpHash {
        cp_hash_a: Tpm2bDigest::from_bytes(&dummy_cp_hash).unwrap(),
    };
    let policy_cp_hash_handles = PolicyCpHashHandles {
        policy_session: session_handle,
    };
    let res = sim.execute_with_handles(policy_cp_hash, policy_cp_hash_handles);
    assert!(
        res.is_err(),
        "Expected PolicyCpHash to fail for a bound session"
    );
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH);

    // 2. PolicyDuplicationSelect should fail because bind_entity != RHNull
    let (_ek, ek_name) = create_signing_key(&mut sim);
    let policy_dup = PolicyDuplicationSelect {
        object_name: sk_name,
        new_parent_name: ek_name,
        include_object: true,
    };
    let policy_dup_handles = PolicyDuplicationSelectHandles {
        policy_session: session_handle,
    };
    let res = sim.execute_with_handles(policy_dup, policy_dup_handles);
    assert!(
        res.is_err(),
        "Expected PolicyDuplicationSelect to fail for a bound session"
    );
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH);

    flush_context(&mut sim, session_handle).unwrap();
}

#[test]
fn test_policy_duplication_select_invalid_yes_no() {
    let mut sim = create_simulator!();
    let (_sk, sk_name) = create_signing_key(&mut sim);
    let (_ek, ek_name) = create_signing_key(&mut sim);

    // 1. Setup a trial session.
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // 2. Call PolicyDuplicationSelect with include_object = 2 (invalid value).
    let policy_dup = PolicyDuplicationSelect {
        object_name: sk_name,
        new_parent_name: ek_name,
        include_object: false,
    };
    let policy_dup_handles = PolicyDuplicationSelectHandles {
        policy_session: session_handle,
    };
    let res =
        execute_with_corrupted_bytes(&mut sim, &policy_dup, policy_dup_handles, 0, &[], |buf| {
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

#[test]
fn test_trial_session_leak_stress() {
    let mut sim = create_simulator!();
    let (_sk, sk_name) = create_signing_key(&mut sim);
    let (_ek, ek_name) = create_signing_key_with_unique(&mut sim, b"ek");

    // Run 20 iterations. Since MAX_ACTIVE_SESSIONS = 4, if they leaked,
    // we would fail by iteration 5.
    for _ in 0..20 {
        let start_auth = StartAuthSession {
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let start_auth_handles = StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        };
        let (_, start_rsp_handles) =
            execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[])
                .unwrap();

        let policy_dup = PolicyDuplicationSelect {
            object_name: sk_name,
            new_parent_name: ek_name,
            include_object: true,
        };
        let policy_dup_handles = PolicyDuplicationSelectHandles {
            policy_session: start_rsp_handles.session_handle,
        };
        sim.execute_with_handles(policy_dup, policy_dup_handles)
            .unwrap();

        // Flush session at the end of each iteration.
        flush_context(&mut sim, start_rsp_handles.session_handle).unwrap();
    }

    // Now verify that if we DON'T flush, we hit the limit on the 65th attempt.
    let mut active_handles = Vec::new();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let start_auth = StartAuthSession {
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let start_auth_handles = StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        };
        let (_, start_rsp_handles) =
            execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[])
                .unwrap();
        active_handles.push(start_rsp_handles.session_handle);
    }

    // The next StartAuthSession beyond capacity should fail with SessionMemory
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]);
    assert!(res.is_err(), "Expected 65th session creation to fail");
    let err = res.unwrap_err();
    assert_eq!(err, TpmRc::SESSION_MEMORY.get());

    // Flush active sessions to clean up properly.
    for handle in active_handles {
        flush_context(&mut sim, handle).unwrap();
    }

    // Flush transient keys as well to verify clean state.
    flush_context(&mut sim, _sk).unwrap();
    flush_context(&mut sim, _ek).unwrap();
}

#[test]
fn test_trial_session_cleanup_on_failure() {
    let mut sim = create_simulator!();
    let (_sk, sk_name) = create_signing_key(&mut sim);
    let (_ek, ek_name) = create_signing_key_with_unique(&mut sim, b"ek");

    // 1. Start a trial session.
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // 2. Execute a policy command that fails (e.g., PolicyDuplicationSelect with invalid bool).
    let policy_dup = PolicyDuplicationSelect {
        object_name: sk_name,
        new_parent_name: ek_name,
        include_object: false,
    };
    let policy_dup_handles = PolicyDuplicationSelectHandles {
        policy_session: session_handle,
    };
    let res =
        execute_with_corrupted_bytes(&mut sim, &policy_dup, policy_dup_handles, 0, &[], |buf| {
            let last_idx = buf.len() - 1;
            buf[last_idx] = 2; // corrupt to 2 (invalid)
        });
    assert!(
        res.is_err(),
        "Expected PolicyDuplicationSelect to fail with invalid bool"
    );

    // 3. Flush the failed session context.
    flush_context(&mut sim, session_handle).unwrap();

    // 4. Verify we can start 4 new sessions (meaning the slot was released).
    let mut active_handles = Vec::new();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let start_auth = StartAuthSession {
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let start_auth_handles = StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        };
        let (_, start_rsp_handles) =
            execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[])
                .unwrap();
        active_handles.push(start_rsp_handles.session_handle);
    }

    // 5. Clean up.
    for handle in active_handles {
        flush_context(&mut sim, handle).unwrap();
    }
    flush_context(&mut sim, _sk).unwrap();
    flush_context(&mut sim, _ek).unwrap();
}

#[test]
fn test_trial_session_creation_failure_no_leak() {
    let mut sim = create_simulator!();

    // 1. Attempt to start a session with a non-existent key handle (e.g. 0x80000000).
    // This should fail to create the session.
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle(0x80000000), // Non-existent key handle
        bind: Handle::RH_NULL,
    };
    let res = execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]);
    assert!(
        res.is_err(),
        "Expected StartAuthSession to fail with invalid key handle"
    );

    // 2. Verify that we can still start MAX_LOADED_SESSIONS active sessions (i.e. the failed attempt didn't occupy a slot).
    let mut active_handles = Vec::new();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let start_auth = StartAuthSession {
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let start_auth_handles = StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        };
        let (_, start_rsp_handles) =
            execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[])
                .unwrap();
        active_handles.push(start_rsp_handles.session_handle);
    }

    // 3. Clean up.
    for handle in active_handles {
        flush_context(&mut sim, handle).unwrap();
    }
}

#[test]
fn test_trial_session_double_flush() {
    let mut sim = create_simulator!();

    // 1. Start a trial session.
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, start_rsp_handles) =
        execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[]).unwrap();
    let session_handle = start_rsp_handles.session_handle;

    // 2. Flush it once.
    flush_context(&mut sim, session_handle).unwrap();

    // 3. Flush it again (should fail with handle error, but not crash/corrupt the system).
    let res = flush_context(&mut sim, session_handle);
    assert!(res.is_err(), "Expected double flush to fail");

    // 4. Verify we can still start MAX_LOADED_SESSIONS active sessions.
    let mut active_handles = Vec::new();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let start_auth = StartAuthSession {
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let start_auth_handles = StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        };
        let (_, start_rsp_handles) =
            execute_with_password_sessions(&mut sim, &start_auth, start_auth_handles, 0, &[])
                .unwrap();
        active_handles.push(start_rsp_handles.session_handle);
    }

    // 5. Clean up.
    for handle in active_handles {
        flush_context(&mut sim, handle).unwrap();
    }
}
