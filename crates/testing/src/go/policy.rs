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
use tpm2::{Handle, TpmCc, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce,
    Tpm2bOperand, Tpm2bSensitiveData, TpmaNv, TpmaObject, TpmiAlgHash, TpmlDigest,
    TpmlPcrSelection, TpmsEccParms, TpmsNvPublic, TpmsPcrSelection, TpmsSensitiveCreate,
    TpmsSignatureEcc, TpmtEccScheme, TpmtPublic, TpmtSignature, TpmtTkVerified,
};
use tpm2_platform_linux::LinuxRng;
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

// Original Go test: policy_test.go - TestCreatePolicySession
#[test]
fn test_create_policy_session() {
    for &session_type in &[TpmSe::Trial, TpmSe::Policy] {
        let mut sim = create_simulator!();

        let start_auth = StartAuthSession {
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type,
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

        let get_digest = PolicyGetDigest {};
        let get_digest_handles = PolicyGetDigestHandles {
            policy_session: start_rsp_handles.session_handle,
        };
        let (get_digest_rsp, _) =
            execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[])
                .unwrap();

        let digest = get_digest_rsp.policy_digest.get_buffer();
        assert!(
            digest.iter().all(|&b| b == 0),
            "Policy digest should be all zeros"
        );

        flush_context(&mut sim, start_rsp_handles.session_handle).unwrap();
    }
}

// Original Go test: policy_test.go - TestPolicySignedUpdate
#[test]
fn test_policy_signed_update() {
    let mut sim = create_simulator!();
    let (sk, _) = create_signing_key(&mut sim);

    // Use a trial session to calculate this policy
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

    let policy_ref = [5, 6, 7, 8];
    let policy_signed = PolicySigned {
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::from_bytes(&policy_ref).unwrap(),
        expiration: 0,
        auth: TpmtSignature::Ecdsa(TpmsSignatureEcc {
            hash: TpmiAlgHash::Sha256,
            signature_r: tpm2::Tpm2bEccParameter::default(),
            signature_s: tpm2::Tpm2bEccParameter::default(),
        }),
    };
    let policy_signed_handles = PolicySignedHandles {
        auth_object: sk,
        policy_session: start_rsp_handles.session_handle,
    };
    let _ = execute_with_password_sessions(&mut sim, &policy_signed, policy_signed_handles, 0, &[])
        .unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

    let key_name = read_public_name(&mut sim, sk);
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_signed(key_name.get_buffer(), &policy_ref);

    assert_eq!(pol.policy_digest, get_digest_rsp.policy_digest.get_buffer());
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
}

// Original Go test: policy_test.go - TestPolicySecretUpdate
#[test]
fn test_policy_secret_update() {
    let mut sim = create_simulator!();
    let (sk, _) = create_signing_key(&mut sim);

    // Use a trial session to calculate this policy
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

    let policy_ref = [5, 6, 7, 8];
    let policy_secret = PolicySecret {
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::from_bytes(&policy_ref).unwrap(),
        expiration: 0,
    };
    let policy_secret_handles = PolicySecretHandles {
        auth_handle: sk,
        policy_session: start_rsp_handles.session_handle,
    };
    let _ = execute_with_password_sessions(&mut sim, &policy_secret, policy_secret_handles, 1, &[])
        .unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

    let key_name = read_public_name(&mut sim, sk);
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_secret(key_name.get_buffer(), &policy_ref);

    assert_eq!(pol.policy_digest, get_digest_rsp.policy_digest.get_buffer());
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
}

// Original Go test: policy_test.go - TestPolicyOrUpdate
#[test]
fn test_policy_or_update() {
    let mut sim = create_simulator!();

    // Use a trial session to calculate this policy
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

    let hash_list = vec![
        Tpm2bDigest::from_bytes(&[1, 2, 3]).unwrap(),
        Tpm2bDigest::from_bytes(&[4, 5, 6]).unwrap(),
    ];
    let policy_or = PolicyOR {
        p_hash_list: TpmlDigest::from_slice(&hash_list).unwrap(),
    };
    let policy_or_handles = PolicyORHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_or, policy_or_handles, 0, &[]).unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_or(&hash_list);

    assert_eq!(pol.policy_digest, get_digest_rsp.policy_digest.get_buffer());
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
}

pub(crate) fn get_expected_pcr_digest(
    sim: &mut Simulator<'_>,
    selection: &TpmlPcrSelection,
) -> Vec<u8> {
    let read_cmd = tpm2::commands::PCRRead {
        pcr_selection_in: *selection,
    };
    let read_rsp = sim.execute(read_cmd).unwrap();
    let mut expected_val = Vec::new();
    for val in read_rsp.pcr_values.digests() {
        expected_val.extend_from_slice(val.as_ref());
    }

    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(
        sim.context.platform.crypto,
        TpmiAlgHash::Sha256,
        &expected_val,
        &mut digest_buf,
    )
    .unwrap()
    .digest()
    .to_vec()
}

// Original Go test: policy_test.go - TestPolicyPCR
#[test]
fn test_policy_pcr() {
    let mut select_bytes = [0u8; 3];
    // PCRs 0, 1, 2, 3, 7
    select_bytes[0] = 0x8F;
    let selection =
        TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha256, &select_bytes).unwrap()
        ])
        .unwrap();

    struct TestCase {
        name: &'static str,
        session_type: TpmSe,
        pcr_digest: Option<Vec<u8>>,
        call_should_succeed: bool,
    }

    let mut sim_helper = create_simulator!();
    let expected_digest = get_expected_pcr_digest(&mut sim_helper, &selection);
    let crypto = tpm2_platform_linux::PlatformCryptoProvider;
    let mut wrong_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let wrong_digest = tpm2::crypto::hash(
        &crypto,
        TpmiAlgHash::Sha256,
        &expected_digest,
        &mut wrong_buf,
    )
    .unwrap()
    .digest()
    .to_vec();

    let cases = vec![
        TestCase {
            name: "TrialCorrect",
            session_type: TpmSe::Trial,
            pcr_digest: Some(expected_digest.clone()),
            call_should_succeed: true,
        },
        TestCase {
            name: "TrialIncorrect",
            session_type: TpmSe::Trial,
            pcr_digest: Some(wrong_digest.clone()),
            call_should_succeed: true,
        },
        TestCase {
            name: "TrialEmpty",
            session_type: TpmSe::Trial,
            pcr_digest: None,
            call_should_succeed: true,
        },
        TestCase {
            name: "RealCorrect",
            session_type: TpmSe::Policy,
            pcr_digest: Some(expected_digest.clone()),
            call_should_succeed: true,
        },
        TestCase {
            name: "RealIncorrect",
            session_type: TpmSe::Policy,
            pcr_digest: Some(wrong_digest.clone()),
            call_should_succeed: false,
        },
        TestCase {
            name: "RealEmpty",
            session_type: TpmSe::Policy,
            pcr_digest: None,
            call_should_succeed: true,
        },
    ];

    for tc in cases {
        let mut sim = create_simulator!();

        let start_auth = StartAuthSession {
            nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: tc.session_type,
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

        let input_digest = match &tc.pcr_digest {
            Some(d) => Tpm2bDigest::from_bytes(d).unwrap(),
            None => Tpm2bDigest::default(),
        };

        let policy_pcr = PolicyPCR {
            pcr_digest: input_digest,
            pcrs: selection,
        };
        let policy_pcr_handles = PolicyPCRHandles {
            policy_session: start_rsp_handles.session_handle,
        };

        let res = execute_with_password_sessions(&mut sim, &policy_pcr, policy_pcr_handles, 0, &[]);
        if tc.call_should_succeed {
            res.expect(tc.name);
        } else {
            assert!(res.is_err(), "Expected error for {}", tc.name);
            continue;
        }

        let get_digest = PolicyGetDigest {};
        let get_digest_handles = PolicyGetDigestHandles {
            policy_session: start_rsp_handles.session_handle,
        };
        let (get_digest_rsp, _) =
            execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[])
                .unwrap();

        // Calculate expected digest locally
        let calc_digest = match tc.pcr_digest {
            Some(d) => {
                if tc.session_type == TpmSe::Trial {
                    d // Trial uses input digest directly
                } else {
                    get_expected_pcr_digest(&mut sim, &selection)
                }
            }
            None => get_expected_pcr_digest(&mut sim, &selection),
        };

        let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
        pol.policy_pcr(&selection, &calc_digest);

        assert_eq!(
            pol.policy_digest,
            get_digest_rsp.policy_digest.get_buffer(),
            "Mismatch on {}",
            tc.name
        );
    }
}

// Original Go test: policy_test.go - TestPolicyCpHashUpdate
#[test]
fn test_policy_cp_hash_update() {
    let mut sim = create_simulator!();

    // Use a trial session to calculate this policy
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

    let dummy_cp_hash = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 16,
    ];
    let policy_cp_hash = PolicyCpHash {
        cp_hash_a: Tpm2bDigest::from_bytes(&dummy_cp_hash).unwrap(),
    };
    let policy_cp_hash_handles = PolicyCpHashHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_cp_hash, policy_cp_hash_handles, 0, &[])
            .unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_cp_hash(&dummy_cp_hash);

    assert_eq!(pol.policy_digest, get_digest_rsp.policy_digest.get_buffer());
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
}

// Original Go test: policy_test.go - TestPolicyAuthorizeUpdate
#[test]
fn test_policy_authorize_update() {
    let mut sim = create_simulator!();
    let (_sk, sk_name) = create_signing_key(&mut sim);

    // Use a trial session to calculate this policy
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

    let policy_ref = [5, 6, 7, 8];

    let policy_authorize = PolicyAuthorize {
        approved_policy: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::from_bytes(&policy_ref).unwrap(),
        key_sign: sk_name,
        check_ticket: TpmtTkVerified::Verified(Handle::RH_ENDORSEMENT, Tpm2bDigest::default()),
    };
    let policy_authorize_handles = PolicyAuthorizeHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let _ = execute_with_password_sessions(
        &mut sim,
        &policy_authorize,
        policy_authorize_handles,
        0,
        &[],
    )
    .unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_authorize(sk_name.get_buffer(), &policy_ref);

    assert_eq!(pol.policy_digest, get_digest_rsp.policy_digest.get_buffer());
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
}

// Original Go test: policy_test.go - TestPolicyNVWrittenUpdate
#[test]
fn test_policy_nv_written_update() {
    let mut sim = create_simulator!();

    // Use a trial session to calculate this policy
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

    let policy_nv_written = PolicyNvWritten { written_set: true };
    let policy_nv_written_handles = PolicyNvWrittenHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let _ = execute_with_password_sessions(
        &mut sim,
        &policy_nv_written,
        policy_nv_written_handles,
        0,
        &[],
    )
    .unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_nv_written(true);

    assert_eq!(pol.policy_digest, get_digest_rsp.policy_digest.get_buffer());
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
}

// Original Go test: policy_test.go - TestPolicyNVUpdate
#[test]
fn test_policy_nv_update() {
    let mut sim = create_simulator!();
    let (nv_handle, nv_name) = create_nv_index(&mut sim);

    // Use a trial session to calculate this policy
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

    let operand_b = b"operandB";
    let policy_nv = PolicyNV {
        operand_b: Tpm2bOperand::from_bytes(operand_b).unwrap(),
        offset: 2,
        operation: tpm2::TpmEo::SignedLE,
    };
    let policy_nv_handles = PolicyNVHandles {
        auth_handle: nv_handle,
        nv_index: nv_handle,
        policy_session: start_rsp_handles.session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_nv, policy_nv_handles, 1, &[]).unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_nv(operand_b, 2, tpm2::TpmEo::SignedLE, &nv_name);

    assert_eq!(pol.policy_digest, get_digest_rsp.policy_digest.get_buffer());
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
}

// Original Go test: policy_test.go - TestPolicyAuthorizeNVUpdate
#[test]
fn test_policy_authorize_nv_update() {
    let mut sim = create_simulator!();
    let (nv_handle, nv_name) = create_nv_index(&mut sim);

    // Use a trial session to calculate this policy
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

    let policy_auth_nv = tpm2::commands::PolicyAuthorizeNV {};
    let policy_auth_nv_handles = tpm2::commands::PolicyAuthorizeNVHandles {
        auth_handle: nv_handle,
        nv_index: nv_handle,
        policy_session: start_rsp_handles.session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_auth_nv, policy_auth_nv_handles, 1, &[])
            .unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_authorize_nv(&nv_name);

    assert_eq!(pol.policy_digest, get_digest_rsp.policy_digest.get_buffer());
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
}

// Original Go test: policy_test.go - TestPolicyCommandCodeUpdate
#[test]
fn test_policy_command_code_update() {
    let mut sim = create_simulator!();

    // Use a trial session to calculate this policy
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

    let pcc = PolicyCommandCode {
        code: TpmCc::Create,
    };
    let pcc_handles = PolicyCommandCodeHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let _ = execute_with_password_sessions(&mut sim, &pcc, pcc_handles, 0, &[]).unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

    // Check against PolicyCalculator (PolicyCommandCode is just cc || TpmCc)
    let crypto = tpm2_platform_linux::PlatformCryptoProvider;
    let pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    let mut expected_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let expected = tpm2::crypto::hash(
        &crypto,
        TpmiAlgHash::Sha256,
        &[
            &pol.policy_digest[..],
            &(TpmCc::PolicyCommandCode.code()).to_be_bytes()[..],
            &(TpmCc::Create.code()).to_be_bytes()[..],
        ]
        .concat(),
        &mut expected_buf,
    )
    .unwrap()
    .digest()
    .to_vec();

    assert_eq!(expected, get_digest_rsp.policy_digest.get_buffer());
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
}

// Original Go test: policy_test.go - TestPolicyAuthValue
#[test]
fn test_policy_auth_value() {
    let mut sim = create_simulator!();
    let password = b"foo";

    // Step 1: Calculate policy digest of PolicyAuthValue using trial session
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

    let pav = PolicyAuthValue {};
    let pav_handles = PolicyAuthValueHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let _ = execute_with_password_sessions(&mut sim, &pav, pav_handles, 0, &[]).unwrap();

    let get_digest = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: start_rsp_handles.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[]).unwrap();

    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_auth_value();
    assert_eq!(pol.policy_digest, get_digest_rsp.policy_digest.get_buffer());
    let _ = flush_context(&mut sim, start_rsp_handles.session_handle);

    // Step 2: Create primary key
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

    // Test cases for real authorization
    struct SubTest {
        name: &'static str,
        key_auth: &'static [u8],
        password_provided: Option<&'static [u8]>,
        call_should_succeed: bool,
    }

    let sub_tests = vec![
        SubTest {
            name: "PasswordCorrect",
            key_auth: password,
            password_provided: Some(password),
            call_should_succeed: true,
        },
        SubTest {
            name: "PasswordIncorrect",
            key_auth: password,
            password_provided: Some(b"wrongpwd"),
            call_should_succeed: false,
        },
        SubTest {
            name: "PasswordMissing",
            key_auth: password,
            password_provided: None,
            call_should_succeed: false,
        },
        SubTest {
            name: "PasswordEmpty",
            key_auth: &[],
            password_provided: Some(password),
            call_should_succeed: false,
        },
    ];

    for tc in sub_tests {
        let sensitive_create = TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(tc.key_auth).unwrap(),
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

        let auth_bytes = tc.password_provided.unwrap_or(&[]);

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

        let mut final_session = active_sess.clone();
        final_session.bind_auth = auth_bytes.to_vec();

        // Sign with the session
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
            &[auth_bytes],
        );

        if tc.call_should_succeed {
            assert!(
                res.is_ok(),
                "Expected Sign to succeed for {}, got err {:?}",
                tc.name,
                res.err()
            );
        } else {
            assert!(res.is_err(), "Expected Sign to fail for {}", tc.name);
        }

        // Flush the key to avoid leaking object slots
        let _ = flush_context(&mut sim, rsp_handles.object_handle);

        // Flush the session to avoid leaking session memory slots
        let _ = flush_context(&mut sim, active_sess.session_handle);
    }
}

// Original Go test: policy_test.go - TestPolicyDuplicationSelectUpdate
#[test]
fn test_policy_duplication_select_update() {
    let mut sim = create_simulator!();
    let (_sk, sk_name) = create_signing_key(&mut sim);
    let (_ek, ek_name) = create_signing_key(&mut sim); // Use EK as new parent name

    struct SubTest {
        name: &'static str,
        object_name: Tpm2bName<'static>,
        include_object: bool,
    }

    let cases = vec![
        SubTest {
            name: "IncludeObjectFalse",
            object_name: Tpm2bName::default(),
            include_object: false,
        },
        SubTest {
            name: "IncludeObjectTrue",
            object_name: sk_name,
            include_object: true,
        },
    ];

    for tc in cases {
        // Use a trial session to calculate this policy
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
            object_name: tc.object_name,
            new_parent_name: ek_name,
            include_object: tc.include_object,
        };
        let policy_dup_handles = PolicyDuplicationSelectHandles {
            policy_session: start_rsp_handles.session_handle,
        };
        let _ = execute_with_password_sessions(&mut sim, &policy_dup, policy_dup_handles, 0, &[])
            .unwrap();

        let get_digest = PolicyGetDigest {};
        let get_digest_handles = PolicyGetDigestHandles {
            policy_session: start_rsp_handles.session_handle,
        };
        let (get_digest_rsp, _) =
            execute_with_password_sessions(&mut sim, &get_digest, get_digest_handles, 0, &[])
                .unwrap();

        let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
        pol.policy_duplication_select(
            tc.object_name.get_buffer(),
            ek_name.get_buffer(),
            tc.include_object,
        );

        assert_eq!(
            pol.policy_digest,
            get_digest_rsp.policy_digest.get_buffer(),
            "Mismatch on {}",
            tc.name
        );

        let _ = flush_context(&mut sim, start_rsp_handles.session_handle);
    }
}
