// Ported from tpm-go/tpm2/test/policy_test.go

use crate::test_utils::*;
use tpm2::commands::{
    CreateLoaded, CreateLoadedHandles, CreatePrimary, CreatePrimaryHandles, NVDefineSpace,
    NVDefineSpaceHandles, NVReadPublic, NVReadPublicHandles, NVUndefineSpace,
    NVUndefineSpaceHandles, PolicyAuthValue, PolicyAuthValueHandles, PolicyAuthorize,
    PolicyAuthorizeHandles, PolicyAuthorizeNV, PolicyAuthorizeNVHandles, PolicyCommandCode,
    PolicyCommandCodeHandles, PolicyCpHash, PolicyCpHashHandles, PolicyDuplicationSelect,
    PolicyDuplicationSelectHandles, PolicyGetDigest, PolicyGetDigestHandles, PolicyNV,
    PolicyNVHandles, PolicyNvWritten, PolicyNvWrittenHandles, PolicyOR, PolicyORHandles, PolicyPCR,
    PolicyPCRHandles, PolicySecret, PolicySecretHandles, PolicySigned, PolicySignedHandles, Sign,
    SignHandles, StartAuthSession, StartAuthSessionHandles,
};
use tpm2::{Handle, TpmCc, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce,
    Tpm2bOperand, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaNv, TpmaObject, TpmaSession,
    TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmlDigest, TpmlPcrSelection, TpmsEccParms,
    TpmsNvPublic, TpmsPcrSelection, TpmsRsaParms, TpmsSensitiveCreate, TpmsSignatureEcc,
    TpmtEccScheme, TpmtPublic, TpmtRsaScheme, TpmtSigScheme, TpmtSignature, TpmtSymDefObject,
    TpmtTkHashcheck, TpmtTkVerified,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

/// Computes `hashAlg(data)` with the platform crypto provider.
fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let crypto = tpm2_platform_linux::PlatformCryptoProvider;
    let mut buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(&crypto, TpmiAlgHash::Sha256, data, &mut buf)
        .unwrap()
        .digest()
        .to_vec()
}

/// Equivalent of go-tpm's `PolicySession(thetpm, TPMAlgSHA256, 16, opts...)`:
/// starts an unbound, unsalted policy (or trial, if `trial`) session with a
/// random 16-byte caller nonce, a NULL symmetric algorithm and the
/// `continueSession` attribute set.
fn policy_session(sim: &mut Simulator<'_>, trial: bool) -> ActiveSession {
    let session_type = if trial { TpmSe::Trial } else { TpmSe::Policy };
    let mut sess = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        session_type,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("setting up policy session");
    sess.attributes = TpmaSession::CONTINUE_SESSION;
    sess
}

/// Executes `TPM2_PolicyGetDigest` on `session` and returns the digest.
fn policy_get_digest(sim: &mut Simulator<'_>, session: Handle) -> Tpm2bDigest<'static> {
    let pgd = PolicyGetDigest {};
    let pgd_handles = PolicyGetDigestHandles {
        policy_session: session,
    };
    let (rsp, _) = execute_with_password_sessions(sim, &pgd, pgd_handles, 0, &[])
        .expect("executing PolicyGetDigest");
    rsp.policy_digest
}

/// Equivalent of the Go `signingKey` helper: creates an ECDSA-P256-SHA256
/// signing primary key under the owner hierarchy. Clean up with
/// [`flush_context`].
fn signing_key(sim: &mut Simulator<'_>) -> (Handle, Tpm2bName<'static>) {
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint::default(),
        ),
    };
    let create_primary = CreatePrimary {
        in_public: tpm2::Tpm2b(public_area),
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &create_primary, create_handles, 1, &[])
            .expect("could not create key");
    (rsp_handles.object_handle, rsp.name)
}

/// NV index used by the Go `nvIndex` helper.
const NV_INDEX: Handle = Handle(0x01800001);

/// Equivalent of the Go `nvIndex` helper: defines an ordinary NV index
/// (OwnerWrite | AuthRead, no data) and reads back its Name. Clean up with
/// [`nv_index_cleanup`].
fn nv_index(sim: &mut Simulator<'_>) -> (Handle, Tpm2bName<'static>) {
    let def_space = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: tpm2::Tpm2b(TpmsNvPublic {
            nv_index: NV_INDEX,
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD,
            auth_policy: Tpm2bDigest::default(),
            data_size: 0,
        }),
    };
    let def_space_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(sim, &def_space, def_space_handles, 1, &[])
        .expect("could not create NV index");

    let read_pub = NVReadPublic {};
    let read_pub_handles = NVReadPublicHandles { nv_index: NV_INDEX };
    let (read_rsp, _) = execute_with_password_sessions(sim, &read_pub, read_pub_handles, 0, &[])
        .expect("could not read NV index public info");

    (NV_INDEX, read_rsp.nv_name)
}

/// Cleanup returned by the Go `nvIndex` helper: undefines the NV index.
fn nv_index_cleanup(sim: &mut Simulator<'_>, nv: Handle) {
    let undefine = NVUndefineSpace {};
    let undefine_handles = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv,
    };
    execute_with_password_sessions(sim, &undefine, undefine_handles, 1, &[])
        .expect("could not undefine NV index");
}

/// 256 zero bytes, the RSA `unique` field of go-tpm's SRK/EK templates.
static RSA_UNIQUE_ZEROS: [u8; 256] = [0u8; 256];

/// Equivalent of go-tpm's `RSASRKTemplate`.
fn rsa_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&RSA_UNIQUE_ZEROS).unwrap(),
        ),
    }
}

/// Equivalent of go-tpm's `RSAEKTemplate`.
fn rsa_ek_template_go() -> TpmtPublic<'static> {
    TpmtPublic {
        parms_and_id: match rsa_ek_template().parms_and_id {
            PublicParmsAndId::Rsa(parms, _) => PublicParmsAndId::Rsa(
                parms,
                Tpm2bPublicKeyRsa::from_bytes(&RSA_UNIQUE_ZEROS).unwrap(),
            ),
            _ => unreachable!("rsa_ek_template() is an RSA template"),
        },
        ..rsa_ek_template()
    }
}

/// Creates a primary key from `template` under `hierarchy` (empty password
/// auth) and returns its handle and Name. Clean up with [`flush_context`].
fn create_primary(
    sim: &mut Simulator<'_>,
    hierarchy: Handle,
    template: TpmtPublic<'static>,
) -> (Handle, Tpm2bName<'static>) {
    let create_primary = CreatePrimary {
        in_public: tpm2::Tpm2b(template),
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: hierarchy,
    };
    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &create_primary, create_handles, 1, &[])
            .expect("could not create primary key");
    (rsp_handles.object_handle, rsp.name)
}

/// Equivalent of the Go `primaryRSASRK` helper.
fn primary_rsa_srk(sim: &mut Simulator<'_>) -> (Handle, Tpm2bName<'static>) {
    create_primary(sim, Handle::RH_OWNER, rsa_srk_template())
}

/// Equivalent of the Go `primaryRSAEK` helper.
fn primary_rsa_ek(sim: &mut Simulator<'_>) -> (Handle, Tpm2bName<'static>) {
    create_primary(sim, Handle::RH_ENDORSEMENT, rsa_ek_template_go())
}

/// Shared body of the `TestCreatePolicySession` subtests.
fn create_policy_session(session_type: TpmSe) {
    let mut sim = create_simulator!();

    let sas = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let sas_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (_, sas_rsp_handles) = execute_with_password_sessions(&mut sim, &sas, sas_handles, 0, &[])
        .expect("StartAuthSession()");

    let digest = policy_get_digest(&mut sim, sas_rsp_handles.session_handle);
    assert!(
        digest.get_buffer().iter().all(|&b| b == 0),
        "PolicyGetDigest() = {:02x?}, want all zeros",
        digest.get_buffer()
    );

    flush_context(&mut sim, sas_rsp_handles.session_handle).expect("FlushContext()");
}

// Original Go test: policy_test.go - TestCreatePolicySession/trial
#[test]
fn test_create_policy_session_trial() {
    create_policy_session(TpmSe::Trial);
}

// Original Go test: policy_test.go - TestCreatePolicySession/policy
#[test]
fn test_create_policy_session_policy() {
    create_policy_session(TpmSe::Policy);
}

// Original Go test: policy_test.go - TestPolicySignedUpdate
#[test]
fn test_policy_signed_update() {
    let mut sim = create_simulator!();
    let (sk, sk_name) = signing_key(&mut sim);

    // Use a trial session to calculate this policy
    let sess = policy_session(&mut sim, true);

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
        policy_session: sess.session_handle,
    };
    execute_with_password_sessions(&mut sim, &policy_signed, policy_signed_handles, 0, &[])
        .expect("executing PolicySigned");

    let want = policy_get_digest(&mut sim, sess.session_handle);

    // Use the policy helper to calculate the same policy
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_signed(sk_name.get_buffer(), &policy_ref);

    assert_eq!(pol.policy_digest, want.get_buffer(), "policySigned.Hash()");

    flush_context(&mut sim, sess.session_handle).expect("cleaning up policy session");
    flush_context(&mut sim, sk).expect("could not flush signing key");
}

// Original Go test: policy_test.go - TestPolicySecretUpdate
#[test]
fn test_policy_secret_update() {
    let mut sim = create_simulator!();
    let (sk, sk_name) = signing_key(&mut sim);

    // Use a trial session to calculate this policy
    let sess = policy_session(&mut sim, true);

    let policy_ref = [5, 6, 7, 8];
    let policy_secret = PolicySecret {
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::from_bytes(&policy_ref).unwrap(),
        expiration: 0,
    };
    let policy_secret_handles = PolicySecretHandles {
        auth_handle: sk,
        policy_session: sess.session_handle,
    };
    execute_with_password_sessions(&mut sim, &policy_secret, policy_secret_handles, 1, &[])
        .expect("executing PolicySecret");

    let want = policy_get_digest(&mut sim, sess.session_handle);

    // Use the policy helper to calculate the same policy
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_secret(sk_name.get_buffer(), &policy_ref);

    assert_eq!(pol.policy_digest, want.get_buffer(), "policySecret.Hash()");

    flush_context(&mut sim, sess.session_handle).expect("cleaning up policy session");
    flush_context(&mut sim, sk).expect("could not flush signing key");
}

// Original Go test: policy_test.go - TestPolicyOrUpdate
#[test]
fn test_policy_or_update() {
    let mut sim = create_simulator!();

    // Use a trial session to calculate this policy
    let sess = policy_session(&mut sim, true);

    let hash_list = [
        Tpm2bDigest::from_bytes(&[1, 2, 3]).unwrap(),
        Tpm2bDigest::from_bytes(&[4, 5, 6]).unwrap(),
    ];
    let policy_or = PolicyOR {
        p_hash_list: TpmlDigest::from_slice(&hash_list).unwrap(),
    };
    let policy_or_handles = PolicyORHandles {
        policy_session: sess.session_handle,
    };
    execute_with_password_sessions(&mut sim, &policy_or, policy_or_handles, 0, &[])
        .expect("executing PolicyOr");

    let want = policy_get_digest(&mut sim, sess.session_handle);

    // Use the policy helper to calculate the same policy
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_or(&hash_list);

    assert_eq!(pol.policy_digest, want.get_buffer(), "policyOr.Hash()");

    flush_context(&mut sim, sess.session_handle).expect("cleaning up policy session");
}

/// Equivalent of the Go `getExpectedPCRDigest` helper: reads the selected
/// PCRs and returns the SHA-256 digest of their concatenated values.
pub(crate) fn get_expected_pcr_digest(
    sim: &mut Simulator<'_>,
    selection: &TpmlPcrSelection,
) -> Vec<u8> {
    let read_cmd = tpm2::commands::PCRRead {
        pcr_selection_in: *selection,
    };
    let read_rsp = sim.execute(read_cmd).expect("failed to read PCRs");
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

/// The `pcrDigest` column of the `TestPolicyPCR` table.
enum PcrDigestCase {
    /// `expectedDigest`: the digest of the current PCR values.
    Expected,
    /// `wrongDigest[:]`: SHA-256 of `expectedDigest`.
    Wrong,
    /// `nil`: an empty digest.
    Empty,
}

/// Shared body of the `TestPolicyPCR` subtests (one table entry each).
fn policy_pcr(trial: bool, pcr_digest_case: PcrDigestCase, call_should_succeed: bool) {
    let mut sim = create_simulator!();

    // PCRs 0, 1, 2, 3, 7 (PCClientCompatible: 3-byte select)
    let selection = TpmlPcrSelection::from_slice(&[TpmsPcrSelection::new(
        TpmiAlgHash::Sha256,
        &[0x8F, 0x00, 0x00],
    )
    .unwrap()])
    .unwrap();

    let expected_digest = get_expected_pcr_digest(&mut sim, &selection);
    let wrong_digest = hash_sha256(&expected_digest);

    let pcr_digest: Option<Vec<u8>> = match pcr_digest_case {
        PcrDigestCase::Expected => Some(expected_digest),
        PcrDigestCase::Wrong => Some(wrong_digest),
        PcrDigestCase::Empty => None,
    };

    let sess = policy_session(&mut sim, trial);

    let input_digest = match &pcr_digest {
        Some(d) => Tpm2bDigest::from_bytes(leak_bytes(d)).unwrap(),
        None => Tpm2bDigest::default(),
    };
    let policy_pcr = PolicyPCR {
        pcr_digest: input_digest,
        pcrs: selection,
    };
    let policy_pcr_handles = PolicyPCRHandles {
        policy_session: sess.session_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &policy_pcr, policy_pcr_handles, 0, &[]);
    if call_should_succeed {
        res.expect("executing PolicyPCR");
    } else {
        assert!(res.is_err(), "expected PolicyPCR to return error, got nil");
        return;
    }

    let want = policy_get_digest(&mut sim, sess.session_handle);

    // If the pcrDigest is empty: see TPM 2.0 Part 3, 23.7.
    let calc_digest = match pcr_digest {
        Some(d) => d,
        None => {
            let expected_digest = get_expected_pcr_digest(&mut sim, &selection);
            println!("expectedDigest={:02x?}", expected_digest);
            // Create a populated policyPCR for the PolicyCalculator
            expected_digest
        }
    };

    // Use the policy helper to calculate the same policy
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_pcr(&selection, &calc_digest);

    assert_eq!(pol.policy_digest, want.get_buffer(), "policyPCR.Hash()");

    flush_context(&mut sim, sess.session_handle).expect("cleaning up policy session");
}

// Original Go test: policy_test.go - TestPolicyPCR/TrialCorrect
#[test]
fn test_policy_pcr_trial_correct() {
    policy_pcr(true, PcrDigestCase::Expected, true);
}

// Original Go test: policy_test.go - TestPolicyPCR/TrialIncorrect
#[test]
fn test_policy_pcr_trial_incorrect() {
    policy_pcr(true, PcrDigestCase::Wrong, true);
}

// Original Go test: policy_test.go - TestPolicyPCR/TrialEmpty
#[test]
fn test_policy_pcr_trial_empty() {
    policy_pcr(true, PcrDigestCase::Empty, true);
}

// Original Go test: policy_test.go - TestPolicyPCR/RealCorrect
#[test]
fn test_policy_pcr_real_correct() {
    policy_pcr(false, PcrDigestCase::Expected, true);
}

// Original Go test: policy_test.go - TestPolicyPCR/RealIncorrect
#[test]
fn test_policy_pcr_real_incorrect() {
    policy_pcr(false, PcrDigestCase::Wrong, false);
}

// Original Go test: policy_test.go - TestPolicyPCR/RealEmpty
#[test]
fn test_policy_pcr_real_empty() {
    policy_pcr(false, PcrDigestCase::Empty, true);
}

// Original Go test: policy_test.go - TestPolicyCpHashUpdate
#[test]
fn test_policy_cp_hash_update() {
    let mut sim = create_simulator!();

    // Use a trial session to calculate this policy
    let sess = policy_session(&mut sim, true);

    let cp_hash_a = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 16,
    ];
    let policy_cp_hash = PolicyCpHash {
        cp_hash_a: Tpm2bDigest::from_bytes(&cp_hash_a).unwrap(),
    };
    let policy_cp_hash_handles = PolicyCpHashHandles {
        policy_session: sess.session_handle,
    };
    execute_with_password_sessions(&mut sim, &policy_cp_hash, policy_cp_hash_handles, 0, &[])
        .expect("executing PolicyCpHash");

    let want = policy_get_digest(&mut sim, sess.session_handle);

    // Use the policy helper to calculate the same policy
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_cp_hash(&cp_hash_a);

    assert_eq!(pol.policy_digest, want.get_buffer(), "policyCpHash.Hash()");

    flush_context(&mut sim, sess.session_handle).expect("cleaning up policy session");
}

// Original Go test: policy_test.go - TestPolicyAuthorizeUpdate
#[test]
fn test_policy_authorize_update() {
    let mut sim = create_simulator!();

    // Use a trial session to calculate this policy
    let sess = policy_session(&mut sim, true);

    let (sk, sk_name) = signing_key(&mut sim);

    let policy_ref = [5, 6, 7, 8];
    let policy_authorize = PolicyAuthorize {
        approved_policy: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::from_bytes(&policy_ref).unwrap(),
        key_sign: sk_name,
        check_ticket: TpmtTkVerified::Verified(Handle::RH_ENDORSEMENT, Tpm2bDigest::default()),
    };
    let policy_authorize_handles = PolicyAuthorizeHandles {
        policy_session: sess.session_handle,
    };
    execute_with_password_sessions(
        &mut sim,
        &policy_authorize,
        policy_authorize_handles,
        0,
        &[],
    )
    .expect("executing PolicyAuthorize");

    let want = policy_get_digest(&mut sim, sess.session_handle);

    // Use the policy helper to calculate the same policy
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_authorize(sk_name.get_buffer(), &policy_ref);

    assert_eq!(
        pol.policy_digest,
        want.get_buffer(),
        "policyAuthorize.Hash()"
    );

    flush_context(&mut sim, sk).expect("could not flush signing key");
    flush_context(&mut sim, sess.session_handle).expect("cleaning up policy session");
}

// Original Go test: policy_test.go - TestPolicyNVWrittenUpdate
#[test]
fn test_policy_nv_written_update() {
    let mut sim = create_simulator!();

    // Use a trial session to calculate this policy
    let sess = policy_session(&mut sim, true);

    let policy_nv_written = PolicyNvWritten { written_set: true };
    let policy_nv_written_handles = PolicyNvWrittenHandles {
        policy_session: sess.session_handle,
    };
    execute_with_password_sessions(
        &mut sim,
        &policy_nv_written,
        policy_nv_written_handles,
        0,
        &[],
    )
    .expect("executing PolicyNVWritten");

    let want = policy_get_digest(&mut sim, sess.session_handle);

    // Use the policy helper to calculate the same policy
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_nv_written(true);

    assert_eq!(
        pol.policy_digest,
        want.get_buffer(),
        "PolicyNVWritten.Hash()"
    );

    flush_context(&mut sim, sess.session_handle).expect("cleaning up policy session");
}

// Original Go test: policy_test.go - TestPolicyNVUpdate
#[test]
fn test_policy_nv_update() {
    let mut sim = create_simulator!();
    let (nv, nv_name) = nv_index(&mut sim);

    // Use a trial session to calculate this policy
    let sess = policy_session(&mut sim, true);

    let operand_b = b"operandB";
    let policy_nv = PolicyNV {
        operand_b: Tpm2bOperand::from_bytes(operand_b).unwrap(),
        offset: 2,
        operation: tpm2::TpmEo::SignedLE,
    };
    let policy_nv_handles = PolicyNVHandles {
        auth_handle: nv,
        nv_index: nv,
        policy_session: sess.session_handle,
    };
    execute_with_password_sessions(&mut sim, &policy_nv, policy_nv_handles, 1, &[])
        .expect("executing PolicyAuthorizeNV");

    let want = policy_get_digest(&mut sim, sess.session_handle);

    // Use the policy helper to calculate the same policy
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_nv(operand_b, 2, tpm2::TpmEo::SignedLE, &nv_name);

    assert_eq!(
        pol.policy_digest,
        want.get_buffer(),
        "PolicyAuthorizeNV.Hash()"
    );

    flush_context(&mut sim, sess.session_handle).expect("cleaning up policy session");
    nv_index_cleanup(&mut sim, nv);
}

// Original Go test: policy_test.go - TestPolicyAuthorizeNVUpdate
#[test]
fn test_policy_authorize_nv_update() {
    let mut sim = create_simulator!();
    let (nv, nv_name) = nv_index(&mut sim);

    // Use a trial session to calculate this policy
    let sess = policy_session(&mut sim, true);

    let policy_authorize_nv = PolicyAuthorizeNV {};
    let policy_authorize_nv_handles = PolicyAuthorizeNVHandles {
        auth_handle: nv,
        nv_index: nv,
        policy_session: sess.session_handle,
    };
    execute_with_password_sessions(
        &mut sim,
        &policy_authorize_nv,
        policy_authorize_nv_handles,
        1,
        &[],
    )
    .expect("executing PolicyAuthorizeNV");

    let want = policy_get_digest(&mut sim, sess.session_handle);

    // Use the policy helper to calculate the same policy
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_authorize_nv(&nv_name);

    assert_eq!(
        pol.policy_digest,
        want.get_buffer(),
        "PolicyAuthorizeNV.Hash()"
    );

    flush_context(&mut sim, sess.session_handle).expect("cleaning up policy session");
    nv_index_cleanup(&mut sim, nv);
}

// Original Go test: policy_test.go - TestPolicyCommandCodeUpdate
#[test]
fn test_policy_command_code_update() {
    let mut sim = create_simulator!();

    // Use a trial session to calculate this policy
    let sess = policy_session(&mut sim, true);

    let pcc = PolicyCommandCode {
        code: TpmCc::Create,
    };
    let pcc_handles = PolicyCommandCodeHandles {
        policy_session: sess.session_handle,
    };
    execute_with_password_sessions(&mut sim, &pcc, pcc_handles, 0, &[])
        .expect("executing PolicyCommandCode");

    let want = policy_get_digest(&mut sim, sess.session_handle);

    // Calculate the same policy locally (PolicyCalculator has no
    // PolicyCommandCode helper): H(policyDigest || TPM_CC_PolicyCommandCode || code).
    let pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    let got = hash_sha256(
        &[
            &pol.policy_digest[..],
            &TpmCc::PolicyCommandCode.code().to_be_bytes()[..],
            &TpmCc::Create.code().to_be_bytes()[..],
        ]
        .concat(),
    );

    assert_eq!(got, want.get_buffer(), "PolicyCommandCode.Hash()");

    flush_context(&mut sim, sess.session_handle).expect("cleaning up policy session");
}

/// Shared body of the `TestPolicyAuthValue` subtests (one table entry each).
///
/// * `password`: the auth value of the created signing key.
/// * `auth_option`: `Some(auth)` for go-tpm's `Auth(auth)` session option,
///   `None` for no auth option.
fn policy_auth_value(
    password: &'static [u8],
    auth_option: Option<&'static [u8]>,
    call_should_succeed: bool,
) {
    let mut sim = create_simulator!();

    let (pk, _pk_name) = primary_rsa_srk(&mut sim);

    // create a trial policy with PolicyAuthValue
    let sess = policy_session(&mut sim, true);

    let pav = PolicyAuthValue {};
    let pav_handles = PolicyAuthValueHandles {
        policy_session: sess.session_handle,
    };
    execute_with_password_sessions(&mut sim, &pav, pav_handles, 0, &[])
        .expect("error executing policyAuthValue");

    // verify the digest
    let pgd = policy_get_digest(&mut sim, sess.session_handle);

    // Use the policy helper to calculate the same policy
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_auth_value();

    assert_eq!(
        pol.policy_digest,
        pgd.get_buffer(),
        "PolicyAuthValue.Hash()"
    );

    // now apply the policy to a new key
    let rsa_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: pgd,
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let create_loaded = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: make_template(&rsa_template),
    };
    let create_loaded_handles = CreateLoadedHandles { parent_handle: pk };
    let (_, k_handles) =
        execute_with_password_sessions(&mut sim, &create_loaded, create_loaded_handles, 1, &[])
            .expect("error creating key");
    let k = k_handles.object_handle;

    // create a real policy session and use the password through the authOption
    let sess2 = policy_session(&mut sim, false);

    let policy_auth_value2 = PolicyAuthValue {};
    let policy_auth_value2_handles = PolicyAuthValueHandles {
        policy_session: sess2.session_handle,
    };
    execute_with_password_sessions(
        &mut sim,
        &policy_auth_value2,
        policy_auth_value2_handles,
        0,
        &[],
    )
    .expect("executing policyAuthValue");

    // sign some data with the key using the session
    let digest = hash_sha256(b"somedata");
    let sign = Sign {
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        // go-tpm marshals the zero (nullable) hierarchy as TPM_RH_NULL.
        validation: TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    let sign_handles = SignHandles { key_handle: k };
    let session_auth: &[u8] = auth_option.unwrap_or(&[]);
    let mut sign_sessions = [sess2.clone()];
    let res = execute_with_hmac_sessions_status(
        &mut sim,
        &sign,
        sign_handles,
        &[],
        &mut sign_sessions,
        &[session_auth],
    );

    // Go's deferred cleanups run in LIFO order regardless of the outcome:
    // the policy session (error ignored), the key, the trial session and
    // finally the primary key.
    let cleanup = |sim: &mut Simulator<'_>| {
        let _ = flush_context(sim, sess2.session_handle);
        flush_context(sim, k).expect("error cleaning up key");
        flush_context(sim, sess.session_handle).expect("cleaning up trial session");
        flush_context(sim, pk).expect("could not flush primary key");
    };

    if call_should_succeed {
        assert!(
            res.is_ok(),
            "expected no error for PolicyAuthValue but got: {:?}",
            res.err()
        );
    } else {
        assert!(res.is_err(), "expected error for PolicyAuthValue, got nil");
    }
    cleanup(&mut sim);
}

const POLICY_AUTH_VALUE_PASSWORD: &[u8] = b"foo";
const POLICY_AUTH_VALUE_WRONG_PASSWORD: &[u8] = b"bar";

// Original Go test: policy_test.go - TestPolicyAuthValue/PasswordCorrect
#[test]
fn test_policy_auth_value_password_correct() {
    policy_auth_value(
        POLICY_AUTH_VALUE_PASSWORD,
        Some(POLICY_AUTH_VALUE_PASSWORD),
        true,
    );
}

// Original Go test: policy_test.go - TestPolicyAuthValue/PasswordIncorrect
#[test]
fn test_policy_auth_value_password_incorrect() {
    policy_auth_value(
        POLICY_AUTH_VALUE_WRONG_PASSWORD,
        Some(POLICY_AUTH_VALUE_PASSWORD),
        false,
    );
}

// Original Go test: policy_test.go - TestPolicyAuthValue/PasswordEmpty
#[test]
fn test_policy_auth_value_password_empty() {
    policy_auth_value(&[], Some(POLICY_AUTH_VALUE_PASSWORD), false);
}

// Original Go test: policy_test.go - TestPolicyAuthValue/AuthOptionEmpty
#[test]
fn test_policy_auth_value_auth_option_empty() {
    policy_auth_value(POLICY_AUTH_VALUE_PASSWORD, None, false);
}

/// Objects created by the shared setup of `TestPolicyDuplicationSelectUpdate`.
struct DuplicationSelectSetup {
    ek: Handle,
    ek_name: Tpm2bName<'static>,
    pk: Handle,
    k: Handle,
    k_name: Tpm2bName<'static>,
}

/// Shared setup of `TestPolicyDuplicationSelectUpdate`: creates the RSA EK,
/// the RSA SRK and a duplicable RSA signing key under the SRK.
fn duplication_select_setup(sim: &mut Simulator<'_>) -> DuplicationSelectSetup {
    let (ek, ek_name) = primary_rsa_ek(sim);
    let (pk, _pk_name) = primary_rsa_srk(sim);

    let template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let create_loaded = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate::default()),
        in_public: make_template(&template),
    };
    let create_loaded_handles = CreateLoadedHandles { parent_handle: pk };
    let (k_rsp, k_handles) =
        execute_with_password_sessions(sim, &create_loaded, create_loaded_handles, 1, &[])
            .expect("error creating key");

    DuplicationSelectSetup {
        ek,
        ek_name,
        pk,
        k: k_handles.object_handle,
        k_name: k_rsp.name,
    }
}

/// Shared body of the `TestPolicyDuplicationSelectUpdate` subtests.
///
/// `include_object` selects the table entry: `false` uses an empty object
/// Name, `true` uses the Name of the created key.
fn policy_duplication_select_update(include_object: bool) {
    let mut sim = create_simulator!();
    let setup = duplication_select_setup(&mut sim);

    let object_name = if include_object {
        setup.k_name
    } else {
        Tpm2bName::default()
    };

    // create a trial policy with PolicyDuplicationSelect
    let sess = policy_session(&mut sim, true);

    let pds = PolicyDuplicationSelect {
        object_name,
        new_parent_name: setup.ek_name,
        include_object,
    };
    let pds_handles = PolicyDuplicationSelectHandles {
        policy_session: sess.session_handle,
    };
    execute_with_password_sessions(&mut sim, &pds, pds_handles, 0, &[])
        .expect("error executing PolicyDuplicationSelect");

    let pdr = policy_get_digest(&mut sim, sess.session_handle);

    // Use the policy helper to calculate the same policy
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_duplication_select(
        object_name.get_buffer(),
        setup.ek_name.get_buffer(),
        include_object,
    );

    assert_eq!(
        pol.policy_digest,
        pdr.get_buffer(),
        "PolicyAuthValue.Hash()"
    );

    flush_context(&mut sim, sess.session_handle).expect("error cleaning up trial session");

    // Deferred cleanups of the parent test.
    flush_context(&mut sim, setup.k).expect("error cleaning up key");
    flush_context(&mut sim, setup.pk).expect("could not flush primary key");
    flush_context(&mut sim, setup.ek).expect("could not flush primary key");
}

// Original Go test: policy_test.go - TestPolicyDuplicationSelectUpdate/IncludeObjectFalse
#[test]
fn test_policy_duplication_select_update_include_object_false() {
    policy_duplication_select_update(false);
}

// Original Go test: policy_test.go - TestPolicyDuplicationSelectUpdate/IncludeObjectTrue
#[test]
fn test_policy_duplication_select_update_include_object_true() {
    policy_duplication_select_update(true);
}
