//! White-box tests for `TPM2_PolicyPCR` around `pcrUpdateCounter` wrap-around.
//!
//! Moved from the black-box `testing` crate: they force the TPM-internal PCR
//! update counter to `u32::MAX` (unreachable through the command interface
//! without ~4 billion PCR updates) via [`tpm2_impl::GlobalState`].

mod common;

use common::{
    FakeRng, FakeStorage, FakeTimer, RealCryptoEngine, TestCryptoProvider, execute_command,
    password_auth, setup_real_crypto_tpm,
};
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, PCRExtend, PCRExtendHandles, PCRRead, PolicyGetDigest,
    PolicyGetDigestHandles, PolicyPCR, PolicyPCRHandles, Sign, SignHandles, StartAuthSession,
    StartAuthSessionHandles,
};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce,
    Tpm2bSensitiveData, TpmEccCurve, TpmSe, TpmaObject, TpmaSession, TpmiAlgHash, TpmlDigestValues,
    TpmlPcrSelection, TpmsAuthCommand, TpmsEccParms, TpmsPcrSelection, TpmsSensitiveCreate,
    TpmtEccScheme, TpmtHa, TpmtPublic, TpmtTkHashcheck,
};

const PASSWORD: &[u8] = b"barpassword";

/// Selection of PCR 0 in the SHA-256 bank.
fn pcr0_selection() -> TpmlPcrSelection {
    TpmlPcrSelection::from_slice(&[
        TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x01, 0, 0]).unwrap()
    ])
    .unwrap()
}

/// Computes the PolicyPCR `pcrDigest` (SHA-256 over the selected PCR values)
/// from the current PCR contents.
fn current_pcr_digest(
    tpm: &mut RealCryptoEngine<'_>,
    global_state: &mut tpm2_impl::GlobalState,
) -> Vec<u8> {
    let (_, read) = execute_command(
        tpm,
        global_state,
        &(),
        &PCRRead {
            pcr_selection_in: pcr0_selection(),
        },
        &[],
    )
    .expect("PCRRead failed");
    let crypto = TestCryptoProvider;
    let mut ctx = tpm2::crypto::HashCtx::new(&crypto, TpmiAlgHash::Sha256).unwrap();
    for value in read.pcr_values.as_ref() {
        ctx.update(value.get_buffer()).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
}

/// Starts an unbound, unsalted session of `session_type` and returns its handle.
fn start_session(
    tpm: &mut RealCryptoEngine<'_>,
    global_state: &mut tpm2_impl::GlobalState,
    session_type: TpmSe,
) -> Handle {
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0x5a; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let (resp_handles, _) =
        execute_command(tpm, global_state, &handles, &cmd, &[]).expect("StartAuthSession failed");
    resp_handles.session_handle
}

/// Executes `TPM2_PolicyPCR(pcrDigest, PCR0)` on `session`.
fn policy_pcr(
    tpm: &mut RealCryptoEngine<'_>,
    global_state: &mut tpm2_impl::GlobalState,
    session: Handle,
    pcr_digest: &[u8],
) {
    let cmd = PolicyPCR {
        pcr_digest: Tpm2bDigest::from_bytes(pcr_digest).unwrap(),
        pcrs: pcr0_selection(),
    };
    let handles = PolicyPCRHandles {
        policy_session: session,
    };
    execute_command(tpm, global_state, &handles, &cmd, &[]).expect("PolicyPCR failed");
}

/// Creates an ECDSA signing primary key whose authPolicy is
/// `PolicyPCR(PCR0 = current value)`, and returns `(key handle, pcrDigest)`.
fn create_pcr_gated_key(
    tpm: &mut RealCryptoEngine<'_>,
    global_state: &mut tpm2_impl::GlobalState,
) -> (Handle, Vec<u8>) {
    let pcr_digest = current_pcr_digest(tpm, global_state);

    // Compute the policy digest with a trial session.
    let trial = start_session(tpm, global_state, TpmSe::Trial);
    policy_pcr(tpm, global_state, trial, &pcr_digest);
    let (_, digest) = execute_command(
        tpm,
        global_state,
        &PolicyGetDigestHandles {
            policy_session: trial,
        },
        &PolicyGetDigest {},
        &[],
    )
    .expect("PolicyGetDigest failed");

    let create = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(PASSWORD).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SIGN_ENCRYPT,
            auth_policy: digest.policy_digest,
            parms_and_id: PublicParmsAndId::Ecc(
                TpmsEccParms {
                    symmetric: None,
                    scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                tpm2::TpmsEccPoint::default(),
            ),
        }),
        ..Default::default()
    };
    let (handles, _) = execute_command(
        tpm,
        global_state,
        &CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        &create,
        &[password_auth(b"")],
    )
    .expect("CreatePrimary failed");
    (handles.object_handle, pcr_digest)
}

/// Signs a fixed digest with `key`, authorized by the policy `session`.
fn sign_with_policy_session(
    tpm: &mut RealCryptoEngine<'_>,
    global_state: &mut tpm2_impl::GlobalState,
    key: Handle,
    session: Handle,
) -> Result<(), u32> {
    let auth = TpmsAuthCommand {
        session_handle: session,
        nonce: Tpm2bNonce::from_bytes(&[0xa5; 16]).unwrap(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };
    let cmd = Sign {
        digest: Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    execute_command(
        tpm,
        global_state,
        &SignHandles { key_handle: key },
        &cmd,
        &[auth],
    )
    .map(|_| ())
}

/// `pcrUpdateCounter` is `u32::MAX` when `TPM2_PolicyPCR` gates the session;
/// a subsequent `TPM2_PCR_Extend` wraps the counter to 0. The session must
/// still be rejected with `TPM_RC_PCR_CHANGED` (no wrap-around bypass).
#[test]
fn test_policy_pcr_counter_overflow_vulnerability() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut gs) = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    gs.pcrs.update_counter = u32::MAX;
    let (key, pcr_digest) = create_pcr_gated_key(&mut tpm, &mut gs);

    let session = start_session(&mut tpm, &mut gs, TpmSe::Policy);
    policy_pcr(&mut tpm, &mut gs, session, &pcr_digest);

    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&[0xaa; 32])).unwrap();
    execute_command(
        &mut tpm,
        &mut gs,
        &PCRExtendHandles {
            pcr_handle: Handle(0),
        },
        &PCRExtend { digests },
        &[password_auth(b"")],
    )
    .expect("PCR_Extend failed");
    assert_eq!(gs.pcrs.update_counter, 0, "pcrUpdateCounter must wrap to 0");

    assert_eq!(
        sign_with_policy_session(&mut tpm, &mut gs, key, session),
        Err(TpmRc::PCR_CHANGED.get()),
        "Sign must fail with TPM_RC_PCR_CHANGED after the counter wrapped"
    );
}

/// `pcrUpdateCounter` is `u32::MAX` when `TPM2_PolicyPCR` gates the session
/// and then (as if it wrapped) becomes 0 without the PCR values changing. The
/// counter mismatch alone must cause `TPM_RC_PCR_CHANGED`.
#[test]
fn test_policy_pcr_counter_bypass_on_max() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut gs) = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    gs.pcrs.update_counter = u32::MAX;
    let (key, pcr_digest) = create_pcr_gated_key(&mut tpm, &mut gs);

    let session = start_session(&mut tpm, &mut gs, TpmSe::Policy);
    policy_pcr(&mut tpm, &mut gs, session, &pcr_digest);

    gs.pcrs.update_counter = 0;

    assert_eq!(
        sign_with_policy_session(&mut tpm, &mut gs, key, session),
        Err(TpmRc::PCR_CHANGED.get()),
        "Sign must fail with TPM_RC_PCR_CHANGED when the counter changed from u32::MAX to 0"
    );
}

/// Control case: without any PCR update the PCR-gated key is usable, so the
/// failures above are caused by the counter check and nothing else.
#[test]
fn test_policy_pcr_counter_unchanged_succeeds() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut gs) = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    gs.pcrs.update_counter = u32::MAX;
    let (key, pcr_digest) = create_pcr_gated_key(&mut tpm, &mut gs);

    let session = start_session(&mut tpm, &mut gs, TpmSe::Policy);
    policy_pcr(&mut tpm, &mut gs, session, &pcr_digest);

    sign_with_policy_session(&mut tpm, &mut gs, key, session)
        .expect("Sign with an unchanged pcrUpdateCounter must succeed");
}
