//! Policy session tests.
//!
//! These focus on the global state of a policy session,
//! rather than on what individual assertions check.
//!
//! Unlike the other suites, only the tests of what a policy session adds to
//! nonce handling (policy commands, and failed use) assert whether the nonce
//! rolled; the basic tests cover the rest. These also assert
//! `TPM2_PolicyAuthValue`: otherwise, an unbound, unsalted policy session's
//! HMAC is empty, so command success doesn't prove that the TPM's nonce is the
//! one we expect.

use std::thread::sleep;
use std::time::Duration;

use tpm2::commands::{
    ContextLoad, ContextSave, NVChangeAuth, NVDefineSpace, NVRead, NVUndefineSpace, PCRExtend,
    PCRRead, PolicyAuthValue, PolicyCommandCode, PolicyGetDigest, PolicyPCR, PolicySecret,
    Shutdown, StartAuthSession, Startup,
};
use tpm2::crypto::hash;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_client::ClientError::Tpm;
use tpm2_client::connection::tcp::{SimulatorPlatformSignal, TcpSimulator};
use tpm2_client::sessions::{AuthorizationArea, PasswordSession, PolicyDigest, PolicySession};
use tpm2_client::{CryptoBackend, nv_name, run_command, run_command_with_sessions};

use crate::{ALG, DIGEST_SIZE, NV_DATA_SIZE, NV_INDEX, RESP_BUFFER_SIZE, get_lockout_counter, nonce_unchanged, nv_public, read_nv_index, start, start_hmac_session, stop, tpm_result, write_nv_index};

/// PCR 16 (debug) is resettable, extendable at locality 0, and changes to it
/// increment the TPM's PCR update counter.
const PCR: Handle = Handle(16);

//
// Helpers.
//

/// Starts an unbound, unsalted SHA-256 policy session, and checks that its
/// policyDigest starts as a Zero Digest.
fn start_policy_session(simulator: &mut TcpSimulator) -> PolicySession {
    try_start_policy_session(simulator, ALG).unwrap()
}

/// Starts an unbound, unsalted policy session using `alg`, and checks that its
/// policyDigest starts as a Zero Digest. Returns the response code if the TPM
/// rejects it, e.g. because it doesn't implement `alg`.
fn try_start_policy_session(simulator: &mut TcpSimulator, alg: TpmiAlgHash) -> Result<PolicySession, TpmRc> {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    let start_auth_session = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[42u8; TpmiAlgHash::MAX_DIGEST_BYTES][..alg.digest_size()]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: alg,
    };
    let start_auth_session_rsp = match run_command(&start_auth_session, simulator.connection_mut(), resp_buffer) {
        Ok(rsp) => rsp,
        Err(Tpm(rc)) => return Err(rc),
        Err(e) => panic!("unexpected error: {e:?}"),
    };

    let session = PolicySession::new(start_auth_session_rsp.session_handle, start_auth_session.auth_hash, start_auth_session.nonce_caller, start_auth_session_rsp.nonce_tpm);

    assert_eq!(session.policy().digest().as_slice(), &[0u8; TpmiAlgHash::MAX_DIGEST_BYTES][..alg.digest_size()]);
    assert_policy_digest(simulator, &session);

    Ok(session)
}

/// Asserts that the TPM's policyDigest (`TPM2_PolicyGetDigest`) is the one
/// that we computed.
fn assert_policy_digest(simulator: &mut TcpSimulator, session: &PolicySession) {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    let policy_get_digest = PolicyGetDigest {
        policy_session: session.handle(),
    };
    let policy_get_digest_rsp = run_command(&policy_get_digest, simulator.connection_mut(), resp_buffer).unwrap();
    assert_eq!(policy_get_digest_rsp.policy_digest, session.policy().digest());
}

/// Runs a policy command (with `cmd_sessions` for its authorizations, if
/// any) on `session`. On success, `update` mirrors the command in `session`.
/// Either way, this checks that the TPM's policyDigest is the one that we
/// computed (so a failed assertion doesn't change it).
///
/// Policy commands take the policy session as a handle, rather than as an
/// authorization, so they don't update its nonce (see
/// `policy_construction_and_usage()`).
fn run_policy_command<C: Command<MaxBuffer = [u8; N]>, const N: usize>(
    simulator: &mut TcpSimulator,
    cmd: &C,
    cmd_sessions: &mut impl AuthorizationArea,
    session: &mut PolicySession,
    update: impl FnOnce(&mut PolicySession),
) -> Result<(), TpmRc> {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    let rsp = tpm_result(run_command_with_sessions(cmd, &[], cmd_sessions, simulator.connection_mut(), resp_buffer));
    if rsp.is_ok() {
        update(session);
    }
    assert_policy_digest(simulator, session);

    rsp
}

/// Defines and writes `nv_public` using OWNER authorization (so it must have
/// `TPMA_NV_OWNERWRITE`), rather than with the session under test.
fn define_and_write_nv_index(simulator: &mut TcpSimulator, nv_public: &mut TpmsNvPublic) {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    // The owner's authValue is empty.
    let mut owner = PasswordSession::default();

    // To make this test idempotent, undefine the space, but ignore the return value.
    let nv_undefine_space = NVUndefineSpace {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_public.nv_index,
    };
    let _ = run_command_with_sessions(&nv_undefine_space, &[], &mut owner, simulator.connection_mut(), resp_buffer);

    let nv_define_space = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info: Tpm2b(*nv_public),
    };
    assert!(run_command_with_sessions(&nv_define_space, &[], &mut owner, simulator.connection_mut(), resp_buffer).is_ok());

    assert!(write_nv_index(simulator, nv_public, Handle::RH_OWNER, &mut owner).is_ok());
}

/// Runs `TPM2_PolicyCommandCode`.
fn policy_command_code(simulator: &mut TcpSimulator, session: &mut PolicySession, code: TpmCc) -> Result<(), TpmRc> {
    let policy_command_code = PolicyCommandCode {
        policy_session: session.handle(),
        code,
    };
    run_policy_command(simulator, &policy_command_code, &mut (), session, |s| s.policy_mut().policy_command_code(code).unwrap())
}

/// Runs `TPM2_PolicyAuthValue`, for an entity whose authValue is empty.
fn policy_auth_value(simulator: &mut TcpSimulator, session: &mut PolicySession) -> Result<(), TpmRc> {
    let policy_auth_value = PolicyAuthValue {
        policy_session: session.handle(),
    };
    run_policy_command(simulator, &policy_auth_value, &mut (), session, |s| s.policy_auth_value(Tpm2bAuth::default()).unwrap())
}

/// Runs `TPM2_PolicyPCR` on `pcr`, which is expected to have `pcr_digest`
/// (see `read_pcr_digest()`).
fn policy_pcr(simulator: &mut TcpSimulator, session: &mut PolicySession, pcr: Handle, pcr_digest: &[u8; DIGEST_SIZE]) -> Result<(), TpmRc> {
    let policy_pcr = PolicyPCR {
        policy_session: session.handle(),
        pcr_digest: Tpm2bDigest::new(pcr_digest).unwrap(),
        pcrs: pcr_selection(pcr),
    };
    run_policy_command(simulator, &policy_pcr, &mut (), session, |s| {
        s.policy_mut()
            .policy_pcr(Tpm2bDigest::new(pcr_digest).unwrap(), &pcr_selection(pcr))
            .unwrap()
    })
}

/// Runs `TPM2_PolicySecret` with the owner (whose authValue is empty) as
/// `authHandle`, and the session's current `nonceTPM` (so `expiration` is
/// relative to the session's startTime).
fn policy_secret(simulator: &mut TcpSimulator, session: &mut PolicySession, expiration: i32) -> Result<(), TpmRc> {
    let mut nonce_tpm = [0u8; DIGEST_SIZE];
    nonce_tpm.copy_from_slice(session.nonce_tpm().as_slice());

    let policy_secret = PolicySecret {
        auth_handle: Handle::RH_OWNER,
        policy_session: session.handle(),
        nonce_tpm: Tpm2bNonce::new(&nonce_tpm).unwrap(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration,
    };
    run_policy_command(simulator, &policy_secret, &mut PasswordSession::default(), session, |s| {
        // The owner's Name is its handle.
        let owner_name = Handle::RH_OWNER.0.to_be_bytes();
        s.policy_mut()
            .policy_secret(Tpm2bName::new(&owner_name).unwrap(), Tpm2bNonce::default())
            .unwrap();
    })
}

/// Returns the policyDigest of a policy consisting only of `assertions`
/// `TPM2_PolicySecret` assertions with the owner as `authHandle`.
fn owner_policy_secret_digest(assertions: usize) -> PolicyDigest {
    let mut policy = PolicyDigest::new(ALG);
    let owner_name = Handle::RH_OWNER.0.to_be_bytes();
    for _ in 0..assertions {
        policy
            .policy_secret(Tpm2bName::new(&owner_name).unwrap(), Tpm2bNonce::default())
            .unwrap();
    }
    policy
}

/// Selects `pcr` in the SHA-256 bank.
fn pcr_selection(pcr: Handle) -> TpmlPcrSelection {
    let mut select = [0u8; TpmsPcrSelect::MIN];
    select[pcr.0 as usize / 8] = 1 << (pcr.0 % 8);
    TpmlPcrSelection::new(&[TpmsPcrSelection {
        hash: ALG,
        selection: TpmsPcrSelect::new(&select).unwrap(),
    }])
    .unwrap()
}

/// Reads `pcr`, and returns the digest of the selected PCR values that
/// `TPM2_PolicyPCR` checks: `H(PCR[pcr])`.
fn read_pcr_digest(simulator: &mut TcpSimulator, pcr: Handle) -> [u8; DIGEST_SIZE] {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    let pcr_read = PCRRead {
        pcr_selection_in: pcr_selection(pcr),
    };
    let pcr_read_rsp = run_command(&pcr_read, simulator.connection_mut(), resp_buffer).unwrap();
    assert_eq!(pcr_read_rsp.pcr_selection_out, pcr_selection(pcr));

    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let pcr_value = pcr_read_rsp.pcr_values.as_slice()[0];
    let pcr_digest = hash::<CryptoBackend>(ALG, &[pcr_value.as_slice()], &mut out).unwrap();
    pcr_digest.digest().try_into().unwrap()
}

/// Extends `pcr`, authorizing it with `session`.
fn extend_pcr(simulator: &mut TcpSimulator, pcr: Handle, session: &mut impl AuthorizationArea) -> Result<(), TpmRc> {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    let pcr_extend = PCRExtend {
        pcr_handle: pcr,
        digests: TpmlDigestValues::new(&[TpmtHa::Sha256(&[42u8; DIGEST_SIZE])]).unwrap(),
    };
    tpm_result(run_command_with_sessions(&pcr_extend, &[], session, simulator.connection_mut(), resp_buffer))
}

/// Like `read_nv_index()` (on the index itself), but retries once on
/// `TPM_RC_RETRY`: unlike OWNER authorization, which is exempt from DA,
/// using the index's authValue might need to wait for DA's startup.
fn read_nv_index_retrying(simulator: &mut TcpSimulator, nv_public: &TpmsNvPublic, session: &mut impl AuthorizationArea) -> Result<(), TpmRc> {
    let nv_read_rsp = read_nv_index(simulator, nv_public, NV_INDEX, session);
    if nv_read_rsp == Err(TpmRc::RETRY) {
        return read_nv_index(simulator, nv_public, NV_INDEX, session);
    }
    nv_read_rsp
}

/// Changes the authValue of `nv_public` (`TPM2_NV_ChangeAuth`), authorizing
/// its ADMIN role with `session`.
fn change_nv_auth(simulator: &mut TcpSimulator, nv_public: &TpmsNvPublic, session: &mut impl AuthorizationArea) -> Result<(), TpmRc> {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let mut name_buf = [0u8; Tpm2bName::CAP];
    let name = nv_name::<CryptoBackend>(nv_public, &mut name_buf).unwrap();

    let nv_change_auth = NVChangeAuth {
        nv_index: nv_public.nv_index,
        new_auth: Tpm2bAuth::new(&[42u8; DIGEST_SIZE]).unwrap(),
    };
    tpm_result(run_command_with_sessions(&nv_change_auth, &[Some(name)], session, simulator.connection_mut(), resp_buffer))
}

//
// Tests.
//

/// Policy commands take a policy session's handle and update its policyDigest,
/// but they're sent without sessions and don't roll the nonces.
/// `run_policy_command()` checks the policyDigest after every policy command.
/// Send two commands to prove via induction that it's changing appropriately.
///
/// Then, using the policy session resets its context (Part 1, "Policy
/// Session Context Values"). This checks the policyDigest and commandCode.
fn policy_construction_and_usage() {
    let mut simulator = start("policy_construction_and_usage()");
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    auth_policy.policy_command_code(TpmCc::NVRead).unwrap();
    auth_policy.policy_auth_value().unwrap();
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    // This checks that policyDigest begins as a Zero Digest.
    let mut session = start_policy_session(&mut simulator);
    // Test that the nonce rolls.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVRead).is_ok());
    // This command takes the session as a handle, rather than as an authorization.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);

    // The index's authValue is empty.
    assert!(policy_auth_value(&mut simulator, &mut session).is_ok());
    // This command takes the session as a handle, rather than as an authorization.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);

    // After `TPM2_PolicyAuthValue`, the HMAC is checked, so this also proves
    // that the policy commands didn't roll the TPM's nonce.
    assert!(read_nv_index_retrying(&mut simulator, &nv_public, &mut session).is_ok());
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    // policyDigest was reset to a Zero Digest.
    assert_eq!(session.policy().digest().as_slice(), [0u8; DIGEST_SIZE]);
    assert_policy_digest(&mut simulator, &session);

    // commandCode was reset: otherwise, a different command code would be
    // incompatible with it (TPM_RC_VALUE).
    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVWrite).is_ok());

    assert!(stop(simulator, session.handle()).is_ok());
}

/// A policyDigest that doesn't match the entity's authPolicy fails the
/// authorization. The session keeps its policy (and its nonce), so an
/// incomplete policy can then be completed.
fn valid_and_invalid_policy() {
    let mut simulator = start("valid_and_invalid_policy()");
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    auth_policy.policy_auth_value().unwrap();
    auth_policy.policy_command_code(TpmCc::NVRead).unwrap();
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);
    // Test that the nonce rolls.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    // The policy is missing its last assertion.
    assert!(policy_auth_value(&mut simulator, &mut session).is_ok());

    assert_eq!(
        read_nv_index_retrying(&mut simulator, &nv_public, &mut session),
        Err(TpmRc::POLICY_FAIL.with(Position::session(1)))
    );
    // Failure doesn't update the nonce, nor reset the policy.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);
    assert_policy_digest(&mut simulator, &session);

    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVRead).is_ok());

    // After `TPM2_PolicyAuthValue`, the HMAC is checked, so this also proves
    // that the failure didn't roll the TPM's nonce.
    assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    assert!(stop(simulator, session.handle()).is_ok());
}

/// A command that fails after its authorization succeeded doesn't reset the
/// policy session (or roll its nonce), so the session can still be used.
/// `valid_and_invalid_policy()` covers a failed authorization.
fn failed_use_keeps_policy() {
    let mut simulator = start("failed_use_keeps_policy()");
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    auth_policy.policy_command_code(TpmCc::NVRead).unwrap();
    auth_policy.policy_auth_value().unwrap();
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);
    // Test that the nonce rolls.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVRead).is_ok());
    // The index's authValue is empty.
    assert!(policy_auth_value(&mut simulator, &mut session).is_ok());

    // Authorization succeeds, but the read is out of range.
    let mut name_buf = [0u8; Tpm2bName::CAP];
    let name = nv_name::<CryptoBackend>(&nv_public, &mut name_buf).unwrap();
    let nv_read = NVRead {
        auth_handle: NV_INDEX,
        nv_index: NV_INDEX,
        size: NV_DATA_SIZE,
        offset: NV_DATA_SIZE / 2,
    };
    // Unlike OWNER authorisation, which is exempt from DA, this might need to wait for its startup.
    let mut nv_read_rsp = tpm_result(run_command_with_sessions(&nv_read, &[Some(name), Some(name)], &mut session, simulator.connection_mut(), resp_buffer));
    if nv_read_rsp == Err(TpmRc::RETRY) {
        nv_read_rsp = tpm_result(run_command_with_sessions(&nv_read, &[Some(name), Some(name)], &mut session, simulator.connection_mut(), resp_buffer));
    }
    assert_eq!(nv_read_rsp, Err(TpmRc::NV_RANGE));
    // Failure doesn't update the nonce, nor reset the policy.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);
    assert_policy_digest(&mut simulator, &session);

    // So fixing the mistake succeeds. After `TPM2_PolicyAuthValue`, the HMAC
    // is checked, so this also proves that the failure didn't roll the TPM's
    // nonce.
    assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    assert!(stop(simulator, session.handle()).is_ok());
}

/// Repeating `TPM2_PolicyCommandCode` with the same command code is
/// compatible, and extends the policyDigest again. A different command code
/// is incompatible, and fails without changing the policyDigest. The session
/// can then be used for the first command code.
fn repeated_command_code() {
    let mut simulator = start("repeated_command_code()");

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    auth_policy.policy_command_code(TpmCc::NVRead).unwrap();
    auth_policy.policy_command_code(TpmCc::NVRead).unwrap(); // Compatible repeated assertion.
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);

    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVRead).is_ok());
    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVRead).is_ok());

    assert_eq!(
        policy_command_code(&mut simulator, &mut session, TpmCc::NVWrite),
        Err(TpmRc::VALUE.with(Position::parameter(1)))
    );

    assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());

    assert!(stop(simulator, session.handle()).is_ok());
}

//
// Extended tests.
//

/// Making access to an NV index depend on PCR values means giving it a
/// PolicyPCR authPolicy, and not allowing authValue authorization (here, no
/// `TPMA_NV_AUTHREAD`). Then an HMAC session can't be used to read it, but a
/// policy session can.
fn pcr_requires_policy(use_policy_session: bool) {
    let mut simulator = start(&format!("pcr_requires_policy(use_policy_session: {use_policy_session})"));

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    let pcr_digest = read_pcr_digest(&mut simulator, PCR);
    auth_policy
        .policy_pcr(Tpm2bDigest::new(&pcr_digest).unwrap(), &pcr_selection(PCR))
        .unwrap();
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let session_handle = if use_policy_session {
        let mut session = start_policy_session(&mut simulator);

        assert!(policy_pcr(&mut simulator, &mut session, PCR, &pcr_digest).is_ok());

        assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());

        session.handle()
    } else {
        let mut session = start_hmac_session(&mut simulator);

        assert_eq!(read_nv_index_retrying(&mut simulator, &nv_public, &mut session), Err(TpmRc::AUTH_UNAVAILABLE));

        session.handle()
    };

    assert!(stop(simulator, session_handle).is_ok());
}

/// The ADMIN role of an NV index requires a policy session, so an HMAC session
/// fails with `TPM_RC_AUTH_TYPE`, even though the index's authValue is
/// available. Its USER role can still use the HMAC session.
fn admin_role_requires_policy_session() {
    let mut simulator = start("admin_role_requires_policy_session()");

    let mut session = start_hmac_session(&mut simulator);

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    auth_policy.policy_command_code(TpmCc::NVChangeAuth).unwrap();
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    // Unlike OWNER authorisation, which is exempt from DA, this might need to wait for its startup.
    let mut nv_change_auth_rsp = change_nv_auth(&mut simulator, &nv_public, &mut session);
    if nv_change_auth_rsp == Err(TpmRc::RETRY) {
        nv_change_auth_rsp = change_nv_auth(&mut simulator, &nv_public, &mut session);
    }
    assert_eq!(nv_change_auth_rsp, Err(TpmRc::AUTH_TYPE));

    // The index's authValue is empty.
    assert!(read_nv_index_retrying(&mut simulator, &nv_public, &mut session).is_ok());

    assert!(stop(simulator, session.handle()).is_ok());
}

/// The ADMIN role can only be granted for a specific command, so a policy
/// session for it must have a commandCode, even if its policyDigest matches.
/// Here, without `TPM2_PolicyCommandCode`, the authPolicy is a Zero Digest,
/// which a new policy session matches.
///
/// The index has neither `TPMA_NV_POLICYREAD` nor `TPMA_NV_POLICYWRITE`: as a
/// policy session is required for the ADMIN role, its authPolicy is available
/// regardless.
fn admin_role_requires_command_code(set: bool) {
    let mut simulator = start(&format!("admin_role_requires_command_code(set: {set})"));

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    if set {
        auth_policy.policy_command_code(TpmCc::NVChangeAuth).unwrap();
    }
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);

    if set {
        assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVChangeAuth).is_ok());
    }
    assert_eq!(session.policy().digest(), auth_policy.digest());

    let nv_change_auth_rsp = change_nv_auth(&mut simulator, &nv_public, &mut session);
    if set {
        assert!(nv_change_auth_rsp.is_ok());
    } else {
        assert_eq!(nv_change_auth_rsp, Err(TpmRc::POLICY_FAIL.with(Position::session(1))));
    }

    assert!(stop(simulator, session.handle()).is_ok());
}

/// An NV index's authPolicy is unavailable to a policy session if it's empty,
/// or if the index doesn't allow policy authorization for the operation (here,
/// reading without `TPMA_NV_POLICYREAD`), even if the policyDigest matches.
fn nv_auth_policy_unavailable(empty_policy: bool) {
    let mut simulator = start(&format!("nv_auth_policy_unavailable(empty_policy: {empty_policy})"));

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    auth_policy.policy_command_code(TpmCc::NVRead).unwrap();
    let mut nv_public = if empty_policy {
        nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, Tpm2bDigest::default())
    } else {
        nv_public(TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD, auth_policy.digest())
    };
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);

    // No policyDigest can match an empty authPolicy, but this is checked first.
    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVRead).is_ok());

    assert_eq!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session), Err(TpmRc::AUTH_UNAVAILABLE));

    assert!(stop(simulator, session.handle()).is_ok());
}

/// The policyDigest must match the authPolicy's algorithm, as well as its
/// value. A new policy session's policyDigest is a Zero Digest, so an
/// authPolicy that is a Zero Digest of the same size matches it, but a
/// comparison of only the shorter digest's length would accept other sizes
/// too. A different algorithm of the same size can only be told apart by the
/// algorithm. If the TPM doesn't implement `session_alg`, this is skipped.
fn policy_digest_algorithm(index_alg: TpmiAlgHash, session_alg: TpmiAlgHash) {
    let mut simulator = start(&format!("policy_digest_algorithm(index_alg: {index_alg:?}, session_alg: {session_alg:?})"));

    let zero_digest = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let mut nv_public = TpmsNvPublic {
        name_alg: index_alg,
        ..nv_public(
            TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD,
            Tpm2bDigest::new(&zero_digest[..index_alg.digest_size()]).unwrap(),
        )
    };
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = match try_start_policy_session(&mut simulator, session_alg) {
        Ok(session) => session,
        Err(rc) if rc.to_fmt1().is_some_and(|(fmt1, _)| fmt1 == TpmRc::HASH) => {
            println!("Skipped: the TPM doesn't implement {session_alg:?}.");
            assert!(simulator.stop_nicely().is_ok());
            return;
        }
        Err(rc) => panic!("unexpected error: {rc:?}"),
    };

    let nv_read_rsp = read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session);
    if index_alg == session_alg {
        assert!(nv_read_rsp.is_ok());
    } else {
        assert_eq!(nv_read_rsp, Err(TpmRc::POLICY_FAIL.with(Position::session(1))));
    }

    assert!(stop(simulator, session.handle()).is_ok());
}

/// `TPM2_PolicyPCR` checks the PCR values when it's run, and records the TPM's
/// PCR update counter, which is checked when the session is used. So a PCR
/// change before `TPM2_PolicyPCR` (even after the session started) doesn't
/// fail the session, but one after it does, even though the policyDigest
/// still matches.
fn pcr_changed(after_policy_pcr: bool) {
    let mut simulator = start(&format!("pcr_changed(after_policy_pcr: {after_policy_pcr})"));

    let mut session = start_policy_session(&mut simulator);

    if !after_policy_pcr {
        // The PCR's authValue is empty.
        assert!(extend_pcr(&mut simulator, PCR, &mut PasswordSession::default()).is_ok());
    }

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    let pcr_digest = read_pcr_digest(&mut simulator, PCR);
    auth_policy
        .policy_pcr(Tpm2bDigest::new(&pcr_digest).unwrap(), &pcr_selection(PCR))
        .unwrap();
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    assert!(policy_pcr(&mut simulator, &mut session, PCR, &pcr_digest).is_ok());

    if after_policy_pcr {
        // The PCR's authValue is empty.
        assert!(extend_pcr(&mut simulator, PCR, &mut PasswordSession::default()).is_ok());
    }

    let nv_read_rsp = read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session);
    if after_policy_pcr {
        assert_eq!(nv_read_rsp, Err(TpmRc::PCR_CHANGED));
    } else {
        assert!(nv_read_rsp.is_ok());
    }

    assert!(stop(simulator, session.handle()).is_ok());
}

/// What passes a session's timeout.
#[derive(Debug)]
enum TimeoutEvent {
    /// Waiting until after it.
    Wait,
    /// A power cycle, which restarts the TPM's timer. The session must be
    /// saved to survive it.
    PowerCycle,
    /// The TPM's timer stopping while power is still applied. No command
    /// does this, so the simulator is signalled.
    TimerStopped,
}

/// An assertion with an expiration sets the session's timeout, which a later
/// assertion can shorten, but not extend. After it, the session can't be
/// used. A timeout is a time since the TPM's timer started, so it's only
/// valid in the timer's epoch: when the timer restarts, the session has
/// expired, even if its timeout seems to be in the future.
///
/// The failed use doesn't reset the session's startTime and epoch, so a new
/// expiration (relative to them) has already passed too.
fn timeout_expires(after: TimeoutEvent) {
    let mut simulator = start(&format!("timeout_expires(after: {after:?})"));
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    let auth_policy = owner_policy_secret_digest(2);
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);

    // Expires 1 second after the session's startTime. For a new epoch, the
    // timeout is long after the test ends, so only the epoch can expire it.
    let expiration = if matches!(after, TimeoutEvent::Wait) { 1 } else { 100 };
    assert!(policy_secret(&mut simulator, &mut session, expiration).is_ok());
    // A longer expiration doesn't extend the timeout.
    assert!(policy_secret(&mut simulator, &mut session, 1000).is_ok());

    match after {
        TimeoutEvent::Wait => sleep(Duration::from_secs(2)),
        TimeoutEvent::PowerCycle => {
            let context_save = ContextSave {
                save_handle: session.handle(),
            };
            let context_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
            let context_save_rsp = run_command(&context_save, simulator.connection_mut(), context_buffer).unwrap();

            let shutdown = Shutdown {
                shutdown_type: TpmSu::State,
            };
            assert!(run_command(&shutdown, simulator.connection_mut(), resp_buffer).is_ok());

            assert!(simulator.connection_mut().reinit().is_ok());

            let startup = Startup {
                startup_type: TpmSu::State,
            };
            assert!(run_command(&startup, simulator.connection_mut(), resp_buffer).is_ok());

            let context_load = ContextLoad {
                context: context_save_rsp.context,
            };
            assert!(run_command(&context_load, simulator.connection_mut(), resp_buffer).is_ok());
        }
        TimeoutEvent::TimerStopped => {
            assert!(simulator.connection_mut().platform_signal(SimulatorPlatformSignal::Restart).is_ok());
        }
    }

    assert_eq!(
        read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session),
        Err(TpmRc::EXPIRED.with(Position::session(1)))
    );

    // Expires 1 second after the session's startTime: that's 2 seconds ago,
    // or in the old epoch.
    assert_eq!(
        policy_secret(&mut simulator, &mut session, 1),
        Err(TpmRc::EXPIRED.with(Position::parameter(4)))
    );

    assert!(stop(simulator, session.handle()).is_ok());
}

/// Using the session resets its timeout, so it can be used again after the
/// old timeout, or in a new epoch. It also resets the session's startTime and
/// epoch, so the next expiration is relative to that use.
fn use_resets_timeout() {
    let mut simulator = start("use_resets_timeout()");

    let auth_policy = owner_policy_secret_digest(1);
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);

    // Expires 1 second after the session's startTime.
    assert!(policy_secret(&mut simulator, &mut session, 1).is_ok());
    assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());

    // Pass the old timeout, and start a new epoch.
    sleep(Duration::from_secs(2));
    assert!(simulator.connection_mut().platform_signal(SimulatorPlatformSignal::Restart).is_ok());

    // Without an expiration, so that this only depends on the old timeout
    // having been reset. Without a timeout, the epoch isn't checked.
    assert!(policy_secret(&mut simulator, &mut session, 0).is_ok());
    assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());

    // Expires 1 second after the session's startTime: unless the last use
    // reset it, that's 2 seconds ago, in the old epoch.
    assert!(policy_secret(&mut simulator, &mut session, 1).is_ok());
    assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());

    assert!(stop(simulator, session.handle()).is_ok());
}

/// A policyDigest that doesn't match the entity's authPolicy isn't a DA
/// failure: unlike a wrong authValue, it doesn't increment failedTries, even
/// after `TPM2_PolicyAuthValue` makes the session DA-protected.
///
/// TODO: Consider this some more. It's a single failed command, about DA
/// rather than the session's state, so it might belong with the auth tests.
fn policy_failure_is_not_da_failure() {
    let mut simulator = start("policy_failure_is_not_da_failure()");

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    auth_policy.policy_auth_value().unwrap();
    auth_policy.policy_command_code(TpmCc::NVRead).unwrap();
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);

    // The policy is missing its last assertion.
    assert!(policy_auth_value(&mut simulator, &mut session).is_ok());

    let failed_tries = get_lockout_counter(&mut simulator);
    assert_eq!(
        read_nv_index_retrying(&mut simulator, &nv_public, &mut session),
        Err(TpmRc::POLICY_FAIL.with(Position::session(1)))
    );
    assert_eq!(get_lockout_counter(&mut simulator), failed_tries);

    assert!(stop(simulator, session.handle()).is_ok());
}

//
// Driver.
//
pub fn run() {
    // TODO: Do a deep review.
    policy_construction_and_usage();

    valid_and_invalid_policy();
    failed_use_keeps_policy();
    // TODO: Test that `TPM2_PolicyRestart` resets the policy, but not startTime.

    // TODO: Test a key conflict.
    repeated_command_code();

    pcr_requires_policy(true);
    pcr_requires_policy(false);

    admin_role_requires_policy_session();
    // TODO: Test that a session for one command can't be used for another (`TPM_RC_POLICY_CC`).
    admin_role_requires_command_code(false);
    admin_role_requires_command_code(true);

    nv_auth_policy_unavailable(true);
    nv_auth_policy_unavailable(false);

    policy_digest_algorithm(TpmiAlgHash::Sha256, TpmiAlgHash::Sha256);
    policy_digest_algorithm(TpmiAlgHash::Sha256, TpmiAlgHash::Sha1);
    policy_digest_algorithm(TpmiAlgHash::Sha1, TpmiAlgHash::Sha256);
    policy_digest_algorithm(TpmiAlgHash::Sha256, TpmiAlgHash::Sha3_256);

    // TODO: Test PCRs that don't increment the PCR update counter.
    pcr_changed(false);
    pcr_changed(true);

    timeout_expires(TimeoutEvent::Wait);
    timeout_expires(TimeoutEvent::PowerCycle);
    timeout_expires(TimeoutEvent::TimerStopped);
    use_resets_timeout();

    // TODO: Consider whether this belongs here.
    policy_failure_is_not_da_failure();

    println!("TODO: Continue on policies.");
}
