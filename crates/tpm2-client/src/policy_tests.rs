//! Policy session tests.
//!
//! These focus on the global state of a policy session,
//! rather than on what individual assertions check.

use std::thread::sleep;
use std::time::Duration;

use tpm2::commands::{
    NVDefineSpace, NVRead, NVUndefineSpace, PCRExtend, PCRRead, PolicyAuthValue,
    PolicyCommandCode, PolicyGetDigest, PolicyPCR, PolicySecret, StartAuthSession,
};
use tpm2::crypto::hash;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_client::connection::tcp::TcpSimulator;
use tpm2_client::sessions::{AuthorizationArea, PasswordSession, PolicyDigest, PolicySession};
use tpm2_client::{CryptoBackend, nv_name, run_command, run_command_with_sessions};

use crate::{ALG, DIGEST_SIZE, NV_DATA_SIZE, NV_INDEX, RESP_BUFFER_SIZE, nonce_unchanged, nv_public, read_nv_index, start, start_hmac_session, stop, tpm_result, write_nv_index};

/// PCR 16 (debug) is resettable, extendable at locality 0, and (unlike PCR
/// 20-22 on the simulator) changes increment the TPM's PCR update counter.
const PCR: Handle = Handle(16);

//
// Helpers.
//

/// Starts an unbound, unsalted SHA-256 policy session, and checks that its
/// policyDigest starts as a Zero Digest.
fn start_policy_session(simulator: &mut TcpSimulator) -> PolicySession {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    let start_auth_session = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[42u8; DIGEST_SIZE]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: ALG,
    };
    let start_auth_session_rsp = run_command(&start_auth_session, simulator.connection_mut(), resp_buffer).unwrap();
    println!("{:?}", start_auth_session_rsp);

    let session: PolicySession = PolicySession::new(start_auth_session_rsp.session_handle, start_auth_session.auth_hash, start_auth_session.nonce_caller, start_auth_session_rsp.nonce_tpm);

    assert_eq!(session.policy().digest().as_slice(), [0u8; DIGEST_SIZE]);
    assert_policy_digest(simulator, &session);

    session
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
/// authorization, so they don't update its nonce. This isn't asserted.
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

/// Runs `TPM2_PolicyPCR` on `PCR`, which is expected to have `pcr_digest`
/// (see `read_pcr_digest()`).
fn policy_pcr(simulator: &mut TcpSimulator, session: &mut PolicySession, pcr_digest: &[u8; DIGEST_SIZE]) -> Result<(), TpmRc> {
    let policy_pcr = PolicyPCR {
        policy_session: session.handle(),
        pcr_digest: Tpm2bDigest::new(pcr_digest).unwrap(),
        pcrs: pcr_selection(),
    };
    run_policy_command(simulator, &policy_pcr, &mut (), session, |s| {
        s.policy_mut()
            .policy_pcr(Tpm2bDigest::new(pcr_digest).unwrap(), &pcr_selection())
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

/// Returns the policyDigest of a policy consisting only of
/// `TPM2_PolicySecret` with the owner as `authHandle`.
fn owner_policy_secret_digest() -> PolicyDigest {
    let mut policy: PolicyDigest = PolicyDigest::new(ALG);
    let owner_name = Handle::RH_OWNER.0.to_be_bytes();
    policy
        .policy_secret(Tpm2bName::new(&owner_name).unwrap(), Tpm2bNonce::default())
        .unwrap();
    policy
}

/// Selects `PCR` in the SHA-256 bank.
fn pcr_selection() -> TpmlPcrSelection {
    let mut select = [0u8; TpmsPcrSelect::MIN];
    select[PCR.0 as usize / 8] = 1 << (PCR.0 % 8);
    TpmlPcrSelection::new(&[TpmsPcrSelection {
        hash: ALG,
        selection: TpmsPcrSelect::new(&select).unwrap(),
    }])
    .unwrap()
}

/// Reads `PCR`, and returns the digest of the selected PCR values that
/// `TPM2_PolicyPCR` checks: `H(PCR[16])`.
fn read_pcr_digest(simulator: &mut TcpSimulator) -> [u8; DIGEST_SIZE] {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    let pcr_read = PCRRead {
        pcr_selection_in: pcr_selection(),
    };
    let pcr_read_rsp = run_command(&pcr_read, simulator.connection_mut(), resp_buffer).unwrap();
    assert_eq!(pcr_read_rsp.pcr_selection_out, pcr_selection());

    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let pcr_value = pcr_read_rsp.pcr_values.as_slice()[0];
    let pcr_digest = hash::<CryptoBackend>(ALG, &[pcr_value.as_slice()], &mut out).unwrap();
    pcr_digest.digest().try_into().unwrap()
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

    let mut session = start_policy_session(&mut simulator);
    // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    // policyDigest begins as a Zero Digest.
    assert_eq!(session.policy().digest().as_slice(), [0u8; DIGEST_SIZE]);
    assert_policy_digest(&mut simulator, &session);

    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVRead).is_ok());
    assert_ne!(session.policy().digest().as_slice(), [0u8; DIGEST_SIZE]);
    assert_policy_digest(&mut simulator, &session);

    // The index's authValue is empty.
    let policy_auth_value = PolicyAuthValue {
        policy_session: session.handle(),
    };
    assert!(run_policy_command(&mut simulator, &policy_auth_value, &mut (), &mut session, |s| s.policy_auth_value(Tpm2bAuth::default()).unwrap()).is_ok());
    assert_policy_digest(&mut simulator, &session);

    let mut nv_read_rsp = read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session);
    if nv_read_rsp == Err(TpmRc::RETRY) {
        nv_read_rsp = read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session);
    }
    assert!(nv_read_rsp.is_ok());
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    // policyDigest was reset to a Zero Digest.
    assert_eq!(session.policy().digest().as_slice(), [0u8; DIGEST_SIZE]);
    assert_policy_digest(&mut simulator, &session);

    // commandCode was reset: otherwise, a different command code would be
    // incompatible with it (TPM_RC_VALUE).
    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVWrite).is_ok());

    assert!(stop(simulator, session.handle()).is_ok());
}

/// Repeating `TPM2_PolicyCommandCode` with the same command code is
/// compatible, and extends the policyDigest again. A different command code
/// is incompatible, and fails without changing the policyDigest. Either way,
/// the session can then be used for the first command code.
fn repeated_command_code() {
    let mut simulator = start("repeated_command_code()");
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    auth_policy.policy_command_code(TpmCc::NVRead).unwrap();
    auth_policy.policy_command_code(TpmCc::NVRead).unwrap(); // Compatible repeated assertion.
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);
    // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVRead).is_ok());
    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVRead).is_ok());

    assert_eq!(
        policy_command_code(&mut simulator, &mut session, TpmCc::NVWrite),
        Err(TpmRc::VALUE.with(Position::parameter(1)))
    );

    assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    assert!(stop(simulator, session.handle()).is_ok());
}

/// Making access to an NV index depend on PCR values means giving it a
/// PolicyPCR authPolicy, and not allowing authValue authorization (here, no
/// `TPMA_NV_AUTHREAD`). Then an HMAC session can't be used to read it, but a
/// policy session can.
fn pcr_requires_policy(use_policy_session: bool) {
    let mut simulator = start(&format!("pcr_requires_policy(use_policy_session: {use_policy_session})"));
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    let pcr_digest = read_pcr_digest(&mut simulator);
    auth_policy
        .policy_pcr(Tpm2bDigest::new(&pcr_digest).unwrap(), &pcr_selection())
        .unwrap();
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let session_handle = if use_policy_session {
        let mut session = start_policy_session(&mut simulator);
        // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

        assert!(policy_pcr(&mut simulator, &mut session, &pcr_digest).is_ok());

        assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

        session.handle()
    } else {
        let mut session = start_hmac_session(&mut simulator);
        // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

        // Unlike OWNER authorisation, which is exempt from DA, this might need to wait for its startup.
        let mut nv_read_rsp = read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session);
        if nv_read_rsp == Err(TpmRc::RETRY) {
            nv_read_rsp = read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session);
        }
        assert_eq!(nv_read_rsp, Err(TpmRc::AUTH_UNAVAILABLE));
        // Failure doesn't update the nonce.
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);

        session.handle()
    };

    assert!(stop(simulator, session_handle).is_ok());
}

/// A PCR change between `TPM2_PolicyPCR` and using the session fails the
/// authorization, even though the policyDigest still matches.
fn pcr_changed_before_use(extend: bool) {
    let mut simulator = start(&format!("pcr_changed_before_use(extend: {extend})"));
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    let pcr_digest = read_pcr_digest(&mut simulator);
    auth_policy
        .policy_pcr(Tpm2bDigest::new(&pcr_digest).unwrap(), &pcr_selection())
        .unwrap();
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);
    // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    assert!(policy_pcr(&mut simulator, &mut session, &pcr_digest).is_ok());

    if extend {
        // The PCR's authValue is empty.
        let pcr_extend = PCRExtend {
            pcr_handle: PCR,
            digests: TpmlDigestValues::new(&[TpmtHa::Sha256(&[42u8; DIGEST_SIZE])]).unwrap(),
        };
        assert!(run_command_with_sessions(&pcr_extend, &[], &mut PasswordSession::default(), simulator.connection_mut(), resp_buffer).is_ok());

        // This command doesn't take the policy session.
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);
    }

    let nv_read_rsp = read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session);
    if extend {
        assert_eq!(nv_read_rsp, Err(TpmRc::PCR_CHANGED));
        // Failure doesn't update the nonce.
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);
    } else {
        assert!(nv_read_rsp.is_ok());
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);
    }

    assert!(stop(simulator, session.handle()).is_ok());
}

/// An assertion with an expiration sets the session's timeout, after which
/// the session can't be used. Using the session resets the timeout.
fn policy_timeout(wait: bool) {
    let mut simulator = start(&format!("policy_timeout(wait: {wait})"));
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    let auth_policy = owner_policy_secret_digest();
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);
    // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    // Expires 1 second after the session's startTime.
    assert!(policy_secret(&mut simulator, &mut session, 1).is_ok());

    if wait {
        sleep(Duration::from_secs(2));
    }

    let nv_read_rsp = read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session);
    if wait {
        assert_eq!(nv_read_rsp, Err(TpmRc::EXPIRED.with(Position::session(1))));
        // Failure doesn't update the nonce.
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);
    } else {
        assert!(nv_read_rsp.is_ok());
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

        // The timeout was reset: without an expiration this time, the
        // session can be used after the old timeout.
        assert!(policy_secret(&mut simulator, &mut session, 0).is_ok());
        sleep(Duration::from_secs(2));

        assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);
    }

    assert!(stop(simulator, session.handle()).is_ok());
}

/// startTime is set when the session is started, and reset when it's used.
/// An expiration (with `nonceTPM`) is relative to startTime, so an
/// assertion's expiration can already be in the past.
fn policy_start_time(use_first: bool) {
    let mut simulator = start(&format!("policy_start_time(use_first: {use_first})"));
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    let auth_policy = owner_policy_secret_digest();
    let mut nv_public = nv_public(TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD, auth_policy.digest());
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);
    // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    sleep(Duration::from_secs(2));

    if use_first {
        // Without an expiration, so that this can't expire.
        assert!(policy_secret(&mut simulator, &mut session, 0).is_ok());

        assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);
    }

    // Expires 1 second after the session's startTime: that is 2 seconds ago,
    // unless using the session reset it.
    let policy_secret_rsp = policy_secret(&mut simulator, &mut session, 1);
    if use_first {
        assert!(policy_secret_rsp.is_ok());

        assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);
    } else {
        // A failed assertion doesn't change the policyDigest, which `run_policy_command()` checked.
        assert_eq!(policy_secret_rsp, Err(TpmRc::EXPIRED.with(Position::parameter(4))));
    }

    assert!(stop(simulator, session.handle()).is_ok());
}

/// A failed use of a policy session doesn't reset it (or roll its nonce),
/// whether authorization failed, or the command failed after authorization
/// succeeded. Then, the session can still be used.
fn failed_use_keeps_policy(auth_failure: bool) {
    let mut simulator = start(&format!("failed_use_keeps_policy(auth_failure: {auth_failure})"));
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    let mut auth_policy: PolicyDigest = PolicyDigest::new(ALG);
    auth_policy.policy_command_code(TpmCc::NVRead).unwrap();
    let mut nv_public = nv_public(
        TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD | TpmaNv::POLICYWRITE,
        auth_policy.digest(),
    );
    define_and_write_nv_index(&mut simulator, &mut nv_public);

    let mut session = start_policy_session(&mut simulator);
    // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    assert!(policy_command_code(&mut simulator, &mut session, TpmCc::NVRead).is_ok());

    if auth_failure {
        // The policyDigest matches, but the policy is for NV_Read.
        assert_eq!(
            write_nv_index(&mut simulator, &mut nv_public, NV_INDEX, &mut session),
            Err(TpmRc::POLICY_CC.with(Position::session(1)))
        );
    } else {
        // Authorization succeeds, but the read is out of range.
        let mut name_buf = [0u8; Tpm2bName::CAP];
        let name = nv_name::<CryptoBackend>(&nv_public, &mut name_buf).unwrap();

        let nv_read = NVRead {
            auth_handle: NV_INDEX,
            nv_index: NV_INDEX,
            size: NV_DATA_SIZE,
            offset: NV_DATA_SIZE / 2,
        };
        let nv_read_rsp = run_command_with_sessions(&nv_read, &[Some(name), Some(name)], &mut session, simulator.connection_mut(), resp_buffer);
        assert_eq!(tpm_result(nv_read_rsp), Err(TpmRc::NV_RANGE));
    }

    // Failure doesn't update the nonce, nor reset the policy.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);
    assert_ne!(session.policy().digest().as_slice(), [0u8; DIGEST_SIZE]);
    assert_policy_digest(&mut simulator, &session);

    // So fixing the mistake succeeds.
    assert!(read_nv_index(&mut simulator, &nv_public, NV_INDEX, &mut session).is_ok());
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);
    assert_policy_digest(&mut simulator, &session);

    assert!(stop(simulator, session.handle()).is_ok());
}

//
// Driver.
//
pub fn run() {
    policy_construction_and_usage();

    // TODO: Test a key conflict.
    repeated_command_code();

    // TODO: Do the deep review from here onwards.
    pcr_requires_policy(true);
    pcr_requires_policy(false);
    pcr_changed_before_use(false);
    pcr_changed_before_use(true);

    policy_timeout(false);
    policy_timeout(true);
    policy_start_time(false);
    policy_start_time(true);

    failed_use_keeps_policy(true);
    failed_use_keeps_policy(false);

    println!("TODO: Continue on policies.");
}
