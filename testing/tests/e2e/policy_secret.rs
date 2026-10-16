//! TPM2_PolicySecret: cpHash, expiration, tickets and authorization handles.

use crate::_common::*;
use testing::tpm::{SimulatorPlatformSignal, Tpm};
use tpm2::commands::{PolicyGetDigest, PolicySecret, StartAuthSession};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce, TpmSe, TpmaNv, TpmiAlgHash,
    TpmsNvPublic,
};

/// A second PolicySecret with a different cpHashA fails with TPM_RC_CPHASH.
#[test]
fn conflicting_cp_hash_rejected() {
    let mut sim = Tpm::new();

    // Start Policy session
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

    let cp_hash_1 = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let cp_hash_2 = Tpm2bDigest::from_bytes(&[0x22; 32]).unwrap();

    // First call sets temp_cp_hash to cp_hash_1
    let cmd1 = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
        nonce_tpm: active_session.nonce_tpm,
        cp_hash_a: cp_hash_1,
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let _ = execute_with_password_sessions(&mut sim, &cmd1, 1, &[]).unwrap();

    // Second call with cp_hash_2 should fail with CpHash error
    let cmd2 = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
        nonce_tpm: active_session.nonce_tpm,
        cp_hash_a: cp_hash_2,
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd2, 1, &[]);
    assert_eq!(res.err().unwrap(), TpmRc::CPHASH.get());
}

/// PolicySecret with a cpHashA of the wrong digest size fails with TPM_RC_SIZE.
#[test]
fn cp_hash_wrong_size_rejected() {
    let mut sim = Tpm::new();

    // Start Policy session
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

    // cpHashA with size 20 (SHA1 digest size) instead of 32 (SHA256 session digest size)
    let bad_cp_hash = Tpm2bDigest::from_bytes(&[0xAA; 20]).unwrap();

    let cmd = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
        nonce_tpm: active_session.nonce_tpm,
        cp_hash_a: bad_cp_hash,
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::SIZE.with(Position::parameter(2)).get()
    );
}

/// PolicySecret with expiration -1 sets a 1 s timeout; after sleeping, the policy session fails with TPM_RC_EXPIRED.
#[test]
fn expiration_enforced_after_timeout() {
    let mut sim = Tpm::new();

    // 1. Start Policy session
    let start_auth = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_rsp = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();
    let session_handle = start_rsp.session_handle;

    // 2. Call PolicySecret with expiration = -1 (which sets the timeout to 1 second)
    let policy_secret = PolicySecret {
        auth_handle: Handle::RH_OWNER,
        policy_session: session_handle,
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: -1, // 1 second timeout
    };
    let _ = execute_with_password_sessions(&mut sim, &policy_secret, 1, &[])
        .expect("PolicySecret failed");

    // Immediately the policy should still be valid. Let's verify by calling PolicyGetDigest
    let get_digest = PolicyGetDigest {
        policy_session: session_handle,
    };
    assert!(execute_with_password_sessions(&mut sim, &get_digest, 0, &[]).is_ok());

    // 3. Wait for 1.5 seconds so that the session expires
    sleep(std::time::Duration::from_millis(1500));

    // 4. Repeat PolicySecret with the same 1-second expiration. It should return
    // an error due to session expiration. (C PolicyOR does not check the
    // session timeout at all; it would fail with VALUE+P1 because the current
    // digest is not in the list. PolicySecret's expiration is checked against
    // the session start time: EXPIRED+P4, Policy_spt.c:36-39.)
    // With nonceTPM present, C measures the expiration from the session start
    // time (Policy_spt.c ComputeAuthTimeout); with an empty nonce it would be
    // relative to the current second and not reliably expired.
    let policy_secret = PolicySecret {
        auth_handle: Handle::RH_OWNER,
        policy_session: session_handle,
        nonce_tpm: start_rsp.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: -1,
    };
    let res = execute_with_password_sessions(&mut sim, &policy_secret, 1, &[]);
    assert!(
        res.is_err(),
        "Expected command to fail on expired session, but it succeeded!"
    );
    let err_code = res.err().unwrap();
    // TPM_RC_EXPIRED is 0x00000023, combined with session/parameter positions.
    // Let's verify that the base error code is EXPIRED (0x23).
    assert_eq!(
        err_code & 0x3F,
        0x23,
        "Expected expired error 0x23, got {:x}",
        err_code
    );
}

/// PolicySecret with a started HMAC session as policySession fails with TPM_RC_VALUE + H2.
#[test]
fn hmac_session_handle_rejected() {
    let mut sim = Tpm::new();

    // Start an HMAC session
    let hmac_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC, // HMAC instead of Policy
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("start HMAC session failed");

    let cmd = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: hmac_session.session_handle,
        nonce_tpm: hmac_session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    // policySession is a TPMI_SH_POLICY: a non-policy (0x02) handle fails handle unmarshaling
    // with TPM_RCS_VALUE + RC_H2 (C TPMI_SH_POLICY_Unmarshal), before any session processing.
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );
}

/// PolicySecret with a negative expiration returns a timeout and an auth ticket.
#[test]
fn negative_expiration_returns_ticket() {
    let mut sim = Tpm::new();

    // Start Policy session
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

    let cmd = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
        nonce_tpm: active_session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: -1, // Negative expiration!
    };
    let resp = execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    assert_eq!(resp.policy_ticket.tag(), 0x8023);
    assert!(!resp.policy_ticket.digest().get_buffer().is_empty());
}

/// PolicySecret with a non-policy session handle fails with TPM_RC_VALUE + H2 at unmarshal.
#[test]
fn non_policy_session_handle_rejected() {
    let mut sim = Tpm::new();

    let cmd = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: Handle(0x020000FF), // Non-existent session
        nonce_tpm: tpm2::Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    // policySession is a TPMI_SH_POLICY: a non-policy (0x02) handle fails handle unmarshaling
    // with TPM_RCS_VALUE + RC_H2 (C TPMI_SH_POLICY_Unmarshal), before any session processing.
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );
}

/// PolicySecret with a nonceTPM that does not match the session fails with TPM_RC_NONCE.
#[test]
fn nonce_tpm_mismatch_rejected() {
    let mut sim = Tpm::new();

    // Start Policy session
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

    // Generate a mismatched nonce
    let mut bad_nonce_bytes = active_session.nonce_tpm.get_buffer().to_vec();
    if !bad_nonce_bytes.is_empty() {
        bad_nonce_bytes[0] ^= 0xFF;
    }
    let bad_nonce = tpm2::Tpm2bNonce::from_bytes(&bad_nonce_bytes).unwrap();

    let cmd = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: active_session.session_handle,
        nonce_tpm: bad_nonce,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::NONCE.with(Position::parameter(1)).get()
    );
}

/// PolicySecret with an NV index as authHandle succeeds and updates the digest with the NV name
#[test]
fn nv_index_as_auth_handle() {
    let mut sim = Tpm::new();

    // 1. Define NV index
    let nv_index_val = 0x01600008;
    let nv_pub = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    };
    let public_info = tpm2::Tpm2b(nv_pub);
    let nv_auth = Tpm2bAuth::default();

    let define_cmd = tpm2::commands::NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        public_info,
        auth: nv_auth,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, 1, &[]).unwrap();

    // 2. Start policy session
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // 3. Execute PolicySecret using NV Index as auth_handle
    let policy_secret_cmd = PolicySecret {
        auth_handle: Handle(nv_index_val),
        policy_session: session.session_handle,
        nonce_tpm: session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };

    // Auth session 1 is for the NV Index (password session with empty auth)
    let res = execute_with_password_sessions(&mut sim, &policy_secret_cmd, 1, &[]);
    assert!(res.is_ok(), "PolicySecret failed: {:?}", res.err());

    // 4. Get policy digest
    let get_digest_cmd = PolicyGetDigest {
        policy_session: session.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();

    // 5. Compute expected digest
    // expected_digest = H( H(0_size || TPM_CC_PolicySecret || nv_name) || policyRef )
    let nv_name = nv_name(&nv_pub);

    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_secret(nv_name.get_buffer(), &[]);

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        pol.policy_digest.as_slice(),
        "PolicySecret digest should match the expected digest computed with NV Index Name"
    );
}

/// PolicySecret against a PIN Pass index with an expiration returns a null ticket.
#[test]
fn pin_pass_index_gets_null_ticket() {
    // Part 3 (PIN Pass tickets); parts 1-2 are engine authorization checks (fix-auth).
    let mut sim = Tpm::new();
    let index = 0x0150_0012;
    define_pin_pass(&mut sim, index);
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    let rsp = policy_secret(&mut sim, Handle(index), &s, &[], -1).unwrap();
    assert_eq!(rsp.timeout.get_size(), 0);
    assert_eq!(rsp.policy_ticket.tag(), tpm2::TpmSt::AUTH_SECRET.id());
    assert_eq!(rsp.policy_ticket.hierarchy(), Handle::RH_NULL);
    assert_eq!(rsp.policy_ticket.digest().get_size(), 0);
}

/// PIN Pass index gets a null ticket; an expiration needs NV (NV_UNAVAILABLE), no expiration does not.
#[test]
fn pin_pass_ticket_and_expiration_needs_nv() {
    let mut sim = Tpm::new();

    // PIN Pass index: no ticket (null ticket, empty timeout).
    let index = 0x0150_0011;
    define_pin_pass(&mut sim, index);
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    let rsp = policy_secret(&mut sim, Handle(index), &s, &[], -100).unwrap();
    assert_eq!(rsp.timeout.get_size(), 0);
    assert_eq!(rsp.policy_ticket.hierarchy(), Handle::RH_NULL);
    assert_eq!(rsp.policy_ticket.digest().get_size(), 0);

    // NV unavailable: an expiration cannot be checked (RETURN_IF_NV_IS_NOT_AVAILABLE).
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(
        policy_secret(&mut sim, Handle::RH_OWNER, &s, &[], 100).map(|_| ()),
        Err(TpmRc::NV_UNAVAILABLE.get())
    );
    // Without an expiration NV is not needed.
    policy_secret(&mut sim, Handle::RH_OWNER, &s, &[], 0).unwrap();
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    policy_secret(&mut sim, Handle::RH_OWNER, &s, &[], 100).unwrap();
}

/// PolicySecret tickets resolve lockout/NV to the owner hierarchy; PolicyTicket rejects trial sessions.
///
/// PolicySecret tickets use `EntityGetHierarchy`: lockout, PCR and owner-created NV indices
/// belong to the owner hierarchy; PIN Pass indices never get a ticket. PolicyTicket rejects
/// trial sessions and empty timeouts.
#[test]
fn ticket_hierarchy_resolution_and_trial_rejection() {
    let mut sim = Tpm::new();

    // TPM_RH_LOCKOUT -> TPM_RH_OWNER, and the ticket validates with the owner proof.
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    let rsp = policy_secret(&mut sim, Handle::RH_LOCKOUT, &s, &[], -100).unwrap();
    assert_eq!(rsp.policy_ticket.hierarchy(), Handle::RH_OWNER);
    assert_eq!(rsp.timeout.get_size(), 8);
    let s2 = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_ticket(
        &mut sim,
        s2,
        rsp.timeout.get_buffer(),
        &[],
        &Handle::RH_LOCKOUT.0.to_be_bytes(),
        rsp.policy_ticket,
    )
    .expect("PolicyTicket with a lockout PolicySecret ticket");

    // Ordinary NV Index without PLATFORMCREATE -> TPM_RH_OWNER.
    let index = 0x0150_0010;
    define_nv_empty_policy(&mut sim, index, nv_attrs(TpmaNv::empty()), 8);
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    let rsp = policy_secret(&mut sim, Handle(index), &s, &[], -100).unwrap();
    assert_eq!(rsp.policy_ticket.hierarchy(), Handle::RH_OWNER);

    // Trial session on PolicyTicket.
    let t = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_ticket(
            &mut sim,
            t,
            &[0; 8],
            &[],
            &Handle::RH_OWNER.0.to_be_bytes(),
            null_secret_ticket()
        ),
        Err(TpmRc::ATTRIBUTES.with(Position::handle(1)).get())
    );
}

/// PolicySecret on a trial session succeeds.
#[test]
fn trial_session_succeeds() {
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
    .expect("start Trial session failed");

    let cmd = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: trial_session.session_handle,
        nonce_tpm: trial_session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: tpm2::Tpm2bNonce::default(),
        expiration: 0,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 1, &[]);
    assert!(res.is_ok(), "PolicySecret on Trial session failed");
}

/// An expiration of `INT32_MIN` (a ticket requested for 2^31 seconds) uses its absolute value,
/// 2^31 s, for the timeout (TPM 2.0 Part 3, "Policy Parameter Checks": "the absolute value of
/// *expiration* is converted to milliseconds"), both relative to the session start (with
/// nonceTPM) and as an absolute time (empty nonceTPM, which also sets the expires-on-reset flag in
/// the reference's timeout format).
#[test]
fn most_negative_expiration_uses_its_absolute_value() {
    const TWO_POW_31_MS: u64 = (1u64 << 31) * 1000;
    const EXPIRES_ON_RESET: u64 = 1 << 63;
    for with_nonce in [true, false] {
        let mut sim = Tpm::new();
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::Policy,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        let nonce_tpm = if with_nonce {
            session.nonce_tpm
        } else {
            Tpm2bNonce::default()
        };
        let resp = run_pw(
            &mut sim,
            PolicySecret {
                auth_handle: Handle::RH_OWNER,
                policy_session: session.session_handle,
                nonce_tpm,
                cp_hash_a: Tpm2bDigest::default(),
                policy_ref: Default::default(),
                expiration: i32::MIN,
            },
        )
        .expect("PolicySecret with expiration INT32_MIN");
        let timeout = u64::from_be_bytes(resp.timeout.get_buffer().try_into().unwrap());
        assert_eq!(timeout & EXPIRES_ON_RESET != 0, !with_nonce);
        let ms = timeout & !EXPIRES_ON_RESET;
        assert!(
            (TWO_POW_31_MS..TWO_POW_31_MS + 1_000_000_000).contains(&ms),
            "timeout {timeout:#x}"
        );
    }
}
