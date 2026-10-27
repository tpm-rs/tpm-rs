//! TPM2_ACT_SetTimeout and TPM2_SetPrimaryPolicy on ACT handles: handle validation (only the
//! implemented ACTs of the profile), the ACT authorization (platformAuth while phEnable is SET,
//! the ACT-specific authPolicy always), the `startTimeout` rules, `TPM_RC_RETRY` while an update
//! is pending, and the orderly state / NV availability rules.

use crate::_common::{
    SimulatorPlatformSignal, TPM_SU_STATE, act_set_timeout, act_set_timeout_with, act_state,
    build_cmd, build_pw_cmd, execute_with_hmac_sessions, execute_with_password_sessions_status,
    hierarchy_change_auth, hierarchy_control, implemented_act_handles, nv_on, policy_command_code,
    policy_command_code_digest, power_cycle_with, rc_h, rc_of, rc_p, rc_s, run_raw, shutdown_raw,
    sleep, start_auth_session, start_policy, transact_rc_of,
};
use std::time::Duration;
use testing::tpm::Tpm;
use tpm2::commands::{ACTSetTimeout, SetPrimaryPolicy};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, TpmCc, TpmSe, TpmaSession, TpmiAlgHash,
    TpmsAuthCommand,
};

/// `TPM_RH_ACT_0`.
const ACT_0: u32 = 0x4000_0110;
/// `TPMA_ACT.signaled`.
const SIGNALED: u32 = 1;
/// `TPM_CC_ACT_SetTimeout`.
const CC_ACT_SET_TIMEOUT: u32 = 0x198;
/// `TPM_RC_RETRY`.
const RC_RETRY: u32 = 0x922;

/// One ACT tick.
fn tick() {
    sleep(Duration::from_secs(1));
}

/// A policy session authorization (no policy password/authValue: empty HMAC).
fn policy_auth(session: Handle) -> TpmsAuthCommand<'static> {
    TpmsAuthCommand {
        session_handle: session,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    }
}

/// `TPM2_SetPrimaryPolicy(auth_handle, SHA-256 policy)` with the password `auth`.
fn set_act_policy(sim: &mut Tpm, act: u32, policy: &[u8], auth: &[u8]) -> u32 {
    let cmd = SetPrimaryPolicy {
        auth_handle: Handle(act),
        auth_policy: Tpm2bDigest::from_bytes(policy).unwrap(),
        hash_alg: if policy.is_empty() {
            None
        } else {
            Some(TpmiAlgHash::Sha256)
        },
    };
    match execute_with_password_sessions_status(sim, &cmd, 1, auth) {
        Ok([]) => 0,
        Err(rc) => rc,
    }
}

/// Every implemented ACT accepts TPM2_ACT_SetTimeout; the other `TPMI_RH_ACT` values are not
/// loaded (`TPM_RC_VALUE + RC_H1`), as are values outside `{TPM_RH_ACT_0:TPM_RH_ACT_F}`.
#[test]
fn only_implemented_acts_are_accepted() {
    let mut sim = Tpm::new();
    let implemented = implemented_act_handles();
    for act in Handle::RH_ACT_0.0..=Handle::RH_ACT_F.0 {
        let expected = if implemented.contains(&act) {
            0
        } else {
            rc_h(TpmRc::VALUE, 1)
        };
        assert_eq!(act_set_timeout(&mut sim, act, 10), expected, "{act:#x}");
        let expected_policy = if implemented.contains(&act) {
            0
        } else {
            rc_h(TpmRc::VALUE, 1)
        };
        assert_eq!(
            set_act_policy(&mut sim, act, &[0x11; 32], &[]),
            expected_policy,
            "SetPrimaryPolicy {act:#x}"
        );
    }
    for handle in [
        0x4000_010F,
        0x4000_0120,
        Handle::RH_PLATFORM.0,
        Handle::RH_OWNER.0,
    ] {
        assert_eq!(
            act_set_timeout(&mut sim, handle, 10),
            rc_h(TpmRc::VALUE, 1),
            "{handle:#x}"
        );
    }
}

/// The ACT authValue is platformAuth (Part 1, "Authenticated Countdown Timer (ACT)"): a wrong
/// password fails, the current platformAuth succeeds.
#[test]
fn platform_auth_authorizes_the_act() {
    let mut sim = Tpm::new();
    hierarchy_change_auth(&mut sim, Handle::RH_PLATFORM, &[], b"platform").unwrap();
    assert_eq!(
        act_set_timeout_with(&mut sim, ACT_0, 5, &[]),
        rc_s(TpmRc::BAD_AUTH, 1)
    );
    assert_eq!(act_set_timeout_with(&mut sim, ACT_0, 5, b"platform"), 0);
    assert_eq!(
        set_act_policy(&mut sim, ACT_0, &[0x22; 32], b"wrong"),
        rc_s(TpmRc::BAD_AUTH, 1)
    );
    assert_eq!(set_act_policy(&mut sim, ACT_0, &[0x22; 32], b"platform"), 0);
}

/// An HMAC session authorizes TPM2_ACT_SetTimeout with platformAuth; the Name of an ACT is its
/// handle.
#[test]
fn hmac_session_authorizes_the_act() {
    let mut sim = Tpm::new();
    hierarchy_change_auth(&mut sim, Handle::RH_PLATFORM, &[], b"secret").unwrap();
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let name = ACT_0.to_be_bytes();
    let cmd = ACTSetTimeout {
        act_handle: Handle(ACT_0),
        start_timeout: 7,
    };
    execute_with_hmac_sessions(&mut sim, &cmd, &[&name], &mut [session], &[b"secret"]).unwrap();
    assert_eq!(act_state(&mut sim, ACT_0), (7, 0));
}

/// "The *authValue* is the same as the current *platformAuth* and can only be used if *phEnable*
/// is SET. The *authPolicy* is ACT-specific and is neither enabled nor disabled by *phEnable*":
/// with phEnable CLEAR a password is `TPM_RC_AUTH_UNAVAILABLE`, but the ACT policy authorizes
/// both TPM2_ACT_SetTimeout and TPM2_SetPrimaryPolicy.
#[test]
fn act_policy_works_while_platform_hierarchy_disabled() {
    let mut sim = Tpm::new();
    // An empty policy (no assertions): any policy session satisfies it.
    assert_eq!(set_act_policy(&mut sim, ACT_0, &[0; 32], &[]), 0);
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_PLATFORM, false).unwrap();

    assert_eq!(
        act_set_timeout(&mut sim, ACT_0, 5),
        TpmRc::AUTH_UNAVAILABLE.get()
    );
    assert_eq!(
        set_act_policy(&mut sim, ACT_0, &[0x33; 32], &[]),
        TpmRc::AUTH_UNAVAILABLE.get()
    );

    let (session, _) = start_policy(&mut sim, TpmSe::Policy);
    let cmd = ACTSetTimeout {
        act_handle: Handle(ACT_0),
        start_timeout: 5,
    };
    assert_eq!(
        rc_of(&run_raw(
            &mut sim,
            &build_cmd(&cmd, &[policy_auth(session)])
        )),
        0
    );
    assert_eq!(act_state(&mut sim, ACT_0), (5, 0));

    // Change the ACT policy through the policy: only TPM2_ACT_SetTimeout from now on.
    let digest = policy_command_code_digest(TpmiAlgHash::Sha256, TpmCc::ACTSetTimeout);
    let set_policy = SetPrimaryPolicy {
        auth_handle: Handle(ACT_0),
        auth_policy: digest,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    assert_eq!(
        rc_of(&run_raw(
            &mut sim,
            &build_cmd(&set_policy, &[policy_auth(session)])
        )),
        0
    );
    // An empty policy session no longer matches.
    let (session, _) = start_policy(&mut sim, TpmSe::Policy);
    tick();
    let cmd = ACTSetTimeout {
        act_handle: Handle(ACT_0),
        start_timeout: 9,
    };
    assert_eq!(
        rc_of(&run_raw(
            &mut sim,
            &build_cmd(&cmd, &[policy_auth(session)])
        )),
        rc_s(TpmRc::POLICY_FAIL, 1)
    );
    policy_command_code(&mut sim, session, TpmCc::ACTSetTimeout).unwrap();
    assert_eq!(
        rc_of(&run_raw(
            &mut sim,
            &build_cmd(&cmd, &[policy_auth(session)])
        )),
        0
    );
}

/// Without an ACT policy, a policy session cannot authorize the ACT
/// (`TPM_RC_AUTH_UNAVAILABLE`).
#[test]
fn empty_act_policy_is_unavailable() {
    let mut sim = Tpm::new();
    let (session, _) = start_policy(&mut sim, TpmSe::Policy);
    let cmd = ACTSetTimeout {
        act_handle: Handle(ACT_0),
        start_timeout: 5,
    };
    assert_eq!(
        rc_of(&run_raw(
            &mut sim,
            &build_cmd(&cmd, &[policy_auth(session)])
        )),
        TpmRc::AUTH_UNAVAILABLE.get()
    );
}

/// TPM2_ACT_SetTimeout needs an authorization session.
#[test]
fn authorization_is_required() {
    let mut sim = Tpm::new();
    let mut cmd = vec![0x80, 0x01, 0, 0, 0, 0x12];
    cmd.extend_from_slice(&CC_ACT_SET_TIMEOUT.to_be_bytes());
    cmd.extend_from_slice(&ACT_0.to_be_bytes());
    cmd.extend_from_slice(&5u32.to_be_bytes());
    assert_eq!(transact_rc_of(&mut sim, &cmd), TpmRc::AUTH_MISSING.get());
}

/// A missing `startTimeout` is `TPM_RC_INSUFFICIENT + RC_P1`, trailing bytes `TPM_RC_SIZE`.
#[test]
fn start_timeout_unmarshaling() {
    let mut sim = Tpm::new();
    let cmd = build_pw_cmd(CC_ACT_SET_TIMEOUT, &[ACT_0], 1, &[0, 0]);
    assert_eq!(transact_rc_of(&mut sim, &cmd), rc_p(TpmRc::INSUFFICIENT, 1));
    let cmd = build_pw_cmd(CC_ACT_SET_TIMEOUT, &[ACT_0], 1, &[0, 0, 0, 5, 0]);
    assert_eq!(transact_rc_of(&mut sim, &cmd), TpmRc::SIZE.get());
    assert_eq!(act_state(&mut sim, ACT_0), (0, 0));
}

/// `startTimeout` `0xFFFFFFFF` is only accepted for an ACT that has signaled (TCG reference:
/// "attempt to disable signaling from an ACT that has not expired" is `TPM_RC_VALUE`).
#[test]
fn max_start_timeout_requires_a_signaled_act() {
    let mut sim = Tpm::new();
    assert_eq!(
        act_set_timeout(&mut sim, ACT_0, u32::MAX),
        rc_p(TpmRc::VALUE, 1)
    );
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 5), 0);
    tick();
    assert_eq!(
        act_set_timeout(&mut sim, ACT_0, u32::MAX),
        rc_p(TpmRc::VALUE, 1)
    );
    sleep(Duration::from_secs(4));
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));
    assert_eq!(act_set_timeout(&mut sim, ACT_0, u32::MAX), 0);
}

/// While an update waits for the next tick, another TPM2_ACT_SetTimeout of the same ACT is
/// `TPM_RC_RETRY` and changes nothing; after the tick it succeeds.
#[test]
fn pending_update_returns_retry() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 5), 0);
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 6), RC_RETRY);
    assert_eq!(act_state(&mut sim, ACT_0), (5, 0));
    // Another ACT is independent.
    if let Some(&other) = implemented_act_handles().get(1) {
        assert_eq!(act_set_timeout(&mut sim, other, 8), 0);
    }
    sleep(Duration::from_millis(999));
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 6), RC_RETRY);
    sleep(Duration::from_millis(1));
    assert_eq!(act_state(&mut sim, ACT_0), (4, 0));
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 6), 0);
    tick();
    assert_eq!(act_state(&mut sim, ACT_0), (5, 0));
}

/// TPM2_ACT_SetTimeout clears the orderly state: after it, TPM2_Startup(TPM_SU_STATE) following
/// the earlier TPM2_Shutdown(TPM_SU_STATE) fails ("If a TPM2_ACT_SetTimeout() occurs after the
/// TPM2_Shutdown(), then the TPM state is no longer orderly"). A rejected or retried update
/// keeps it.
#[test]
fn set_timeout_after_shutdown_state_prevents_resume() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 5), 0);
    assert_eq!(shutdown_raw(&mut sim, TPM_SU_STATE), 0);
    // Pending: TPM_RC_RETRY; not signaled: TPM_RC_VALUE.
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 6), RC_RETRY);
    assert_eq!(
        act_set_timeout(&mut sim, ACT_0, u32::MAX),
        rc_p(TpmRc::VALUE, 1)
    );
    assert_eq!(power_cycle_with(&mut sim, None, TPM_SU_STATE), 0);
    assert_eq!(act_state(&mut sim, ACT_0), (5, 0));

    assert_eq!(shutdown_raw(&mut sim, TPM_SU_STATE), 0);
    tick();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 6), 0);
    assert_eq!(
        power_cycle_with(&mut sim, None, TPM_SU_STATE),
        rc_p(TpmRc::VALUE, 1)
    );
}

/// TPM2_SetPrimaryPolicy on an ACT clears the orderly state too.
#[test]
fn act_policy_change_after_shutdown_state_prevents_resume() {
    let mut sim = Tpm::new();
    assert_eq!(shutdown_raw(&mut sim, TPM_SU_STATE), 0);
    assert_eq!(set_act_policy(&mut sim, ACT_0, &[0x44; 32], &[]), 0);
    assert_eq!(
        power_cycle_with(&mut sim, None, TPM_SU_STATE),
        rc_p(TpmRc::VALUE, 1)
    );
}

/// An update needs NV only while the TPM is orderly (it clears the orderly state); a policy
/// change always needs NV (TPM2_SetPrimaryPolicy).
#[test]
fn nv_is_needed_only_to_clear_the_orderly_state() {
    let mut sim = Tpm::new();
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 5), 0);
    assert_eq!(
        set_act_policy(&mut sim, ACT_0, &[0x55; 32], &[]),
        TpmRc::NV_UNAVAILABLE.get()
    );
    nv_on(&mut sim);
    assert_eq!(shutdown_raw(&mut sim, TPM_SU_STATE), 0);
    tick();
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(
        act_set_timeout(&mut sim, ACT_0, 6),
        TpmRc::NV_UNAVAILABLE.get()
    );
    nv_on(&mut sim);
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 6), 0);
}
