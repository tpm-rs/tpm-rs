//! TPM2_PolicyPhysicalPresence: the policy digest update, and that a policy session with
//! *isPPRequired* SET authorizes only while Physical Presence is asserted (the
//! `PhysicalPresenceOn`/`Off` platform signals), across context save/load and until
//! TPM2_PolicyRestart.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{
    ClockRateAdjust, ContextLoad, ContextSave, PolicyPhysicalPresence, PolicyRestart,
    SetPrimaryPolicy,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, TpmCc, TpmClockAdjust, TpmSe, TpmaSession,
    TpmiAlgHash, TpmsAuthCommand,
};

/// A policy session authorization with an empty HMAC (the session is unbound and unsalted and
/// the policy needs no authValue, so the HMAC key is empty).
fn policy_auth(session: Handle) -> TpmsAuthCommand<'static> {
    TpmsAuthCommand {
        session_handle: session,
        nonce: Tpm2bNonce::from_bytes(&[0x11; 16]).unwrap(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    }
}

/// H(0^32 || TPM_CC_PolicyPhysicalPresence), the SHA-256 policy of a lone
/// TPM2_PolicyPhysicalPresence.
fn pp_policy_digest() -> Vec<u8> {
    sha256(&[
        &[0u8; 32],
        &TpmCc::PolicyPhysicalPresence.code().to_be_bytes(),
    ])
}

/// Makes the Physical Presence policy the owner's authPolicy.
fn set_owner_policy(tpm: &mut Tpm, digest: &[u8]) {
    execute_with_password_sessions(
        tpm,
        &SetPrimaryPolicy {
            auth_handle: Handle::RH_OWNER,
            auth_policy: Tpm2bDigest::from_bytes(leak_bytes(digest)).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        1,
        &[],
    )
    .expect("TPM2_SetPrimaryPolicy failed");
}

/// Starts a SHA-256 policy session and asserts TPM2_PolicyPhysicalPresence in it.
fn pp_session(tpm: &mut Tpm) -> Handle {
    let session = start_session_with_nonce(tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);
    execute_with_password_sessions(
        tpm,
        &PolicyPhysicalPresence {
            policy_session: session,
        },
        0,
        &[],
    )
    .expect("TPM2_PolicyPhysicalPresence failed");
    session
}

/// Runs `TPM2_ClockRateAdjust(TPM_RH_OWNER)` authorized by `session`.
fn clock_rate_adjust_with(tpm: &mut Tpm, session: Handle) -> Result<(), u32> {
    exec_command(
        tpm,
        &ClockRateAdjust {
            auth: Handle::RH_OWNER,
            rate_adjust: TpmClockAdjust::NoChange,
        },
        &[policy_auth(session)],
    )
    .map(|_| ())
}

/// TPM2_PolicyPhysicalPresence extends the digest with H(digest || TPM_CC_PolicyPhysicalPresence)
/// in a trial session.
#[test]
fn extends_trial_policy_digest() {
    let mut tpm = Tpm::new();
    let session = start_session_with_nonce(&mut tpm, TpmSe::Trial, TpmiAlgHash::Sha256, &[1; 32]);
    execute_with_password_sessions(
        &mut tpm,
        &PolicyPhysicalPresence {
            policy_session: session,
        },
        0,
        &[],
    )
    .unwrap();
    assert_eq!(
        policy_get_digest_checked(&mut tpm, session),
        pp_policy_digest()
    );

    // A second assertion extends the digest again.
    execute_with_password_sessions(
        &mut tpm,
        &PolicyPhysicalPresence {
            policy_session: session,
        },
        0,
        &[],
    )
    .unwrap();
    let expected = sha256(&[
        &pp_policy_digest(),
        &TpmCc::PolicyPhysicalPresence.code().to_be_bytes(),
    ]);
    assert_eq!(policy_get_digest_checked(&mut tpm, session), expected);
}

/// TPM2_PolicyPhysicalPresence needs a policy session handle (`TPM_RC_VALUE` for an HMAC
/// session handle).
#[test]
fn rejects_hmac_session_handle() {
    let mut tpm = Tpm::new();
    let session = start_session_with_nonce(&mut tpm, TpmSe::HMAC, TpmiAlgHash::Sha256, &[1; 32]);
    let rc = execute_with_password_sessions(
        &mut tpm,
        &PolicyPhysicalPresence {
            policy_session: session,
        },
        0,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::VALUE.with(Position::handle(1)).get());
}

/// A session with *isPPRequired* SET fails authorization with `TPM_RC_PP` (session 1) while
/// Physical Presence is not asserted, and authorizes once it is.
#[test]
fn authorization_requires_asserted_physical_presence() {
    let mut tpm = Tpm::new();
    set_owner_policy(&mut tpm, &pp_policy_digest());
    let session = pp_session(&mut tpm);

    assert_eq!(
        clock_rate_adjust_with(&mut tpm, session),
        Err(TpmRc::PP.with(Position::session(1)).get())
    );

    tpm.signal_platform(SimulatorPlatformSignal::PhysicalPresenceOn)
        .unwrap();
    assert_eq!(clock_rate_adjust_with(&mut tpm, session), Ok(()));

    // The continued session was reset by its use; asserting PP again and deasserting the signal
    // makes it fail again.
    execute_with_password_sessions(
        &mut tpm,
        &PolicyPhysicalPresence {
            policy_session: session,
        },
        0,
        &[],
    )
    .unwrap();
    tpm.signal_platform(SimulatorPlatformSignal::PhysicalPresenceOff)
        .unwrap();
    assert_eq!(
        clock_rate_adjust_with(&mut tpm, session),
        Err(TpmRc::PP.with(Position::session(1)).get())
    );
}

/// A failed policy digest comparison (`TPM_RC_POLICY_FAIL`) comes before the Physical Presence
/// check.
#[test]
fn policy_digest_mismatch_precedes_physical_presence() {
    let mut tpm = Tpm::new();
    set_owner_policy(&mut tpm, &[0x5A; 32]);
    let session = pp_session(&mut tpm);
    assert_eq!(
        clock_rate_adjust_with(&mut tpm, session),
        Err(TpmRc::POLICY_FAIL.with(Position::session(1)).get())
    );
}

/// *isPPRequired* survives TPM2_ContextSave/TPM2_ContextLoad of the policy session.
#[test]
fn requirement_survives_context_save_and_load() {
    let mut tpm = Tpm::new();
    set_owner_policy(&mut tpm, &pp_policy_digest());
    let session = pp_session(&mut tpm);

    let saved = tpm
        .execute(ContextSave {
            save_handle: session,
        })
        .expect("TPM2_ContextSave failed");
    let loaded = tpm
        .execute(ContextLoad {
            context: saved.context,
        })
        .expect("TPM2_ContextLoad failed");
    assert_eq!(
        clock_rate_adjust_with(&mut tpm, loaded.loaded_handle),
        Err(TpmRc::PP.with(Position::session(1)).get())
    );
}

/// TPM2_PolicyRestart clears *isPPRequired* along with the policy digest.
#[test]
fn policy_restart_clears_requirement() {
    let mut tpm = Tpm::new();
    set_owner_policy(&mut tpm, &[0u8; 32]);
    let session = pp_session(&mut tpm);
    execute_with_password_sessions(
        &mut tpm,
        &PolicyRestart {
            session_handle: session,
        },
        0,
        &[],
    )
    .unwrap();
    // The empty (all-zero) policy now matches, and no Physical Presence is required.
    assert_eq!(clock_rate_adjust_with(&mut tpm, session), Ok(()));
}

/// The Physical Presence "pin" is kept across power cycles, and the signals are ignored while
/// the power is off.
#[test]
fn physical_presence_survives_power_cycle_and_ignores_signals_while_off() {
    let mut tpm = Tpm::new();
    set_owner_policy(&mut tpm, &pp_policy_digest());

    tpm.signal_platform(SimulatorPlatformSignal::PhysicalPresenceOn)
        .unwrap();
    tpm.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    // Ignored: the power is off.
    tpm.signal_platform(SimulatorPlatformSignal::PhysicalPresenceOff)
        .unwrap();
    power_on_start_up(&mut tpm);

    let session = pp_session(&mut tpm);
    assert_eq!(clock_rate_adjust_with(&mut tpm, session), Ok(()));
}
