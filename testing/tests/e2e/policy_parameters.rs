//! TPM2_PolicyParameters: the policy digest update, the size and cpHash-occupied checks, the
//! mutual exclusion with TPM2_PolicyCpHash/NameHash/Template, and that the session authorizes
//! only a command with the bound command code and parameters, whatever its handles.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{
    ClockRateAdjust, ContextLoad, ContextSave, PolicyCpHash, PolicyNameHash, PolicyParameters,
    PolicyTemplate, SetPrimaryPolicy,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, TpmCc, TpmClockAdjust, TpmSe, TpmaSession,
    TpmiAlgHash, TpmsAuthCommand,
};

/// A policy session authorization with an empty HMAC (unbound, unsalted, no authValue).
fn policy_auth(session: Handle) -> TpmsAuthCommand<'static> {
    TpmsAuthCommand {
        session_handle: session,
        nonce: Tpm2bNonce::from_bytes(&[0x33; 16]).unwrap(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    }
}

/// The pHash of `TPM2_ClockRateAdjust(rate_adjust)`: H(TPM_CC_ClockRateAdjust || rateAdjust).
fn clock_rate_adjust_p_hash(rate_adjust: TpmClockAdjust) -> Vec<u8> {
    sha256(&[
        &TpmCc::ClockRateAdjust.code().to_be_bytes(),
        &[rate_adjust as i8 as u8],
    ])
}

/// `TPM2_PolicyParameters(session, p_hash)`.
fn policy_parameters(tpm: &mut Tpm, session: Handle, p_hash: &[u8]) -> Result<(), u32> {
    execute_with_password_sessions(
        tpm,
        &PolicyParameters {
            policy_session: session,
            p_hash: Tpm2bDigest::from_bytes(leak_bytes(p_hash)).unwrap(),
        },
        0,
        &[],
    )
    .map(|_| ())
}

/// Sets the authPolicy of `hierarchy` to the SHA-256 `digest`.
fn set_policy(tpm: &mut Tpm, hierarchy: Handle, digest: &[u8]) {
    execute_with_password_sessions(
        tpm,
        &SetPrimaryPolicy {
            auth_handle: hierarchy,
            auth_policy: Tpm2bDigest::from_bytes(leak_bytes(digest)).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        1,
        &[],
    )
    .expect("TPM2_SetPrimaryPolicy failed");
}

/// `TPM2_ClockRateAdjust(auth, rate_adjust)` authorized by `session`.
fn clock_rate_adjust_with(
    tpm: &mut Tpm,
    auth: Handle,
    rate_adjust: TpmClockAdjust,
    session: Handle,
) -> Result<(), u32> {
    exec_command(
        tpm,
        &ClockRateAdjust { auth, rate_adjust },
        &[policy_auth(session)],
    )
    .map(|_| ())
}

/// The policy digest of a lone TPM2_PolicyParameters(pHash).
fn parameters_policy(p_hash: &[u8]) -> Vec<u8> {
    sha256(&[
        &[0u8; 32],
        &TpmCc::PolicyParameters.code().to_be_bytes(),
        p_hash,
    ])
}

/// TPM2_PolicyParameters extends the digest with H(digest || TPM_CC_PolicyParameters || pHash).
#[test]
fn extends_trial_policy_digest() {
    let mut tpm = Tpm::new();
    let session = start_session_with_nonce(&mut tpm, TpmSe::Trial, TpmiAlgHash::Sha256, &[1; 32]);
    let p_hash = [0x42u8; 32];
    assert_eq!(policy_parameters(&mut tpm, session, &p_hash), Ok(()));
    assert_eq!(
        policy_get_digest_checked(&mut tpm, session),
        parameters_policy(&p_hash)
    );
}

/// A pHash whose size is not the session's digest size is `TPM_RC_SIZE` (parameter 1).
#[test]
fn rejects_wrong_p_hash_size() {
    let mut tpm = Tpm::new();
    let session = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);
    for size in [0usize, 20, 48] {
        assert_eq!(
            policy_parameters(&mut tpm, session, &vec![1u8; size]),
            Err(TpmRc::SIZE.with(Position::parameter(1)).get())
        );
    }
}

/// Only one of cpHash, nameHash, pHash and templateHash: TPM2_PolicyParameters after any of
/// them, any of them after TPM2_PolicyParameters, and a repeated TPM2_PolicyParameters (even
/// with the same pHash) are `TPM_RC_CPHASH`.
#[test]
fn excludes_other_cp_hash_assertions() {
    let mut tpm = Tpm::new();
    let digest = Tpm2bDigest::from_bytes(&[7u8; 32]).unwrap();

    let session = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);
    assert_eq!(policy_parameters(&mut tpm, session, &[7u8; 32]), Ok(()));
    assert_eq!(
        policy_parameters(&mut tpm, session, &[7u8; 32]),
        Err(TpmRc::CPHASH.get())
    );
    let rcs = [
        execute_with_password_sessions(
            &mut tpm,
            &PolicyCpHash {
                policy_session: session,
                cp_hash_a: digest,
            },
            0,
            &[],
        )
        .map(|_| ()),
        execute_with_password_sessions(
            &mut tpm,
            &PolicyNameHash {
                policy_session: session,
                name_hash: digest,
            },
            0,
            &[],
        )
        .map(|_| ()),
        execute_with_password_sessions(
            &mut tpm,
            &PolicyTemplate {
                policy_session: session,
                template_hash: digest,
            },
            0,
            &[],
        )
        .map(|_| ()),
    ];
    assert_eq!(rcs, [Err(TpmRc::CPHASH.get()); 3]);

    let session = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[2; 32]);
    execute_with_password_sessions(
        &mut tpm,
        &PolicyCpHash {
            policy_session: session,
            cp_hash_a: digest,
        },
        0,
        &[],
    )
    .unwrap();
    assert_eq!(
        policy_parameters(&mut tpm, session, &[7u8; 32]),
        Err(TpmRc::CPHASH.get())
    );
}

/// The session authorizes the command with the bound command code and parameters, whatever its
/// handles (the Names are not part of the pHash); other parameters fail with
/// `TPM_RC_POLICY_FAIL` (session 1).
#[test]
fn authorizes_only_bound_parameters() {
    let mut tpm = Tpm::new();
    let p_hash = clock_rate_adjust_p_hash(TpmClockAdjust::NoChange);
    let policy = parameters_policy(&p_hash);
    set_policy(&mut tpm, Handle::RH_OWNER, &policy);
    set_policy(&mut tpm, Handle::RH_PLATFORM, &policy);

    let session = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);
    policy_parameters(&mut tpm, session, &p_hash).unwrap();
    assert_eq!(
        clock_rate_adjust_with(
            &mut tpm,
            Handle::RH_OWNER,
            TpmClockAdjust::FineFaster,
            session
        ),
        Err(TpmRc::POLICY_FAIL.with(Position::session(1)).get())
    );
    assert_eq!(
        clock_rate_adjust_with(
            &mut tpm,
            Handle::RH_OWNER,
            TpmClockAdjust::NoChange,
            session
        ),
        Ok(())
    );

    // The same pHash authorizes the command with another handle.
    policy_parameters(&mut tpm, session, &p_hash).unwrap();
    assert_eq!(
        clock_rate_adjust_with(
            &mut tpm,
            Handle::RH_PLATFORM,
            TpmClockAdjust::NoChange,
            session
        ),
        Ok(())
    );
}

/// The pHash restriction survives TPM2_ContextSave/TPM2_ContextLoad of the policy session.
#[test]
fn restriction_survives_context_save_and_load() {
    let mut tpm = Tpm::new();
    let p_hash = clock_rate_adjust_p_hash(TpmClockAdjust::NoChange);
    set_policy(&mut tpm, Handle::RH_OWNER, &parameters_policy(&p_hash));

    let session = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);
    policy_parameters(&mut tpm, session, &p_hash).unwrap();
    let saved = tpm
        .execute(ContextSave {
            save_handle: session,
        })
        .unwrap();
    let session = tpm
        .execute(ContextLoad {
            context: saved.context,
        })
        .unwrap()
        .loaded_handle;
    assert_eq!(
        clock_rate_adjust_with(
            &mut tpm,
            Handle::RH_OWNER,
            TpmClockAdjust::FineSlower,
            session
        ),
        Err(TpmRc::POLICY_FAIL.with(Position::session(1)).get())
    );
}
