//! TPM2_PolicyLocality: digest updates and conflicting localities.

use crate::_common::*;
use tpm2::commands::{PolicyLocality, PolicyPassword};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmSe, TpmaLocality, TpmiAlgHash};
use tpm2_simulator::create_simulator;

/// A trial session's digest after PolicyLocality and PolicyPassword matches the client-computed value.
#[test]
fn locality_and_password_digest() {
    let mut sim = create_simulator!();

    // Start a trial policy session
    let policy_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession failed")
    .session_handle;

    // 1. Run PolicyLocality(LOC_ZERO | LOC_ONE)
    sim.execute(PolicyLocality {
        policy_session,
        locality: TpmaLocality(3), // Bit 0 and Bit 1 set (LOC_ZERO | LOC_ONE)
    })
    .expect("PolicyLocality failed");

    // Expected policy digest after PolicyLocality:
    // SHA256(32 zero bytes || TPM_CC_PolicyLocality || locality)
    let digest_after_loc = sha256(&[
        &[0u8; 32],
        &TpmCc::PolicyLocality.code().to_be_bytes(),
        &[3],
    ]);
    assert_eq!(policy_digest(&mut sim, policy_session), digest_after_loc);

    // 2. Run PolicyPassword
    sim.execute(PolicyPassword { policy_session })
        .expect("PolicyPassword failed");

    // Expected policy digest after PolicyPassword:
    // SHA256(digest_after_loc || TPM_CC_PolicyAuthValue)
    let digest_after_pw = sha256(&[
        &digest_after_loc,
        &TpmCc::PolicyAuthValue.code().to_be_bytes(),
    ]);
    assert_eq!(policy_digest(&mut sim, policy_session), digest_after_pw);
}

/// PolicyLocality with a locality disjoint from an earlier one is TPM_RC_RANGE
#[test]
fn locality_mismatch_rejected() {
    let mut sim = create_simulator!();

    let policy_session_handle =
        start_session_with_nonce(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256, &[1; 32]);
    execute_with_password_sessions(
        &mut sim,
        &PolicyLocality {
            policy_session: policy_session_handle,
            locality: TpmaLocality(8), // LOC_THREE (bit 3 set)
        },
        0,
        &[],
    )
    .unwrap();

    let res = execute_with_password_sessions(
        &mut sim,
        &PolicyLocality {
            policy_session: policy_session_handle,
            locality: TpmaLocality(1), // LOC_ZERO (bit 0 set, intersection with bit 3 is 0)
        },
        0,
        &[],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::RANGE.with(Position::parameter(1)).get())
    );
}

/// PolicyLocality(LOC_ZERO) succeeds and updates the digest (commands are sent at locality 0)
#[test]
fn locality_zero_updates_digest() {
    let mut sim = create_simulator!();

    // The simulator's command interface sends every command at locality 0.
    let policy_session_handle =
        start_session_with_nonce(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256, &[1; 32]);

    let res = execute_with_password_sessions(
        &mut sim,
        &PolicyLocality {
            policy_session: policy_session_handle,
            locality: TpmaLocality(1), // LOC_ZERO (bit 0 set)
        },
        0,
        &[],
    );
    assert!(
        res.is_ok(),
        "Expected PolicyLocality(LOC_ZERO) to succeed when locality=0, got {:?}",
        res.err()
    );

    let policy_digest = policy_get_digest_checked(&mut sim, policy_session_handle);

    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(&[0u8; 32]);
    data_to_hash.extend_from_slice(&(TpmCc::PolicyLocality.code()).to_be_bytes());
    data_to_hash.extend_from_slice(&[1u8]);
    let digest = hash_bytes(TpmiAlgHash::Sha256, &data_to_hash);
    assert_eq!(policy_digest, digest);
}
