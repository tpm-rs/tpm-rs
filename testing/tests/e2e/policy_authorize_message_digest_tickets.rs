//! TPM2_PolicyAuthorize with the version 185 tickets: a `TPM_ST_MESSAGE_VERIFIED` ticket of
//! TPM2_VerifySequenceComplete over *approvedPolicy* || *policyRef* and a
//! `TPM_ST_DIGEST_VERIFIED` ticket of TPM2_VerifyDigestSignature over its digest authorize the
//! policy; a ticket over another message does not.

#![cfg(any(
    feature = "cc-verify-digest-signature",
    all(
        feature = "cc-verify-sequence-start",
        feature = "cc-verify-sequence-complete"
    )
))]

use crate::_common::{
    create_signing_key, execute_with_password_sessions, leak_bytes, null_hashcheck, rc_at, sha256,
    start_policy_session,
};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{PolicyAuthorize, PolicyGetDigest, Sign};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmtSignature, TpmtTkVerified};

/// The current policy digest of `session`.
fn policy_digest(sim: &mut Tpm, session: Handle) -> Tpm2bDigest<'static> {
    execute_with_password_sessions(
        sim,
        &PolicyGetDigest {
            policy_session: session,
        },
        0,
        &[],
    )
    .unwrap()
    .policy_digest
}

/// Signs the SHA-256 digest of `message` with the ECDSA-SHA256 key `key` (TPM2_Sign).
#[allow(deprecated)]
fn sign_message(sim: &mut Tpm, key: Handle, message: &[u8]) -> TpmtSignature<'static> {
    execute_with_password_sessions(
        sim,
        &Sign {
            key_handle: key,
            digest: Tpm2bDigest::from_bytes(leak_bytes(&sha256(&[message]))).unwrap(),
            in_scheme: None,
            validation: null_hashcheck(),
        },
        1,
        &[],
    )
    .unwrap()
    .signature
}

/// Runs TPM2_PolicyAuthorize on `session`.
fn policy_authorize(
    sim: &mut Tpm,
    session: Handle,
    approved_policy: Tpm2bDigest<'static>,
    policy_ref: &'static [u8],
    key_sign: Tpm2bName<'static>,
    check_ticket: TpmtTkVerified<'static>,
) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &PolicyAuthorize {
            policy_session: session,
            approved_policy,
            policy_ref: Tpm2bNonce::from_bytes(policy_ref).unwrap(),
            key_sign,
            check_ticket,
        },
        0,
        &[],
    )
    .map(|_| ())
}

/// A `TPM_ST_MESSAGE_VERIFIED` ticket from TPM2_VerifySequenceComplete over *approvedPolicy* ||
/// *policyRef* authorizes the policy; the same ticket with another *policyRef* is
/// `TPM_RC_VALUE` on `checkTicket`.
#[test]
#[cfg(all(
    feature = "cc-verify-sequence-start",
    feature = "cc-verify-sequence-complete"
))]
fn message_verified_ticket_authorizes_policy() {
    let mut sim = Tpm::new();
    let (key, key_name) = create_signing_key(&mut sim);
    let session = start_policy_session(&mut sim).session_handle;
    let approved = policy_digest(&mut sim, session);
    let policy_ref: &'static [u8] = b"policy reference";
    let message = leak_bytes(&[approved.get_buffer(), policy_ref].concat());
    let signature = sign_message(&mut sim, key, message);

    let seq = crate::_common::verify_sequence_start(&mut sim, key, &[], &[], &[]).unwrap();
    crate::_common::sequence_update(&mut sim, seq, message).unwrap();
    let ticket =
        crate::_common::verify_sequence_complete(&mut sim, seq, &[], key, signature).unwrap();

    assert_eq!(
        policy_authorize(
            &mut sim,
            session,
            approved,
            b"other reference",
            key_name,
            ticket
        ),
        Err(rc_at(TpmRc::VALUE, Position::parameter(4)))
    );
    policy_authorize(&mut sim, session, approved, policy_ref, key_name, ticket)
        .expect("the TPM_ST_MESSAGE_VERIFIED ticket authorizes the policy");
}

/// A `TPM_ST_DIGEST_VERIFIED` ticket from TPM2_VerifyDigestSignature over the SHA-256 digest of
/// *approvedPolicy* || *policyRef* authorizes the policy; the same ticket with another
/// *policyRef* is `TPM_RC_VALUE` on `checkTicket`.
#[test]
#[cfg(feature = "cc-verify-digest-signature")]
fn digest_verified_ticket_authorizes_policy() {
    let mut sim = Tpm::new();
    let (key, key_name) = create_signing_key(&mut sim);
    let session = start_policy_session(&mut sim).session_handle;
    let approved = policy_digest(&mut sim, session);
    let policy_ref: &'static [u8] = b"policy reference";
    let message = [approved.get_buffer(), policy_ref].concat();
    let signature = sign_message(&mut sim, key, &message);
    let ticket = crate::_common::verify_digest_signature(
        &mut sim,
        key,
        &[],
        leak_bytes(&sha256(&[&message])),
        signature,
    )
    .unwrap();

    assert_eq!(
        policy_authorize(
            &mut sim,
            session,
            approved,
            b"other reference",
            key_name,
            ticket
        ),
        Err(rc_at(TpmRc::VALUE, Position::parameter(4)))
    );
    policy_authorize(&mut sim, session, approved, policy_ref, key_name, ticket)
        .expect("the TPM_ST_DIGEST_VERIFIED ticket authorizes the policy");
}
