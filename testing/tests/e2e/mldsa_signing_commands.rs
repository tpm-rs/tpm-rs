//! The version 185 signing commands with ML-DSA keys: TPM2_SignSequenceStart/Complete and
//! TPM2_VerifySequenceStart/Complete sign/verify the message with a context string (pure
//! ML-DSA computes `mu` over the whole message), TPM2_SignDigest/TPM2_VerifyDigestSignature
//! sign/verify an externally computed `mu` (only keys with *allowExternalMu*; the verification
//! ticket is a NULL Ticket), and HashML-DSA keys (pre-hashed message) with all of them.

#![cfg(all(
    feature = "mldsa",
    feature = "cc-sign-digest",
    feature = "cc-verify-digest-signature",
    feature = "cc-sign-sequence-start",
    feature = "cc-sign-sequence-complete",
    feature = "cc-verify-sequence-start",
    feature = "cc-verify-sequence-complete"
))]

use crate::_common::{
    base_attrs, context_load, context_save, create_primary_returning_public, flush_context,
    leak_bytes, mldsa_client_key, mldsa_client_sign, mldsa_client_verify_mu, mldsa_public,
    mldsa_public_key, mldsa_pure_mu, mldsa_signature, mldsa_signature_bytes, null_hashcheck, rc_at,
    sequence_update, sign_digest, sign_sequence_complete, sign_sequence_start,
    verify_digest_signature, verify_sequence_complete, verify_sequence_start,
};
use testing::tpm::Tpm;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bDigest, TpmaObject, TpmiAlgHash, TpmiMldsaParms, TpmtTkVerified};

/// The parameter set of the tests (the smallest, for speed).
const PARAMS: TpmiMldsaParms = TpmiMldsaParms::Mldsa44;

/// Creates an unrestricted ML-DSA signing primary key with *allowExternalMu*
/// `allow_external_mu`; returns its handle and verification key.
fn mldsa_key(sim: &mut Tpm, allow_external_mu: bool) -> (Handle, Vec<u8>) {
    let (key, public) = create_primary_returning_public(
        sim,
        mldsa_public(
            PARAMS,
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            allow_external_mu,
        ),
        &[],
    );
    (key, mldsa_public_key(&public).1)
}

/// A signing sequence of a pure ML-DSA key signs the message (given in blocks and in
/// *buffer*) with *context* as the context string: the signature verifies over
/// `mu = SHAKE256(tr || 0 || len(ctx) || ctx || M)`.
#[test]
fn sign_sequence_signs_message_with_context() {
    let mut sim = Tpm::new();
    let (key, public_key) = mldsa_key(&mut sim, false);
    for context in [&b""[..], &b"application context"[..]] {
        let seq = sign_sequence_start(&mut sim, key, &[], leak_bytes(context)).unwrap();
        sequence_update(&mut sim, seq, b"post-quantum ").unwrap();
        let signature = sign_sequence_complete(&mut sim, seq, &[], key, &[], b"message").unwrap();
        let mu = mldsa_pure_mu(&public_key, context, b"post-quantum message");
        assert!(mldsa_client_verify_mu(
            PARAMS,
            &public_key,
            &mu,
            &mldsa_signature_bytes(&signature)
        ));
    }
}

/// A verification sequence of a pure ML-DSA key verifies a signature of the message with the
/// context string *context* and gives a `TPM_ST_MESSAGE_VERIFIED` ticket of the key's
/// hierarchy; with another context the signature is `TPM_RC_SIGNATURE`.
#[test]
fn verify_sequence_verifies_message_with_context() {
    let mut sim = Tpm::new();
    let (key, _) = mldsa_key(&mut sim, false);
    let seq = sign_sequence_start(&mut sim, key, &[], b"ctx").unwrap();
    let signature =
        sign_sequence_complete(&mut sim, seq, &[], key, &[], b"signed message").unwrap();

    let seq = verify_sequence_start(&mut sim, key, &[], &[], b"ctx").unwrap();
    sequence_update(&mut sim, seq, b"signed ").unwrap();
    sequence_update(&mut sim, seq, b"message").unwrap();
    let ticket = verify_sequence_complete(&mut sim, seq, &[], key, signature).unwrap();
    assert!(matches!(
        ticket,
        TpmtTkVerified::MessageVerified(Handle::RH_OWNER, ref hmac) if !hmac.get_buffer().is_empty()
    ));

    let seq = verify_sequence_start(&mut sim, key, &[], &[], b"other").unwrap();
    sequence_update(&mut sim, seq, b"signed message").unwrap();
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], key, signature),
        Err(rc_at(TpmRc::SIGNATURE, Position::parameter(1)))
    );
}

/// A client-side pure ML-DSA signature verifies with the public area of its key loaded by
/// TPM2_LoadExternal (NULL hierarchy: a NULL Ticket).
#[test]
fn verify_sequence_verifies_client_signature() {
    let mut sim = Tpm::new();
    let (seed, public_key) = mldsa_client_key(PARAMS);
    let key = crate::_common::load_external_public(
        &mut sim,
        crate::_common::mldsa_public_with_key(
            PARAMS,
            TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            false,
            &public_key,
        ),
    );
    let signature = mldsa_client_sign(PARAMS, &seed, b"id", b"client message");
    let seq = verify_sequence_start(&mut sim, key, &[], &[], b"id").unwrap();
    sequence_update(&mut sim, seq, b"client message").unwrap();
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], key, mldsa_signature(&signature)),
        Ok(TpmtTkVerified::MessageVerified(
            Handle::RH_NULL,
            Tpm2bDigest::default()
        ))
    );
}

/// A pure ML-DSA signing sequence survives TPM2_ContextSave/TPM2_ContextLoad in the middle of
/// the message (its running `mu` is saved with it).
#[test]
fn sign_sequence_survives_context_save_load() {
    let mut sim = Tpm::new();
    let (key, public_key) = mldsa_key(&mut sim, false);
    let seq = sign_sequence_start(&mut sim, key, &[], b"ctx").unwrap();
    sequence_update(&mut sim, seq, b"saved ").unwrap();
    let context = context_save(&mut sim, seq);
    flush_context(&mut sim, seq).unwrap();
    let loaded = context_load(&mut sim, context).unwrap();
    sequence_update(&mut sim, loaded, b"and ").unwrap();
    let signature = sign_sequence_complete(&mut sim, loaded, &[], key, &[], b"loaded").unwrap();
    let mu = mldsa_pure_mu(&public_key, b"ctx", b"saved and loaded");
    assert!(mldsa_client_verify_mu(
        PARAMS,
        &public_key,
        &mu,
        &mldsa_signature_bytes(&signature)
    ));
}

/// TPM2_SignDigest signs an external `mu` with an *allowExternalMu* key; without
/// *allowExternalMu* the key is `TPM_RC_ATTRIBUTES` on `keyHandle`, a context is `TPM_RC_VALUE`
/// on `context` (it is an input of `mu`), and a `mu` that is not 64 octets is `TPM_RC_SIZE` on
/// `digest`.
#[test]
fn sign_digest_signs_external_mu() {
    let mut sim = Tpm::new();
    let (key, public_key) = mldsa_key(&mut sim, true);
    let mu = mldsa_pure_mu(&public_key, b"", b"external mu");
    let signature = sign_digest(&mut sim, key, &[], leak_bytes(&mu), null_hashcheck()).unwrap();
    assert!(mldsa_client_verify_mu(
        PARAMS,
        &public_key,
        &mu,
        &mldsa_signature_bytes(&signature)
    ));
    assert_eq!(
        sign_digest(&mut sim, key, b"c", leak_bytes(&mu), null_hashcheck()),
        Err(rc_at(TpmRc::VALUE, Position::parameter(1)))
    );
    assert_eq!(
        sign_digest(&mut sim, key, &[], leak_bytes(&mu[..63]), null_hashcheck()),
        Err(rc_at(TpmRc::SIZE, Position::parameter(2)))
    );

    let (no_mu_key, _) = mldsa_key(&mut sim, false);
    assert_eq!(
        sign_digest(&mut sim, no_mu_key, &[], leak_bytes(&mu), null_hashcheck()),
        Err(rc_at(TpmRc::ATTRIBUTES, Position::handle(1)))
    );
}

/// TPM2_VerifyDigestSignature verifies a signature of an external `mu` with an
/// *allowExternalMu* key and gives a NULL `TPM_ST_DIGEST_VERIFIED` ticket (errata: a mu ticket is
/// not useful to TPM2_PolicyAuthorize); a signature of another `mu` is `TPM_RC_SIGNATURE`, and a
/// key without *allowExternalMu* is `TPM_RC_ATTRIBUTES`.
#[test]
fn verify_digest_signature_verifies_external_mu() {
    let mut sim = Tpm::new();
    let (key, public_key) = mldsa_key(&mut sim, true);
    let mu = mldsa_pure_mu(&public_key, b"", b"verified mu");
    let signature = sign_digest(&mut sim, key, &[], leak_bytes(&mu), null_hashcheck()).unwrap();
    assert_eq!(
        verify_digest_signature(&mut sim, key, &[], leak_bytes(&mu), signature),
        Ok(TpmtTkVerified::DigestVerified(
            Handle::RH_NULL,
            TpmiAlgHash::Sha256,
            Tpm2bDigest::default()
        ))
    );
    let other = mldsa_pure_mu(&public_key, b"", b"other mu");
    assert_eq!(
        verify_digest_signature(&mut sim, key, &[], leak_bytes(&other), signature),
        Err(rc_at(TpmRc::SIGNATURE, Position::parameter(3)))
    );
    flush_context(&mut sim, key).unwrap();

    let (no_mu_key, _) = mldsa_key(&mut sim, false);
    assert_eq!(
        verify_digest_signature(&mut sim, no_mu_key, &[], leak_bytes(&mu), signature),
        Err(rc_at(TpmRc::ATTRIBUTES, Position::handle(1)))
    );
}

/// A restricted ML-DSA key cannot sign an external `mu` ("Restricted ML-DSA keys cannot be
/// used with TPM2_SignDigest()"), but signs a message in a sequence (whose first block is
/// checked like any restricted key's).
#[test]
fn restricted_key_signs_only_in_sequences() {
    let mut sim = Tpm::new();
    let (key, public) = create_primary_returning_public(
        &mut sim,
        crate::_common::mldsa_attestation_public(PARAMS),
        &[],
    );
    let public_key = mldsa_public_key(&public).1;
    assert_eq!(
        sign_digest(&mut sim, key, &[], leak_bytes(&[0u8; 64]), null_hashcheck()),
        Err(rc_at(TpmRc::ATTRIBUTES, Position::handle(1)))
    );
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    let signature = sign_sequence_complete(&mut sim, seq, &[], key, &[], b"safe message").unwrap();
    let mu = mldsa_pure_mu(&public_key, b"", b"safe message");
    assert!(mldsa_client_verify_mu(
        PARAMS,
        &public_key,
        &mu,
        &mldsa_signature_bytes(&signature)
    ));
}

/// A HashML-DSA key (pre-hash SHA-256): a signing sequence signs `OID || SHA-256(M)` with the
/// context string, TPM2_SignDigest signs a given SHA-256 digest, and TPM2_VerifyDigestSignature
/// verifies it with an ordinary `TPM_ST_DIGEST_VERIFIED` ticket of the pre-hash.
#[test]
#[cfg(feature = "hash_mldsa")]
fn hash_mldsa_signs_pre_hashed_message() {
    let mut sim = Tpm::new();
    let template = tpm2::TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: base_attrs() | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::HashMldsa(
            tpm2::TpmsHashMldsaParms {
                parameter_set: PARAMS,
                hash_alg: TpmiAlgHash::Sha256,
            },
            tpm2::Tpm2bPublicKeyMldsa::default(),
        ),
    };
    let (key, public) = create_primary_returning_public(&mut sim, template, &[]);
    let public_key = mldsa_public_key(&public).1;
    let hash_mu = |context: &[u8], digest: &[u8]| -> [u8; 64] {
        let tr: [u8; 64] = crate::_common::shake256(&[&public_key]);
        crate::_common::shake256(&[
            &tr,
            &[1, context.len() as u8],
            context,
            crate::_common::hash_mldsa_oid(TpmiAlgHash::Sha256),
            digest,
        ])
    };
    let hashed_signature = |signature: &tpm2::TpmtSignature<'_>| match signature {
        tpm2::TpmtSignature::HashMldsa(sig) => {
            assert_eq!(sig.hash, TpmiAlgHash::Sha256);
            sig.signature.get_buffer().to_vec()
        }
        other => panic!("not a HashML-DSA signature: {other:?}"),
    };

    let seq = sign_sequence_start(&mut sim, key, &[], b"ctx").unwrap();
    sequence_update(&mut sim, seq, b"pre-hashed ").unwrap();
    let signature = sign_sequence_complete(&mut sim, seq, &[], key, &[], b"message").unwrap();
    let digest = crate::_common::sha256(&[b"pre-hashed message"]);
    assert!(mldsa_client_verify_mu(
        PARAMS,
        &public_key,
        &hash_mu(b"ctx", &digest),
        &hashed_signature(&signature)
    ));

    let signature =
        sign_digest(&mut sim, key, b"ctx", leak_bytes(&digest), null_hashcheck()).unwrap();
    assert!(mldsa_client_verify_mu(
        PARAMS,
        &public_key,
        &hash_mu(b"ctx", &digest),
        &hashed_signature(&signature)
    ));
    let ticket =
        verify_digest_signature(&mut sim, key, b"ctx", leak_bytes(&digest), signature).unwrap();
    assert!(matches!(
        ticket,
        TpmtTkVerified::DigestVerified(Handle::RH_OWNER, TpmiAlgHash::Sha256, ref hmac)
            if !hmac.get_buffer().is_empty()
    ));
}

/// An ML-DSA verification sequence with a ticket survives TPM2_ContextSave/TPM2_ContextLoad
/// (its running `mu` and ticket HMAC are saved with it): the loaded sequence gives the same
/// `TPM_ST_MESSAGE_VERIFIED` ticket as one without the save/load.
#[test]
fn verify_sequence_survives_context_save_load() {
    let mut sim = Tpm::new();
    let (key, _) = mldsa_key(&mut sim, false);
    let seq = sign_sequence_start(&mut sim, key, &[], b"ctx").unwrap();
    let signature = sign_sequence_complete(&mut sim, seq, &[], key, &[], b"saved message").unwrap();

    let seq = verify_sequence_start(&mut sim, key, &[], &[], b"ctx").unwrap();
    sequence_update(&mut sim, seq, b"saved ").unwrap();
    let context = context_save(&mut sim, seq);
    flush_context(&mut sim, seq).unwrap();
    let loaded = context_load(&mut sim, context).unwrap();
    sequence_update(&mut sim, loaded, b"message").unwrap();
    let ticket = verify_sequence_complete(&mut sim, loaded, &[], key, signature).unwrap();

    let seq = verify_sequence_start(&mut sim, key, &[], &[], b"ctx").unwrap();
    sequence_update(&mut sim, seq, b"saved message").unwrap();
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], key, signature),
        Ok(ticket)
    );
}

/// A failed ML-DSA verification leaves the sequence unchanged: after `TPM_RC_SIGNATURE`, more
/// of the message can be added and the genuine signature of the whole message verifies.
#[test]
fn failed_verification_leaves_sequence_intact() {
    let mut sim = Tpm::new();
    let (key, _) = mldsa_key(&mut sim, false);
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    let signature = sign_sequence_complete(&mut sim, seq, &[], key, &[], b"first second").unwrap();
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    let partial = sign_sequence_complete(&mut sim, seq, &[], key, &[], b"other").unwrap();

    let seq = verify_sequence_start(&mut sim, key, &[], &[], &[]).unwrap();
    sequence_update(&mut sim, seq, b"first ").unwrap();
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], key, partial),
        Err(rc_at(TpmRc::SIGNATURE, Position::parameter(1)))
    );
    sequence_update(&mut sim, seq, b"second").unwrap();
    verify_sequence_complete(&mut sim, seq, &[], key, signature)
        .expect("the sequence is unchanged after a failed verification");
}
