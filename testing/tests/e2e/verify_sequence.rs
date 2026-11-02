//! TPM2_VerifySequenceStart and TPM2_VerifySequenceComplete (TPM 2.0 version 185): verifying a
//! signature over a message accumulated with TPM2_SequenceUpdate (digest schemes and HMAC), the
//! `TPM_ST_MESSAGE_VERIFIED` ticket, the binding of the sequence to the key that started it, the
//! scheme check of the signature, the key/hint/context checks of the start, and the sequence
//! object's lifetime (flushed on success, unchanged on failure).

#![cfg(all(
    feature = "cc-verify-sequence-start",
    feature = "cc-verify-sequence-complete"
))]

use crate::_common::{
    base_attributes, build_raw_cmd, context_load, context_save, create_primary_handle,
    create_primary_with_data_handle, create_signing_key, ecc_template, ecdaa_template,
    execute_with_password_sessions, flush_context, hash_alg_implemented, hash_sequence_start,
    hmac_sha256, hmac_template, leak_bytes, load_external_public, null_hashcheck, rc_at,
    send_with_rc, sequence_update, sequence_update_with_auth, sha256, verify_sequence_complete,
    verify_sequence_start,
};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{ReadPublic, Sign};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bDigest, TpmCc, TpmaObject, TpmiAlgHash, TpmtEccScheme, TpmtHa,
    TpmtKeyedHashScheme, TpmtSignature, TpmtTkVerified,
};

/// Signs the SHA-256 digest of `message` with `key` (its own scheme) using TPM2_Sign.
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
    .expect("TPM2_Sign")
    .signature
}

/// The size of a ticket HMAC (the context integrity hash: SHA-512, or SHA-384 without it).
fn ticket_hmac_size() -> usize {
    if hash_alg_implemented(TpmiAlgHash::Sha512) {
        64
    } else {
        48
    }
}

/// Starts a verification sequence for `key` and adds `blocks` with TPM2_SequenceUpdate.
fn verify_sequence_with(sim: &mut Tpm, key: Handle, blocks: &[&'static [u8]]) -> Handle {
    let seq = verify_sequence_start(sim, key, &[], &[], &[]).unwrap();
    for block in blocks {
        sequence_update(sim, seq, block).unwrap();
    }
    seq
}

/// An HMAC-SHA256 key with the HMAC key `hmac_key`.
fn hmac_key(sim: &mut Tpm, hmac_key: &'static [u8]) -> Handle {
    create_primary_with_data_handle(
        sim,
        hmac_template(
            TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        hmac_key,
    )
}

/// A genuine ECDSA signature over a message in several blocks verifies and gives a
/// `TPM_ST_MESSAGE_VERIFIED` ticket of the key's hierarchy; the ticket depends on the message
/// and is the same for the same message.
#[test]
fn ecdsa_signature_gives_message_verified_ticket() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let signature = sign_message(&mut sim, key, b"verify this message");

    let seq = verify_sequence_with(&mut sim, key, &[b"verify ", b"this ", b"message"]);
    let ticket = verify_sequence_complete(&mut sim, seq, &[], key, signature).unwrap();
    let TpmtTkVerified::MessageVerified(hierarchy, hmac) = ticket else {
        panic!("not a TPM_ST_MESSAGE_VERIFIED ticket: {ticket:?}");
    };
    assert_eq!(hierarchy, Handle::RH_OWNER);
    assert_eq!(hmac.get_buffer().len(), ticket_hmac_size());

    // The same message in other blocks gives the same ticket.
    let seq = verify_sequence_with(&mut sim, key, &[b"verify this", b" message"]);
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], key, signature),
        Ok(ticket)
    );
}

/// An HMAC key verifies the HMAC of the message (not of its digest).
#[test]
fn hmac_signature_over_message_verifies() {
    let mut sim = Tpm::new();
    let key_bytes: &'static [u8] = &[0x24; 32];
    let key = hmac_key(&mut sim, key_bytes);
    let hmac = hmac_sha256(key_bytes, &[b"hmac message"]);
    let signature =
        TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha256, leak_bytes(&hmac)).unwrap());
    let seq = verify_sequence_with(&mut sim, key, &[b"hmac ", b"message"]);
    let ticket = verify_sequence_complete(&mut sim, seq, &[], key, signature).unwrap();
    assert!(matches!(
        ticket,
        TpmtTkVerified::MessageVerified(Handle::RH_OWNER, _)
    ));
}

/// A signature over another message is `TPM_RC_SIGNATURE` on `signature` and leaves the
/// sequence unchanged: a later TPM2_VerifySequenceComplete with the genuine signature succeeds.
#[test]
fn failed_verification_leaves_sequence_intact() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let genuine = sign_message(&mut sim, key, b"the message");
    let other = sign_message(&mut sim, key, b"another message");

    let seq = verify_sequence_with(&mut sim, key, &[b"the message"]);
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], key, other),
        Err(rc_at(TpmRc::SIGNATURE, Position::parameter(1)))
    );
    verify_sequence_complete(&mut sim, seq, &[], key, genuine)
        .expect("the sequence is unchanged after a failed verification");
    // A successful verification flushes the sequence.
    assert!(flush_context(&mut sim, seq).is_err());

    // The same for an HMAC sequence.
    let key_bytes: &'static [u8] = &[0x99; 32];
    let hkey = hmac_key(&mut sim, key_bytes);
    let seq = verify_sequence_with(&mut sim, hkey, &[b"hmac"]);
    let wrong = TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha256, &[0u8; 32]).unwrap());
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], hkey, wrong),
        Err(rc_at(TpmRc::SIGNATURE, Position::parameter(1)))
    );
    let good = hmac_sha256(key_bytes, &[b"hmac"]);
    let good = TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha256, leak_bytes(&good)).unwrap());
    verify_sequence_complete(&mut sim, seq, &[], hkey, good).unwrap();
}

/// A signature whose scheme or hash is not the sequence's scheme is `TPM_RC_SCHEME` on
/// `signature`.
#[test]
fn signature_of_other_scheme_rejected() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let mut signature = sign_message(&mut sim, key, b"scheme");
    if let TpmtSignature::Ecdsa(sig) = &mut signature {
        sig.hash = TpmiAlgHash::Sha384;
    }
    let seq = verify_sequence_with(&mut sim, key, &[b"scheme"]);
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], key, signature),
        Err(rc_at(TpmRc::SCHEME, Position::parameter(1)))
    );
    flush_context(&mut sim, seq).unwrap();

    let key_bytes: &'static [u8] = &[0x77; 32];
    let hkey = hmac_key(&mut sim, key_bytes);
    let seq = verify_sequence_with(&mut sim, hkey, &[b"scheme"]);
    let sha1 = TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha1, &[0u8; 20]).unwrap());
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], hkey, sha1),
        Err(rc_at(TpmRc::SCHEME, Position::parameter(1)))
    );
}

/// The sequence is bound to the Name of the key that started it: another key is
/// `TPM_RC_SIGN_CONTEXT_KEY` on `keyHandle`.
#[test]
fn bound_to_starting_key_name() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    // Another template (noDA), so another key with another Name.
    let other_key = create_primary_handle(
        &mut sim,
        ecc_template(
            base_attributes() | TpmaObject::SIGN_ENCRYPT | TpmaObject::NO_DA,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
    );
    let signature = sign_message(&mut sim, key, b"bound");
    let seq = verify_sequence_with(&mut sim, key, &[b"bound"]);
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], other_key, signature),
        Err(rc_at(TpmRc::SIGN_CONTEXT_KEY, Position::handle(2)))
    );
    verify_sequence_complete(&mut sim, seq, &[], key, signature).unwrap();
}

/// A key in the NULL hierarchy (TPM2_LoadExternal of the public area) verifies and gives a
/// NULL Ticket.
#[test]
fn null_hierarchy_key_gives_null_ticket() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let signature = sign_message(&mut sim, key, b"null hierarchy");
    let public =
        execute_with_password_sessions(&mut sim, &ReadPublic { object_handle: key }, 0, &[])
            .unwrap()
            .out_public
            .0;
    let external = load_external_public(&mut sim, public);
    let seq = verify_sequence_with(&mut sim, external, &[b"null ", b"hierarchy"]);
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], external, signature),
        Ok(TpmtTkVerified::MessageVerified(
            Handle::RH_NULL,
            Tpm2bDigest::default()
        ))
    );
}

/// TPM2_VerifySequenceStart checks the key and the parameters: not a signing key or a restricted
/// HMAC key is `TPM_RC_KEY`, no scheme of its own or ECDAA is `TPM_RC_SCHEME` (on `keyHandle`),
/// a public-only HMAC key is `TPM_RC_KEY`, a non-empty `context` is `TPM_RC_VALUE` on `context`,
/// and a hint, which no algorithm of the profile takes, is `TPM_RC_SIZE` on `hint`.
#[test]
fn start_checks_key_hint_and_context() {
    let mut sim = Tpm::new();
    let cases = [
        (
            ecc_template(base_attributes() | TpmaObject::DECRYPT, None),
            rc_at(TpmRc::KEY, Position::handle(1)),
        ),
        (
            hmac_template(
                TpmaObject::SIGN_ENCRYPT
                    | TpmaObject::USER_WITH_AUTH
                    | TpmaObject::RESTRICTED
                    | TpmaObject::SENSITIVE_DATA_ORIGIN,
                Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            ),
            rc_at(TpmRc::KEY, Position::handle(1)),
        ),
        (
            ecc_template(base_attributes() | TpmaObject::SIGN_ENCRYPT, None),
            rc_at(TpmRc::SCHEME, Position::handle(1)),
        ),
        (
            ecdaa_template(base_attributes() | TpmaObject::SIGN_ENCRYPT),
            rc_at(TpmRc::SCHEME, Position::handle(1)),
        ),
    ];
    for (template, rc) in cases {
        let key = create_primary_handle(&mut sim, template);
        assert_eq!(verify_sequence_start(&mut sim, key, &[], &[], &[]), Err(rc));
        flush_context(&mut sim, key).unwrap();
    }

    // The public area of an HMAC key alone cannot run the HMAC.
    let hkey = hmac_key(&mut sim, &[0x11; 32]);
    let public = execute_with_password_sessions(
        &mut sim,
        &ReadPublic {
            object_handle: hkey,
        },
        0,
        &[],
    )
    .unwrap()
    .out_public
    .0;
    let public_only = load_external_public(&mut sim, public);
    assert_eq!(
        verify_sequence_start(&mut sim, public_only, &[], &[], &[]),
        Err(rc_at(TpmRc::KEY, Position::handle(1)))
    );

    let (key, _) = create_signing_key(&mut sim);
    assert_eq!(
        verify_sequence_start(&mut sim, key, &[], &[], b"c"),
        Err(rc_at(TpmRc::VALUE, Position::parameter(3)))
    );
    // No algorithm of this profile takes a hint (only EdDSA does), so `TPM2B_SIGNATURE_HINT` has
    // no room for any octet (`MAX_SIGNATURE_HINT_SIZE` = 0): a 1-octet hint is `TPM_RC_SIZE`.
    let params = [&[0u8, 0][..], &[0, 1, 0x68], &[0, 0]].concat();
    let cmd = build_raw_cmd(
        0x8001,
        TpmCc::VerifySequenceStart.code(),
        &[key.0],
        None,
        &params,
    );
    assert_eq!(
        send_with_rc(&mut sim, &cmd).0,
        rc_at(TpmRc::SIZE, Position::parameter(2))
    );
}

/// A verification sequence is authorized with its *auth*, and only a verification sequence can
/// be completed by TPM2_VerifySequenceComplete (`TPM_RC_MODE` on `sequenceHandle`).
#[test]
fn sequence_authorization_and_kind() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let signature = sign_message(&mut sim, key, b"auth");
    let seq = verify_sequence_start(&mut sim, key, b"verify pw", &[], &[]).unwrap();
    assert_eq!(
        sequence_update_with_auth(&mut sim, seq, b"wrong", b"auth"),
        Err(rc_at(TpmRc::BAD_AUTH, Position::session(1)))
    );
    sequence_update_with_auth(&mut sim, seq, b"verify pw", b"auth").unwrap();
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, b"wrong", key, signature),
        Err(rc_at(TpmRc::BAD_AUTH, Position::session(1)))
    );
    verify_sequence_complete(&mut sim, seq, b"verify pw", key, signature).unwrap();

    let hash_seq = hash_sequence_start(&mut sim);
    assert_eq!(
        verify_sequence_complete(&mut sim, hash_seq, &[], key, signature),
        Err(rc_at(TpmRc::MODE, Position::handle(1)))
    );
}

/// A verification sequence survives TPM2_ContextSave/TPM2_ContextLoad in the middle of the
/// message, including its running ticket: the ticket equals that of a sequence without the
/// save/load.
#[test]
fn context_save_load_mid_sequence() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let signature = sign_message(&mut sim, key, b"saved and loaded");

    let seq = verify_sequence_with(&mut sim, key, &[b"saved "]);
    let context = context_save(&mut sim, seq);
    flush_context(&mut sim, seq).unwrap();
    let loaded = context_load(&mut sim, context).unwrap();
    sequence_update(&mut sim, loaded, b"and loaded").unwrap();
    let ticket = verify_sequence_complete(&mut sim, loaded, &[], key, signature).unwrap();

    let seq = verify_sequence_with(&mut sim, key, &[b"saved and loaded"]);
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], key, signature),
        Ok(ticket)
    );
}

/// The public point of the ECC key `key` (TPM2_ReadPublic).
#[cfg(feature = "sm2")]
fn ecc_point(sim: &mut Tpm, key: Handle) -> (Vec<u8>, Vec<u8>) {
    let public = execute_with_password_sessions(
        sim,
        &tpm2::commands::ReadPublic { object_handle: key },
        0,
        &[],
    )
    .unwrap()
    .out_public
    .0;
    match public.parms_and_id {
        tpm2::PublicParmsAndId::Ecc(_, point) => {
            (point.x.get_buffer().to_vec(), point.y.get_buffer().to_vec())
        }
        _ => panic!("not an ECC key"),
    }
}

/// An SM2 key verifies a signature over the message with *context* as the identity `ID_A`: a
/// TPM2_Sign signature of `e = H(Z_A || M)` verifies, and the same signature with another
/// identity does not (`TPM_RC_SIGNATURE`).
#[test]
#[cfg(feature = "sm2")]
#[allow(deprecated)]
fn sm2_verifies_message_with_context_as_identity() {
    let mut sim = Tpm::new();
    let key = create_primary_handle(
        &mut sim,
        ecc_template(
            base_attributes() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Sm2(TpmiAlgHash::Sha256)),
        ),
    );
    let (x, y) = ecc_point(&mut sim, key);
    let e = crate::_common::sm2_message_digest(
        tpm2::TpmEccCurve::NistP256,
        &x,
        &y,
        b"id",
        b"sm2 message",
    );
    let signature = execute_with_password_sessions(
        &mut sim,
        &Sign {
            key_handle: key,
            digest: Tpm2bDigest::from_bytes(leak_bytes(&e)).unwrap(),
            in_scheme: None,
            validation: null_hashcheck(),
        },
        1,
        &[],
    )
    .unwrap()
    .signature;

    let seq = verify_sequence_start(&mut sim, key, &[], &[], b"id").unwrap();
    sequence_update(&mut sim, seq, b"sm2 message").unwrap();
    verify_sequence_complete(&mut sim, seq, &[], key, signature).unwrap();

    let seq = verify_sequence_start(&mut sim, key, &[], &[], b"ID").unwrap();
    sequence_update(&mut sim, seq, b"sm2 message").unwrap();
    assert_eq!(
        verify_sequence_complete(&mut sim, seq, &[], key, signature),
        Err(rc_at(TpmRc::SIGNATURE, Position::parameter(1)))
    );
}
