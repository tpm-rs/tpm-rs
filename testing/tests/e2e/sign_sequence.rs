//! TPM2_SignSequenceStart and TPM2_SignSequenceComplete (TPM 2.0 version 185): signing a
//! message accumulated with TPM2_SequenceUpdate (digest schemes and HMAC), the binding of the
//! sequence to the key that started it, the restricted-key check of the first block, the
//! key/scheme/context checks of the start, and the sequence object's lifetime.

#![cfg(all(
    feature = "cc-sign-sequence-start",
    feature = "cc-sign-sequence-complete"
))]

use crate::_common::{
    base_attributes, commit, context_load, context_save, create_primary_handle,
    create_primary_with_data_handle, create_signing_key, ecc_template, ecdaa_template,
    execute_with_password_sessions, flush_context, hash_sequence_start, hmac_sha256, hmac_template,
    leak_bytes, null_hashcheck, rc_at, rsa_signing_template_with, sequence_update,
    sequence_update_with_auth, sha256, sign_sequence_complete, sign_sequence_start,
};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{SequenceComplete, Sign, VerifySignature};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bDigest, Tpm2bMaxBuffer, TpmaObject, TpmiAlgHash, TpmtEccScheme,
    TpmtKeyedHashScheme, TpmtSignature,
};

/// `TPM_GENERATED_VALUE`, the first octets of every TPM-generated structure.
const TPM_GENERATED: &[u8] = &[0xFF, b'T', b'C', b'G'];

/// Verifies `signature` over the SHA-256 digest of `message` with TPM2_VerifySignature.
#[allow(deprecated)]
fn verify(sim: &mut Tpm, key: Handle, message: &[u8], signature: TpmtSignature<'static>) {
    execute_with_password_sessions(
        sim,
        &VerifySignature {
            key_handle: key,
            digest: Tpm2bDigest::from_bytes(leak_bytes(&sha256(&[message]))).unwrap(),
            signature,
        },
        0,
        &[],
    )
    .expect("TPM2_VerifySignature of the sequence signature");
}

/// A restricted ECDSA-SHA256 signing key.
fn restricted_ecdsa_key(sim: &mut Tpm) -> Handle {
    create_primary_handle(
        sim,
        ecc_template(
            base_attributes() | TpmaObject::SIGN_ENCRYPT | TpmaObject::RESTRICTED,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
    )
}

/// An ECDSA signature over a message given in two TPM2_SequenceUpdate blocks and the
/// *buffer* of TPM2_SignSequenceComplete verifies over the SHA-256 digest of the whole message.
#[test]
fn ecdsa_signature_over_updates_and_buffer() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    sequence_update(&mut sim, seq, b"first block, ").unwrap();
    sequence_update(&mut sim, seq, b"second block, ").unwrap();
    let signature = sign_sequence_complete(&mut sim, seq, &[], key, &[], b"last part").unwrap();
    assert_eq!(signature.sig_alg(), tpm2::Alg::ECDSA);
    verify(
        &mut sim,
        key,
        b"first block, second block, last part",
        signature,
    );
}

/// A message that fits in *buffer* is signed without any TPM2_SequenceUpdate, and an empty
/// message is signed too.
#[test]
fn message_in_buffer_only() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    for message in [&b"whole message"[..], &b""[..]] {
        let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
        let signature =
            sign_sequence_complete(&mut sim, seq, &[], key, &[], leak_bytes(message)).unwrap();
        verify(&mut sim, key, message, signature);
    }
}

/// An HMAC key signs the message itself: the signature is the HMAC of the message with the
/// key's HMAC key and hash.
#[test]
fn hmac_signature_is_hmac_of_message() {
    let mut sim = Tpm::new();
    let hmac_key = [0x42u8; 32];
    let key = create_primary_with_data_handle(
        &mut sim,
        hmac_template(
            TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        leak_bytes(&hmac_key),
    );
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    sequence_update(&mut sim, seq, b"hmac ").unwrap();
    let signature = sign_sequence_complete(&mut sim, seq, &[], key, &[], b"message").unwrap();
    let TpmtSignature::Hmac(ha) = signature else {
        panic!("not an HMAC signature: {signature:?}");
    };
    assert_eq!(ha.hash_alg(), TpmiAlgHash::Sha256);
    assert_eq!(ha.digest(), hmac_sha256(&hmac_key, &[b"hmac message"]));
}

/// An RSASSA signature (deterministic) of a sequence equals the TPM2_Sign signature of the
/// SHA-256 digest of the message.
#[test]
#[allow(deprecated)]
fn rsassa_signature_matches_sign_of_digest() {
    let mut sim = Tpm::new();
    let key = create_primary_handle(&mut sim, rsa_signing_template_with(TpmaObject::default()));
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    sequence_update(&mut sim, seq, b"rsassa ").unwrap();
    let signature = sign_sequence_complete(&mut sim, seq, &[], key, &[], b"sequence").unwrap();
    let expected = execute_with_password_sessions(
        &mut sim,
        &Sign {
            key_handle: key,
            digest: Tpm2bDigest::from_bytes(leak_bytes(&sha256(&[b"rsassa sequence"]))).unwrap(),
            in_scheme: None,
            validation: null_hashcheck(),
        },
        1,
        &[],
    )
    .unwrap()
    .signature;
    assert_eq!(signature, expected);
}

/// The sequence is bound to the Name of the key that started it: another key is
/// `TPM_RC_SIGN_CONTEXT_KEY` on `keyHandle` (and leaves the sequence intact), the same key
/// loaded again under another handle completes it.
#[test]
fn bound_to_starting_key_name() {
    let mut sim = Tpm::new();
    let template = ecc_template(
        base_attributes() | TpmaObject::SIGN_ENCRYPT | TpmaObject::NO_DA,
        Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
    );
    let key = create_primary_handle(&mut sim, template);
    // Another template (without noDA), so another key with another Name.
    let (other_key, _) = create_signing_key(&mut sim);
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    sequence_update(&mut sim, seq, b"bound ").unwrap();

    assert_eq!(
        sign_sequence_complete(&mut sim, seq, &[], other_key, &[], b"x"),
        Err(rc_at(TpmRc::SIGN_CONTEXT_KEY, Position::handle(2)))
    );
    flush_context(&mut sim, other_key).unwrap();
    // A sequence object has the Empty Buffer as its Name.
    let other_seq = hash_sequence_start(&mut sim);
    assert_eq!(
        sign_sequence_complete(&mut sim, seq, &[], other_seq, &[], b"x"),
        Err(rc_at(TpmRc::SIGN_CONTEXT_KEY, Position::handle(2)))
    );
    flush_context(&mut sim, other_seq).unwrap();

    // The primary key is derived from the seed and the template: flushing and creating it
    // again gives the same key (same Name) under another handle.
    flush_context(&mut sim, key).unwrap();
    let same_key = create_primary_handle(&mut sim, template);
    let signature = sign_sequence_complete(&mut sim, seq, &[], same_key, &[], b"key").unwrap();
    verify(&mut sim, same_key, b"bound key", signature);
}

/// With a restricted key, the message must not begin with `TPM_GENERATED_VALUE`, and its first
/// block must be long enough to tell: a first block that begins with it or is shorter than it
/// is `TPM_RC_VALUE` on `buffer` (the sequence stays loaded); a safe message is signed.
#[test]
fn restricted_key_checks_first_block() {
    let mut sim = Tpm::new();
    let key = restricted_ecdsa_key(&mut sim);

    let generated = [TPM_GENERATED, b" attestation"].concat();
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    assert_eq!(
        sign_sequence_complete(&mut sim, seq, &[], key, &[], leak_bytes(&generated)),
        Err(rc_at(TpmRc::VALUE, Position::parameter(1)))
    );
    // The same applies when TPM_GENERATED_VALUE comes in the first TPM2_SequenceUpdate.
    sequence_update(&mut sim, seq, leak_bytes(&generated)).unwrap();
    assert_eq!(
        sign_sequence_complete(&mut sim, seq, &[], key, &[], b"tail"),
        Err(rc_at(TpmRc::VALUE, Position::parameter(1)))
    );
    flush_context(&mut sim, seq).unwrap();

    // A first block shorter than TPM_GENERATED_VALUE is not safe, whatever follows.
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    sequence_update(&mut sim, seq, b"ab").unwrap();
    assert_eq!(
        sign_sequence_complete(&mut sim, seq, &[], key, &[], b"cdefgh"),
        Err(rc_at(TpmRc::VALUE, Position::parameter(1)))
    );
    flush_context(&mut sim, seq).unwrap();

    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    sequence_update(&mut sim, seq, b"safe message ").unwrap();
    let signature = sign_sequence_complete(&mut sim, seq, &[], key, &[], leak_bytes(TPM_GENERATED))
        .expect("TPM_GENERATED_VALUE after the first block is fine");
    verify(
        &mut sim,
        key,
        &[b"safe message ", TPM_GENERATED].concat(),
        signature,
    );
}

/// TPM2_SignSequenceStart checks the key: not a signing key or a restricted HMAC key is
/// `TPM_RC_KEY`, *x509sign* is `TPM_RC_ATTRIBUTES`, no scheme of its own is `TPM_RC_SCHEME` (all
/// on `keyHandle`), and a non-empty `context` for a scheme without a use for it is
/// `TPM_RC_VALUE` on `context`.
#[test]
fn start_checks_key_scheme_and_context() {
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
            ecc_template(
                base_attributes() | TpmaObject::SIGN_ENCRYPT | TpmaObject::X509_SIGN,
                Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
            ),
            rc_at(TpmRc::ATTRIBUTES, Position::handle(1)),
        ),
        (
            ecc_template(base_attributes() | TpmaObject::SIGN_ENCRYPT, None),
            rc_at(TpmRc::SCHEME, Position::handle(1)),
        ),
    ];
    for (template, rc) in cases {
        let key = create_primary_handle(&mut sim, template);
        assert_eq!(sign_sequence_start(&mut sim, key, &[], &[]), Err(rc));
        flush_context(&mut sim, key).unwrap();
    }

    let (key, _) = create_signing_key(&mut sim);
    assert_eq!(
        sign_sequence_start(&mut sim, key, &[], b"c"),
        Err(rc_at(TpmRc::VALUE, Position::parameter(2)))
    );
    // A sequence object is not a signing key.
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    assert_eq!(
        sign_sequence_start(&mut sim, seq, &[], &[]),
        Err(rc_at(TpmRc::KEY, Position::handle(1)))
    );
}

/// The sequence is authorized with the *auth* of TPM2_SignSequenceStart and the key with its
/// own authValue: a wrong password is `TPM_RC_BAD_AUTH` on the session of the sequence (a
/// sequence object is not DA-protected) and `TPM_RC_AUTH_FAIL` on that of the (DA-protected)
/// key.
#[test]
fn sequence_and_key_authorization() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let seq = sign_sequence_start(&mut sim, key, b"sequence password", &[]).unwrap();

    assert_eq!(
        sequence_update_with_auth(&mut sim, seq, b"wrong", b"data"),
        Err(rc_at(TpmRc::BAD_AUTH, Position::session(1)))
    );
    sequence_update_with_auth(&mut sim, seq, b"sequence password", b"data").unwrap();
    assert_eq!(
        sign_sequence_complete(&mut sim, seq, b"wrong", key, &[], b""),
        Err(rc_at(TpmRc::BAD_AUTH, Position::session(1)))
    );
    assert_eq!(
        sign_sequence_complete(&mut sim, seq, b"sequence password", key, b"wrong", b""),
        Err(rc_at(TpmRc::AUTH_FAIL, Position::session(2)))
    );
    let signature =
        sign_sequence_complete(&mut sim, seq, b"sequence password", key, &[], b"").unwrap();
    verify(&mut sim, key, b"data", signature);
}

/// A signing sequence cannot be completed by TPM2_SequenceComplete, and a hash sequence cannot
/// be completed by TPM2_SignSequenceComplete: both are `TPM_RC_MODE` on `sequenceHandle`.
#[test]
fn other_sequence_kinds_rejected() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    assert_eq!(
        execute_with_password_sessions(
            &mut sim,
            &SequenceComplete {
                sequence_handle: seq,
                buffer: Tpm2bMaxBuffer::default(),
                hierarchy: Handle::RH_NULL,
            },
            1,
            &[],
        )
        .map(|_| ()),
        Err(rc_at(TpmRc::MODE, Position::handle(1)))
    );

    let hash_seq = hash_sequence_start(&mut sim);
    assert_eq!(
        sign_sequence_complete(&mut sim, hash_seq, &[], key, &[], b""),
        Err(rc_at(TpmRc::MODE, Position::handle(1)))
    );
    // A key is not a sequence either.
    assert_eq!(
        sign_sequence_complete(&mut sim, key, &[], key, &[], b""),
        Err(rc_at(TpmRc::MODE, Position::handle(1)))
    );
}

/// TPM2_SignSequenceComplete flushes the sequence object.
#[test]
fn complete_flushes_sequence() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let seq = sign_sequence_start(&mut sim, key, &[], &[]).unwrap();
    sign_sequence_complete(&mut sim, seq, &[], key, &[], b"flush").unwrap();
    assert!(flush_context(&mut sim, seq).is_err());
    assert!(sequence_update(&mut sim, seq, b"more").is_err());
}

/// A signing sequence survives TPM2_ContextSave/TPM2_ContextLoad in the middle of the message:
/// the loaded sequence continues the message and signs it.
#[test]
fn context_save_load_mid_sequence() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let seq = sign_sequence_start(&mut sim, key, b"pw", &[]).unwrap();
    sequence_update_with_auth(&mut sim, seq, b"pw", b"saved ").unwrap();
    let context = context_save(&mut sim, seq);
    flush_context(&mut sim, seq).unwrap();
    let loaded = context_load(&mut sim, context).unwrap();
    sequence_update_with_auth(&mut sim, loaded, b"pw", b"and ").unwrap();
    let signature = sign_sequence_complete(&mut sim, loaded, b"pw", key, &[], b"loaded").unwrap();
    verify(&mut sim, key, b"saved and loaded", signature);
}

/// An ECDAA key takes the commit counter of TPM2_Commit from the `context` of
/// TPM2_SignSequenceStart ("If the scheme of *keyHandle* uses a counter value (e.g.,
/// TPM\_ALG\_ECDAA), then *context* shall contain the counter value from `TPM2_Commit()`"): the
/// sequence produces an ECDAA signature and consumes the commitment, so a second sequence with
/// the same counter fails with `TPM_RC_VALUE`; a `context` that is not a 2-octet counter is
/// `TPM_RC_VALUE` on `context`.
#[test]
fn ecdaa_key_takes_commit_counter_from_context() {
    let mut sim = Tpm::new();
    let key = create_primary_handle(
        &mut sim,
        ecdaa_template(base_attributes() | TpmaObject::SIGN_ENCRYPT),
    );
    for context in [&b""[..], &b"1"[..]] {
        assert_eq!(
            sign_sequence_start(&mut sim, key, &[], leak_bytes(context)),
            Err(rc_at(TpmRc::VALUE, Position::parameter(2)))
        );
    }

    let counter = commit(&mut sim, key, &[]).unwrap();
    let context = leak_bytes(&counter.to_be_bytes());
    let seq = sign_sequence_start(&mut sim, key, &[], context).unwrap();
    sequence_update(&mut sim, seq, b"anonymous ").unwrap();
    let signature = sign_sequence_complete(&mut sim, seq, &[], key, &[], b"message").unwrap();
    assert_eq!(signature.sig_alg(), tpm2::Alg::ECDAA);

    let seq = sign_sequence_start(&mut sim, key, &[], context).unwrap();
    assert_eq!(
        sign_sequence_complete(&mut sim, seq, &[], key, &[], b"again"),
        Err(TpmRc::VALUE.get())
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

/// An SM2 key signs the message with *context* as the identity `ID_A` (Part 3, "SM2 ...
/// Signs/verifies the message using the provided *context* as *ID_A*"): the signature verifies
/// with TPM2_VerifySignature over `e = H(Z_A || M)` (Part 1, "SM2 Sign"), for an empty and a
/// non-empty identity.
#[test]
#[cfg(feature = "sm2")]
#[allow(deprecated)]
fn sm2_signs_message_with_context_as_identity() {
    let mut sim = Tpm::new();
    let key = create_primary_handle(
        &mut sim,
        ecc_template(
            base_attributes() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Sm2(TpmiAlgHash::Sha256)),
        ),
    );
    let (x, y) = ecc_point(&mut sim, key);
    for id in [&b""[..], &b"12"[..]] {
        let seq = sign_sequence_start(&mut sim, key, &[], leak_bytes(id)).unwrap();
        sequence_update(&mut sim, seq, b"sm2 ").unwrap();
        let signature = sign_sequence_complete(&mut sim, seq, &[], key, &[], b"message").unwrap();
        assert_eq!(signature.sig_alg(), tpm2::Alg::SM2);
        let e = crate::_common::sm2_message_digest(
            tpm2::TpmEccCurve::NistP256,
            &x,
            &y,
            id,
            b"sm2 message",
        );
        execute_with_password_sessions(
            &mut sim,
            &VerifySignature {
                key_handle: key,
                digest: Tpm2bDigest::from_bytes(leak_bytes(&e)).unwrap(),
                signature,
            },
            0,
            &[],
        )
        .expect("the SM2 signature is over e = H(Z_A || M)");
    }
}
