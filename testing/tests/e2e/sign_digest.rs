//! TPM2_SignDigest (TPM 2.0 version 185): signing a digest with the scheme of the key, the
//! hash-check ticket of restricted keys, and the key, scheme and context checks.

#![cfg(feature = "cc-sign-digest")]

use crate::_common::{
    base_attributes, commit, create_primary_handle, create_primary_with_data_handle,
    create_signing_key, ecc_template, ecdaa_template, exec_pws, execute_with_password_sessions,
    hmac_template, leak_bytes, null_hashcheck, rc_at, rsa_signing_template_with, sha256,
    sign_digest,
};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{Hash, Sign, VerifySignature};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bDigest, Tpm2bMaxBuffer, TpmaObject, TpmiAlgHash, TpmtEccScheme,
    TpmtKeyedHashScheme, TpmtSignature, TpmtTkHashcheck,
};

/// A SHA-256 digest of `message`, leaked for the `'static` command helpers.
fn digest_of(message: &[u8]) -> &'static [u8] {
    crate::_common::leak_bytes(&sha256(&[message]))
}

/// An ECDSA signature made by TPM2_SignDigest verifies with TPM2_VerifySignature over the same
/// digest, and carries the key's scheme (ECDSA with SHA-256).
#[test]
#[allow(deprecated)]
fn ecdsa_signature_verifies() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let digest = digest_of(b"sign digest message");

    let signature = sign_digest(&mut sim, key, &[], digest, null_hashcheck()).unwrap();
    let TpmtSignature::Ecdsa(ecdsa) = signature else {
        panic!("not an ECDSA signature: {signature:?}");
    };
    assert_eq!(ecdsa.hash, TpmiAlgHash::Sha256);

    execute_with_password_sessions(
        &mut sim,
        &VerifySignature {
            key_handle: key,
            digest: Tpm2bDigest::from_bytes(digest).unwrap(),
            signature,
        },
        0,
        &[],
    )
    .expect("TPM2_VerifySignature of the TPM2_SignDigest signature");
}

/// An RSASSA signature (deterministic) made by TPM2_SignDigest is byte-identical to the
/// TPM2_Sign signature of the same digest with the key's scheme.
#[test]
#[allow(deprecated)]
fn rsassa_signature_matches_sign() {
    let mut sim = Tpm::new();
    let key = create_primary_handle(&mut sim, rsa_signing_template_with(TpmaObject::default()));
    let digest = digest_of(b"rsassa");

    let signature = sign_digest(&mut sim, key, &[], digest, null_hashcheck()).unwrap();
    let expected = execute_with_password_sessions(
        &mut sim,
        &Sign {
            key_handle: key,
            digest: Tpm2bDigest::from_bytes(digest).unwrap(),
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

/// A restricted signing key signs a digest only with a valid hash-check ticket: a NULL ticket
/// is `TPM_RC_TICKET` on `validation`, the ticket of TPM2_Hash over a safe message works.
#[test]
fn restricted_key_requires_ticket() {
    let mut sim = Tpm::new();
    let key = create_primary_handle(
        &mut sim,
        ecc_template(
            base_attributes() | TpmaObject::SIGN_ENCRYPT | TpmaObject::RESTRICTED,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
    );
    let message: &'static [u8] = b"a message that is safe to sign";
    let digest = digest_of(message);

    assert_eq!(
        sign_digest(&mut sim, key, &[], digest, null_hashcheck()),
        Err(rc_at(TpmRc::TICKET, Position::parameter(3)))
    );

    let hash = execute_with_password_sessions(
        &mut sim,
        &Hash {
            data: Tpm2bMaxBuffer::from_bytes(message).unwrap(),
            hash_alg: TpmiAlgHash::Sha256,
            hierarchy: Handle::RH_OWNER,
        },
        0,
        &[],
    )
    .unwrap();
    assert_eq!(hash.out_hash.get_buffer(), digest);
    let validation: TpmtTkHashcheck<'static> = hash.validation;
    sign_digest(&mut sim, key, &[], digest, validation).expect("signing with a valid ticket");
}

/// Without a ticket, a digest that is not the size of the scheme's hash is `TPM_RC_SIZE` on
/// `digest`.
#[test]
fn digest_size_must_match_scheme_hash() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    assert_eq!(
        sign_digest(&mut sim, key, &[], &[0x5A; 48], null_hashcheck()),
        Err(rc_at(TpmRc::SIZE, Position::parameter(2)))
    );
}

/// An HMAC key cannot sign a digest (its scheme signs the message: Part 3, "HMAC ... Not
/// supported"): `TPM_RC_SCHEME` on `keyHandle`.
#[test]
fn hmac_key_rejected() {
    let mut sim = Tpm::new();
    let key = create_primary_with_data_handle(
        &mut sim,
        hmac_template(
            TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        &[0x42; 32],
    );
    assert_eq!(
        sign_digest(&mut sim, key, &[], digest_of(b"x"), null_hashcheck()),
        Err(rc_at(TpmRc::SCHEME, Position::handle(1)))
    );
}

/// A key without a signing scheme of its own (the command cannot override the scheme) is
/// `TPM_RC_SCHEME` on `keyHandle`.
#[test]
fn key_without_scheme_rejected() {
    let mut sim = Tpm::new();
    let key = create_primary_handle(
        &mut sim,
        ecc_template(base_attributes() | TpmaObject::SIGN_ENCRYPT, None),
    );
    assert_eq!(
        sign_digest(&mut sim, key, &[], digest_of(b"x"), null_hashcheck()),
        Err(rc_at(TpmRc::SCHEME, Position::handle(1)))
    );
}

/// An ECDAA key takes the commit counter of TPM2_Commit from `context` (Part 2,
/// TPMU_SIGNATURE_CTX `commitCount`): the signature is an ECDAA signature, the counter is
/// consumed (signing again with it is `TPM_RC_VALUE`), and a `context` that is not a 2-octet
/// counter is `TPM_RC_VALUE` on `context`.
#[test]
fn ecdaa_key_takes_commit_counter_from_context() {
    let mut sim = Tpm::new();
    let key = create_primary_handle(
        &mut sim,
        ecdaa_template(base_attributes() | TpmaObject::SIGN_ENCRYPT),
    );
    for context in [&b""[..], &b"1"[..]] {
        assert_eq!(
            sign_digest(
                &mut sim,
                key,
                leak_bytes(context),
                digest_of(b"x"),
                null_hashcheck()
            ),
            Err(rc_at(TpmRc::VALUE, Position::parameter(1)))
        );
    }

    let counter = commit(&mut sim, key, &[]).unwrap();
    let context = leak_bytes(&counter.to_be_bytes());
    let signature = sign_digest(
        &mut sim,
        key,
        context,
        digest_of(b"ecdaa"),
        null_hashcheck(),
    )
    .expect("ECDAA signature with the commit counter");
    assert_eq!(signature.sig_alg(), tpm2::Alg::ECDAA);
    assert_eq!(signature.hash_alg(), Some(TpmiAlgHash::Sha256));
    // The commitment can never be used again.
    assert_eq!(
        sign_digest(
            &mut sim,
            key,
            context,
            digest_of(b"ecdaa"),
            null_hashcheck()
        ),
        Err(TpmRc::VALUE.get())
    );
}

/// A non-empty signing `context` is `TPM_RC_VALUE` on `context` for a key whose scheme has no
/// use for it (every scheme but ECDAA of an RSA, ECC or keyed-hash key).
#[test]
fn context_rejected() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    assert_eq!(
        sign_digest(&mut sim, key, b"c", digest_of(b"x"), null_hashcheck()),
        Err(rc_at(TpmRc::VALUE, Position::parameter(1)))
    );
}

/// A key without the *sign* attribute is `TPM_RC_KEY` on `keyHandle`, and an *x509sign* key
/// is `TPM_RC_ATTRIBUTES` on `keyHandle`.
#[test]
fn key_attributes_checked() {
    let mut sim = Tpm::new();
    let decrypt_key = create_primary_handle(
        &mut sim,
        ecc_template(base_attributes() | TpmaObject::DECRYPT, None),
    );
    assert_eq!(
        sign_digest(
            &mut sim,
            decrypt_key,
            &[],
            digest_of(b"x"),
            null_hashcheck()
        ),
        Err(rc_at(TpmRc::KEY, Position::handle(1)))
    );

    let x509_key = create_primary_handle(
        &mut sim,
        ecc_template(
            base_attributes() | TpmaObject::SIGN_ENCRYPT | TpmaObject::X509_SIGN,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
    );
    assert_eq!(
        sign_digest(&mut sim, x509_key, &[], digest_of(b"x"), null_hashcheck()),
        Err(rc_at(TpmRc::ATTRIBUTES, Position::handle(1)))
    );
}

/// The key handle needs USER authorization: without a session the command fails with
/// `TPM_RC_AUTH_MISSING`, with a wrong password with `TPM_RC_AUTH_FAIL` (the key is
/// DA-protected).
#[test]
fn key_authorization_required() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let cmd = tpm2::commands::SignDigest {
        key_handle: key,
        context: tpm2::Tpm2bSignatureCtx::default(),
        digest: Tpm2bDigest::from_bytes(digest_of(b"x")).unwrap(),
        validation: null_hashcheck(),
    };
    assert_eq!(
        exec_pws(&mut sim, &cmd, &[]).unwrap_err(),
        TpmRc::AUTH_MISSING.get()
    );
    assert_eq!(
        exec_pws(&mut sim, &cmd, &[b"wrong"]).unwrap_err(),
        TpmRc::AUTH_FAIL
            .with(tpm2::errors::Position::session(1))
            .get()
    );
}

/// The signature uses the key's scheme even though the command has no *inScheme*: an RSAPSS
/// key produces an RSAPSS signature with the key's hash.
#[test]
#[allow(deprecated)]
fn signature_uses_key_scheme() {
    let mut sim = Tpm::new();
    let mut template = rsa_signing_template_with(TpmaObject::default());
    if let tpm2::PublicParmsAndId::Rsa(parms, _) = &mut template.parms_and_id {
        parms.scheme = Some(tpm2::TpmtRsaScheme::Rsapss(TpmiAlgHash::Sha384));
    }
    let key = create_primary_handle(&mut sim, template);
    let digest = crate::_common::leak_bytes(&[0x33; 48]);
    let signature = sign_digest(&mut sim, key, &[], digest, null_hashcheck()).unwrap();
    assert_eq!(signature.sig_alg(), tpm2::Alg::RSAPSS);
    execute_with_password_sessions(
        &mut sim,
        &VerifySignature {
            key_handle: key,
            digest: Tpm2bDigest::from_bytes(digest).unwrap(),
            signature,
        },
        0,
        &[],
    )
    .expect("RSAPSS-SHA384 signature verifies");
}
