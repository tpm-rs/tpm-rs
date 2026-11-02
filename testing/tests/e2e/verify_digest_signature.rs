//! TPM2_VerifyDigestSignature (TPM 2.0 version 185): verifying a signature over a digest with
//! the scheme of the key, the `TPM_ST_DIGEST_VERIFIED` ticket, and the key, scheme, digest and
//! context checks.

#![cfg(feature = "cc-verify-digest-signature")]

use crate::_common::{
    base_attributes, create_primary_handle, create_primary_with_data_handle, create_signing_key,
    ecc_template, ecdaa_template, execute_with_password_sessions, flush_context, hmac_template,
    leak_bytes, load_external_public, null_hashcheck, rc_at, sha256, verify_digest_signature,
};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{ReadPublic, Sign};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bDigest, TpmaObject, TpmiAlgHash, TpmtEccScheme, TpmtKeyedHashScheme,
    TpmtSigScheme, TpmtSignature, TpmtTkVerified,
};

/// Signs `digest` with `key` and `scheme` using TPM2_Sign.
#[allow(deprecated)]
fn sign(
    sim: &mut Tpm,
    key: Handle,
    scheme: Option<TpmtSigScheme>,
    digest: &'static [u8],
) -> TpmtSignature<'static> {
    execute_with_password_sessions(
        sim,
        &Sign {
            key_handle: key,
            digest: Tpm2bDigest::from_bytes(digest).unwrap(),
            in_scheme: scheme,
            validation: null_hashcheck(),
        },
        1,
        &[],
    )
    .expect("TPM2_Sign")
    .signature
}

/// The size of a ticket HMAC: the digest size of the context integrity hash (SHA-512, or
/// SHA-384 on a TPM without SHA-512).
fn ticket_hmac_size() -> usize {
    if crate::_common::hash_alg_implemented(TpmiAlgHash::Sha512) {
        64
    } else {
        48
    }
}

/// A genuine ECDSA signature verifies and gives a `TPM_ST_DIGEST_VERIFIED` ticket of the key's
/// hierarchy whose metadata is the scheme's hash algorithm.
#[test]
fn genuine_signature_gives_digest_verified_ticket() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let digest = leak_bytes(&sha256(&[b"verify digest"]));
    let signature = sign(&mut sim, key, None, digest);

    let ticket = verify_digest_signature(&mut sim, key, &[], digest, signature).unwrap();
    let TpmtTkVerified::DigestVerified(hierarchy, hash_alg, hmac) = ticket else {
        panic!("not a TPM_ST_DIGEST_VERIFIED ticket: {ticket:?}");
    };
    assert_eq!(hierarchy, Handle::RH_OWNER);
    assert_eq!(hash_alg, TpmiAlgHash::Sha256);
    assert_eq!(hmac.get_buffer().len(), ticket_hmac_size());

    // The ticket is deterministic: verifying again gives the same HMAC.
    let again = verify_digest_signature(&mut sim, key, &[], digest, signature).unwrap();
    assert_eq!(again, ticket);
}

/// A key in the NULL hierarchy (loaded with TPM2_LoadExternal) gives a NULL Ticket
/// (`TPM_RH_NULL`, empty HMAC) that still carries the hash algorithm.
#[test]
fn null_hierarchy_key_gives_null_ticket() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let digest = leak_bytes(&sha256(&[b"null hierarchy"]));
    let signature = sign(&mut sim, key, None, digest);

    let public =
        execute_with_password_sessions(&mut sim, &ReadPublic { object_handle: key }, 0, &[])
            .unwrap()
            .out_public
            .0;
    let external = load_external_public(&mut sim, public);
    let ticket = verify_digest_signature(&mut sim, external, &[], digest, signature).unwrap();
    assert_eq!(
        ticket,
        TpmtTkVerified::DigestVerified(
            Handle::RH_NULL,
            TpmiAlgHash::Sha256,
            Tpm2bDigest::default()
        )
    );
}

/// A signature over another digest is `TPM_RC_SIGNATURE` on `signature`.
#[test]
fn wrong_signature_rejected() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let signature = sign(&mut sim, key, None, leak_bytes(&sha256(&[b"one"])));
    assert_eq!(
        verify_digest_signature(
            &mut sim,
            key,
            &[],
            leak_bytes(&sha256(&[b"two"])),
            signature
        ),
        Err(rc_at(TpmRc::SIGNATURE, Position::parameter(3)))
    );
}

/// A signature whose scheme or hash is not the key's scheme is `TPM_RC_SCHEME` on `signature`
/// (Part 3: "The TPM will verify that the signing scheme (including the hash or XOF algorithm) in
/// *signature* matches the signing scheme of *keyHandle*").
#[test]
fn signature_of_other_scheme_rejected() {
    let mut sim = Tpm::new();
    // An ECDSA-SHA256 key and a signature that claims SHA-384.
    let (key, _) = create_signing_key(&mut sim);
    let digest = leak_bytes(&[0x11; 32]);
    let mut signature = sign(&mut sim, key, None, digest);
    if let TpmtSignature::Ecdsa(sig) = &mut signature {
        sig.hash = TpmiAlgHash::Sha384;
    }
    assert_eq!(
        verify_digest_signature(&mut sim, key, &[], digest, signature),
        Err(rc_at(TpmRc::SCHEME, Position::parameter(3)))
    );
}

/// A digest that is not the size of the scheme's hash is `TPM_RC_SIZE` on `digest`.
#[test]
fn digest_size_must_match_scheme_hash() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let signature = sign(&mut sim, key, None, leak_bytes(&[0x22; 32]));
    assert_eq!(
        verify_digest_signature(&mut sim, key, &[], &[0x22; 20], signature),
        Err(rc_at(TpmRc::SIZE, Position::parameter(2)))
    );
}

/// A non-empty `context` is `TPM_RC_VALUE` on `context`.
#[test]
fn context_rejected() {
    let mut sim = Tpm::new();
    let (key, _) = create_signing_key(&mut sim);
    let digest = leak_bytes(&[0x33; 32]);
    let signature = sign(&mut sim, key, None, digest);
    assert_eq!(
        verify_digest_signature(&mut sim, key, b"c", digest, signature),
        Err(rc_at(TpmRc::VALUE, Position::parameter(1)))
    );
}

/// An HMAC key (Part 3, "HMAC ... Not supported"), a key without a scheme of its own and an
/// ECDAA key are `TPM_RC_SCHEME` on `keyHandle`.
#[test]
fn key_without_digest_scheme_rejected() {
    let mut sim = Tpm::new();
    let hmac_key = create_primary_with_data_handle(
        &mut sim,
        hmac_template(
            TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        &[0x42; 32],
    );
    let digest = leak_bytes(&[0x44; 32]);
    let hmac_signature = sign(&mut sim, hmac_key, None, digest);
    assert_eq!(
        verify_digest_signature(&mut sim, hmac_key, &[], digest, hmac_signature),
        Err(rc_at(TpmRc::SCHEME, Position::handle(1)))
    );
    flush_context(&mut sim, hmac_key).unwrap();

    let (ecdsa_key, _) = create_signing_key(&mut sim);
    let signature = sign(&mut sim, ecdsa_key, None, digest);
    for template in [
        ecc_template(base_attributes() | TpmaObject::SIGN_ENCRYPT, None),
        ecdaa_template(base_attributes() | TpmaObject::SIGN_ENCRYPT),
    ] {
        let key = create_primary_handle(&mut sim, template);
        assert_eq!(
            verify_digest_signature(&mut sim, key, &[], digest, signature),
            Err(rc_at(TpmRc::SCHEME, Position::handle(1)))
        );
        flush_context(&mut sim, key).unwrap();
    }
}

/// A key without the *sign* attribute is `TPM_RC_ATTRIBUTES` on `keyHandle` (as
/// TPM2_VerifySignature).
#[test]
fn non_signing_key_rejected() {
    let mut sim = Tpm::new();
    let (signer, _) = create_signing_key(&mut sim);
    let digest = leak_bytes(&[0x55; 32]);
    let signature = sign(&mut sim, signer, None, digest);
    let key = create_primary_handle(
        &mut sim,
        ecc_template(
            base_attributes() | TpmaObject::DECRYPT,
            None::<TpmtEccScheme>,
        ),
    );
    assert_eq!(
        verify_digest_signature(&mut sim, key, &[], digest, signature),
        Err(rc_at(TpmRc::ATTRIBUTES, Position::handle(1)))
    );
}
