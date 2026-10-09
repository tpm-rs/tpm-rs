//! Smoke tests for the ML-KEM and ML-DSA implementations of the [`RustCrypto`]
//! backend.
//!
//! The known-answer tests check seed-derived public keys against OpenSSL 3.6,
//! the KEM tests check that encapsulation round-trips, and the ML-DSA message
//! encodings (`M'`) are cross-checked against the `ml-dsa` crate.

use hex_literal::hex;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams};
use sha2::{Digest, Sha256};
use tpm2::{
    Tpm2b, Tpm2bKemCiphertext, Tpm2bPublicKeyMldsa, Tpm2bPublicKeyMlkem, Tpm2bSignatureCtx,
    Tpm2bSignatureMldsa, TpmiMldsaParms, TpmiMlkemParms, TpmtHa,
    crypto::{
        Finalize, Mldsa, MldsaMessage, MldsaPrivateKey as _, MldsaPublicKey as _, Mlkem,
        MlkemPrivateKey as _, MlkemPublicKey as _, Random, Update,
    },
};
use tpm2_rustcrypto::{
    ChaChaRng, MldsaPrivateKey, MldsaPublicKey, MlkemPrivateKey, MlkemPublicKey, RustCrypto,
};

/// DER encoding of the SHA-256 OID (2.16.840.1.101.3.4.2.1).
const SHA256_OID: [u8; 11] = hex!("0609608648016503040201");

/// Returns `[0, 1, 2, ..., N - 1]`.
fn counting<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    out.iter_mut().zip(0u8..).for_each(|(b, i)| *b = i);
    out
}

fn rng() -> ChaChaRng {
    RustCrypto.rng_seeded(b"pqc smoke test").unwrap()
}

fn mlkem_encoded(key: &MlkemPublicKey) -> Vec<u8> {
    let mut out = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
    key.encoded(&mut out).unwrap().as_slice().to_vec()
}

fn load_mlkem(set: TpmiMlkemParms, key: &[u8]) -> Option<MlkemPublicKey> {
    let key = Tpm2bPublicKeyMlkem::new(key).unwrap();
    Mlkem::load_public(&RustCrypto, set, key).unwrap()
}

fn mlkem_decapsulate(key: &MlkemPrivateKey, ciphertext: &[u8]) -> Option<[u8; 32]> {
    let ciphertext = Tpm2bKemCiphertext::new(ciphertext).unwrap();
    let mut out = [0u8; 32];
    let shared_secret = Mlkem::decapsulate(&RustCrypto, key, ciphertext, &mut out).unwrap()?;
    Some(shared_secret.as_slice().try_into().unwrap())
}

#[test]
fn mlkem_kats() {
    // SHA-256 of the public keys derived from seed (d || z) = 00 01 .. 3f
    // with `openssl genpkey -algorithm ML-KEM-* -pkeyopt hexseed:...`.
    let cases = [
        (
            TpmiMlkemParms::Mlkem512,
            hex!("3ae268dccc5456ac0d0f9b39257dc48fe081383b97c400512d712b739762daee"),
        ),
        (
            TpmiMlkemParms::Mlkem768,
            hex!("0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"),
        ),
        (
            TpmiMlkemParms::Mlkem1024,
            hex!("c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530"),
        ),
    ];
    let seed = counting::<64>();
    for (set, expected) in cases {
        let key = Mlkem::derive_key(&RustCrypto, set, Tpm2b(&seed)).unwrap();
        assert_eq!(key.public_key().parameter_set(), set);
        let public = mlkem_encoded(key.public_key());
        assert_eq!(public.len(), set.pub_key_bytes());
        assert_eq!(Sha256::digest(&public)[..], expected, "{set:?}");
        let mut out = [0u8; 64];
        assert_eq!(*key.seed(&mut out).unwrap().0, seed);
    }
}

#[test]
fn mlkem_load() {
    let mut rng = rng();
    for set in [
        TpmiMlkemParms::Mlkem512,
        TpmiMlkemParms::Mlkem768,
        TpmiMlkemParms::Mlkem1024,
    ] {
        let key = Mlkem::generate_key(&RustCrypto, &mut rng, set).unwrap();
        let mut public = mlkem_encoded(key.public_key());
        let loaded = load_mlkem(set, &public).unwrap();
        assert_eq!(loaded, *key.public_key());

        let mut seed = [0u8; 64];
        key.seed(&mut seed).unwrap();
        let private = Mlkem::load_private(&RustCrypto, loaded.clone(), Tpm2b(&seed)).unwrap();
        assert_eq!(private.unwrap().public_key(), &loaded);
        seed[0] ^= 1;
        let wrong = Mlkem::load_private(&RustCrypto, loaded, Tpm2b(&seed)).unwrap();
        assert!(wrong.is_none());

        // Wrong length.
        assert!(load_mlkem(set, &public[1..]).is_none());
        // The first coefficient is 0xFFF >= q (fails the modulus check).
        public[0] = 0xFF;
        public[1] |= 0x0F;
        assert!(load_mlkem(set, &public).is_none());
    }
}

#[test]
fn mlkem_encapsulate_decapsulate() {
    let mut rng = rng();
    for set in [
        TpmiMlkemParms::Mlkem512,
        TpmiMlkemParms::Mlkem768,
        TpmiMlkemParms::Mlkem1024,
    ] {
        let key = Mlkem::generate_key(&RustCrypto, &mut rng, set).unwrap();
        let mut ct_buf = [0u8; TpmiMlkemParms::MAX_CT_BYTES];
        let mut ss_buf = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
        let (ciphertext, shared_secret) = Mlkem::encapsulate(
            &RustCrypto,
            &mut rng,
            key.public_key(),
            &mut ct_buf,
            &mut ss_buf,
        )
        .unwrap();
        let mut ciphertext = ciphertext.as_slice().to_vec();
        let shared_secret: [u8; 32] = shared_secret.as_slice().try_into().unwrap();
        assert_eq!(ciphertext.len(), set.ct_bytes());

        assert_eq!(mlkem_decapsulate(&key, &ciphertext), Some(shared_secret));
        assert_eq!(mlkem_decapsulate(&key, &ciphertext[1..]), None);
        // Invalid ciphertexts are implicitly rejected with a different secret.
        ciphertext[0] ^= 1;
        let rejected = mlkem_decapsulate(&key, &ciphertext).unwrap();
        assert_ne!(rejected, shared_secret);
    }
}

fn mldsa_encoded(key: &MldsaPublicKey) -> Vec<u8> {
    let mut out = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
    key.encoded(&mut out).unwrap().as_slice().to_vec()
}

fn load_mldsa(set: TpmiMldsaParms, key: &[u8]) -> Option<MldsaPublicKey> {
    let key = Tpm2bPublicKeyMldsa::new(key).unwrap();
    Mldsa::load_public(&RustCrypto, set, key).unwrap()
}

fn mldsa_sign(rng: &mut ChaChaRng, key: &MldsaPrivateKey, message: MldsaMessage<'_>) -> Vec<u8> {
    let mut out = [0u8; TpmiMldsaParms::MAX_SIG_BYTES];
    let signature = Mldsa::sign(&RustCrypto, rng, key, message, &mut out).unwrap();
    signature.unwrap().as_slice().to_vec()
}

fn mldsa_verify(key: &MldsaPublicKey, message: MldsaMessage<'_>, signature: &[u8]) -> bool {
    let signature = Tpm2bSignatureMldsa::new(signature).unwrap();
    Mldsa::verify(&RustCrypto, key, message, signature).unwrap()
}

/// Verifies `signature` over `M'` with the `ml-dsa` crate (`ML-DSA.Verify_internal`).
fn verify_internal<P: MlDsaParams>(public: &[u8], m_prime: &[u8], signature: &[u8]) -> bool {
    let key = ml_dsa::VerifyingKey::<P>::decode(&public.try_into().unwrap());
    let signature = ml_dsa::Signature::<P>::try_from(signature).unwrap();
    key.verify_internal(m_prime, &signature)
}

fn ml_dsa_verify_internal(
    set: TpmiMldsaParms,
    public: &[u8],
    m_prime: &[u8],
    signature: &[u8],
) -> bool {
    match set {
        TpmiMldsaParms::Mldsa44 => verify_internal::<MlDsa44>(public, m_prime, signature),
        TpmiMldsaParms::Mldsa65 => verify_internal::<MlDsa65>(public, m_prime, signature),
        TpmiMldsaParms::Mldsa87 => verify_internal::<MlDsa87>(public, m_prime, signature),
    }
}

/// Returns `M' = domain || |ctx| || ctx || parts...` (FIPS 204, Algorithms 2 and 4).
fn m_prime(domain: u8, context: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut m_prime = vec![domain, u8::try_from(context.len()).unwrap()];
    m_prime.extend_from_slice(context);
    parts
        .iter()
        .for_each(|part| m_prime.extend_from_slice(part));
    m_prime
}

#[test]
fn mldsa_kats() {
    // SHA-256 of the public keys derived from seed ξ = 00 01 .. 1f with
    // `openssl genpkey -algorithm ML-DSA-* -pkeyopt hexseed:...`.
    let cases = [
        (
            TpmiMldsaParms::Mldsa44,
            hex!("9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46"),
        ),
        (
            TpmiMldsaParms::Mldsa65,
            hex!("d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9"),
        ),
        (
            TpmiMldsaParms::Mldsa87,
            hex!("91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd"),
        ),
    ];
    let seed = counting::<32>();
    for (set, expected) in cases {
        let key = Mldsa::derive_key(&RustCrypto, set, Tpm2b(&seed)).unwrap();
        assert_eq!(key.public_key().parameter_set(), set);
        let public = mldsa_encoded(key.public_key());
        assert_eq!(public.len(), set.pub_key_bytes());
        assert_eq!(Sha256::digest(&public)[..], expected, "{set:?}");
        let mut out = [0u8; 32];
        assert_eq!(*key.seed(&mut out).unwrap().0, seed);
    }
}

#[test]
fn mldsa_load() {
    let mut rng = rng();
    for set in [
        TpmiMldsaParms::Mldsa44,
        TpmiMldsaParms::Mldsa65,
        TpmiMldsaParms::Mldsa87,
    ] {
        let key = Mldsa::generate_key(&RustCrypto, &mut rng, set).unwrap();
        let public = mldsa_encoded(key.public_key());
        let loaded = load_mldsa(set, &public).unwrap();
        assert_eq!(loaded, *key.public_key());
        assert!(load_mldsa(set, &public[1..]).is_none());

        let mut seed = [0u8; 32];
        key.seed(&mut seed).unwrap();
        let private = Mldsa::load_private(&RustCrypto, loaded.clone(), Tpm2b(&seed)).unwrap();
        assert_eq!(private.unwrap().public_key(), &loaded);
        seed[0] ^= 1;
        let wrong = Mldsa::load_private(&RustCrypto, loaded, Tpm2b(&seed)).unwrap();
        assert!(wrong.is_none());
    }
}

#[test]
fn mldsa_sign_verify() {
    let mut rng = rng();
    let context = Tpm2bSignatureCtx::new(b"context").unwrap();
    let message: &[u8] = b"message to be signed";
    let digest: [u8; 32] = Sha256::digest(message).into();
    let pure = MldsaMessage::Pure { context, message };
    let pre_hash = MldsaMessage::PreHash {
        context,
        digest: TpmtHa::Sha256(&digest),
    };
    for set in [
        TpmiMldsaParms::Mldsa44,
        TpmiMldsaParms::Mldsa65,
        TpmiMldsaParms::Mldsa87,
    ] {
        let key = Mldsa::generate_key(&RustCrypto, &mut rng, set).unwrap();
        let public = key.public_key();
        let encoded = mldsa_encoded(public);

        // ML-DSA
        let mut signature = mldsa_sign(&mut rng, &key, pure);
        assert_eq!(signature.len(), set.sig_bytes());
        assert!(mldsa_verify(public, pure, &signature));
        let pure_m_prime = m_prime(0, context.as_slice(), &[message]);
        assert!(ml_dsa_verify_internal(
            set,
            &encoded,
            &pure_m_prime,
            &signature
        ));
        // Signing is hedged.
        assert_ne!(mldsa_sign(&mut rng, &key, pure), signature);

        // HashML-DSA
        let pre_hash_signature = mldsa_sign(&mut rng, &key, pre_hash);
        assert!(mldsa_verify(public, pre_hash, &pre_hash_signature));
        let pre_hash_m_prime = m_prime(1, context.as_slice(), &[&SHA256_OID, &digest]);
        assert!(ml_dsa_verify_internal(
            set,
            &encoded,
            &pre_hash_m_prime,
            &pre_hash_signature
        ));
        assert!(!mldsa_verify(public, pure, &pre_hash_signature));
        assert!(!mldsa_verify(public, pre_hash, &signature));

        // External µ, computed in two parts with `mu_start`.
        let mut mu_context = Mldsa::mu_start(&RustCrypto, public, context).unwrap();
        mu_context.update(&message[..7]).unwrap();
        mu_context.update(&message[7..]).unwrap();
        let mut mu = [0u8; TpmiMldsaParms::MU_BYTES];
        mu_context.finalize(&mut mu).unwrap();
        let external_mu = MldsaMessage::ExternalMu(&mu);
        assert!(mldsa_verify(public, external_mu, &signature));
        let mu_signature = mldsa_sign(&mut rng, &key, external_mu);
        assert!(mldsa_verify(public, pure, &mu_signature));

        // Wrong message, wrong context, and malformed signatures.
        let other = MldsaMessage::Pure {
            context,
            message: b"other message",
        };
        assert!(!mldsa_verify(public, other, &signature));
        let other = MldsaMessage::Pure {
            context: Tpm2bSignatureCtx::new(b"other context").unwrap(),
            message,
        };
        assert!(!mldsa_verify(public, other, &signature));
        assert!(!mldsa_verify(public, pure, &signature[1..]));
        signature[0] ^= 1;
        assert!(!mldsa_verify(public, pure, &signature));
    }
}
