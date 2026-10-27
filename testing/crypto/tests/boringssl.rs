//! Tests for the BoringSSL backend, including the algorithms it doesn't
//! implement.

type C = tpm2_boringssl::BoringSsl;

#[path = "common/suite.rs"]
mod suite;

use tpm2::{
    AlgSym, TpmEccCurve, TpmiAlgHash, TpmiMldsaParms, TpmiMlkemParms, TpmtEccScheme, TpmtHa,
    crypto::{
        CipherInput, CmacContext, CryptoError, Direction, EccPrivateKey, MAX_SIGNATURE_BYTES,
        MldsaPrivateKey, MlkemPrivateKey, Random, SymmetricKey,
        backend::{
            Ecc, EccCurve, EdwardsCurve, Hash, HashState, Mldsa, MldsaKey, Mlkem, MlkemKey,
            PrivateKey, Rsa, RsaKey,
        },
        hash, hmac,
    },
};

/// BoringSSL hash states can be cloned mid-stream.
#[test]
fn hash_state_clone() {
    let mut a = <C as Hash>::Sha256::init().unwrap();
    a.update(b"a").unwrap();
    let mut b = a.clone();
    a.update(b"bc").unwrap();
    b.update(b"bc").unwrap();
    let (mut out_a, mut out_b) = ([0; 32], [0; 32]);
    a.finalize(&mut out_a).unwrap();
    b.finalize(&mut out_b).unwrap();
    let sha256_abc = testing_crypto::vectors::hash::SHA256[1].1;
    assert_eq!((&out_a[..], &out_b[..]), (sha256_abc, sha256_abc));
}

#[test]
fn unsupported_hashes() {
    let mut out = [0; TpmiAlgHash::MAX_DIGEST_BYTES];
    for alg in [
        TpmiAlgHash::Sm3_256,
        TpmiAlgHash::Sha3_256,
        TpmiAlgHash::Sha3_384,
        TpmiAlgHash::Sha3_512,
    ] {
        let result = hash::<C>(alg, &[b"abc"], &mut out);
        assert_eq!(result, Err(CryptoError::Unsupported), "{alg:?}");
        let result = hmac::<C>(alg, b"key", &[b"abc"], &mut out);
        assert_eq!(result, Err(CryptoError::Unsupported), "{alg:?}");
    }
}

#[test]
fn unsupported_ciphers() {
    for (alg, len) in [
        (AlgSym::Sm4_128, 16),
        (AlgSym::Camellia128, 16),
        (AlgSym::Camellia192, 24),
        (AlgSym::Camellia256, 32),
    ] {
        let bytes = [0; 32];
        let key = SymmetricKey::new(alg, &bytes[..len]).unwrap();
        let (mut iv, mut data) = ([0; 16], [0; 16]);
        let input = CipherInput::Ctr(&mut iv, &mut data);
        let result = key.crypt::<C>(Direction::Encrypt, input);
        assert_eq!(result, Err(CryptoError::Unsupported), "{alg:?}");
        let result = CmacContext::<C>::new(key);
        assert!(matches!(result, Err(CryptoError::Unsupported)), "{alg:?}");
    }
}

#[test]
fn unsupported_curves() {
    let mut rng = C::from_seed(b"unsupported_curves").unwrap();
    for curve in [
        TpmEccCurve::NistP192,
        TpmEccCurve::BNP256,
        TpmEccCurve::BNP638,
        TpmEccCurve::SM2P256,
        TpmEccCurve::BpP256R1,
        TpmEccCurve::BpP384R1,
        TpmEccCurve::BpP512R1,
        TpmEccCurve::Curve448,
    ] {
        let result = EccPrivateKey::<C>::generate(&mut rng, curve, None);
        assert!(matches!(result, Err(CryptoError::Unsupported)), "{curve:?}");
    }
    let result =
        EccPrivateKey::<C>::generate(&mut rng, TpmEccCurve::Curve448, Some(TpmtEccScheme::Eddsa));
    assert!(matches!(result, Err(CryptoError::Unsupported)));
}

#[test]
fn unsupported_mlkem512() {
    let mut rng = C::from_seed(b"unsupported_mlkem512").unwrap();
    let result = MlkemPrivateKey::<C>::generate(&mut rng, TpmiMlkemParms::Mlkem512);
    assert!(matches!(result, Err(CryptoError::Unsupported)));
}

/// RSA signatures need a SHA-1 or SHA-2 digest.
#[test]
fn unsupported_rsa_signature_hashes() {
    type Rsa1024 = <C as Rsa>::Rsa1024;
    let mut rng = C::from_seed(b"unsupported_rsa_signature_hashes").unwrap();
    let key = Rsa1024::generate(&mut rng, 65537).unwrap();
    let digest = TpmtHa::new(TpmiAlgHash::Sha3_256, &[0x5a; 32]).unwrap();
    let mut sig = [0; 128];
    let result = key.rsassa_sign(&mut rng, digest, &mut sig);
    assert_eq!(result, Err(CryptoError::Unsupported));
    let result = key.rsapss_sign(&mut rng, digest, &mut sig);
    assert_eq!(result, Err(CryptoError::Unsupported));
}

/// HashML-DSA needs a FIPS 204 approved hash (not SHA-1).
#[test]
fn unsupported_hash_mldsa_sha1() {
    let mut rng = C::from_seed(b"unsupported_hash_mldsa_sha1").unwrap();
    let key = MldsaPrivateKey::<C>::generate(&mut rng, TpmiMldsaParms::Mldsa44).unwrap();
    let mut buf = [0; MAX_SIGNATURE_BYTES];
    let result = key.sign_prehash(&mut rng, TpmiAlgHash::Sha1, b"", &[0; 20], &mut buf);
    assert_eq!(result, Err(CryptoError::Unsupported));
}

/// Operations whose output depends on randomness use BoringSSL's system RNG,
/// so they reject a seeded RNG (rather than silently ignoring it).
#[test]
fn randomized_operations_require_system_rng() {
    let mut seeded = C::from_seed(b"randomized_operations_require_system_rng").unwrap();
    let mut system = C::from_entropy().unwrap();
    let digest = TpmtHa::new(TpmiAlgHash::Sha256, &[0x5a; 32]).unwrap();

    let ecc = <C as Ecc>::NistP256::generate(&mut seeded, ()).unwrap();
    let (mut r, mut s) = ([0; 32], [0; 32]);
    let result = ecc.sign(&mut seeded, digest.digest(), &mut r, &mut s);
    assert_eq!(result, Err(CryptoError::Internal));
    ecc.sign(&mut system, digest.digest(), &mut r, &mut s)
        .unwrap();

    type Rsa1024 = <C as Rsa>::Rsa1024;
    let rsa = Rsa1024::generate(&mut seeded, 65537).unwrap();
    let public = rsa.as_public();
    let mut out = [0; 128];
    let result = rsa.rsapss_sign(&mut seeded, digest, &mut out);
    assert_eq!(result, Err(CryptoError::Internal));
    rsa.rsapss_sign(&mut system, digest, &mut out).unwrap();
    let result = Rsa1024::oaep_encrypt(
        public,
        &mut seeded,
        TpmiAlgHash::Sha256,
        b"",
        b"m",
        &mut out,
    );
    assert_eq!(result, Err(CryptoError::Internal));
    Rsa1024::oaep_encrypt(
        public,
        &mut system,
        TpmiAlgHash::Sha256,
        b"",
        b"m",
        &mut out,
    )
    .unwrap();
    let result = Rsa1024::rsaes_encrypt(public, &mut seeded, b"m", &mut out);
    assert_eq!(result, Err(CryptoError::Internal));
    Rsa1024::rsaes_encrypt(public, &mut system, b"m", &mut out).unwrap();
    // Deterministic operations accept either RNG.
    rsa.rsassa_sign(&mut seeded, digest, &mut out).unwrap();

    let mldsa = <C as Mldsa>::Mldsa44::generate(&mut seeded, ()).unwrap();
    let mut sig = [0; 2420];
    let result = mldsa.sign_mu(&mut seeded, &[0; 64], &mut sig);
    assert_eq!(result, Err(CryptoError::Internal));
    mldsa.sign_mu(&mut system, &[0; 64], &mut sig).unwrap();
    let result = mldsa.sign_message(&mut seeded, b"", &[b"msg"], &mut sig);
    assert_eq!(result, Err(CryptoError::Internal));
    let result = mldsa.sign_prehash(&mut seeded, b"", digest, &mut sig);
    assert_eq!(result, Err(CryptoError::Internal));

    type Mlkem768 = <C as Mlkem>::Mlkem768;
    let mlkem = Mlkem768::generate(&mut seeded, ()).unwrap();
    let (mut ct, mut ss) = ([0; 1088], [0; 32]);
    let result = Mlkem768::encapsulate(mlkem.as_public(), &mut seeded, &mut ct, &mut ss);
    assert_eq!(result, Err(CryptoError::Internal));
    Mlkem768::encapsulate(mlkem.as_public(), &mut system, &mut ct, &mut ss).unwrap();
}

/// Multi-part EdDSA messages are copied into a 4096-byte buffer, as BoringSSL
/// needs them contiguous.
#[test]
fn eddsa_long_multi_part_messages() {
    type Ed25519 = <C as Ecc>::Ed25519;
    let mut rng = C::from_entropy().unwrap();
    let key = Ed25519::generate(&mut rng, ()).unwrap();
    let (a, b) = ([0x41; 2048], [0x42; 2049]);
    let (mut r, mut s) = ([0; 32], [0; 32]);
    let result = key.sign_message(&[&a, &b], &mut r, &mut s);
    assert_eq!(result, Err(CryptoError::Unsupported));
    let result = Ed25519::verify_message(key.as_public(), &[&a, &b], &r, &s);
    assert_eq!(result, Err(CryptoError::Unsupported));
    // A single slice of any length is passed through directly.
    let whole = [a.as_slice(), b.as_slice()].concat();
    key.sign_message(&[&whole], &mut r, &mut s).unwrap();
    assert!(Ed25519::verify_message(key.as_public(), &[&whole], &r, &s).unwrap());
}
