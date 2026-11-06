//! RSA-3072 and RSA-4096 with every backend (the key sizes of `tpm2-engine`'s `rsa3072` and
//! `rsa4096` features): key generation (random and seeded), RSASSA/RSAPSS signing and
//! verification, RSAES/OAEP/raw encryption, and the conversions the engine uses for sensitive
//! areas (prime-only form, CRT form, re-import from the prime), all cross-checked with the `rsa`
//! crate.
//!
//! These key sizes are not part of the TPM's default profile (the `rsa3072`/`rsa4096` features
//! of `tpm2`), so the tests use the providers' backend key types (`Rsa::Rsa3072`,
//! `Rsa::Rsa4096`) directly.

use rsa::BigUint;
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use tpm2::crypto::backend::{PrivateKey, Rsa, RsaKey};
use tpm2::crypto::{CryptoError, Random};
use tpm2::{TpmiAlgHash, TpmtHa};
use tpm2_crypto_tests::TestProvider;

/// The provider's RNG.
type R = <TestProvider as Random>::Rng;
/// The provider's RSA-3072 key.
type Rsa3072 = <TestProvider as Rsa>::Rsa3072;
/// The provider's RSA-4096 key.
type Rsa4096 = <TestProvider as Rsa>::Rsa4096;

/// Runs the generic check `$f` for both larger RSA key sizes under test (3072 and 4096 bits).
macro_rules! for_each_size {
    ($f:ident) => {
        $f::<Rsa3072, 384, 192>(3072);
        $f::<Rsa4096, 512, 256>(4096);
    };
}

/// A generated key: the modulus, the backend's private key and its stored prime.
struct Key<K> {
    modulus: Vec<u8>,
    prime: Vec<u8>,
    key: K,
}

/// Generates a key with `seed` (or the backend's RNG).
fn generate<K: RsaKey<M, P, R>, const M: usize, const P: usize>(seed: Option<&[u8]>) -> Key<K> {
    let mut rng = match seed {
        Some(seed) => TestProvider::from_seed(seed).unwrap(),
        None => TestProvider::from_entropy().unwrap(),
    };
    let key = K::generate(&mut rng, 65537).unwrap();
    let mut modulus = [0u8; M];
    K::store_public(key.as_public(), &mut modulus).unwrap();
    let mut prime = [0u8; P];
    key.store(&mut prime).unwrap();
    Key {
        modulus: modulus.to_vec(),
        prime: prime.to_vec(),
        key,
    }
}

/// The `rsa` crate's view of a backend private key (rebuilt from the modulus and the stored
/// prime).
fn parse<K>(key: &Key<K>) -> rsa::RsaPrivateKey {
    let n = BigUint::from_bytes_be(&key.modulus);
    let p = BigUint::from_bytes_be(&key.prime);
    assert_eq!(&n % &p, BigUint::from(0u32), "the stored prime divides n");
    let q = &n / &p;
    rsa::RsaPrivateKey::from_p_q(p, q, BigUint::from(65537u32)).unwrap()
}

/// A SHA-256 digest.
fn sha256(digest: &[u8; 32]) -> TpmtHa<'_> {
    TpmtHa::Sha256(digest)
}

/// A generated key has a modulus of exactly `bits` bits (top bit set), the default exponent,
/// and two primes of half the size. (The stored private key is the prime, of
/// `PRIME_SIZE = bits / 16` bytes by type; exp's variable-size PKCS#8 blob and its fit in the
/// engine's private-key buffer no longer exist.)
fn check_generated_size<K: RsaKey<M, P, R>, const M: usize, const P: usize>(bits: usize) {
    let key = generate::<K, M, P>(None);
    assert_eq!(key.modulus.len(), bits / 8, "{bits}");
    assert!(key.modulus[0] >= 0x80, "{bits}");
    assert_eq!(K::exponent(key.key.as_public()), 65537, "{bits}");
    let parsed = parse(&key);
    assert_eq!(parsed.n().to_bytes_be(), key.modulus);
    assert_eq!(parsed.e(), &BigUint::from(65537u32));
    assert_eq!(parsed.primes().len(), 2);
    for prime in parsed.primes() {
        assert_eq!(prime.bits(), bits / 2, "{bits}");
    }
    assert_eq!(key.prime.len(), bits / 16, "{bits}");
}

#[test]
fn generated_keys_have_the_requested_size() {
    for_each_size!(check_generated_size);
}

/// Seeded key generation is deterministic, and different seeds give different keys.
fn check_seeded<K: RsaKey<M, P, R>, const M: usize, const P: usize>(bits: usize) {
    let a = generate::<K, M, P>(Some(b"seed one"));
    let b = generate::<K, M, P>(Some(b"seed one"));
    let c = generate::<K, M, P>(Some(b"seed two"));
    assert_eq!(a.modulus, b.modulus, "{bits}");
    assert_eq!(a.prime, b.prime, "{bits}");
    assert_ne!(a.modulus, c.modulus, "{bits}");
}

#[test]
fn seeded_generation_is_deterministic() {
    for_each_size!(check_seeded);
}

/// RSASSA and RSAPSS signatures (as long as the modulus, by type) verify with the backend and
/// the `rsa` crate, and fail to verify after a bit flip.
fn check_signatures<K: RsaKey<M, P, R>, const M: usize, const P: usize>(bits: usize) {
    let key = generate::<K, M, P>(None);
    let public = rsa::RsaPublicKey::from(&parse(&key));
    let mut rng = TestProvider::from_entropy().unwrap();
    let digest = [0x5au8; 32];
    for pss in [false, true] {
        let mut signature = [0u8; M];
        if pss {
            key.key
                .rsapss_sign(&mut rng, sha256(&digest), &mut signature)
                .unwrap();
        } else {
            key.key
                .rsassa_sign(&mut rng, sha256(&digest), &mut signature)
                .unwrap();
        }
        let verify = |signature: &[u8; M]| {
            if pss {
                K::rsapss_verify(key.key.as_public(), sha256(&digest), signature)
            } else {
                K::rsassa_verify(key.key.as_public(), sha256(&digest), signature)
            }
        };
        assert_eq!(verify(&signature), Ok(true), "{bits} pss={pss}");
        if pss {
            public
                .verify(rsa::pss::Pss::new::<sha2::Sha256>(), &digest, &signature)
                .unwrap();
        } else {
            public
                .verify(
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(),
                    &digest,
                    &signature,
                )
                .unwrap();
        }
        signature[M / 2] ^= 1;
        assert_eq!(verify(&signature), Ok(false), "{bits} pss={pss}");
    }
}

#[test]
fn signatures_verify() {
    for_each_size!(check_signatures);
}

/// RSAES, OAEP and raw (`TPM_ALG_NULL`) encryption round-trip, and OAEP ciphertexts of the
/// `rsa` crate decrypt.
fn check_encryption<K: RsaKey<M, P, R>, const M: usize, const P: usize>(bits: usize) {
    let key = generate::<K, M, P>(None);
    let public = key.key.as_public();
    let mut rng = TestProvider::from_entropy().unwrap();
    let message = b"a secret for a large key";

    // RSAES
    let mut ciphertext = [0u8; M];
    match K::rsaes_encrypt(public, &mut rng, message, &mut ciphertext) {
        Ok(res) => {
            res.unwrap();
            let mut plaintext = [0u8; M];
            let len = key
                .key
                .rsaes_decrypt(&mut rng, &ciphertext, &mut plaintext)
                .unwrap()
                .unwrap();
            assert_eq!(&plaintext[..len], message, "{bits} RSAES");
        }
        // Not every backend implements RSAES (whatever the key size).
        Err(CryptoError::Unsupported) => {}
        Err(e) => panic!("{bits} RSAES: {e:?}"),
    }

    // OAEP
    for hash in [TpmiAlgHash::Sha256, TpmiAlgHash::Sha384] {
        let mut ciphertext = [0u8; M];
        K::oaep_encrypt(public, &mut rng, hash, b"", message, &mut ciphertext)
            .unwrap()
            .unwrap();
        let mut plaintext = [0u8; M];
        let len = key
            .key
            .oaep_decrypt(&mut rng, hash, b"", &ciphertext, &mut plaintext)
            .unwrap()
            .unwrap();
        assert_eq!(&plaintext[..len], message, "{bits} OAEP {hash:?}");
    }

    let rsa_public = rsa::RsaPublicKey::from(&parse(&key));
    let ciphertext = rsa_public
        .encrypt(
            &mut rand_core::OsRng,
            rsa::Oaep::new::<sha2::Sha256>(),
            message,
        )
        .unwrap();
    let mut plaintext = [0u8; M];
    let len = key
        .key
        .oaep_decrypt(
            &mut rng,
            TpmiAlgHash::Sha256,
            b"",
            ciphertext.as_slice().try_into().unwrap(),
            &mut plaintext,
        )
        .unwrap()
        .unwrap();
    assert_eq!(&plaintext[..len], message, "{bits}");

    // Raw RSA: m^e^d = m, left-padded to the modulus size.
    let mut data = [0u8; M];
    data[M - 3..].copy_from_slice(&[1, 2, 3]);
    let mut ciphertext = [0u8; M];
    K::raw_encrypt(public, &data, &mut ciphertext)
        .unwrap()
        .unwrap();
    let mut plaintext = [0u8; M];
    key.key
        .raw_decrypt(&mut rng, &ciphertext, &mut plaintext)
        .unwrap()
        .unwrap();
    assert_eq!(plaintext, data, "{bits}");
}

#[test]
fn encryption_round_trips() {
    for_each_size!(check_encryption);
}

/// The prime-only form is a prime of half the modulus size; importing it rebuilds a key that
/// decrypts what the original key's public half encrypted (the other prime of the modulus is
/// accepted too). A prime of another key is rejected.
fn check_prime_import<K: RsaKey<M, P, R>, const M: usize, const P: usize>(bits: usize) {
    let key = generate::<K, M, P>(None);
    let prime: [u8; P] = key.prime.as_slice().try_into().unwrap();
    assert_eq!(prime.len(), bits / 16, "{bits}");
    let parsed = parse(&key);
    assert!(
        parsed.primes().iter().any(|p| p.to_bytes_be() == prime[..]),
        "{bits}"
    );
    let other_factor = parsed
        .primes()
        .iter()
        .map(|p| p.to_bytes_be())
        .find(|p| p[..] != prime[..])
        .unwrap();
    let other_factor: [u8; P] = other_factor.as_slice().try_into().unwrap();

    let load_public = || {
        K::load_public(65537, key.modulus.as_slice().try_into().unwrap())
            .unwrap()
            .unwrap()
    };
    let mut rng = TestProvider::from_entropy().unwrap();
    let message = b"rebuilt from the prime";
    let mut ciphertext = [0u8; M];
    K::oaep_encrypt(
        key.key.as_public(),
        &mut rng,
        TpmiAlgHash::Sha256,
        b"",
        message,
        &mut ciphertext,
    )
    .unwrap()
    .unwrap();
    for p in [prime, other_factor] {
        let imported = K::load(load_public(), &p).unwrap().unwrap();
        let mut plaintext = [0u8; M];
        let len = imported
            .oaep_decrypt(
                &mut rng,
                TpmiAlgHash::Sha256,
                b"",
                &ciphertext,
                &mut plaintext,
            )
            .unwrap()
            .unwrap();
        assert_eq!(&plaintext[..len], message, "{bits}");
    }

    let other = generate::<K, M, P>(None);
    let other_prime: [u8; P] = other.prime.as_slice().try_into().unwrap();
    assert!(
        matches!(K::load(load_public(), &other_prime), Ok(None)),
        "{bits}"
    );
}

#[test]
fn prime_round_trips_through_import() {
    for_each_size!(check_prime_import);
}

/// The CRT form is five values of half the modulus size: `p` (the larger prime), `q`,
/// `dP = e^-1 mod (p - 1)`, `dQ = e^-1 mod (q - 1)` and `qInv = q^-1 mod p`.
fn check_crt<K: RsaKey<M, P, R>, const M: usize, const P: usize>(bits: usize) {
    let key = generate::<K, M, P>(None);
    let mut crt = [[0u8; P]; 5];
    key.key.store_crt(&mut crt).unwrap();
    assert_eq!(crt.as_flattened().len(), 5 * (bits / 16), "{bits}");
    let value = |i: usize| BigUint::from_bytes_be(&crt[i]);
    let (p, q, dp, dq, qinv) = (value(0), value(1), value(2), value(3), value(4));
    let one = BigUint::from(1u32);
    let e = BigUint::from(65537u32);
    assert!(p > q, "{bits}");
    assert_eq!(&p * &q, BigUint::from_bytes_be(&key.modulus), "{bits}");
    assert_eq!((&e * &dp) % (&p - &one), one, "{bits}");
    assert_eq!((&e * &dq) % (&q - &one), one, "{bits}");
    assert_eq!((&q * &qinv) % &p, one, "{bits}");
}

#[test]
fn crt_form_is_consistent() {
    for_each_size!(check_crt);
}

/// A 4096-bit key cannot be built from a 3072-bit modulus's prime: the backend key types take
/// primes of exactly their own size, so the 3072-bit prime (left-padded with zeros to the
/// 4096-bit prime size) does not factor the 4096-bit modulus.
#[test]
fn mismatched_prime_size_is_rejected() {
    let small = generate::<Rsa3072, 384, 192>(None);
    let large = generate::<Rsa4096, 512, 256>(None);
    let mut prime = [0u8; 256];
    prime[256 - 192..].copy_from_slice(&small.prime);
    let public = <Rsa4096 as PrivateKey<512, 256, R, u32>>::load_public(
        65537,
        large.modulus.as_slice().try_into().unwrap(),
    )
    .unwrap()
    .unwrap();
    assert!(matches!(
        <Rsa4096 as PrivateKey<512, 256, R, u32>>::load(public, &prime),
        Ok(None)
    ));
}
