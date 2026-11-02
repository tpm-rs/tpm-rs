//! RSA-3072 and RSA-4096 with every backend (the key sizes of `tpm2-engine`'s `rsa3072` and
//! `rsa4096` features): key generation (random and seeded), the private-key buffer the engine
//! reserves for them, RSASSA/RSAPSS signing and verification, RSAES/OAEP/raw encryption, and the
//! conversions the engine uses for sensitive areas (prime-only form, CRT form, re-import from the
//! prime), all cross-checked with the `rsa` crate.

use rsa::BigUint;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use tpm2::crypto::CryptoError;
use tpm2::crypto::asymmetric::{Asymmetric, AsymmetricSign, KeyParams, TpmiRsaKeyBits};
use tpm2::{Alg, TpmtHa};
use tpm2_crypto_tests::TestProvider;

/// The larger RSA key sizes under test.
const KEY_BITS: [u16; 2] = [3072, 4096];

/// The capacity of a loaded object's private key in `tpm2-engine` with RSA-4096
/// (`handler::MAX_PRIVATE_KEY_SIZE`: `4.5 * 512 + 128` octets).
const ENGINE_PRIVATE_KEY_CAPACITY_4096: usize = 512 * 9 / 2 + 128;

/// A generated key: the modulus and the backend's private key.
struct Key {
    modulus: Vec<u8>,
    private: Vec<u8>,
}

/// Generates a `bits`-bit key with `seed` (or the backend's RNG).
fn generate(bits: u16, seed: Option<&[u8]>) -> Key {
    let mut public = [0u8; 512];
    let mut private = [0u8; 4096];
    let (pub_len, priv_len) = TestProvider
        .generate_key(
            Alg::RSA,
            Some(KeyParams::Rsa(TpmiRsaKeyBits(bits))),
            &mut public,
            &mut private,
            seed,
        )
        .unwrap();
    Key {
        modulus: public[..pub_len].to_vec(),
        private: private[..priv_len].to_vec(),
    }
}

/// The `rsa` crate's view of a backend private key (PKCS#8 DER).
fn parse(key: &Key) -> rsa::RsaPrivateKey {
    rsa::RsaPrivateKey::from_pkcs8_der(&key.private).unwrap()
}

/// A generated key has a modulus of exactly `bits` bits (top bit set), the default exponent,
/// two primes of half the size, and fits the private-key buffer of the engine.
#[test]
fn generated_keys_have_the_requested_size() {
    for bits in KEY_BITS {
        let key = generate(bits, None);
        assert_eq!(key.modulus.len(), usize::from(bits) / 8, "{bits}");
        assert!(key.modulus[0] >= 0x80, "{bits}");
        let parsed = parse(&key);
        assert_eq!(parsed.n().to_bytes_be(), key.modulus);
        assert_eq!(parsed.e(), &BigUint::from(65537u32));
        assert_eq!(parsed.primes().len(), 2);
        for prime in parsed.primes() {
            assert_eq!(prime.bits(), usize::from(bits) / 2, "{bits}");
        }
        assert!(
            key.private.len() <= ENGINE_PRIVATE_KEY_CAPACITY_4096,
            "{bits}"
        );
    }
}

/// Seeded key generation is deterministic, and different seeds give different keys.
#[test]
fn seeded_generation_is_deterministic() {
    for bits in KEY_BITS {
        let a = generate(bits, Some(b"seed one"));
        let b = generate(bits, Some(b"seed one"));
        let c = generate(bits, Some(b"seed two"));
        assert_eq!(a.modulus, b.modulus, "{bits}");
        assert_ne!(a.modulus, c.modulus, "{bits}");
    }
}

/// RSASSA and RSAPSS signatures are as long as the modulus, verify with the backend and the
/// `rsa` crate, and fail to verify after a bit flip.
#[test]
fn signatures_verify() {
    for bits in KEY_BITS {
        let key = generate(bits, None);
        let public = rsa::RsaPublicKey::from(&parse(&key));
        let digest = [0x5au8; 32];
        for scheme in [Alg::RSASSA, Alg::RSAPSS] {
            let mut signature = [0u8; 512];
            let len = TestProvider
                .sign_inner(
                    scheme,
                    &key.private,
                    TpmtHa::Sha256(&digest),
                    &mut signature,
                )
                .unwrap()
                .unwrap();
            assert_eq!(len, usize::from(bits) / 8, "{bits} {scheme:?}");
            let signature = &mut signature[..len];
            assert_eq!(
                TestProvider.verify_inner(
                    scheme,
                    &key.modulus,
                    0,
                    TpmtHa::Sha256(&digest),
                    signature
                ),
                Ok(true),
                "{bits} {scheme:?}"
            );
            if scheme == Alg::RSASSA {
                public
                    .verify(
                        rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(),
                        &digest,
                        signature,
                    )
                    .unwrap();
            } else {
                public
                    .verify(rsa::pss::Pss::new::<sha2::Sha256>(), &digest, signature)
                    .unwrap();
            }
            signature[len / 2] ^= 1;
            assert_eq!(
                TestProvider.verify_inner(
                    scheme,
                    &key.modulus,
                    0,
                    TpmtHa::Sha256(&digest),
                    signature
                ),
                Ok(false),
                "{bits} {scheme:?}"
            );
        }
    }
}

/// RSAES, OAEP and raw (`TPM_ALG_NULL`) encryption round-trip, and OAEP ciphertexts of the
/// `rsa` crate decrypt.
#[test]
fn encryption_round_trips() {
    for bits in KEY_BITS {
        let key = generate(bits, None);
        let size = usize::from(bits) / 8;
        let message = b"a secret for a large key";
        for (scheme, hash) in [
            (Alg::RSAES, Alg::NULL),
            (Alg::OAEP, Alg::SHA256),
            (Alg::OAEP, Alg::SHA384),
        ] {
            let mut ciphertext = [0u8; 512];
            let len = match TestProvider.encrypt(
                scheme,
                hash,
                &key.modulus,
                0,
                message,
                &mut ciphertext,
                b"",
            ) {
                Ok(len) => len.unwrap(),
                // Not every backend implements RSAES (whatever the key size).
                Err(CryptoError::Unsupported) if scheme == Alg::RSAES => continue,
                Err(e) => panic!("{bits} {scheme:?}: {e:?}"),
            };
            assert_eq!(len, size, "{bits} {scheme:?}");
            let mut plaintext = [0u8; 512];
            let len = TestProvider
                .decrypt(
                    scheme,
                    hash,
                    &key.private,
                    &ciphertext[..len],
                    &mut plaintext,
                    b"",
                )
                .unwrap()
                .unwrap();
            assert_eq!(&plaintext[..len], message, "{bits} {scheme:?}");
        }

        let public = rsa::RsaPublicKey::from(&parse(&key));
        let ciphertext = public
            .encrypt(
                &mut rand_core::OsRng,
                rsa::Oaep::new::<sha2::Sha256>(),
                message,
            )
            .unwrap();
        let mut plaintext = [0u8; 512];
        let len = TestProvider
            .decrypt(
                Alg::OAEP,
                Alg::SHA256,
                &key.private,
                &ciphertext,
                &mut plaintext,
                b"",
            )
            .unwrap()
            .unwrap();
        assert_eq!(&plaintext[..len], message, "{bits}");

        // Raw RSA: m^e^d = m, left-padded to the modulus size.
        let mut data = vec![0u8; size];
        data[size - 3..].copy_from_slice(&[1, 2, 3]);
        let mut ciphertext = [0u8; 512];
        let len = TestProvider
            .encrypt(
                Alg::NULL,
                Alg::NULL,
                &key.modulus,
                0,
                &data,
                &mut ciphertext,
                b"",
            )
            .unwrap()
            .unwrap();
        let mut plaintext = [0u8; 512];
        let len = TestProvider
            .decrypt(
                Alg::NULL,
                Alg::NULL,
                &key.private,
                &ciphertext[..len],
                &mut plaintext,
                b"",
            )
            .unwrap()
            .unwrap();
        assert_eq!(&plaintext[..len], &data[..], "{bits}");
    }
}

/// The prime-only form is a prime of half the modulus size; importing it rebuilds a key that
/// decrypts what the original key's public half encrypted. A prime of another key is rejected.
#[test]
fn prime_round_trips_through_import() {
    for bits in KEY_BITS {
        let key = generate(bits, None);
        let mut prime = [0u8; 256];
        let prime_len = TestProvider
            .rsa_private_key_to_prime_p(&key.private, &mut prime)
            .unwrap()
            .unwrap();
        assert_eq!(prime_len, usize::from(bits) / 16, "{bits}");
        let parsed = parse(&key);
        assert!(
            parsed
                .primes()
                .iter()
                .any(|p| p.to_bytes_be() == prime[..prime_len]),
            "{bits}"
        );

        let mut imported = [0u8; 4096];
        let imported_len = TestProvider
            .rsa_import_private_key(&key.modulus, &prime[..prime_len], 65537, &mut imported)
            .unwrap()
            .unwrap();
        let message = b"rebuilt from the prime";
        let mut ciphertext = [0u8; 512];
        let len = TestProvider
            .encrypt(
                Alg::OAEP,
                Alg::SHA256,
                &key.modulus,
                0,
                message,
                &mut ciphertext,
                b"",
            )
            .unwrap()
            .unwrap();
        let mut plaintext = [0u8; 512];
        let len = TestProvider
            .decrypt(
                Alg::OAEP,
                Alg::SHA256,
                &imported[..imported_len],
                &ciphertext[..len],
                &mut plaintext,
                b"",
            )
            .unwrap()
            .unwrap();
        assert_eq!(&plaintext[..len], message, "{bits}");

        let other = generate(bits, None);
        let mut other_prime = [0u8; 256];
        let other_len = TestProvider
            .rsa_private_key_to_prime_p(&other.private, &mut other_prime)
            .unwrap()
            .unwrap();
        assert_eq!(
            TestProvider.rsa_import_private_key(
                &key.modulus,
                &other_prime[..other_len],
                65537,
                &mut imported
            ),
            Ok(None),
            "{bits}"
        );
    }
}

/// The CRT form is five values of half the modulus size: `p` (the larger prime), `q`,
/// `dP = e^-1 mod (p - 1)`, `dQ = e^-1 mod (q - 1)` and `qInv = q^-1 mod p`.
#[test]
fn crt_form_is_consistent() {
    for bits in KEY_BITS {
        let key = generate(bits, None);
        let mut crt = [0u8; 5 * 256];
        let len = TestProvider
            .rsa_private_key_to_crt(&key.private, &mut crt)
            .unwrap()
            .unwrap();
        let size = usize::from(bits) / 16;
        assert_eq!(len, 5 * size, "{bits}");
        let value = |i: usize| BigUint::from_bytes_be(&crt[i * size..(i + 1) * size]);
        let (p, q, dp, dq, qinv) = (value(0), value(1), value(2), value(3), value(4));
        let one = BigUint::from(1u32);
        let e = BigUint::from(65537u32);
        assert!(p > q, "{bits}");
        assert_eq!(&p * &q, BigUint::from_bytes_be(&key.modulus), "{bits}");
        assert_eq!((&e * &dp) % (&p - &one), one, "{bits}");
        assert_eq!((&e * &dq) % (&q - &one), one, "{bits}");
        assert_eq!((&q * &qinv) % &p, one, "{bits}");
    }
}

/// A 4096-bit key cannot be built from a 3072-bit modulus's prime and vice versa: the sizes of
/// the modulus and the prime must match.
#[test]
fn mismatched_prime_size_is_rejected() {
    let small = generate(3072, None);
    let large = generate(4096, None);
    let mut prime = [0u8; 256];
    let prime_len = TestProvider
        .rsa_private_key_to_prime_p(&small.private, &mut prime)
        .unwrap()
        .unwrap();
    let mut imported = [0u8; 4096];
    assert_eq!(
        TestProvider.rsa_import_private_key(
            &large.modulus,
            &prime[..prime_len],
            65537,
            &mut imported
        ),
        Ok(None)
    );
}
