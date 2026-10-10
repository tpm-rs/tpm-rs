//! Tests for [`Rsa`] keys and encryption.
//!
//! Most tests use fixed keys (one per size, with `e = 65537`) so that they
//! don't depend on (slow) key generation.

use tpm2::{
    Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmiAlgHash, TpmiRsaKeyBits,
    crypto::{Rsa, RsaEncryptScheme, RsaPrivateKey, RsaPublicKey},
};

use crate::{
    Caps, Check, expect_support,
    util::{HASHES, RSA_KEY_BITS, add_be, assert_bytes, flip, pattern, seeded_rng},
    vectors::rsa as kat,
};

/// The default public exponent.
const E: u32 = 65537;

/// Returns the size of an RSA modulus in bytes.
pub(crate) fn bytes(bits: TpmiRsaKeyBits) -> usize {
    usize::from(bits.as_u16()) / 8
}

/// Returns the fixed `(modulus, prime p)` of the test key of size `bits`.
pub(crate) fn fixed_key(bits: TpmiRsaKeyBits) -> (&'static [u8], &'static [u8]) {
    match bits {
        TpmiRsaKeyBits::Rsa1024 => (&kat::N1024, &kat::P1024),
        TpmiRsaKeyBits::Rsa2048 => (&kat::N2048, &kat::P2048),
        TpmiRsaKeyBits::Rsa3072 => (&kat::N3072, &kat::P3072),
        TpmiRsaKeyBits::Rsa4096 => (&kat::N4096, &kat::P4096),
    }
}

/// Loads an RSA public key, returning `None` if it is rejected.
pub(crate) fn load_public<C: Rsa>(
    c: &C,
    bits: TpmiRsaKeyBits,
    exponent: u32,
    modulus: &[u8],
) -> Option<C::PublicKey> {
    let modulus = Tpm2bPublicKeyRsa::new(modulus).expect("modulus too long");
    Rsa::load_public(c, bits, exponent, modulus).check("Rsa::load_public")
}

/// Loads an RSA private key, returning `None` if it is rejected.
pub(crate) fn load_private<C: Rsa>(c: &C, public: C::PublicKey, p: &[u8]) -> Option<C::PrivateKey> {
    let p = Tpm2bPrivateKeyRsa::new(p).expect("prime too long");
    Rsa::load_private(c, public, p).check("Rsa::load_private")
}

/// Loads the fixed test key of size `bits`, or returns `None` if the size is
/// (correctly) unsupported.
pub(crate) fn load_fixed<C: Rsa>(
    c: &C,
    caps: &Caps,
    bits: TpmiRsaKeyBits,
) -> Option<C::PrivateKey> {
    let (n, p) = fixed_key(bits);
    let modulus = Tpm2bPublicKeyRsa::new(n).expect("modulus too long");
    let result = Rsa::load_public(c, bits, E, modulus);
    let public = expect_support(
        caps.rsa.contains(&bits),
        format!("RSA-{}", bits.as_u16()),
        result,
    )?
    .unwrap_or_else(|| panic!("fixed RSA-{} public key rejected", bits.as_u16()));
    let private = load_private(c, public, p);
    Some(private.unwrap_or_else(|| panic!("fixed RSA-{} private key rejected", bits.as_u16())))
}

/// Returns the modulus of `key`.
pub(crate) fn modulus<K: RsaPublicKey>(key: &K) -> Vec<u8> {
    let mut out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    key.modulus(&mut out)
        .check("RsaPublicKey::modulus")
        .as_slice()
        .to_vec()
}

/// Returns the prime `p` of `key`.
pub(crate) fn prime<K: RsaPrivateKey>(key: &K) -> Vec<u8> {
    let mut out = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    key.prime_p(&mut out)
        .check("RsaPrivateKey::prime_p")
        .as_slice()
        .to_vec()
}

/// Returns `true` if `scheme` is expected to be supported.
pub(crate) fn scheme_supported(caps: &Caps, scheme: RsaEncryptScheme<'_>) -> bool {
    match scheme {
        RsaEncryptScheme::Raw => caps.rsa_raw,
        RsaEncryptScheme::Rsaes => caps.rsaes,
        RsaEncryptScheme::Oaep { hash, .. } => caps.oaep.contains(&hash),
    }
}

/// Encrypts `message`, returning `Err` if the scheme is unsupported and
/// `Ok(None)` if `message` is invalid for the key and scheme.
pub(crate) fn encrypt<C: Rsa>(
    c: &C,
    rng: &mut C::Rng,
    key: &C::PublicKey,
    scheme: RsaEncryptScheme<'_>,
    message: &[u8],
) -> Result<Option<Vec<u8>>, tpm2::crypto::CryptoError> {
    let mut out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let ciphertext = Rsa::encrypt(c, rng, key, scheme, message, &mut out)?;
    Ok(ciphertext.map(|c| c.as_slice().to_vec()))
}

/// Decrypts `ciphertext`, returning `Err` if the scheme is unsupported and
/// `Ok(None)` if the ciphertext is invalid.
pub(crate) fn decrypt<C: Rsa>(
    c: &C,
    key: &C::PrivateKey,
    scheme: RsaEncryptScheme<'_>,
    ciphertext: &[u8],
) -> Result<Option<Vec<u8>>, tpm2::crypto::CryptoError> {
    let mut out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let plaintext = Rsa::decrypt(c, key, scheme, ciphertext, &mut out)?;
    Ok(plaintext.map(|p| p.as_slice().to_vec()))
}

/// Returns the maximum message length of `scheme` for a `k`-byte modulus.
fn max_message_len(scheme: RsaEncryptScheme<'_>, k: usize) -> Option<usize> {
    match scheme {
        RsaEncryptScheme::Raw => Some(k),
        RsaEncryptScheme::Rsaes => k.checked_sub(11),
        RsaEncryptScheme::Oaep { hash, .. } => k.checked_sub(2 * hash.digest_size() + 2),
    }
}

/// The fixed keys load, report their size and exponent, and round-trip their
/// modulus and prime. An exponent of `0` means `65537`.
pub fn rsa_load_fixed_keys<C: Rsa>(c: &C, caps: &Caps) {
    for &bits in RSA_KEY_BITS {
        let Some(private) = load_fixed(c, caps, bits) else {
            continue;
        };
        let (n, p) = fixed_key(bits);
        let public = private.public_key();
        assert_eq!(public.bits(), bits);
        assert_eq!(public.exponent(), E);
        assert_bytes(
            &modulus(public),
            n,
            format!("RSA-{} modulus", bits.as_u16()),
        );
        // The prime must be one of the two factors of the right size: check
        // that it loads.
        let prime = prime(&private);
        assert_eq!(prime.len(), p.len(), "RSA-{} prime size", bits.as_u16());
        let reloaded = load_public(c, bits, E, n).expect("public key rejected");
        assert!(
            load_private(c, reloaded, &prime).is_some(),
            "exported prime rejected"
        );

        let default = load_public(c, bits, 0, n).expect("public key with exponent 0 rejected");
        assert_eq!(default.exponent(), E, "exponent 0 should mean 65537");
    }
}

/// Invalid public and private keys are rejected with `Ok(None)`.
pub fn rsa_load_rejects_invalid<C: Rsa>(c: &C, caps: &Caps) {
    for &bits in RSA_KEY_BITS {
        if load_fixed(c, caps, bits).is_none() {
            continue;
        }
        let (n, p) = fixed_key(bits);
        let k = bytes(bits);
        let size = bits.as_u16();
        // Moduli of the wrong length, or zero.
        assert!(
            load_public(c, bits, E, &n[1..]).is_none(),
            "RSA-{size}: short modulus accepted"
        );
        if k < Tpm2bPublicKeyRsa::CAP {
            let long = [n, &[0x01]].concat();
            assert!(
                load_public(c, bits, E, &long).is_none(),
                "RSA-{size}: long modulus accepted"
            );
        }
        assert!(
            load_public(c, bits, E, &vec![0; k]).is_none(),
            "RSA-{size}: zero modulus accepted"
        );
        // Exponents that are too small or even.
        for exponent in [1, 2] {
            assert!(
                load_public(c, bits, exponent, n).is_none(),
                "RSA-{size}: exponent {exponent} accepted"
            );
        }
        // Primes that aren't a factor of the modulus.
        let not_factors: [&[u8]; 5] = [&[], &[0x00], &[0x01], &add_be(p, 2), &[0x02; 8]];
        for bad in not_factors {
            let public = load_public(c, bits, E, n).expect("public key rejected");
            assert!(
                load_private(c, public, bad).is_none(),
                "RSA-{size}: bad prime accepted"
            );
        }
        if k <= Tpm2bPrivateKeyRsa::CAP {
            // p = n (so q = 1).
            let public = load_public(c, bits, E, n).expect("public key rejected");
            assert!(
                load_private(c, public, n).is_none(),
                "RSA-{size}: p = n accepted"
            );
        }
    }
}

/// Raw RSA (`TPM_ALG_NULL`) known answer: `c = m^e mod n`, with the leading
/// zeros of the plaintext preserved on decryption.
pub fn rsa_raw_kat<C: Rsa>(c: &C, caps: &Caps) {
    let Some(key) = load_fixed(c, caps, TpmiRsaKeyBits::Rsa2048) else {
        return;
    };
    let mut rng = seeded_rng(c, "rsa_raw_kat");
    let scheme = RsaEncryptScheme::Raw;
    let result = encrypt(c, &mut rng, key.public_key(), scheme, &kat::RAW_M2048);
    let Some(ciphertext) = expect_support(caps.rsa_raw, "raw RSA", result) else {
        return;
    };
    let ciphertext = ciphertext.expect("valid raw plaintext rejected");
    assert_bytes(&ciphertext, &kat::RAW_C2048, "raw RSA encryption");
    let plaintext = decrypt(c, &key, scheme, &kat::RAW_C2048).check("raw RSA decryption");
    assert_bytes(
        &plaintext.expect("valid ciphertext rejected"),
        &kat::RAW_M2048,
        "raw RSA decryption",
    );
}

/// RSAES-PKCS1-v1_5 and OAEP (SHA-1, and SHA-256 with a label) ciphertexts
/// produced by another implementation decrypt correctly.
pub fn rsa_decrypt_kat<C: Rsa>(c: &C, caps: &Caps) {
    let Some(key) = load_fixed(c, caps, TpmiRsaKeyBits::Rsa2048) else {
        return;
    };
    let cases = [
        (RsaEncryptScheme::Rsaes, &kat::RSAES_C2048),
        (
            RsaEncryptScheme::Oaep {
                hash: TpmiAlgHash::Sha1,
                label: b"",
            },
            &kat::OAEP_SHA1_C2048,
        ),
        (
            RsaEncryptScheme::Oaep {
                hash: TpmiAlgHash::Sha256,
                label: b"DUPLICATE\0",
            },
            &kat::OAEP_SHA256_C2048,
        ),
    ];
    for (scheme, ciphertext) in cases {
        let result = decrypt(c, &key, scheme, ciphertext);
        let Some(plaintext) = expect_support(
            scheme_supported(caps, scheme),
            format!("{scheme:?}"),
            result,
        ) else {
            continue;
        };
        let plaintext =
            plaintext.unwrap_or_else(|| panic!("{scheme:?}: valid ciphertext rejected"));
        assert_bytes(&plaintext, kat::MESSAGE, format!("{scheme:?} decryption"));
    }
}

/// Encryption round-trips for every scheme (and OAEP hash, with and without a
/// label) and key size, for empty and maximum-length messages. Randomized
/// schemes give different ciphertexts each time.
pub fn rsa_encrypt_decrypt<C: Rsa>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "rsa_encrypt_decrypt");
    for &bits in RSA_KEY_BITS {
        let Some(key) = load_fixed(c, caps, bits) else {
            continue;
        };
        let k = bytes(bits);
        let mut schemes = vec![RsaEncryptScheme::Raw, RsaEncryptScheme::Rsaes];
        // Only the 2048-bit key is tested with every OAEP hash, as the
        // private key operations of the larger keys are slow.
        for &hash in HASHES {
            if bits == TpmiRsaKeyBits::Rsa2048 || hash == TpmiAlgHash::Sha256 {
                schemes.push(RsaEncryptScheme::Oaep { hash, label: b"" });
            }
        }
        schemes.push(RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha256,
            label: b"DUPLICATE\0",
        });

        for scheme in schemes {
            let what = format!("RSA-{} {scheme:?}", bits.as_u16());
            let Some(max) = max_message_len(scheme, k) else {
                // The padding doesn't fit, so every message is too long.
                let result = encrypt(c, &mut rng, key.public_key(), scheme, b"");
                if let Some(ciphertext) =
                    expect_support(scheme_supported(caps, scheme), &what, result)
                {
                    assert!(
                        ciphertext.is_none(),
                        "{what}: message accepted although no message fits"
                    );
                }
                continue;
            };
            let messages = match scheme {
                // Raw plaintexts are integers less than the modulus.
                RsaEncryptScheme::Raw => {
                    vec![vec![0u8; k], [&[0u8][..], &pattern(k - 1, 10)].concat()]
                }
                _ => vec![Vec::new(), pattern(max, 11)],
            };
            for message in messages {
                let result = encrypt(c, &mut rng, key.public_key(), scheme, &message);
                let Some(ciphertext) =
                    expect_support(scheme_supported(caps, scheme), &what, result)
                else {
                    break;
                };
                let ciphertext =
                    ciphertext.unwrap_or_else(|| panic!("{what}: valid message rejected"));
                assert_eq!(ciphertext.len(), k, "{what}: ciphertext size");
                let plaintext = decrypt(c, &key, scheme, &ciphertext).check(&what);
                let plaintext = plaintext.unwrap_or_else(|| panic!("{what}: ciphertext rejected"));
                assert_bytes(
                    &plaintext,
                    &message,
                    format!("{what} of {} bytes", message.len()),
                );

                if scheme != RsaEncryptScheme::Raw {
                    let again = encrypt(c, &mut rng, key.public_key(), scheme, &message)
                        .check(&what)
                        .expect("valid message rejected");
                    assert_ne!(again, ciphertext, "{what}: encryption isn't randomized");
                }
            }
        }
    }
}

/// Messages that are too long (or not less than the modulus) are rejected
/// with `Ok(None)`.
pub fn rsa_encrypt_rejects_invalid<C: Rsa>(c: &C, caps: &Caps) {
    let Some(key) = load_fixed(c, caps, TpmiRsaKeyBits::Rsa2048) else {
        return;
    };
    let mut rng = seeded_rng(c, "rsa_encrypt_rejects_invalid");
    let (n, _) = fixed_key(TpmiRsaKeyBits::Rsa2048);
    let k = n.len();
    let oaep = RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label: b"",
    };
    let cases: [(RsaEncryptScheme<'_>, Vec<u8>); 5] = [
        (RsaEncryptScheme::Raw, n.to_vec()),
        (RsaEncryptScheme::Raw, vec![0xFF; k]),
        (RsaEncryptScheme::Raw, [&[0x01][..], n].concat()),
        (RsaEncryptScheme::Rsaes, pattern(k - 10, 12)),
        (oaep, pattern(k - 2 * 32 - 1, 13)),
    ];
    for (scheme, message) in cases {
        let what = format!("{scheme:?} with a {}-byte message", message.len());
        let result = encrypt(c, &mut rng, key.public_key(), scheme, &message);
        if let Some(ciphertext) = expect_support(scheme_supported(caps, scheme), &what, result) {
            assert!(ciphertext.is_none(), "{what}: accepted");
        }
    }
}

/// Invalid ciphertexts are rejected with `Ok(None)`: values not less than the
/// modulus, oversized inputs, corrupted padding, and the wrong OAEP label or
/// scheme.
pub fn rsa_decrypt_rejects_invalid<C: Rsa>(c: &C, caps: &Caps) {
    let Some(key) = load_fixed(c, caps, TpmiRsaKeyBits::Rsa2048) else {
        return;
    };
    let (n, _) = fixed_key(TpmiRsaKeyBits::Rsa2048);
    let k = n.len();
    let oaep_sha1 = RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha1,
        label: b"",
    };
    let oaep_sha256 = RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label: b"DUPLICATE\0",
    };
    let cases: [(RsaEncryptScheme<'_>, Vec<u8>, &str); 10] = [
        (RsaEncryptScheme::Raw, n.to_vec(), "ciphertext = n"),
        (RsaEncryptScheme::Raw, vec![0xFF; k], "ciphertext > n"),
        (
            RsaEncryptScheme::Raw,
            [&[0x01][..], &kat::RAW_C2048].concat(),
            "oversized ciphertext",
        ),
        (
            RsaEncryptScheme::Rsaes,
            flip(&kat::RSAES_C2048, k / 2),
            "corrupted ciphertext",
        ),
        (
            RsaEncryptScheme::Rsaes,
            kat::OAEP_SHA1_C2048.to_vec(),
            "OAEP ciphertext",
        ),
        (
            oaep_sha1,
            flip(&kat::OAEP_SHA1_C2048, k / 2),
            "corrupted ciphertext",
        ),
        (oaep_sha1, kat::RSAES_C2048.to_vec(), "RSAES ciphertext"),
        (
            oaep_sha256,
            kat::OAEP_SHA1_C2048.to_vec(),
            "ciphertext with the wrong hash",
        ),
        (
            RsaEncryptScheme::Oaep {
                hash: TpmiAlgHash::Sha256,
                label: b"DUPLICATE",
            },
            kat::OAEP_SHA256_C2048.to_vec(),
            "wrong label",
        ),
        (
            RsaEncryptScheme::Oaep {
                hash: TpmiAlgHash::Sha256,
                label: b"",
            },
            kat::OAEP_SHA256_C2048.to_vec(),
            "missing label",
        ),
    ];
    for (scheme, ciphertext, why) in cases {
        let what = format!("{scheme:?}: {why}");
        let result = decrypt(c, &key, scheme, &ciphertext);
        if let Some(plaintext) = expect_support(scheme_supported(caps, scheme), &what, result) {
            assert!(plaintext.is_none(), "{what}: accepted");
        }
    }
}

/// Generated keys (of the sizes that are fast enough to generate) have the
/// right size and exponent, round-trip through their modulus and prime, and
/// work for encryption.
pub fn rsa_generate_key<C: Rsa>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "rsa_generate_key");
    for bits in [TpmiRsaKeyBits::Rsa1024, TpmiRsaKeyBits::Rsa2048] {
        let result = Rsa::generate_key(c, &mut rng, bits, 0);
        let Some(key) = expect_support(
            caps.rsa.contains(&bits),
            format!("RSA-{}", bits.as_u16()),
            result,
        ) else {
            continue;
        };
        let size = bits.as_u16();
        let public = key.public_key();
        assert_eq!(public.bits(), bits);
        assert_eq!(
            public.exponent(),
            E,
            "RSA-{size}: exponent 0 should mean 65537"
        );
        let n = modulus(public);
        assert_eq!(n.len(), bytes(bits), "RSA-{size}: modulus size");
        assert!(n[0] & 0x80 != 0, "RSA-{size}: modulus is too short");
        assert_eq!(n[n.len() - 1] & 1, 1, "RSA-{size}: modulus is even");

        let reloaded = load_public(c, bits, E, &n).expect("generated public key rejected");
        let reloaded = load_private(c, reloaded, &prime(&key)).expect("generated prime rejected");
        if caps.oaep.contains(&TpmiAlgHash::Sha256) {
            let scheme = RsaEncryptScheme::Oaep {
                hash: TpmiAlgHash::Sha256,
                label: b"",
            };
            let ciphertext = encrypt(c, &mut rng, public, scheme, b"generated")
                .check("encrypt")
                .expect("message rejected");
            for key in [&key, &reloaded] {
                let plaintext = decrypt(c, key, scheme, &ciphertext).check("decrypt");
                assert_eq!(
                    plaintext.as_deref(),
                    Some(&b"generated"[..]),
                    "RSA-{size} round trip"
                );
            }
        }
    }
}

/// Key generation from a seeded RNG is deterministic (as required for
/// `TPM2_CreatePrimary`), and depends on the seed.
pub fn rsa_generate_key_deterministic<C: Rsa>(c: &C, caps: &Caps) {
    // Use the smallest supported size, as key generation is slow.
    let Some(&bits) = caps.rsa.iter().min() else {
        let mut rng = seeded_rng(c, "rsa_generate_key_deterministic");
        let result = Rsa::generate_key(c, &mut rng, TpmiRsaKeyBits::Rsa2048, 0);
        expect_support(false, "RSA key generation", result);
        return;
    };
    let generate = |seed: &str| {
        let mut rng = c.rng_seeded(seed.as_bytes()).check("Random::rng_seeded");
        let key = Rsa::generate_key(c, &mut rng, bits, 0).check("Rsa::generate_key");
        (modulus(key.public_key()), prime(&key))
    };
    let first = generate("rsa seed 1");
    assert_eq!(first, generate("rsa seed 1"), "same seed, different key");
    assert_ne!(
        first.0,
        generate("rsa seed 2").0,
        "different seeds, same key"
    );
}
