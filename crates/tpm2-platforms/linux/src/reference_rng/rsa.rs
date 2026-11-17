//! The C reference TPMs' random RSA operations (`CryptRsa.c`, `CryptPrime.c`,
//! `CryptPrimeSieve.c` of the TCG reference implementation), linked from the original C code:
//! key generation (prime search with the reference's sieve and Miller-Rabin bases, and the
//! pairwise consistency test of signing keys) and the randomized encodings `OaepEncode()`,
//! `RSAES_PKCS1v1_5Encode()` and `PssEncode()`. They are the test oracles of the Rust
//! implementations with the same draws (`tpm2_engine::asymmetric::rsa_generate_key` and
//! `tpm2::crypto::{rsa_oaep_encode, rsa_pkcs1v15_encode, rsa_pss_encode}`, `oracles.rs`).
//!
//! Compared to generic implementations, the reference code draws its randomness in a specific way
//! (e.g. RSAES-PKCS1-v1_5 replaces zero padding bytes with `0x55` instead of drawing new ones, and
//! PSS uses the largest salt FIPS 186-4 allows). Moduli are limited to the reference profile's
//! `MAX_RSA_KEY_BYTES` (4096 bits).

use tpm2::errors::TpmRc;
use tpm2::{Alg, TpmiAlgHash};

use tpm2_engine::DrbgState;

use super::{RefRng, ffi};

/// The default public exponent of RSA keys (`RSA_DEFAULT_PUBLIC_EXPONENT`), used for the
/// exponent 0.
pub const RSA_DEFAULT_PUBLIC_EXPONENT: u32 = 65537;

/// `CryptRsaGenerateKey()`: generates a `key_bits`-bit RSA key with public exponent `exponent`
/// (0 for the default) from `rand` (`None`: the TPM's DRBG).
///
/// Writes the modulus (`key_bits / 8` bytes) to the front of `modulus` and the prime the
/// reference stores first in the sensitive area (`key_bits / 16` bytes; the prime-only form of
/// the private key) to the front of `prime`, and returns the public exponent used. For a
/// signing key (`sign`), the reference's pairwise consistency test is run as well, which draws a
/// random value in `[1, n)` from `rand`.
///
/// Errors: `TPM_RC_RANGE` for an unsupported exponent, `TPM_RC_VALUE` for an unsupported key
/// size, `TPM_RC_FAILURE` if the outputs are too small or drawing fails.
pub fn generate_key(
    rng: &mut RefRng<'_>,
    rand: Option<&mut DrbgState>,
    key_bits: u16,
    exponent: u32,
    sign: bool,
    modulus: &mut [u8],
    prime: &mut [u8],
) -> Result<u32, TpmRc> {
    ffi::rsa_generate_key(rng, rand, key_bits, exponent, sign, modulus, prime, None)?;
    Ok(if exponent == 0 {
        RSA_DEFAULT_PUBLIC_EXPONENT
    } else {
        exponent
    })
}

/// `OaepEncode()`: encodes `message` with `label` (including its terminating NUL, if any) into
/// `padded` (the modulus size), drawing the seed from `rand` (`None`: the TPM's DRBG).
///
/// Errors: `TPM_RC_HASH` if `padded` cannot hold two digests, `TPM_RC_VALUE` if `message` is too
/// long or `padded` exceeds the largest modulus (as in the reference code).
pub fn oaep_encode(
    rng: &mut RefRng<'_>,
    rand: Option<&mut DrbgState>,
    hash_alg: TpmiAlgHash,
    label: &[u8],
    message: &[u8],
    padded: &mut [u8],
) -> Result<(), TpmRc> {
    ffi::oaep_encode(rng, rand, Alg::from(hash_alg).id(), label, message, padded)
}

/// `RSAES_PKCS1v1_5Encode()`: `00 02 PS 00 M` into `padded` (the modulus size), with `PS` drawn
/// from `rand` (`None`: the TPM's DRBG) and its zero bytes replaced with `0x55`.
///
/// Errors: `TPM_RC_VALUE` if `message` is too long.
pub fn rsaes_pkcs1v15_encode(
    rng: &mut RefRng<'_>,
    rand: Option<&mut DrbgState>,
    message: &[u8],
    padded: &mut [u8],
) -> Result<(), TpmRc> {
    ffi::rsaes_pkcs1v15_encode(rng, rand, message, padded)
}

/// `PssEncode()`: the EMSA-PSS encoding of `digest` into `out` (the modulus size), with the
/// largest salt that fits (capped at the digest size, `CryptRsaPssSaltSize()`) drawn from `rand`
/// (`None`: the TPM's DRBG).
///
/// Errors: `TPM_RC_FAILURE` if `out` cannot hold the digest (a fatal error in the reference).
pub fn pss_encode(
    rng: &mut RefRng<'_>,
    rand: Option<&mut DrbgState>,
    hash_alg: TpmiAlgHash,
    digest: &[u8],
    out: &mut [u8],
) -> Result<(), TpmRc> {
    // `PssEncode()` asserts this (a fatal error in the reference).
    if out.len() < hash_alg.digest_size() + 2 {
        return Err(TpmRc::FAILURE);
    }
    ffi::pss_encode(rng, rand, Alg::from(hash_alg).id(), digest, out)
}

#[cfg(test)]
mod tests {
    use super::super::drbg::{self, tests::FixedEntropy};
    use super::*;
    use num_bigint::BigUint;
    use tpm2::crypto::HashContext;
    use tpm2_crypto_bssl::BsslCryptoProvider as Crypto;

    /// SHA-256 of the concatenation of `parts`.
    fn sha256(parts: &[&[u8]]) -> [u8; 32] {
        let mut state = HashContext::<Crypto>::new(TpmiAlgHash::Sha256).unwrap();
        for p in parts {
            state.update(p).unwrap();
        }
        let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let d = state.finalize(&mut buf).unwrap();
        d.digest().try_into().unwrap()
    }

    /// The TPM's DRBG, instantiated from fixed entropy.
    fn tpm_drbg() -> DrbgState {
        let mut state = DrbgState::default();
        let mut entropy = FixedEntropy(&[0x11, 0x22, 0x33, 0x44, 0x55], 0);
        drbg::instantiate(&mut RefRng {
            drbg: Some(&mut state),
            entropy: Some(&mut entropy),
            flags: None,
        })
        .unwrap();
        state
    }

    /// A context drawing from `state` with no entropy source.
    fn tpm(state: &mut DrbgState) -> RefRng<'_> {
        RefRng {
            drbg: Some(state),
            entropy: None,
            flags: None,
        }
    }

    #[test]
    fn generated_key_is_consistent() {
        let mut seeded = drbg::instantiate_seeded(b"seed", b"rsa\0", b"", b"").unwrap();
        let (mut n, mut p) = ([0u8; 128], [0u8; 64]);
        let e = generate_key(
            &mut RefRng::seeded_only(),
            Some(&mut seeded),
            1024,
            0,
            true,
            &mut n,
            &mut p,
        )
        .unwrap();
        assert_eq!(e, RSA_DEFAULT_PUBLIC_EXPONENT);
        let (n, p) = (BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&p));
        assert_eq!(n.bits(), 1024);
        assert_eq!(p.bits(), 512);
        assert_eq!(&n % &p, BigUint::from(0u32));

        let rng = &mut RefRng::seeded_only();
        let mut st = seeded;
        assert_eq!(
            generate_key(
                rng,
                Some(&mut st),
                1000,
                0,
                false,
                &mut [0; 128],
                &mut [0; 64]
            ),
            Err(TpmRc::VALUE.to_rc())
        );
        assert_eq!(
            generate_key(
                rng,
                Some(&mut st),
                1024,
                3,
                false,
                &mut [0; 128],
                &mut [0; 64]
            ),
            Err(TpmRc::RANGE.to_rc())
        );
        // Outputs that are too small are rejected before the C code runs.
        assert_eq!(
            generate_key(
                rng,
                Some(&mut st),
                1024,
                0,
                false,
                &mut [0; 127],
                &mut [0; 64]
            ),
            Err(TpmRc::FAILURE)
        );
        assert_eq!(st, seeded);
    }

    /// The prime sieve's limit depends on the prime size and is per thread: concurrent
    /// generations of keys of different sizes give the same keys as sequential ones.
    #[test]
    fn concurrent_key_generations_do_not_interfere() {
        let generate = |key_bits: u16| {
            let mut seeded = drbg::instantiate_seeded(b"seed", b"rsa\0", b"", b"").unwrap();
            let (mut n, mut p) = ([0u8; 256], [0u8; 128]);
            let len = usize::from(key_bits) / 8;
            generate_key(
                &mut RefRng::seeded_only(),
                Some(&mut seeded),
                key_bits,
                0,
                false,
                &mut n[..len],
                &mut p[..len / 2],
            )
            .unwrap();
            (n, p)
        };
        let expected = [generate(1024), generate(2048)];
        let handles: std::vec::Vec<_> = (0..6)
            .map(|i| {
                std::thread::spawn(move || {
                    let key_bits = if i % 2 == 0 { 1024 } else { 2048 };
                    for _ in 0..3 {
                        assert_eq!(generate(key_bits), expected[i % 2]);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }

    /// SHA-256 of `n || p || crt` of the keys `CryptRsaGenerateKey()` generates from the seeded
    /// DRBGs of [`crt_form_matches_the_reference_packed_sensitive_area`] (the modulus, the prime
    /// stored first and the reference's packed CRT sensitive area), and whether that prime is the
    /// larger one. `tpm2_engine` checks that the CRT form it stores under fixedTPM parents is the
    /// reference's for the keys 0, 1, 2 and 7 (its `handler::rsa_sensitive` tests hold their `n`
    /// and `p` and these digests).
    const CRT_DIGESTS: [([u8; 32], bool); 12] = [
        // Key 0 (1024 bits, the smaller prime first).
        (
            hex_literal::hex!("877d5068669f74d3424dc2d7f4597e513d5c77d65f60d00ac8dac3b0340561ea"),
            false,
        ),
        // Key 1 (2048 bits, the smaller prime first).
        (
            hex_literal::hex!("8b89d34ac7a9f754ee6ac536d777b8897c28619542040f93b3978835cdbfed91"),
            false,
        ),
        // Key 2 (1024 bits, the larger prime first).
        (
            hex_literal::hex!("2bb6a03c43cd1c452424272b51b87ae9e52c34cf3dcc199d5ce4850e38f036c9"),
            true,
        ),
        // Key 3 (2048 bits, the smaller prime first).
        (
            hex_literal::hex!("53f81925bfd38f7c9689123ace10739b9f7fc92bcc4ab456bdc1fadbdf4e9c44"),
            false,
        ),
        // Key 4 (1024 bits, the larger prime first).
        (
            hex_literal::hex!("1dcd7cf99237e108f79550b01ecaf7e8729fd072305b4f0545ac35645461f1df"),
            true,
        ),
        // Key 5 (2048 bits, the smaller prime first).
        (
            hex_literal::hex!("d1beee6a1bee4c7efeb66c7327cd4711718b798806e6e841deaa70fa48e58721"),
            false,
        ),
        // Key 6 (1024 bits, the larger prime first).
        (
            hex_literal::hex!("73a5e6b9bf7f2dec6e8188108a000f56537a1f92a10eaac5a6167a6e942b72da"),
            true,
        ),
        // Key 7 (2048 bits, the larger prime first).
        (
            hex_literal::hex!("32f777e1398ef7dbc1140ad4f339c90f44a7b1b668b1d02ce39acd398b3f5c7c"),
            true,
        ),
        // Key 8 (1024 bits, the larger prime first).
        (
            hex_literal::hex!("4b22e22201e328c18ccfe7cab35c4c23784f92408fb648d7bd5869fb07323f90"),
            true,
        ),
        // Key 9 (2048 bits, the smaller prime first).
        (
            hex_literal::hex!("4004b2719d9c14aa5541f0a311e5e85b069114f616c0ee43d698db0fd65c3ffa"),
            false,
        ),
        // Key 10 (1024 bits, the smaller prime first).
        (
            hex_literal::hex!("7f0918240c360339ed2d9cc060bab0b86651e3535ce080da45ba26b8d2cdbea7"),
            false,
        ),
        // Key 11 (2048 bits, the smaller prime first).
        (
            hex_literal::hex!("a3c35b3f9d37a7d418e9e943954972f572fd609fc09b2238509986006e559529"),
            false,
        ),
    ];

    /// The packed sensitive area of the C reference's `CryptRsaGenerateKey()` (the CRT form that
    /// tpm-rs stores under fixedTPM parents, `tpm2_engine`'s `handler::rsa_sensitive`: the
    /// backend's CRT values rearranged around the prime-only form) is pinned by
    /// [`CRT_DIGESTS`], both when the reference's first prime is the larger and when it is the
    /// smaller one; the CRT values are consistent with the key.
    #[test]
    fn crt_form_matches_the_reference_packed_sensitive_area() {
        let (mut larger_first, mut smaller_first) = (0, 0);
        for (i, key_bits) in (0u8..12).zip([1024u16, 2048].into_iter().cycle()) {
            let mut seeded = drbg::instantiate_seeded(b"crt", &[i], b"", b"").unwrap();
            let len = usize::from(key_bits) / 8;
            let (mut n, mut p, mut c_crt) = ([0u8; 256], [0u8; 128], [0u8; 640]);
            ffi::rsa_generate_key(
                &mut RefRng::seeded_only(),
                Some(&mut seeded),
                key_bits,
                0,
                i % 3 == 0,
                &mut n[..len],
                &mut p[..len / 2],
                Some(&mut c_crt[..5 * len / 2]),
            )
            .unwrap();
            let (n, p, c_crt) = (&n[..len], &p[..len / 2], &c_crt[..5 * len / 2]);
            let (digest, prime_is_larger) = CRT_DIGESTS[usize::from(i)];
            assert_eq!(sha256(&[n, p, c_crt]), digest, "key {i} ({key_bits} bits)");
            // `P, Q, dP, dQ, qInv`, with `p` (the prime-only form) first.
            let (c_p, rest) = c_crt.split_at(len / 2);
            let (c_q, _) = rest.split_at(len / 2);
            assert_eq!(c_p, p);
            let (big_n, big_p, big_q) = (
                BigUint::from_bytes_be(n),
                BigUint::from_bytes_be(c_p),
                BigUint::from_bytes_be(c_q),
            );
            assert_eq!(&big_p * &big_q, big_n, "key {i}");
            assert_eq!(big_p > big_q, prime_is_larger, "key {i}");
            if prime_is_larger {
                larger_first += 1;
            } else {
                smaller_first += 1;
            }
        }
        assert!(
            larger_first > 0 && smaller_first > 0,
            "{larger_first} / {smaller_first}"
        );
    }

    #[test]
    fn pkcs1v15_padding_is_well_formed() {
        let mut state = tpm_drbg();
        let mut padded = [0xaau8; 64];
        rsaes_pkcs1v15_encode(&mut tpm(&mut state), None, &[1, 2, 3, 4, 5], &mut padded).unwrap();
        assert_eq!(padded[..2], [0, 2]);
        assert!(padded[2..58].iter().all(|&b| b != 0));
        assert_eq!(padded[58..], [0, 1, 2, 3, 4, 5]);
        assert_eq!(
            rsaes_pkcs1v15_encode(&mut tpm(&mut state), None, &[0; 54], &mut padded),
            Err(TpmRc::VALUE.to_rc())
        );
        // The padding comes from the TPM's DRBG.
        assert_eq!(
            rsaes_pkcs1v15_encode(&mut RefRng::seeded_only(), None, &[1], &mut padded),
            Err(TpmRc::FAILURE)
        );
    }

    /// MGF1 with SHA-256.
    fn mgf1(seed: &[u8], len: usize) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        for counter in 0u32.. {
            if out.len() >= len {
                break;
            }
            out.extend_from_slice(&sha256(&[seed, &counter.to_be_bytes()]));
        }
        out.truncate(len);
        out
    }

    #[test]
    fn oaep_and_pss_encodings_are_well_formed() {
        let mut state = tpm_drbg();
        let mut padded = [0u8; 128];
        oaep_encode(
            &mut tpm(&mut state),
            None,
            TpmiAlgHash::Sha256,
            b"label\0",
            b"msg",
            &mut padded,
        )
        .unwrap();
        assert_eq!(padded[0], 0);
        // Unmask the seed and DB and check the structure.
        let seed_mask = mgf1(&padded[33..], 32);
        let seed: std::vec::Vec<u8> = (0..32).map(|i| padded[1 + i] ^ seed_mask[i]).collect();
        let db_mask = mgf1(&seed, 95);
        let db: std::vec::Vec<u8> = (0..95).map(|i| padded[33 + i] ^ db_mask[i]).collect();
        assert_eq!(&db[95 - 4..], &[0x01, b'm', b's', b'g']);
        assert_eq!(&db[..32], &sha256(&[b"label\0"]));
        assert_eq!(
            oaep_encode(
                &mut tpm(&mut state),
                None,
                TpmiAlgHash::Sha256,
                b"",
                &[0; 63],
                &mut padded
            ),
            Err(TpmRc::VALUE.to_rc())
        );
        #[cfg(feature = "sha512")]
        assert_eq!(
            oaep_encode(
                &mut tpm(&mut state),
                None,
                TpmiAlgHash::Sha512,
                b"",
                b"",
                &mut [0; 129]
            ),
            Err(TpmRc::HASH.to_rc())
        );

        let mut out = [0u8; 128];
        pss_encode(
            &mut tpm(&mut state),
            None,
            TpmiAlgHash::Sha256,
            &[1; 32],
            &mut out,
        )
        .unwrap();
        assert_eq!(out[127], 0xbc);
        assert_eq!(out[0] & 0x80, 0);
        assert_eq!(
            pss_encode(
                &mut tpm(&mut state),
                None,
                TpmiAlgHash::Sha256,
                &[1; 32],
                &mut [0; 33]
            ),
            Err(TpmRc::FAILURE)
        );
    }
}
