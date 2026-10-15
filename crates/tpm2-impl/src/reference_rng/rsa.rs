//! The C reference TPMs' random RSA operations (`CryptRsa.c`, `CryptPrime.c`,
//! `CryptPrimeSieve.c` of the TCG reference implementation), linked from the original C code:
//! key generation (prime search with the reference's sieve and Miller-Rabin bases, and the
//! pairwise consistency test of signing keys) and the randomized encodings whose output is then
//! raised to the public (encryption) or private (PSS signature) exponent by the crypto provider.
//!
//! Compared to generic implementations, the reference code draws its randomness in a specific way
//! (e.g. RSAES-PKCS1-v1_5 replaces zero padding bytes with `0x55` instead of drawing new ones, and
//! PSS uses the largest salt FIPS 186-4 allows), which is why the encodings come from the
//! reference too. Moduli are limited to the reference profile's `MAX_RSA_KEY_BYTES` (3072 bits).

use tpm2::errors::TpmRc;
use tpm2::{Alg, TpmiAlgHash};

use super::{RefRng, ffi};
use crate::engine::DrbgState;

/// `RSA_DEFAULT_PUBLIC_EXPONENT`.
pub const RSA_DEFAULT_PUBLIC_EXPONENT: u32 = 65537;

/// `CryptRsaGenerateKey()`: generates a `key_bits`-bit RSA key with public exponent `exponent`
/// (0 for the default) from `rand` (`None`: the TPM's DRBG).
///
/// Writes the modulus (`key_bits / 8` bytes) to the front of `modulus` and the prime the
/// reference stores first in the sensitive area (`key_bits / 16` bytes; the private key with
/// `RSA_PRIVATE_PRIME_ONLY`) to the front of `prime`, and returns the public exponent used. For a
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
    ffi::rsa_generate_key(rng, rand, key_bits, exponent, sign, modulus, prime)?;
    Ok(if exponent == 0 {
        RSA_DEFAULT_PUBLIC_EXPONENT
    } else {
        exponent
    })
}

/// `OaepEncode()`: encodes `message` with `label` (including its terminating NUL, if any) into
/// `padded` (the modulus size), drawing the seed from the TPM's DRBG.
///
/// Errors: `TPM_RC_HASH` if `padded` cannot hold two digests, `TPM_RC_VALUE` if `message` is too
/// long or `padded` exceeds the largest modulus (as in the reference code).
pub fn oaep_encode(
    rng: &mut RefRng<'_>,
    hash_alg: TpmiAlgHash,
    label: &[u8],
    message: &[u8],
    padded: &mut [u8],
) -> Result<(), TpmRc> {
    ffi::oaep_encode(rng, Alg::from(hash_alg).id(), label, message, padded)
}

/// `RSAES_PKCS1v1_5Encode()`: `00 02 PS 00 M` into `padded` (the modulus size), with `PS` drawn
/// from the TPM's DRBG and its zero bytes replaced with `0x55`.
///
/// Errors: `TPM_RC_VALUE` if `message` is too long.
pub fn rsaes_pkcs1v15_encode(
    rng: &mut RefRng<'_>,
    message: &[u8],
    padded: &mut [u8],
) -> Result<(), TpmRc> {
    ffi::rsaes_pkcs1v15_encode(rng, message, padded)
}

/// `PssEncode()`: the EMSA-PSS encoding of `digest` into `out` (the modulus size), with the
/// largest salt that fits (capped at the digest size, `CryptRsaPssSaltSize()`) drawn from the
/// TPM's DRBG.
///
/// Errors: `TPM_RC_FAILURE` if `out` cannot hold the digest (a fatal error in the reference).
pub fn pss_encode(
    rng: &mut RefRng<'_>,
    hash_alg: TpmiAlgHash,
    digest: &[u8],
    out: &mut [u8],
) -> Result<(), TpmRc> {
    // `PssEncode()` asserts this (a fatal error in the reference).
    if out.len() < hash_alg.digest_size() + 2 {
        return Err(TpmRc::FAILURE);
    }
    ffi::pss_encode(rng, Alg::from(hash_alg).id(), digest, out)
}

#[cfg(test)]
mod tests {
    use super::super::drbg::{self, tests::FixedEntropy};
    use super::*;
    use num_bigint::BigUint;
    use tpm2::crypto::HashStream;
    use tpm2_crypto_bssl::BsslCryptoProvider as Crypto;

    extern crate std;

    /// SHA-256 of the concatenation of `parts`.
    fn sha256(parts: &[&[u8]]) -> [u8; 32] {
        let mut state = HashStream::new(&Crypto, TpmiAlgHash::Sha256).unwrap();
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
        })
        .unwrap();
        state
    }

    /// A context drawing from `state` with no entropy source.
    fn tpm(state: &mut DrbgState) -> RefRng<'_> {
        RefRng {
            drbg: Some(state),
            entropy: None,
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

    #[test]
    fn pkcs1v15_padding_is_well_formed() {
        let mut state = tpm_drbg();
        let mut padded = [0xaau8; 64];
        rsaes_pkcs1v15_encode(&mut tpm(&mut state), &[1, 2, 3, 4, 5], &mut padded).unwrap();
        assert_eq!(padded[..2], [0, 2]);
        assert!(padded[2..58].iter().all(|&b| b != 0));
        assert_eq!(padded[58..], [0, 1, 2, 3, 4, 5]);
        assert_eq!(
            rsaes_pkcs1v15_encode(&mut tpm(&mut state), &[0; 54], &mut padded),
            Err(TpmRc::VALUE.to_rc())
        );
        // The padding comes from the TPM's DRBG.
        assert_eq!(
            rsaes_pkcs1v15_encode(&mut RefRng::seeded_only(), &[1], &mut padded),
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
                TpmiAlgHash::Sha256,
                b"",
                &[0; 63],
                &mut padded
            ),
            Err(TpmRc::VALUE.to_rc())
        );
        assert_eq!(
            oaep_encode(
                &mut tpm(&mut state),
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
                TpmiAlgHash::Sha256,
                &[1; 32],
                &mut [0; 33]
            ),
            Err(TpmRc::FAILURE)
        );
    }
}
