//! A [`Crypto`] backend built on the formally verified `libcrux` primitives.
//!
//! [`CruxCryptoProvider`] implements the [`tpm2::crypto::backend`] traits with
//! `libcrux` where it provides the primitive (SHA-256/384/512, NIST P-256
//! ECDH/ECDSA, ML-KEM, ML-DSA), and with RustCrypto crates for the rest:
//!   - [`Hash`](tpm2::crypto::backend::Hash): SHA-1, SHA-256, SHA-384, SHA-512.
//!   - [`Hmac`](tpm2::crypto::backend::Hmac): HMAC with SHA-1, SHA-256,
//!     SHA-384, SHA-512.
//!   - [`Cmac`](tpm2::crypto::backend::Cmac): AES-128, AES-192, AES-256,
//!     Camellia-128, Camellia-192, Camellia-256.
//!   - [`Symmetric`](tpm2::crypto::backend::Symmetric): AES-128, AES-192,
//!     AES-256, Camellia-128, Camellia-192, Camellia-256 in the CTR, OFB, CBC,
//!     CFB and ECB modes. libcrux has no Camellia and no AES modes other than
//!     GCM, so the block ciphers (here and in
//!     [`Cmac`](tpm2::crypto::backend::Cmac)) are the RustCrypto `aes` and
//!     `camellia` crates.
//!   - [`Rsa`](tpm2::crypto::backend::Rsa): RSA-1024/2048/3072/4096 keys
//!     (RustCrypto `rsa`) with RSASSA, RSA-PSS, RSAES-OAEP, RSAES-PKCS1-v1_5
//!     and raw RSA, key generation, import from a prime and the CRT form.
//!   - [`Ecc`](tpm2::crypto::backend::Ecc): NIST P-256 (`libcrux-p256`), P-384
//!     and P-521 (RustCrypto `p384`/`p521`) with ECDSA and ECDH, and BN P-256,
//!     NIST P-192, BN P-638 and SM2 P-256 with the generic constant-time
//!     short-Weierstrass arithmetic of `tpm2-crypto-weierstrass` (neither
//!     `libcrux` nor RustCrypto offers these curves); see [`ecc`] for the
//!     schemes of each curve.
//!   - [`Mlkem`](tpm2::crypto::backend::Mlkem): ML-KEM-512/768/1024
//!     (`libcrux-ml-kem`).
//!   - [`Mldsa`](tpm2::crypto::backend::Mldsa): ML-DSA-44/65/87 key generation
//!     and pure ML-DSA (`libcrux-ml-dsa`); signing and verification on an
//!     external `mu` and HashML-DSA fall back to RustCrypto `ml-dsa`
//!     ([`tpm2_crypto_rust::pqc`]), as `libcrux-ml-dsa` signs and verifies
//!     whole messages only (see [`pqc`]), so the formal verification of
//!     `libcrux` does not cover them.
//!   - [`Random`]: [`CruxRng`], the operating system RNG, or a deterministic
//!     ChaCha20 generator for [`Random::from_seed`].
//!
//! Following the `tpm2::crypto` conventions, semantic failures (an invalid
//! signature, key, point, or ciphertext) are reported in the `Ok` value
//! (`Ok(false)` / `Ok(None)`), unsupported algorithms as
//! [`CryptoError::Unsupported`], and internal failures as
//! [`CryptoError::Internal`].
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use tpm2::crypto::{Crypto, CryptoError, Random, Rng};

/// The `libcrux`-based cryptography backend.
///
/// This is a stateless unit struct: every algorithm is an associated type of
/// the [`tpm2::crypto::backend`] traits. Randomness (signature nonces and
/// salts, OAEP padding, key generation) comes from the [`CruxRng`] passed to
/// the operations.
pub struct CruxCryptoProvider;

/// The random number generator of [`CruxCryptoProvider`].
///
/// [`Random::from_entropy`] creates a generator that draws from the operating
/// system RNG (and ignores [`Rng::stir_bytes`], as the operating system RNG
/// reseeds itself). [`Random::from_seed`] creates a deterministic ChaCha20
/// generator seeded with SHA-256(`seed`); [`Rng::stir_bytes`] reseeds it with
/// SHA-256(32 bytes of its output || `data`), so that its output depends only
/// on the seed and the sequence of calls.
pub struct CruxRng(RngInner);

#[allow(clippy::large_enum_variant)]
enum RngInner {
    /// The operating system RNG.
    Os,
    /// A deterministic ChaCha20 generator.
    Seeded(rand_chacha::ChaCha20Rng),
}

/// SHA-256 of the concatenation of `parts`.
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

impl Rng for CruxRng {
    /// Returns [`CryptoError::Internal`] if the operating system RNG fails.
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        match &mut self.0 {
            RngInner::Os => {
                use rand::TryRngCore as _;
                rand::rngs::OsRng
                    .try_fill_bytes(out)
                    .map_err(|_| CryptoError::Internal)
            }
            RngInner::Seeded(rng) => {
                rand_core::RngCore::fill_bytes(rng, out);
                Ok(())
            }
        }
    }

    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if let RngInner::Seeded(rng) = &mut self.0 {
            use rand_chacha::rand_core::SeedableRng as _;
            let mut state = [0u8; 32];
            rand_core::RngCore::fill_bytes(rng, &mut state);
            *rng = rand_chacha::ChaCha20Rng::from_seed(sha256(&[&state, data]));
        }
        Ok(())
    }
}

/// [`CruxRng`] is also a `rand_core` 0.6 RNG, for the RustCrypto crates.
///
/// The infallible methods panic if the operating system RNG fails (as
/// `rand_core::OsRng` does); [`try_fill_bytes`](rand_core::RngCore::try_fill_bytes)
/// reports the failure.
impl rand_core::RngCore for CruxRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("the operating system RNG failed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Rng::fill_bytes(self, dest).map_err(|_| {
            rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            )
        })
    }
}

impl rand_core::CryptoRng for CruxRng {}

impl Random for CruxCryptoProvider {
    type Rng = CruxRng;

    fn from_entropy() -> Result<CruxRng, CryptoError> {
        Ok(CruxRng(RngInner::Os))
    }

    fn from_seed(seed: &[u8]) -> Result<CruxRng, CryptoError> {
        use rand_chacha::rand_core::SeedableRng as _;
        Ok(CruxRng(RngInner::Seeded(
            rand_chacha::ChaCha20Rng::from_seed(sha256(&[seed])),
        )))
    }
}

impl Crypto for CruxCryptoProvider {
    /// Compares `a` and `b` in constant time (with respect to their contents)
    /// using [`subtle`].
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq as _;
        a.ct_eq(b).into()
    }
}

pub mod asymmetric;
pub mod cmac;
pub mod ecc;
pub mod hash;
pub mod pqc;
pub mod symmetric;
pub use {asymmetric::*, cmac::*, ecc::*, hash::*, pqc::*};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_matches_equality() {
        let a = [0x5au8; 48];
        assert!(CruxCryptoProvider::ct_eq(&a, &a));
        for i in 0..a.len() {
            for bit in 0..8 {
                let mut b = a;
                b[i] ^= 1 << bit;
                assert!(!CruxCryptoProvider::ct_eq(&a, &b));
            }
        }
        assert!(CruxCryptoProvider::ct_eq(&[], &[]));
        assert!(!CruxCryptoProvider::ct_eq(&a, &a[1..]));
    }

    #[test]
    fn digest_eq_uses_ct_eq() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(tpm2::crypto::digest_eq::<CruxCryptoProvider>(
            tpm2::TpmtHa::Sha256(&a),
            tpm2::TpmtHa::Sha256(&a)
        ));
        assert!(!tpm2::crypto::digest_eq::<CruxCryptoProvider>(
            tpm2::TpmtHa::Sha256(&a),
            tpm2::TpmtHa::Sha256(&b)
        ));
    }

    #[test]
    fn entropy_rng_fills_and_accepts_stirring() {
        let mut rng = CruxCryptoProvider::from_entropy().unwrap();
        let (mut x, mut y) = ([0u8; 64], [0u8; 64]);
        rng.fill_bytes(&mut x).unwrap();
        rng.fill_bytes(&mut y).unwrap();
        assert_ne!(x, y);
        rng.fill_bytes(&mut []).unwrap();
        assert_eq!(rng.stir_bytes(b"additional input"), Ok(()));
        CruxCryptoProvider::rand_bytes(&mut x).unwrap();
        assert_ne!(x, y);
    }

    #[test]
    fn seeded_rng_is_deterministic() {
        let output = |seed: &[u8], stir: &[u8]| {
            let mut rng = CruxCryptoProvider::from_seed(seed).unwrap();
            let mut out = [0u8; 96];
            rng.fill_bytes(&mut out[..32]).unwrap();
            rng.stir_bytes(stir).unwrap();
            rng.fill_bytes(&mut out[32..]).unwrap();
            out
        };
        assert_eq!(output(b"seed", b"stir"), output(b"seed", b"stir"));
        assert_ne!(output(b"seed", b"stir"), output(b"seed", b"other"));
        assert_ne!(
            output(b"seed", b"stir")[..32],
            output(b"other", b"stir")[..32]
        );
        assert_eq!(output(b"seed", b"stir")[..32], output(b"seed", b"x")[..32]);
    }
}
