//! A [`CryptoProvider`] backed by the formally verified `libcrux` primitives.
//!
//! [`CruxCryptoProvider`] implements the `tpm2::crypto` interfaces with
//! `libcrux` where it provides the primitive (SHA-256/384/512, NIST P-256
//! ECDH/ECDSA), and with RustCrypto crates for the rest:
//!   - [`Hash`](tpm2::crypto::Hash): SHA-1, SHA-256, SHA-384, SHA-512.
//!   - [`Hmac`](tpm2::crypto::Hmac): HMAC with SHA-1, SHA-256, SHA-384, SHA-512.
//!   - [`Cmac`](tpm2::crypto::Cmac): AES-128, AES-192, AES-256.
//!   - [`Symmetric`](tpm2::crypto::Symmetric): AES-128, AES-192, AES-256 in CFB
//!     mode (other modes return [`CryptoError::Unsupported`]).
//!   - [`Asymmetric`](tpm2::crypto::Asymmetric) /
//!     [`AsymmetricSign`](tpm2::crypto::AsymmetricSign): RSASSA, RSA-PSS,
//!     RSA-OAEP, raw RSA, RSA key generation and import, ECDSA on NIST P-256
//!     (SHA-256), P-384 (SHA-384) and P-521 (SHA-512), and ECC key generation on
//!     NIST P-256/P-384/P-521 and BN P-256.
//!   - [`Ecc`](tpm2::crypto::Ecc): NIST P-256, P-384, P-521 and BN P-256 (no
//!     ECDAA).
//!   - The provider CSPRNG ([`CryptoProvider::get_random`]) draws from the
//!     operating system RNG.
//!
//! Following the `tpm2::crypto` conventions, semantic failures (an invalid
//! signature, key, point, or ciphertext) are reported in the `Ok` value
//! (`Ok(false)` / `Ok(None)`), unsupported algorithms as
//! [`CryptoError::Unsupported`], and internal failures (including output
//! buffers that are too small) as [`CryptoError::Internal`].
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use tpm2::crypto::{ConstantTimeEq, CryptoError, CryptoProvider, Random};

/// The `libcrux`-based cryptography provider.
///
/// This is a stateless unit struct. Unseeded randomness (the provider CSPRNG,
/// signature nonces and salts, OAEP padding, unseeded key generation) comes
/// from the operating system RNG.
pub struct CruxCryptoProvider;

impl CryptoProvider for CruxCryptoProvider {
    /// Fills `dest` from the operating system RNG.
    ///
    /// Returns [`CryptoError::Internal`] if the operating system RNG fails.
    /// [`CryptoProvider::stir_random`] keeps its default (the additional data is
    /// ignored), as the operating system RNG reseeds itself.
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        use rand::TryRngCore as _;
        rand::rngs::OsRng
            .try_fill_bytes(dest)
            .map_err(|_| CryptoError::Internal)
    }
}

impl ConstantTimeEq for CruxCryptoProvider {
    /// Compares `a` and `b` in constant time (with respect to their contents)
    /// using [`subtle`].
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        use subtle::ConstantTimeEq as _;
        a.as_slice().ct_eq(b.as_slice()).into()
    }
}

/// [`CruxCryptoProvider`] does not create [`Rng`](tpm2::crypto::Rng)
/// instances: [`Random::rng`] and [`Random::rng_seeded`] return
/// [`CryptoError::Unsupported`]. Seeded key generation is done by
/// [`Asymmetric::rsa_generate_key`](tpm2::crypto::Asymmetric::rsa_generate_key)
/// and
/// [`Asymmetric::ecc_generate_key`](tpm2::crypto::Asymmetric::ecc_generate_key)
/// themselves.
impl Random for CruxCryptoProvider {
    type Rng = !;
}

pub mod asymmetric;
pub mod cmac;
pub mod ecc;
pub mod hash;
pub mod symmetric;
pub use {cmac::*, ecc::*, hash::*};

#[allow(clippy::large_enum_variant)]
pub(crate) enum RngWrapper {
    ChaCha(rand_chacha::ChaCha20Rng),
    Os(rand_core::OsRng),
}

impl rand_core::RngCore for RngWrapper {
    fn next_u32(&mut self) -> u32 {
        match self {
            Self::ChaCha(rng) => rng.next_u32(),
            Self::Os(rng) => rng.next_u32(),
        }
    }
    fn next_u64(&mut self) -> u64 {
        match self {
            Self::ChaCha(rng) => rng.next_u64(),
            Self::Os(rng) => rng.next_u64(),
        }
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            Self::ChaCha(rng) => rng.fill_bytes(dest),
            Self::Os(rng) => rng.fill_bytes(dest),
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        match self {
            Self::ChaCha(rng) => rng.try_fill_bytes(dest),
            Self::Os(rng) => rng.try_fill_bytes(dest),
        }
    }
}

impl rand_core::CryptoRng for RngWrapper {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equality() {
        let c = CruxCryptoProvider;
        let a = [0x5au8; 48];
        assert!(c.constant_time_eq(&a, &a));
        for i in 0..a.len() {
            for bit in 0..8 {
                let mut b = a;
                b[i] ^= 1 << bit;
                assert!(!c.constant_time_eq(&a, &b));
            }
        }
        assert!(c.constant_time_eq(&[], &[]));
    }

    #[test]
    fn digest_eq_uses_constant_time_eq() {
        let c = CruxCryptoProvider;
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(tpm2::crypto::digest_eq(
            &c,
            tpm2::TpmtHa::Sha256(&a),
            tpm2::TpmtHa::Sha256(&a)
        ));
        assert!(!tpm2::crypto::digest_eq(
            &c,
            tpm2::TpmtHa::Sha256(&a),
            tpm2::TpmtHa::Sha256(&b)
        ));
    }

    #[test]
    fn get_random_fills_and_stir_random_is_accepted() {
        let c = CruxCryptoProvider;
        let (mut x, mut y) = ([0u8; 64], [0u8; 64]);
        c.get_random(&mut x).unwrap();
        c.get_random(&mut y).unwrap();
        assert_ne!(x, y);
        c.get_random(&mut []).unwrap();
        assert_eq!(c.stir_random(b"additional input"), Ok(()));
    }

    #[test]
    fn random_factory_is_unsupported() {
        let c = CruxCryptoProvider;
        assert!(matches!(c.rng(), Err(CryptoError::Unsupported)));
        assert!(matches!(
            c.rng_seeded(b"seed"),
            Err(CryptoError::Unsupported)
        ));
    }
}
