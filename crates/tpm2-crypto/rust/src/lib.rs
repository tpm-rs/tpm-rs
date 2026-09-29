#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

use tpm2::Alg;
use tpm2::crypto::Rng;
use tpm2::crypto::{CryptoError, CryptoProvider};

/// A cryptographic provider implementation using RustCrypto crates (such as `aes`, `rsa`, `p256`, `sha2`, `hmac`).
///
/// This provider supplies all the necessary cryptographic primitives required by the TPM 2.0 stack.
pub struct RustCryptoProvider;

impl CryptoProvider for RustCryptoProvider {}

impl tpm2::crypto::Base for RustCryptoProvider {
    type Error = CryptoError;

    fn unimplemented(&self, _alg: Alg) -> Self::Error {
        CryptoError::UnsupportedAlgorithm
    }
}

impl Rng for RustCryptoProvider {
    /// Fills the destination buffer with high-quality random bytes generated from the operating system's entropy source.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HardwareFailure` if the OS random number generator fails.
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        use rand::TryRngCore as _;
        rand::rngs::OsRng
            .try_fill_bytes(dest)
            .map_err(|_| CryptoError::HardwareFailure)
    }
}

/// A wrapper enum over different random number generator backends.
///
/// This is used to support both standard hardware-backed OS entropy (via `OsRng`)
/// and deterministic, seeded random number generation (via `ChaCha20Rng`) for scenarios like key derivation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum RngWrapper {
    /// A cryptographically secure pseudo-random number generator (CSPRNG) seeded for deterministic execution.
    ChaCha(rand_chacha::ChaCha20Rng),
    /// The standard operating system source of entropy.
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

pub mod asymmetric;
pub mod cmac;
pub mod ecc;
pub mod hash;
pub mod symmetric;
pub use {cmac::*, ecc::*, hash::*, symmetric::*};
