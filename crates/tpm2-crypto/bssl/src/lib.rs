#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

use tpm2::crypto::{ConstantTimeEq, CryptoError, CryptoProvider, Random};

/// BoringSSL-based implementation of the `tpm2::crypto` interfaces
/// ([`CryptoProvider`] and its super-traits).
///
/// Supported algorithms: SHA-1/SHA-256/SHA-384/SHA-512 (hash and HMAC),
/// AES-128/192/256 (CMAC, and CFB for symmetric encryption), RSA 1024-4096
/// (RSASSA, RSAPSS, RSAES, OAEP, raw RSA, key generation and import), the NIST
/// P-224/P-256/P-384/P-521 curves (ECDSA, point operations and key generation),
/// and BN-P256 (point operations and key generation).
/// Everything else returns [`CryptoError::Unsupported`].
pub struct BsslCryptoProvider;

impl CryptoProvider for BsslCryptoProvider {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        bssl_crypto::rand_bytes(dest);
        Ok(())
    }
}

impl ConstantTimeEq for BsslCryptoProvider {
    /// Compares `a` and `b` with BoringSSL's `CRYPTO_memcmp`, in time independent
    /// of their contents.
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        bssl_crypto::constant_time_compare(a, b)
    }
}

/// The provider does not create [`tpm2::crypto::Rng`] instances: its CSPRNG is
/// [`CryptoProvider::get_random`], and deterministic key generation takes a seed
/// directly ([`tpm2::crypto::Asymmetric::generate_key`]).
impl Random for BsslCryptoProvider {
    type Rng = !;
}

#[forbid(unsafe_code)]
pub mod asymmetric;
pub mod bssl;
#[forbid(unsafe_code)]
pub mod cmac;
#[forbid(unsafe_code)]
pub mod ecc;
#[forbid(unsafe_code)]
pub mod hash;
#[forbid(unsafe_code)]
pub mod symmetric;
pub use {bssl::*, cmac::*, ecc::*, hash::*};

/// Maps the result of a verification or validation binding to the
/// `tpm2::crypto` convention: [`BsslError::InvalidData`] (a bad signature, key,
/// or point) is `Ok(false)`.
pub(crate) fn verified(result: Result<(), BsslError>) -> Result<bool, CryptoError> {
    match result {
        Ok(()) => Ok(true),
        Err(BsslError::InvalidData) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Maps the result of a binding producing output to the `tpm2::crypto`
/// convention: [`BsslError::InvalidData`] (an invalid input) is `Ok(None)`.
pub(crate) fn output<T>(result: Result<T, BsslError>) -> Result<Option<T>, CryptoError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(BsslError::InvalidData) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Random number generator backed by BoringSSL's `RAND_bytes`.
pub struct BsslRng;

impl rand_core::RngCore for BsslRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        bssl_crypto::rand_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        bssl_crypto::rand_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        bssl_crypto::rand_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        bssl_crypto::rand_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for BsslRng {}

#[allow(clippy::large_enum_variant)]
pub(crate) enum RngWrapper {
    ChaCha(rand_chacha::ChaCha20Rng),
    Bssl(BsslRng),
}

impl rand_core::RngCore for RngWrapper {
    fn next_u32(&mut self) -> u32 {
        match self {
            Self::ChaCha(rng) => rng.next_u32(),
            Self::Bssl(rng) => rng.next_u32(),
        }
    }
    fn next_u64(&mut self) -> u64 {
        match self {
            Self::ChaCha(rng) => rng.next_u64(),
            Self::Bssl(rng) => rng.next_u64(),
        }
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            Self::ChaCha(rng) => rng.fill_bytes(dest),
            Self::Bssl(rng) => rng.fill_bytes(dest),
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        match self {
            Self::ChaCha(rng) => rng.try_fill_bytes(dest),
            Self::Bssl(rng) => rng.try_fill_bytes(dest),
        }
    }
}

impl rand_core::CryptoRng for RngWrapper {}
