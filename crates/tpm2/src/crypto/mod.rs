//! Cryptography Interfaces for TPM implementations and clients
mod cmac;
mod ecc;
mod hash;
mod hmac;
mod kdf;
mod rng;
mod rsa;
mod signing;
mod symmetric;
pub use {cmac::*, ecc::*, hash::*, hmac::*, kdf::*, rng::*, rsa::*, signing::*, symmetric::*};

/// Common error type for all cryptographic traits.
///
/// We intentionally don't allow cryptography backends to provide rich error
/// information, as we can't do anything other than enter failure mode when we
/// receive [`CryptoError::Internal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The requested algorithm, mode, or key size is unsupported.
    Unsupported,
    /// An internal error, which puts the TPM into failure mode.
    Internal,
}

/// Selects between encryption and decryption operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

/// Constant-time equality comparison for fixed-length byte arrays.
pub trait ConstantTimeEq {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool;
}

/// Feeds incremental input bytes into an active cryptographic stream context.
pub trait Update {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;
}
/// Consumes a cryptographic stream context and writes the fixed-length output.
///
/// Other traits and functions wrap this to return TPM structs. For example,
/// [`HashStream::finalize`] wraps this to return a [TpmtHa](crate::TpmtHa).
pub trait Finalize<const N: usize> {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError>;
}

impl Update for ! {
    fn update(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        match *self {}
    }
}
impl<const N: usize> Finalize<N> for ! {
    fn finalize(self, _: &mut [u8; N]) -> Result<(), CryptoError> {
        match self {}
    }
}
