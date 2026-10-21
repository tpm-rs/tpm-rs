//! Cryptography interfaces for TPM implementations and clients.

mod active;
mod backend_traits;
mod cmac;
mod hash;
mod hmac;
mod kdf;
mod rng;
mod symmetric;
pub use {active::*, backend_traits::*, cmac::*, hash::*, hmac::*, kdf::*, rng::*, symmetric::*};

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

/// Constant-time equality comparison for byte slices.
pub trait ConstantTimeEq {
    fn eq(a: &[u8], b: &[u8]) -> bool;
}
