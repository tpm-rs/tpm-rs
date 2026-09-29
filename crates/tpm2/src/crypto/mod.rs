//! Cryptography Interfaces for TPM implementations and clients
use crate::Alg;

pub mod asymmetric;
pub mod cmac;
pub mod ecc;
mod hash;
pub mod kdf;
pub mod rng;
pub mod symmetric;
pub use {asymmetric::*, cmac::*, ecc::*, hash::*, kdf::*, rng::*, symmetric::*};

pub trait Base {
    type Error;

    fn unimplemented(&self, alg: Alg) -> Self::Error;
}

pub trait Update<Error> {
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
}
pub trait UpdateInPlace<Error> {
    fn update(&mut self, data: &mut [u8]) -> Result<(), Error>;
}
pub trait Finalize<const N: usize, Error> {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), Error>;
}

impl<Error> Update<Error> for ! {
    fn update(&mut self, _: &[u8]) -> Result<(), Error> {
        match *self {}
    }
}
impl<Error> UpdateInPlace<Error> for ! {
    fn update(&mut self, _: &mut [u8]) -> Result<(), Error> {
        match *self {}
    }
}
impl<const N: usize, Error> Finalize<N, Error> for ! {
    fn finalize(self, _: &mut [u8; N]) -> Result<(), Error> {
        match self {}
    }
}

/// Standard Crypto Errors mapped to hardware failure cases.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Returned when the requested algorithm (e.g., TPM_ALG_SHA256, TPM_ALG_AES) is not supported by the underlying hardware backend.
    UnsupportedAlgorithm,

    /// Returned when a provided cryptographic key does not meet the minimum length requirements for an algorithm (e.g. AES-128 request with 8-byte key).
    KeyTooSmall,

    /// Returned when input data (like a ciphertext, digital signature, or public key curve point) is mathematically invalid, corrupted, or fails structural bounds checks (e.g. Invalid MAC/Signature).
    InvalidData,

    /// Returned when the destination buffer provided for an output (like a hash digest, ciphertext, or signature block) is too small to contain the full result.
    BufferTooSmall,

    /// Returned for severe physical failures inside the cryptographic hardware perimeter (e.g., TRNG entropy failure, RNG continuous test failure, coprocessor bus fault).
    HardwareFailure,
}

/// The core cryptography provider factory.
/// This acts as the entire Hardware Abstraction Layer mapping.
pub trait CryptoProvider:
    Rng
    + Hash<Error = CryptoError>
    + Hmac<Error = CryptoError>
    + Symmetric<Error = CryptoError>
    + Asymmetric<Error = CryptoError>
    + AsymmetricSign<Error = CryptoError>
    + Cmac<Error = CryptoError>
    + Ecc<Error = CryptoError>
{
}
