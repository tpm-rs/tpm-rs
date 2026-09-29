#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use tpm2::Alg;
use tpm2::crypto::Rng;
use tpm2::crypto::{CryptoError, CryptoProvider};

pub struct CruxCryptoProvider;

impl CryptoProvider for CruxCryptoProvider {}

impl tpm2::crypto::Base for CruxCryptoProvider {
    type Error = CryptoError;

    fn unimplemented(&self, _alg: Alg) -> Self::Error {
        CryptoError::UnsupportedAlgorithm
    }
}

impl Rng for CruxCryptoProvider {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        use rand::TryRngCore as _;
        rand::rngs::OsRng
            .try_fill_bytes(dest)
            .map_err(|_| CryptoError::HardwareFailure)
    }
}

pub mod asymmetric;
pub mod cmac;
pub mod ecc;
pub mod hash;
pub mod symmetric;
pub use {cmac::*, ecc::*, hash::*, symmetric::*};

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
