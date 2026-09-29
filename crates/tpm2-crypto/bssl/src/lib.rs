#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

use tpm2::Alg;
use tpm2::crypto::Rng;
use tpm2::crypto::{CryptoError, CryptoProvider};

pub struct BsslCryptoProvider;

impl CryptoProvider for BsslCryptoProvider {}

impl tpm2::crypto::Base for BsslCryptoProvider {
    type Error = CryptoError;

    fn unimplemented(&self, _alg: Alg) -> Self::Error {
        CryptoError::UnsupportedAlgorithm
    }
}

impl Rng for BsslCryptoProvider {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        bssl_crypto::rand_bytes(dest);
        Ok(())
    }
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
pub use {bssl::*, cmac::*, ecc::*, hash::*, symmetric::*};

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
