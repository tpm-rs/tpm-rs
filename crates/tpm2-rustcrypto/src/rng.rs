//! [`Random`] and [`Rng`]: a ChaCha20-based RNG.

use core::fmt;

use rand_chacha::{
    ChaCha20Rng,
    rand_core::{Rng as _, SeedableRng},
};
use sha2::{Digest, Sha256};
use tpm2::crypto::{CryptoError, Random, Rng};

use crate::RustCrypto;

/// ChaCha20-based random number generator.
///
/// - [`Random::from_entropy`] keys it with 32 bytes from the OS (via
///   `getrandom`).
/// - [`Random::from_seed`] keys it with `SHA-256(seed)`.
/// - [`Rng::stir_bytes`] draws 32 bytes from the current state and rekeys it
///   with `SHA-256(drawn || data)`.
pub struct ChaChaRng(ChaCha20Rng);

impl ChaChaRng {
    fn from_key(key: [u8; 32]) -> Self {
        Self(ChaCha20Rng::from_seed(key))
    }
}

impl fmt::Debug for ChaChaRng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't leak the RNG state.
        f.debug_struct("ChaChaRng").finish_non_exhaustive()
    }
}

impl Random for RustCrypto {
    type Rng = ChaChaRng;

    fn from_entropy() -> Result<ChaChaRng, CryptoError> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|_| CryptoError::Internal)?;
        Ok(ChaChaRng::from_key(key))
    }

    fn from_seed(seed: &[u8]) -> Result<ChaChaRng, CryptoError> {
        Ok(ChaChaRng::from_key(Sha256::digest(seed).into()))
    }

    fn rand_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::fill(out).map_err(|_| CryptoError::Internal)
    }
}

impl Rng for ChaChaRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.0.fill_bytes(out);
        Ok(())
    }

    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let mut drawn = [0u8; 32];
        self.0.fill_bytes(&mut drawn);
        let key = Sha256::new()
            .chain_update(drawn)
            .chain_update(data)
            .finalize();
        *self = Self::from_key(key.into());
        Ok(())
    }
}
