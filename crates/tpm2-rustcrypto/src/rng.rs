//! [`Random`]: a ChaCha20-based DRBG.

use core::fmt;

use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};
use sha2::{Digest, Sha256};
use tpm2::crypto::{CryptoError, Random, Rng};

use crate::RustCrypto;

/// ChaCha20-based deterministic random bit generator.
///
/// - [`Random::rng`] keys it with 32 bytes of entropy from the operating
///   system (via [`getrandom`]).
/// - [`Random::rng_seeded`] keys it with `SHA-256(seed)`.
/// - [`Rng::reseed`] draws 32 bytes from the current state and rekeys it
///   with `SHA-256(drawn || data)`.
pub struct ChaChaRng(pub(crate) ChaCha20Rng);

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

impl Rng for ChaChaRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        self.0.fill_bytes(dest);
        Ok(())
    }

    fn reseed(&mut self, data: &[u8]) -> Result<(), CryptoError> {
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

impl Random for RustCrypto {
    type Rng = ChaChaRng;

    fn rng(&self) -> Result<Self::Rng, CryptoError> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|_| CryptoError::Internal)?;
        Ok(ChaChaRng::from_key(key))
    }

    fn rng_seeded(&self, seed: &[u8]) -> Result<Self::Rng, CryptoError> {
        Ok(ChaChaRng::from_key(Sha256::digest(seed).into()))
    }
}
