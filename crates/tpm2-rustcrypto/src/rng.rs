//! [`Random`]: a ChaCha20-based DRBG.

use core::fmt;

use rand_chacha::{
    ChaCha20Rng,
    rand_core::{Rng as _, SeedableRng},
};
use sha2::{Digest, Sha256};
use tpm2::crypto::{CryptoError, Rng};

/// ChaCha20-based deterministic random bit generator.
///
/// - [`Rng::from_seed`] keys it with `SHA-256(seed)`.
/// - [`Rng::reseed`] draws 32 bytes from the current state and rekeys it
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

impl Rng for ChaChaRng {
    fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self::from_key(Sha256::digest(seed).into()))
    }

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
