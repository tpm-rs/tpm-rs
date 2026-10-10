//! [`Random`] implementation: a ChaCha20-based DRBG seeded via BoringSSL.

use core::fmt;

use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};
use tpm2::crypto::{CryptoError, Random, Rng};

use crate::{BoringSsl, bssl};

/// ChaCha20-based deterministic random bit generator.
///
/// - [`Random::rng`] keys it with 32 bytes of entropy from BoringSSL's CSPRNG
///   ([`bssl_crypto::rand_bytes`]).
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
        let mut hasher = bssl_crypto::digest::Sha256::new();
        hasher.update(&drawn);
        hasher.update(data);
        *self = Self::from_key(hasher.digest());
        Ok(())
    }
}

impl Random for BoringSsl {
    type Rng = ChaChaRng;

    fn rng(&self) -> Result<ChaChaRng, CryptoError> {
        let mut key = [0u8; 32];
        bssl::rand_bytes(&mut key);
        Ok(ChaChaRng::from_key(key))
    }

    fn rng_seeded(&self, seed: &[u8]) -> Result<ChaChaRng, CryptoError> {
        Ok(ChaChaRng::from_key(bssl_crypto::digest::Sha256::hash(seed)))
    }
}
