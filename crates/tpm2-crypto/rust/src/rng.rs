//! Random number generation: [`RustCryptoRng`] and the [`RngAdapter`] to the `rand_core` traits.

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng as _};
use sha2::{Digest as _, Sha256};
use tpm2::crypto::{CryptoError, Rng};

/// The random number generator of [`RustCryptoProvider`](crate::RustCryptoProvider).
///
/// Either the operating system's entropy source ([`Random::from_entropy`]), or a deterministic
/// ChaCha20 generator ([`Random::from_seed`]) keyed with `SHA-256(seed)`, whose output depends
/// only on the seed and the sequence of calls (`rand_chacha`'s ChaCha20 stream is portable and
/// stable across versions).
///
/// [`Random::from_entropy`]: tpm2::crypto::Random::from_entropy
/// [`Random::from_seed`]: tpm2::crypto::Random::from_seed
#[allow(clippy::large_enum_variant)]
pub enum RustCryptoRng {
    /// The standard operating system source of entropy.
    Os(rand_core::OsRng),
    /// A cryptographically secure pseudo-random number generator (CSPRNG) seeded for
    /// deterministic execution.
    Seeded(ChaCha20Rng),
}

impl RustCryptoRng {
    /// The generator of the operating system's entropy source.
    pub fn os() -> Self {
        Self::Os(rand_core::OsRng)
    }

    /// The deterministic generator of `seed`: ChaCha20 keyed with `SHA-256(seed)`.
    pub fn seeded(seed: &[u8]) -> Self {
        Self::Seeded(ChaCha20Rng::from_seed(Sha256::digest(seed).into()))
    }
}

impl Rng for RustCryptoRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Os(rng) => rng.try_fill_bytes(out).map_err(|_| CryptoError::Internal),
            Self::Seeded(rng) => {
                rng.fill_bytes(out);
                Ok(())
            }
        }
    }

    /// Mixes `data` into a seeded generator, deterministically: the new ChaCha20 key is
    /// `SHA-256(K || data)`, where `K` are the next 32 output bytes of the generator.
    ///
    /// The operating system's entropy source is continuously reseeded and cannot be stirred, so
    /// `data` is ignored for it.
    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if let Self::Seeded(rng) = self {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key);
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(data);
            *rng = ChaCha20Rng::from_seed(hasher.finalize().into());
            key.fill(0);
        }
        Ok(())
    }
}

/// Adapts a [`tpm2::crypto::Rng`] to the `rand_core` 0.6 [`RngCore`] and [`CryptoRng`] traits of
/// the RustCrypto libraries (`rsa`, `p256`, ...), for any backend's random number generator.
///
/// [`RngCore::fill_bytes`] cannot fail: if the underlying generator fails, the output is zeroed
/// and the failure recorded, so the caller must discard the result of the operation and return
/// [`CryptoError::Internal`] (see [`RngAdapter::finish`]).
pub struct RngAdapter<'a, R: Rng> {
    rng: &'a mut R,
    failed: bool,
}

impl<'a, R: Rng> RngAdapter<'a, R> {
    /// Wraps `rng`.
    pub fn new(rng: &'a mut R) -> Self {
        Self { rng, failed: false }
    }

    /// Returns `result` (the result of an operation that drew from this adapter), or
    /// [`CryptoError::Internal`] if the underlying generator failed.
    pub fn finish<T>(self, result: T) -> Result<T, CryptoError> {
        if self.failed {
            Err(CryptoError::Internal)
        } else {
            Ok(result)
        }
    }
}

impl<R: Rng> RngCore for RngAdapter<'_, R> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.failed || self.rng.fill_bytes(dest).is_err() {
            self.failed = true;
            dest.fill(0);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        RngCore::fill_bytes(self, dest);
        if self.failed {
            Err(rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START)
                    .unwrap_or(core::num::NonZeroU32::MIN),
            ))
        } else {
            Ok(())
        }
    }
}

impl<R: Rng> CryptoRng for RngAdapter<'_, R> {}
