//! TPM 2.0 Random Number Generator (RNG) Abstractions
//!
//! This module defines the cryptographic traits required for random number generation in TPM 2.0,
//! including TRNG (True Random Number Generator) and DRBG (Deterministic Random Bit Generator)
//! operations.
//!
//! ### Provider Abstraction
//!
//! Similar to other cryptographic components in `tpm-rs`, these operations are defined as traits
//! rather than concrete structs. This allows the core library to remain independent of the
//! underlying cryptographic backend (e.g., RustCrypto, BoringSSL).
//!
//! Users can implement these traits for their specific hardware or software stack and provide
//! the implementation via the [`CryptoProvider`](super::CryptoProvider) trait.
//!
//! ### Error Handling
//!
//! All operations return [`CryptoError`] to indicate failure. This includes errors returned
//! by the hardware itself (wrapped as [`CryptoError::HardwareFailure`]) and client-side
//! validation errors (e.g., [`CryptoError::InvalidData`]).
use super::CryptoError;

pub trait Rng {
    /// Fills the provided buffer with cryptographically secure random bytes.
    ///
    /// # Errors
    /// * `CryptoError::HardwareFailure` - Returned if the underlying entropy source fails (e.g. TRNG runs out of entropy, continuous health test failure).
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError>;

    /// Mixes additional entropy into the RNG state (`platform.crypto.stir_random`).
    ///
    /// # Errors
    /// * `CryptoError::HardwareFailure` - Returned if the underlying entropy source fails to stir.
    fn stir_random(&self, _in_data: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}
