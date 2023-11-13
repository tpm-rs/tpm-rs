/// Provides access to cryptographic operations.
pub trait Crypto: CryptoRandom {}

// For all types that implement every Crypto sub trait, also implement the combined trait.
impl<T: CryptoRandom> Crypto for T {}

/// Provides cryptographic operations for random numbers.
pub trait CryptoRandom {
    /// Filles the specified buffer up with random bytes.
    fn get_random_bytes(&mut self, buffer: &mut [u8]);
}
