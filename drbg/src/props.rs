use digest::generic_array::ArrayLength;

/// Table 2: Definitions for Hash-Based DRBG Mechanisms.
pub trait HashDrbgProps {
    /// Seed length (seedlen) for Hash_DRBG in bits
    type SeedLenBits: ArrayLength<u8>;
    /// Seed length (seedlen) for Hash_DRBG converted to bytes
    type SeedLenBytes: ArrayLength<u8>;
    /// highest_supported_security_strength
    const SECURITY_STRENGTH_BITS: usize;
    const SECURITY_STRENGTH_BYTES: usize = Self::SECURITY_STRENGTH_BITS / 8;
}
