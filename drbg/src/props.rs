use digest::{consts::U8, generic_array::ArrayLength, typenum::PartialDiv};

/// Table 2: Definitions for Hash-Based DRBG Mechanisms.
///
/// Do not derive this trait manually, instead use [`derive_hash_drbg_props`].
///
/// [`derive_hash_drbg_props`]: crate::derive_hash_drbg_props
pub trait HashDrbgProps {
    /// Seed length (seedlen) for Hash_DRBG in bits
    type SeedLenBits: ArrayLength<u8>;
    /// Seed length (seedlen) for Hash_DRBG converted to bytes
    type SeedLenBytes: ArrayLength<u8>;
    /// the numbers are taken from NIST test Vectors
    type EntropyLenBytes: ArrayLength<u8>;
    /// the numbers are taken from NIST test Vectors
    type NonceLenBytes: ArrayLength<u8>;
    /// highest_supported_security_strength
    const SECURITY_STRENGTH_BITS: usize;
    const SECURITY_STRENGTH_BYTES: usize = Self::SECURITY_STRENGTH_BITS / 8;
    /// 8.6.7.a Nonce: A value with at least (security_strength/2) bits of entropy
    const NONCE_BYTES_MIN: usize = Self::SECURITY_STRENGTH_BYTES / 2;
}

/// Divides by 8 ... type-wise
///
/// A utility type used by [`derive_hash_drbg_props`], it is usefull
/// for calculating [HashDrbgProps::SeedLenBytes].
///
/// [`derive_hash_drbg_props`]: crate::derive_hash_drbg_props
pub type BitsToBytes<T> = <T as PartialDiv<U8>>::Output;

/// This macro derives [`HashDrbgProps`] for a given type:
/// It currently support the following hash functions:
/// - `"sha224"`
/// - `"sha512/224"`
/// - `"sha256"`
///
/// # Examples
///
/// ```
/// use tpm2_rs_drbg::derive_hash_drbg_props;
///
/// struct MyCustomSha256;
///
/// // the rest of the implementation of sha256 follows here
/// // including implementing Digest.
///
/// derive_hash_drbg_props!("sha256", MyCustomSha256);
///
/// // now you can use HashDrbg<MyCustomSha256>
/// ```
#[macro_export]
macro_rules! derive_hash_drbg_props {
    ("sha224", $ty:path) => {
        impl $crate::HashDrbgProps for $ty {
            /// Table 2: Definitions for Hash-Based DRBG Mechanisms.
            type SeedLenBits = $crate::digest::consts::U440;
            type SeedLenBytes = $crate::BitsToBytes<Self::SeedLenBits>;
            type EntropyLenBytes = $crate::digest::consts::U24;
            type NonceLenBytes = $crate::digest::consts::U12;
            /// taken from [NIST SP 800-57 Part 1 Revision
            /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
            /// security strengths for hash and hash-based functions
            const SECURITY_STRENGTH_BITS: usize = 122;
        }
    };
    ("sha512/224", $ty:path) => {
        impl $crate::HashDrbgProps for $ty {
            /// Table 2: Definitions for Hash-Based DRBG Mechanisms.
            type SeedLenBits = $crate::digest::consts::U440;
            type SeedLenBytes = $crate::BitsToBytes<Self::SeedLenBits>;
            type EntropyLenBytes = $crate::digest::consts::U24;
            type NonceLenBytes = $crate::digest::consts::U12;
            /// taken from [NIST SP 800-57 Part 1 Revision
            /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
            /// security strengths for hash and hash-based functions
            const SECURITY_STRENGTH_BITS: usize = 122;
        }
    };
    ("sha256", $ty:path) => {
        impl $crate::HashDrbgProps for $ty {
            /// Table 2: Definitions for Hash-Based DRBG Mechanisms.
            type SeedLenBits = $crate::digest::consts::U440;
            type SeedLenBytes = $crate::BitsToBytes<Self::SeedLenBits>;
            type EntropyLenBytes = $crate::digest::consts::U32;
            type NonceLenBytes = $crate::digest::consts::U16;
            /// taken from [NIST SP 800-57 Part 1 Revision
            /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
            /// security strengths for hash and hash-based functions
            const SECURITY_STRENGTH_BITS: usize = 128;
        }
    };
    ("sha512/256", $ty:path) => {
        impl $crate::HashDrbgProps for $ty {
            /// Table 2: Definitions for Hash-Based DRBG Mechanisms.
            type SeedLenBits = $crate::digest::consts::U440;
            type SeedLenBytes = $crate::BitsToBytes<Self::SeedLenBits>;
            type EntropyLenBytes = $crate::digest::consts::U32;
            type NonceLenBytes = $crate::digest::consts::U16;
            /// taken from [NIST SP 800-57 Part 1 Revision
            /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
            /// security strengths for hash and hash-based functions
            const SECURITY_STRENGTH_BITS: usize = 128;
        }
    };
    ("sha384", $ty:path) => {
        impl $crate::HashDrbgProps for $ty {
            /// Table 2: Definitions for Hash-Based DRBG Mechanisms.
            type SeedLenBits = $crate::digest::consts::U888;
            type SeedLenBytes = $crate::BitsToBytes<Self::SeedLenBits>;
            type EntropyLenBytes = $crate::digest::consts::U32;
            type NonceLenBytes = $crate::digest::consts::U16;
            /// taken from [NIST SP 800-57 Part 1 Revision
            /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
            /// security strengths for hash and hash-based functions
            const SECURITY_STRENGTH_BITS: usize = 192;
        }
    };
    ("sha512", $ty:path) => {
        impl $crate::HashDrbgProps for $ty {
            /// Table 2: Definitions for Hash-Based DRBG Mechanisms.
            type SeedLenBits = $crate::digest::consts::U888;
            type SeedLenBytes = $crate::BitsToBytes<Self::SeedLenBits>;
            type EntropyLenBytes = $crate::digest::consts::U32;
            type NonceLenBytes = $crate::digest::consts::U16;
            /// taken from [NIST SP 800-57 Part 1 Revision
            /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
            /// security strengths for hash and hash-based functions
            const SECURITY_STRENGTH_BITS: usize = 256;
        }
    };
}

/// Table 2: Definitions for Hash-Based DRBG Mechanisms:
/// `max_number_of_bits_per_request`
pub const MAX_BITS_PER_REQUEST: usize = 1 << 19;
pub const MAX_BYTES_PER_REQUEST: usize = MAX_BITS_PER_REQUEST / 8;
/// Table 2: Definitions for Hash-Based DRBG Mechanisms:
/// `max_personalization_string_length`
pub const MAX_BITS_PERSONALIZATION_STRING: usize = 2 << 35;
pub const MAX_BYTES_PERSONALIZATION_STRING: usize = MAX_BITS_PERSONALIZATION_STRING / 8;
/// Table 2: Definitions for Hash-Based DRBG Mechanisms:
/// `max_additional_input_length`
pub const MAX_BITS_ADDITIONAL_INPUT: usize = 2 << 35;
pub const MAX_BYTES_ADDITIONAL_INPUT: usize = MAX_BITS_ADDITIONAL_INPUT / 8;
/// Table 2: Definitions for Hash-Based DRBG Mechanisms:
/// Maximum number of requests between reseeds (`reseed_interval`)
pub const MAX_REQUESTS_BETWEEN_RESEEDS: u64 = 2 << 48;
