use core::ops::{Add, Shr};
use digest::{
    consts::{U3, U7},
    generic_array::ArrayLength,
    Digest,
};

/// Table 2: Definitions for Hash-Based DRBG Mechanisms.
///
/// Do not derive this trait manually, instead use [`derive_hash_drbg_props`].
///
/// [`derive_hash_drbg_props`]: crate::derive_hash_drbg_props
pub trait HashDrbgProps: Digest {
    /// Seed length (seedlen) for Hash_DRBG in bits
    type SeedLenBits: ArrayLength<u8>;
    /// Seed length (seedlen) for Hash_DRBG converted to bytes
    type SeedLenBytes: ArrayLength<u8>;
    /// the numbers are taken from NIST test Vectors
    type EntropyLenBytes: ArrayLength<u8>;
    /// the numbers are taken from NIST test Vectors
    type NonceLenBytes: ArrayLength<u8>;
    /// highest_supported_security_strength
    const HIGHEST_SUPPORTED_SECURITY_STRENGTH_BITS: usize;
    const HIGHEST_SUPPORTED_SECURITY_STRENGTH_BYTES: usize =
        bits_to_bytes(Self::HIGHEST_SUPPORTED_SECURITY_STRENGTH_BITS);
    /// 8.6.7.a Nonce: A value with at least (security_strength/2) bits of entropy
    const NONCE_BYTES_MIN: usize = Self::HIGHEST_SUPPORTED_SECURITY_STRENGTH_BYTES / 2;
}

/// Divides by 8, rounding up ... type-wise
///
/// A utility type used by [`derive_hash_drbg_props`], it is usefull
/// for calculating [HashDrbgProps::SeedLenBytes]. This type calculates
/// the minimum number of bytes required to store given bits.
///
/// [`derive_hash_drbg_props`]: crate::derive_hash_drbg_props
// Hack: we must use the `>> 3` because division takes too much memory and is very
// slow to compute the types
pub type BitsToBytes<T> = <<T as Add<U7>>::Output as Shr<U3>>::Output;

/// Divides by 8, rounding up
///
/// A utility function that calculates the minimum number of bytes required to
/// store given bits.
pub const fn bits_to_bytes(bits: usize) -> usize {
    (bits + 7) / 8
}
/// This macro derives [`HashDrbgProps`] for a given type:
/// It currently support the following hash functions:
/// - `"sha224"`
/// - `"sha512/224"`
/// - `"sha256"`
///
/// # Examples
///
/// ```
/// use digest::{
///     consts::U32, Digest, FixedOutput, FixedOutputReset, Output, OutputSizeUser, Reset, Update,
/// };
/// use tpm2_rs_drbg::derive_hash_drbg_props;
/// #[derive(Default)]
/// struct MyCustomSha256;
///
/// impl OutputSizeUser for MyCustomSha256 {
///     type OutputSize = U32;
/// }
/// impl Reset for MyCustomSha256 {
///     fn reset(&mut self) {
///         todo!()
///     }
/// }
/// impl Update for MyCustomSha256 {
///     fn update(&mut self, data: &[u8]) {
///         todo!()
///     }
/// }
/// impl FixedOutput for MyCustomSha256 {
///     fn finalize_into(self, out: &mut Output<Self>) {
///         todo!()
///     }
/// }
/// impl FixedOutputReset for MyCustomSha256 {
///     fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
///         todo!()
///     }
/// }
/// impl Digest for MyCustomSha256 {
///     fn new() -> Self {
///         todo!()
///     }
///     fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
///         todo!()
///     }
///     fn update(&mut self, data: impl AsRef<[u8]>) {
///         todo!()
///     }
///     fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
///         todo!()
///     }
///     fn finalize(self) -> Output<Self> {
///         todo!()
///     }
///     fn finalize_into(self, out: &mut Output<Self>) {
///         todo!()
///     }
///     fn finalize_reset(&mut self) -> Output<Self>
///     where
///         Self: FixedOutputReset,
///     {
///         todo!()
///     }
///     fn finalize_into_reset(&mut self, out: &mut Output<Self>)
///     where
///         Self: FixedOutputReset,
///     {
///         todo!()
///     }
///     fn reset(&mut self)
///     where
///         Self: Reset,
///     {
///         todo!()
///     }
///     fn output_size() -> usize {
///         todo!()
///     }
///     fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
///         todo!()
///     }
/// }
/// derive_hash_drbg_props!("sha256", MyCustomSha256);
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
            const HIGHEST_SUPPORTED_SECURITY_STRENGTH_BITS: usize = 112;
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
            const HIGHEST_SUPPORTED_SECURITY_STRENGTH_BITS: usize = 112;
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
            const HIGHEST_SUPPORTED_SECURITY_STRENGTH_BITS: usize = 128;
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
            const HIGHEST_SUPPORTED_SECURITY_STRENGTH_BITS: usize = 128;
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
            const HIGHEST_SUPPORTED_SECURITY_STRENGTH_BITS: usize = 192;
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
            const HIGHEST_SUPPORTED_SECURITY_STRENGTH_BITS: usize = 256;
        }
    };
}

/// Table 2: Definitions for Hash-Based DRBG Mechanisms:
/// `max_number_of_bits_per_request`
pub const MAX_BITS_PER_REQUEST: usize = 1 << 19;
pub const MAX_BYTES_PER_REQUEST: usize = bits_to_bytes(MAX_BITS_PER_REQUEST);
/// Table 2: Definitions for Hash-Based DRBG Mechanisms:
/// `max_personalization_string_length`
pub const MAX_BITS_PERSONALIZATION_STRING: usize = 2 << 35;
pub const MAX_BYTES_PERSONALIZATION_STRING: usize = bits_to_bytes(MAX_BITS_PERSONALIZATION_STRING);
/// Table 2: Definitions for Hash-Based DRBG Mechanisms:
/// `max_additional_input_length`
pub const MAX_BITS_ADDITIONAL_INPUT: usize = 2 << 35;
pub const MAX_BYTES_ADDITIONAL_INPUT: usize = bits_to_bytes(MAX_BITS_ADDITIONAL_INPUT);
/// Table 2: Definitions for Hash-Based DRBG Mechanisms:
/// Maximum number of requests between reseeds (`reseed_interval`)
pub const MAX_REQUESTS_BETWEEN_RESEEDS: u64 = 2 << 48;

#[cfg(test)]
mod test {
    use super::{bits_to_bytes, BitsToBytes};
    use digest::{
        consts::{U0, U1, U10, U11, U12, U13, U14, U15, U16, U17, U2, U3, U4, U5, U6, U7, U8, U9},
        typenum::Unsigned,
    };

    #[test]
    fn test_bits_to_bytes_type() {
        assert_eq!(BitsToBytes::<U0>::to_usize(), 0);
        assert_eq!(BitsToBytes::<U1>::to_usize(), 1);
        assert_eq!(BitsToBytes::<U2>::to_usize(), 1);
        assert_eq!(BitsToBytes::<U3>::to_usize(), 1);
        assert_eq!(BitsToBytes::<U4>::to_usize(), 1);
        assert_eq!(BitsToBytes::<U5>::to_usize(), 1);
        assert_eq!(BitsToBytes::<U6>::to_usize(), 1);
        assert_eq!(BitsToBytes::<U7>::to_usize(), 1);
        assert_eq!(BitsToBytes::<U8>::to_usize(), 1);
        assert_eq!(BitsToBytes::<U9>::to_usize(), 2);
        assert_eq!(BitsToBytes::<U10>::to_usize(), 2);
        assert_eq!(BitsToBytes::<U11>::to_usize(), 2);
        assert_eq!(BitsToBytes::<U12>::to_usize(), 2);
        assert_eq!(BitsToBytes::<U13>::to_usize(), 2);
        assert_eq!(BitsToBytes::<U14>::to_usize(), 2);
        assert_eq!(BitsToBytes::<U15>::to_usize(), 2);
        assert_eq!(BitsToBytes::<U16>::to_usize(), 2);
        assert_eq!(BitsToBytes::<U17>::to_usize(), 3);
    }

    #[test]
    fn test_bits_to_bytese() {
        assert_eq!(bits_to_bytes(0), 0);
        assert_eq!(bits_to_bytes(1), 1);
        assert_eq!(bits_to_bytes(2), 1);
        assert_eq!(bits_to_bytes(3), 1);
        assert_eq!(bits_to_bytes(4), 1);
        assert_eq!(bits_to_bytes(5), 1);
        assert_eq!(bits_to_bytes(6), 1);
        assert_eq!(bits_to_bytes(7), 1);
        assert_eq!(bits_to_bytes(8), 1);
        assert_eq!(bits_to_bytes(9), 2);
        assert_eq!(bits_to_bytes(10), 2);
        assert_eq!(bits_to_bytes(11), 2);
        assert_eq!(bits_to_bytes(12), 2);
        assert_eq!(bits_to_bytes(13), 2);
        assert_eq!(bits_to_bytes(14), 2);
        assert_eq!(bits_to_bytes(15), 2);
        assert_eq!(bits_to_bytes(16), 2);
        assert_eq!(bits_to_bytes(17), 3);
    }
}
