use digest::{generic_array::ArrayLength, Digest};

/// Divides by 8, rounding up
///
/// A utility function that calculates the minimum number of bytes required to
/// store given bits.
pub const fn bits_to_bytes(bits: usize) -> usize {
    bits.div_ceil(8)
}

/// Constants for Hash-Based DRBG Mechanisms.
pub trait HashDrbgProps: Digest {
    /// Table 2: `outlen`
    type OutLenBits: ArrayLength<u8>;
    /// Table 2: `outlen` in Bytes
    type OutLenBytes: ArrayLength<u8>;

    /// Length of Expected Entropy.
    /// According to Table 2, must be between `security_strength` and 2**35 bits.
    type EntropyLenBytes: ArrayLength<u8>;

    /// Table 2: Seed length (seedlen) for Hash_DRBG in bits
    type SeedLenBits: ArrayLength<u8>;
    /// Table 2: Seed length (seedlen) for Hash_DRBG converted to bytes
    type SeedLenBytes: ArrayLength<u8>;

    /// Table 2: `max_personalization_string_length`
    const MAX_PERSONALIZATION_STRING_BITS: usize = usize::pow(2, 35);
    /// Table 2: `max_personalization_string_length` in bytes
    const MAX_PERSONALIZATION_STRING_BYTES: usize =
        bits_to_bytes(Self::MAX_PERSONALIZATION_STRING_BITS);

    /// Table 2: `max_additional_input_length`
    const MAX_ADDITIONAL_INPUT_BITS: usize = usize::pow(2, 35);
    /// Table 2: `max_additional_input_length` in bytes
    const MAX_ADDITIONAL_INPUT_BYTES: usize = bits_to_bytes(Self::MAX_ADDITIONAL_INPUT_BITS);

    /// Table 2: `max_number_of_bits_per_request`
    const MAX_BITS_PER_REQUEST: usize = usize::pow(2, 19);
    /// Table 2: `max_number_of_bits_per_request` in bytes
    const MAX_BYTES_PER_REQUEST: usize = bits_to_bytes(Self::MAX_BITS_PER_REQUEST);

    /// Table 2: `reseed_interval`
    const MAX_REQUESTS_BETWEEN_RESEEDS: u64 = u64::pow(2, 48);

    /// This implementation Requires a nonce.
    ///
    /// 8.6.7: A nonce may be required in the construction of a seed during instantiation in order
    /// to provide a security cushion to block certain attacks.
    type NonceLenBytes: ArrayLength<u8>;
}

#[cfg(test)]
mod test {
    use super::bits_to_bytes;

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
