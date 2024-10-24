use crate::derive_hash_drbg_props;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

derive_hash_drbg_props!("sha224", Sha224);
derive_hash_drbg_props!("sha512/224", Sha512_224);
derive_hash_drbg_props!("sha256", Sha256);
derive_hash_drbg_props!("sha512/256", Sha512_256);
derive_hash_drbg_props!("sha384", Sha384);
derive_hash_drbg_props!("sha512", Sha512);

#[cfg(test)]
mod test {
    use crate::{BitsToBytes, HashDrbgProps};
    use digest::consts::{U16, U440, U8};
    use sha1::Sha1;
    /// Sha1 is not longer recommended for usage, we only include it here
    /// for testing purposes
    impl HashDrbgProps for Sha1 {
        type SeedLenBits = U440;
        /// it is U888 divided by 8
        type SeedLenBytes = BitsToBytes<Self::SeedLenBits>;
        type EntropyLenBytes = U16;
        type NonceLenBytes = U8;
        /// taken from [NIST SP 800-57 Part 1 Revision
        /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
        /// security strengths for hash and hash-based functions
        const SECURITY_STRENGTH_BITS: usize = 80;
    }
}
