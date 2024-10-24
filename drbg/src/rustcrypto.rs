use crate::HashDrbgProps;
use digest::consts::{U440, U8, U888};
use digest::typenum::PartialDiv;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

/// Divides by 8 ... type-wise
///
/// usefull for calculating [HashDrbgProps::SeedLenBytes]
#[cfg(any(test, feature = "rustcrypto"))]
type BitsToBytes<T> = <T as PartialDiv<U8>>::Output;

impl HashDrbgProps for Sha224 {
    type SeedLenBits = U440;
    type SeedLenBytes = BitsToBytes<Self::SeedLenBits>;
    /// taken from [NIST SP 800-57 Part 1 Revision
    /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
    /// security strengths for hash and hash-based functions
    const SECURITY_STRENGTH_BITS: usize = 122;
}

impl HashDrbgProps for Sha512_224 {
    type SeedLenBits = U440;
    type SeedLenBytes = BitsToBytes<Self::SeedLenBits>;
    /// taken from [NIST SP 800-57 Part 1 Revision
    /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
    /// security strengths for hash and hash-based functions
    const SECURITY_STRENGTH_BITS: usize = 122;
}

impl HashDrbgProps for Sha256 {
    type SeedLenBits = U440;
    type SeedLenBytes = BitsToBytes<Self::SeedLenBits>;
    /// taken from [NIST SP 800-57 Part 1 Revision
    /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
    /// security strengths for hash and hash-based functions
    const SECURITY_STRENGTH_BITS: usize = 128;
}

impl HashDrbgProps for Sha512_256 {
    type SeedLenBits = U440;
    type SeedLenBytes = BitsToBytes<Self::SeedLenBits>;
    /// taken from [NIST SP 800-57 Part 1 Revision
    /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
    /// security strengths for hash and hash-based functions
    const SECURITY_STRENGTH_BITS: usize = 128;
}

impl HashDrbgProps for Sha384 {
    type SeedLenBits = U888;
    type SeedLenBytes = BitsToBytes<Self::SeedLenBits>;
    /// taken from [NIST SP 800-57 Part 1 Revision
    /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
    /// security strengths for hash and hash-based functions
    const SECURITY_STRENGTH_BITS: usize = 192;
}

impl HashDrbgProps for Sha512 {
    type SeedLenBits = U888;
    type SeedLenBytes = BitsToBytes<Self::SeedLenBits>;
    /// taken from [NIST SP 800-57 Part 1 Revision
    /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
    /// security strengths for hash and hash-based functions
    const SECURITY_STRENGTH_BITS: usize = 256;
}

#[cfg(test)]
mod test {
    use super::{BitsToBytes, HashDrbgProps};
    use digest::consts::U440;
    use sha1::Sha1;
    /// Sha1 is not longer recommended for usage, we only include it here
    /// for testing purposes
    impl HashDrbgProps for Sha1 {
        type SeedLenBits = U440;
        /// it is U888 divided by 8
        type SeedLenBytes = BitsToBytes<Self::SeedLenBits>;
        /// taken from [NIST SP 800-57 Part 1 Revision
        /// 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) Table 3: Maximum
        /// security strengths for hash and hash-based functions
        const SECURITY_STRENGTH_BITS: usize = 80;
    }
}
