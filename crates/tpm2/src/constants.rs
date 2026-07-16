//! Constants and C-like enums

use core::fmt::Debug;

use crate::BE;

/// Algorithms defined by either the `TPM_ALG_ID` listing in Part 2 of the
/// [TPM2 Specification] or the `TCG_ALG_ID` list in the
/// [TCG Algorithm Registry](https://trustedcomputinggroup.org/resource/tcg-algorithm-registry/).
///
/// [TPM2 Specification]: https://trustedcomputinggroup.org/work-groups/trusted-platform-module/
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Alg(pub(crate) BE<u16>);

// We do this for naming consistency with the other algorithm enums.
// TODO: Should this just be an enum?
#[allow(non_upper_case_globals)]
impl Alg {
    /// Creates a new [`Alg`] from raw 16-bit algorithm ID numerical value.
    #[inline(always)]
    pub const fn new(id: u16) -> Self {
        Self(BE::<u16>::new(id))
    }

    pub const Rsa: Self = Self::new(0x0001);
    pub const Tdes: Self = Self::new(0x0003);
    pub const Sha1: Self = Self::new(0x0004);
    pub const Hmac: Self = Self::new(0x0005);
    pub const Aes: Self = Self::new(0x0006);
    pub const Mgf1: Self = Self::new(0x0007);
    pub const KeyedHash: Self = Self::new(0x0008);
    pub const Null: Self = Self::new(0x0010);
    pub const Xor: Self = Self::new(0x000A);
    pub const Sha256: Self = Self::new(0x000B);
    pub const Sha384: Self = Self::new(0x000C);
    pub const Sha512: Self = Self::new(0x000D);
    pub const Sm3_256: Self = Self::new(0x0012);
    pub const Sm4: Self = Self::new(0x0013);
    pub const RsaSsa: Self = Self::new(0x0014);
    pub const RsaEs: Self = Self::new(0x0015);
    pub const RsaPss: Self = Self::new(0x0016);
    pub const Oaep: Self = Self::new(0x0017);
    pub const Ecdsa: Self = Self::new(0x0018);
    pub const Ecdh: Self = Self::new(0x0019);
    pub const Ecdaa: Self = Self::new(0x001A);
    pub const Sm2: Self = Self::new(0x001B);
    pub const EcSchnorr: Self = Self::new(0x001C);
    pub const Ecmqv: Self = Self::new(0x001D);
    pub const Kdf1Sp800_56A: Self = Self::new(0x0020);
    pub const Kdf2: Self = Self::new(0x0021);
    pub const Kdf1Sp800_108: Self = Self::new(0x0022);
    pub const Ecc: Self = Self::new(0x0023);
    pub const SymCipher: Self = Self::new(0x0025);
    pub const Camellia: Self = Self::new(0x0026);
    pub const Sha3_256: Self = Self::new(0x0027);
    pub const Sha3_384: Self = Self::new(0x0028);
    pub const Sha3_512: Self = Self::new(0x0029);
    pub const Ctr: Self = Self::new(0x0040);
    pub const Ofb: Self = Self::new(0x0041);
    pub const Cbc: Self = Self::new(0x0042);
    pub const Cfb: Self = Self::new(0x0043);
    pub const Ecb: Self = Self::new(0x0044);
}

impl Default for Alg {
    fn default() -> Self {
        Self::Null
    }
}
