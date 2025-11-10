//! Constant (`TPM_`) types defined in Part 2, Section 6 "Constants"

use crate::{
    errors::UnmarshalError,
    marshal::{Limits, MarshalFixed, UnmarshalFixed},
};

/// Algorithms defined by either `TPM_ALG_ID` in Part 2 of the
/// [TPM2 Specification] or `TCG_ALG_ID` in the [TCG Algorithm Registry].
///
/// [TPM2 Specification]: https://trustedcomputinggroup.org/work-groups/trusted-platform-module/
/// [TCG Algorithm Registry]: https://trustedcomputinggroup.org/resource/tcg-algorithm-registry/
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Alg(pub u16);

// We do this for naming consistnancy with the other algorithm enums.
// TODO: Should this just be an enum?
#[allow(non_upper_case_globals)]
impl Alg {
    pub const Rsa: Self = Self(0x0001);
    pub const Tdes: Self = Self(0x0003);
    pub const Sha1: Self = Self(0x0004);
    pub const Hmac: Self = Self(0x0005);
    pub const Aes: Self = Self(0x0006);
    pub const Mgf1: Self = Self(0x0007);
    pub const KeyedHash: Self = Self(0x0008);
    pub const Null: Self = Self(0x0010);
    pub const Xor: Self = Self(0x000A);
    pub const Sha256: Self = Self(0x000B);
    pub const Sha384: Self = Self(0x000C);
    pub const Sha512: Self = Self(0x000D);
    pub const Sm3_256: Self = Self(0x0012);
    pub const Sm4: Self = Self(0x0013);
    pub const RsaSsa: Self = Self(0x0014);
    pub const RsaEs: Self = Self(0x0015);
    pub const RsaPss: Self = Self(0x0016);
    pub const Oaep: Self = Self(0x0017);
    pub const Ecdsa: Self = Self(0x0018);
    pub const Ecdh: Self = Self(0x0019);
    pub const Ecdaa: Self = Self(0x001A);
    pub const Sm2: Self = Self(0x001B);
    pub const EcSchnorr: Self = Self(0x001C);
    pub const Ecmqv: Self = Self(0x001D);
    pub const Kdf1Sp800_56A: Self = Self(0x0020);
    pub const Kdf2: Self = Self(0x0021);
    pub const Kdf1Sp800_108: Self = Self(0x0022);
    pub const Ecc: Self = Self(0x0023);
    pub const SymCipher: Self = Self(0x0025);
    pub const Camellia: Self = Self(0x0026);
    pub const Sha3_256: Self = Self(0x0027);
    pub const Sha3_384: Self = Self(0x0028);
    pub const Sha3_512: Self = Self(0x0029);
    pub const Ctr: Self = Self(0x0040);
    pub const Ofb: Self = Self(0x0041);
    pub const Cbc: Self = Self(0x0042);
    pub const Cfb: Self = Self(0x0043);
    pub const Ecb: Self = Self(0x0044);
}

impl MarshalFixed for Alg {
    const SIZE: usize = 2;
    type Array = [u8; 2];
    fn marshal_fixed(&self, arr: &mut [u8; Self::SIZE]) {
        self.0.marshal_fixed(arr)
    }
}
impl UnmarshalFixed for Alg {
    fn unmarshal_fixed<L: Limits>(arr: &Self::Array) -> Result<Self, UnmarshalError> {
        Ok(Self(UnmarshalFixed::unmarshal_fixed::<L>(arr)?))
    }
}
