//! Types related to hash algorithms and digests
use crate::{
    errors::{HashError, MarshalError, UnmarshalError},
    marshal::{Limits, Marshal, MarshalFixed, Unmarshal, UnmarshalFixed, pop_array},
};

/// Algorithms defined by either the `TPM_ALG_ID` listing in Part 2 of the
/// [TPM2 Specification] or the `TCG_ALG_ID` list in the
/// [TCG Algorithm Registry](https://trustedcomputinggroup.org/resource/tcg-algorithm-registry/).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
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
    #[inline(always)]
    fn marshal_fixed(&self, arr: &mut [u8; Self::SIZE]) {
        self.0.marshal_fixed(arr)
    }
}
impl UnmarshalFixed for Alg {
    #[inline(always)]
    fn unmarshal_value(arr: &Self::Array) -> Result<Self, UnmarshalError> {
        Ok(Self(u16::unmarshal_value(arr)?))
    }
}

#[cfg(test)]
mod test {
    use crate::TpmtHa;

    #[test]
    fn size_of_tpmt_ha() {
        assert_eq!(size_of::<TpmtHa>(), 2 * size_of::<usize>());
        assert_eq!(size_of::<Option<TpmtHa>>(), 2 * size_of::<usize>());
    }
}

/// `TPMI_ALG_HASH`
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u16)]
#[non_exhaustive]
pub enum TpmiAlgHash {
    Sha1 = Alg::Sha1.0,
    #[default]
    Sha256 = Alg::Sha256.0,
    Sha384 = Alg::Sha384.0,
    Sha512 = Alg::Sha512.0,
    Sm3_256 = Alg::Sm3_256.0,
    Sha3_256 = Alg::Sha3_256.0,
    Sha3_384 = Alg::Sha3_384.0,
    Sha3_512 = Alg::Sha3_512.0,
}
use TpmiAlgHash::*;

impl TpmiAlgHash {
    pub const fn digest_size(self) -> usize {
        match self {
            Sha1 => 160 / 8,
            Sha256 => 256 / 8,
            Sha384 => 384 / 8,
            Sha512 => 512 / 8,
            Sm3_256 => 256 / 8,
            Sha3_256 => 256 / 8,
            Sha3_384 => 384 / 8,
            Sha3_512 => 512 / 8,
        }
    }
}

impl From<TpmiAlgHash> for Alg {
    fn from(h: TpmiAlgHash) -> Alg {
        Alg(h as u16)
    }
}
impl TryFrom<Alg> for TpmiAlgHash {
    type Error = HashError;
    fn try_from(a: Alg) -> Result<TpmiAlgHash, Self::Error> {
        match a {
            Alg::Sha1 => Ok(Sha1),
            Alg::Sha256 => Ok(Sha256),
            Alg::Sha384 => Ok(Sha384),
            Alg::Sha512 => Ok(Sha512),
            Alg::Sm3_256 => Ok(Sm3_256),
            Alg::Sha3_256 => Ok(Sha3_256),
            Alg::Sha3_384 => Ok(Sha3_384),
            Alg::Sha3_512 => Ok(Sha3_512),
            _ => Err(HashError),
        }
    }
}

impl MarshalFixed for TpmiAlgHash {
    const SIZE: usize = 2;
    type Array = [u8; 2];
    #[inline(always)]
    fn marshal_fixed(&self, arr: &mut [u8; Self::SIZE]) {
        Alg::from(*self).marshal_fixed(arr)
    }
}
impl UnmarshalFixed for TpmiAlgHash {
    fn unmarshal_value(arr: &Self::Array) -> Result<Self, UnmarshalError> {
        Ok(Alg::unmarshal_value(arr)?.try_into()?)
    }
}

/// `TPMT_HA`
///
/// There is no type for `TPMU_HA` in this crate, use this type instead.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtHa<'a> {
    Sha1(&'a [u8; Sha1.digest_size()]) = Alg::Sha1.0,
    Sha256(&'a [u8; Sha256.digest_size()]) = Alg::Sha256.0,
    Sha384(&'a [u8; Sha384.digest_size()]) = Alg::Sha384.0,
    Sha512(&'a [u8; Sha512.digest_size()]) = Alg::Sha512.0,
    Sm3_256(&'a [u8; Sm3_256.digest_size()]) = Alg::Sm3_256.0,
    Sha3_256(&'a [u8; Sha3_256.digest_size()]) = Alg::Sha3_256.0,
    Sha3_384(&'a [u8; Sha3_384.digest_size()]) = Alg::Sha3_384.0,
    Sha3_512(&'a [u8; Sha3_512.digest_size()]) = Alg::Sha3_512.0,
}

impl<'a> TpmtHa<'a> {
    pub const fn hash_alg(self) -> TpmiAlgHash {
        match self {
            Self::Sha1(_) => Sha1,
            Self::Sha256(_) => Sha256,
            Self::Sha384(_) => Sha384,
            Self::Sha512(_) => Sha512,
            Self::Sm3_256(_) => Sm3_256,
            Self::Sha3_256(_) => Sha3_256,
            Self::Sha3_384(_) => Sha3_384,
            Self::Sha3_512(_) => Sha3_512,
        }
    }
    pub fn digest(self) -> &'a [u8] {
        match self {
            Self::Sha1(d) => d,
            Self::Sha256(d) => d,
            Self::Sha384(d) => d,
            Self::Sha512(d) => d,
            Self::Sm3_256(d) => d,
            Self::Sha3_256(d) => d,
            Self::Sha3_384(d) => d,
            Self::Sha3_512(d) => d,
        }
    }
}

impl<'a> Marshal for TpmtHa<'a> {
    fn marshal<'dst, L: Limits>(
        &self,
        buf: &'dst mut [u8],
    ) -> Result<&'dst mut [u8], MarshalError> {
        if !L::SUPPORTED_HASH_ALGS.contains(&self.hash_alg()) {
            return Err(MarshalError);
        }
        let buf = self.hash_alg().marshal::<L>(buf)?;
        match self {
            Self::Sha1(d) => d.marshal::<L>(buf),
            Self::Sha256(d) => d.marshal::<L>(buf),
            Self::Sha384(d) => d.marshal::<L>(buf),
            Self::Sha512(d) => d.marshal::<L>(buf),
            Self::Sm3_256(d) => d.marshal::<L>(buf),
            Self::Sha3_256(d) => d.marshal::<L>(buf),
            Self::Sha3_384(d) => d.marshal::<L>(buf),
            Self::Sha3_512(d) => d.marshal::<L>(buf),
        }
    }
    fn marshaled_size(&self) -> usize {
        2 + self.hash_alg().digest_size()
    }
    fn marshaled_size_max<L: Limits>() -> usize {
        2 + L::MAX_DIGEST_SIZE
    }
}
impl<'a, 'src: 'a> Unmarshal<'src> for TpmtHa<'a> {
    fn unmarshal<L: Limits>(&mut self, mut buf: &'src [u8]) -> Result<&'src [u8], UnmarshalError> {
        *self = match TpmiAlgHash::unmarshal_value(pop_array(&mut buf)?)? {
            Sha1 if L::SUPPORTED_HASH_ALGS.contains(&Sha1) => Self::Sha1(pop_array(&mut buf)?),
            Sha256 if L::SUPPORTED_HASH_ALGS.contains(&Sha256) => {
                Self::Sha256(pop_array(&mut buf)?)
            }
            Sha384 if L::SUPPORTED_HASH_ALGS.contains(&Sha384) => {
                Self::Sha384(pop_array(&mut buf)?)
            }
            Sha512 if L::SUPPORTED_HASH_ALGS.contains(&Sha512) => {
                Self::Sha512(pop_array(&mut buf)?)
            }
            Sm3_256 if L::SUPPORTED_HASH_ALGS.contains(&Sm3_256) => {
                Self::Sm3_256(pop_array(&mut buf)?)
            }
            Sha3_256 if L::SUPPORTED_HASH_ALGS.contains(&Sha3_256) => {
                Self::Sha3_256(pop_array(&mut buf)?)
            }
            Sha3_384 if L::SUPPORTED_HASH_ALGS.contains(&Sha3_384) => {
                Self::Sha3_384(pop_array(&mut buf)?)
            }
            Sha3_512 if L::SUPPORTED_HASH_ALGS.contains(&Sha3_512) => {
                Self::Sha3_512(pop_array(&mut buf)?)
            }
            _ => return Err(UnmarshalError),
        };
        Ok(buf)
    }
}
