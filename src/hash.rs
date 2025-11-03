//! Types related to hash algorithms and digests

use crate::{
    Alg, HashError, Limits, Marshal, MarshalError, MarshalFixed, Unmarshal, UnmarshalError,
    UnmarshalFixed,
};

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
            Sha1 => 20,
            Sha256 => 32,
            Sha384 => 48,
            Sha512 => 64,
            Sm3_256 => 32,
            Sha3_256 => 32,
            Sha3_384 => 48,
            Sha3_512 => 64,
        }
    }
    /// Hash Algs sorted in descending order of digest size
    pub(crate) const BY_SIZE_DESC: &[Self] = &[
        Sha512, Sha3_512, Sha384, Sha3_384, Sha256, Sha3_256, Sm3_256, Sha1,
    ];
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
    fn unmarshal_fixed(&mut self, arr: &[u8; Self::SIZE]) -> Result<(), UnmarshalError> {
        *self = Alg::unmarshal_value(arr)?.try_into()?;
        Ok(())
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
    // TODO: Add other Hash Algs
}

impl<'a> TpmtHa<'a> {
    pub const fn hash_alg(self) -> TpmiAlgHash {
        match self {
            Self::Sha1(_) => Sha1,
            Self::Sha256(_) => Sha256,
            Self::Sha384(_) => Sha384,
            Self::Sha512(_) => Sha512,
        }
    }
    pub fn digest(self) -> &'a [u8] {
        match self {
            Self::Sha1(d) => d,
            Self::Sha256(d) => d,
            Self::Sha384(d) => d,
            Self::Sha512(d) => d,
        }
    }
}

impl<'a> Marshal for TpmtHa<'a> {
    fn marshal<'dst>(
        &self,
        limits: impl Limits,
        buf: &'dst mut [u8],
    ) -> Result<&'dst mut [u8], MarshalError> {
        if !limits.supports_hash(self.hash_alg()) {
            return Err(MarshalError);
        }
        let buf = self.hash_alg().marshal(limits, buf)?;
        match self {
            Self::Sha1(d) => d.marshal(limits, buf),
            Self::Sha256(d) => d.marshal(limits, buf),
            Self::Sha384(d) => d.marshal(limits, buf),
            Self::Sha512(d) => d.marshal(limits, buf),
        }
    }
    fn marshaled_size(&self) -> usize {
        2 + self.hash_alg().digest_size()
    }
    fn marshaled_size_max(limits: impl Limits) -> usize {
        2 + limits.max_digest_size()
    }
}
impl<'a, 'src: 'a> Unmarshal<'src> for TpmtHa<'a> {
    fn unmarshal(
        &mut self,
        limits: impl Limits,
        buf: &'src [u8],
    ) -> Result<&'src [u8], UnmarshalError> {
        let (arr, buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
        match TpmiAlgHash::unmarshal_value(arr)? {
            Sha1 if limits.supports_hash(Sha1) => {
                let (arr, buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
                *self = Self::Sha1(arr);
                Ok(buf)
            }
            Sha256 if limits.supports_hash(Sha256) => {
                let (arr, buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
                *self = Self::Sha256(arr);
                Ok(buf)
            }
            Sha384 if limits.supports_hash(Sha384) => {
                let (arr, buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
                *self = Self::Sha384(arr);
                Ok(buf)
            }
            Sha512 if limits.supports_hash(Sha512) => {
                let (arr, buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
                *self = Self::Sha512(arr);
                Ok(buf)
            }
            _ => Err(UnmarshalError),
        }
    }
}
