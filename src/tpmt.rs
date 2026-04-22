//! `TPMT_` tagged union types

use crate::{
    Alg, Limits, Marshal, TpmiAlgHash, Unmarshal, UnmarshalArray,
    errors::{MarshalError, UnmarshalError},
};

use TpmiAlgHash::*;
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

        match TpmiAlgHash::unmarshal_array(arr)? {
            TpmiAlgHash::Sha1 if limits.supports_hash(Sha1) => {
                let (arr, buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
                *self = Self::Sha1(arr);
                Ok(buf)
            }
            TpmiAlgHash::Sha256 if limits.supports_hash(Sha256) => {
                let (arr, buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
                *self = Self::Sha256(arr);
                Ok(buf)
            }
            TpmiAlgHash::Sha384 if limits.supports_hash(Sha384) => {
                let (arr, buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
                *self = Self::Sha384(arr);
                Ok(buf)
            }
            TpmiAlgHash::Sha512 if limits.supports_hash(Sha512) => {
                let (arr, buf) = buf.split_first_chunk().ok_or(UnmarshalError)?;
                *self = Self::Sha512(arr);
                Ok(buf)
            }
            _ => Err(UnmarshalError),
        }
    }
}
