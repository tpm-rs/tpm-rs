//! `TPMI_` interface types
use crate::{
    Alg,
    errors::{HashError, UnmarshalError},
    marshal::{MarshalArray, UnmarshalArray},
};

/// `TPMI_ALG_HASH`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
#[non_exhaustive]
pub enum TpmiAlgHash {
    Sha1 = Alg::Sha1.0,
    Sha256 = Alg::Sha256.0,
    Sha384 = Alg::Sha384.0,
    Sha512 = Alg::Sha512.0,
    Sm3_256 = Alg::Sm3_256.0,
    Sha3_256 = Alg::Sha3_256.0,
    Sha3_384 = Alg::Sha3_384.0,
    Sha3_512 = Alg::Sha3_512.0,
}

impl TpmiAlgHash {
    pub const fn digest_size(self) -> usize {
        use TpmiAlgHash::*;
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

    /// Used for simple implementation of [`crate::Limits::max_digest_size`]
    pub(crate) const BY_SIZE_DESC: &[Self] = const {
        use TpmiAlgHash::*;
        &[
            Sha512, Sha3_512, // 64-byte digest
            Sha384, Sha3_384, // 48-byte digest
            Sha256, Sha3_256, Sm3_256, // 32-byte digest
            Sha1,    // 20-byte digest
        ]
    };
}
impl From<TpmiAlgHash> for Alg {
    fn from(h: TpmiAlgHash) -> Alg {
        Alg(h as u16)
    }
}
impl TryFrom<Alg> for TpmiAlgHash {
    type Error = HashError;
    fn try_from(a: Alg) -> Result<TpmiAlgHash, Self::Error> {
        use TpmiAlgHash::*;
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
impl MarshalArray for TpmiAlgHash {
    const SIZE: usize = 2;
    type Array = [u8; 2];
    #[inline(always)]
    fn marshal_array(&self, arr: &mut [u8; Self::SIZE]) {
        Alg::from(*self).marshal_array(arr)
    }
}
impl UnmarshalArray for TpmiAlgHash {
    type Error = UnmarshalError;

    fn unmarshal_array(arr: &[u8; Self::SIZE]) -> Result<Self, UnmarshalError> {
        let Ok(alg) = Alg::unmarshal_array(arr);
        alg.try_into().map_err(HashError::into)
    }
}
