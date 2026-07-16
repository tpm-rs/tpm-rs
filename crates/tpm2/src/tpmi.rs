use crate::{Alg, BE, errors::HashError};

/// `TPMI_ALG_HASH`
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u16)]
#[non_exhaustive]
pub enum TpmiAlgHash {
    Sha1 = Alg::Sha1.0.0,
    #[default]
    Sha256 = Alg::Sha256.0.0,
    Sha384 = Alg::Sha384.0.0,
    Sha512 = Alg::Sha512.0.0,
    Sm3_256 = Alg::Sm3_256.0.0,
    Sha3_256 = Alg::Sha3_256.0.0,
    Sha3_384 = Alg::Sha3_384.0.0,
    Sha3_512 = Alg::Sha3_512.0.0,
}
use TpmiAlgHash::*;

impl TpmiAlgHash {
    /// The maximum digest size (in bytes) across all supported TPM2 hash algorithms.
    pub const MAX_DIGEST_SIZE: usize = 64;

    /// Returns the digest size (in bytes) of this hash algorithm.
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
}
impl From<TpmiAlgHash> for Alg {
    fn from(h: TpmiAlgHash) -> Alg {
        Alg(BE(h as u16))
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
