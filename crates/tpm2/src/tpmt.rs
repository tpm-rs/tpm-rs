//! `TPMT_` tagged union types
use crate::TpmiAlgHash;
use TpmiAlgHash::*;

/// `TPMT_HA`
///
/// There is no type for `TPMU_HA` in this crate, use this type instead.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtHa<'a> {
    Sha1(&'a [u8; Sha1.digest_size()]),
    Sha256(&'a [u8; Sha256.digest_size()]),
    Sha384(&'a [u8; Sha384.digest_size()]),
    Sha512(&'a [u8; Sha512.digest_size()]),
    // TODO: Add other Hash Algs
}

impl<'a> TpmtHa<'a> {
    /// Returns the [`TpmiAlgHash`] corresponding to this digest.
    pub const fn hash_alg(self) -> TpmiAlgHash {
        match self {
            Self::Sha1(_) => Sha1,
            Self::Sha256(_) => Sha256,
            Self::Sha384(_) => Sha384,
            Self::Sha512(_) => Sha512,
        }
    }

    /// Returns the underlying digest byte slice.
    pub fn digest(self) -> &'a [u8] {
        match self {
            Self::Sha1(d) => d,
            Self::Sha256(d) => d,
            Self::Sha384(d) => d,
            Self::Sha512(d) => d,
        }
    }
}

const EMPTY_SHA256: &[u8; Sha256.digest_size()] = &[0; Sha256.digest_size()];

impl<'a> Default for TpmtHa<'a> {
    fn default() -> Self {
        Self::Sha256(EMPTY_SHA256)
    }
}
