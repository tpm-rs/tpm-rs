//! Tagged Union (`TPMT_`) types defined in:
//!   - Part 2, Section 10 "Structure Definitions"
//!   - Part 2, Section 11 "Algorithm Parameters and Structures"
//!   - Part 2, Section 12 "Key/Object Complex"
use crate::{
    Alg,
    TpmiAlgHash::{self, *},
    errors::{MarshalError, UnmarshalError},
    marshal::{Limits, Marshal, Unmarshal, UnmarshalFixed, pop_array},
};

/// `TPMT_HA` / `TPMU_HA`
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
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
    pub const fn digest(self) -> &'a [u8] {
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
    const fn supported<L: Limits>(self) -> bool {
        self.hash_alg().supported::<L>()
    }
}

impl<'a> Marshal for TpmtHa<'a> {
    fn marshal<'dst, L: Limits>(
        &self,
        buf: &'dst mut [u8],
    ) -> Result<&'dst mut [u8], MarshalError> {
        if !self.supported::<L>() {
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
impl<'a, 's: 'a> Unmarshal<'s> for TpmtHa<'a> {
    fn unmarshal<L: Limits>(&mut self, mut buf: &'s [u8]) -> Result<&'s [u8], UnmarshalError> {
        *self = match TpmiAlgHash::unmarshal_fixed::<L>(pop_array(&mut buf)?)? {
            Sha1 => Self::Sha1(pop_array(&mut buf)?),
            Sha256 => Self::Sha256(pop_array(&mut buf)?),
            Sha384 => Self::Sha384(pop_array(&mut buf)?),
            Sha512 => Self::Sha512(pop_array(&mut buf)?),
            Sm3_256 => Self::Sm3_256(pop_array(&mut buf)?),
            Sha3_256 => Self::Sha3_256(pop_array(&mut buf)?),
            Sha3_384 => Self::Sha3_384(pop_array(&mut buf)?),
            Sha3_512 => Self::Sha3_512(pop_array(&mut buf)?),
        };
        Ok(buf)
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
