//! Tagged Union (`TPMT_`) types defined in:
//!   - Part 2, Section 10 "Structure Definitions"
//!   - Part 2, Section 11 "Algorithm Parameters and Structures"
//!   - Part 2, Section 12 "Key/Object Complex"
//!   - Part 2, Section 13 "NV Storage Structures"

use crate::errors::{MarshalError, UnmarshalError};
use crate::marshal::{Limits, Marshal, Unmarshal, UnmarshalFixed, pop_array};
use crate::{
    Alg, TpmiAesKeyBits, TpmiAlgHash, TpmiAlgSymMode, TpmiCamelliaKeyBits, TpmiSm4KeyBits,
    TpmiTdesKeyBits, TpmsEccParms, TpmsHashMldsaParms, TpmsKdfSchemeHkdf, TpmsKeyedHashParms,
    TpmsMldsaParms, TpmsMlkemParms, TpmsRsaParms, TpmsSchemeEcdaa, TpmsSchemeHash, TpmsSchemeHmac,
    TpmsSchemeXor, TpmsSymCipherParms,
};

/// `TPMT_HA` / `TPMU_HA`
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmtHa<'a> {
    Sha1(&'a [u8; TpmiAlgHash::Sha1.digest_size()]) = Alg::Sha1.0,
    Sha256(&'a [u8; TpmiAlgHash::Sha256.digest_size()]) = Alg::Sha256.0,
    Sha384(&'a [u8; TpmiAlgHash::Sha384.digest_size()]) = Alg::Sha384.0,
    Sha512(&'a [u8; TpmiAlgHash::Sha512.digest_size()]) = Alg::Sha512.0,
    Sm3_256(&'a [u8; TpmiAlgHash::Sm3_256.digest_size()]) = Alg::Sm3_256.0,
    Sha3_256(&'a [u8; TpmiAlgHash::Sha3_256.digest_size()]) = Alg::Sha3_256.0,
    Sha3_384(&'a [u8; TpmiAlgHash::Sha3_384.digest_size()]) = Alg::Sha3_384.0,
    Sha3_512(&'a [u8; TpmiAlgHash::Sha3_512.digest_size()]) = Alg::Sha3_512.0,
}

impl<'a> TpmtHa<'a> {
    pub const fn hash_alg(self) -> TpmiAlgHash {
        match self {
            Self::Sha1(_) => TpmiAlgHash::Sha1,
            Self::Sha256(_) => TpmiAlgHash::Sha256,
            Self::Sha384(_) => TpmiAlgHash::Sha384,
            Self::Sha512(_) => TpmiAlgHash::Sha512,
            Self::Sm3_256(_) => TpmiAlgHash::Sm3_256,
            Self::Sha3_256(_) => TpmiAlgHash::Sha3_256,
            Self::Sha3_384(_) => TpmiAlgHash::Sha3_384,
            Self::Sha3_512(_) => TpmiAlgHash::Sha3_512,
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
        2 + const { L::HASH_ALGS.max_digest_size() }
    }
}
impl<'a, 's: 'a> Unmarshal<'s> for TpmtHa<'a> {
    fn unmarshal<L: Limits>(&mut self, mut buf: &'s [u8]) -> Result<&'s [u8], UnmarshalError> {
        *self = match TpmiAlgHash::unmarshal_fixed::<L>(pop_array(&mut buf)?)? {
            TpmiAlgHash::Sha1 => Self::Sha1(pop_array(&mut buf)?),
            TpmiAlgHash::Sha256 => Self::Sha256(pop_array(&mut buf)?),
            TpmiAlgHash::Sha384 => Self::Sha384(pop_array(&mut buf)?),
            TpmiAlgHash::Sha512 => Self::Sha512(pop_array(&mut buf)?),
            TpmiAlgHash::Sm3_256 => Self::Sm3_256(pop_array(&mut buf)?),
            TpmiAlgHash::Sha3_256 => Self::Sha3_256(pop_array(&mut buf)?),
            TpmiAlgHash::Sha3_384 => Self::Sha3_384(pop_array(&mut buf)?),
            TpmiAlgHash::Sha3_512 => Self::Sha3_512(pop_array(&mut buf)?),
        };
        Ok(buf)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmtSymDefObject {
    Aes(TpmiAesKeyBits, Option<TpmiAlgSymMode>) = Alg::Aes.0,
    Sm4(TpmiSm4KeyBits, Option<TpmiAlgSymMode>) = Alg::Sm4.0,
    Camellia(TpmiCamelliaKeyBits, Option<TpmiAlgSymMode>) = Alg::Camellia.0,
    #[deprecated(note = "TDES was deprecated in Version 184 of the TPM 2.0 Specification")]
    Tdes(TpmiTdesKeyBits, Option<TpmiAlgSymMode>) = Alg::Tdes.0,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmtSymDef {
    Aes(TpmiAesKeyBits, Option<TpmiAlgSymMode>) = Alg::Aes.0,
    Sm4(TpmiSm4KeyBits, Option<TpmiAlgSymMode>) = Alg::Sm4.0,
    Camellia(TpmiCamelliaKeyBits, Option<TpmiAlgSymMode>) = Alg::Camellia.0,
    #[deprecated(note = "TDES was deprecated in Version 184 of the TPM 2.0 Specification")]
    Tdes(TpmiTdesKeyBits, Option<TpmiAlgSymMode>) = Alg::Tdes.0,
    Xor(TpmiAlgHash) = Alg::Xor.0,
}

/// `TPMT_PUBLIC_PARMS` / `TPMU_PUBLIC_PARMS`
#[derive(Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmtPublicParms {
    KeyedHash(TpmsKeyedHashParms) = Alg::KeyedHash.0,
    SymCipher(TpmsSymCipherParms) = Alg::SymCipher.0,
    Rsa(TpmsRsaParms) = Alg::Rsa.0,
    Ecc(TpmsEccParms) = Alg::Ecc.0,
    Mldsa(TpmsMldsaParms) = Alg::Mldsa.0,
    HashMldsa(TpmsHashMldsaParms) = Alg::HashMldsa.0,
    Mlkem(TpmsMlkemParms) = Alg::Mlkem.0,
}

/// TODO: Write docs
#[derive(Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmtKeyedHashScheme {
    Hmac(TpmsSchemeHmac) = Alg::Hmac.0,
    Xor(TpmsSchemeXor) = Alg::Xor.0,
}

/// TODO: Write docs
#[derive(Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmtRsaScheme {
    RsaSsa(TpmsSchemeHash) = Alg::RsaSsa.0,
    // TODO: add other variants
}

/// TODO: Write docs
#[derive(Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmtEccScheme {
    Ecdsa(TpmsSchemeHash) = Alg::Ecdsa.0,
    // TODO: add other variants
    Ecdaa(TpmsSchemeEcdaa) = Alg::Ecdaa.0,
}

/// TODO: Write docs
#[derive(Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmtKdfScheme {
    // TODO: add other variants
    Hkdf(TpmsKdfSchemeHkdf) = Alg::Hkdf.0,
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
