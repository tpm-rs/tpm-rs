use crate::{
    errors::UnmarshalError,
    marshal::{marshal_helper, max},
    *,
};
use TpmiAlgHash::*;

/// `TPMT_HA` structure defined in TPM 2.0 Part 2: Structures, Section 10.3.3 (Table 86).
///
/// A tagged hash-agile structure containing a hash algorithm identifier (`TPMI_ALG_HASH`) and the corresponding hash digest.
/// Used throughout the TPM stack to provide hash agility.
#[doc(alias = "TPMT_HA")]
#[doc(alias = "TPMU_HA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtHa<'a> {
    #[cfg(feature = "sha1")]
    Sha1(&'a [u8; Sha1.digest_size()]),
    #[cfg(feature = "sha256")]
    Sha256(&'a [u8; Sha256.digest_size()]),
    #[cfg(feature = "sha384")]
    Sha384(&'a [u8; Sha384.digest_size()]),
    #[cfg(feature = "sha512")]
    Sha512(&'a [u8; Sha512.digest_size()]),
    #[cfg(feature = "sm3_256")]
    Sm3_256(&'a [u8; Sm3_256.digest_size()]),
    #[cfg(feature = "sha3_256")]
    Sha3_256(&'a [u8; Sha3_256.digest_size()]),
    #[cfg(feature = "sha3_384")]
    Sha3_384(&'a [u8; Sha3_384.digest_size()]),
    #[cfg(feature = "sha3_512")]
    Sha3_512(&'a [u8; Sha3_512.digest_size()]),
}

impl<'a> TpmtHa<'a> {
    /// The maximum digest size (in bytes) across all supported TPM2 hash algorithms.
    pub const MAX_DIGEST_SIZE: usize = max(&[
        #[cfg(feature = "sha1")]
        Sha1.digest_size(),
        #[cfg(feature = "sha256")]
        Sha256.digest_size(),
        #[cfg(feature = "sha384")]
        Sha384.digest_size(),
        #[cfg(feature = "sha512")]
        Sha512.digest_size(),
        #[cfg(feature = "sm3_256")]
        Sm3_256.digest_size(),
        #[cfg(feature = "sha3_256")]
        Sha3_256.digest_size(),
        #[cfg(feature = "sha3_384")]
        Sha3_384.digest_size(),
        #[cfg(feature = "sha3_512")]
        Sha3_512.digest_size(),
    ]);
    /// The maximum number of implemented hash algorithms.
    #[doc(alias = "TPM2_NUM_PCR_BANKS")]
    pub const HASH_COUNT: usize = 8;

    pub const fn hash_alg(self) -> TpmiAlgHash {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(_) => Sha1,
            #[cfg(feature = "sha256")]
            Self::Sha256(_) => Sha256,
            #[cfg(feature = "sha384")]
            Self::Sha384(_) => Sha384,
            #[cfg(feature = "sha512")]
            Self::Sha512(_) => Sha512,
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(_) => Sm3_256,
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(_) => Sha3_256,
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(_) => Sha3_384,
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(_) => Sha3_512,
        }
    }

    pub const fn digest(self) -> &'a [u8] {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(b) => b,
            #[cfg(feature = "sha256")]
            Self::Sha256(b) => b,
            #[cfg(feature = "sha384")]
            Self::Sha384(b) => b,
            #[cfg(feature = "sha512")]
            Self::Sha512(b) => b,
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(b) => b,
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(b) => b,
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(b) => b,
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(b) => b,
        }
    }
}

impl<'a> Marshal for TpmtHa<'a> {
    const MAX_SIZE: usize = TpmiAlgHash::MAX_SIZE + Self::MAX_DIGEST_SIZE;
    type MaxBuffer = [u8; TpmtHa::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtHa::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.hash_alg(), dst, 0);
        let digest = self.digest();
        dst[count..count + digest.len()].copy_from_slice(digest);
        count + digest.len()
    }
}

impl<'a> Unmarshal<'a> for TpmtHa<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match TpmiAlgHash::unmarshal(src)? {
            #[cfg(feature = "sha1")]
            TpmiAlgHash::Sha1 => Self::Sha1(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha256")]
            TpmiAlgHash::Sha256 => Self::Sha256(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha384")]
            TpmiAlgHash::Sha384 => Self::Sha384(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha512")]
            TpmiAlgHash::Sha512 => Self::Sha512(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sm3_256")]
            TpmiAlgHash::Sm3_256 => Self::Sm3_256(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha3_256")]
            TpmiAlgHash::Sha3_256 => Self::Sha3_256(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha3_384")]
            TpmiAlgHash::Sha3_384 => Self::Sha3_384(Unmarshal::unmarshal(src)?),
            #[cfg(feature = "sha3_512")]
            TpmiAlgHash::Sha3_512 => Self::Sha3_512(Unmarshal::unmarshal(src)?),
        })
    }
}

/// `TPMT_KEYEDHASH_SCHEME` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.10 (Table 164).
///
/// Tagged structure selecting a scheme for a keyed hash object (HMAC or XOR).
#[doc(alias = "TPMT_KEYEDHASH_SCHEME")]
#[doc(alias = "TPMU_SCHEME_KEYEDHASH")]
#[doc(alias = "TPMS_KEYEDHASH_PARMS")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtKeyedHashScheme {
    Hmac(TpmiAlgHash),
    Xor(TpmsSchemeXor),
}

impl TpmtKeyedHashScheme {
    #[doc(alias = "TPMI_ALG_KEYEDHASH_SCHEME")]
    pub const fn scheme(self) -> Alg {
        match self {
            Self::Hmac(_) => Alg::HMAC,
            Self::Xor(_) => Alg::XOR,
        }
    }
}

impl Marshal for Option<TpmtKeyedHashScheme> {
    const MAX_SIZE: usize = Alg::MAX_SIZE + max(&[TpmiAlgHash::MAX_SIZE, TpmsSchemeXor::MAX_SIZE]);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let Some(s) = self else {
            return marshal_helper(&Alg::NULL, dst, 0);
        };
        let count = marshal_helper(&s.scheme(), dst, 0);
        match s {
            TpmtKeyedHashScheme::Hmac(hash) => marshal_helper(hash, dst, count),
            TpmtKeyedHashScheme::Xor(xor) => marshal_helper(xor, dst, count),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtKeyedHashScheme> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let alg = Alg::unmarshal(src)?;
        if alg == Alg::NULL {
            return Ok(None);
        }
        Ok(Some(match alg {
            Alg::HMAC => TpmtKeyedHashScheme::Hmac(Unmarshal::unmarshal(src)?),
            Alg::XOR => TpmtKeyedHashScheme::Xor(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        }))
    }
}

/// `TPMT_SYM_DEF_OBJECT` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.5 (Table 152).
///
/// Used to select a symmetric block cipher algorithm and key size (AES, SM4, Camellia, not XOR).
#[doc(alias = "TPMT_SYM_DEF_OBJECT")]
#[doc(alias = "TPMU_SYM_DETAILS")]
#[doc(alias = "TPMS_SYMCIPHER_PARMS")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtSymDefObject {
    Aes128(Option<TpmiAlgSymMode>),
    Aes192(Option<TpmiAlgSymMode>),
    Aes256(Option<TpmiAlgSymMode>),
    Sm4_128(Option<TpmiAlgSymMode>),
    Camellia128(Option<TpmiAlgSymMode>),
    Camellia192(Option<TpmiAlgSymMode>),
    Camellia256(Option<TpmiAlgSymMode>),
}

impl TpmtSymDefObject {
    #[doc(alias = "TPMI_ALG_SYM_OBJECT")]
    pub const fn algorithm(self) -> Alg {
        match self {
            Self::Aes128(_) | Self::Aes192(_) | Self::Aes256(_) => Alg::AES,
            Self::Sm4_128(_) => Alg::SM4,
            Self::Camellia128(_) | Self::Camellia192(_) | Self::Camellia256(_) => Alg::CAMELLIA,
        }
    }

    #[doc(alias = "TPMU_SYM_KEY_BITS")]
    #[doc(alias = "TPMI_AES_KEY_BITS")]
    #[doc(alias = "TPMI_SM4_KEY_BITS")]
    #[doc(alias = "TPMI_CAMELLIA_KEY_BITS")]
    pub const fn key_bits(self) -> u16 {
        match self {
            Self::Aes128(_) | Self::Sm4_128(_) | Self::Camellia128(_) => 128,
            Self::Aes192(_) | Self::Camellia192(_) => 192,
            Self::Aes256(_) | Self::Camellia256(_) => 256,
        }
    }

    #[doc(alias = "TPMU_SYM_MODE")]
    pub const fn mode(self) -> Option<TpmiAlgSymMode> {
        match self {
            Self::Aes128(m)
            | Self::Aes192(m)
            | Self::Aes256(m)
            | Self::Sm4_128(m)
            | Self::Camellia128(m)
            | Self::Camellia192(m)
            | Self::Camellia256(m) => m,
        }
    }
}

impl Marshal for TpmtSymDefObject {
    const MAX_SIZE: usize = Alg::MAX_SIZE + u16::MAX_SIZE + <Option<TpmiAlgSymMode>>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.algorithm(), dst, 0);
        let count = marshal_helper(&self.key_bits(), dst, count);
        marshal_helper(&self.mode(), dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmtSymDefObject {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let alg = Alg::unmarshal(src)?;
        let key_bits = u16::unmarshal(src)?;
        let mode = Option::<TpmiAlgSymMode>::unmarshal(src)?;
        Ok(match (alg, key_bits) {
            (Alg::AES, 128) => Self::Aes128(mode),
            (Alg::AES, 192) => Self::Aes192(mode),
            (Alg::AES, 256) => Self::Aes256(mode),
            (Alg::SM4, 128) => Self::Sm4_128(mode),
            (Alg::CAMELLIA, 128) => Self::Camellia128(mode),
            (Alg::CAMELLIA, 192) => Self::Camellia192(mode),
            (Alg::CAMELLIA, 256) => Self::Camellia256(mode),
            _ => return Err(UnmarshalError),
        })
    }
}

impl Marshal for Option<TpmtSymDefObject> {
    const MAX_SIZE: usize = TpmtSymDefObject::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let Some(s) = self else {
            return marshal_helper(&Alg::NULL, dst, 0);
        };
        s.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtSymDefObject> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let orig = *src;
        Ok(match Alg::unmarshal(src)? {
            Alg::NULL => None,
            _ => {
                *src = orig;
                Some(TpmtSymDefObject::unmarshal(src)?)
            }
        })
    }
}

/// `TPMT_SYM_DEF` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.4 (Table 151).
///
/// Tagged structure selecting a symmetric block cipher or XOR mode.
#[doc(alias = "TPMT_SYM_DEF")]
#[doc(alias = "TPMU_SYM_DETAILS")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtSymDef {
    Obj(TpmtSymDefObject),
    Xor(TpmiAlgHash),
}

impl TpmtSymDef {
    #[doc(alias = "TPMI_ALG_SYM")]
    pub const fn algorithm(self) -> Alg {
        match self {
            Self::Obj(obj) => obj.algorithm(),
            Self::Xor(_) => Alg::XOR,
        }
    }
}

impl Marshal for Option<TpmtSymDef> {
    const MAX_SIZE: usize = TpmtSymDefObject::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let Some(s) = self else {
            return marshal_helper(&Alg::NULL, dst, 0);
        };
        match s {
            TpmtSymDef::Obj(obj) => obj.marshal(dst),
            TpmtSymDef::Xor(hash) => {
                let count = marshal_helper(&Alg::XOR, dst, 0);
                marshal_helper(hash, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtSymDef> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let orig = *src;
        Ok(match Alg::unmarshal(src)? {
            Alg::NULL => None,
            Alg::XOR => Some(TpmtSymDef::Xor(Unmarshal::unmarshal(src)?)),
            _ => {
                *src = orig;
                Some(TpmtSymDef::Obj(Unmarshal::unmarshal(src)?))
            }
        })
    }
}

/// `TPMT_SIGNATURE` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.3.4 (Table 200).
///
/// Tagged algorithm-agile signature structure containing a signature algorithm ID (`sigAlg`) and the signature payload (`TPMU_SIGNATURE`).
#[doc(alias = "TPMT_SIGNATURE")]
#[doc(alias = "TPMU_SIGNATURE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtSignature<'a> {
    Hmac(TpmtHa<'a>),
    Rsassa(TpmsSignatureRsa),
    Rsapss(TpmsSignatureRsa),
    Ecdsa(TpmsSignatureEcc),
    Ecdaa(TpmsSignatureEcc),
    Sm2(TpmsSignatureEcc),
    Ecschnorr(TpmsSignatureEcc),
}

impl<'a> TpmtSignature<'a> {
    #[doc(alias = "TPMI_ALG_SIG_SCHEME")]
    pub const fn sig_alg(self) -> Alg {
        match self {
            Self::Hmac(_) => Alg::HMAC,
            Self::Rsassa(_) => Alg::RSASSA,
            Self::Rsapss(_) => Alg::RSAPSS,
            Self::Ecdsa(_) => Alg::ECDSA,
            Self::Ecdaa(_) => Alg::ECDAA,
            Self::Sm2(_) => Alg::SM2,
            Self::Ecschnorr(_) => Alg::ECSCHNORR,
        }
    }
}

impl<'a> Marshal for TpmtSignature<'a> {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + max(&[
            TpmtHa::MAX_SIZE,
            TpmsSignatureRsa::MAX_SIZE,
            TpmsSignatureEcc::MAX_SIZE,
        ]);
    type MaxBuffer = [u8; TpmtSignature::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.sig_alg(), dst, 0);
        match self {
            Self::Hmac(x) => marshal_helper(x, dst, count),
            Self::Rsassa(x) | Self::Rsapss(x) => marshal_helper(x, dst, count),
            Self::Ecdsa(x) | Self::Ecdaa(x) | Self::Sm2(x) | Self::Ecschnorr(x) => {
                marshal_helper(x, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtSignature<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match Alg::unmarshal(src)? {
            Alg::HMAC => Self::Hmac(Unmarshal::unmarshal(src)?),
            Alg::RSASSA => Self::Rsassa(Unmarshal::unmarshal(src)?),
            Alg::RSAPSS => Self::Rsapss(Unmarshal::unmarshal(src)?),
            Alg::ECDSA => Self::Ecdsa(Unmarshal::unmarshal(src)?),
            Alg::ECDAA => Self::Ecdaa(Unmarshal::unmarshal(src)?),
            Alg::SM2 => Self::Sm2(Unmarshal::unmarshal(src)?),
            Alg::ECSCHNORR => Self::Ecschnorr(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        })
    }
}

/// Tagged signature scheme structure specifying a signature algorithm (HMAC, RSASSA, RSAPSS, ECDSA, ECDAA, SM2, ECSchnorr) and its hash algorithm.
#[doc(alias = "TPMT_SIG_SCHEME")]
#[doc(alias = "TPMU_SIG_SCHEME")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtSigScheme {
    Hmac(TpmiAlgHash),
    Rsassa(TpmiAlgHash),
    Rsapss(TpmiAlgHash),
    Ecdsa(TpmiAlgHash),
    Ecdaa(TpmsSchemeEcdaa),
    Sm2(TpmiAlgHash),
    Ecschnorr(TpmiAlgHash),
}

impl TpmtSigScheme {
    #[doc(alias = "TPMI_ALG_SIG_SCHEME")]
    pub const fn scheme(self) -> Alg {
        match self {
            Self::Hmac(_) => Alg::HMAC,
            Self::Rsassa(_) => Alg::RSASSA,
            Self::Rsapss(_) => Alg::RSAPSS,
            Self::Ecdsa(_) => Alg::ECDSA,
            Self::Ecdaa(_) => Alg::ECDAA,
            Self::Sm2(_) => Alg::SM2,
            Self::Ecschnorr(_) => Alg::ECSCHNORR,
        }
    }
}

impl Marshal for Option<TpmtSigScheme> {
    const MAX_SIZE: usize =
        Alg::MAX_SIZE + max(&[TpmiAlgHash::MAX_SIZE, TpmsSchemeEcdaa::MAX_SIZE]);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let Some(s) = self else {
            return marshal_helper(&Alg::NULL, dst, 0);
        };
        let count = marshal_helper(&s.scheme(), dst, 0);
        match s {
            TpmtSigScheme::Hmac(x)
            | TpmtSigScheme::Rsassa(x)
            | TpmtSigScheme::Rsapss(x)
            | TpmtSigScheme::Ecdsa(x)
            | TpmtSigScheme::Sm2(x)
            | TpmtSigScheme::Ecschnorr(x) => marshal_helper(x, dst, count),
            TpmtSigScheme::Ecdaa(x) => marshal_helper(x, dst, count),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtSigScheme> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let alg = Alg::unmarshal(src)?;
        if alg == Alg::NULL {
            return Ok(None);
        }
        Ok(Some(match alg {
            Alg::HMAC => TpmtSigScheme::Hmac(Unmarshal::unmarshal(src)?),
            Alg::RSASSA => TpmtSigScheme::Rsassa(Unmarshal::unmarshal(src)?),
            Alg::RSAPSS => TpmtSigScheme::Rsapss(Unmarshal::unmarshal(src)?),
            Alg::ECDSA => TpmtSigScheme::Ecdsa(Unmarshal::unmarshal(src)?),
            Alg::ECDAA => TpmtSigScheme::Ecdaa(Unmarshal::unmarshal(src)?),
            Alg::SM2 => TpmtSigScheme::Sm2(Unmarshal::unmarshal(src)?),
            Alg::ECSCHNORR => TpmtSigScheme::Ecschnorr(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        }))
    }
}

/// `TPMT_RSA_SCHEME` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.1.3 (Table 182).
///
/// Tagged RSA scheme structure specifying an RSA scheme (RSAPSS, RSASSA, OAEP, RSAES) and associated hash algorithm.
#[doc(alias = "TPMT_RSA_SCHEME")]
#[doc(alias = "TPMT_RSA_DECRYPT")]
#[doc(alias = "TPMU_RSA_SCHEME")]
#[doc(alias = "TPMU_RSA_DECRYPT")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtRsaScheme {
    Rsassa(TpmiAlgHash),
    Rsaes,
    Rsapss(TpmiAlgHash),
    Oaep(TpmiAlgHash),
}

impl TpmtRsaScheme {
    #[doc(alias = "TPMI_ALG_RSA_SCHEME")]
    #[doc(alias = "TPMI_ALG_RSA_DECRYPT")]
    pub const fn scheme(self) -> Alg {
        match self {
            Self::Rsassa(_) => Alg::RSASSA,
            Self::Rsaes => Alg::RSAES,
            Self::Rsapss(_) => Alg::RSAPSS,
            Self::Oaep(_) => Alg::OAEP,
        }
    }
}

impl Marshal for Option<TpmtRsaScheme> {
    const MAX_SIZE: usize = Alg::MAX_SIZE + TpmiAlgHash::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let Some(s) = self else {
            return marshal_helper(&Alg::NULL, dst, 0);
        };
        let count = marshal_helper(&s.scheme(), dst, 0);
        match s {
            TpmtRsaScheme::Rsassa(x) | TpmtRsaScheme::Rsapss(x) | TpmtRsaScheme::Oaep(x) => {
                marshal_helper(x, dst, count)
            }
            TpmtRsaScheme::Rsaes => count,
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtRsaScheme> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let alg = Alg::unmarshal(src)?;
        if alg == Alg::NULL {
            return Ok(None);
        }
        Ok(Some(match alg {
            Alg::RSASSA => TpmtRsaScheme::Rsassa(Unmarshal::unmarshal(src)?),
            Alg::RSAES => TpmtRsaScheme::Rsaes,
            Alg::RSAPSS => TpmtRsaScheme::Rsapss(Unmarshal::unmarshal(src)?),
            Alg::OAEP => TpmtRsaScheme::Oaep(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        }))
    }
}

/// `TPMT_ECC_SCHEME` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.2.5 (Table 193).
///
/// Tagged ECC scheme structure specifying an ECC scheme (ECDSA, ECDAA, SM2, ECSchnorr, ECDH, ECMQV) and associated parameters.
#[doc(alias = "TPMT_ECC_SCHEME")]
#[doc(alias = "TPMU_ECC_SCHEME")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtEccScheme {
    Ecdsa(TpmiAlgHash),
    Ecdh(TpmiAlgHash),
    Ecdaa(TpmsSchemeEcdaa),
    Sm2(TpmiAlgHash),
    Ecschnorr(TpmiAlgHash),
    Ecmqv(TpmiAlgHash),
}

impl TpmtEccScheme {
    #[doc(alias = "TPMI_ALG_ECC_SCHEME")]
    pub const fn scheme(self) -> Alg {
        match self {
            Self::Ecdsa(_) => Alg::ECDSA,
            Self::Ecdh(_) => Alg::ECDH,
            Self::Ecdaa(_) => Alg::ECDAA,
            Self::Sm2(_) => Alg::SM2,
            Self::Ecschnorr(_) => Alg::ECSCHNORR,
            Self::Ecmqv(_) => Alg::ECMQV,
        }
    }
}

impl Marshal for Option<TpmtEccScheme> {
    const MAX_SIZE: usize =
        Alg::MAX_SIZE + max(&[TpmiAlgHash::MAX_SIZE, TpmsSchemeEcdaa::MAX_SIZE]);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let Some(s) = self else {
            return marshal_helper(&Alg::NULL, dst, 0);
        };
        let count = marshal_helper(&s.scheme(), dst, 0);
        match s {
            TpmtEccScheme::Ecdsa(x)
            | TpmtEccScheme::Ecdh(x)
            | TpmtEccScheme::Sm2(x)
            | TpmtEccScheme::Ecschnorr(x)
            | TpmtEccScheme::Ecmqv(x) => marshal_helper(x, dst, count),
            TpmtEccScheme::Ecdaa(x) => marshal_helper(x, dst, count),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtEccScheme> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let alg = Alg::unmarshal(src)?;
        if alg == Alg::NULL {
            return Ok(None);
        }
        Ok(Some(match alg {
            Alg::ECDSA => TpmtEccScheme::Ecdsa(Unmarshal::unmarshal(src)?),
            Alg::ECDH => TpmtEccScheme::Ecdh(Unmarshal::unmarshal(src)?),
            Alg::ECDAA => TpmtEccScheme::Ecdaa(Unmarshal::unmarshal(src)?),
            Alg::SM2 => TpmtEccScheme::Sm2(Unmarshal::unmarshal(src)?),
            Alg::ECSCHNORR => TpmtEccScheme::Ecschnorr(Unmarshal::unmarshal(src)?),
            Alg::ECMQV => TpmtEccScheme::Ecmqv(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        }))
    }
}

impl TryFrom<TpmtRsaScheme> for TpmtSigScheme {
    type Error = ();

    fn try_from(scheme: TpmtRsaScheme) -> Result<Self, Self::Error> {
        match scheme {
            TpmtRsaScheme::Rsassa(s) => Ok(Self::Rsassa(s)),
            TpmtRsaScheme::Rsapss(s) => Ok(Self::Rsapss(s)),
            _ => Err(()),
        }
    }
}

impl TryFrom<TpmtEccScheme> for TpmtSigScheme {
    type Error = ();

    fn try_from(scheme: TpmtEccScheme) -> Result<Self, Self::Error> {
        match scheme {
            TpmtEccScheme::Ecdsa(s) => Ok(Self::Ecdsa(s)),
            TpmtEccScheme::Ecdaa(s) => Ok(Self::Ecdaa(s)),
            TpmtEccScheme::Sm2(s) => Ok(Self::Sm2(s)),
            TpmtEccScheme::Ecschnorr(s) => Ok(Self::Ecschnorr(s)),
            _ => Err(()),
        }
    }
}

/// `TPMT_KDF_SCHEME` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.11 (Table 177).
///
/// Tagged KDF scheme structure specifying a key derivation function algorithm and associated hash algorithm.
#[doc(alias = "TPMT_KDF_SCHEME")]
#[doc(alias = "TPMU_KDF_SCHEME")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtKdfScheme {
    Mgf1(TpmiAlgHash),
    Kdf1Sp800_56a(TpmiAlgHash),
    Kdf2(TpmiAlgHash),
    Kdf1Sp800_108(TpmiAlgHash),
}

impl TpmtKdfScheme {
    /// Returns the algorithm selector (scheme) for this KDF scheme.
    pub const fn scheme(self) -> TpmiAlgKdf {
        match self {
            Self::Mgf1(_) => TpmiAlgKdf::Mgf1,
            Self::Kdf1Sp800_56a(_) => TpmiAlgKdf::Kdf1Sp800_56a,
            Self::Kdf2(_) => TpmiAlgKdf::Kdf2,
            Self::Kdf1Sp800_108(_) => TpmiAlgKdf::Kdf1Sp800_108,
        }
    }

    /// Returns the associated hash algorithm.
    pub const fn hash_alg(self) -> TpmiAlgHash {
        match self {
            Self::Mgf1(h) | Self::Kdf1Sp800_56a(h) | Self::Kdf2(h) | Self::Kdf1Sp800_108(h) => h,
        }
    }
}

impl Marshal for Option<TpmtKdfScheme> {
    const MAX_SIZE: usize = <Option<TpmiAlgKdf>>::MAX_SIZE + TpmiAlgHash::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let Some(s) = self else {
            return marshal_helper(&Alg::NULL, dst, 0);
        };
        let count = marshal_helper(&Some(s.scheme()), dst, 0);
        match s {
            TpmtKdfScheme::Mgf1(x)
            | TpmtKdfScheme::Kdf1Sp800_56a(x)
            | TpmtKdfScheme::Kdf2(x)
            | TpmtKdfScheme::Kdf1Sp800_108(x) => marshal_helper(x, dst, count),
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtKdfScheme> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let Some(alg) = Option::<TpmiAlgKdf>::unmarshal(src)? else {
            return Ok(None);
        };
        Ok(Some(match alg {
            TpmiAlgKdf::Mgf1 => TpmtKdfScheme::Mgf1(Unmarshal::unmarshal(src)?),
            TpmiAlgKdf::Kdf1Sp800_56a => TpmtKdfScheme::Kdf1Sp800_56a(Unmarshal::unmarshal(src)?),
            TpmiAlgKdf::Kdf2 => TpmtKdfScheme::Kdf2(Unmarshal::unmarshal(src)?),
            TpmiAlgKdf::Kdf1Sp800_108 => TpmtKdfScheme::Kdf1Sp800_108(Unmarshal::unmarshal(src)?),
        }))
    }
}

/// `TPMT_PUBLIC_PARMS` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.3.6 (Table 210).
///
/// Tagged structure specifying algorithm parameters for an object type, used in `TPM2_TestParms` to validate parameter sets.
#[doc(alias = "TPMT_PUBLIC_PARMS")]
#[doc(alias = "TPMU_PUBLIC_PARMS")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtPublicParms {
    KeyedHash(Option<TpmtKeyedHashScheme>),
    Sym(TpmtSymDefObject),
    Rsa(TpmsRsaParms),
    Ecc(TpmsEccParms),
}

impl TpmtPublicParms {
    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn algorithm(self) -> Alg {
        match self {
            Self::KeyedHash(_) => Alg::KEYEDHASH,
            Self::Sym(_) => Alg::SYMCIPHER,
            Self::Rsa(_) => Alg::RSA,
            Self::Ecc(_) => Alg::ECC,
        }
    }
}

impl Marshal for TpmtPublicParms {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + max(&[
            <Option<TpmtKeyedHashScheme>>::MAX_SIZE,
            TpmtSymDefObject::MAX_SIZE,
            TpmsRsaParms::MAX_SIZE,
            TpmsEccParms::MAX_SIZE,
        ]);
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.algorithm(), dst, 0);
        match self {
            Self::KeyedHash(x) => marshal_helper(x, dst, count),
            Self::Sym(x) => marshal_helper(x, dst, count),
            Self::Rsa(x) => marshal_helper(x, dst, count),
            Self::Ecc(x) => marshal_helper(x, dst, count),
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtPublicParms {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match Alg::unmarshal(src)? {
            Alg::KEYEDHASH => Self::KeyedHash(Unmarshal::unmarshal(src)?),
            Alg::SYMCIPHER => Self::Sym(Unmarshal::unmarshal(src)?),
            Alg::RSA => Self::Rsa(Unmarshal::unmarshal(src)?),
            Alg::ECC => Self::Ecc(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        })
    }
}

impl Default for TpmtPublicParms {
    fn default() -> Self {
        Self::KeyedHash(None)
    }
}

/// Common trait for all `TpmtTk*` ticket types.
pub trait Ticket {
    fn tag(&self) -> TpmSt;
    fn hierarchy(&self) -> Handle;
    fn digest(&self) -> Tpm2bDigest;
}

/// `TPMT_TK_CREATION` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.5 (Table 104).
///
/// Creation ticket produced by `TPM2_Create` or `TPM2_CreatePrimary` to prove that a creation digest was produced by the TPM.
#[doc(alias = "TPMT_TK_CREATION")]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TpmtTkCreation {
    Creation(Handle, Tpm2bDigest),
}

impl Ticket for TpmtTkCreation {
    fn tag(&self) -> TpmSt {
        match self {
            Self::Creation(..) => TpmSt::CREATION,
        }
    }
    fn hierarchy(&self) -> Handle {
        match self {
            Self::Creation(hierarchy, _) => *hierarchy,
        }
    }
    fn digest(&self) -> Tpm2bDigest {
        match self {
            Self::Creation(_, digest) => *digest,
        }
    }
}

impl Marshal for TpmtTkCreation {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE + Handle::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.tag(), dst, 0);
        match self {
            Self::Creation(hierarchy, digest) => {
                let count = marshal_helper(hierarchy, dst, count);
                marshal_helper(digest, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtTkCreation {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match TpmSt::unmarshal(src)? {
            TpmSt::CREATION => {
                Self::Creation(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?)
            }
            _ => return Err(UnmarshalError),
        })
    }
}

impl Default for TpmtTkCreation {
    fn default() -> Self {
        Self::Creation(Handle::RH_NULL, Tpm2bDigest::default())
    }
}

/// `TPMT_TK_VERIFIED` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.6 (Table 105).
///
/// Verification ticket produced by `TPM2_VerifySignature` proving that a signature was verified by the TPM.
#[doc(alias = "TPMT_TK_VERIFIED")]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TpmtTkVerified {
    Verified(Handle, Tpm2bDigest),
}

impl Ticket for TpmtTkVerified {
    fn tag(&self) -> TpmSt {
        match self {
            Self::Verified(..) => TpmSt::VERIFIED,
        }
    }
    fn hierarchy(&self) -> Handle {
        match self {
            Self::Verified(hierarchy, _) => *hierarchy,
        }
    }
    fn digest(&self) -> Tpm2bDigest {
        match self {
            Self::Verified(_, digest) => *digest,
        }
    }
}

impl Marshal for TpmtTkVerified {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE + Handle::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.tag(), dst, 0);
        match self {
            Self::Verified(hierarchy, digest) => {
                let count = marshal_helper(hierarchy, dst, count);
                marshal_helper(digest, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtTkVerified {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match TpmSt::unmarshal(src)? {
            TpmSt::VERIFIED => {
                Self::Verified(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?)
            }
            _ => return Err(UnmarshalError),
        })
    }
}

impl Default for TpmtTkVerified {
    fn default() -> Self {
        Self::Verified(Handle::RH_NULL, Tpm2bDigest::default())
    }
}

/// `TPMT_TK_AUTH` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.7 (Table 106).
///
/// Authorization ticket produced by `TPM2_PolicySigned` or `TPM2_PolicySecret` when authorization has an expiration time.
#[doc(alias = "TPMT_TK_AUTH")]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TpmtTkAuth {
    Signed(Handle, Tpm2bDigest),
    Secret(Handle, Tpm2bDigest),
}

impl Ticket for TpmtTkAuth {
    fn tag(&self) -> TpmSt {
        match self {
            Self::Signed(..) => TpmSt::AUTH_SIGNED,
            Self::Secret(..) => TpmSt::AUTH_SECRET,
        }
    }

    fn hierarchy(&self) -> Handle {
        match self {
            Self::Signed(hierarchy, _) | Self::Secret(hierarchy, _) => *hierarchy,
        }
    }

    fn digest(&self) -> Tpm2bDigest {
        match self {
            Self::Signed(_, digest) | Self::Secret(_, digest) => *digest,
        }
    }
}

impl Marshal for TpmtTkAuth {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE + Handle::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.tag(), dst, 0);
        match self {
            Self::Signed(hierarchy, digest) | Self::Secret(hierarchy, digest) => {
                let count = marshal_helper(hierarchy, dst, count);
                marshal_helper(digest, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtTkAuth {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match TpmSt::unmarshal(src)? {
            TpmSt::AUTH_SIGNED => {
                Self::Signed(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?)
            }
            TpmSt::AUTH_SECRET => {
                Self::Secret(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?)
            }
            _ => return Err(UnmarshalError),
        })
    }
}

/// `TPMT_TK_HASHCHECK` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.8 (Table 107).
///
/// Hash check ticket produced by `TPM2_Hash` or `TPM2_SequenceComplete` proving that a hash digest was computed by the TPM.
#[doc(alias = "TPMT_TK_HASHCHECK")]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TpmtTkHashcheck {
    Hashcheck(Handle, Tpm2bDigest),
}

impl TpmtTkHashcheck {
    pub const fn new(hierarchy: Handle, digest: Tpm2bDigest) -> Self {
        Self::Hashcheck(hierarchy, digest)
    }
}

impl Ticket for TpmtTkHashcheck {
    fn tag(&self) -> TpmSt {
        match self {
            Self::Hashcheck(..) => TpmSt::HASHCHECK,
        }
    }

    fn hierarchy(&self) -> Handle {
        match self {
            Self::Hashcheck(hierarchy, _) => *hierarchy,
        }
    }

    fn digest(&self) -> Tpm2bDigest {
        match self {
            Self::Hashcheck(_, digest) => *digest,
        }
    }
}

impl Marshal for TpmtTkHashcheck {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE + Handle::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.tag(), dst, 0);
        match self {
            Self::Hashcheck(hierarchy, digest) => {
                let count = marshal_helper(hierarchy, dst, count);
                marshal_helper(digest, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtTkHashcheck {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match TpmSt::unmarshal(src)? {
            TpmSt::HASHCHECK => {
                Self::Hashcheck(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?)
            }
            _ => return Err(UnmarshalError),
        })
    }
}

impl Default for TpmtTkHashcheck {
    fn default() -> Self {
        Self::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default())
    }
}

/// `TPMT_PUBLIC` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.4 (Table 211).
///
/// Defines the public area of a TPM object (object type, name algorithm, object attributes, auth policy, parameters, and public key data).
#[doc(alias = "TPMT_PUBLIC")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmtPublic {
    pub name_alg: Option<TpmiAlgHash>,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest,
    pub parms_and_id: PublicParmsAndId,
}

impl TpmtPublic {
    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn algorithm(self) -> Alg {
        self.parms_and_id.algorithm()
    }
    pub const fn parms(self) -> TpmtPublicParms {
        self.parms_and_id.parms()
    }
}

impl Marshal for TpmtPublic {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + <Option<TpmiAlgHash>>::MAX_SIZE
        + TpmaObject::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + PublicParmsAndId::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.parms_and_id.algorithm(), dst, 0);
        let count = marshal_helper(&self.name_alg, dst, count);
        let count = marshal_helper(&self.object_attributes, dst, count);
        let count = marshal_helper(&self.auth_policy, dst, count);
        marshal_helper(&self.parms_and_id, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmtPublic {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Alg::unmarshal(src)?;
        Ok(TpmtPublic {
            name_alg: Unmarshal::unmarshal(src)?,
            object_attributes: Unmarshal::unmarshal(src)?,
            auth_policy: Unmarshal::unmarshal(src)?,
            parms_and_id: PublicParmsAndId::unmarshal_variant(selector, src)?,
        })
    }
}

/// `TPMT_SENSITIVE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.5 (Table 216).
///
/// Defines the sensitive/private area of a TPM object (sensitive type, auth value, seed value, and private key composite).
#[doc(alias = "TPMT_SENSITIVE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmtSensitive {
    pub auth_value: Tpm2bAuth,
    pub seed_value: Tpm2bDigest,
    pub sensitive: TpmuSensitiveComposite,
}

impl TpmtSensitive {
    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn sensitive_type(self) -> Alg {
        self.sensitive.sensitive_type()
    }
}

impl Marshal for TpmtSensitive {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + Tpm2bAuth::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + TpmuSensitiveComposite::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.sensitive_type(), dst, 0);
        let count = marshal_helper(&self.auth_value, dst, count);
        let count = marshal_helper(&self.seed_value, dst, count);
        marshal_helper(&self.sensitive, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmtSensitive {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Unmarshal::unmarshal(src)?;
        Ok(Self {
            auth_value: Unmarshal::unmarshal(src)?,
            seed_value: Unmarshal::unmarshal(src)?,
            sensitive: TpmuSensitiveComposite::unmarshal_variant(selector, src)?,
        })
    }
}
