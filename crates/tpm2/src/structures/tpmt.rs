use crate::{errors::UnmarshalError, marshal::marshal_helper, *};
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
    const fn split(self) -> (TpmiAlgHash, &'a [u8]) {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(b) => (Sha1, b),
            #[cfg(feature = "sha256")]
            Self::Sha256(b) => (Sha256, b),
            #[cfg(feature = "sha384")]
            Self::Sha384(b) => (Sha384, b),
            #[cfg(feature = "sha512")]
            Self::Sha512(b) => (Sha512, b),
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(b) => (Sm3_256, b),
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(b) => (Sha3_256, b),
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(b) => (Sha3_384, b),
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(b) => (Sha3_512, b),
        }
    }

    pub const fn hash_alg(self) -> TpmiAlgHash {
        self.split().0
    }
    pub const fn digest(self) -> &'a [u8] {
        self.split().1
    }

    pub fn new(alg: TpmiAlgHash, slice: &'a [u8]) -> Option<Self> {
        Some(match alg {
            #[cfg(feature = "sha1")]
            Sha1 => Self::Sha1(slice.try_into().ok()?),
            #[cfg(feature = "sha256")]
            Sha256 => Self::Sha256(slice.try_into().ok()?),
            #[cfg(feature = "sha384")]
            Sha384 => Self::Sha384(slice.try_into().ok()?),
            #[cfg(feature = "sha512")]
            Sha512 => Self::Sha512(slice.try_into().ok()?),
            #[cfg(feature = "sm3_256")]
            Sm3_256 => Self::Sm3_256(slice.try_into().ok()?),
            #[cfg(feature = "sha3_256")]
            Sha3_256 => Self::Sha3_256(slice.try_into().ok()?),
            #[cfg(feature = "sha3_384")]
            Sha3_384 => Self::Sha3_384(slice.try_into().ok()?),
            #[cfg(feature = "sha3_512")]
            Sha3_512 => Self::Sha3_512(slice.try_into().ok()?),
        })
    }

    fn unmarshal_digest(alg: TpmiAlgHash, src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (digest, rest) = src
            .split_at_checked(alg.digest_size())
            .ok_or(UnmarshalError)?;
        *src = rest;
        Self::new(alg, digest).ok_or(UnmarshalError)
    }
}

impl Marshal for TpmtHa<'_> {
    const MAX_SIZE: usize = TpmiAlgHash::MAX_SIZE + TpmiAlgHash::MAX_DIGEST_BYTES;
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
        let alg = TpmiAlgHash::unmarshal(src)?;
        Self::unmarshal_digest(alg, src)
    }
}

impl Marshal for Option<TpmtHa<'_>> {
    const MAX_SIZE: usize = TpmtHa::MAX_SIZE;
    type MaxBuffer = [u8; TpmtHa::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let Some(h) = self else {
            return marshal_helper(&Alg::NULL, dst, 0);
        };
        h.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtHa<'a>> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match Option::<TpmiAlgHash>::unmarshal(src)? {
            Some(alg) => TpmtHa::unmarshal_digest(alg, src).map(Some),
            None => Ok(None),
        }
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
    const MAX_SIZE: usize = Alg::MAX_SIZE + max!(TpmiAlgHash::MAX_SIZE, TpmsSchemeXor::MAX_SIZE);
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

/// Symmetric block cipher algorithm and key size (AES, SM4, Camellia).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlgSym {
    #[cfg(feature = "aes128")]
    Aes128,
    #[cfg(feature = "aes192")]
    Aes192,
    #[cfg(feature = "aes256")]
    Aes256,
    #[cfg(feature = "sm4_128")]
    Sm4_128,
    #[cfg(feature = "camellia128")]
    Camellia128,
    #[cfg(feature = "camellia192")]
    Camellia192,
    #[cfg(feature = "camellia256")]
    Camellia256,
}

#[cfg(not(any(
    feature = "aes128",
    feature = "aes192",
    feature = "aes256",
    feature = "sm4_128",
    feature = "camellia128",
    feature = "camellia192",
    feature = "camellia256",
)))]
compile_error!("at least one symmetric algorithm feature must be enabled");

impl AlgSym {
    const ALL: &[Self] = &[
        #[cfg(feature = "aes128")]
        Self::Aes128,
        #[cfg(feature = "aes192")]
        Self::Aes192,
        #[cfg(feature = "aes256")]
        Self::Aes256,
        #[cfg(feature = "sm4_128")]
        Self::Sm4_128,
        #[cfg(feature = "camellia128")]
        Self::Camellia128,
        #[cfg(feature = "camellia192")]
        Self::Camellia192,
        #[cfg(feature = "camellia256")]
        Self::Camellia256,
    ];

    pub const MAX_KEY_BITS: u16 = max_by!(Self::ALL, Self::key_bits);
    pub const MAX_KEY_BYTES: usize = bits_to_bytes(Self::MAX_KEY_BITS);

    /// All symmetric encryption algorithms have a block size of 16.
    #[doc(alias = "MAX_SYM_BLOCK_SIZE")]
    #[doc(alias = "TPM2_MAX_SYM_BLOCK_SIZE")]
    pub const BLOCK_SIZE: usize = 16;

    /// Returns [`None`] if the specified algorithm + key size isn't supported.
    pub const fn new(alg: Alg, bits: u16) -> Option<Self> {
        find_by!(Self::ALL, |s| {
            let (a, b) = s.info();
            a.id() == alg.id() && b == bits
        })
    }

    const fn info(self) -> (Alg, u16) {
        match self {
            #[cfg(feature = "aes128")]
            Self::Aes128 => (Alg::AES, 128),
            #[cfg(feature = "aes192")]
            Self::Aes192 => (Alg::AES, 192),
            #[cfg(feature = "aes256")]
            Self::Aes256 => (Alg::AES, 256),
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128 => (Alg::SM4, 128),
            #[cfg(feature = "camellia128")]
            Self::Camellia128 => (Alg::CAMELLIA, 128),
            #[cfg(feature = "camellia192")]
            Self::Camellia192 => (Alg::CAMELLIA, 192),
            #[cfg(feature = "camellia256")]
            Self::Camellia256 => (Alg::CAMELLIA, 256),
        }
    }

    #[doc(alias = "TPMI_ALG_SYM_OBJECT")]
    pub const fn algorithm(self) -> Alg {
        self.info().0
    }
    #[doc(alias = "TPMU_SYM_KEY_BITS")]
    #[doc(alias = "TPMI_AES_KEY_BITS")]
    #[doc(alias = "TPMI_SM4_KEY_BITS")]
    #[doc(alias = "TPMI_CAMELLIA_KEY_BITS")]
    pub const fn key_bits(self) -> u16 {
        self.info().1
    }
    pub const fn key_bytes(self) -> usize {
        bits_to_bytes(self.key_bits())
    }
}

impl Marshal for AlgSym {
    const MAX_SIZE: usize = Alg::MAX_SIZE + u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.algorithm(), dst, 0);
        marshal_helper(&self.key_bits(), dst, count)
    }
}

impl<'a> Unmarshal<'a> for AlgSym {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Self::new(Alg::unmarshal(src)?, u16::unmarshal(src)?).ok_or(UnmarshalError)
    }
}

/// `TPMT_SYM_DEF_OBJECT` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.5 (Table 152).
///
/// Used to select a symmetric block cipher algorithm and key size (AES, SM4, Camellia, not XOR).
#[doc(alias = "TPMT_SYM_DEF_OBJECT")]
#[doc(alias = "TPMU_SYM_DETAILS")]
#[doc(alias = "TPMS_SYMCIPHER_PARMS")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmtSymDefObject {
    pub alg: AlgSym,
    pub mode: Option<TpmiAlgSymMode>,
}

impl Marshal for TpmtSymDefObject {
    const MAX_SIZE: usize = AlgSym::MAX_SIZE + <Option<TpmiAlgSymMode>>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.alg, dst, 0);
        marshal_helper(&self.mode, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmtSymDefObject {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            alg: Unmarshal::unmarshal(src)?,
            mode: Unmarshal::unmarshal(src)?,
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
            Self::Obj(obj) => obj.alg.algorithm(),
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
    Rsassa(TpmsSignatureRsa<'a>),
    Rsapss(TpmsSignatureRsa<'a>),
    Ecdsa(TpmsSignatureEcc<'a>),
    Ecdaa(TpmsSignatureEcc<'a>),
    Sm2(TpmsSignatureEcc<'a>),
    Ecschnorr(TpmsSignatureEcc<'a>),
    Eddsa(Tpm2bSignatureEddsa<'a>),
    HashEddsa(Tpm2bSignatureEddsa<'a>),
    Mldsa(Tpm2bSignatureMldsa<'a>),
    HashMldsa(TpmsSignatureHashMldsa<'a>),
}

impl<'a> TpmtSignature<'a> {
    #[doc(alias = "TPMU_SIGNATURE_CTX")]
    pub const MAX_CTX_BYTES: usize = 255;
    #[doc(alias = "MAX_SIGNATURE_HINT_SIZE")]
    pub const MAX_HINT_BYTES: usize = 57;

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
            Self::Eddsa(_) => Alg::EDDSA,
            Self::HashEddsa(_) => Alg::HASH_EDDSA,
            Self::Mldsa(_) => Alg::MLDSA,
            Self::HashMldsa(_) => Alg::HASH_MLDSA,
        }
    }
}

impl Marshal for TpmtSignature<'_> {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + max!(
            TpmtHa::MAX_SIZE,
            TpmsSignatureRsa::MAX_SIZE,
            TpmsSignatureEcc::MAX_SIZE,
            Tpm2bSignatureEddsa::MAX_SIZE,
            Tpm2bSignatureMldsa::MAX_SIZE,
            TpmsSignatureHashMldsa::MAX_SIZE,
        );
    type MaxBuffer = [u8; TpmtSignature::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtSignature::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.sig_alg(), dst, 0);
        match self {
            Self::Hmac(x) => marshal_helper(x, dst, count),
            Self::Rsassa(x) | Self::Rsapss(x) => marshal_helper(x, dst, count),
            Self::Ecdsa(x) | Self::Ecdaa(x) | Self::Sm2(x) | Self::Ecschnorr(x) => {
                marshal_helper(x, dst, count)
            }
            Self::Eddsa(x) | Self::HashEddsa(x) => marshal_helper(x, dst, count),
            Self::Mldsa(x) => marshal_helper(x, dst, count),
            Self::HashMldsa(x) => marshal_helper(x, dst, count),
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
            Alg::EDDSA => Self::Eddsa(Unmarshal::unmarshal(src)?),
            Alg::HASH_EDDSA => Self::HashEddsa(Unmarshal::unmarshal(src)?),
            Alg::MLDSA => Self::Mldsa(Unmarshal::unmarshal(src)?),
            Alg::HASH_MLDSA => Self::HashMldsa(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        })
    }
}

impl Marshal for Option<TpmtSignature<'_>> {
    const MAX_SIZE: usize = TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; TpmtSignature::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let Some(s) = self else {
            return marshal_helper(&Alg::NULL, dst, 0);
        };
        s.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtSignature<'a>> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let orig = *src;
        Ok(match Alg::unmarshal(src)? {
            Alg::NULL => None,
            _ => {
                *src = orig;
                Some(TpmtSignature::unmarshal(src)?)
            }
        })
    }
}

/// `TPMT_SIG_SCHEME` structure defined in TPM 2.0 Part 2: Structures
///
/// Tagged signature scheme structure specifying a signature algorithm and its parameters (if any).
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
    Eddsa,
    HashEddsa,
    Mldsa,
    HashMldsa,
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
            Self::Eddsa => Alg::EDDSA,
            Self::HashEddsa => Alg::HASH_EDDSA,
            Self::Mldsa => Alg::MLDSA,
            Self::HashMldsa => Alg::HASH_MLDSA,
        }
    }
}

impl Marshal for Option<TpmtSigScheme> {
    const MAX_SIZE: usize = Alg::MAX_SIZE + max!(TpmiAlgHash::MAX_SIZE, TpmsSchemeEcdaa::MAX_SIZE);
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
            TpmtSigScheme::Eddsa | TpmtSigScheme::HashEddsa => count,
            TpmtSigScheme::Mldsa | TpmtSigScheme::HashMldsa => count,
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
            Alg::EDDSA => TpmtSigScheme::Eddsa,
            Alg::HASH_EDDSA => TpmtSigScheme::HashEddsa,
            Alg::MLDSA => TpmtSigScheme::Mldsa,
            Alg::HASH_MLDSA => TpmtSigScheme::HashMldsa,
            _ => return Err(UnmarshalError),
        }))
    }
}

/// `TPMT_RSA_SCHEME` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.1.3 (Table 182).
///
/// Tagged RSA scheme structure specifying an RSA scheme (RSAPSS, RSASSA, OAEP, RSAES) and associated hash algorithm.
#[doc(alias = "TPMT_RSA_SCHEME")]
#[doc(alias = "TPMU_RSA_SCHEME")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtRsaScheme {
    Rsassa(TpmiAlgHash),
    Rsaes,
    Rsapss(TpmiAlgHash),
    Oaep(TpmiAlgHash),
}

impl TpmtRsaScheme {
    #[doc(alias = "TPMI_ALG_RSA_SCHEME")]
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

/// `TPMT_RSA_DECRYPT` structure defined in TPM 2.0 Part 2: Structures
///
/// Tagged RSA decryption scheme structure specifying an RSA decryption scheme (RSAES or OAEP) and associated hash algorithm.
#[doc(alias = "TPMT_RSA_DECRYPT")]
#[doc(alias = "TPMU_RSA_DECRYPT")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtRsaDecrypt {
    Rsaes,
    Oaep(TpmiAlgHash),
}

impl TpmtRsaDecrypt {
    #[doc(alias = "TPMI_ALG_RSA_DECRYPT")]
    pub const fn scheme(self) -> Alg {
        match self {
            Self::Rsaes => Alg::RSAES,
            Self::Oaep(_) => Alg::OAEP,
        }
    }
}

impl Marshal for Option<TpmtRsaDecrypt> {
    const MAX_SIZE: usize = Alg::MAX_SIZE + TpmiAlgHash::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let Some(s) = self else {
            return marshal_helper(&Alg::NULL, dst, 0);
        };
        let count = marshal_helper(&s.scheme(), dst, 0);
        match s {
            TpmtRsaDecrypt::Oaep(x) => marshal_helper(x, dst, count),
            TpmtRsaDecrypt::Rsaes => count,
        }
    }
}

impl<'a> Unmarshal<'a> for Option<TpmtRsaDecrypt> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let alg = Alg::unmarshal(src)?;
        if alg == Alg::NULL {
            return Ok(None);
        }
        Ok(Some(match alg {
            Alg::RSAES => TpmtRsaDecrypt::Rsaes,
            Alg::OAEP => TpmtRsaDecrypt::Oaep(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        }))
    }
}

impl TryFrom<TpmtRsaScheme> for TpmtRsaDecrypt {
    type Error = ();

    fn try_from(scheme: TpmtRsaScheme) -> Result<Self, Self::Error> {
        match scheme {
            TpmtRsaScheme::Rsaes => Ok(Self::Rsaes),
            TpmtRsaScheme::Oaep(s) => Ok(Self::Oaep(s)),
            _ => Err(()),
        }
    }
}

impl From<TpmtRsaDecrypt> for TpmtRsaScheme {
    fn from(scheme: TpmtRsaDecrypt) -> Self {
        match scheme {
            TpmtRsaDecrypt::Rsaes => Self::Rsaes,
            TpmtRsaDecrypt::Oaep(s) => Self::Oaep(s),
        }
    }
}

/// `TPMT_ECC_SCHEME` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.2.5 (Table 193).
///
/// Tagged ECC scheme structure specifying an ECC scheme (ECDSA, ECDAA, SM2, ECSchnorr, ECDH, ECMQV, EdDSA, HashEdDSA) and associated parameters.
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
    Eddsa,
    HashEddsa,
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
            Self::Eddsa => Alg::EDDSA,
            Self::HashEddsa => Alg::HASH_EDDSA,
        }
    }
}

impl Marshal for Option<TpmtEccScheme> {
    const MAX_SIZE: usize = Alg::MAX_SIZE + max!(TpmiAlgHash::MAX_SIZE, TpmsSchemeEcdaa::MAX_SIZE);
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
            TpmtEccScheme::Eddsa | TpmtEccScheme::HashEddsa => count,
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
            Alg::EDDSA => TpmtEccScheme::Eddsa,
            Alg::HASH_EDDSA => TpmtEccScheme::HashEddsa,
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
            TpmtEccScheme::Eddsa => Ok(Self::Eddsa),
            TpmtEccScheme::HashEddsa => Ok(Self::HashEddsa),
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
    Hkdf(TpmiAlgHash),
}

impl TpmtKdfScheme {
    /// Returns the algorithm selector (scheme) for this KDF scheme.
    pub const fn scheme(self) -> TpmiAlgKdf {
        match self {
            Self::Mgf1(_) => TpmiAlgKdf::Mgf1,
            Self::Kdf1Sp800_56a(_) => TpmiAlgKdf::Kdf1Sp800_56a,
            Self::Kdf2(_) => TpmiAlgKdf::Kdf2,
            Self::Kdf1Sp800_108(_) => TpmiAlgKdf::Kdf1Sp800_108,
            Self::Hkdf(_) => TpmiAlgKdf::Hkdf,
        }
    }

    /// Returns the associated hash algorithm.
    pub const fn hash_alg(self) -> TpmiAlgHash {
        match self {
            Self::Mgf1(h)
            | Self::Kdf1Sp800_56a(h)
            | Self::Kdf2(h)
            | Self::Kdf1Sp800_108(h)
            | Self::Hkdf(h) => h,
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
            | TpmtKdfScheme::Kdf1Sp800_108(x)
            | TpmtKdfScheme::Hkdf(x) => marshal_helper(x, dst, count),
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
            TpmiAlgKdf::Hkdf => TpmtKdfScheme::Hkdf(Unmarshal::unmarshal(src)?),
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
    Mldsa(TpmsMldsaParms),
    HashMldsa(TpmsHashMldsaParms),
    Mlkem(TpmsMlkemParms),
}

impl TpmtPublicParms {
    #[doc(alias = "MAX_SHARED_SECRET_SIZE")]
    pub const MAX_SHARED_SECRET_BYTES: usize = max!(
        TpmEccCurve::MAX_ECC_KEY_BYTES,
        TpmiMlkemParms::SHARED_SECRET_BYTES,
    );
    #[doc(alias = "TPMU_KEM_CIPHERTEXT")]
    pub const MAX_KEM_CIPHERTEXT_BYTES: usize =
        max!(TpmsEccPoint::MAX_SIZE, TpmiMlkemParms::MAX_CT_BYTES);
    pub const MAX_ENCRYPTED_SECRET_BYTES: usize = max!(
        TpmiRsaKeyBits::MAX_PUB_KEY_BYTES,
        TpmsEccPoint::MAX_SIZE,
        TpmiMlkemParms::MAX_CT_BYTES,
        Tpm2bDigest::MAX_SIZE,
    );

    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn algorithm(self) -> Alg {
        match self {
            Self::KeyedHash(_) => Alg::KEYEDHASH,
            Self::Sym(_) => Alg::SYMCIPHER,
            Self::Rsa(_) => Alg::RSA,
            Self::Ecc(_) => Alg::ECC,
            Self::Mldsa(_) => Alg::MLDSA,
            Self::HashMldsa(_) => Alg::HASH_MLDSA,
            Self::Mlkem(_) => Alg::MLKEM,
        }
    }
}

impl Marshal for TpmtPublicParms {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + max!(
            <Option<TpmtKeyedHashScheme>>::MAX_SIZE,
            TpmtSymDefObject::MAX_SIZE,
            TpmsRsaParms::MAX_SIZE,
            TpmsEccParms::MAX_SIZE,
            TpmsMldsaParms::MAX_SIZE,
            TpmsHashMldsaParms::MAX_SIZE,
            TpmsMlkemParms::MAX_SIZE,
        );
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.algorithm(), dst, 0);
        match self {
            Self::KeyedHash(x) => marshal_helper(x, dst, count),
            Self::Sym(x) => marshal_helper(x, dst, count),
            Self::Rsa(x) => marshal_helper(x, dst, count),
            Self::Ecc(x) => marshal_helper(x, dst, count),
            Self::Mldsa(x) => marshal_helper(x, dst, count),
            Self::HashMldsa(x) => marshal_helper(x, dst, count),
            Self::Mlkem(x) => marshal_helper(x, dst, count),
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
            Alg::MLDSA => Self::Mldsa(Unmarshal::unmarshal(src)?),
            Alg::HASH_MLDSA => Self::HashMldsa(Unmarshal::unmarshal(src)?),
            Alg::MLKEM => Self::Mlkem(Unmarshal::unmarshal(src)?),
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
    fn digest(&self) -> Tpm2bDigest<'_>;
}

/// `TPMT_TK_CREATION` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.5 (Table 104).
///
/// Creation ticket produced by `TPM2_Create` or `TPM2_CreatePrimary` to prove that a creation digest was produced by the TPM.
#[doc(alias = "TPMT_TK_CREATION")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtTkCreation<'a> {
    Creation(Handle, Tpm2bDigest<'a>),
}

impl Ticket for TpmtTkCreation<'_> {
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
    fn digest(&self) -> Tpm2bDigest<'_> {
        match self {
            Self::Creation(_, digest) => *digest,
        }
    }
}

impl Marshal for TpmtTkCreation<'_> {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE + Handle::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmtTkCreation::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtTkCreation::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.tag(), dst, 0);
        match self {
            Self::Creation(hierarchy, digest) => {
                let count = marshal_helper(hierarchy, dst, count);
                marshal_helper(digest, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtTkCreation<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match TpmSt::unmarshal(src)? {
            TpmSt::CREATION => {
                Self::Creation(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?)
            }
            _ => return Err(UnmarshalError),
        })
    }
}

impl Default for TpmtTkCreation<'_> {
    fn default() -> Self {
        Self::Creation(Handle::RH_NULL, Tpm2bDigest::default())
    }
}

/// `TPMT_TK_VERIFIED` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.6 (Table 105).
///
/// Verification ticket produced by `TPM2_VerifySignature`, `TPM2_VerifySequenceComplete`, or `TPM2_VerifyDigestSignature`
/// proving that a signature was verified by the TPM.
#[doc(alias = "TPMT_TK_VERIFIED")]
#[doc(alias = "TPMU_TK_VERIFIED_META")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtTkVerified<'a> {
    Verified(Handle, Tpm2bDigest<'a>),
    MessageVerified(Handle, Tpm2bDigest<'a>),
    DigestVerified(Handle, TpmiAlgHash, Tpm2bDigest<'a>),
}

impl Ticket for TpmtTkVerified<'_> {
    fn tag(&self) -> TpmSt {
        match self {
            Self::Verified(..) => TpmSt::VERIFIED,
            Self::MessageVerified(..) => TpmSt::MESSAGE_VERIFIED,
            Self::DigestVerified(..) => TpmSt::DIGEST_VERIFIED,
        }
    }
    fn hierarchy(&self) -> Handle {
        match self {
            Self::Verified(hierarchy, _)
            | Self::MessageVerified(hierarchy, _)
            | Self::DigestVerified(hierarchy, _, _) => *hierarchy,
        }
    }
    fn digest(&self) -> Tpm2bDigest<'_> {
        match self {
            Self::Verified(_, digest)
            | Self::MessageVerified(_, digest)
            | Self::DigestVerified(_, _, digest) => *digest,
        }
    }
}

impl Marshal for TpmtTkVerified<'_> {
    const MAX_SIZE: usize =
        TpmSt::MAX_SIZE + Handle::MAX_SIZE + TpmiAlgHash::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmtTkVerified::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtTkVerified::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.tag(), dst, 0);
        match self {
            Self::Verified(hierarchy, digest) | Self::MessageVerified(hierarchy, digest) => {
                let count = marshal_helper(hierarchy, dst, count);
                marshal_helper(digest, dst, count)
            }
            Self::DigestVerified(hierarchy, hash_alg, digest) => {
                let count = marshal_helper(hierarchy, dst, count);
                let count = marshal_helper(hash_alg, dst, count);
                marshal_helper(digest, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtTkVerified<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match TpmSt::unmarshal(src)? {
            TpmSt::VERIFIED => {
                Self::Verified(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?)
            }
            TpmSt::MESSAGE_VERIFIED => {
                Self::MessageVerified(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?)
            }
            TpmSt::DIGEST_VERIFIED => Self::DigestVerified(
                Unmarshal::unmarshal(src)?,
                Unmarshal::unmarshal(src)?,
                Unmarshal::unmarshal(src)?,
            ),
            _ => return Err(UnmarshalError),
        })
    }
}

impl Default for TpmtTkVerified<'_> {
    fn default() -> Self {
        Self::Verified(Handle::RH_NULL, Tpm2bDigest::default())
    }
}

/// `TPMT_TK_AUTH` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.7 (Table 106).
///
/// Authorization ticket produced by `TPM2_PolicySigned` or `TPM2_PolicySecret` when authorization has an expiration time.
#[doc(alias = "TPMT_TK_AUTH")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtTkAuth<'a> {
    Signed(Handle, Tpm2bDigest<'a>),
    Secret(Handle, Tpm2bDigest<'a>),
}

impl Ticket for TpmtTkAuth<'_> {
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

    fn digest(&self) -> Tpm2bDigest<'_> {
        match self {
            Self::Signed(_, digest) | Self::Secret(_, digest) => *digest,
        }
    }
}

impl Marshal for TpmtTkAuth<'_> {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE + Handle::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmtTkAuth::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtTkAuth::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.tag(), dst, 0);
        match self {
            Self::Signed(hierarchy, digest) | Self::Secret(hierarchy, digest) => {
                let count = marshal_helper(hierarchy, dst, count);
                marshal_helper(digest, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtTkAuth<'a> {
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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtTkHashcheck<'a> {
    Hashcheck(Handle, Tpm2bDigest<'a>),
}

impl Ticket for TpmtTkHashcheck<'_> {
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

    fn digest(&self) -> Tpm2bDigest<'_> {
        match self {
            Self::Hashcheck(_, digest) => *digest,
        }
    }
}

impl Marshal for TpmtTkHashcheck<'_> {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE + Handle::MAX_SIZE + Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; TpmtTkHashcheck::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtTkHashcheck::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.tag(), dst, 0);
        match self {
            Self::Hashcheck(hierarchy, digest) => {
                let count = marshal_helper(hierarchy, dst, count);
                marshal_helper(digest, dst, count)
            }
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtTkHashcheck<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match TpmSt::unmarshal(src)? {
            TpmSt::HASHCHECK => {
                Self::Hashcheck(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?)
            }
            _ => return Err(UnmarshalError),
        })
    }
}

impl Default for TpmtTkHashcheck<'_> {
    fn default() -> Self {
        Self::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default())
    }
}

/// `TPMT_PUBLIC` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.4 (Table 211).
///
/// Defines the public area of a TPM object (object type, name algorithm, object attributes, auth policy, parameters, and public key data).
#[doc(alias = "TPMT_PUBLIC")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TpmtPublic<'a> {
    pub name_alg: Option<TpmiAlgHash>,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest<'a>,
    pub parms_and_id: PublicParmsAndId<'a>,
}

impl TpmtPublic<'_> {
    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn algorithm(self) -> Alg {
        self.parms_and_id.algorithm()
    }
    pub const fn parms(self) -> TpmtPublicParms {
        self.parms_and_id.parms()
    }
}

impl Marshal for TpmtPublic<'_> {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + <Option<TpmiAlgHash>>::MAX_SIZE
        + TpmaObject::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + PublicParmsAndId::MAX_SIZE;
    type MaxBuffer = [u8; TpmtPublic::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtPublic::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.parms_and_id.algorithm(), dst, 0);
        let count = marshal_helper(&self.name_alg, dst, count);
        let count = marshal_helper(&self.object_attributes, dst, count);
        let count = marshal_helper(&self.auth_policy, dst, count);
        marshal_helper(&self.parms_and_id, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmtPublic<'a> {
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
pub struct TpmtSensitive<'a> {
    pub auth_value: Tpm2bAuth<'a>,
    pub seed_value: Tpm2bDigest<'a>,
    pub sensitive: TpmuSensitiveComposite<'a>,
}

impl TpmtSensitive<'_> {
    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn sensitive_type(self) -> Alg {
        self.sensitive.sensitive_type()
    }
}

impl Marshal for TpmtSensitive<'_> {
    const MAX_SIZE: usize = Alg::MAX_SIZE
        + Tpm2bAuth::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + TpmuSensitiveComposite::MAX_SIZE;
    type MaxBuffer = [u8; TpmtSensitive::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtSensitive::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.sensitive_type(), dst, 0);
        let count = marshal_helper(&self.auth_value, dst, count);
        let count = marshal_helper(&self.seed_value, dst, count);
        marshal_helper(&self.sensitive, dst, count)
    }
}

impl<'a> Unmarshal<'a> for TpmtSensitive<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let selector = Unmarshal::unmarshal(src)?;
        Ok(Self {
            auth_value: Unmarshal::unmarshal(src)?,
            seed_value: Unmarshal::unmarshal(src)?,
            sensitive: TpmuSensitiveComposite::unmarshal_variant(selector, src)?,
        })
    }
}

/// `TPMT_NV_PUBLIC_2` structure defined in TPM 2.0 Part 2: Structures
///
/// Tagged structure defining the public parameters of an NV Index in `TPM2_NV_DefineSpace2` and `TPM2_NV_ReadPublic2`,
/// discriminated by its handle type (`TPM_HT_NV_INDEX`, `TPM_HT_EXTERNAL_NV`, or `TPM_HT_PERMANENT_NV`).
#[doc(alias = "TPMT_NV_PUBLIC_2")]
#[doc(alias = "TPMU_NV_PUBLIC_2")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TpmtNvPublic2<'a> {
    NvIndex(TpmsNvPublic<'a>),
    ExternalNv(TpmsNvPublicExpAttr<'a>),
    PermanentNv(TpmsNvPublic<'a>),
}

impl TpmtNvPublic2<'_> {
    pub const fn handle_type(&self) -> TpmHt {
        match self {
            Self::NvIndex(_) => TpmHt::NVIndex,
            Self::ExternalNv(_) => TpmHt::ExternalNV,
            Self::PermanentNv(_) => TpmHt::PermanentNV,
        }
    }

    /// Returns the handle of the NV Index (`nvIndex`).
    pub const fn nv_index(&self) -> Handle {
        match self {
            Self::NvIndex(x) | Self::PermanentNv(x) => x.nv_index,
            Self::ExternalNv(x) => x.nv_index,
        }
    }
}

impl Marshal for TpmtNvPublic2<'_> {
    const MAX_SIZE: usize =
        TpmHt::MAX_SIZE + max!(TpmsNvPublic::MAX_SIZE, TpmsNvPublicExpAttr::MAX_SIZE);
    type MaxBuffer = [u8; TpmtNvPublic2::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtNvPublic2::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.handle_type(), dst, 0);
        match self {
            Self::NvIndex(x) | Self::PermanentNv(x) => marshal_helper(x, dst, count),
            Self::ExternalNv(x) => marshal_helper(x, dst, count),
        }
    }
}

impl<'a> Unmarshal<'a> for TpmtNvPublic2<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let handle_type = TpmHt::unmarshal(src)?;
        let public = match handle_type {
            TpmHt::NVIndex => Self::NvIndex(Unmarshal::unmarshal(src)?),
            TpmHt::ExternalNV => Self::ExternalNv(Unmarshal::unmarshal(src)?),
            TpmHt::PermanentNV => Self::PermanentNv(Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        };
        // The selector must match the handle type of nvIndex.
        if public.nv_index().handle_type() != Some(handle_type) {
            return Err(UnmarshalError);
        }
        Ok(public)
    }
}
