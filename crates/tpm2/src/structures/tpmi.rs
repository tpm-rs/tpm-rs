use crate::{errors::UnmarshalError, *};

/// `TPMI_ALG_KDF` interface type defined in TPM 2.0 Part 2: Structures, Section 9.31 (Table 62).
///
/// Selects a key derivation function algorithm (MGF1, KDF1_SP800_56A, KDF2, KDF1_SP800_108).
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiAlgKdf>::None`.
#[doc(alias = "TPMI_ALG_KDF")]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TpmiAlgKdf {
    Mgf1 = Alg::MGF1.tag(),
    Kdf1Sp800_56a = Alg::KDF1_SP800_56A.tag(),
    Kdf2 = Alg::KDF2.tag(),
    Kdf1Sp800_108 = Alg::KDF1_SP800_108.tag(),
}

impl TryFrom<Alg> for Option<TpmiAlgKdf> {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            Alg::NULL => Ok(None),
            Alg::MGF1 => Ok(Some(TpmiAlgKdf::Mgf1)),
            Alg::KDF1_SP800_56A => Ok(Some(TpmiAlgKdf::Kdf1Sp800_56a)),
            Alg::KDF2 => Ok(Some(TpmiAlgKdf::Kdf2)),
            Alg::KDF1_SP800_108 => Ok(Some(TpmiAlgKdf::Kdf1Sp800_108)),
            _ => Err(UnmarshalError),
        }
    }
}

impl From<Option<TpmiAlgKdf>> for Alg {
    fn from(kdf: Option<TpmiAlgKdf>) -> Self {
        match kdf {
            Some(alg) => Alg::new(alg as u16),
            None => Alg::NULL,
        }
    }
}

impl Marshal for Option<TpmiAlgKdf> {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmiAlgKdf> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

/// `TPMI_ALG_SYM_MODE` interface type defined in TPM 2.0 Part 2: Structures, Section 9.25 (Table 56).
///
/// Selects a symmetric block cipher mode of operation (such as CBC, CFB, ECB, OFB, CTR, or CMAC).
/// Used in symmetric cipher definitions (`TPMT_SYM_DEF`, `TPMT_SYM_DEF_OBJECT`).
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiAlgSymMode>::None`.
#[doc(alias = "TPMI_ALG_SYM_MODE")]
#[doc(alias = "TPMI_ALG_CIPHER_MODE")]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TpmiAlgSymMode {
    CMAC = Alg::CMAC.tag(),
    CTR = Alg::CTR.tag(),
    OFB = Alg::OFB.tag(),
    CBC = Alg::CBC.tag(),
    CFB = Alg::CFB.tag(),
    ECB = Alg::ECB.tag(),
}

impl TryFrom<Alg> for Option<TpmiAlgSymMode> {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            Alg::NULL => Ok(None),
            Alg::CMAC => Ok(Some(TpmiAlgSymMode::CMAC)),
            Alg::CTR => Ok(Some(TpmiAlgSymMode::CTR)),
            Alg::OFB => Ok(Some(TpmiAlgSymMode::OFB)),
            Alg::CBC => Ok(Some(TpmiAlgSymMode::CBC)),
            Alg::CFB => Ok(Some(TpmiAlgSymMode::CFB)),
            Alg::ECB => Ok(Some(TpmiAlgSymMode::ECB)),
            _ => Err(UnmarshalError),
        }
    }
}

impl From<Option<TpmiAlgSymMode>> for Alg {
    fn from(mode: Option<TpmiAlgSymMode>) -> Self {
        match mode {
            Some(alg) => Alg::new(alg as u16),
            None => Alg::NULL,
        }
    }
}

impl Marshal for Option<TpmiAlgSymMode> {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmiAlgSymMode> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

/// `TPMI_RSA_KEY_BITS`: the number of bits in an RSA key's modulus.
///
/// While [Part 2: Structures] allows for an implementation to support any
/// set of RSA key sizes, this implementation only allows for RSA keys sizes of
/// 1024, 2048, 3072, and 4096.
#[doc(alias = "TPMI_RSA_KEY_BITS")]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum TpmiRsaKeyBits {
    Rsa1024 = 1024,
    Rsa2048 = 2048,
    Rsa3072 = 3072,
    Rsa4096 = 4096,
}

impl TryFrom<u16> for TpmiRsaKeyBits {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        Ok(match val {
            1024 => Self::Rsa1024,
            2048 => Self::Rsa2048,
            3072 => Self::Rsa3072,
            4096 => Self::Rsa4096,
            _ => return Err(UnmarshalError),
        })
    }
}

impl From<TpmiRsaKeyBits> for u16 {
    fn from(val: TpmiRsaKeyBits) -> Self {
        val as u16
    }
}

impl Marshal for TpmiRsaKeyBits {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u16::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiRsaKeyBits {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u16::unmarshal(src)?.try_into()
    }
}

/// `TPMI_ST_COMMAND_TAG` interface type defined in TPM 2.0 Part 2: Structures, Section 9.30 (Table 61).
///
/// Specifies the structure tag in a command header (`TPM_ST_NO_SESSIONS` or `TPM_ST_SESSIONS`).
#[doc(alias = "TPMI_ST_COMMAND_TAG")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmiStCommandTag {
    #[default]
    NoSessions = TpmSt::NO_SESSIONS.tag(),
    Sessions = TpmSt::SESSIONS.tag(),
}

impl TryFrom<TpmSt> for TpmiStCommandTag {
    type Error = UnmarshalError;

    fn try_from(value: TpmSt) -> Result<Self, Self::Error> {
        Ok(match value {
            TpmSt::NO_SESSIONS => Self::NoSessions,
            TpmSt::SESSIONS => Self::Sessions,
            _ => return Err(UnmarshalError),
        })
    }
}

impl From<TpmiStCommandTag> for TpmSt {
    fn from(value: TpmiStCommandTag) -> Self {
        TpmSt::new(value as u16)
    }
}

impl Marshal for TpmiStCommandTag {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        TpmSt::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiStCommandTag {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        TpmSt::unmarshal(src)?.try_into()
    }
}

/// `TPMI_ALG_HASH` interface type defined in TPM 2.0 Part 2: Structures, Section 9.21 (Table 52).
///
/// Selects a hash algorithm (SHA1, SHA256, SHA384, SHA512, SM3_256, etc.).
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiAlgHash>::None`.
#[doc(alias = "TPMI_ALG_HASH")]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TpmiAlgHash {
    #[cfg(feature = "sha1")]
    Sha1 = Alg::SHA1.tag(),
    #[cfg(feature = "sha256")]
    Sha256 = Alg::SHA256.tag(),
    #[cfg(feature = "sha384")]
    Sha384 = Alg::SHA384.tag(),
    #[cfg(feature = "sha512")]
    Sha512 = Alg::SHA512.tag(),
    #[cfg(feature = "sm3_256")]
    Sm3_256 = Alg::SM3_256.tag(),
    #[cfg(feature = "sha3_256")]
    Sha3_256 = Alg::SHA3_256.tag(),
    #[cfg(feature = "sha3_384")]
    Sha3_384 = Alg::SHA3_384.tag(),
    #[cfg(feature = "sha3_512")]
    Sha3_512 = Alg::SHA3_512.tag(),
}

impl TpmiAlgHash {
    /// Returns the digest size (in bytes) of this hash algorithm.
    pub const fn digest_size(self) -> usize {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1 => 20,
            #[cfg(feature = "sha256")]
            Self::Sha256 => 32,
            #[cfg(feature = "sha384")]
            Self::Sha384 => 48,
            #[cfg(feature = "sha512")]
            Self::Sha512 => 64,
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256 => 32,
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256 => 32,
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384 => 48,
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512 => 64,
        }
    }

    pub const fn block_size(self) -> u16 {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1 => 64,
            #[cfg(feature = "sha256")]
            Self::Sha256 => 64,
            #[cfg(feature = "sha384")]
            Self::Sha384 => 128,
            #[cfg(feature = "sha512")]
            Self::Sha512 => 128,
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256 => 64,
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256 => 136,
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384 => 104,
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512 => 72,
        }
    }
}

impl TryFrom<Alg> for TpmiAlgHash {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<TpmiAlgHash, Self::Error> {
        match a {
            #[cfg(feature = "sha1")]
            Alg::SHA1 => Ok(Self::Sha1),
            #[cfg(feature = "sha256")]
            Alg::SHA256 => Ok(Self::Sha256),
            #[cfg(feature = "sha384")]
            Alg::SHA384 => Ok(Self::Sha384),
            #[cfg(feature = "sha512")]
            Alg::SHA512 => Ok(Self::Sha512),
            #[cfg(feature = "sm3_256")]
            Alg::SM3_256 => Ok(Self::Sm3_256),
            #[cfg(feature = "sha3_256")]
            Alg::SHA3_256 => Ok(Self::Sha3_256),
            #[cfg(feature = "sha3_384")]
            Alg::SHA3_384 => Ok(Self::Sha3_384),
            #[cfg(feature = "sha3_512")]
            Alg::SHA3_512 => Ok(Self::Sha3_512),
            _ => Err(UnmarshalError),
        }
    }
}
impl From<TpmiAlgHash> for Alg {
    fn from(h: TpmiAlgHash) -> Alg {
        Alg::new(h as u16)
    }
}
impl Marshal for TpmiAlgHash {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        Alg::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmiAlgHash {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

impl TryFrom<Alg> for Option<TpmiAlgHash> {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Option<TpmiAlgHash>, Self::Error> {
        match a {
            Alg::NULL => Ok(None),
            a => a.try_into().map(Some),
        }
    }
}
impl From<Option<TpmiAlgHash>> for Alg {
    fn from(h: Option<TpmiAlgHash>) -> Alg {
        h.map_or(Alg::NULL, Alg::from)
    }
}
impl Marshal for Option<TpmiAlgHash> {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        Alg::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for Option<TpmiAlgHash> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}
