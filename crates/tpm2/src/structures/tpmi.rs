use crate::{errors::*, *};

/// `TPMI_ALG_KDF` interface type defined in TPM 2.0 Part 2: Structures, Section 9.31 (Table 77).
///
/// Selects a key derivation function algorithm (MGF1, HKDF, KDF1_SP800_56A, KDF2, KDF1_SP800_108).
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiAlgKdf>::None`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmiAlgKdf {
    Mgf1 = Alg::MGF1.tag(),
    Hkdf = Alg::HKDF.tag(),
    Kdf1Sp800_56a = Alg::KDF1_SP800_56A.tag(),
    Kdf2 = Alg::KDF2.tag(),
    Kdf1Sp800_108 = Alg::KDF1_SP800_108.tag(),
}

impl TryFrom<Alg> for TpmiAlgKdf {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<TpmiAlgKdf, Self::Error> {
        match a {
            Alg::MGF1 => Ok(Self::Mgf1),
            Alg::HKDF => Ok(Self::Hkdf),
            Alg::KDF1_SP800_56A => Ok(Self::Kdf1Sp800_56a),
            Alg::KDF2 => Ok(Self::Kdf2),
            Alg::KDF1_SP800_108 => Ok(Self::Kdf1Sp800_108),
            _ => Err(UnmarshalError::KDF),
        }
    }
}

impl TryFrom<u16> for TpmiAlgKdf {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<TpmiAlgKdf, Self::Error> {
        Self::try_from(Alg::from(val))
    }
}

impl From<TpmiAlgKdf> for Alg {
    fn from(kdf: TpmiAlgKdf) -> Alg {
        Alg::from_tag(kdf as u16)
    }
}

impl Marshal for TpmiAlgKdf {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiAlgKdf {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

impl TryFrom<Alg> for Option<TpmiAlgKdf> {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            Alg::NULL => Ok(None),
            a => a.try_into().map(Some),
        }
    }
}

impl From<Option<TpmiAlgKdf>> for Alg {
    fn from(kdf: Option<TpmiAlgKdf>) -> Self {
        kdf.map_or(Alg::NULL, Alg::from)
    }
}

impl Marshal for Option<TpmiAlgKdf> {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmiAlgKdf> {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

/// `TPMI_ALG_SYM_MODE` interface type defined in TPM 2.0 Part 2: Structures, Section 9.25 (Table 56).
///
/// Selects a symmetric block cipher mode of operation (such as CBC, CFB, ECB, OFB, CTR, or CMAC).
/// Used in symmetric cipher definitions (`TPMT_SYM_DEF`, `TPMT_SYM_DEF_OBJECT`).
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiAlgSymMode>::None`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
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
            _ => Err(UnmarshalError::MODE),
        }
    }
}

impl From<Option<TpmiAlgSymMode>> for Alg {
    fn from(mode: Option<TpmiAlgSymMode>) -> Self {
        match mode {
            Some(TpmiAlgSymMode::CMAC) => Alg::CMAC,
            Some(TpmiAlgSymMode::CTR) => Alg::CTR,
            Some(TpmiAlgSymMode::OFB) => Alg::OFB,
            Some(TpmiAlgSymMode::CBC) => Alg::CBC,
            Some(TpmiAlgSymMode::CFB) => Alg::CFB,
            Some(TpmiAlgSymMode::ECB) => Alg::ECB,
            None => Alg::NULL,
        }
    }
}

impl Marshal for Option<TpmiAlgSymMode> {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmiAlgSymMode> {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

/// `TPMI_ALG_CIPHER_MODE` interface type defined in TPM 2.0 Part 2: Structures, Section 9.26 (Table 57).
///
/// Selects a symmetric block cipher mode of operation (CTR, OFB, CBC, CFB, or ECB).
/// Unlike [`TpmiAlgSymMode`], this type excludes `TPM_ALG_CMAC` and is used in
/// `TPM2_EncryptDecrypt` and `TPM2_EncryptDecrypt2`.
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiAlgCipherMode>::None`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmiAlgCipherMode {
    CTR = Alg::CTR.tag(),
    OFB = Alg::OFB.tag(),
    CBC = Alg::CBC.tag(),
    CFB = Alg::CFB.tag(),
    ECB = Alg::ECB.tag(),
}

impl TryFrom<Alg> for TpmiAlgCipherMode {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<TpmiAlgCipherMode, Self::Error> {
        match a {
            Alg::CTR => Ok(Self::CTR),
            Alg::OFB => Ok(Self::OFB),
            Alg::CBC => Ok(Self::CBC),
            Alg::CFB => Ok(Self::CFB),
            Alg::ECB => Ok(Self::ECB),
            _ => Err(UnmarshalError::MODE),
        }
    }
}

impl TryFrom<u16> for TpmiAlgCipherMode {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<TpmiAlgCipherMode, Self::Error> {
        Self::try_from(Alg::from(val))
    }
}

impl From<TpmiAlgCipherMode> for Alg {
    fn from(mode: TpmiAlgCipherMode) -> Alg {
        Alg::from_tag(mode as u16)
    }
}

impl From<TpmiAlgCipherMode> for TpmiAlgSymMode {
    fn from(mode: TpmiAlgCipherMode) -> Self {
        match mode {
            TpmiAlgCipherMode::CTR => Self::CTR,
            TpmiAlgCipherMode::OFB => Self::OFB,
            TpmiAlgCipherMode::CBC => Self::CBC,
            TpmiAlgCipherMode::CFB => Self::CFB,
            TpmiAlgCipherMode::ECB => Self::ECB,
        }
    }
}

impl TryFrom<TpmiAlgSymMode> for TpmiAlgCipherMode {
    type Error = UnmarshalError;
    fn try_from(mode: TpmiAlgSymMode) -> Result<Self, Self::Error> {
        match mode {
            TpmiAlgSymMode::CTR => Ok(Self::CTR),
            TpmiAlgSymMode::OFB => Ok(Self::OFB),
            TpmiAlgSymMode::CBC => Ok(Self::CBC),
            TpmiAlgSymMode::CFB => Ok(Self::CFB),
            TpmiAlgSymMode::ECB => Ok(Self::ECB),
            TpmiAlgSymMode::CMAC => Err(UnmarshalError::MODE),
        }
    }
}

impl Marshal for TpmiAlgCipherMode {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiAlgCipherMode {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

impl TryFrom<Alg> for Option<TpmiAlgCipherMode> {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            Alg::NULL => Ok(None),
            a => a.try_into().map(Some),
        }
    }
}

impl From<Option<TpmiAlgCipherMode>> for Alg {
    fn from(mode: Option<TpmiAlgCipherMode>) -> Self {
        mode.map_or(Alg::NULL, Alg::from)
    }
}

impl Marshal for Option<TpmiAlgCipherMode> {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmiAlgCipherMode> {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

/// `TPMI_RSA_KEY_BITS` interface type defined in TPM 2.0 Part 2: Structures, Section 9.29 (Table 60).
///
/// Selects an RSA key size in bits (1024, 2048, 3072, or 4096 bits).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct TpmiRsaKeyBits(pub u16);

impl TpmiRsaKeyBits {
    pub const MAX_PUB_KEY_BITS: usize = crate::marshal::max(&[
        #[cfg(feature = "rsa1024")]
        1024,
        #[cfg(feature = "rsa2048")]
        2048,
        #[cfg(feature = "rsa3072")]
        3072,
        #[cfg(feature = "rsa4096")]
        4096,
    ]);
    pub const MAX_PUB_KEY_BYTES: usize = Self::MAX_PUB_KEY_BITS.div_ceil(8);
    pub const MAX_PRIV_KEY_BYTES: usize = Self::MAX_PUB_KEY_BYTES.div_ceil(2) * 5;
}
impl TryFrom<u16> for TpmiRsaKeyBits {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            #[cfg(feature = "rsa1024")]
            1024 => Ok(Self(val)),
            #[cfg(feature = "rsa2048")]
            2048 => Ok(Self(val)),
            #[cfg(feature = "rsa3072")]
            3072 => Ok(Self(val)),
            #[cfg(feature = "rsa4096")]
            4096 => Ok(Self(val)),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}

impl From<TpmiRsaKeyBits> for u16 {
    fn from(val: TpmiRsaKeyBits) -> Self {
        val.0
    }
}

impl Marshal for TpmiRsaKeyBits {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiRsaKeyBits {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u16::unmarshal(src)?.try_into()
    }
}

/// `TPMI_ST_COMMAND_TAG` interface type defined in TPM 2.0 Part 2: Structures, Section 9.30 (Table 61).
///
/// Specifies the structure tag in a command header (`TPM_ST_NO_SESSIONS` or `TPM_ST_SESSIONS`).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(u16)]
pub enum TpmiStCommandTag {
    #[default]
    NoSessions = TpmSt::NO_SESSIONS.tag(),
    Sessions = TpmSt::SESSIONS.tag(),
}

impl From<TpmiStCommandTag> for u16 {
    fn from(val: TpmiStCommandTag) -> Self {
        u16::from_be(val as u16)
    }
}

impl From<TpmiStCommandTag> for TpmSt {
    #[inline(always)]
    fn from(val: TpmiStCommandTag) -> Self {
        match val {
            TpmiStCommandTag::NoSessions => TpmSt::NO_SESSIONS,
            TpmiStCommandTag::Sessions => TpmSt::SESSIONS,
        }
    }
}

impl PartialEq<TpmiStCommandTag> for TpmSt {
    #[inline(always)]
    fn eq(&self, other: &TpmiStCommandTag) -> bool {
        *self == Self::from(*other)
    }
}

impl PartialEq<TpmSt> for TpmiStCommandTag {
    #[inline(always)]
    fn eq(&self, other: &TpmSt) -> bool {
        TpmSt::from(*self) == *other
    }
}

impl Marshal for TpmiStCommandTag {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u16::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiStCommandTag {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u16 = Unmarshal::unmarshal(src)?;
        match val {
            0x8001 => Ok(Self::NoSessions),
            0x8002 => Ok(Self::Sessions),
            _ => Err(UnmarshalError::BAD_TAG),
        }
    }
}

/// `TPMI_ALG_HASH` interface type defined in TPM 2.0 Part 2: Structures, Section 9.21 (Table 52).
///
/// Selects a hash algorithm (SHA1, SHA256, SHA384, SHA512, SM3_256, etc.).
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiAlgHash>::None`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
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
    /// Default hash algorithm selected from the enabled hash algorithm features,
    /// preferring `Sha256`, then `Sha384`, `Sha512`, `Sha1`, `Sm3_256`, `Sha3_256`,
    /// `Sha3_384`, and `Sha3_512`.
    pub const DEFAULT_HASH: Self = {
        #[cfg(feature = "sha256")]
        {
            Self::Sha256
        }
        #[cfg(all(not(feature = "sha256"), feature = "sha384"))]
        {
            Self::Sha384
        }
        #[cfg(all(not(feature = "sha256"), not(feature = "sha384"), feature = "sha512"))]
        {
            Self::Sha512
        }
        #[cfg(all(
            not(feature = "sha256"),
            not(feature = "sha384"),
            not(feature = "sha512"),
            feature = "sha1"
        ))]
        {
            Self::Sha1
        }
        #[cfg(all(
            not(feature = "sha256"),
            not(feature = "sha384"),
            not(feature = "sha512"),
            not(feature = "sha1"),
            feature = "sm3_256"
        ))]
        {
            Self::Sm3_256
        }
        #[cfg(all(
            not(feature = "sha256"),
            not(feature = "sha384"),
            not(feature = "sha512"),
            not(feature = "sha1"),
            not(feature = "sm3_256"),
            feature = "sha3_256"
        ))]
        {
            Self::Sha3_256
        }
        #[cfg(all(
            not(feature = "sha256"),
            not(feature = "sha384"),
            not(feature = "sha512"),
            not(feature = "sha1"),
            not(feature = "sm3_256"),
            not(feature = "sha3_256"),
            feature = "sha3_384"
        ))]
        {
            Self::Sha3_384
        }
        #[cfg(all(
            not(feature = "sha256"),
            not(feature = "sha384"),
            not(feature = "sha512"),
            not(feature = "sha1"),
            not(feature = "sm3_256"),
            not(feature = "sha3_256"),
            not(feature = "sha3_384"),
            feature = "sha3_512"
        ))]
        {
            Self::Sha3_512
        }
    };

    /// The maximum digest size (in bytes) across all supported TPM2 hash algorithms.
    pub const MAX_DIGEST_BYTES: usize = crate::marshal::max(&[
        #[cfg(feature = "sha1")]
        Self::Sha1.digest_size(),
        #[cfg(feature = "sha256")]
        Self::Sha256.digest_size(),
        #[cfg(feature = "sha384")]
        Self::Sha384.digest_size(),
        #[cfg(feature = "sha512")]
        Self::Sha512.digest_size(),
        #[cfg(feature = "sm3_256")]
        Self::Sm3_256.digest_size(),
        #[cfg(feature = "sha3_256")]
        Self::Sha3_256.digest_size(),
        #[cfg(feature = "sha3_384")]
        Self::Sha3_384.digest_size(),
        #[cfg(feature = "sha3_512")]
        Self::Sha3_512.digest_size(),
    ]);
    /// The maximum number of implemented hash algorithms.
    #[doc(alias = "TPM2_NUM_PCR_BANKS")]
    pub const HASH_COUNT: usize = crate::TPM2_NUM_PCR_BANKS as usize;

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

impl Default for TpmiAlgHash {
    #[inline(always)]
    fn default() -> Self {
        Self::DEFAULT_HASH
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
            _ => Err(UnmarshalError::HASH),
        }
    }
}

impl TryFrom<u16> for TpmiAlgHash {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<TpmiAlgHash, Self::Error> {
        Self::try_from(Alg::from(val))
    }
}
impl From<TpmiAlgHash> for Alg {
    fn from(h: TpmiAlgHash) -> Alg {
        Alg::from_tag(h as u16)
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

macro_rules! impl_handle_tpmi {
    ($name:ident) => {
        impl From<$name> for Handle {
            #[inline(always)]
            fn from(h: $name) -> Self {
                h.0
            }
        }

        impl Marshal for $name {
            const MAX_SIZE: usize = Handle::MAX_SIZE;
            type MaxBuffer = [u8; Self::MAX_SIZE];

            #[inline(always)]
            fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
                self.0.marshal(dst)
            }
        }

        impl<'a> Unmarshal<'a> for $name {
            #[inline(always)]
            fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
                Handle::unmarshal(src)?.try_into()
            }
        }
    };
}

macro_rules! impl_handle_tpmi_flag {
    ($name:ident, $flag:ident) => {
        impl<const $flag: bool> From<$name<$flag>> for Handle {
            #[inline(always)]
            fn from(h: $name<$flag>) -> Self {
                h.0
            }
        }

        impl<const $flag: bool> Marshal for $name<$flag> {
            const MAX_SIZE: usize = Handle::MAX_SIZE;
            type MaxBuffer = [u8; Handle::MAX_SIZE];

            #[inline(always)]
            fn marshal(&self, dst: &mut [u8; Handle::MAX_SIZE]) -> usize {
                self.0.marshal(dst)
            }
        }

        impl<'a, const $flag: bool> Unmarshal<'a> for $name<$flag> {
            #[inline(always)]
            fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
                Handle::unmarshal(src)?.try_into()
            }
        }
    };
}

/// `TPMI_DH_OBJECT` interface type defined in TPM 2.0 Part 2: Structures, Section 9.3 (Table 44).
///
/// Validates loaded transient object handles (`TRANSIENT_FIRST..=TRANSIENT_LAST`), persistent object
/// handles (`PERSISTENT_FIRST..=PERSISTENT_LAST`), and conditionally `TPM_RH_NULL` when `ALLOW_NULL` is `true`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiDhObject<const ALLOW_NULL: bool = false>(pub Handle);

/// Non-null object handle (`TPMI_DH_OBJECT`).
pub type TpmiDhObjectNonNull = TpmiDhObject<false>;
/// Nullable object handle (`TPMI_DH_OBJECT+`).
pub type TpmiDhObjectNullable = TpmiDhObject<true>;

impl<const ALLOW_NULL: bool> TryFrom<Handle> for TpmiDhObject<ALLOW_NULL> {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (Handle::TRANSIENT_FIRST.0..=Handle::TRANSIENT_LAST.0).contains(&handle.0)
            || (Handle::PERSISTENT_FIRST.0..=Handle::PERSISTENT_LAST.0).contains(&handle.0)
            || (ALLOW_NULL && handle == Handle::RH_NULL)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi_flag!(TpmiDhObject, ALLOW_NULL);

/// `TPMI_DH_PARENT` interface type defined in TPM 2.0 Part 2: Structures, Section 9.4 (Table 45).
///
/// Validates transient object handles (`TRANSIENT_FIRST..=TRANSIENT_LAST`), persistent object handles
/// (`PERSISTENT_FIRST..=PERSISTENT_LAST`), and hierarchy handles (`TPM_RH_OWNER`, `TPM_RH_PLATFORM`,
/// `TPM_RH_ENDORSEMENT`, `TPM_RH_NULL`, firmware-limited, and SVN-limited hierarchies).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiDhParent(pub Handle);

impl TryFrom<Handle> for TpmiDhParent {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (Handle::TRANSIENT_FIRST.0..=Handle::TRANSIENT_LAST.0).contains(&handle.0)
            || (Handle::PERSISTENT_FIRST.0..=Handle::PERSISTENT_LAST.0).contains(&handle.0)
            || handle.is_hierarchy()
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiDhParent);

/// `TPMI_DH_PERSISTENT` interface type defined in TPM 2.0 Part 2: Structures, Section 9.5 (Table 46).
///
/// Validates persistent object handles (`PERSISTENT_FIRST..=PERSISTENT_LAST`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiDhPersistent(pub Handle);

impl TryFrom<Handle> for TpmiDhPersistent {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (Handle::PERSISTENT_FIRST.0..=Handle::PERSISTENT_LAST.0).contains(&handle.0) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiDhPersistent);

/// `TPMI_DH_ENTITY` interface type defined in TPM 2.0 Part 2: Structures, Section 9.6 (Table 47).
///
/// Validates any entity handle that can be authorized (`TPM_RH_OWNER`, `TPM_RH_ENDORSEMENT`,
/// `TPM_RH_PLATFORM`, `TPM_RH_LOCKOUT`, auth handles `TPM_RH_AUTH_00..=TPM_RH_AUTH_FF`, transient objects
/// `TRANSIENT_FIRST..=TRANSIENT_LAST`, persistent objects `PERSISTENT_FIRST..=PERSISTENT_LAST`, NV indices
/// `NV_INDEX_FIRST..=NV_INDEX_LAST`, PCR handles `PCR_FIRST..=PCR_LAST`, and optionally `TPM_RH_NULL`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiDhEntity<const ALLOW_NULL: bool = false>(pub Handle);

impl<const ALLOW_NULL: bool> TryFrom<Handle> for TpmiDhEntity<ALLOW_NULL> {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if matches!(
            handle,
            Handle::RH_OWNER | Handle::RH_ENDORSEMENT | Handle::RH_PLATFORM | Handle::RH_LOCKOUT
        ) || (Handle::TRANSIENT_FIRST.0..=Handle::TRANSIENT_LAST.0).contains(&handle.0)
            || (Handle::PERSISTENT_FIRST.0..=Handle::PERSISTENT_LAST.0).contains(&handle.0)
            || (Handle::NV_INDEX_FIRST.0..=Handle::NV_INDEX_LAST.0).contains(&handle.0)
            || (Handle::PCR_FIRST.0..=Handle::PCR_LAST.0).contains(&handle.0)
            || (Handle::RH_AUTH_00.0..=Handle::RH_AUTH_FF.0).contains(&handle.0)
            || (ALLOW_NULL && handle == Handle::RH_NULL)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi_flag!(TpmiDhEntity, ALLOW_NULL);

/// `TPMI_DH_PCR` interface type defined in TPM 2.0 Part 2: Structures, Section 9.7 (Table 48).
///
/// Validates PCR handles (`PCR_FIRST..=PCR_LAST`) and optionally `TPM_RH_NULL`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiDhPcr<const ALLOW_NULL: bool = false>(pub Handle);

impl<const ALLOW_NULL: bool> TryFrom<Handle> for TpmiDhPcr<ALLOW_NULL> {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (Handle::PCR_FIRST.0..=Handle::PCR_LAST.0).contains(&handle.0)
            || (ALLOW_NULL && handle == Handle::RH_NULL)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi_flag!(TpmiDhPcr, ALLOW_NULL);

/// `TPMI_SH_AUTH_SESSION` interface type defined in TPM 2.0 Part 2: Structures, Section 9.8 (Table 49).
///
/// Validates HMAC session handles (`HMAC_SESSION_FIRST..=HMAC_SESSION_LAST`), policy session handles
/// (`POLICY_SESSION_FIRST..=POLICY_SESSION_LAST`), and optionally password session `TPM_RS_PW` (`0x40000009`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiShAuthSession<const ALLOW_RS_PW: bool = false>(pub Handle);

impl<const ALLOW_RS_PW: bool> TryFrom<Handle> for TpmiShAuthSession<ALLOW_RS_PW> {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (Handle::HMAC_SESSION_FIRST.0..=Handle::HMAC_SESSION_LAST.0).contains(&handle.0)
            || (Handle::POLICY_SESSION_FIRST.0..=Handle::POLICY_SESSION_LAST.0).contains(&handle.0)
            || (ALLOW_RS_PW && handle == Handle::RS_PW)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi_flag!(TpmiShAuthSession, ALLOW_RS_PW);

/// `TPMI_SH_HMAC` interface type defined in TPM 2.0 Part 2: Structures, Section 9.9 (Table 50).
///
/// Validates HMAC session handles (`HMAC_SESSION_FIRST..=HMAC_SESSION_LAST`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiShHmac(pub Handle);

impl TryFrom<Handle> for TpmiShHmac {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (Handle::HMAC_SESSION_FIRST.0..=Handle::HMAC_SESSION_LAST.0).contains(&handle.0) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiShHmac);

/// `TPMI_SH_POLICY` interface type defined in TPM 2.0 Part 2: Structures, Section 9.10 (Table 51).
///
/// Validates policy session handles (`POLICY_SESSION_FIRST..=POLICY_SESSION_LAST`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiShPolicy(pub Handle);

impl TryFrom<Handle> for TpmiShPolicy {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (Handle::POLICY_SESSION_FIRST.0..=Handle::POLICY_SESSION_LAST.0).contains(&handle.0) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiShPolicy);

/// `TPMI_DH_CONTEXT` interface type defined in TPM 2.0 Part 2: Structures, Section 9.11 (Table 52).
///
/// Validates handles that can be saved or flushed: HMAC sessions (`HMAC_SESSION_FIRST..=HMAC_SESSION_LAST`),
/// policy sessions (`POLICY_SESSION_FIRST..=POLICY_SESSION_LAST`), and transient objects (`TRANSIENT_FIRST..=TRANSIENT_LAST`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiDhContext(pub Handle);

impl TryFrom<Handle> for TpmiDhContext {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (Handle::HMAC_SESSION_FIRST.0..=Handle::HMAC_SESSION_LAST.0).contains(&handle.0)
            || (Handle::POLICY_SESSION_FIRST.0..=Handle::POLICY_SESSION_LAST.0).contains(&handle.0)
            || (Handle::TRANSIENT_FIRST.0..=Handle::TRANSIENT_LAST.0).contains(&handle.0)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiDhContext);

/// `TPMI_DH_SAVED` interface type defined in TPM 2.0 Part 2: Structures, Section 9.12 (Table 53).
///
/// Validates handles that can appear in `TPMS_CONTEXT`: HMAC sessions (`HMAC_SESSION_FIRST..=HMAC_SESSION_LAST`),
/// policy sessions (`POLICY_SESSION_FIRST..=POLICY_SESSION_LAST`), and saved transient object context markers
/// (`0x80000000..=0x80000002`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiDhSaved(pub Handle);

impl TryFrom<Handle> for TpmiDhSaved {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (Handle::HMAC_SESSION_FIRST.0..=Handle::HMAC_SESSION_LAST.0).contains(&handle.0)
            || (Handle::POLICY_SESSION_FIRST.0..=Handle::POLICY_SESSION_LAST.0).contains(&handle.0)
            || (0x8000_0000..=0x8000_0002).contains(&handle.0)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiDhSaved);

/// `TPMI_RH_HIERARCHY` interface type defined in TPM 2.0 Part 2: Structures, Section 9.13 (Table 47).
///
/// Validates permanent hierarchy handles (`TPM_RH_OWNER`, `TPM_RH_PLATFORM`, `TPM_RH_ENDORSEMENT`,
/// `TPM_RH_NULL`), firmware-limited hierarchy handles (`TPM_RH_FW_OWNER`, `TPM_RH_FW_PLATFORM`,
/// `TPM_RH_FW_ENDORSEMENT`, `TPM_RH_FW_NULL`), and SVN-limited hierarchy handles (`0x40010000..=0x4004FFFF`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhHierarchy(pub Handle);

impl TryFrom<Handle> for TpmiRhHierarchy {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if handle.is_hierarchy() {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhHierarchy);

/// `TPMI_RH_ENABLES` interface type defined in TPM 2.0 Part 2: Structures, Section 9.14 (Table 48).
///
/// Validates hierarchy enable handles (`TPM_RH_OWNER`, `TPM_RH_PLATFORM`, `TPM_RH_ENDORSEMENT`,
/// `TPM_RH_PLATFORM_NV`, and optionally `TPM_RH_NULL`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhEnables<const ALLOW_NULL: bool = false>(pub Handle);

impl<const ALLOW_NULL: bool> TryFrom<Handle> for TpmiRhEnables<ALLOW_NULL> {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if matches!(
            handle,
            Handle::RH_OWNER
                | Handle::RH_PLATFORM
                | Handle::RH_ENDORSEMENT
                | Handle::RH_PLATFORM_NV
        ) || (ALLOW_NULL && handle == Handle::RH_NULL)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi_flag!(TpmiRhEnables, ALLOW_NULL);

/// `TPMI_RH_HIERARCHY_AUTH` interface type defined in TPM 2.0 Part 2: Structures, Section 9.15 (Table 49).
///
/// Validates hierarchy auth handles (`TPM_RH_OWNER`, `TPM_RH_PLATFORM`, `TPM_RH_ENDORSEMENT`,
/// `TPM_RH_LOCKOUT`, and optionally `TPM_RH_NULL`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhHierarchyAuth<const ALLOW_NULL: bool = false>(pub Handle);

impl<const ALLOW_NULL: bool> TryFrom<Handle> for TpmiRhHierarchyAuth<ALLOW_NULL> {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if matches!(
            handle,
            Handle::RH_OWNER | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT | Handle::RH_LOCKOUT
        ) || (ALLOW_NULL && handle == Handle::RH_NULL)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi_flag!(TpmiRhHierarchyAuth, ALLOW_NULL);

/// `TPMI_RH_HIERARCHY_POLICY` interface type defined in TPM 2.0 Part 2: Structures, Section 9.16 (Table 57).
///
/// Validates hierarchy policy handles (`TPM_RH_OWNER`, `TPM_RH_PLATFORM`, `TPM_RH_ENDORSEMENT`,
/// `TPM_RH_LOCKOUT`, and ACT handles `0x40000110..=0x4000011F`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhHierarchyPolicy(pub Handle);

impl TryFrom<Handle> for TpmiRhHierarchyPolicy {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if matches!(
            handle,
            Handle::RH_OWNER | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT | Handle::RH_LOCKOUT
        ) || (0x4000_0110..=0x4000_011F).contains(&handle.0)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhHierarchyPolicy);

/// `TPMI_RH_BASE_HIERARCHY` interface type defined in TPM 2.0 Part 2: Structures, Section 9.16 (Table 50a).
///
/// Validates base hierarchy handles (`TPM_RH_OWNER`, `TPM_RH_PLATFORM`, `TPM_RH_ENDORSEMENT`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhBaseHierarchy(pub Handle);

impl TryFrom<Handle> for TpmiRhBaseHierarchy {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if matches!(
            handle,
            Handle::RH_OWNER | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT
        ) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhBaseHierarchy);

/// `TPMI_RH_PLATFORM` interface type defined in TPM 2.0 Part 2: Structures, Section 9.17 (Table 51).
///
/// Validates the platform hierarchy handle (`TPM_RH_PLATFORM`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhPlatform(pub Handle);

impl TryFrom<Handle> for TpmiRhPlatform {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if handle == Handle::RH_PLATFORM {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhPlatform);

/// `TPMI_RH_OWNER` interface type defined in TPM 2.0 Part 2: Structures, Section 9.18 (Table 52).
///
/// Validates the owner hierarchy handle (`TPM_RH_OWNER`) and optionally `TPM_RH_NULL`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhOwner<const ALLOW_NULL: bool = false>(pub Handle);

impl<const ALLOW_NULL: bool> TryFrom<Handle> for TpmiRhOwner<ALLOW_NULL> {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if handle == Handle::RH_OWNER || (ALLOW_NULL && handle == Handle::RH_NULL) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi_flag!(TpmiRhOwner, ALLOW_NULL);

/// `TPMI_RH_ENDORSEMENT` interface type defined in TPM 2.0 Part 2: Structures, Section 9.19 (Table 53).
///
/// Validates the endorsement hierarchy handle (`TPM_RH_ENDORSEMENT`) and optionally `TPM_RH_NULL`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhEndorsement<const ALLOW_NULL: bool = false>(pub Handle);

impl<const ALLOW_NULL: bool> TryFrom<Handle> for TpmiRhEndorsement<ALLOW_NULL> {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if handle == Handle::RH_ENDORSEMENT || (ALLOW_NULL && handle == Handle::RH_NULL) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi_flag!(TpmiRhEndorsement, ALLOW_NULL);

/// `TPMI_RH_PROVISION` interface type defined in TPM 2.0 Part 2: Structures, Section 9.20 (Table 54).
///
/// Validates provisioning handles (`TPM_RH_OWNER`, `TPM_RH_PLATFORM`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhProvision(pub Handle);

impl TryFrom<Handle> for TpmiRhProvision {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if matches!(handle, Handle::RH_OWNER | Handle::RH_PLATFORM) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhProvision);

/// `TPMI_RH_CLEAR` interface type defined in TPM 2.0 Part 2: Structures, Section 9.21 (Table 55).
///
/// Validates clear authorization handles (`TPM_RH_LOCKOUT`, `TPM_RH_PLATFORM`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhClear(pub Handle);

impl TryFrom<Handle> for TpmiRhClear {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if matches!(handle, Handle::RH_LOCKOUT | Handle::RH_PLATFORM) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhClear);

/// `TPMI_RH_NV_AUTH` interface type defined in TPM 2.0 Part 2: Structures, Section 9.22 (Table 56).
///
/// Validates NV authorization handles (`TPM_RH_OWNER`, `TPM_RH_PLATFORM`, and NV index handles
/// `0x01000000..=0x01FFFFFF`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhNvAuth(pub Handle);

impl TryFrom<Handle> for TpmiRhNvAuth {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if matches!(handle, Handle::RH_OWNER | Handle::RH_PLATFORM)
            || (0x0100_0000..=0x01FF_FFFF).contains(&handle.0)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhNvAuth);

/// `TPMI_RH_LOCKOUT` interface type defined in TPM 2.0 Part 2: Structures, Section 9.23 (Table 57).
///
/// Validates the lockout handle (`TPM_RH_LOCKOUT`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhLockout(pub Handle);

impl TryFrom<Handle> for TpmiRhLockout {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if handle == Handle::RH_LOCKOUT {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhLockout);

/// `TPMI_RH_NV_INDEX` interface type defined in TPM 2.0 Part 2: Structures, Section 9.24 (Table 58).
///
/// Validates NV index handles (`0x01000000..=0x01FFFFFF` and `0x11000000..=0x12FFFFFF`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhNvIndex(pub Handle);

impl TryFrom<Handle> for TpmiRhNvIndex {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (0x0100_0000..=0x01FF_FFFF).contains(&handle.0)
            || (0x1100_0000..=0x12FF_FFFF).contains(&handle.0)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhNvIndex);

/// `TPMI_RH_NV_DEFINED_INDEX` interface type defined in TPM 2.0 Part 2: Structures, Section 9.24.
///
/// Validates defined NV index handles (`0x01000000..=0x01FFFFFF` and `0x11000000..=0x11FFFFFF`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhNvDefinedIndex(pub Handle);

impl TryFrom<Handle> for TpmiRhNvDefinedIndex {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (0x0100_0000..=0x01FF_FFFF).contains(&handle.0)
            || (0x1100_0000..=0x11FF_FFFF).contains(&handle.0)
        {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhNvDefinedIndex);

/// `TPMI_RH_NV_LEGACY_INDEX` interface type defined in TPM 2.0 Part 2: Structures, Section 9.24.
///
/// Validates legacy NV index handles (`0x01000000..=0x01FFFFFF`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhNvLegacyIndex(pub Handle);

impl TryFrom<Handle> for TpmiRhNvLegacyIndex {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (0x0100_0000..=0x01FF_FFFF).contains(&handle.0) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhNvLegacyIndex);

/// `TPMI_RH_NV_EXP_INDEX` interface type defined in TPM 2.0 Part 2: Structures, Section 9.24.
///
/// Validates extended NV index handles (`0x11000000..=0x11FFFFFF`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhNvExpIndex(pub Handle);

impl TryFrom<Handle> for TpmiRhNvExpIndex {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (0x1100_0000..=0x11FF_FFFF).contains(&handle.0) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhNvExpIndex);

/// `TPMI_RH_AC` interface type defined in TPM 2.0 Part 2: Structures, Section 9.25 (Table 59).
///
/// Validates attached component handles (`0x90000000..=0x9000FFFF`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhAc(pub Handle);

impl TryFrom<Handle> for TpmiRhAc {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (0x9000_0000..=0x9000_FFFF).contains(&handle.0) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhAc);

/// `TPMI_RH_ACT` interface type defined in TPM 2.0 Part 2: Structures, Section 9.26 (Table 60).
///
/// Validates authenticated countdown timer handles (`0x40000110..=0x4000011F`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmiRhAct(pub Handle);

impl TryFrom<Handle> for TpmiRhAct {
    type Error = UnmarshalError;
    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        if (0x4000_0110..=0x4000_011F).contains(&handle.0) {
            Ok(Self(handle))
        } else {
            Err(UnmarshalError::VALUE)
        }
    }
}
impl_handle_tpmi!(TpmiRhAct);

/// `TPMI_ALG_MAC_SCHEME` interface type defined in TPM 2.0 Part 2: Structures, Section 9.37 (Table 81).
///
/// Selects a MAC algorithm (`TPM_ALG_CMAC`, or a hash algorithm used for HMAC).
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiAlgMacScheme>::None`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmiAlgMacScheme {
    Cmac = Alg::CMAC.tag(),
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

impl TryFrom<Alg> for TpmiAlgMacScheme {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            Alg::CMAC => Ok(Self::Cmac),
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
            _ => Err(UnmarshalError::SYMMETRIC),
        }
    }
}

impl TryFrom<u16> for TpmiAlgMacScheme {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        Self::try_from(Alg::from(val))
    }
}

impl From<TpmiAlgMacScheme> for Alg {
    fn from(val: TpmiAlgMacScheme) -> Alg {
        Alg::from_tag(val as u16)
    }
}

impl From<TpmiAlgHash> for TpmiAlgMacScheme {
    fn from(hash: TpmiAlgHash) -> Self {
        match hash {
            #[cfg(feature = "sha1")]
            TpmiAlgHash::Sha1 => Self::Sha1,
            #[cfg(feature = "sha256")]
            TpmiAlgHash::Sha256 => Self::Sha256,
            #[cfg(feature = "sha384")]
            TpmiAlgHash::Sha384 => Self::Sha384,
            #[cfg(feature = "sha512")]
            TpmiAlgHash::Sha512 => Self::Sha512,
            #[cfg(feature = "sm3_256")]
            TpmiAlgHash::Sm3_256 => Self::Sm3_256,
            #[cfg(feature = "sha3_256")]
            TpmiAlgHash::Sha3_256 => Self::Sha3_256,
            #[cfg(feature = "sha3_384")]
            TpmiAlgHash::Sha3_384 => Self::Sha3_384,
            #[cfg(feature = "sha3_512")]
            TpmiAlgHash::Sha3_512 => Self::Sha3_512,
        }
    }
}

impl Marshal for TpmiAlgMacScheme {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiAlgMacScheme {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

impl TryFrom<Alg> for Option<TpmiAlgMacScheme> {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            Alg::NULL => Ok(None),
            a => a.try_into().map(Some),
        }
    }
}

impl From<Option<TpmiAlgMacScheme>> for Alg {
    fn from(val: Option<TpmiAlgMacScheme>) -> Self {
        val.map_or(Alg::NULL, Alg::from)
    }
}

impl Marshal for Option<TpmiAlgMacScheme> {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmiAlgMacScheme> {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

/// `TPMI_ALG_SIG_SCHEME` interface type defined in TPM 2.0 Part 2: Structures, Section 9.32 (Table 78).
///
/// Selects a signature scheme algorithm (`RSASSA`, `RSAPSS`, `ECDSA`, `ECDAA`, `SM2`, `ECSCHNORR`,
/// `EDDSA`, `HASH_EDDSA`, `HMAC`).
/// Note: `+TPM_ALG_NULL` is represented as `Option<TpmiAlgSigScheme>::None`.
#[doc(alias = "TPMI_ALG_SIG_SCHEME")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u16)]
pub enum TpmiAlgSigScheme {
    #[cfg(feature = "rsassa")]
    Rsassa = Alg::RSASSA.tag(),
    #[cfg(feature = "rsapss")]
    Rsapss = Alg::RSAPSS.tag(),
    #[cfg(feature = "ecdsa")]
    Ecdsa = Alg::ECDSA.tag(),
    #[cfg(feature = "ecdaa")]
    Ecdaa = Alg::ECDAA.tag(),
    #[cfg(feature = "sm2")]
    Sm2 = Alg::SM2.tag(),
    #[cfg(feature = "ecschnorr")]
    Ecschnorr = Alg::ECSCHNORR.tag(),
    Eddsa = Alg::EDDSA.tag(),
    HashEddsa = Alg::HASH_EDDSA.tag(),
    Hmac = Alg::HMAC.tag(),
}

impl TryFrom<Alg> for TpmiAlgSigScheme {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            #[cfg(feature = "rsassa")]
            Alg::RSASSA => Ok(Self::Rsassa),
            #[cfg(feature = "rsapss")]
            Alg::RSAPSS => Ok(Self::Rsapss),
            #[cfg(feature = "ecdsa")]
            Alg::ECDSA => Ok(Self::Ecdsa),
            #[cfg(feature = "ecdaa")]
            Alg::ECDAA => Ok(Self::Ecdaa),
            #[cfg(feature = "sm2")]
            Alg::SM2 => Ok(Self::Sm2),
            #[cfg(feature = "ecschnorr")]
            Alg::ECSCHNORR => Ok(Self::Ecschnorr),
            Alg::EDDSA => Ok(Self::Eddsa),
            Alg::HASH_EDDSA => Ok(Self::HashEddsa),
            Alg::HMAC => Ok(Self::Hmac),
            _ => Err(UnmarshalError::SCHEME),
        }
    }
}

impl TryFrom<u16> for TpmiAlgSigScheme {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        Self::try_from(Alg::from(val))
    }
}

impl From<TpmiAlgSigScheme> for Alg {
    fn from(val: TpmiAlgSigScheme) -> Alg {
        Alg::from_tag(val as u16)
    }
}

impl From<TpmiAlgSigScheme> for u16 {
    fn from(val: TpmiAlgSigScheme) -> u16 {
        Alg::from(val).id()
    }
}

impl Marshal for TpmiAlgSigScheme {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiAlgSigScheme {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

impl TryFrom<Alg> for Option<TpmiAlgSigScheme> {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            Alg::NULL => Ok(None),
            a => a.try_into().map(Some),
        }
    }
}

impl From<Option<TpmiAlgSigScheme>> for Alg {
    fn from(val: Option<TpmiAlgSigScheme>) -> Self {
        val.map_or(Alg::NULL, Alg::from)
    }
}

impl Marshal for Option<TpmiAlgSigScheme> {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmiAlgSigScheme> {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

/// `TPMI_ECC_KEY_EXCHANGE` interface type defined in TPM 2.0 Part 2: Structures, Section 9.35 (Table 79).
///
/// Selects an ECC key exchange scheme (`TPM_ALG_ECDH`, `TPM_ALG_SM2`, `TPM_ALG_ECMQV`).
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiEccKeyExchange>::None`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(any(feature = "ecdh", feature = "sm2", feature = "ecmqv"), repr(u16))]
pub enum TpmiEccKeyExchange {
    #[cfg(feature = "ecdh")]
    Ecdh = Alg::ECDH.tag(),
    #[cfg(feature = "sm2")]
    Sm2 = Alg::SM2.tag(),
    #[cfg(feature = "ecmqv")]
    Ecmqv = Alg::ECMQV.tag(),
}

impl TryFrom<Alg> for TpmiEccKeyExchange {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            #[cfg(feature = "ecdh")]
            Alg::ECDH => Ok(Self::Ecdh),
            #[cfg(feature = "sm2")]
            Alg::SM2 => Ok(Self::Sm2),
            #[cfg(feature = "ecmqv")]
            Alg::ECMQV => Ok(Self::Ecmqv),
            _ => Err(UnmarshalError::SCHEME),
        }
    }
}

impl TryFrom<u16> for TpmiEccKeyExchange {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        Self::try_from(Alg::from(val))
    }
}

impl From<TpmiEccKeyExchange> for Alg {
    fn from(val: TpmiEccKeyExchange) -> Alg {
        match val {
            #[cfg(feature = "ecdh")]
            TpmiEccKeyExchange::Ecdh => Alg::ECDH,
            #[cfg(feature = "sm2")]
            TpmiEccKeyExchange::Sm2 => Alg::SM2,
            #[cfg(feature = "ecmqv")]
            TpmiEccKeyExchange::Ecmqv => Alg::ECMQV,
        }
    }
}

impl Marshal for TpmiEccKeyExchange {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiEccKeyExchange {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

impl TryFrom<Alg> for Option<TpmiEccKeyExchange> {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            Alg::NULL => Ok(None),
            a => a.try_into().map(Some),
        }
    }
}

impl From<Option<TpmiEccKeyExchange>> for Alg {
    fn from(val: Option<TpmiEccKeyExchange>) -> Self {
        val.map_or(Alg::NULL, Alg::from)
    }
}

impl Marshal for Option<TpmiEccKeyExchange> {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmiEccKeyExchange> {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

/// `TPMI_MLKEM_PARMS` interface type defined in TPM 2.0 Part 2: Structures, Section 11.2.5.1.
///
/// Selects the ML-KEM parameter set (`TPM_MLKEM_512`, `TPM_MLKEM_768`, `TPM_MLKEM_1024`).
/// Unmarshalling an unrecognized value returns `TPM_RC_PARMS` (`UnmarshalError::PARMS`).
#[doc(alias = "TPMI_MLKEM_PARMS")]
#[doc(alias = "TPM_MLKEM_PARMS")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u16)]
pub enum TpmiMlkemParms {
    Mlkem512 = 0x0001,
    Mlkem768 = 0x0002,
    Mlkem1024 = 0x0003,
}

/// Type alias for `TPM_MLKEM_PARMS` (`TPMI_MLKEM_PARMS`).
pub type TpmMlkemParms = TpmiMlkemParms;

impl TpmiMlkemParms {
    pub const TPM_MLKEM_512: Self = Self::Mlkem512;
    pub const TPM_MLKEM_768: Self = Self::Mlkem768;
    pub const TPM_MLKEM_1024: Self = Self::Mlkem1024;

    /// Returns the encapsulation (public) key size in bytes for this parameter set.
    #[inline]
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::Mlkem512 => 800,
            Self::Mlkem768 => 1184,
            Self::Mlkem1024 => 1568,
        }
    }

    /// Returns the decapsulation (private) seed size (`d || z`) in bytes for this parameter set.
    #[inline]
    pub const fn private_key_bytes(self) -> usize {
        64
    }

    /// Returns the ciphertext size in bytes for this parameter set.
    #[inline]
    pub const fn ciphertext_bytes(self) -> usize {
        match self {
            Self::Mlkem512 => 768,
            Self::Mlkem768 => 1088,
            Self::Mlkem1024 => 1568,
        }
    }

    /// Returns the shared secret size in bytes for this parameter set.
    #[inline]
    pub const fn shared_secret_bytes(self) -> usize {
        32
    }
}

impl TryFrom<u16> for TpmiMlkemParms {
    type Error = UnmarshalError;
    #[inline]
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0001 => Ok(Self::Mlkem512),
            0x0002 => Ok(Self::Mlkem768),
            0x0003 => Ok(Self::Mlkem1024),
            _ => Err(UnmarshalError::PARMS),
        }
    }
}

impl From<TpmiMlkemParms> for u16 {
    #[inline]
    fn from(val: TpmiMlkemParms) -> u16 {
        val as u16
    }
}

impl Marshal for TpmiMlkemParms {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        u16::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiMlkemParms {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u16::unmarshal(src)?.try_into()
    }
}

/// `TPMI_MLDSA_PARMS` interface type defined in TPM 2.0 Part 2: Structures, Section 11.2.6.1.
///
/// Selects the ML-DSA parameter set (`TPM_MLDSA_44`, `TPM_MLDSA_65`, `TPM_MLDSA_87`).
/// Unmarshalling an unrecognized value returns `TPM_RC_PARMS` (`UnmarshalError::PARMS`).
#[doc(alias = "TPMI_MLDSA_PARMS")]
#[doc(alias = "TPM_MLDSA_PARMS")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u16)]
pub enum TpmiMldsaParms {
    Mldsa44 = 0x0001,
    Mldsa65 = 0x0002,
    Mldsa87 = 0x0003,
}

/// Type alias for `TPM_MLDSA_PARMS` (`TPMI_MLDSA_PARMS`).
pub type TpmMldsaParms = TpmiMldsaParms;

impl TpmiMldsaParms {
    pub const TPM_MLDSA_44: Self = Self::Mldsa44;
    pub const TPM_MLDSA_65: Self = Self::Mldsa65;
    pub const TPM_MLDSA_87: Self = Self::Mldsa87;

    /// Returns the verification (public) key size in bytes for this parameter set.
    #[inline]
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::Mldsa44 => 1312,
            Self::Mldsa65 => 1952,
            Self::Mldsa87 => 2592,
        }
    }

    /// Returns the signing (private) seed size (`xi`) in bytes for this parameter set.
    #[inline]
    pub const fn private_key_bytes(self) -> usize {
        32
    }

    /// Returns the signature size in bytes for this parameter set.
    #[inline]
    pub const fn signature_bytes(self) -> usize {
        match self {
            Self::Mldsa44 => 2420,
            Self::Mldsa65 => 3309,
            Self::Mldsa87 => 4627,
        }
    }
}

impl TryFrom<u16> for TpmiMldsaParms {
    type Error = UnmarshalError;
    #[inline]
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0001 => Ok(Self::Mldsa44),
            0x0002 => Ok(Self::Mldsa65),
            0x0003 => Ok(Self::Mldsa87),
            _ => Err(UnmarshalError::PARMS),
        }
    }
}

impl From<TpmiMldsaParms> for u16 {
    #[inline]
    fn from(val: TpmiMldsaParms) -> u16 {
        val as u16
    }
}

impl Marshal for TpmiMldsaParms {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        u16::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiMldsaParms {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u16::unmarshal(src)?.try_into()
    }
}

/// `TPMI_ALG_PUBLIC` interface type defined in TPM 2.0 Part 2: Structures, Section 12.2.2.
///
/// Selects a public object type algorithm (`RSA`, `KEYEDHASH`, `ECC`, `SYMCIPHER`, `MLKEM`,
/// `MLDSA`, `HASH_MLDSA`).
/// Unmarshalling an unsupported algorithm returns `TPM_RC_TYPE` (`UnmarshalError::TYPE`).
#[doc(alias = "TPMI_ALG_PUBLIC")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u16)]
pub enum TpmiAlgPublic {
    Rsa = Alg::RSA.tag(),
    KeyedHash = Alg::KEYEDHASH.tag(),
    Ecc = Alg::ECC.tag(),
    SymCipher = Alg::SYMCIPHER.tag(),
    Mlkem = Alg::MLKEM.tag(),
    Mldsa = Alg::MLDSA.tag(),
    HashMldsa = Alg::HASH_MLDSA.tag(),
}

impl TryFrom<Alg> for TpmiAlgPublic {
    type Error = UnmarshalError;
    #[inline]
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            #[cfg(feature = "rsa")]
            Alg::RSA => Ok(Self::Rsa),
            Alg::KEYEDHASH => Ok(Self::KeyedHash),
            #[cfg(feature = "ecc")]
            Alg::ECC => Ok(Self::Ecc),
            Alg::SYMCIPHER => Ok(Self::SymCipher),
            Alg::MLKEM => Ok(Self::Mlkem),
            Alg::MLDSA => Ok(Self::Mldsa),
            Alg::HASH_MLDSA => Ok(Self::HashMldsa),
            _ => Err(UnmarshalError::TYPE),
        }
    }
}

impl TryFrom<u16> for TpmiAlgPublic {
    type Error = UnmarshalError;
    #[inline]
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        Self::try_from(Alg::from(val))
    }
}

impl From<TpmiAlgPublic> for Alg {
    #[inline]
    fn from(val: TpmiAlgPublic) -> Alg {
        Alg::from_tag(val as u16)
    }
}

impl From<TpmiAlgPublic> for u16 {
    #[inline]
    fn from(val: TpmiAlgPublic) -> u16 {
        Alg::from(val).id()
    }
}

impl Marshal for TpmiAlgPublic {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiAlgPublic {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}
