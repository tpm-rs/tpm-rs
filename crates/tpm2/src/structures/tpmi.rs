use crate::{errors::UnmarshalError, *};

/// `TPMI_ALG_KDF` interface type defined in TPM 2.0 Part 2: Structures, Section 9.31 (Table 62).
///
/// Selects a key derivation function algorithm (MGF1, KDF1_SP800_56A, KDF2, KDF1_SP800_108, HKDF).
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiAlgKdf>::None`.
#[doc(alias = "TPMI_ALG_KDF")]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TpmiAlgKdf {
    Mgf1 = Alg::MGF1.tag(),
    Kdf1Sp800_56a = Alg::KDF1_SP800_56A.tag(),
    Kdf2 = Alg::KDF2.tag(),
    Kdf1Sp800_108 = Alg::KDF1_SP800_108.tag(),
    Hkdf = Alg::HKDF.tag(),
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
            Alg::HKDF => Ok(Some(TpmiAlgKdf::Hkdf)),
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

/// `TPMI_ECC_KEY_EXCHANGE` interface type defined in TPM 2.0 Part 2: Structures
///
/// Selects an ECC key exchange scheme (`TPM_ALG_ECDH`, `TPM_ALG_ECMQV`, or `TPM_ALG_SM2`), used in `TPM2_ZGen_2Phase`.
#[doc(alias = "TPMI_ECC_KEY_EXCHANGE")]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TpmiEccKeyExchange {
    Ecdh = Alg::ECDH.tag(),
    Ecmqv = Alg::ECMQV.tag(),
    Sm2 = Alg::SM2.tag(),
}

impl TryFrom<Alg> for TpmiEccKeyExchange {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            Alg::ECDH => Ok(Self::Ecdh),
            Alg::ECMQV => Ok(Self::Ecmqv),
            Alg::SM2 => Ok(Self::Sm2),
            _ => Err(UnmarshalError),
        }
    }
}

impl From<TpmiEccKeyExchange> for Alg {
    fn from(scheme: TpmiEccKeyExchange) -> Self {
        Alg::new(scheme as u16)
    }
}

impl Marshal for TpmiEccKeyExchange {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiEccKeyExchange {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

/// `TPMI_ALG_CIPHER_MODE` interface type defined in TPM 2.0 Part 2: Structures, Section 9.26 (Table 57).
///
/// Selects a symmetric block cipher encryption mode of operation (CTR, OFB, CBC, CFB, or ECB).
/// Unlike [`TpmiAlgSymMode`], this excludes `CMAC`.
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiAlgCipherMode>::None`.
#[doc(alias = "TPMI_ALG_CIPHER_MODE")]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TpmiAlgCipherMode {
    #[cfg(feature = "ctr")]
    Ctr = Alg::CTR.tag(),
    #[cfg(feature = "ofb")]
    Ofb = Alg::OFB.tag(),
    #[cfg(feature = "cbc")]
    Cbc = Alg::CBC.tag(),
    Cfb = Alg::CFB.tag(),
    #[cfg(feature = "ecb")]
    Ecb = Alg::ECB.tag(),
}

impl TryFrom<Alg> for Option<TpmiAlgCipherMode> {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            Alg::NULL => Ok(None),
            #[cfg(feature = "ctr")]
            Alg::CTR => Ok(Some(TpmiAlgCipherMode::Ctr)),
            #[cfg(feature = "ofb")]
            Alg::OFB => Ok(Some(TpmiAlgCipherMode::Ofb)),
            #[cfg(feature = "cbc")]
            Alg::CBC => Ok(Some(TpmiAlgCipherMode::Cbc)),
            Alg::CFB => Ok(Some(TpmiAlgCipherMode::Cfb)),
            #[cfg(feature = "ecb")]
            Alg::ECB => Ok(Some(TpmiAlgCipherMode::Ecb)),
            _ => Err(UnmarshalError),
        }
    }
}

impl From<Option<TpmiAlgCipherMode>> for Alg {
    fn from(mode: Option<TpmiAlgCipherMode>) -> Self {
        match mode {
            Some(alg) => Alg::new(alg as u16),
            None => Alg::NULL,
        }
    }
}

impl Marshal for Option<TpmiAlgCipherMode> {
    const MAX_SIZE: usize = Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Alg::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for Option<TpmiAlgCipherMode> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Alg::unmarshal(src)?.try_into()
    }
}

/// `TPMI_ALG_SYM_MODE` interface type defined in TPM 2.0 Part 2: Structures, Section 9.25 (Table 56).
///
/// Selects a symmetric block cipher mode of operation (CBC, CFB, ECB, OFB, CTR, or CMAC).
/// Used in symmetric cipher definitions (`TPMT_SYM_DEF`, `TPMT_SYM_DEF_OBJECT`).
/// Note: `TPM_ALG_NULL` is represented as `Option<TpmiAlgSymMode>::None`.
#[doc(alias = "TPMI_ALG_SYM_MODE")]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TpmiAlgSymMode {
    #[cfg(feature = "cmac")]
    Cmac,
    Cipher(TpmiAlgCipherMode),
}

impl From<TpmiAlgCipherMode> for TpmiAlgSymMode {
    fn from(mode: TpmiAlgCipherMode) -> Self {
        Self::Cipher(mode)
    }
}

impl TryFrom<Alg> for Option<TpmiAlgSymMode> {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<Self, Self::Error> {
        match a {
            #[cfg(feature = "cmac")]
            Alg::CMAC => Ok(Some(TpmiAlgSymMode::Cmac)),
            other => Option::<TpmiAlgCipherMode>::try_from(other).map(|m| m.map(Into::into)),
        }
    }
}

impl From<Option<TpmiAlgSymMode>> for Alg {
    fn from(mode: Option<TpmiAlgSymMode>) -> Self {
        match mode {
            #[cfg(feature = "cmac")]
            Some(TpmiAlgSymMode::Cmac) => Alg::CMAC,
            Some(TpmiAlgSymMode::Cipher(c)) => Alg::from(Some(c)),
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

impl TpmiRsaKeyBits {
    const ALL: &[Self] = &[Self::Rsa1024, Self::Rsa2048, Self::Rsa3072, Self::Rsa4096];

    pub const MAX_PUB_KEY_BITS: u16 = max_by!(Self::ALL, Self::as_u16);
    pub const MAX_PUB_KEY_BYTES: usize = bits_to_bytes(Self::MAX_PUB_KEY_BITS);
    pub const MAX_PRIV_KEY_BYTES: usize = Self::MAX_PUB_KEY_BYTES.div_ceil(2);

    /// Returns [`None`] if the specified key bit size isn't supported.
    pub const fn new(bits: u16) -> Option<Self> {
        find_by!(Self::ALL, |k| k.as_u16() == bits)
    }
    /// Convert the typed enum into an integer number of bits.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for TpmiRsaKeyBits {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        Self::new(val).ok_or(UnmarshalError)
    }
}

impl From<TpmiRsaKeyBits> for u16 {
    fn from(val: TpmiRsaKeyBits) -> Self {
        val.as_u16()
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

/// `TPMI_MLKEM_PARMS` interface type defined in TPM 2.0 Part 2: Structures
///
/// Selects an ML-KEM parameter set (`TPM_MLKEM_512`, `TPM_MLKEM_768`, or `TPM_MLKEM_1024`).
#[doc(alias = "TPMI_MLKEM_PARMS")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum TpmiMlkemParms {
    Mlkem512 = 0x0001,
    Mlkem768 = 0x0002,
    Mlkem1024 = 0x0003,
}

impl TpmiMlkemParms {
    const ALL: &[Self] = &[Self::Mlkem512, Self::Mlkem768, Self::Mlkem1024];

    #[doc(alias = "MAX_MLKEM_PUB_SIZE")]
    pub const MAX_PUB_KEY_BYTES: usize = max_by!(Self::ALL, Self::pub_key_bytes);
    #[doc(alias = "MAX_MLKEM_CT_SIZE")]
    pub const MAX_CT_BYTES: usize = max_by!(Self::ALL, Self::ct_bytes);
    pub const SHARED_SECRET_BYTES: usize = 32;

    const fn info(self) -> (usize, usize) {
        match self {
            Self::Mlkem512 => (800, 768),
            Self::Mlkem768 => (1184, 1088),
            Self::Mlkem1024 => (1568, 1568),
        }
    }

    pub const fn pub_key_bytes(self) -> usize {
        self.info().0
    }

    pub const fn ct_bytes(self) -> usize {
        self.info().1
    }
}

impl TryFrom<u16> for TpmiMlkemParms {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        find_by!(Self::ALL, |p| u16::from(p) == val).ok_or(UnmarshalError)
    }
}

impl From<TpmiMlkemParms> for u16 {
    fn from(val: TpmiMlkemParms) -> Self {
        val as u16
    }
}

impl Marshal for TpmiMlkemParms {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u16::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiMlkemParms {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u16::unmarshal(src)?.try_into()
    }
}

/// `TPMI_MLDSA_PARMS` interface type defined in TPM 2.0 Part 2: Structures
///
/// Selects an ML-DSA parameter set (`TPM_MLDSA_44`, `TPM_MLDSA_65`, or `TPM_MLDSA_87`).
#[doc(alias = "TPMI_MLDSA_PARMS")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum TpmiMldsaParms {
    Mldsa44 = 0x0001,
    Mldsa65 = 0x0002,
    Mldsa87 = 0x0003,
}

impl TpmiMldsaParms {
    const ALL: &[Self] = &[Self::Mldsa44, Self::Mldsa65, Self::Mldsa87];

    #[doc(alias = "MAX_MLDSA_PUB_SIZE")]
    pub const MAX_PUB_KEY_BYTES: usize = max_by!(Self::ALL, Self::pub_key_bytes);
    #[doc(alias = "MAX_MLDSA_SIG_SIZE")]
    pub const MAX_SIG_BYTES: usize = max_by!(Self::ALL, Self::sig_bytes);
    pub const MU_BYTES: usize = 64;

    const fn info(self) -> (usize, usize) {
        match self {
            Self::Mldsa44 => (1312, 2420),
            Self::Mldsa65 => (1952, 3309),
            Self::Mldsa87 => (2592, 4627),
        }
    }

    pub const fn pub_key_bytes(self) -> usize {
        self.info().0
    }

    pub const fn sig_bytes(self) -> usize {
        self.info().1
    }
}

impl TryFrom<u16> for TpmiMldsaParms {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        find_by!(Self::ALL, |p| u16::from(p) == val).ok_or(UnmarshalError)
    }
}

impl From<TpmiMldsaParms> for u16 {
    fn from(val: TpmiMldsaParms) -> Self {
        val as u16
    }
}

impl Marshal for TpmiMldsaParms {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u16::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmiMldsaParms {
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

#[cfg(not(any(
    feature = "sha1",
    feature = "sha256",
    feature = "sha384",
    feature = "sha512",
    feature = "sm3_256",
    feature = "sha3_256",
    feature = "sha3_384",
    feature = "sha3_512",
)))]
compile_error!("at least one hash algorithm feature must be enabled");

impl TpmiAlgHash {
    const ALL: &[Self] = &[
        #[cfg(feature = "sha1")]
        Self::Sha1,
        #[cfg(feature = "sha256")]
        Self::Sha256,
        #[cfg(feature = "sha384")]
        Self::Sha384,
        #[cfg(feature = "sha512")]
        Self::Sha512,
        #[cfg(feature = "sm3_256")]
        Self::Sm3_256,
        #[cfg(feature = "sha3_256")]
        Self::Sha3_256,
        #[cfg(feature = "sha3_384")]
        Self::Sha3_384,
        #[cfg(feature = "sha3_512")]
        Self::Sha3_512,
    ];

    /// The maximum digest size (in bytes) across all supported TPM2 hash algorithms.
    #[doc(alias = "MAX_DIGEST_SIZE")]
    #[doc(alias = "MAX_HASH_DIGEST_SIZE")]
    pub const MAX_DIGEST_BYTES: usize = max_by!(Self::ALL, Self::digest_size);
    /// The maximum number of implemented hash algorithms.
    #[doc(alias = "TPM2_NUM_PCR_BANKS")]
    pub const HASH_COUNT: usize = Self::ALL.len();

    const fn info(self) -> (usize, usize) {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1 => (20, 64),
            #[cfg(feature = "sha256")]
            Self::Sha256 => (32, 64),
            #[cfg(feature = "sha384")]
            Self::Sha384 => (48, 128),
            #[cfg(feature = "sha512")]
            Self::Sha512 => (64, 128),
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256 => (32, 64),
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256 => (32, 136),
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384 => (48, 104),
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512 => (64, 72),
        }
    }

    /// Returns the digest size (in bytes) of this hash algorithm.
    pub const fn digest_size(self) -> usize {
        self.info().0
    }
    /// Returns the block size (in bytes) of this hash algorithm.
    pub const fn block_size(self) -> usize {
        self.info().1
    }
}

impl TryFrom<Alg> for TpmiAlgHash {
    type Error = UnmarshalError;
    fn try_from(a: Alg) -> Result<TpmiAlgHash, Self::Error> {
        find_by!(Self::ALL, |h| Alg::from(h) == a).ok_or(UnmarshalError)
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
