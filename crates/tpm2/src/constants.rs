//! Definitions of constants, identifier types, and C-like enums.
//!
//! The types in this module are generally thin wrappers around basic
//! integer values. They do not check if the values are valid. Instead,
//! those checks are performed by other structures that use these types.
//! For example, `Alg` is valid for any value, but interface types such as
//! [`TpmiAlgHash`](crate::structures::TpmiAlgHash) check that the `Alg` is a valid
//! hash algorithm ID, returning an `Err` if not.
use core::fmt;

use crate::errors::UnmarshalError;
use crate::marshal::{Marshal, Unmarshal};

/// Big-Endian [`u16`] wrapper.
///
/// Many types in this crate ([`Alg`], [`TpmSt`], etc...) have an underlying
/// integer value, and we can reduce the marshalling code size by representing
/// them as big-endian in memory. We use the big-endian value as a tag for the
/// corresponding `Tpmt` types, allowing smaller marshalling code there as well.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
struct BeU16(u16);

impl BeU16 {
    const fn new(x: u16) -> Self {
        Self(x.to_be())
    }
    const fn get(self) -> u16 {
        u16::from_be(self.0)
    }
    const fn tag(self) -> u16 {
        self.0
    }
    const fn from_tag(x: u16) -> Self {
        Self(x)
    }
}
impl Marshal for BeU16 {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    // Already big-endian, so no need for a byte conversion.
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        self.0.to_ne_bytes().marshal(dst)
    }
}
impl Unmarshal<'_> for BeU16 {
    fn unmarshal(src: &mut &[u8]) -> Result<Self, UnmarshalError> {
        let tag = u16::from_ne_bytes(Unmarshal::unmarshal(src)?);
        Ok(BeU16(tag))
    }
}

/// Algorithms defined by either the `TPM_ALG_ID` listing in Part 2 of the
/// [TPM2 Specification](https://trustedcomputinggroup.org/work-groups/trusted-platform-module/)
/// or the `TCG_ALG_ID` list in the
/// [TCG Algorithm Registry](https://trustedcomputinggroup.org/resource/tcg-algorithm-registry/).
///
/// Note that unlike other types, `TPM_ALG_NULL` is represented by
/// [`Alg::NULL`], not [`Option<Alg>::None`].
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Alg(BeU16);

impl Alg {
    /// Creates a new [`Alg`] from raw 16-bit algorithm ID numerical value.
    ///
    /// Panics if `id` is a reserved value:
    /// - `0x0000` (`TPM_ALG_ERROR`)
    /// - `0x00C1` - `0x00C6` (to avoid collision TPM 1.2 values)
    /// - `0x8000` - `0XFFFF` (to avoid collision with [`TpmSt`] values)
    pub const fn new(id: u16) -> Self {
        assert!(
            id != 0x0000 && !(0x00C1 <= id && id <= 0x00C6) && id < 0x8000,
            "reserved or invalid algorithm ID"
        );
        Self(BeU16::new(id))
    }
    /// Returns the raw 16-bit algorithm ID.
    pub const fn id(self) -> u16 {
        self.0.get()
    }
    /// Big-endian tag value to use in `Tpmt*` types
    pub(crate) const fn tag(self) -> u16 {
        self.0.tag()
    }
    pub(crate) const fn from_tag(x: u16) -> Self {
        Self(BeU16::from_tag(x))
    }

    // Object Types
    #[doc(alias = "TPM_ALG_KEYEDHASH")]
    pub const KEYEDHASH: Self = Self::new(0x0008);
    #[doc(alias = "TPM_ALG_SYMCIPHER")]
    pub const SYMCIPHER: Self = Self::new(0x0025);
    #[doc(alias = "TPM_ALG_RSA")]
    pub const RSA: Self = Self::new(0x0001);
    #[doc(alias = "TPM_ALG_ECC")]
    pub const ECC: Self = Self::new(0x0023);
    #[doc(alias = "TPM_ALG_MLKEM")]
    pub const MLKEM: Self = Self::new(0x00A0);
    #[doc(alias = "TPM_ALG_MLDSA")]
    pub const MLDSA: Self = Self::new(0x00A1);
    #[doc(alias = "TPM_ALG_HASH_MLDSA")]
    pub const HASH_MLDSA: Self = Self::new(0x00A2);

    // Hash Algorithms
    #[doc(alias = "TPM_ALG_SHA1")]
    pub const SHA1: Self = Self::new(0x0004);
    #[doc(alias = "TPM_ALG_SHA256")]
    pub const SHA256: Self = Self::new(0x000B);
    #[doc(alias = "TPM_ALG_SHA384")]
    pub const SHA384: Self = Self::new(0x000C);
    #[doc(alias = "TPM_ALG_SHA512")]
    pub const SHA512: Self = Self::new(0x000D);
    #[doc(alias = "TPM_ALG_SM3_256")]
    pub const SM3_256: Self = Self::new(0x0012);
    #[doc(alias = "TPM_ALG_SHA3_256")]
    pub const SHA3_256: Self = Self::new(0x0027);
    #[doc(alias = "TPM_ALG_SHA3_384")]
    pub const SHA3_384: Self = Self::new(0x0028);
    #[doc(alias = "TPM_ALG_SHA3_512")]
    pub const SHA3_512: Self = Self::new(0x0029);

    // Block Ciphers
    #[doc(alias = "TPM_ALG_TDES")]
    pub const TDES: Self = Self::new(0x0003);
    #[doc(alias = "TPM_ALG_AES")]
    pub const AES: Self = Self::new(0x0006);
    #[doc(alias = "TPM_ALG_SM4")]
    pub const SM4: Self = Self::new(0x0013);
    #[doc(alias = "TPM_ALG_CAMELLIA")]
    pub const CAMELLIA: Self = Self::new(0x0026);

    // Block Cipher Modes
    #[doc(alias = "TPM_ALG_CTR")]
    pub const CTR: Self = Self::new(0x0040);
    #[doc(alias = "TPM_ALG_OFB")]
    pub const OFB: Self = Self::new(0x0041);
    #[doc(alias = "TPM_ALG_CBC")]
    pub const CBC: Self = Self::new(0x0042);
    #[doc(alias = "TPM_ALG_CFB")]
    pub const CFB: Self = Self::new(0x0043);
    #[doc(alias = "TPM_ALG_ECB")]
    pub const ECB: Self = Self::new(0x0044);

    // Message Authentication Codes
    #[doc(alias = "TPM_ALG_HMAC")]
    pub const HMAC: Self = Self::new(0x0005);
    #[doc(alias = "TPM_ALG_CMAC")]
    pub const CMAC: Self = Self::new(0x003F);

    // Key Derivation Functions
    #[doc(alias = "TPM_ALG_HKDF")]
    pub const HKDF: Self = Self::new(0x001F);
    #[doc(alias = "TPM_ALG_KDF1_SP800_56A")]
    pub const KDF1_SP800_56A: Self = Self::new(0x0020);
    #[doc(alias = "TPM_ALG_KDF2")]
    pub const KDF2: Self = Self::new(0x0021);
    #[doc(alias = "TPM_ALG_KDF1_SP800_108")]
    pub const KDF1_SP800_108: Self = Self::new(0x0022);

    // RSA Schemes
    #[doc(alias = "TPM_ALG_RSASSA")]
    pub const RSASSA: Self = Self::new(0x0014);
    #[doc(alias = "TPM_ALG_RSAPSS")]
    pub const RSAPSS: Self = Self::new(0x0016);
    #[doc(alias = "TPM_ALG_RSAES")]
    pub const RSAES: Self = Self::new(0x0015);
    #[doc(alias = "TPM_ALG_OAEP")]
    pub const OAEP: Self = Self::new(0x0017);

    // ECC Schemes
    #[doc(alias = "TPM_ALG_ECDSA")]
    pub const ECDSA: Self = Self::new(0x0018);
    #[doc(alias = "TPM_ALG_ECSCHNORR")]
    pub const ECSCHNORR: Self = Self::new(0x001C);
    #[doc(alias = "TPM_ALG_ECDAA")]
    pub const ECDAA: Self = Self::new(0x001A);
    #[doc(alias = "TPM_ALG_ECDH")]
    pub const ECDH: Self = Self::new(0x0019);
    #[doc(alias = "TPM_ALG_ECMQV")]
    pub const ECMQV: Self = Self::new(0x001D);
    #[doc(alias = "TPM_ALG_SM2")]
    pub const SM2: Self = Self::new(0x001B);
    #[doc(alias = "TPM_ALG_EDDSA")]
    pub const EDDSA: Self = Self::new(0x0060);
    #[doc(alias = "TPM_ALG_HASH_EDDSA")]
    pub const HASH_EDDSA: Self = Self::new(0x0061);

    // Miscellaneous
    #[doc(alias = "TPM_ALG_NULL")]
    pub const NULL: Self = Self::new(0x0010);
    #[doc(alias = "TPM_ALG_XOR")]
    pub const XOR: Self = Self::new(0x000A);
    #[doc(alias = "TPM_ALG_MGF1")]
    pub const MGF1: Self = Self::new(0x0007);
}

impl From<u16> for Alg {
    fn from(val: u16) -> Self {
        Self(BeU16::new(val))
    }
}
impl From<Alg> for u16 {
    fn from(val: Alg) -> Self {
        val.id()
    }
}
impl Default for Alg {
    fn default() -> Self {
        Self::NULL
    }
}
impl Marshal for Alg {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        self.0.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for Alg {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        BeU16::unmarshal(src).map(Self)
    }
}

impl fmt::Debug for Alg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::KEYEDHASH => write!(f, "Alg::KEYEDHASH"),
            Self::SYMCIPHER => write!(f, "Alg::SYMCIPHER"),
            Self::RSA => write!(f, "Alg::RSA"),
            Self::ECC => write!(f, "Alg::ECC"),
            Self::MLKEM => write!(f, "Alg::MLKEM"),
            Self::MLDSA => write!(f, "Alg::MLDSA"),
            Self::HASH_MLDSA => write!(f, "Alg::HASH_MLDSA"),
            Self::SHA1 => write!(f, "Alg::SHA1"),
            Self::SHA256 => write!(f, "Alg::SHA256"),
            Self::SHA384 => write!(f, "Alg::SHA384"),
            Self::SHA512 => write!(f, "Alg::SHA512"),
            Self::SM3_256 => write!(f, "Alg::SM3_256"),
            Self::SHA3_256 => write!(f, "Alg::SHA3_256"),
            Self::SHA3_384 => write!(f, "Alg::SHA3_384"),
            Self::SHA3_512 => write!(f, "Alg::SHA3_512"),
            Self::TDES => write!(f, "Alg::TDES"),
            Self::AES => write!(f, "Alg::AES"),
            Self::SM4 => write!(f, "Alg::SM4"),
            Self::CAMELLIA => write!(f, "Alg::CAMELLIA"),
            Self::CTR => write!(f, "Alg::CTR"),
            Self::OFB => write!(f, "Alg::OFB"),
            Self::CBC => write!(f, "Alg::CBC"),
            Self::CFB => write!(f, "Alg::CFB"),
            Self::ECB => write!(f, "Alg::ECB"),
            Self::HMAC => write!(f, "Alg::HMAC"),
            Self::CMAC => write!(f, "Alg::CMAC"),
            Self::HKDF => write!(f, "Alg::HKDF"),
            Self::KDF1_SP800_56A => write!(f, "Alg::KDF1_SP800_56A"),
            Self::KDF2 => write!(f, "Alg::KDF2"),
            Self::KDF1_SP800_108 => write!(f, "Alg::KDF1_SP800_108"),
            Self::RSASSA => write!(f, "Alg::RSASSA"),
            Self::RSAPSS => write!(f, "Alg::RSAPSS"),
            Self::RSAES => write!(f, "Alg::RSAES"),
            Self::OAEP => write!(f, "Alg::OAEP"),
            Self::ECDSA => write!(f, "Alg::ECDSA"),
            Self::ECSCHNORR => write!(f, "Alg::ECSCHNORR"),
            Self::ECDAA => write!(f, "Alg::ECDAA"),
            Self::ECDH => write!(f, "Alg::ECDH"),
            Self::ECMQV => write!(f, "Alg::ECMQV"),
            Self::SM2 => write!(f, "Alg::SM2"),
            Self::EDDSA => write!(f, "Alg::EDDSA"),
            Self::HASH_EDDSA => write!(f, "Alg::HASH_EDDSA"),
            Self::NULL => write!(f, "Alg::NULL"),
            Self::XOR => write!(f, "Alg::XOR"),
            Self::MGF1 => write!(f, "Alg::MGF1"),
            other => write!(f, "Alg(0x{:04X})", other.id()),
        }
    }
}

/// TPM 2.0 specification family indicator (`0x322E3000`, ASCII `"2.0\0"`).
///
/// Defined in TPM 2.0 Part 2, Section 6.1 (Table 6 — Definition of `(UINT32) TPM_SPEC` Constants).
#[doc(alias = "SPEC_FAMILY")]
pub const TPM_SPEC_FAMILY: u32 = 0x322E_3000;

/// TPM 2.0 specification level number (`0`).
///
/// Defined in TPM 2.0 Part 2, Section 6.1 (Table 6 — Definition of `(UINT32) TPM_SPEC` Constants).
#[doc(alias = "SPEC_LEVEL")]
pub const TPM_SPEC_LEVEL: u32 = 0;

/// TPM 2.0 specification version number (`185`).
///
/// Defined in TPM 2.0 Part 2, Section 6.1 (Table 6 — Definition of `(UINT32) TPM_SPEC` Constants).
#[doc(alias = "SPEC_VERSION")]
pub const TPM_SPEC_VERSION: u32 = 185;

/// TPM 2.0 specification year (`0` in version 185+).
///
/// Defined in TPM 2.0 Part 2, Section 6.1 (Table 6 — Definition of `(UINT32) TPM_SPEC` Constants).
/// Prior to version 185, this constant reported the year in which the TPM Library Specification
/// indicated by [`TPM_SPEC_VERSION`] was published. Beginning with version 185, it is set to `0`
/// to indicate that the errata level is reported in [`TPM_SPEC_ERRATA`].
#[doc(alias = "SPEC_YEAR")]
pub const TPM_SPEC_YEAR: u32 = 0;

/// TPM 2.0 errata version implemented by the TPM (`0`).
///
/// Defined in TPM 2.0 Part 2, Section 6.1 (Table 6 — Definition of `(UINT32) TPM_SPEC` Constants).
/// Prior to version 185, this constant was called [`TPM_SPEC_DAY_OF_YEAR`].
#[doc(alias = "SPEC_ERRATA")]
pub const TPM_SPEC_ERRATA: u32 = 0;

/// Legacy alias for [`TPM_SPEC_ERRATA`] (prior to TPM 2.0 specification version 185).
///
/// Defined in TPM 2.0 Part 2, Section 6.1 (Table 6 — Definition of `(UINT32) TPM_SPEC` Constants).
#[doc(alias = "SPEC_DAY_OF_YEAR")]
pub const TPM_SPEC_DAY_OF_YEAR: u32 = TPM_SPEC_ERRATA;

/// Alias for [`TPM_SPEC_FAMILY`] (`SPEC_FAMILY` in C reference implementations).
pub const SPEC_FAMILY: u32 = TPM_SPEC_FAMILY;

/// Alias for [`TPM_SPEC_LEVEL`] (`SPEC_LEVEL` in C reference implementations).
pub const SPEC_LEVEL: u32 = TPM_SPEC_LEVEL;

/// Alias for [`TPM_SPEC_VERSION`] (`SPEC_VERSION` in C reference implementations).
pub const SPEC_VERSION: u32 = TPM_SPEC_VERSION;

/// Alias for [`TPM_SPEC_YEAR`] (`SPEC_YEAR` in C reference implementations).
pub const SPEC_YEAR: u32 = TPM_SPEC_YEAR;

/// Alias for [`TPM_SPEC_ERRATA`] (`SPEC_ERRATA` in C reference implementations).
pub const SPEC_ERRATA: u32 = TPM_SPEC_ERRATA;

/// Alias for [`TPM_SPEC_DAY_OF_YEAR`] (`SPEC_DAY_OF_YEAR` in C reference implementations).
pub const SPEC_DAY_OF_YEAR: u32 = TPM_SPEC_DAY_OF_YEAR;

/// TPM 2.0 Part 2 Section 6.1 Table 6: Definition of `(UINT32) TPM_SPEC` Constants.
///
/// Architectural specification version constants returned by `TPM2_GetCapability`
/// for fixed TPM properties ([`TpmPt::FAMILY_INDICATOR`], [`TpmPt::LEVEL`],
/// [`TpmPt::REVISION`], [`TpmPt::ERRATA`], and [`TpmPt::YEAR`]).
#[doc(alias = "TPM_SPEC")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[repr(transparent)]
pub struct TpmSpec(pub u32);

impl TpmSpec {
    /// Creates a new [`TpmSpec`] from a raw 32-bit specification constant value.
    pub const fn new(val: u32) -> Self {
        Self(val)
    }

    /// Returns the raw 32-bit `TPM_SPEC` value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_SPEC` value.
    pub const fn id(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_SPEC` value.
    pub const fn code(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_SPEC` value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// ASCII `"2.0\0"` family indicator (`0x322E3000`).
    #[doc(alias = "TPM_SPEC_FAMILY")]
    pub const FAMILY: u32 = TPM_SPEC_FAMILY;

    /// 4-octet byte representation of [`TPM_SPEC_FAMILY`] (`*b"2.0\0"`).
    pub const FAMILY_BYTES: [u8; 4] = TPM_SPEC_FAMILY.to_be_bytes();

    /// Level number for the specification (`0`).
    #[doc(alias = "TPM_SPEC_LEVEL")]
    pub const LEVEL: u32 = TPM_SPEC_LEVEL;

    /// Version number of the specification (`185`).
    #[doc(alias = "TPM_SPEC_VERSION")]
    pub const VERSION: u32 = TPM_SPEC_VERSION;

    /// Specification year (`0` in version 185+).
    #[doc(alias = "TPM_SPEC_YEAR")]
    pub const YEAR: u32 = TPM_SPEC_YEAR;

    /// Errata version implemented by the TPM (`0`).
    #[doc(alias = "TPM_SPEC_ERRATA")]
    pub const ERRATA: u32 = TPM_SPEC_ERRATA;

    /// Legacy alias for [`Self::ERRATA`] (`TPM_SPEC_DAY_OF_YEAR`).
    #[doc(alias = "TPM_SPEC_DAY_OF_YEAR")]
    pub const DAY_OF_YEAR: u32 = TPM_SPEC_DAY_OF_YEAR;

    /// Alias for [`TPM_SPEC_FAMILY`].
    pub const TPM_SPEC_FAMILY: u32 = TPM_SPEC_FAMILY;

    /// Alias for [`TPM_SPEC_LEVEL`].
    pub const TPM_SPEC_LEVEL: u32 = TPM_SPEC_LEVEL;

    /// Alias for [`TPM_SPEC_VERSION`].
    pub const TPM_SPEC_VERSION: u32 = TPM_SPEC_VERSION;

    /// Alias for [`TPM_SPEC_YEAR`].
    pub const TPM_SPEC_YEAR: u32 = TPM_SPEC_YEAR;

    /// Alias for [`TPM_SPEC_ERRATA`].
    pub const TPM_SPEC_ERRATA: u32 = TPM_SPEC_ERRATA;

    /// Alias for [`TPM_SPEC_DAY_OF_YEAR`].
    pub const TPM_SPEC_DAY_OF_YEAR: u32 = TPM_SPEC_DAY_OF_YEAR;
}

impl From<u32> for TpmSpec {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<TpmSpec> for u32 {
    fn from(val: TpmSpec) -> Self {
        val.0
    }
}

impl PartialEq<u32> for TpmSpec {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl PartialEq<TpmSpec> for u32 {
    fn eq(&self, other: &TpmSpec) -> bool {
        *self == other.0
    }
}

impl Marshal for TpmSpec {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmSpec {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self(u32::unmarshal(src)?))
    }
}

/// 32-bit miscellaneous TPM constant type (`(UINT32) TPM_CONSTANTS32`).
///
/// Defined in TPM 2.0 Part 2, Section 6.2 (Table 7 — Definition of `(UINT32) TPM_CONSTANTS32` Constants).
#[doc(alias = "TPM_CONSTANTS32")]
pub type TpmConstants32 = u32;

/// `0xFF 'TCG'` (`0xFF544347`) magic constant used to differentiate TPM-generated structures
/// from non-TPM structures (`TPM_GENERATED_VALUE`).
///
/// Defined in TPM 2.0 Part 2, Section 6.2 (Table 7 — `TPM_CONSTANTS32`).
#[doc(alias = "TPM2_GENERATED_VALUE")]
pub const TPM_GENERATED_VALUE: TpmConstants32 = 0xFF54_4347;

/// Alias for [`TPM_GENERATED_VALUE`].
pub const TPM2_GENERATED_VALUE: TpmConstants32 = TPM_GENERATED_VALUE;

/// Maximum number of bits generated by an instantiation of the KDF during object derivation (`TPM_MAX_DERIVATION_BITS`).
///
/// Per TPM 2.0 Spec Part 2 Section 6.2 (Table 7 — `TPM_CONSTANTS32`) and Part 1 Section 25.2.
#[doc(alias = "TPM_MAX_DERIVATION_BITS")]
pub const TPM2_MAX_DERIVATION_BITS: TpmConstants32 = 8192;

/// Maximum number of bits that may be generated by an instantiation of the deterministic
/// pseudo-random bit generator (`TPM_MAX_DERIVATION_BITS`).
///
/// Defined in TPM 2.0 Part 2, Section 6.2 (Table 7 — `TPM_CONSTANTS32`) and Part 1, Section 25.2.
pub const TPM_MAX_DERIVATION_BITS: TpmConstants32 = TPM2_MAX_DERIVATION_BITS;

pub const TPM2_MAX_DIGEST_BUFFER: u32 = 1024;
/// Maximum data size in one NV read, write, extend, or certify command (`MAX_NV_BUFFER_SIZE` / `TPM_PT_NV_BUFFER_MAX`).
///
/// Per TPM 2.0 Part 2 Section 6.13 (`TPM_PT_NV_BUFFER_MAX`), Section 10.4.11 (`TPM2B_MAX_NV_BUFFER`),
/// and C reference (`TpmProfile_Misc.h`: `MAX_NV_BUFFER_SIZE = 1024`).
#[doc(alias = "MAX_NV_BUFFER_SIZE")]
pub const TPM2_MAX_NV_BUFFER_SIZE: u32 = 1024;
/// Maximum data size of an NV Index (`MAX_NV_INDEX_SIZE`).
///
/// Per TPM 2.0 Part 2 Section 13.6 (Table 227 — `TPMS_NV_PUBLIC`), `dataSize` is bounded
/// by `MAX_NV_INDEX_SIZE` (2048 bytes).
#[doc(alias = "MAX_NV_INDEX_SIZE")]
pub const TPM2_MAX_NV_INDEX_SIZE: u16 = 2048;
pub const TPM2_MAX_CAP_BUFFER: u32 = 1024;
/// The number of implemented hash algorithms and PCR banks (`HASH_COUNT`).
///
/// Computed dynamically from the enabled hash algorithm features (`sha1`, `sha256`,
/// `sha384`, `sha512`, `sm3_256`, `sha3_256`, `sha3_384`, `sha3_512`).
/// Per TPM 2.0 Part 2, Sections 10.8.6 (`TPML_DIGEST_VALUES`) and 10.8.7 (`TPML_PCR_SELECTION`),
/// this value bounds the maximum list count for digest values and PCR selections.
#[doc(alias = "HASH_COUNT")]
pub const TPM2_NUM_PCR_BANKS: u32 = cfg!(feature = "sha1") as u32
    + cfg!(feature = "sha256") as u32
    + cfg!(feature = "sha384") as u32
    + cfg!(feature = "sha512") as u32
    + cfg!(feature = "sm3_256") as u32
    + cfg!(feature = "sha3_256") as u32
    + cfg!(feature = "sha3_384") as u32
    + cfg!(feature = "sha3_512") as u32;
pub const TPM2_MAX_PCRS: u32 = 24;
pub const TPM2_PCR_SELECT_MIN: usize = 3;
pub const TPM2_PCR_SELECT_MAX: u32 = TPM2_MAX_PCRS.div_ceil(8);
pub const TPM2_LABEL_MAX_BUFFER: u32 = 32;

/* Encryption block sizes */
pub const TPM2_MAX_SYM_BLOCK_SIZE: u32 = 16;
/// Maximum symmetric/sealed sensitive data size (`MAX_SYM_DATA`).
///
/// Per TPM 2.0 Part 2 Section 11.1.9 (Table 158 — `TPMU_SENSITIVE_CREATE` and Table 159 — `TPM2B_SENSITIVE_DATA`),
/// "For interoperability, `MAX_SYM_DATA` should be 128."
#[doc(alias = "MAX_SYM_DATA")]
pub const TPM2_MAX_SYM_DATA: u32 = 128;
pub const TPM2_MAX_ECC_KEY_BYTES: u32 = 128;
pub const TPM2_MAX_SYM_KEY_BYTES: u32 = crate::TpmtSymDefObject::MAX_KEY_BYTES as u32;
pub const TPM2_MAX_RSA_KEY_BYTES: u32 = crate::TpmiRsaKeyBits::MAX_PUB_KEY_BYTES as u32;
pub const TPM2_RSA_PRIVATE_SIZE: usize = (TPM2_MAX_RSA_KEY_BYTES as usize / 2) * 5;
#[doc(alias = "MAX_MLKEM_PUB_SIZE")]
pub const TPM2_MAX_MLKEM_PUB_SIZE: usize = 1568;
#[doc(alias = "MAX_MLKEM_PRIV_SIZE")]
pub const TPM2_MAX_MLKEM_PRIV_SIZE: usize = 64;
#[doc(alias = "MAX_MLKEM_CT_SIZE")]
pub const TPM2_MAX_MLKEM_CT_SIZE: usize = 1568;
#[doc(alias = "MAX_KEM_CIPHERTEXT_SIZE")]
pub const TPM2_MAX_KEM_CIPHERTEXT_SIZE: usize =
    crate::marshal::max(&[crate::TpmsEccPoint::MAX_SIZE, TPM2_MAX_MLKEM_CT_SIZE]);
#[doc(alias = "MAX_MLDSA_PUB_SIZE")]
pub const TPM2_MAX_MLDSA_PUB_SIZE: usize = 2592;
#[doc(alias = "MAX_MLDSA_PRIV_SIZE")]
pub const TPM2_MAX_MLDSA_PRIV_SIZE: usize = 32;
#[doc(alias = "MAX_MLDSA_SIG_SIZE")]
pub const TPM2_MAX_MLDSA_SIG_SIZE: usize = 4627;
#[doc(alias = "MAX_SIGNATURE_CTX_SIZE")]
pub const TPM2_MAX_SIGNATURE_CTX_SIZE: usize = 255;

pub const TPM2_MAX_CONTEXT_SIZE: u32 = 5120;
/// Maximum buffer size of `TPM2B_PRIVATE` (`sizeof(_PRIVATE)`).
///
/// Per TPM 2.0 Spec Part 2, Section 12.3.6 (Table 218 — `_PRIVATE`) and Section 12.3.7
/// (Table 219 — `TPM2B_PRIVATE`), `_PRIVATE` consists of `integrityOuter` (`TPM2B_DIGEST`),
/// `integrityInner` (`TPM2B_DIGEST`), and `sensitive` (`TPM2B_SENSITIVE`).
pub const TPM2_MAX_PRIVATE_SIZE: usize =
    crate::Tpm2bDigest::MAX_SIZE + crate::Tpm2bDigest::MAX_SIZE + crate::Tpm2bSensitive::MAX_SIZE;
pub const TPM2_MAX_ACTIVE_SESSIONS: u32 = 64;
#[doc(alias = "MAX_LOADED_OBJECTS")]
pub const TPM2_MAX_LOADED_OBJECTS: u32 = 16;

/// `TPM_ECC_CURVE` and `TPMI_ECC_CURVE` defined in TPM 2.0 Part 2: Structures, Section 6.4 (Table 10) and Section 9.7 (Table 38).
///
/// See definition in Part 2: Structures, section 6.4.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(u16)]
pub enum TpmEccCurve {
    #[default]
    #[doc(alias = "TPM_ECC_NONE")]
    None = 0x0000,
    #[cfg(feature = "ecc_curve_nist_p192")]
    #[doc(alias = "TPM_ECC_NIST_P192")]
    NistP192 = 0x0001,
    #[cfg(feature = "ecc_curve_nist_p224")]
    #[doc(alias = "TPM_ECC_NIST_P224")]
    NistP224 = 0x0002,
    #[cfg(feature = "ecc_curve_nist_p256")]
    #[doc(alias = "TPM_ECC_NIST_P256")]
    NistP256 = 0x0003,
    #[cfg(feature = "ecc_curve_nist_p384")]
    #[doc(alias = "TPM_ECC_NIST_P384")]
    NistP384 = 0x0004,
    #[cfg(feature = "ecc_curve_nist_p521")]
    #[doc(alias = "TPM_ECC_NIST_P521")]
    NistP521 = 0x0005,
    #[cfg(feature = "ecc_curve_bn_p256")]
    #[doc(alias = "TPM_ECC_BN_P256")]
    BNP256 = 0x0010,
    #[cfg(feature = "ecc_curve_bn_p638")]
    #[doc(alias = "TPM_ECC_BN_P638")]
    BNP638 = 0x0011,
    #[cfg(feature = "ecc_curve_sm2_p256")]
    #[doc(alias = "TPM_ECC_SM2_P256")]
    SM2P256 = 0x0020,
    #[cfg(feature = "ecc_curve_bp_p256_r1")]
    #[doc(alias = "TPM_ECC_BP_P256_R1")]
    BpP256R1 = 0x0030,
    #[cfg(feature = "ecc_curve_bp_p384_r1")]
    #[doc(alias = "TPM_ECC_BP_P384_R1")]
    BpP384R1 = 0x0031,
    #[cfg(feature = "ecc_curve_bp_p512_r1")]
    #[doc(alias = "TPM_ECC_BP_P512_R1")]
    BpP512R1 = 0x0032,
    #[cfg(feature = "ecc_curve_curve25519")]
    #[doc(alias = "TPM_ECC_CURVE_25519")]
    Curve25519 = 0x0040,
    #[cfg(feature = "ecc_curve_curve448")]
    #[doc(alias = "TPM_ECC_CURVE_448")]
    Curve448 = 0x0041,
}

impl TpmEccCurve {
    pub const MAX_ECC_KEY_BITS: usize = crate::marshal::max(&[
        #[cfg(feature = "ecc_curve_nist_p192")]
        192,
        #[cfg(feature = "ecc_curve_nist_p224")]
        224,
        #[cfg(feature = "ecc_curve_nist_p256")]
        256,
        #[cfg(feature = "ecc_curve_nist_p384")]
        384,
        #[cfg(feature = "ecc_curve_nist_p521")]
        521,
        #[cfg(feature = "ecc_curve_bn_p256")]
        256,
        #[cfg(feature = "ecc_curve_bn_p638")]
        638,
        #[cfg(feature = "ecc_curve_sm2_p256")]
        256,
        #[cfg(feature = "ecc_curve_bp_p256_r1")]
        256,
        #[cfg(feature = "ecc_curve_bp_p384_r1")]
        384,
        #[cfg(feature = "ecc_curve_bp_p512_r1")]
        512,
        #[cfg(feature = "ecc_curve_curve25519")]
        256,
        #[cfg(feature = "ecc_curve_curve448")]
        448,
    ]);
    pub const MAX_ECC_KEY_BYTES: usize = Self::MAX_ECC_KEY_BITS.div_ceil(8);

    /// Returns the coordinate and scalar parameter size (in bytes) for this curve.
    pub const fn parameter_size(self) -> usize {
        match self {
            Self::None => 0,
            #[cfg(feature = "ecc_curve_nist_p192")]
            Self::NistP192 => 24,
            #[cfg(feature = "ecc_curve_nist_p224")]
            Self::NistP224 => 28,
            #[cfg(feature = "ecc_curve_nist_p256")]
            Self::NistP256 => 32,
            #[cfg(feature = "ecc_curve_nist_p384")]
            Self::NistP384 => 48,
            #[cfg(feature = "ecc_curve_nist_p521")]
            Self::NistP521 => 66,
            #[cfg(feature = "ecc_curve_bn_p256")]
            Self::BNP256 => 32,
            #[cfg(feature = "ecc_curve_bn_p638")]
            Self::BNP638 => 80,
            #[cfg(feature = "ecc_curve_sm2_p256")]
            Self::SM2P256 => 32,
            #[cfg(feature = "ecc_curve_bp_p256_r1")]
            Self::BpP256R1 => 32,
            #[cfg(feature = "ecc_curve_bp_p384_r1")]
            Self::BpP384R1 => 48,
            #[cfg(feature = "ecc_curve_bp_p512_r1")]
            Self::BpP512R1 => 64,
            #[cfg(feature = "ecc_curve_curve25519")]
            Self::Curve25519 => 32,
            #[cfg(feature = "ecc_curve_curve448")]
            Self::Curve448 => 56,
        }
    }
}

impl TryFrom<u16> for TpmEccCurve {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0000 => Ok(Self::None),
            #[cfg(feature = "ecc_curve_nist_p192")]
            0x0001 => Ok(Self::NistP192),
            #[cfg(feature = "ecc_curve_nist_p224")]
            0x0002 => Ok(Self::NistP224),
            #[cfg(feature = "ecc_curve_nist_p256")]
            0x0003 => Ok(Self::NistP256),
            #[cfg(feature = "ecc_curve_nist_p384")]
            0x0004 => Ok(Self::NistP384),
            #[cfg(feature = "ecc_curve_nist_p521")]
            0x0005 => Ok(Self::NistP521),
            #[cfg(feature = "ecc_curve_bn_p256")]
            0x0010 => Ok(Self::BNP256),
            #[cfg(feature = "ecc_curve_bn_p638")]
            0x0011 => Ok(Self::BNP638),
            #[cfg(feature = "ecc_curve_sm2_p256")]
            0x0020 => Ok(Self::SM2P256),
            #[cfg(feature = "ecc_curve_bp_p256_r1")]
            0x0030 => Ok(Self::BpP256R1),
            #[cfg(feature = "ecc_curve_bp_p384_r1")]
            0x0031 => Ok(Self::BpP384R1),
            #[cfg(feature = "ecc_curve_bp_p512_r1")]
            0x0032 => Ok(Self::BpP512R1),
            #[cfg(feature = "ecc_curve_curve25519")]
            0x0040 => Ok(Self::Curve25519),
            #[cfg(feature = "ecc_curve_curve448")]
            0x0041 => Ok(Self::Curve448),
            _ => Err(UnmarshalError::CURVE),
        }
    }
}
impl From<TpmEccCurve> for u16 {
    fn from(val: TpmEccCurve) -> Self {
        val as u16
    }
}

impl Marshal for TpmEccCurve {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        u16::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmEccCurve {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match u16::unmarshal(src)?.try_into()? {
            Self::None => Err(UnmarshalError::CURVE),
            curve => Ok(curve),
        }
    }
}

impl Marshal for Option<TpmEccCurve> {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        match self {
            Some(curve) => curve.marshal(dst),
            None => u16::from(TpmEccCurve::None).marshal(dst),
        }
    }
}
impl<'a> Unmarshal<'a> for Option<TpmEccCurve> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match u16::unmarshal(src)?.try_into()? {
            TpmEccCurve::None => Ok(None),
            curve => Ok(Some(curve)),
        }
    }
}

/// TPM_CC (Command Code)
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub struct TpmCc(u32);

#[allow(non_upper_case_globals)]
impl TpmCc {
    /// Creates a new [`TpmCc`] from raw 32-bit command code value.
    pub const fn new(code: u32) -> Self {
        Self(code)
    }
    /// Returns the raw 32-bit command code.
    pub const fn code(self) -> u32 {
        self.0
    }

    /// First command code defined in the TPM 2.0 specification (`0x0000011F`).
    #[doc(alias = "TPM_CC_FIRST")]
    pub const FIRST: Self = Self::NVUndefineSpaceSpecial;

    #[doc(alias = "TPM_CC_NV_UndefineSpaceSpecial")]
    pub const NVUndefineSpaceSpecial: Self = Self::new(0x0000011F);
    #[doc(alias = "TPM_CC_EvictControl")]
    pub const EvictControl: Self = Self::new(0x00000120);
    #[doc(alias = "TPM_CC_HierarchyControl")]
    pub const HierarchyControl: Self = Self::new(0x00000121);
    #[doc(alias = "TPM_CC_NV_UndefineSpace")]
    pub const NVUndefineSpace: Self = Self::new(0x00000122);
    #[doc(alias = "TPM_CC_ChangeEPS")]
    pub const ChangeEPS: Self = Self::new(0x00000124);
    #[doc(alias = "TPM_CC_ChangePPS")]
    pub const ChangePPS: Self = Self::new(0x00000125);
    #[doc(alias = "TPM_CC_Clear")]
    pub const Clear: Self = Self::new(0x00000126);
    #[doc(alias = "TPM_CC_ClearControl")]
    pub const ClearControl: Self = Self::new(0x00000127);
    #[doc(alias = "TPM_CC_ClockSet")]
    pub const ClockSet: Self = Self::new(0x00000128);
    #[doc(alias = "TPM_CC_HierarchyChangeAuth")]
    pub const HierarchyChangeAuth: Self = Self::new(0x00000129);
    #[doc(alias = "TPM_CC_NV_DefineSpace")]
    pub const NVDefineSpace: Self = Self::new(0x0000012A);
    #[doc(alias = "TPM_CC_PCR_Allocate")]
    pub const PCRAllocate: Self = Self::new(0x0000012B);
    #[doc(alias = "TPM_CC_PCR_SetAuthPolicy")]
    pub const PCRSetAuthPolicy: Self = Self::new(0x0000012C);
    #[doc(alias = "TPM_CC_PP_Commands")]
    pub const PPCommands: Self = Self::new(0x0000012D);
    #[doc(alias = "TPM_CC_SetPrimaryPolicy")]
    pub const SetPrimaryPolicy: Self = Self::new(0x0000012E);
    #[doc(alias = "TPM_CC_FieldUpgradeStart")]
    pub const FieldUpgradeStart: Self = Self::new(0x0000012F);
    #[doc(alias = "TPM_CC_ClockRateAdjust")]
    pub const ClockRateAdjust: Self = Self::new(0x00000130);
    #[doc(alias = "TPM_CC_CreatePrimary")]
    pub const CreatePrimary: Self = Self::new(0x00000131);
    #[doc(alias = "TPM_CC_NV_GlobalWriteLock")]
    pub const NVGlobalWriteLock: Self = Self::new(0x00000132);
    #[doc(alias = "TPM_CC_GetCommandAuditDigest")]
    pub const GetCommandAuditDigest: Self = Self::new(0x00000133);
    #[doc(alias = "TPM_CC_NV_Increment")]
    pub const NVIncrement: Self = Self::new(0x00000134);
    #[doc(alias = "TPM_CC_NV_SetBits")]
    pub const NVSetBits: Self = Self::new(0x00000135);
    #[doc(alias = "TPM_CC_NV_Extend")]
    pub const NVExtend: Self = Self::new(0x00000136);
    #[doc(alias = "TPM_CC_NV_Write")]
    pub const NVWrite: Self = Self::new(0x00000137);
    #[doc(alias = "TPM_CC_NV_WriteLock")]
    pub const NVWriteLock: Self = Self::new(0x00000138);
    #[doc(alias = "TPM_CC_DictionaryAttackLockReset")]
    pub const DictionaryAttackLockReset: Self = Self::new(0x00000139);
    #[doc(alias = "TPM_CC_DictionaryAttackParameters")]
    pub const DictionaryAttackParameters: Self = Self::new(0x0000013A);
    #[doc(alias = "TPM_CC_NV_ChangeAuth")]
    pub const NVChangeAuth: Self = Self::new(0x0000013B);
    #[doc(alias = "TPM_CC_PCR_Event")]
    pub const PCREvent: Self = Self::new(0x0000013C);
    #[doc(alias = "TPM_CC_PCR_Reset")]
    pub const PCRReset: Self = Self::new(0x0000013D);
    #[doc(alias = "TPM_CC_SequenceComplete")]
    pub const SequenceComplete: Self = Self::new(0x0000013E);
    #[doc(alias = "TPM_CC_SetAlgorithmSet")]
    pub const SetAlgorithmSet: Self = Self::new(0x0000013F);
    #[doc(alias = "TPM_CC_SetCommandCodeAuditStatus")]
    pub const SetCommandCodeAuditStatus: Self = Self::new(0x00000140);
    #[doc(alias = "TPM_CC_FieldUpgradeData")]
    pub const FieldUpgradeData: Self = Self::new(0x00000141);
    #[doc(alias = "TPM_CC_IncrementalSelfTest")]
    pub const IncrementalSelfTest: Self = Self::new(0x00000142);
    #[doc(alias = "TPM_CC_SelfTest")]
    pub const SelfTest: Self = Self::new(0x00000143);
    #[doc(alias = "TPM_CC_Startup")]
    pub const Startup: Self = Self::new(0x00000144);
    #[doc(alias = "TPM_CC_Shutdown")]
    pub const Shutdown: Self = Self::new(0x00000145);
    #[doc(alias = "TPM_CC_StirRandom")]
    pub const StirRandom: Self = Self::new(0x00000146);
    #[doc(alias = "TPM_CC_ActivateCredential")]
    pub const ActivateCredential: Self = Self::new(0x00000147);
    #[doc(alias = "TPM_CC_Certify")]
    pub const Certify: Self = Self::new(0x00000148);
    #[doc(alias = "TPM_CC_PolicyNV")]
    pub const PolicyNV: Self = Self::new(0x00000149);
    #[doc(alias = "TPM_CC_CertifyCreation")]
    pub const CertifyCreation: Self = Self::new(0x0000014A);
    #[doc(alias = "TPM_CC_Duplicate")]
    pub const Duplicate: Self = Self::new(0x0000014B);
    #[doc(alias = "TPM_CC_GetTime")]
    pub const GetTime: Self = Self::new(0x0000014C);
    #[doc(alias = "TPM_CC_GetSessionAuditDigest")]
    pub const GetSessionAuditDigest: Self = Self::new(0x0000014D);
    #[doc(alias = "TPM_CC_NV_Read")]
    pub const NVRead: Self = Self::new(0x0000014E);
    #[doc(alias = "TPM_CC_NV_ReadLock")]
    pub const NVReadLock: Self = Self::new(0x0000014F);
    #[doc(alias = "TPM_CC_ObjectChangeAuth")]
    pub const ObjectChangeAuth: Self = Self::new(0x00000150);
    #[doc(alias = "TPM_CC_PolicySecret")]
    pub const PolicySecret: Self = Self::new(0x00000151);
    #[doc(alias = "TPM_CC_Rewrap")]
    pub const Rewrap: Self = Self::new(0x00000152);
    #[doc(alias = "TPM_CC_Create")]
    pub const Create: Self = Self::new(0x00000153);
    #[doc(alias = "TPM_CC_ECDH_ZGen")]
    pub const ECDHZGen: Self = Self::new(0x00000154);
    #[doc(alias = "TPM_CC_MAC")]
    pub const MAC: Self = Self::new(0x00000155);
    #[doc(alias = "TPM_CC_HMAC")]
    pub const Hmac: Self = Self::MAC;
    #[doc(alias = "TPM_CC_HMAC")]
    pub const HMAC: Self = Self::MAC;
    #[doc(alias = "TPM_CC_Import")]
    pub const Import: Self = Self::new(0x00000156);
    #[doc(alias = "TPM_CC_Load")]
    pub const Load: Self = Self::new(0x00000157);
    #[doc(alias = "TPM_CC_Quote")]
    pub const Quote: Self = Self::new(0x00000158);
    #[doc(alias = "TPM_CC_RSA_Decrypt")]
    pub const RSADecrypt: Self = Self::new(0x00000159);
    #[doc(alias = "TPM_CC_MAC_Start")]
    pub const MACStart: Self = Self::new(0x0000015B);
    #[doc(alias = "TPM_CC_HMAC_Start")]
    pub const HmacStart: Self = Self::MACStart;
    #[doc(alias = "TPM_CC_HMAC_Start")]
    pub const HMACStart: Self = Self::MACStart;
    #[doc(alias = "TPM_CC_SequenceUpdate")]
    pub const SequenceUpdate: Self = Self::new(0x0000015C);
    #[doc(alias = "TPM_CC_Sign")]
    pub const Sign: Self = Self::new(0x0000015D);
    #[doc(alias = "TPM_CC_Unseal")]
    pub const Unseal: Self = Self::new(0x0000015E);
    #[doc(alias = "TPM_CC_PolicySigned")]
    pub const PolicySigned: Self = Self::new(0x00000160);
    #[doc(alias = "TPM_CC_ContextLoad")]
    pub const ContextLoad: Self = Self::new(0x00000161);
    #[doc(alias = "TPM_CC_ContextSave")]
    pub const ContextSave: Self = Self::new(0x00000162);
    #[doc(alias = "TPM_CC_ECDH_KeyGen")]
    pub const ECDHKeyGen: Self = Self::new(0x00000163);
    #[doc(alias = "TPM_CC_EncryptDecrypt")]
    pub const EncryptDecrypt: Self = Self::new(0x00000164);
    #[doc(alias = "TPM_CC_FlushContext")]
    pub const FlushContext: Self = Self::new(0x00000165);
    #[doc(alias = "TPM_CC_LoadExternal")]
    pub const LoadExternal: Self = Self::new(0x00000167);
    #[doc(alias = "TPM_CC_MakeCredential")]
    pub const MakeCredential: Self = Self::new(0x00000168);
    #[doc(alias = "TPM_CC_NV_ReadPublic")]
    pub const NVReadPublic: Self = Self::new(0x00000169);
    #[doc(alias = "TPM_CC_PolicyAuthorize")]
    pub const PolicyAuthorize: Self = Self::new(0x0000016A);
    #[doc(alias = "TPM_CC_PolicyAuthValue")]
    pub const PolicyAuthValue: Self = Self::new(0x0000016B);
    #[doc(alias = "TPM_CC_PolicyCommandCode")]
    pub const PolicyCommandCode: Self = Self::new(0x0000016C);
    #[doc(alias = "TPM_CC_PolicyCounterTimer")]
    pub const PolicyCounterTimer: Self = Self::new(0x0000016D);
    #[doc(alias = "TPM_CC_PolicyCpHash")]
    pub const PolicyCpHash: Self = Self::new(0x0000016E);
    #[doc(alias = "TPM_CC_PolicyLocality")]
    pub const PolicyLocality: Self = Self::new(0x0000016F);
    #[doc(alias = "TPM_CC_PolicyNameHash")]
    pub const PolicyNameHash: Self = Self::new(0x00000170);
    #[doc(alias = "TPM_CC_PolicyOR")]
    pub const PolicyOR: Self = Self::new(0x00000171);
    #[doc(alias = "TPM_CC_PolicyTicket")]
    pub const PolicyTicket: Self = Self::new(0x00000172);
    #[doc(alias = "TPM_CC_ReadPublic")]
    pub const ReadPublic: Self = Self::new(0x00000173);
    #[doc(alias = "TPM_CC_RSA_Encrypt")]
    pub const RSAEncrypt: Self = Self::new(0x00000174);
    #[doc(alias = "TPM_CC_StartAuthSession")]
    pub const StartAuthSession: Self = Self::new(0x00000176);
    #[doc(alias = "TPM_CC_VerifySignature")]
    pub const VerifySignature: Self = Self::new(0x00000177);
    #[doc(alias = "TPM_CC_ECC_Parameters")]
    pub const ECCParameters: Self = Self::new(0x00000178);
    #[doc(alias = "TPM_CC_FirmwareRead")]
    pub const FirmwareRead: Self = Self::new(0x00000179);
    #[doc(alias = "TPM_CC_GetCapability")]
    pub const GetCapability: Self = Self::new(0x0000017A);
    #[doc(alias = "TPM_CC_GetRandom")]
    pub const GetRandom: Self = Self::new(0x0000017B);
    #[doc(alias = "TPM_CC_GetTestResult")]
    pub const GetTestResult: Self = Self::new(0x0000017C);
    #[doc(alias = "TPM_CC_Hash")]
    pub const Hash: Self = Self::new(0x0000017D);
    #[doc(alias = "TPM_CC_PCR_Read")]
    pub const PCRRead: Self = Self::new(0x0000017E);
    #[doc(alias = "TPM_CC_PolicyPCR")]
    pub const PolicyPCR: Self = Self::new(0x0000017F);
    #[doc(alias = "TPM_CC_PolicyRestart")]
    pub const PolicyRestart: Self = Self::new(0x00000180);
    #[doc(alias = "TPM_CC_ReadClock")]
    pub const ReadClock: Self = Self::new(0x00000181);
    #[doc(alias = "TPM_CC_PCR_Extend")]
    pub const PCRExtend: Self = Self::new(0x00000182);
    #[doc(alias = "TPM_CC_PCR_SetAuthValue")]
    pub const PCRSetAuthValue: Self = Self::new(0x00000183);
    #[doc(alias = "TPM_CC_NV_Certify")]
    pub const NVCertify: Self = Self::new(0x00000184);
    #[doc(alias = "TPM_CC_EventSequenceComplete")]
    pub const EventSequenceComplete: Self = Self::new(0x00000185);
    #[doc(alias = "TPM_CC_HashSequenceStart")]
    pub const HashSequenceStart: Self = Self::new(0x00000186);
    #[doc(alias = "TPM_CC_PolicyPhysicalPresence")]
    pub const PolicyPhysicalPresence: Self = Self::new(0x00000187);
    #[doc(alias = "TPM_CC_PolicyDuplicationSelect")]
    pub const PolicyDuplicationSelect: Self = Self::new(0x00000188);
    #[doc(alias = "TPM_CC_PolicyGetDigest")]
    pub const PolicyGetDigest: Self = Self::new(0x00000189);
    #[doc(alias = "TPM_CC_TestParms")]
    pub const TestParms: Self = Self::new(0x0000018A);
    #[doc(alias = "TPM_CC_Commit")]
    pub const Commit: Self = Self::new(0x0000018B);
    #[doc(alias = "TPM_CC_PolicyPassword")]
    pub const PolicyPassword: Self = Self::new(0x0000018C);
    #[doc(alias = "TPM_CC_ZGen_2Phase")]
    pub const ZGen2Phase: Self = Self::new(0x0000018D);
    #[doc(alias = "TPM_CC_EC_Ephemeral")]
    pub const ECEphemeral: Self = Self::new(0x0000018E);
    #[doc(alias = "TPM_CC_PolicyNvWritten")]
    pub const PolicyNvWritten: Self = Self::new(0x0000018F);
    #[doc(alias = "TPM_CC_PolicyTemplate")]
    pub const PolicyTemplate: Self = Self::new(0x00000190);
    #[doc(alias = "TPM_CC_CreateLoaded")]
    pub const CreateLoaded: Self = Self::new(0x00000191);
    #[doc(alias = "TPM_CC_PolicyAuthorizeNV")]
    pub const PolicyAuthorizeNV: Self = Self::new(0x00000192);
    #[doc(alias = "TPM_CC_EncryptDecrypt2")]
    pub const EncryptDecrypt2: Self = Self::new(0x00000193);
    #[doc(alias = "TPM_CC_AC_GetCapability")]
    pub const ACGetCapability: Self = Self::new(0x00000194);
    #[doc(alias = "TPM_CC_AC_Send")]
    pub const ACSend: Self = Self::new(0x00000195);
    #[doc(alias = "TPM_CC_Policy_AC_SendSelect")]
    pub const PolicyACSendSelect: Self = Self::new(0x00000196);
    #[doc(alias = "TPM_CC_CertifyX509")]
    pub const CertifyX509: Self = Self::new(0x00000197);
    #[doc(alias = "TPM_CC_ACT_SetTimeout")]
    pub const ACTSetTimeout: Self = Self::new(0x00000198);
    #[doc(alias = "TPM_CC_ECC_Encrypt")]
    pub const ECCEncrypt: Self = Self::new(0x00000199);
    #[doc(alias = "TPM_CC_ECC_Decrypt")]
    pub const ECCDecrypt: Self = Self::new(0x0000019A);
    #[doc(alias = "TPM_CC_PolicyCapability")]
    pub const PolicyCapability: Self = Self::new(0x0000019B);
    #[doc(alias = "TPM_CC_PolicyParameters")]
    pub const PolicyParameters: Self = Self::new(0x0000019C);
    #[doc(alias = "TPM_CC_NV_DefineSpace2")]
    pub const NVDefineSpace2: Self = Self::new(0x0000019D);
    #[doc(alias = "TPM_CC_NV_ReadPublic2")]
    pub const NVReadPublic2: Self = Self::new(0x0000019E);
    #[doc(alias = "TPM_CC_SetCapability")]
    pub const SetCapability: Self = Self::new(0x0000019F);
    #[doc(alias = "TPM_CC_ReadOnlyControl")]
    pub const ReadOnlyControl: Self = Self::new(0x000001A0);
    #[doc(alias = "TPM_CC_PolicyTransportSPDM")]
    pub const PolicyTransportSPDM: Self = Self::new(0x000001A1);
    #[doc(alias = "TPM_CC_VerifySequenceComplete")]
    pub const VerifySequenceComplete: Self = Self::new(0x000001A3);
    #[doc(alias = "TPM_CC_SignSequenceComplete")]
    pub const SignSequenceComplete: Self = Self::new(0x000001A4);
    #[doc(alias = "TPM_CC_VerifyDigestSignature")]
    pub const VerifyDigestSignature: Self = Self::new(0x000001A5);
    #[doc(alias = "TPM_CC_SignDigest")]
    pub const SignDigest: Self = Self::new(0x000001A6);
    #[doc(alias = "TPM_CC_Encapsulate")]
    pub const Encapsulate: Self = Self::new(0x000001A7);
    #[doc(alias = "TPM_CC_Decapsulate")]
    pub const Decapsulate: Self = Self::new(0x000001A8);
    #[doc(alias = "TPM_CC_VerifySequenceStart")]
    pub const VerifySequenceStart: Self = Self::new(0x000001A9);
    #[doc(alias = "TPM_CC_SignSequenceStart")]
    pub const SignSequenceStart: Self = Self::new(0x000001AA);

    /// Last command code defined in the TPM 2.0 specification (`0x000001AA`).
    #[doc(alias = "TPM_CC_LAST")]
    pub const LAST: Self = Self::SignSequenceStart;

    /// Base indicator for vendor-specific command codes (`0x20000000`).
    #[doc(alias = "CC_VEND")]
    pub const VEND: Self = Self::new(0x20000000);
    #[doc(alias = "TPM_CC_Vendor_TCG_Test")]
    pub const VendorTcgTest: Self = Self::new(Self::VEND.code());
}

impl From<u32> for TpmCc {
    fn from(val: u32) -> Self {
        Self::new(val)
    }
}
impl From<TpmCc> for u32 {
    fn from(val: TpmCc) -> Self {
        val.code()
    }
}

impl Marshal for TpmCc {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmCc {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Unmarshal::unmarshal(src).map(Self)
    }
}

impl fmt::Debug for TpmCc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TPM_CC(0x{:08X})", self.code())
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmEo {
    #[default]
    #[doc(alias = "TPM_EO_EQ")]
    Eq = 0x0000,
    #[doc(alias = "TPM_EO_NEQ")]
    Neq = 0x0001,
    #[doc(alias = "TPM_EO_SIGNED_GT")]
    SignedGT = 0x0002,
    #[doc(alias = "TPM_EO_UNSIGNED_GT")]
    UnsignedGT = 0x0003,
    #[doc(alias = "TPM_EO_SIGNED_LT")]
    SignedLT = 0x0004,
    #[doc(alias = "TPM_EO_UNSIGNED_LT")]
    UnsignedLT = 0x0005,
    #[doc(alias = "TPM_EO_SIGNED_GE")]
    SignedGE = 0x0006,
    #[doc(alias = "TPM_EO_UNSIGNED_GE")]
    UnsignedGE = 0x0007,
    #[doc(alias = "TPM_EO_SIGNED_LE")]
    SignedLE = 0x0008,
    #[doc(alias = "TPM_EO_UNSIGNED_LE")]
    UnsignedLE = 0x0009,
    #[doc(alias = "TPM_EO_BITSET")]
    BitSet = 0x000A,
    #[doc(alias = "TPM_EO_BITCLEAR")]
    BitClear = 0x000B,
}

impl TryFrom<u16> for TpmEo {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0000 => Ok(Self::Eq),
            0x0001 => Ok(Self::Neq),
            0x0002 => Ok(Self::SignedGT),
            0x0003 => Ok(Self::UnsignedGT),
            0x0004 => Ok(Self::SignedLT),
            0x0005 => Ok(Self::UnsignedLT),
            0x0006 => Ok(Self::SignedGE),
            0x0007 => Ok(Self::UnsignedGE),
            0x0008 => Ok(Self::SignedLE),
            0x0009 => Ok(Self::UnsignedLE),
            0x000A => Ok(Self::BitSet),
            0x000B => Ok(Self::BitClear),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}
impl From<TpmEo> for u16 {
    fn from(val: TpmEo) -> Self {
        val as u16
    }
}

impl Marshal for TpmEo {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        u16::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmEo {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u16::unmarshal(src)?.try_into()
    }
}

/// `TPM_ST` (Structure Tag) defined in TPM 2.0 Part 2: Structures, Section 6.9 (Table 15).
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TpmSt(BeU16);

impl TpmSt {
    /// Creates a new [`TpmSt`] from raw 16-bit structure tag numerical value.
    pub const fn new(id: u16) -> Self {
        Self(BeU16::new(id))
    }
    /// Returns the raw 16-bit structure tag.
    pub const fn id(self) -> u16 {
        self.0.get()
    }
    /// Big-endian tag value to use in `Tpmt*` types
    pub(crate) const fn tag(self) -> u16 {
        self.0.tag()
    }

    #[doc(alias = "TPM_ST_RSP_COMMAND")]
    pub const RSP_COMMAND: Self = Self::new(0x00C4);
    #[doc(alias = "TPM_ST_NULL")]
    pub const NULL: Self = Self::new(0x8000);
    #[doc(alias = "TPM_ST_NO_SESSIONS")]
    pub const NO_SESSIONS: Self = Self::new(0x8001);
    #[doc(alias = "TPM_ST_SESSIONS")]
    pub const SESSIONS: Self = Self::new(0x8002);
    #[doc(alias = "TPM_ST_ATTEST_NV")]
    pub const ATTEST_NV: Self = Self::new(0x8014);
    #[doc(alias = "TPM_ST_ATTEST_COMMAND_AUDIT")]
    pub const ATTEST_COMMAND_AUDIT: Self = Self::new(0x8015);
    #[doc(alias = "TPM_ST_ATTEST_SESSION_AUDIT")]
    pub const ATTEST_SESSION_AUDIT: Self = Self::new(0x8016);
    #[doc(alias = "TPM_ST_ATTEST_CERTIFY")]
    pub const ATTEST_CERTIFY: Self = Self::new(0x8017);
    #[doc(alias = "TPM_ST_ATTEST_QUOTE")]
    pub const ATTEST_QUOTE: Self = Self::new(0x8018);
    #[doc(alias = "TPM_ST_ATTEST_TIME")]
    pub const ATTEST_TIME: Self = Self::new(0x8019);
    #[doc(alias = "TPM_ST_ATTEST_CREATION")]
    pub const ATTEST_CREATION: Self = Self::new(0x801A);
    #[doc(alias = "TPM_ST_ATTEST_NV_DIGEST")]
    pub const ATTEST_NV_DIGEST: Self = Self::new(0x801C);
    #[doc(alias = "TPM_ST_CREATION")]
    pub const CREATION: Self = Self::new(0x8021);
    #[doc(alias = "TPM_ST_VERIFIED")]
    pub const VERIFIED: Self = Self::new(0x8022);
    #[doc(alias = "TPM_ST_AUTH_SECRET")]
    pub const AUTH_SECRET: Self = Self::new(0x8023);
    #[doc(alias = "TPM_ST_HASHCHECK")]
    pub const HASHCHECK: Self = Self::new(0x8024);
    #[doc(alias = "TPM_ST_AUTH_SIGNED")]
    pub const AUTH_SIGNED: Self = Self::new(0x8025);
    #[doc(alias = "TPM_ST_MESSAGE_VERIFIED")]
    pub const MESSAGE_VERIFIED: Self = Self::new(0x8026);
    #[doc(alias = "TPM_ST_DIGEST_VERIFIED")]
    pub const DIGEST_VERIFIED: Self = Self::new(0x8027);
    #[doc(alias = "TPM_ST_FU_MANIFEST")]
    pub const FU_MANIFEST: Self = Self::new(0x8029);
}

impl From<u16> for TpmSt {
    fn from(val: u16) -> Self {
        Self::new(val)
    }
}
impl From<TpmSt> for u16 {
    fn from(val: TpmSt) -> Self {
        val.id()
    }
}

impl Default for TpmSt {
    fn default() -> Self {
        Self::NULL
    }
}

impl Marshal for TpmSt {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmSt {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Unmarshal::unmarshal(src).map(Self)
    }
}

impl fmt::Debug for TpmSt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TPM_ST(0x{:04X})", self.id())
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmSu {
    #[default]
    #[doc(alias = "TPM_SU_CLEAR")]
    Clear = 0x0000,
    #[doc(alias = "TPM_SU_STATE")]
    State = 0x0001,
}

impl TryFrom<u16> for TpmSu {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0000 => Ok(Self::Clear),
            0x0001 => Ok(Self::State),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}
impl From<TpmSu> for u16 {
    fn from(val: TpmSu) -> Self {
        val as u16
    }
}

impl Marshal for TpmSu {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        u16::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmSu {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u16::unmarshal(src)?.try_into()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmSe {
    #[default]
    #[doc(alias = "TPM_SE_HMAC")]
    HMAC = 0x00,
    #[doc(alias = "TPM_SE_POLICY")]
    Policy = 0x01,
    #[doc(alias = "TPM_SE_TRIAL")]
    Trial = 0x03,
}

impl TryFrom<u8> for TpmSe {
    type Error = UnmarshalError;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x00 => Ok(Self::HMAC),
            0x01 => Ok(Self::Policy),
            0x03 => Ok(Self::Trial),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}
impl From<TpmSe> for u8 {
    fn from(val: TpmSe) -> Self {
        val as u8
    }
}

impl Marshal for TpmSe {
    const MAX_SIZE: usize = u8::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        u8::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmSe {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u8::unmarshal(src)?.try_into()
    }
}

/// `TPM_CAP` defined in TPM 2.0 Part 2: Structures, Section 6.12 (Table 22).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmCap {
    #[default]
    #[doc(alias = "TPM_CAP_ALGS")]
    Algs = 0x00000000,
    #[doc(alias = "TPM_CAP_HANDLES")]
    Handles = 0x00000001,
    #[doc(alias = "TPM_CAP_COMMANDS")]
    Commands = 0x00000002,
    #[doc(alias = "TPM_CAP_PP_COMMANDS")]
    PPCommands = 0x00000003,
    #[doc(alias = "TPM_CAP_AUDIT_COMMANDS")]
    AuditCommands = 0x00000004,
    #[doc(alias = "TPM_CAP_PCRS")]
    PCRs = 0x00000005,
    #[doc(alias = "TPM_CAP_TPM_PROPERTIES")]
    TPMProperties = 0x00000006,
    #[doc(alias = "TPM_CAP_PCR_PROPERTIES")]
    PCRProperties = 0x00000007,
    #[doc(alias = "TPM_CAP_ECC_CURVES")]
    ECCCurves = 0x00000008,
    #[doc(alias = "TPM_CAP_AUTH_POLICIES")]
    AuthPolicies = 0x00000009,
    #[doc(alias = "TPM_CAP_ACT")]
    ACT = 0x0000000A,
    #[doc(alias = "TPM_CAP_PUB_KEYS")]
    PubKeys = 0x0000000B,
    #[doc(alias = "TPM_CAP_SPDM_SESSION_INFO")]
    SpdmSessionInfo = 0x0000000C,
    #[doc(alias = "TPM_CAP_VENDOR_PROPERTY")]
    VendorProperty = 0x00000100,
}

impl TpmCap {
    /// First capability tag defined in the TPM 2.0 specification (`0x00000000`).
    #[doc(alias = "TPM_CAP_FIRST")]
    pub const FIRST: Self = Self::Algs;

    /// Last capability tag defined in the TPM 2.0 specification (`0x0000000C`).
    #[doc(alias = "TPM_CAP_LAST")]
    pub const LAST: Self = Self::SpdmSessionInfo;

    pub(crate) const fn tag(self) -> u32 {
        self as u32
    }
}

impl TryFrom<u32> for TpmCap {
    type Error = UnmarshalError;
    fn try_from(val: u32) -> Result<Self, Self::Error> {
        match val {
            0x00000000 => Ok(Self::Algs),
            0x00000001 => Ok(Self::Handles),
            0x00000002 => Ok(Self::Commands),
            0x00000003 => Ok(Self::PPCommands),
            0x00000004 => Ok(Self::AuditCommands),
            0x00000005 => Ok(Self::PCRs),
            0x00000006 => Ok(Self::TPMProperties),
            0x00000007 => Ok(Self::PCRProperties),
            0x00000008 => Ok(Self::ECCCurves),
            0x00000009 => Ok(Self::AuthPolicies),
            0x0000000A => Ok(Self::ACT),
            0x0000000B => Ok(Self::PubKeys),
            0x0000000C => Ok(Self::SpdmSessionInfo),
            0x00000100 => Ok(Self::VendorProperty),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}
impl From<TpmCap> for u32 {
    fn from(value: TpmCap) -> Self {
        value.tag()
    }
}

impl Marshal for TpmCap {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        u32::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmCap {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u32::unmarshal(src)?.try_into()
    }
}

/// `TPM_PT` (Property Tag) defined in TPM 2.0 Part 2: Structures, Section 6.13 (Table 25).
///
/// Modeled as an open 32-bit transparent newtype wrapper so that `TPM2_GetCapability`
/// can unmarshal arbitrary, reserved, vendor-specific, or future property tags without
/// failing with `TPM_RC_VALUE`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct TpmPt(pub u32);

impl TpmPt {
    /// Creates a new [`TpmPt`] from a raw 32-bit property tag value.
    pub const fn new(val: u32) -> Self {
        Self(val)
    }

    /// Returns the raw 32-bit property tag value.
    pub const fn tag(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit property tag value.
    pub const fn id(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit property tag value.
    pub const fn code(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit property tag value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit property tag value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    // Group constants
    /// Indicates no property type (`0x00000000`).
    #[doc(alias = "TPM_PT_NONE")]
    pub const NONE: Self = Self::new(0x00000000);

    /// The number of properties in each group (`0x00000100`).
    pub const PT_GROUP: Self = Self::new(0x00000100);

    /// The group of fixed properties returned as `TPMS_TAGGED_PROPERTY` (`PT_GROUP * 1` = `0x00000100`).
    pub const PT_FIXED: Self = Self::new(0x00000100);

    /// The group of variable properties returned as `TPMS_TAGGED_PROPERTY` (`PT_GROUP * 2` = `0x00000200`).
    pub const PT_VAR: Self = Self::new(0x00000200);

    // Fixed properties (PT_FIXED + offset)
    /// A 4-octet character string containing the TPM Family value ([`TPM_SPEC_FAMILY`]) (`PT_FIXED + 0`).
    #[doc(alias = "TPM_PT_FAMILY_INDICATOR")]
    pub const FAMILY_INDICATOR: Self = Self::new(0x00000100);

    /// The level of the specification ([`TPM_SPEC_LEVEL`]) (`PT_FIXED + 1`).
    #[doc(alias = "TPM_PT_LEVEL")]
    pub const LEVEL: Self = Self::new(0x00000101);

    /// The specification version ([`TPM_SPEC_VERSION`]) (`PT_FIXED + 2`).
    #[doc(alias = "TPM_PT_REVISION")]
    pub const REVISION: Self = Self::new(0x00000102);

    /// The errata version implemented by the TPM ([`TPM_SPEC_ERRATA`]) (`PT_FIXED + 3`).
    /// Prior to version 185, this property was called `TPM_PT_DAY_OF_YEAR` ([`TPM_SPEC_DAY_OF_YEAR`]).
    #[doc(alias = "TPM_PT_ERRATA")]
    pub const ERRATA: Self = Self::new(0x00000103);
    #[doc(alias = "TPM_PT_DAY_OF_YEAR")]
    pub const DAY_OF_YEAR: Self = Self::ERRATA;

    /// Specification year using the CE; shall be zero in v185+ ([`TPM_SPEC_YEAR`]) (`PT_FIXED + 4`).
    #[doc(alias = "TPM_PT_YEAR")]
    pub const YEAR: Self = Self::new(0x00000104);

    /// The vendor ID unique to each TPM manufacturer (`PT_FIXED + 5`).
    #[doc(alias = "TPM_PT_MANUFACTURER")]
    pub const MANUFACTURER: Self = Self::new(0x00000105);

    /// The first four characters of the vendor ID string (`PT_FIXED + 6`).
    #[doc(alias = "TPM_PT_VENDOR_STRING_1")]
    pub const VENDOR_STRING_1: Self = Self::new(0x00000106);

    /// The second four characters of the vendor ID string (`PT_FIXED + 7`).
    #[doc(alias = "TPM_PT_VENDOR_STRING_2")]
    pub const VENDOR_STRING_2: Self = Self::new(0x00000107);

    /// The third four characters of the vendor ID string (`PT_FIXED + 8`).
    #[doc(alias = "TPM_PT_VENDOR_STRING_3")]
    pub const VENDOR_STRING_3: Self = Self::new(0x00000108);

    /// The fourth four characters of the vendor ID string (`PT_FIXED + 9`).
    #[doc(alias = "TPM_PT_VENDOR_STRING_4")]
    pub const VENDOR_STRING_4: Self = Self::new(0x00000109);

    /// Vendor-defined value indicating the TPM model (`PT_FIXED + 10`).
    #[doc(alias = "TPM_PT_VENDOR_TPM_TYPE")]
    pub const VENDOR_TPM_TYPE: Self = Self::new(0x0000010A);

    /// The most-significant 32 bits of a TPM vendor-specific firmware version (`PT_FIXED + 11`).
    #[doc(alias = "TPM_PT_FIRMWARE_VERSION_1")]
    pub const FIRMWARE_VERSION_1: Self = Self::new(0x0000010B);

    /// The least-significant 32 bits of a TPM vendor-specific firmware version (`PT_FIXED + 12`).
    #[doc(alias = "TPM_PT_FIRMWARE_VERSION_2")]
    pub const FIRMWARE_VERSION_2: Self = Self::new(0x0000010C);

    /// The maximum size of a parameter (`TPM2B_MAX_BUFFER`) (`PT_FIXED + 13`).
    #[doc(alias = "TPM_PT_INPUT_BUFFER")]
    pub const INPUT_BUFFER: Self = Self::new(0x0000010D);

    /// The minimum number of transient objects that can be held in TPM RAM (`PT_FIXED + 14`).
    #[doc(alias = "TPM_PT_HR_TRANSIENT_MIN")]
    pub const HR_TRANSIENT_MIN: Self = Self::new(0x0000010E);

    /// The minimum number of persistent objects that can be held in TPM NV memory (`PT_FIXED + 15`).
    #[doc(alias = "TPM_PT_HR_PERSISTENT_MIN")]
    pub const HR_PERSISTENT_MIN: Self = Self::new(0x0000010F);

    /// The minimum number of authorization sessions that can be held in TPM RAM (`PT_FIXED + 16`).
    #[doc(alias = "TPM_PT_HR_LOADED_MIN")]
    pub const HR_LOADED_MIN: Self = Self::new(0x00000110);

    /// The number of authorization sessions that may be active at a time (`PT_FIXED + 17`).
    #[doc(alias = "TPM_PT_ACTIVE_SESSIONS_MAX")]
    pub const ACTIVE_SESSIONS_MAX: Self = Self::new(0x00000111);

    /// The number of PCR implemented (`PT_FIXED + 18`).
    #[doc(alias = "TPM_PT_PCR_COUNT")]
    pub const PCR_COUNT: Self = Self::new(0x00000112);

    /// The minimum number of octets in a `TPMS_PCR_SELECT.sizeOfSelect` (`PT_FIXED + 19`).
    #[doc(alias = "TPM_PT_PCR_SELECT_MIN")]
    pub const PCR_SELECT_MIN: Self = Self::new(0x00000113);

    /// The maximum allowed difference between `contextID` values of two saved session contexts (`PT_FIXED + 20`).
    #[doc(alias = "TPM_PT_CONTEXT_GAP_MAX")]
    pub const CONTEXT_GAP_MAX: Self = Self::new(0x00000114);

    /// The maximum number of NV Indexes allowed to have the `TPM_NT_COUNTER` attribute (`PT_FIXED + 22`).
    #[doc(alias = "TPM_PT_NV_COUNTERS_MAX")]
    pub const NV_COUNTERS_MAX: Self = Self::new(0x00000116);

    /// The maximum size of an NV Index data area (`PT_FIXED + 23`).
    #[doc(alias = "TPM_PT_NV_INDEX_MAX")]
    pub const NV_INDEX_MAX: Self = Self::new(0x00000117);

    /// A `TPMA_MEMORY` indicating the memory management method for the TPM (`PT_FIXED + 24`).
    #[doc(alias = "TPM_PT_MEMORY")]
    pub const MEMORY: Self = Self::new(0x00000118);

    /// Interval, in milliseconds, between updates to the copy of `TPMS_CLOCK_INFO.clock` in NV (`PT_FIXED + 25`).
    #[doc(alias = "TPM_PT_CLOCK_UPDATE")]
    pub const CLOCK_UPDATE: Self = Self::new(0x00000119);

    /// The algorithm used for the integrity HMAC on saved contexts (`PT_FIXED + 26`).
    #[doc(alias = "TPM_PT_CONTEXT_HASH")]
    pub const CONTEXT_HASH: Self = Self::new(0x0000011A);

    /// `TPM_ALG_ID`, the algorithm used for encryption of saved contexts (`PT_FIXED + 27`).
    #[doc(alias = "TPM_PT_CONTEXT_SYM")]
    pub const CONTEXT_SYM: Self = Self::new(0x0000011B);

    /// `TPM_KEY_BITS`, the size of the key used for encryption of saved contexts (`PT_FIXED + 28`).
    #[doc(alias = "TPM_PT_CONTEXT_SYM_SIZE")]
    pub const CONTEXT_SYM_SIZE: Self = Self::new(0x0000011C);

    /// The modulus - 1 of the count for NV update of an orderly counter (`PT_FIXED + 29`).
    #[doc(alias = "TPM_PT_ORDERLY_COUNT")]
    pub const ORDERLY_COUNT: Self = Self::new(0x0000011D);

    /// The maximum value for `commandSize` in a command (`PT_FIXED + 30`).
    #[doc(alias = "TPM_PT_MAX_COMMAND_SIZE")]
    pub const MAX_COMMAND_SIZE: Self = Self::new(0x0000011E);

    /// The maximum value for `responseSize` in a response (`PT_FIXED + 31`).
    #[doc(alias = "TPM_PT_MAX_RESPONSE_SIZE")]
    pub const MAX_RESPONSE_SIZE: Self = Self::new(0x0000011F);

    /// The maximum size of a digest that can be produced by the TPM (`PT_FIXED + 32`).
    #[doc(alias = "TPM_PT_MAX_DIGEST")]
    pub const MAX_DIGEST: Self = Self::new(0x00000120);

    /// The maximum size of an object context returned by `TPM2_ContextSave` (`PT_FIXED + 33`).
    #[doc(alias = "TPM_PT_MAX_OBJECT_CONTEXT")]
    pub const MAX_OBJECT_CONTEXT: Self = Self::new(0x00000121);

    /// The maximum size of a session context returned by `TPM2_ContextSave` (`PT_FIXED + 34`).
    #[doc(alias = "TPM_PT_MAX_SESSION_CONTEXT")]
    pub const MAX_SESSION_CONTEXT: Self = Self::new(0x00000122);

    /// Platform-specific family ([`TpmPs`] / `TPM_PS` value) (`PT_FIXED + 35`).
    #[doc(alias = "TPM_PT_PS_FAMILY_INDICATOR")]
    pub const PS_FAMILY_INDICATOR: Self = Self::new(0x00000123);

    /// The level of the platform-specific specification (`PT_FIXED + 36`).
    #[doc(alias = "TPM_PT_PS_LEVEL")]
    pub const PS_LEVEL: Self = Self::new(0x00000124);

    /// A platform-specific revision value (`PT_FIXED + 37`).
    #[doc(alias = "TPM_PT_PS_REVISION")]
    pub const PS_REVISION: Self = Self::new(0x00000125);

    /// The platform-specific TPM specification day of year using TCG calendar (`PT_FIXED + 38`).
    #[doc(alias = "TPM_PT_PS_DAY_OF_YEAR")]
    pub const PS_DAY_OF_YEAR: Self = Self::new(0x00000126);

    /// The platform-specific TPM specification year using the CE (`PT_FIXED + 39`).
    #[doc(alias = "TPM_PT_PS_YEAR")]
    pub const PS_YEAR: Self = Self::new(0x00000127);

    /// The number of split signing operations supported by the TPM (`PT_FIXED + 40`).
    #[doc(alias = "TPM_PT_SPLIT_MAX")]
    pub const SPLIT_MAX: Self = Self::new(0x00000128);

    /// Total number of commands implemented in the TPM (`PT_FIXED + 41`).
    #[doc(alias = "TPM_PT_TOTAL_COMMANDS")]
    pub const TOTAL_COMMANDS: Self = Self::new(0x00000129);

    /// Number of commands from the TPM library that are implemented (`PT_FIXED + 42`).
    #[doc(alias = "TPM_PT_LIBRARY_COMMANDS")]
    pub const LIBRARY_COMMANDS: Self = Self::new(0x0000012A);

    /// Number of vendor commands that are implemented (`PT_FIXED + 43`).
    #[doc(alias = "TPM_PT_VENDOR_COMMANDS")]
    pub const VENDOR_COMMANDS: Self = Self::new(0x0000012B);

    /// The maximum data size in one NV write, NV read, NV extend, or NV certify command (`PT_FIXED + 44`).
    #[doc(alias = "TPM_PT_NV_BUFFER_MAX")]
    pub const NV_BUFFER_MAX: Self = Self::new(0x0000012C);

    /// A `TPMA_MODES` value indicating that the TPM is designed for these modes (`PT_FIXED + 45`).
    #[doc(alias = "TPM_PT_MODES")]
    pub const MODES: Self = Self::new(0x0000012D);

    /// The maximum size of a `TPMS_CAPABILITY_DATA` structure returned in `TPM2_GetCapability()` (`PT_FIXED + 46`).
    #[doc(alias = "TPM_PT_MAX_CAP_BUFFER")]
    pub const MAX_CAP_BUFFER: Self = Self::new(0x0000012E);

    /// The TPM vendor-specific value indicating the SVN of the firmware (`PT_FIXED + 47`).
    #[doc(alias = "TPM_PT_FIRMWARE_SVN")]
    pub const FIRMWARE_SVN: Self = Self::new(0x0000012F);

    /// The TPM vendor-specific value indicating the maximum value that `TPM_PT_FIRMWARE_SVN` may take in the future (`PT_FIXED + 48`).
    #[doc(alias = "TPM_PT_FIRMWARE_MAX_SVN")]
    pub const FIRMWARE_MAX_SVN: Self = Self::new(0x00000130);

    /// A [`TpmaMlParameterSet`](crate::TpmaMlParameterSet) (`TPMA_ML_PARAMETER_SET`) indicating the supported parameter sets for ML-KEM and ML-DSA (`PT_FIXED + 49`).
    #[doc(alias = "TPM_PT_ML_PARAMETER_SETS")]
    pub const ML_PARAMETER_SETS: Self = Self::new(0x00000131);

    // Variable properties (PT_VAR + offset)
    /// `TPMA_PERMANENT` (`PT_VAR + 0`).
    #[doc(alias = "TPM_PT_PERMANENT")]
    pub const PERMANENT: Self = Self::new(0x00000200);

    /// `TPMA_STARTUP_CLEAR` (`PT_VAR + 1`).
    #[doc(alias = "TPM_PT_STARTUP_CLEAR")]
    pub const STARTUP_CLEAR: Self = Self::new(0x00000201);

    /// The number of NV Indexes currently defined (`PT_VAR + 2`).
    #[doc(alias = "TPM_PT_HR_NV_INDEX")]
    pub const HR_NV_INDEX: Self = Self::new(0x00000202);

    /// The number of authorization sessions currently loaded into TPM RAM (`PT_VAR + 3`).
    #[doc(alias = "TPM_PT_HR_LOADED")]
    pub const HR_LOADED: Self = Self::new(0x00000203);

    /// The number of additional authorization sessions that could be loaded into TPM RAM (`PT_VAR + 4`).
    #[doc(alias = "TPM_PT_HR_LOADED_AVAIL")]
    pub const HR_LOADED_AVAIL: Self = Self::new(0x00000204);

    /// The number of active authorization sessions currently being tracked by the TPM (`PT_VAR + 5`).
    #[doc(alias = "TPM_PT_HR_ACTIVE")]
    pub const HR_ACTIVE: Self = Self::new(0x00000205);

    /// The number of additional authorization sessions that could be created (`PT_VAR + 6`).
    #[doc(alias = "TPM_PT_HR_ACTIVE_AVAIL")]
    pub const HR_ACTIVE_AVAIL: Self = Self::new(0x00000206);

    /// Estimate of the number of additional transient objects that could be loaded into TPM RAM (`PT_VAR + 7`).
    #[doc(alias = "TPM_PT_HR_TRANSIENT_AVAIL")]
    pub const HR_TRANSIENT_AVAIL: Self = Self::new(0x00000207);

    /// The number of persistent objects currently loaded into TPM NV memory (`PT_VAR + 8`).
    #[doc(alias = "TPM_PT_HR_PERSISTENT")]
    pub const HR_PERSISTENT: Self = Self::new(0x00000208);

    /// The number of additional persistent objects that could be loaded into NV memory (`PT_VAR + 9`).
    #[doc(alias = "TPM_PT_HR_PERSISTENT_AVAIL")]
    pub const HR_PERSISTENT_AVAIL: Self = Self::new(0x00000209);

    /// The number of defined NV Indexes that have the `TPM_NT_COUNTER` attribute (`PT_VAR + 10`).
    #[doc(alias = "TPM_PT_NV_COUNTERS")]
    pub const NV_COUNTERS: Self = Self::new(0x0000020A);

    /// The number of additional NV Indexes that can be defined with `TPM_NT_COUNTER` and `TPMA_NV_ORDERLY` (`PT_VAR + 11`).
    #[doc(alias = "TPM_PT_NV_COUNTERS_AVAIL")]
    pub const NV_COUNTERS_AVAIL: Self = Self::new(0x0000020B);

    /// Code that limits the algorithms that may be used with the TPM (`PT_VAR + 12`).
    #[doc(alias = "TPM_PT_ALGORITHM_SET")]
    pub const ALGORITHM_SET: Self = Self::new(0x0000020C);

    /// The number of loaded ECC curves (`PT_VAR + 13`).
    #[doc(alias = "TPM_PT_LOADED_CURVES")]
    pub const LOADED_CURVES: Self = Self::new(0x0000020D);

    /// The current value of the lockout counter (`failedTries`) (`PT_VAR + 14`).
    #[doc(alias = "TPM_PT_LOCKOUT_COUNTER")]
    pub const LOCKOUT_COUNTER: Self = Self::new(0x0000020E);

    /// The number of authorization failures before DA lockout is invoked (`PT_VAR + 15`).
    #[doc(alias = "TPM_PT_MAX_AUTH_FAIL")]
    pub const MAX_AUTH_FAIL: Self = Self::new(0x0000020F);

    /// The number of seconds before `TPM_PT_LOCKOUT_COUNTER` is decremented (`PT_VAR + 16`).
    #[doc(alias = "TPM_PT_LOCKOUT_INTERVAL")]
    pub const LOCKOUT_INTERVAL: Self = Self::new(0x00000210);

    /// The number of seconds after a `lockoutAuth` failure before use of `lockoutAuth` may be attempted again (`PT_VAR + 17`).
    #[doc(alias = "TPM_PT_LOCKOUT_RECOVERY")]
    pub const LOCKOUT_RECOVERY: Self = Self::new(0x00000211);

    /// Number of milliseconds before the TPM will accept another command that will modify NV (`PT_VAR + 18`).
    #[doc(alias = "TPM_PT_NV_WRITE_RECOVERY")]
    pub const NV_WRITE_RECOVERY: Self = Self::new(0x00000212);

    /// The high-order 32 bits of the command audit counter (`PT_VAR + 19`).
    #[doc(alias = "TPM_PT_AUDIT_COUNTER_0")]
    pub const AUDIT_COUNTER_0: Self = Self::new(0x00000213);

    /// The low-order 32 bits of the command audit counter (`PT_VAR + 20`).
    #[doc(alias = "TPM_PT_AUDIT_COUNTER_1")]
    pub const AUDIT_COUNTER_1: Self = Self::new(0x00000214);
}

impl From<u32> for TpmPt {
    fn from(val: u32) -> Self {
        Self::new(val)
    }
}
impl From<TpmPt> for u32 {
    fn from(val: TpmPt) -> Self {
        val.0
    }
}

impl Marshal for TpmPt {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        self.0.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmPt {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u32::unmarshal(src).map(Self::new)
    }
}

impl core::fmt::Debug for TpmPt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::NONE => write!(f, "TpmPt::NONE"),
            Self::FAMILY_INDICATOR => write!(f, "TpmPt::FAMILY_INDICATOR"),
            Self::LEVEL => write!(f, "TpmPt::LEVEL"),
            Self::REVISION => write!(f, "TpmPt::REVISION"),
            Self::ERRATA => write!(f, "TpmPt::ERRATA"),
            Self::YEAR => write!(f, "TpmPt::YEAR"),
            Self::MANUFACTURER => write!(f, "TpmPt::MANUFACTURER"),
            Self::VENDOR_STRING_1 => write!(f, "TpmPt::VENDOR_STRING_1"),
            Self::VENDOR_STRING_2 => write!(f, "TpmPt::VENDOR_STRING_2"),
            Self::VENDOR_STRING_3 => write!(f, "TpmPt::VENDOR_STRING_3"),
            Self::VENDOR_STRING_4 => write!(f, "TpmPt::VENDOR_STRING_4"),
            Self::VENDOR_TPM_TYPE => write!(f, "TpmPt::VENDOR_TPM_TYPE"),
            Self::FIRMWARE_VERSION_1 => write!(f, "TpmPt::FIRMWARE_VERSION_1"),
            Self::FIRMWARE_VERSION_2 => write!(f, "TpmPt::FIRMWARE_VERSION_2"),
            Self::INPUT_BUFFER => write!(f, "TpmPt::INPUT_BUFFER"),
            Self::HR_TRANSIENT_MIN => write!(f, "TpmPt::HR_TRANSIENT_MIN"),
            Self::HR_PERSISTENT_MIN => write!(f, "TpmPt::HR_PERSISTENT_MIN"),
            Self::HR_LOADED_MIN => write!(f, "TpmPt::HR_LOADED_MIN"),
            Self::ACTIVE_SESSIONS_MAX => write!(f, "TpmPt::ACTIVE_SESSIONS_MAX"),
            Self::PCR_COUNT => write!(f, "TpmPt::PCR_COUNT"),
            Self::PCR_SELECT_MIN => write!(f, "TpmPt::PCR_SELECT_MIN"),
            Self::CONTEXT_GAP_MAX => write!(f, "TpmPt::CONTEXT_GAP_MAX"),
            Self::NV_COUNTERS_MAX => write!(f, "TpmPt::NV_COUNTERS_MAX"),
            Self::NV_INDEX_MAX => write!(f, "TpmPt::NV_INDEX_MAX"),
            Self::MEMORY => write!(f, "TpmPt::MEMORY"),
            Self::CLOCK_UPDATE => write!(f, "TpmPt::CLOCK_UPDATE"),
            Self::CONTEXT_HASH => write!(f, "TpmPt::CONTEXT_HASH"),
            Self::CONTEXT_SYM => write!(f, "TpmPt::CONTEXT_SYM"),
            Self::CONTEXT_SYM_SIZE => write!(f, "TpmPt::CONTEXT_SYM_SIZE"),
            Self::ORDERLY_COUNT => write!(f, "TpmPt::ORDERLY_COUNT"),
            Self::MAX_COMMAND_SIZE => write!(f, "TpmPt::MAX_COMMAND_SIZE"),
            Self::MAX_RESPONSE_SIZE => write!(f, "TpmPt::MAX_RESPONSE_SIZE"),
            Self::MAX_DIGEST => write!(f, "TpmPt::MAX_DIGEST"),
            Self::MAX_OBJECT_CONTEXT => write!(f, "TpmPt::MAX_OBJECT_CONTEXT"),
            Self::MAX_SESSION_CONTEXT => write!(f, "TpmPt::MAX_SESSION_CONTEXT"),
            Self::PS_FAMILY_INDICATOR => write!(f, "TpmPt::PS_FAMILY_INDICATOR"),
            Self::PS_LEVEL => write!(f, "TpmPt::PS_LEVEL"),
            Self::PS_REVISION => write!(f, "TpmPt::PS_REVISION"),
            Self::PS_DAY_OF_YEAR => write!(f, "TpmPt::PS_DAY_OF_YEAR"),
            Self::PS_YEAR => write!(f, "TpmPt::PS_YEAR"),
            Self::SPLIT_MAX => write!(f, "TpmPt::SPLIT_MAX"),
            Self::TOTAL_COMMANDS => write!(f, "TpmPt::TOTAL_COMMANDS"),
            Self::LIBRARY_COMMANDS => write!(f, "TpmPt::LIBRARY_COMMANDS"),
            Self::VENDOR_COMMANDS => write!(f, "TpmPt::VENDOR_COMMANDS"),
            Self::NV_BUFFER_MAX => write!(f, "TpmPt::NV_BUFFER_MAX"),
            Self::MODES => write!(f, "TpmPt::MODES"),
            Self::MAX_CAP_BUFFER => write!(f, "TpmPt::MAX_CAP_BUFFER"),
            Self::FIRMWARE_SVN => write!(f, "TpmPt::FIRMWARE_SVN"),
            Self::FIRMWARE_MAX_SVN => write!(f, "TpmPt::FIRMWARE_MAX_SVN"),
            Self::ML_PARAMETER_SETS => write!(f, "TpmPt::ML_PARAMETER_SETS"),
            Self::PERMANENT => write!(f, "TpmPt::PERMANENT"),
            Self::STARTUP_CLEAR => write!(f, "TpmPt::STARTUP_CLEAR"),
            Self::HR_NV_INDEX => write!(f, "TpmPt::HR_NV_INDEX"),
            Self::HR_LOADED => write!(f, "TpmPt::HR_LOADED"),
            Self::HR_LOADED_AVAIL => write!(f, "TpmPt::HR_LOADED_AVAIL"),
            Self::HR_ACTIVE => write!(f, "TpmPt::HR_ACTIVE"),
            Self::HR_ACTIVE_AVAIL => write!(f, "TpmPt::HR_ACTIVE_AVAIL"),
            Self::HR_TRANSIENT_AVAIL => write!(f, "TpmPt::HR_TRANSIENT_AVAIL"),
            Self::HR_PERSISTENT => write!(f, "TpmPt::HR_PERSISTENT"),
            Self::HR_PERSISTENT_AVAIL => write!(f, "TpmPt::HR_PERSISTENT_AVAIL"),
            Self::NV_COUNTERS => write!(f, "TpmPt::NV_COUNTERS"),
            Self::NV_COUNTERS_AVAIL => write!(f, "TpmPt::NV_COUNTERS_AVAIL"),
            Self::ALGORITHM_SET => write!(f, "TpmPt::ALGORITHM_SET"),
            Self::LOADED_CURVES => write!(f, "TpmPt::LOADED_CURVES"),
            Self::LOCKOUT_COUNTER => write!(f, "TpmPt::LOCKOUT_COUNTER"),
            Self::MAX_AUTH_FAIL => write!(f, "TpmPt::MAX_AUTH_FAIL"),
            Self::LOCKOUT_INTERVAL => write!(f, "TpmPt::LOCKOUT_INTERVAL"),
            Self::LOCKOUT_RECOVERY => write!(f, "TpmPt::LOCKOUT_RECOVERY"),
            Self::NV_WRITE_RECOVERY => write!(f, "TpmPt::NV_WRITE_RECOVERY"),
            Self::AUDIT_COUNTER_0 => write!(f, "TpmPt::AUDIT_COUNTER_0"),
            Self::AUDIT_COUNTER_1 => write!(f, "TpmPt::AUDIT_COUNTER_1"),
            other => write!(f, "TpmPt(0x{:08X})", other.0),
        }
    }
}

/// `TPM_PT_PCR` (PCR Property Tag) defined in TPM 2.0 Part 2: Structures, Section 6.14 (Table 26).
///
/// Modeled as an open 32-bit transparent newtype wrapper so that `TPM2_GetCapability`
/// can unmarshal arbitrary, reserved, extended locality, platform-specific, or future
/// PCR property tags without failing with `TPM_RC_VALUE`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct TpmPtPcr(pub u32);

impl TpmPtPcr {
    /// Creates a new [`TpmPtPcr`] from a raw 32-bit PCR property tag value.
    pub const fn new(val: u32) -> Self {
        Self(val)
    }

    /// Returns the raw 32-bit PCR property tag value.
    pub const fn tag(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit PCR property tag value.
    pub const fn id(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit PCR property tag value.
    pub const fn code(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit PCR property tag value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit PCR property tag value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Bottom of the range of `TPM_PT_PCR` properties (`0x00000000`).
    #[doc(alias = "TPM_PT_PCR_FIRST")]
    pub const FIRST: Self = Self::new(0x00000000);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR is saved and restored by `TPM_SU_STATE` (`0x00000000`).
    #[doc(alias = "TPM_PT_PCR_SAVE")]
    pub const SAVE: Self = Self::new(0x00000000);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR may be extended from locality 0 (`0x00000001`).
    #[doc(alias = "TPM_PT_PCR_EXTEND_L0")]
    pub const EXTEND_L0: Self = Self::new(0x00000001);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR may be reset by `TPM2_PCR_Reset()` from locality 0 (`0x00000002`).
    #[doc(alias = "TPM_PT_PCR_RESET_L0")]
    pub const RESET_L0: Self = Self::new(0x00000002);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR may be extended from locality 1 (`0x00000003`).
    #[doc(alias = "TPM_PT_PCR_EXTEND_L1")]
    pub const EXTEND_L1: Self = Self::new(0x00000003);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR may be reset by `TPM2_PCR_Reset()` from locality 1 (`0x00000004`).
    #[doc(alias = "TPM_PT_PCR_RESET_L1")]
    pub const RESET_L1: Self = Self::new(0x00000004);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR may be extended from locality 2 (`0x00000005`).
    #[doc(alias = "TPM_PT_PCR_EXTEND_L2")]
    pub const EXTEND_L2: Self = Self::new(0x00000005);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR may be reset by `TPM2_PCR_Reset()` from locality 2 (`0x00000006`).
    #[doc(alias = "TPM_PT_PCR_RESET_L2")]
    pub const RESET_L2: Self = Self::new(0x00000006);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR may be extended from locality 3 (`0x00000007`).
    #[doc(alias = "TPM_PT_PCR_EXTEND_L3")]
    pub const EXTEND_L3: Self = Self::new(0x00000007);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR may be reset by `TPM2_PCR_Reset()` from locality 3 (`0x00000008`).
    #[doc(alias = "TPM_PT_PCR_RESET_L3")]
    pub const RESET_L3: Self = Self::new(0x00000008);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR may be extended from locality 4 (`0x00000009`).
    #[doc(alias = "TPM_PT_PCR_EXTEND_L4")]
    pub const EXTEND_L4: Self = Self::new(0x00000009);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR may be reset by `TPM2_PCR_Reset()` from locality 4 (`0x0000000A`).
    #[doc(alias = "TPM_PT_PCR_RESET_L4")]
    pub const RESET_L4: Self = Self::new(0x0000000A);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that modifications to this PCR will not increment `pcrUpdateCounter` (`0x00000011`).
    #[doc(alias = "TPM_PT_PCR_NO_INCREMENT")]
    pub const NO_INCREMENT: Self = Self::new(0x00000011);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR is reset by a D-RTM event (`0x00000012`).
    #[doc(alias = "TPM_PT_PCR_DRTM_RESET")]
    pub const DRTM_RESET: Self = Self::new(0x00000012);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR is controlled by policy (`0x00000013`).
    #[doc(alias = "TPM_PT_PCR_POLICY")]
    pub const POLICY: Self = Self::new(0x00000013);

    /// A SET bit in the `TPMS_PCR_SELECT` indicates that the PCR is controlled by an authorization value (`0x00000014`).
    #[doc(alias = "TPM_PT_PCR_AUTH")]
    pub const AUTH: Self = Self::new(0x00000014);

    /// Top of the range of `TPM_PT_PCR` properties of the reference implementation (`0x00000014`).
    #[doc(alias = "TPM_PT_PCR_LAST")]
    pub const LAST: Self = Self::new(0x00000014);
}

impl From<u32> for TpmPtPcr {
    fn from(val: u32) -> Self {
        Self::new(val)
    }
}
impl From<TpmPtPcr> for u32 {
    fn from(val: TpmPtPcr) -> Self {
        val.0
    }
}

impl Marshal for TpmPtPcr {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        self.0.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmPtPcr {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u32::unmarshal(src).map(Self::new)
    }
}

impl core::fmt::Debug for TpmPtPcr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::SAVE => write!(f, "TpmPtPcr::SAVE"),
            Self::EXTEND_L0 => write!(f, "TpmPtPcr::EXTEND_L0"),
            Self::RESET_L0 => write!(f, "TpmPtPcr::RESET_L0"),
            Self::EXTEND_L1 => write!(f, "TpmPtPcr::EXTEND_L1"),
            Self::RESET_L1 => write!(f, "TpmPtPcr::RESET_L1"),
            Self::EXTEND_L2 => write!(f, "TpmPtPcr::EXTEND_L2"),
            Self::RESET_L2 => write!(f, "TpmPtPcr::RESET_L2"),
            Self::EXTEND_L3 => write!(f, "TpmPtPcr::EXTEND_L3"),
            Self::RESET_L3 => write!(f, "TpmPtPcr::RESET_L3"),
            Self::EXTEND_L4 => write!(f, "TpmPtPcr::EXTEND_L4"),
            Self::RESET_L4 => write!(f, "TpmPtPcr::RESET_L4"),
            Self::NO_INCREMENT => write!(f, "TpmPtPcr::NO_INCREMENT"),
            Self::DRTM_RESET => write!(f, "TpmPtPcr::DRTM_RESET"),
            Self::POLICY => write!(f, "TpmPtPcr::POLICY"),
            Self::AUTH => write!(f, "TpmPtPcr::AUTH"),
            other => write!(f, "TpmPtPcr(0x{:08X})", other.0),
        }
    }
}

/// TPM 2.0 Part 2 Section 6.15 Table 27: Definition of (UINT32) TPM_PS Constants
///
/// Platform-specific constants used for the [`TpmPt::PS_FAMILY_INDICATOR`] property.
#[doc(alias = "TPM_PS")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[repr(transparent)]
pub struct TpmPs(pub u32);

impl TpmPs {
    /// Creates a new [`TpmPs`] from a raw 32-bit platform-specific constant value.
    pub const fn new(val: u32) -> Self {
        Self(val)
    }

    /// Returns the raw 32-bit `TPM_PS` value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_PS` value.
    pub const fn id(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_PS` value.
    pub const fn code(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_PS` value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Not platform specific (`0x00000000`).
    #[doc(alias = "TPM_PS_MAIN")]
    pub const MAIN: Self = Self(0x00000000);

    /// PC Client (`0x00000001`).
    #[doc(alias = "TPM_PS_PC")]
    pub const PC: Self = Self(0x00000001);

    /// PDA (includes all mobile devices that are not specifically cell phones) (`0x00000002`).
    #[doc(alias = "TPM_PS_PDA")]
    pub const PDA: Self = Self(0x00000002);

    /// Cell Phone (`0x00000003`).
    #[doc(alias = "TPM_PS_CELL_PHONE")]
    pub const CELL_PHONE: Self = Self(0x00000003);

    /// Server WG (`0x00000004`).
    #[doc(alias = "TPM_PS_SERVER")]
    pub const SERVER: Self = Self(0x00000004);

    /// Peripheral WG (`0x00000005`).
    #[doc(alias = "TPM_PS_PERIPHERAL")]
    pub const PERIPHERAL: Self = Self(0x00000005);

    /// TSS WG (deprecated) (`0x00000006`).
    #[doc(alias = "TPM_PS_TSS")]
    pub const TSS: Self = Self(0x00000006);

    /// Storage WG (`0x00000007`).
    #[doc(alias = "TPM_PS_STORAGE")]
    pub const STORAGE: Self = Self(0x00000007);

    /// Authentication WG (`0x00000008`).
    #[doc(alias = "TPM_PS_AUTHENTICATION")]
    pub const AUTHENTICATION: Self = Self(0x00000008);

    /// Embedded WG (`0x00000009`).
    #[doc(alias = "TPM_PS_EMBEDDED")]
    pub const EMBEDDED: Self = Self(0x00000009);

    /// Hardcopy WG (`0x0000000A`).
    #[doc(alias = "TPM_PS_HARDCOPY")]
    pub const HARDCOPY: Self = Self(0x0000000A);

    /// Infrastructure WG (deprecated) (`0x0000000B`).
    #[doc(alias = "TPM_PS_INFRASTRUCTURE")]
    pub const INFRASTRUCTURE: Self = Self(0x0000000B);

    /// Virtualization WG (`0x0000000C`).
    #[doc(alias = "TPM_PS_VIRTUALIZATION")]
    pub const VIRTUALIZATION: Self = Self(0x0000000C);

    /// Trusted Network Connect WG (deprecated) (`0x0000000D`).
    #[doc(alias = "TPM_PS_TNC")]
    pub const TNC: Self = Self(0x0000000D);

    /// Multi-tenant WG (deprecated) (`0x0000000E`).
    #[doc(alias = "TPM_PS_MULTI_TENANT")]
    pub const MULTI_TENANT: Self = Self(0x0000000E);

    /// Technical Committee (deprecated) (`0x0000000F`).
    #[doc(alias = "TPM_PS_TC")]
    pub const TC: Self = Self(0x0000000F);
}

impl From<u32> for TpmPs {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<TpmPs> for u32 {
    fn from(val: TpmPs) -> Self {
        val.0
    }
}

impl Marshal for TpmPs {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmPs {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self(u32::unmarshal(src)?))
    }
}

/// TPM 2.0 Part 2 Section 6.16 Table 28: Definition of (UINT32) TPM_PUB_KEY Constants
///
/// Public key property constants used in `TPM2_GetCapability` (`capability == TpmCap::PubKeys`)
/// to indicate the public key to be returned.
#[doc(alias = "TPM_PUB_KEY")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[repr(transparent)]
pub struct TpmPubKey(pub u32);

impl TpmPubKey {
    /// Creates a new [`TpmPubKey`] from a raw 32-bit public key property constant value.
    pub const fn new(val: u32) -> Self {
        Self(val)
    }

    /// Returns the `TPM_PUB_KEY_TPM_SPDM_xx` property constant for the given SPDM key index (`0x00..=0xFF`).
    pub const fn tpm_spdm(index: u8) -> Self {
        Self(index as u32)
    }

    /// Returns `true` if this property constant falls within the `TPM_PUB_KEY_TPM_SPDM_00..=TPM_PUB_KEY_TPM_SPDM_FF` range.
    pub const fn is_tpm_spdm(self) -> bool {
        self.0 <= Self::TPM_SPDM_FF.0
    }

    /// Returns the raw 32-bit `TPM_PUB_KEY` value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_PUB_KEY` value.
    pub const fn id(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_PUB_KEY` value.
    pub const fn code(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_PUB_KEY` value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Start of the property range for TPM SPDM authentication public keys (`0x00000000`).
    #[doc(alias = "TPM_PUB_KEY_TPM_SPDM_00")]
    pub const TPM_SPDM_00: Self = Self(0x00000000);

    /// End of the property range for TPM SPDM authentication public keys (`0x000000FF`).
    #[doc(alias = "TPM_PUB_KEY_TPM_SPDM_FF")]
    pub const TPM_SPDM_FF: Self = Self(0x000000FF);

    /// Alias for [`Self::TPM_SPDM_00`].
    pub const SPDM_00: Self = Self::TPM_SPDM_00;

    /// Alias for [`Self::TPM_SPDM_FF`].
    pub const SPDM_FF: Self = Self::TPM_SPDM_FF;
}

impl From<u32> for TpmPubKey {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<TpmPubKey> for u32 {
    fn from(val: TpmPubKey) -> Self {
        val.0
    }
}

impl Marshal for TpmPubKey {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmPubKey {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self(u32::unmarshal(src)?))
    }
}

/// TPM 2.0 Part 2 Section 7.2 Table 28: Definition of (UINT8) TPM_HT Constants
///
/// Most significant octet (MSO) of a handle indicating the handle type.
///
/// Note: Handle prefix `0x02` represents both [`Self::HMACSession`] (for entity handles)
/// and [`Self::LOADED_SESSION`] (for `TPM2_GetCapability(TPM_CAP_HANDLES)` inquiries),
/// and `0x03` represents both [`Self::PolicySession`] (for entity handles) and
/// [`Self::SAVED_SESSION`] (for `TPM2_GetCapability(TPM_CAP_HANDLES)` inquiries),
/// per TPM 2.0 Part 2 Section 7.2 Table 28 and Part 3 Section 30.2.
#[doc(alias = "TPM_HT")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmHt {
    #[default]
    #[doc(alias = "TPM_HT_PCR")]
    PCR = 0x00,
    #[doc(alias = "TPM_HT_NV_INDEX")]
    NVIndex = 0x01,
    /// HMAC authorization session (`0x02`) when assigned to a session handle; also
    /// represents loaded authorization sessions ([`Self::LOADED_SESSION`]) in
    /// `TPM2_GetCapability(TPM_CAP_HANDLES)`.
    #[doc(alias = "TPM_HT_HMAC_SESSION")]
    #[doc(alias = "TPM_HT_LOADED_SESSION")]
    HMACSession = 0x02,
    /// Policy authorization session (`0x03`) when assigned to a session handle; also
    /// represents saved authorization sessions ([`Self::SAVED_SESSION`]) in
    /// `TPM2_GetCapability(TPM_CAP_HANDLES)`.
    #[doc(alias = "TPM_HT_POLICY_SESSION")]
    #[doc(alias = "TPM_HT_SAVED_SESSION")]
    PolicySession = 0x03,
    #[doc(alias = "TPM_HT_EXTERNAL_NV")]
    ExternalNv = 0x11,
    #[doc(alias = "TPM_HT_PERMANENT_NV")]
    PermanentNv = 0x12,
    #[doc(alias = "TPM_HT_PERMANENT")]
    Permanent = 0x40,
    #[doc(alias = "TPM_HT_TRANSIENT")]
    Transient = 0x80,
    #[doc(alias = "TPM_HT_PERSISTENT")]
    Persistent = 0x81,
    #[doc(alias = "TPM_HT_AC")]
    AC = 0x90,
}

impl TpmHt {
    /// Loaded Authorization Session (`0x02`) — used in `TPM2_GetCapability(TPM_CAP_HANDLES)`
    /// to query loaded sessions of type [`Self::HMACSession`] or [`Self::PolicySession`].
    ///
    /// Shares the numerical value `0x02` with [`Self::HMACSession`] per TPM 2.0 Part 2
    /// Section 7.2 Table 28.
    #[doc(alias = "TPM_HT_LOADED_SESSION")]
    pub const LOADED_SESSION: Self = Self::HMACSession;

    /// Alias for [`Self::LOADED_SESSION`].
    #[allow(non_upper_case_globals)]
    #[doc(alias = "TPM_HT_LOADED_SESSION")]
    pub const LoadedSession: Self = Self::HMACSession;

    /// Saved Authorization Session (`0x03`) — used in `TPM2_GetCapability(TPM_CAP_HANDLES)`
    /// to query saved session contexts of type [`Self::HMACSession`] or [`Self::PolicySession`]
    /// for which the TPM maintains tracking information.
    ///
    /// Shares the numerical value `0x03` with [`Self::PolicySession`] per TPM 2.0 Part 2
    /// Section 7.2 Table 28.
    #[doc(alias = "TPM_HT_SAVED_SESSION")]
    pub const SAVED_SESSION: Self = Self::PolicySession;

    /// Alias for [`Self::SAVED_SESSION`].
    #[allow(non_upper_case_globals)]
    #[doc(alias = "TPM_HT_SAVED_SESSION")]
    pub const SavedSession: Self = Self::PolicySession;

    /// HMAC Authorization Session (`0x02`).
    #[doc(alias = "TPM_HT_HMAC_SESSION")]
    pub const HMAC_SESSION: Self = Self::HMACSession;

    /// Policy Authorization Session (`0x03`).
    #[doc(alias = "TPM_HT_POLICY_SESSION")]
    pub const POLICY_SESSION: Self = Self::PolicySession;

    /// NV Index (`0x01`).
    #[doc(alias = "TPM_HT_NV_INDEX")]
    pub const NV_INDEX: Self = Self::NVIndex;

    /// External NV Index (`0x11`).
    #[doc(alias = "TPM_HT_EXTERNAL_NV")]
    pub const EXTERNAL_NV: Self = Self::ExternalNv;

    /// Permanent NV Index (`0x12`).
    #[doc(alias = "TPM_HT_PERMANENT_NV")]
    pub const PERMANENT_NV: Self = Self::PermanentNv;

    /// Permanent Values (`0x40`).
    #[doc(alias = "TPM_HT_PERMANENT")]
    pub const PERMANENT: Self = Self::Permanent;

    /// Transient Objects (`0x80`).
    #[doc(alias = "TPM_HT_TRANSIENT")]
    pub const TRANSIENT: Self = Self::Transient;

    /// Persistent Objects (`0x81`).
    #[doc(alias = "TPM_HT_PERSISTENT")]
    pub const PERSISTENT: Self = Self::Persistent;

    /// Returns the raw 8-bit `TPM_HT` value.
    pub const fn raw(self) -> u8 {
        self as u8
    }

    /// Returns the raw 8-bit `TPM_HT` value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for TpmHt {
    type Error = UnmarshalError;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x00 => Ok(Self::PCR),
            0x01 => Ok(Self::NVIndex),
            0x02 => Ok(Self::HMACSession),
            0x03 => Ok(Self::PolicySession),
            0x11 => Ok(Self::ExternalNv),
            0x12 => Ok(Self::PermanentNv),
            0x40 => Ok(Self::Permanent),
            0x80 => Ok(Self::Transient),
            0x81 => Ok(Self::Persistent),
            0x90 => Ok(Self::AC),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}
impl From<TpmHt> for u8 {
    fn from(val: TpmHt) -> Self {
        val as u8
    }
}

impl Marshal for TpmHt {
    const MAX_SIZE: usize = u8::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        u8::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmHt {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u8::unmarshal(src)?.try_into()
    }
}
/// TPM 2.0 Part 2 Section 10.12 Table 240: Definition of (UINT32) TPM_AT Constants
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TpmAt(pub u32);

impl TpmAt {
    #[doc(alias = "TPM_AT_ANY")]
    pub const ANY: Self = Self(0x00000000);
    #[doc(alias = "TPM_AT_ERROR")]
    pub const ERROR: Self = Self(0x00000001);
    #[doc(alias = "TPM_AT_PV1")]
    pub const PV1: Self = Self(0x00000002);
    #[doc(alias = "TPM_AT_VEND")]
    pub const VEND: Self = Self(0x80000000);
}

impl Marshal for TpmAt {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmAt {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self(u32::unmarshal(src)?))
    }
}

/// TPM 2.0 Part 2 Section 14.8 Table 241: Definition of (UINT32) TPM_AE Constants
///
/// TCG-defined error values returned by an Attached Component (AC).
#[doc(alias = "TPM_AE")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[repr(transparent)]
pub struct TpmAe(pub u32);

impl TpmAe {
    /// Creates a new [`TpmAe`] from a raw 32-bit Attached Component error constant value.
    pub const fn new(val: u32) -> Self {
        Self(val)
    }

    /// Returns the raw 32-bit `TPM_AE` value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_AE` value.
    pub const fn id(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_AE` value.
    pub const fn code(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_AE` value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// In a command, a non-specific request for AC information; in a response, indicates that `outputData` is not meaningful (`0x00000000`).
    #[doc(alias = "TPM_AE_NONE")]
    pub const NONE: Self = Self(0x00000000);
}

impl From<u32> for TpmAe {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<TpmAe> for u32 {
    fn from(val: TpmAe) -> Self {
        val.0
    }
}

impl Marshal for TpmAe {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmAe {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self(u32::unmarshal(src)?))
    }
}

/// TPM 2.0 Part 2 Section 7.5 Table 31: Definition of (TPM_HANDLE) TPM_HC Constants
///
/// Handle value constants and range delimiters used across interface data types and commands.
#[doc(alias = "TPM_HC")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[repr(transparent)]
pub struct TpmHc(pub u32);

impl TpmHc {
    /// Creates a new [`TpmHc`] from a raw 32-bit handle constant value.
    pub const fn new(val: u32) -> Self {
        Self(val)
    }

    /// Returns the raw 32-bit `TPM_HC` value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_HC` value.
    pub const fn id(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_HC` value.
    pub const fn code(self) -> u32 {
        self.0
    }

    /// Returns the raw 32-bit `TPM_HC` value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Converts this [`TpmHc`] constant into a [`Handle`].
    pub const fn as_handle(self) -> Handle {
        Handle(self.0)
    }

    /// Mask to isolate the variable 24-bit handle index (`0x00FF_FFFF`).
    pub const HR_HANDLE_MASK: Self = Self(0x00FF_FFFF);
    /// Mask to isolate the 8-bit handle range (`TPM_HT`) prefix (`0xFF00_0000`).
    pub const HR_RANGE_MASK: Self = Self(0xFF00_0000);
    /// Bit shift for the handle range (`TPM_HT`) prefix (`24`).
    pub const HR_SHIFT: Self = Self(24);
    /// Bit shift amount (`24`) as a `u32` for shift operations.
    pub const HR_SHIFT_BITS: u32 = 24;

    /// Base handle prefix for PCR handles (`TPM_HT_PCR << HR_SHIFT` = `0x0000_0000`).
    pub const HR_PCR: Self = Self((TpmHt::PCR as u32) << Self::HR_SHIFT_BITS);
    /// Base handle prefix for HMAC session handles (`TPM_HT_HMAC_SESSION << HR_SHIFT` = `0x0200_0000`).
    pub const HR_HMAC_SESSION: Self = Self((TpmHt::HMACSession as u32) << Self::HR_SHIFT_BITS);
    /// Base handle prefix for loaded session handles (`TPM_HT_LOADED_SESSION << HR_SHIFT` = `0x0200_0000`).
    pub const HR_LOADED_SESSION: Self = Self((TpmHt::LOADED_SESSION as u32) << Self::HR_SHIFT_BITS);
    /// Base handle prefix for policy session handles (`TPM_HT_POLICY_SESSION << HR_SHIFT` = `0x0300_0000`).
    pub const HR_POLICY_SESSION: Self = Self((TpmHt::PolicySession as u32) << Self::HR_SHIFT_BITS);
    /// Base handle prefix for saved session handles (`TPM_HT_SAVED_SESSION << HR_SHIFT` = `0x0300_0000`).
    pub const HR_SAVED_SESSION: Self = Self((TpmHt::SAVED_SESSION as u32) << Self::HR_SHIFT_BITS);
    /// Base handle prefix for transient object handles (`TPM_HT_TRANSIENT << HR_SHIFT` = `0x8000_0000`).
    pub const HR_TRANSIENT: Self = Self((TpmHt::Transient as u32) << Self::HR_SHIFT_BITS);
    /// Base handle prefix for persistent object handles (`TPM_HT_PERSISTENT << HR_SHIFT` = `0x8100_0000`).
    pub const HR_PERSISTENT: Self = Self((TpmHt::Persistent as u32) << Self::HR_SHIFT_BITS);
    /// Base handle prefix for NV Index handles (`TPM_HT_NV_INDEX << HR_SHIFT` = `0x0100_0000`).
    pub const HR_NV_INDEX: Self = Self((TpmHt::NVIndex as u32) << Self::HR_SHIFT_BITS);
    /// Base handle prefix for external NV Index handles (`TPM_HT_EXTERNAL_NV << HR_SHIFT` = `0x1100_0000`).
    pub const HR_EXTERNAL_NV: Self = Self((TpmHt::ExternalNv as u32) << Self::HR_SHIFT_BITS);
    /// Base handle prefix for permanent NV Index handles (`TPM_HT_PERMANENT_NV << HR_SHIFT` = `0x1200_0000`).
    pub const HR_PERMANENT_NV: Self = Self((TpmHt::PermanentNv as u32) << Self::HR_SHIFT_BITS);
    /// Base handle prefix for permanent handles (`TPM_HT_PERMANENT << HR_SHIFT` = `0x4000_0000`).
    pub const HR_PERMANENT: Self = Self((TpmHt::Permanent as u32) << Self::HR_SHIFT_BITS);

    /// First PCR handle (`0x0000_0000`).
    pub const PCR_FIRST: Self = Self(Self::HR_PCR.0);
    /// Last PCR handle (`PCR_FIRST + IMPLEMENTATION_PCR - 1` = `0x0000_0017`).
    pub const PCR_LAST: Self = Self(Self::PCR_FIRST.0 + TPM2_MAX_PCRS - 1);
    /// First HMAC session handle (`0x0200_0000`).
    pub const HMAC_SESSION_FIRST: Self = Self(Self::HR_HMAC_SESSION.0);
    /// Last HMAC session handle (`HMAC_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1` = `0x0200_003F`).
    pub const HMAC_SESSION_LAST: Self =
        Self(Self::HMAC_SESSION_FIRST.0 + TPM2_MAX_ACTIVE_SESSIONS - 1);
    /// First loaded session handle used in `TPM2_GetCapability` (`0x0200_0000`).
    pub const LOADED_SESSION_FIRST: Self = Self::HMAC_SESSION_FIRST;
    /// Last loaded session handle used in `TPM2_GetCapability` (`0x0200_003F`).
    pub const LOADED_SESSION_LAST: Self = Self::HMAC_SESSION_LAST;
    /// First policy session handle (`0x0300_0000`).
    pub const POLICY_SESSION_FIRST: Self = Self(Self::HR_POLICY_SESSION.0);
    /// Last policy session handle (`POLICY_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1` = `0x0300_003F`).
    pub const POLICY_SESSION_LAST: Self =
        Self(Self::POLICY_SESSION_FIRST.0 + TPM2_MAX_ACTIVE_SESSIONS - 1);
    /// First saved session handle used in `TPM2_GetCapability` (`0x0300_0000`).
    pub const SAVED_SESSION_FIRST: Self = Self::POLICY_SESSION_FIRST;
    /// Last saved session handle used in `TPM2_GetCapability` (`0x0300_003F`).
    pub const SAVED_SESSION_LAST: Self = Self::POLICY_SESSION_LAST;
    /// First transient object handle (`0x8000_0000`).
    pub const TRANSIENT_FIRST: Self = Self(Self::HR_TRANSIENT.0);
    /// First active session handle used in `TPM2_GetCapability` (`0x0300_0000`).
    pub const ACTIVE_SESSION_FIRST: Self = Self::POLICY_SESSION_FIRST;
    /// Last active session handle used in `TPM2_GetCapability` (`0x0300_003F`).
    pub const ACTIVE_SESSION_LAST: Self = Self::POLICY_SESSION_LAST;
    /// Last transient object handle (`TRANSIENT_FIRST + MAX_LOADED_OBJECTS - 1`).
    pub const TRANSIENT_LAST: Self = Self(Self::TRANSIENT_FIRST.0 + TPM2_MAX_LOADED_OBJECTS - 1);
    /// First persistent object handle (`0x8100_0000`).
    pub const PERSISTENT_FIRST: Self = Self(Self::HR_PERSISTENT.0);
    /// Last persistent object handle (`0x81FF_FFFF`).
    pub const PERSISTENT_LAST: Self = Self(Self::PERSISTENT_FIRST.0 + 0x00FF_FFFF);
    /// First platform persistent object handle (`0x8180_0000`).
    pub const PLATFORM_PERSISTENT: Self = Self(Self::PERSISTENT_FIRST.0 + 0x0080_0000);
    /// First allowed NV Index with 32-bit attributes (`0x0100_0000`).
    pub const NV_INDEX_FIRST: Self = Self(Self::HR_NV_INDEX.0);
    /// Last allowed NV Index with 32-bit attributes (`0x01FF_FFFF`).
    pub const NV_INDEX_LAST: Self = Self(Self::NV_INDEX_FIRST.0 + 0x00FF_FFFF);
    /// First external NV Index (`0x1100_0000`).
    pub const EXTERNAL_NV_FIRST: Self = Self(Self::HR_EXTERNAL_NV.0);
    /// Last external NV Index (`0x11FF_FFFF`).
    pub const EXTERNAL_NV_LAST: Self = Self(Self::EXTERNAL_NV_FIRST.0 + 0x00FF_FFFF);
    /// First permanent NV Index (`0x1200_0000`).
    pub const PERMANENT_NV_FIRST: Self = Self(Self::HR_PERMANENT_NV.0);
    /// Last permanent NV Index (`0x12FF_FFFF`).
    pub const PERMANENT_NV_LAST: Self = Self(Self::PERMANENT_NV_FIRST.0 + 0x00FF_FFFF);
    /// First permanent handle (`TPM_RH_FIRST` = `0x4000_0000`).
    pub const PERMANENT_FIRST: Self = Self(0x4000_0000);
    /// Last permanent handle (`TPM_RH_LAST` = `0x4004_FFFF`).
    pub const PERMANENT_LAST: Self = Self(0x4004_FFFF);
    /// First SVN-limited Owner hierarchy handle (`0x4001_0000`).
    pub const SVN_OWNER_FIRST: Self = Self(0x4001_0000);
    /// Last SVN-limited Owner hierarchy handle (`0x4001_FFFF`).
    pub const SVN_OWNER_LAST: Self = Self(0x4001_FFFF);
    /// First SVN-limited Endorsement hierarchy handle (`0x4002_0000`).
    pub const SVN_ENDORSEMENT_FIRST: Self = Self(0x4002_0000);
    /// Last SVN-limited Endorsement hierarchy handle (`0x4002_FFFF`).
    pub const SVN_ENDORSEMENT_LAST: Self = Self(0x4002_FFFF);
    /// First SVN-limited Platform hierarchy handle (`0x4003_0000`).
    pub const SVN_PLATFORM_FIRST: Self = Self(0x4003_0000);
    /// Last SVN-limited Platform hierarchy handle (`0x4003_FFFF`).
    pub const SVN_PLATFORM_LAST: Self = Self(0x4003_FFFF);
    /// First SVN-limited Null hierarchy handle (`0x4004_0000`).
    pub const SVN_NULL_FIRST: Self = Self(0x4004_0000);
    /// Last SVN-limited Null hierarchy handle (`0x4004_FFFF`).
    pub const SVN_NULL_LAST: Self = Self(0x4004_FFFF);
    /// Base handle prefix for AC aliased NV Index handles (`((TPM_HT_NV_INDEX << HR_SHIFT) + 0xD00000)` = `0x01D0_0000`).
    pub const HR_NV_AC: Self = Self(((TpmHt::NVIndex as u32) << Self::HR_SHIFT_BITS) + 0x00D0_0000);
    /// First NV Index aliased to Attached Component (`0x01D0_0000`).
    pub const NV_AC_FIRST: Self = Self(Self::HR_NV_AC.0);
    /// Last NV Index aliased to Attached Component (`0x01D0_FFFF`).
    pub const NV_AC_LAST: Self = Self(Self::HR_NV_AC.0 + 0x0000_FFFF);
    /// Base handle prefix for Attached Component handles (`TPM_HT_AC << HR_SHIFT` = `0x9000_0000`).
    pub const HR_AC: Self = Self((TpmHt::AC as u32) << Self::HR_SHIFT_BITS);
    /// First Attached Component handle (`0x9000_0000`).
    pub const AC_FIRST: Self = Self(Self::HR_AC.0);
    /// Last Attached Component handle (`0x9000_FFFF`).
    pub const AC_LAST: Self = Self(Self::HR_AC.0 + 0x0000_FFFF);
}

impl From<u32> for TpmHc {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<TpmHc> for u32 {
    fn from(val: TpmHc) -> Self {
        val.0
    }
}

impl From<Handle> for TpmHc {
    fn from(val: Handle) -> Self {
        Self(val.0)
    }
}

impl From<TpmHc> for Handle {
    fn from(val: TpmHc) -> Self {
        Self(val.0)
    }
}

impl Marshal for TpmHc {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmHc {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self(u32::unmarshal(src)?))
    }
}

/// Module containing raw `u32` `TPM_HC` handle range constants defined in TPM 2.0 Part 2 Section 7.5 (Table 31).
pub mod tpm_hc {
    use super::TpmHc;

    pub const HR_HANDLE_MASK: u32 = TpmHc::HR_HANDLE_MASK.0;
    pub const HR_RANGE_MASK: u32 = TpmHc::HR_RANGE_MASK.0;
    pub const HR_SHIFT: u32 = TpmHc::HR_SHIFT.0;
    pub const HR_PCR: u32 = TpmHc::HR_PCR.0;
    pub const HR_HMAC_SESSION: u32 = TpmHc::HR_HMAC_SESSION.0;
    pub const HR_LOADED_SESSION: u32 = TpmHc::HR_LOADED_SESSION.0;
    pub const HR_POLICY_SESSION: u32 = TpmHc::HR_POLICY_SESSION.0;
    pub const HR_SAVED_SESSION: u32 = TpmHc::HR_SAVED_SESSION.0;
    pub const HR_TRANSIENT: u32 = TpmHc::HR_TRANSIENT.0;
    pub const HR_PERSISTENT: u32 = TpmHc::HR_PERSISTENT.0;
    pub const HR_NV_INDEX: u32 = TpmHc::HR_NV_INDEX.0;
    pub const HR_EXTERNAL_NV: u32 = TpmHc::HR_EXTERNAL_NV.0;
    pub const HR_PERMANENT_NV: u32 = TpmHc::HR_PERMANENT_NV.0;
    pub const HR_PERMANENT: u32 = TpmHc::HR_PERMANENT.0;
    pub const PCR_FIRST: u32 = TpmHc::PCR_FIRST.0;
    pub const PCR_LAST: u32 = TpmHc::PCR_LAST.0;
    pub const HMAC_SESSION_FIRST: u32 = TpmHc::HMAC_SESSION_FIRST.0;
    pub const HMAC_SESSION_LAST: u32 = TpmHc::HMAC_SESSION_LAST.0;
    pub const LOADED_SESSION_FIRST: u32 = TpmHc::LOADED_SESSION_FIRST.0;
    pub const LOADED_SESSION_LAST: u32 = TpmHc::LOADED_SESSION_LAST.0;
    pub const POLICY_SESSION_FIRST: u32 = TpmHc::POLICY_SESSION_FIRST.0;
    pub const POLICY_SESSION_LAST: u32 = TpmHc::POLICY_SESSION_LAST.0;
    pub const SAVED_SESSION_FIRST: u32 = TpmHc::SAVED_SESSION_FIRST.0;
    pub const SAVED_SESSION_LAST: u32 = TpmHc::SAVED_SESSION_LAST.0;
    pub const TRANSIENT_FIRST: u32 = TpmHc::TRANSIENT_FIRST.0;
    pub const ACTIVE_SESSION_FIRST: u32 = TpmHc::ACTIVE_SESSION_FIRST.0;
    pub const ACTIVE_SESSION_LAST: u32 = TpmHc::ACTIVE_SESSION_LAST.0;
    pub const TRANSIENT_LAST: u32 = TpmHc::TRANSIENT_LAST.0;
    pub const PERSISTENT_FIRST: u32 = TpmHc::PERSISTENT_FIRST.0;
    pub const PERSISTENT_LAST: u32 = TpmHc::PERSISTENT_LAST.0;
    pub const PLATFORM_PERSISTENT: u32 = TpmHc::PLATFORM_PERSISTENT.0;
    pub const NV_INDEX_FIRST: u32 = TpmHc::NV_INDEX_FIRST.0;
    pub const NV_INDEX_LAST: u32 = TpmHc::NV_INDEX_LAST.0;
    pub const EXTERNAL_NV_FIRST: u32 = TpmHc::EXTERNAL_NV_FIRST.0;
    pub const EXTERNAL_NV_LAST: u32 = TpmHc::EXTERNAL_NV_LAST.0;
    pub const PERMANENT_NV_FIRST: u32 = TpmHc::PERMANENT_NV_FIRST.0;
    pub const PERMANENT_NV_LAST: u32 = TpmHc::PERMANENT_NV_LAST.0;
    pub const PERMANENT_FIRST: u32 = TpmHc::PERMANENT_FIRST.0;
    pub const PERMANENT_LAST: u32 = TpmHc::PERMANENT_LAST.0;
    pub const SVN_OWNER_FIRST: u32 = TpmHc::SVN_OWNER_FIRST.0;
    pub const SVN_OWNER_LAST: u32 = TpmHc::SVN_OWNER_LAST.0;
    pub const SVN_ENDORSEMENT_FIRST: u32 = TpmHc::SVN_ENDORSEMENT_FIRST.0;
    pub const SVN_ENDORSEMENT_LAST: u32 = TpmHc::SVN_ENDORSEMENT_LAST.0;
    pub const SVN_PLATFORM_FIRST: u32 = TpmHc::SVN_PLATFORM_FIRST.0;
    pub const SVN_PLATFORM_LAST: u32 = TpmHc::SVN_PLATFORM_LAST.0;
    pub const SVN_NULL_FIRST: u32 = TpmHc::SVN_NULL_FIRST.0;
    pub const SVN_NULL_LAST: u32 = TpmHc::SVN_NULL_LAST.0;
    pub const HR_NV_AC: u32 = TpmHc::HR_NV_AC.0;
    pub const NV_AC_FIRST: u32 = TpmHc::NV_AC_FIRST.0;
    pub const NV_AC_LAST: u32 = TpmHc::NV_AC_LAST.0;
    pub const HR_AC: u32 = TpmHc::HR_AC.0;
    pub const AC_FIRST: u32 = TpmHc::AC_FIRST.0;
    pub const AC_LAST: u32 = TpmHc::AC_LAST.0;
}

pub use tpm_hc::*;

/// TPM 2.0 Part 2 Section 7: Handles and Names
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Handle(pub u32);

impl Handle {
    /// Returns the handle type (`TpmHt`) indicated by the most significant byte of the handle.
    ///
    /// Note that handle type `0x02` returns `Some(TpmHt::HMACSession)` (which equals
    /// [`TpmHt::LOADED_SESSION`]) and `0x03` returns `Some(TpmHt::PolicySession)` (which
    /// equals [`TpmHt::SAVED_SESSION`]).
    pub fn handle_type(self) -> Option<TpmHt> {
        ((self.0 >> Self::HR_SHIFT) as u8).try_into().ok()
    }

    pub const HR_HANDLE_MASK: u32 = TpmHc::HR_HANDLE_MASK.0;
    pub const HR_RANGE_MASK: u32 = TpmHc::HR_RANGE_MASK.0;
    pub const HR_SHIFT: u32 = TpmHc::HR_SHIFT.0;
    pub const HR_PCR: Handle = Handle(TpmHc::HR_PCR.0);
    pub const HR_HMAC_SESSION: Handle = Handle(TpmHc::HR_HMAC_SESSION.0);
    pub const HR_LOADED_SESSION: Handle = Handle(TpmHc::HR_LOADED_SESSION.0);
    pub const HR_POLICY_SESSION: Handle = Handle(TpmHc::HR_POLICY_SESSION.0);
    pub const HR_SAVED_SESSION: Handle = Handle(TpmHc::HR_SAVED_SESSION.0);
    pub const HR_TRANSIENT: Handle = Handle(TpmHc::HR_TRANSIENT.0);
    pub const HR_PERSISTENT: Handle = Handle(TpmHc::HR_PERSISTENT.0);
    pub const HR_NV_INDEX: Handle = Handle(TpmHc::HR_NV_INDEX.0);
    pub const HR_EXTERNAL_NV: Handle = Handle(TpmHc::HR_EXTERNAL_NV.0);
    pub const HR_PERMANENT_NV: Handle = Handle(TpmHc::HR_PERMANENT_NV.0);
    pub const HR_PERMANENT: Handle = Handle(TpmHc::HR_PERMANENT.0);
    pub const PCR_FIRST: Handle = Handle(TpmHc::PCR_FIRST.0);
    pub const PCR_LAST: Handle = Handle(TpmHc::PCR_LAST.0);
    pub const HMAC_SESSION_FIRST: Handle = Handle(TpmHc::HMAC_SESSION_FIRST.0);
    pub const HMAC_SESSION_LAST: Handle = Handle(TpmHc::HMAC_SESSION_LAST.0);
    pub const LOADED_SESSION_FIRST: Handle = Handle(TpmHc::LOADED_SESSION_FIRST.0);
    pub const LOADED_SESSION_LAST: Handle = Handle(TpmHc::LOADED_SESSION_LAST.0);
    pub const POLICY_SESSION_FIRST: Handle = Handle(TpmHc::POLICY_SESSION_FIRST.0);
    pub const POLICY_SESSION_LAST: Handle = Handle(TpmHc::POLICY_SESSION_LAST.0);
    pub const SAVED_SESSION_FIRST: Handle = Handle(TpmHc::SAVED_SESSION_FIRST.0);
    pub const SAVED_SESSION_LAST: Handle = Handle(TpmHc::SAVED_SESSION_LAST.0);
    pub const TRANSIENT_FIRST: Handle = Handle(TpmHc::TRANSIENT_FIRST.0);
    pub const ACTIVE_SESSION_FIRST: Handle = Handle(TpmHc::ACTIVE_SESSION_FIRST.0);
    pub const ACTIVE_SESSION_LAST: Handle = Handle(TpmHc::ACTIVE_SESSION_LAST.0);
    pub const TRANSIENT_LAST: Handle = Handle(TpmHc::TRANSIENT_LAST.0);
    pub const PERSISTENT_FIRST: Handle = Handle(TpmHc::PERSISTENT_FIRST.0);
    pub const PERSISTENT_LAST: Handle = Handle(TpmHc::PERSISTENT_LAST.0);
    pub const PLATFORM_PERSISTENT: Handle = Handle(TpmHc::PLATFORM_PERSISTENT.0);
    pub const NV_INDEX_FIRST: Handle = Handle(TpmHc::NV_INDEX_FIRST.0);
    pub const NV_INDEX_LAST: Handle = Handle(TpmHc::NV_INDEX_LAST.0);
    pub const EXTERNAL_NV_FIRST: Handle = Handle(TpmHc::EXTERNAL_NV_FIRST.0);
    pub const EXTERNAL_NV_LAST: Handle = Handle(TpmHc::EXTERNAL_NV_LAST.0);
    pub const PERMANENT_NV_FIRST: Handle = Handle(TpmHc::PERMANENT_NV_FIRST.0);
    pub const PERMANENT_NV_LAST: Handle = Handle(TpmHc::PERMANENT_NV_LAST.0);
    pub const PERMANENT_FIRST: Handle = Handle(TpmHc::PERMANENT_FIRST.0);
    pub const PERMANENT_LAST: Handle = Handle(TpmHc::PERMANENT_LAST.0);
    pub const SVN_OWNER_FIRST: Handle = Handle(TpmHc::SVN_OWNER_FIRST.0);
    pub const SVN_OWNER_LAST: Handle = Handle(TpmHc::SVN_OWNER_LAST.0);
    pub const SVN_ENDORSEMENT_FIRST: Handle = Handle(TpmHc::SVN_ENDORSEMENT_FIRST.0);
    pub const SVN_ENDORSEMENT_LAST: Handle = Handle(TpmHc::SVN_ENDORSEMENT_LAST.0);
    pub const SVN_PLATFORM_FIRST: Handle = Handle(TpmHc::SVN_PLATFORM_FIRST.0);
    pub const SVN_PLATFORM_LAST: Handle = Handle(TpmHc::SVN_PLATFORM_LAST.0);
    pub const SVN_NULL_FIRST: Handle = Handle(TpmHc::SVN_NULL_FIRST.0);
    pub const SVN_NULL_LAST: Handle = Handle(TpmHc::SVN_NULL_LAST.0);
    pub const HR_NV_AC: Handle = Handle(TpmHc::HR_NV_AC.0);
    pub const NV_AC_FIRST: Handle = Handle(TpmHc::NV_AC_FIRST.0);
    pub const NV_AC_LAST: Handle = Handle(TpmHc::NV_AC_LAST.0);
    pub const HR_AC: Handle = Handle(TpmHc::HR_AC.0);
    pub const AC_FIRST: Handle = Handle(TpmHc::AC_FIRST.0);
    pub const AC_LAST: Handle = Handle(TpmHc::AC_LAST.0);
    #[doc(alias = "TPM_RH_FIRST")]
    pub const RH_FIRST: Handle = Handle(0x40000000);
    #[doc(alias = "TPM_RH_SRK")]
    pub const RH_SRK: Handle = Handle(0x40000000);
    #[doc(alias = "TPM_RH_OWNER")]
    pub const RH_OWNER: Handle = Handle(0x40000001);
    #[doc(alias = "TPM_RH_REVOKE")]
    pub const RH_REVOKE: Handle = Handle(0x40000002);
    #[doc(alias = "TPM_RH_TRANSPORT")]
    pub const RH_TRANSPORT: Handle = Handle(0x40000003);
    #[doc(alias = "TPM_RH_OPERATOR")]
    pub const RH_OPERATOR: Handle = Handle(0x40000004);
    #[doc(alias = "TPM_RH_ADMIN")]
    pub const RH_ADMIN: Handle = Handle(0x40000005);
    #[doc(alias = "TPM_RH_EK")]
    pub const RH_EK: Handle = Handle(0x40000006);
    #[doc(alias = "TPM_RH_NULL")]
    pub const RH_NULL: Handle = Handle(0x40000007);
    #[doc(alias = "TPM_RH_UNASSIGNED")]
    pub const RH_UNASSIGNED: Handle = Handle(0x40000008);
    #[doc(alias = "TPM_RS_PW")]
    pub const RS_PW: Handle = Handle(0x40000009);
    #[doc(alias = "TPM_RH_LOCKOUT")]
    pub const RH_LOCKOUT: Handle = Handle(0x4000000A);
    #[doc(alias = "TPM_RH_ENDORSEMENT")]
    pub const RH_ENDORSEMENT: Handle = Handle(0x4000000B);
    #[doc(alias = "TPM_RH_PLATFORM")]
    pub const RH_PLATFORM: Handle = Handle(0x4000000C);
    #[doc(alias = "TPM_RH_PLATFORM_NV")]
    pub const RH_PLATFORM_NV: Handle = Handle(0x4000000D);
    #[doc(alias = "TPM_RH_AUTH_00")]
    pub const RH_AUTH_00: Handle = Handle(0x40000010);
    #[doc(alias = "TPM_RH_AUTH_FF")]
    pub const RH_AUTH_FF: Handle = Handle(0x4000010F);
    #[doc(alias = "TPM_RH_ACT_0")]
    pub const RH_ACT_0: Handle = Handle(0x40000110);
    #[doc(alias = "TPM_RH_ACT_1")]
    pub const RH_ACT_1: Handle = Handle(0x40000111);
    #[doc(alias = "TPM_RH_ACT_2")]
    pub const RH_ACT_2: Handle = Handle(0x40000112);
    #[doc(alias = "TPM_RH_ACT_3")]
    pub const RH_ACT_3: Handle = Handle(0x40000113);
    #[doc(alias = "TPM_RH_ACT_4")]
    pub const RH_ACT_4: Handle = Handle(0x40000114);
    #[doc(alias = "TPM_RH_ACT_5")]
    pub const RH_ACT_5: Handle = Handle(0x40000115);
    #[doc(alias = "TPM_RH_ACT_6")]
    pub const RH_ACT_6: Handle = Handle(0x40000116);
    #[doc(alias = "TPM_RH_ACT_7")]
    pub const RH_ACT_7: Handle = Handle(0x40000117);
    #[doc(alias = "TPM_RH_ACT_8")]
    pub const RH_ACT_8: Handle = Handle(0x40000118);
    #[doc(alias = "TPM_RH_ACT_9")]
    pub const RH_ACT_9: Handle = Handle(0x40000119);
    #[doc(alias = "TPM_RH_ACT_A")]
    pub const RH_ACT_A: Handle = Handle(0x4000011A);
    #[doc(alias = "TPM_RH_ACT_B")]
    pub const RH_ACT_B: Handle = Handle(0x4000011B);
    #[doc(alias = "TPM_RH_ACT_C")]
    pub const RH_ACT_C: Handle = Handle(0x4000011C);
    #[doc(alias = "TPM_RH_ACT_D")]
    pub const RH_ACT_D: Handle = Handle(0x4000011D);
    #[doc(alias = "TPM_RH_ACT_E")]
    pub const RH_ACT_E: Handle = Handle(0x4000011E);
    #[doc(alias = "TPM_RH_ACT_F")]
    pub const RH_ACT_F: Handle = Handle(0x4000011F);
    #[doc(alias = "TPM_RH_FW_OWNER")]
    pub const RH_FW_OWNER: Handle = Handle(0x40000140);
    #[doc(alias = "TPM_RH_FW_ENDORSEMENT")]
    pub const RH_FW_ENDORSEMENT: Handle = Handle(0x40000141);
    #[doc(alias = "TPM_RH_FW_PLATFORM")]
    pub const RH_FW_PLATFORM: Handle = Handle(0x40000142);
    #[doc(alias = "TPM_RH_FW_NULL")]
    pub const RH_FW_NULL: Handle = Handle(0x40000143);
    #[doc(alias = "TPM_RH_SVN_OWNER_BASE")]
    pub const RH_SVN_OWNER_BASE: Handle = Handle(0x40010000);
    #[doc(alias = "TPM_RH_SVN_ENDORSEMENT_BASE")]
    pub const RH_SVN_ENDORSEMENT_BASE: Handle = Handle(0x40020000);
    #[doc(alias = "TPM_RH_SVN_PLATFORM_BASE")]
    pub const RH_SVN_PLATFORM_BASE: Handle = Handle(0x40030000);
    #[doc(alias = "TPM_RH_SVN_NULL_BASE")]
    pub const RH_SVN_NULL_BASE: Handle = Handle(0x40040000);
    #[doc(alias = "TPM_RH_LAST")]
    pub const RH_LAST: Handle = Handle(0x4004FFFF);

    /// Returns `true` if this handle is a valid `TPMI_RH_HIERARCHY` value per TPM 2.0 Part 2 Table 54.
    pub const fn is_hierarchy(self) -> bool {
        matches!(
            self,
            Self::RH_OWNER
                | Self::RH_PLATFORM
                | Self::RH_ENDORSEMENT
                | Self::RH_NULL
                | Self::RH_FW_OWNER
                | Self::RH_FW_ENDORSEMENT
                | Self::RH_FW_PLATFORM
                | Self::RH_FW_NULL
        ) || (self.0 >= Self::SVN_OWNER_FIRST.0 && self.0 <= Self::SVN_NULL_LAST.0)
    }
}

impl Marshal for Handle {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        self.0.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for Handle {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Unmarshal::unmarshal(src).map(Self)
    }
}

// TpmNt represents a TPM_NT.
// See definition in Part 2: Structures, section 13.4.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmNt {
    // contains data that is opaque to the TPM that can only be modified
    // using TPM2_NV_Write().
    #[default]
    #[doc(alias = "TPM_NT_ORDINARY")]
    Ordinary = 0x0,
    // contains an 8-octet value that is to be used as a counter and can
    // only be modified with TPM2_NV_Increment()
    #[doc(alias = "TPM_NT_COUNTER")]
    Counter = 0x1,
    // contains an 8-octet value to be used as a bit field and can only be
    // modified with TPM2_NV_SetBits().
    #[doc(alias = "TPM_NT_BITS")]
    Bits = 0x2,
    // contains a digest-sized value used like a PCR. The Index can only be
    // modified using TPM2_NV_Extend(). The extend will use the nameAlg of
    // the Index.
    #[doc(alias = "TPM_NT_EXTEND")]
    Extend = 0x4,
    // contains pinCount that increments on a PIN authorization failure and
    // a pinLimit
    #[doc(alias = "TPM_NT_PIN_FAIL")]
    PinFail = 0x8,
    // contains pinCount that increments on a PIN authorization success and
    // a pinLimit
    #[doc(alias = "TPM_NT_PIN_PASS")]
    PinPass = 0x9,
}

impl TryFrom<u8> for TpmNt {
    type Error = UnmarshalError;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x0 => Ok(Self::Ordinary),
            0x1 => Ok(Self::Counter),
            0x2 => Ok(Self::Bits),
            0x4 => Ok(Self::Extend),
            0x8 => Ok(Self::PinFail),
            0x9 => Ok(Self::PinPass),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}
impl From<TpmNt> for u8 {
    fn from(val: TpmNt) -> Self {
        val as u8
    }
}

impl Marshal for TpmNt {
    const MAX_SIZE: usize = u8::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        u8::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmNt {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u8::unmarshal(src)?.try_into()
    }
}

/// Represents the adjustment steps for TPM Clock and Time update rate (`TPM_CLOCK_ADJUST`).
/// See definition in Part 2: Structures, Section 11.3 (`TPM_CLOCK_ADJUST`).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmClockAdjust {
    /// Slow the Clock update rate by one coarse adjustment step (-3).
    #[doc(alias = "TPM_CLOCK_COARSE_SLOWER")]
    CoarseSlower = -3,
    /// Slow the Clock update rate by one medium adjustment step (-2).
    #[doc(alias = "TPM_CLOCK_MEDIUM_SLOWER")]
    MediumSlower = -2,
    /// Slow the Clock update rate by one fine adjustment step (-1).
    #[doc(alias = "TPM_CLOCK_FINE_SLOWER")]
    FineSlower = -1,
    /// No change to the Clock update rate (0).
    #[default]
    #[doc(alias = "TPM_CLOCK_NO_CHANGE")]
    NoChange = 0,
    /// Speed the Clock update rate by one fine adjustment step (1).
    #[doc(alias = "TPM_CLOCK_FINE_FASTER")]
    FineFaster = 1,
    /// Speed the Clock update rate by one medium adjustment step (2).
    #[doc(alias = "TPM_CLOCK_MEDIUM_FASTER")]
    MediumFaster = 2,
    /// Speed the Clock update rate by one coarse adjustment step (3).
    #[doc(alias = "TPM_CLOCK_COARSE_FASTER")]
    CoarseFaster = 3,
}

impl TryFrom<i8> for TpmClockAdjust {
    type Error = UnmarshalError;
    fn try_from(val: i8) -> Result<Self, Self::Error> {
        match val {
            -3 => Ok(Self::CoarseSlower),
            -2 => Ok(Self::MediumSlower),
            -1 => Ok(Self::FineSlower),
            0 => Ok(Self::NoChange),
            1 => Ok(Self::FineFaster),
            2 => Ok(Self::MediumFaster),
            3 => Ok(Self::CoarseFaster),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}
impl From<TpmClockAdjust> for i8 {
    fn from(val: TpmClockAdjust) -> Self {
        val as i8
    }
}

impl Marshal for TpmClockAdjust {
    const MAX_SIZE: usize = i8::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        i8::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmClockAdjust {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        i8::unmarshal(src)?.try_into()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct TpmGenerated;
impl TpmGenerated {
    #[doc(alias = "TPM_GENERATED_VALUE")]
    pub const VALUE: [u8; 4] = *b"\xffTCG";

    /// 32-bit integer representation of `TPM_GENERATED_VALUE` (`0xFF544347`).
    #[doc(alias = "TPM_GENERATED_VALUE")]
    pub const U32_VALUE: TpmConstants32 = TPM_GENERATED_VALUE;

    /// Maximum number of bits that may be generated by an instantiation of the deterministic
    /// pseudo-random bit generator (`TPM_MAX_DERIVATION_BITS` = `8192`).
    #[doc(alias = "TPM_MAX_DERIVATION_BITS")]
    pub const MAX_DERIVATION_BITS: TpmConstants32 = TPM2_MAX_DERIVATION_BITS;
}

impl Marshal for TpmGenerated {
    const MAX_SIZE: usize = 4;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        Self::VALUE.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmGenerated {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match Unmarshal::unmarshal(src)? {
            Self::VALUE => Ok(Self),
            _ => Err(UnmarshalError::VALUE),
        }
    }
}
