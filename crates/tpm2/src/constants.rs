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

/// `TPM_ALG_ID` and `TCG_ALG_ID` defined in TPM 2.0 Part 2: Structures, Section 6.3 (Table 9) and the
/// [TCG Algorithm Registry](https://trustedcomputinggroup.org/resource/tcg-algorithm-registry/).
///
/// Note that unlike other types, `TPM_ALG_NULL` is represented by
/// [`Alg::NULL`], not [`Option<Alg>::None`].
#[doc(alias = "TPM_ALG_ID")]
#[doc(alias = "TCG_ALG_ID")]
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Alg(u16);

/// Numerical ID value for algorithms.
///
/// `Alg` is used both as the algorithm ID in `TPM_ALG_ID` (and related types)
/// and as the enum discriminant value in `Tpmt*`/`Tpmi*` types. Algorithm IDs
/// in the TPM2 specification occupy a single flat namespace. Because [`Self::new`]
/// checks that a value is in a valid range, the defined constants
/// (e.g., [`Self::KEYEDHASH`]) will fail at compile time if an incorrect value is used.
/// Processing logic rarely uses these constants, instead relying on enums for
/// specific types (e.g., [`TpmiAlgSymMode`](crate::structures::TpmiAlgSymMode)).
impl Alg {
    /// Creates a new [`Alg`] from raw 16-bit algorithm ID numerical value.
    ///
    /// Panics if `id` is a reserved value:
    /// - `0x0000` (`TPM_ALG_ERROR`)
    /// - `0x00C1` - `0x00C6` (to avoid collision with TPM 1.2 values)
    /// - `0x8000` - `0xFFFF` (to avoid collision with [`TpmSt`] values)
    ///
    /// These panics are *not* intended to catch runtime errors: note that
    /// `From<u16>` allows any value. Instead, this is to catch incorrect
    /// values for named constants (such as `KEYEDHASH`) at compile time.
    /// Runtime errors involving invalid algorithm IDs are caught during
    /// unmarshalling for specific `tpmi` types, returning an [`UnmarshalError`].
    pub const fn new(id: u16) -> Self {
        assert!(id > 0x0000);
        assert!(id < 0x00C1 || 0x00C6 < id);
        assert!(id < 0x8000);
        Self(id)
    }
    /// Returns the raw 16-bit algorithm ID.
    pub const fn id(self) -> u16 {
        self.0
    }
    /// Enum discriminant value to use in `Tpmt*`/`Tpmi*` types.
    pub(crate) const fn tag(self) -> isize {
        self.0 as isize
    }

    // Object Types
    pub const KEYEDHASH: Self = Self::new(0x0008);
    pub const SYMCIPHER: Self = Self::new(0x0025);
    pub const RSA: Self = Self::new(0x0001);
    pub const ECC: Self = Self::new(0x0023);
    pub const MLKEM: Self = Self::new(0x00A0);
    pub const MLDSA: Self = Self::new(0x00A1);
    pub const HASH_MLDSA: Self = Self::new(0x00A2);

    // Hash Algorithms
    pub const SHA1: Self = Self::new(0x0004);
    pub const SHA256: Self = Self::new(0x000B);
    pub const SHA384: Self = Self::new(0x000C);
    pub const SHA512: Self = Self::new(0x000D);
    pub const SM3_256: Self = Self::new(0x0012);
    pub const SHA3_256: Self = Self::new(0x0027);
    pub const SHA3_384: Self = Self::new(0x0028);
    pub const SHA3_512: Self = Self::new(0x0029);

    // Block Ciphers
    pub const TDES: Self = Self::new(0x0003);
    pub const AES: Self = Self::new(0x0006);
    pub const SM4: Self = Self::new(0x0013);
    pub const CAMELLIA: Self = Self::new(0x0026);

    // Block Cipher Modes
    pub const CTR: Self = Self::new(0x0040);
    pub const OFB: Self = Self::new(0x0041);
    pub const CBC: Self = Self::new(0x0042);
    pub const CFB: Self = Self::new(0x0043);
    pub const ECB: Self = Self::new(0x0044);

    // Message Authentication Codes
    pub const HMAC: Self = Self::new(0x0005);
    pub const CMAC: Self = Self::new(0x003F);

    // Key Derivation Functions
    pub const HKDF: Self = Self::new(0x001F);
    pub const KDF1_SP800_56A: Self = Self::new(0x0020);
    pub const KDF2: Self = Self::new(0x0021);
    pub const KDF1_SP800_108: Self = Self::new(0x0022);

    // RSA Schemes
    pub const RSASSA: Self = Self::new(0x0014);
    pub const RSAES: Self = Self::new(0x0015);
    pub const RSAPSS: Self = Self::new(0x0016);
    pub const OAEP: Self = Self::new(0x0017);

    // ECC Schemes
    pub const ECDSA: Self = Self::new(0x0018);
    pub const ECDH: Self = Self::new(0x0019);
    pub const ECDAA: Self = Self::new(0x001A);
    pub const SM2: Self = Self::new(0x001B);
    pub const ECSCHNORR: Self = Self::new(0x001C);
    pub const ECMQV: Self = Self::new(0x001D);
    pub const EDDSA: Self = Self::new(0x0060);
    pub const HASH_EDDSA: Self = Self::new(0x0061);

    // Miscellaneous
    pub const NULL: Self = Self::new(0x0010);
    pub const XOR: Self = Self::new(0x000A);
    pub const MGF1: Self = Self::new(0x0007);
}

impl Default for Alg {
    fn default() -> Self {
        Self::NULL
    }
}

impl From<u16> for Alg {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Alg> for u16 {
    fn from(value: Alg) -> Self {
        value.id()
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
        u16::unmarshal(src).map(Self)
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

/// `TPM_ECC_CURVE` and `TPMI_ECC_CURVE` defined in TPM 2.0 Part 2: Structures, Section 6.4 (Table 10) and Section 9.7 (Table 38).
///
/// Defines ECC curve identifiers supported by the TPM (NIST, Brainpool, Barreto-Naehrig, SM2, Edwards/Curve25519/448).
/// Used in ECC parameter definitions, ephemeral key generation, and curve capability queries (`TPML_ECC_CURVE`).
///
/// Note: `TPM_ECC_NONE` is omitted as it is not used in the TPM 2.0 specification.
#[doc(alias = "TPM_ECC_CURVE")]
#[doc(alias = "TPMI_ECC_CURVE")]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TpmEccCurve {
    NistP192 = 0x0001,
    NistP224 = 0x0002,
    NistP256 = 0x0003,
    NistP384 = 0x0004,
    NistP521 = 0x0005,
    BNP256 = 0x0010,
    BNP638 = 0x0011,
    SM2P256 = 0x0020,
    BpP256R1 = 0x0030,
    BpP384R1 = 0x0031,
    BpP512R1 = 0x0032,
    Curve25519 = 0x0040,
    Curve448 = 0x0041,
}

impl TpmEccCurve {
    pub const MAX_ECC_KEY_BITS: usize = 638;
    pub const MAX_ECC_KEY_BYTES: usize = Self::MAX_ECC_KEY_BITS.div_ceil(8);
}

impl TryFrom<u16> for TpmEccCurve {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        Ok(match val {
            0x0001 => Self::NistP192,
            0x0002 => Self::NistP224,
            0x0003 => Self::NistP256,
            0x0004 => Self::NistP384,
            0x0005 => Self::NistP521,
            0x0010 => Self::BNP256,
            0x0011 => Self::BNP638,
            0x0020 => Self::SM2P256,
            0x0030 => Self::BpP256R1,
            0x0031 => Self::BpP384R1,
            0x0032 => Self::BpP512R1,
            0x0040 => Self::Curve25519,
            0x0041 => Self::Curve448,
            _ => return Err(UnmarshalError),
        })
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

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u16::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmEccCurve {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u16::unmarshal(src)?.try_into()
    }
}

/// `TPM_CC` (Command Code) defined in TPM 2.0 Part 2: Structures, Section 6.5 (Table 11).
///
/// Represents 32-bit numeric command codes identifying TPM 2.0 commands in  packet
/// headers, audit logs, and capability queries (`TPML_CC`, `TPMA_CC`).
#[doc(alias = "TPM_CC")]
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

    pub const NVUndefineSpaceSpecial: Self = Self::new(0x0000011F);
    pub const EvictControl: Self = Self::new(0x00000120);
    pub const HierarchyControl: Self = Self::new(0x00000121);
    pub const NVUndefineSpace: Self = Self::new(0x00000122);
    pub const ChangeEPS: Self = Self::new(0x00000124);
    pub const ChangePPS: Self = Self::new(0x00000125);
    pub const Clear: Self = Self::new(0x00000126);
    pub const ClearControl: Self = Self::new(0x00000127);
    pub const ClockSet: Self = Self::new(0x00000128);
    pub const HierarchyChangeAuth: Self = Self::new(0x00000129);
    pub const NVDefineSpace: Self = Self::new(0x0000012A);
    pub const PCRAllocate: Self = Self::new(0x0000012B);
    pub const PCRSetAuthPolicy: Self = Self::new(0x0000012C);
    pub const PPCommands: Self = Self::new(0x0000012D);
    pub const SetPrimaryPolicy: Self = Self::new(0x0000012E);
    pub const FieldUpgradeStart: Self = Self::new(0x0000012F);
    pub const ClockRateAdjust: Self = Self::new(0x00000130);
    pub const CreatePrimary: Self = Self::new(0x00000131);
    pub const NVGlobalWriteLock: Self = Self::new(0x00000132);
    pub const GetCommandAuditDigest: Self = Self::new(0x00000133);
    pub const NVIncrement: Self = Self::new(0x00000134);
    pub const NVSetBits: Self = Self::new(0x00000135);
    pub const NVExtend: Self = Self::new(0x00000136);
    pub const NVWrite: Self = Self::new(0x00000137);
    pub const NVWriteLock: Self = Self::new(0x00000138);
    pub const DictionaryAttackLockReset: Self = Self::new(0x00000139);
    pub const DictionaryAttackParameters: Self = Self::new(0x0000013A);
    pub const NVChangeAuth: Self = Self::new(0x0000013B);
    pub const PCREvent: Self = Self::new(0x0000013C);
    pub const PCRReset: Self = Self::new(0x0000013D);
    pub const SequenceComplete: Self = Self::new(0x0000013E);
    pub const SetAlgorithmSet: Self = Self::new(0x0000013F);
    pub const SetCommandCodeAuditStatus: Self = Self::new(0x00000140);
    pub const FieldUpgradeData: Self = Self::new(0x00000141);
    pub const IncrementalSelfTest: Self = Self::new(0x00000142);
    pub const SelfTest: Self = Self::new(0x00000143);
    pub const Startup: Self = Self::new(0x00000144);
    pub const Shutdown: Self = Self::new(0x00000145);
    pub const StirRandom: Self = Self::new(0x00000146);
    pub const ActivateCredential: Self = Self::new(0x00000147);
    pub const Certify: Self = Self::new(0x00000148);
    pub const PolicyNV: Self = Self::new(0x00000149);
    pub const CertifyCreation: Self = Self::new(0x0000014A);
    pub const Duplicate: Self = Self::new(0x0000014B);
    pub const GetTime: Self = Self::new(0x0000014C);
    pub const GetSessionAuditDigest: Self = Self::new(0x0000014D);
    pub const NVRead: Self = Self::new(0x0000014E);
    pub const NVReadLock: Self = Self::new(0x0000014F);
    pub const ObjectChangeAuth: Self = Self::new(0x00000150);
    pub const PolicySecret: Self = Self::new(0x00000151);
    pub const Rewrap: Self = Self::new(0x00000152);
    pub const Create: Self = Self::new(0x00000153);
    pub const ECDHZGen: Self = Self::new(0x00000154);
    pub const MAC: Self = Self::new(0x00000155);
    pub const Hmac: Self = Self::MAC;
    pub const HMAC: Self = Self::MAC;
    pub const Import: Self = Self::new(0x00000156);
    pub const Load: Self = Self::new(0x00000157);
    pub const Quote: Self = Self::new(0x00000158);
    pub const RSADecrypt: Self = Self::new(0x00000159);
    pub const MACStart: Self = Self::new(0x0000015B);
    pub const HmacStart: Self = Self::MACStart;
    pub const HMACStart: Self = Self::MACStart;
    pub const SequenceUpdate: Self = Self::new(0x0000015C);
    pub const Sign: Self = Self::new(0x0000015D);
    pub const Unseal: Self = Self::new(0x0000015E);
    pub const PolicySigned: Self = Self::new(0x00000160);
    pub const ContextLoad: Self = Self::new(0x00000161);
    pub const ContextSave: Self = Self::new(0x00000162);
    pub const ECDHKeyGen: Self = Self::new(0x00000163);
    pub const EncryptDecrypt: Self = Self::new(0x00000164);
    pub const FlushContext: Self = Self::new(0x00000165);
    pub const LoadExternal: Self = Self::new(0x00000167);
    pub const MakeCredential: Self = Self::new(0x00000168);
    pub const NVReadPublic: Self = Self::new(0x00000169);
    pub const PolicyAuthorize: Self = Self::new(0x0000016A);
    pub const PolicyAuthValue: Self = Self::new(0x0000016B);
    pub const PolicyCommandCode: Self = Self::new(0x0000016C);
    pub const PolicyCounterTimer: Self = Self::new(0x0000016D);
    pub const PolicyCpHash: Self = Self::new(0x0000016E);
    pub const PolicyLocality: Self = Self::new(0x0000016F);
    pub const PolicyNameHash: Self = Self::new(0x00000170);
    pub const PolicyOR: Self = Self::new(0x00000171);
    pub const PolicyTicket: Self = Self::new(0x00000172);
    pub const ReadPublic: Self = Self::new(0x00000173);
    pub const RSAEncrypt: Self = Self::new(0x00000174);
    pub const StartAuthSession: Self = Self::new(0x00000176);
    pub const VerifySignature: Self = Self::new(0x00000177);
    pub const ECCParameters: Self = Self::new(0x00000178);
    pub const FirmwareRead: Self = Self::new(0x00000179);
    pub const GetCapability: Self = Self::new(0x0000017A);
    pub const GetRandom: Self = Self::new(0x0000017B);
    pub const GetTestResult: Self = Self::new(0x0000017C);
    pub const Hash: Self = Self::new(0x0000017D);
    pub const PCRRead: Self = Self::new(0x0000017E);
    pub const PolicyPCR: Self = Self::new(0x0000017F);
    pub const PolicyRestart: Self = Self::new(0x00000180);
    pub const ReadClock: Self = Self::new(0x00000181);
    pub const PCRExtend: Self = Self::new(0x00000182);
    pub const PCRSetAuthValue: Self = Self::new(0x00000183);
    pub const NVCertify: Self = Self::new(0x00000184);
    pub const EventSequenceComplete: Self = Self::new(0x00000185);
    pub const HashSequenceStart: Self = Self::new(0x00000186);
    pub const PolicyPhysicalPresence: Self = Self::new(0x00000187);
    pub const PolicyDuplicationSelect: Self = Self::new(0x00000188);
    pub const PolicyGetDigest: Self = Self::new(0x00000189);
    pub const TestParms: Self = Self::new(0x0000018A);
    pub const Commit: Self = Self::new(0x0000018B);
    pub const PolicyPassword: Self = Self::new(0x0000018C);
    pub const ZGen2Phase: Self = Self::new(0x0000018D);
    pub const ECEphemeral: Self = Self::new(0x0000018E);
    pub const PolicyNvWritten: Self = Self::new(0x0000018F);
    pub const PolicyTemplate: Self = Self::new(0x00000190);
    pub const CreateLoaded: Self = Self::new(0x00000191);
    pub const PolicyAuthorizeNV: Self = Self::new(0x00000192);
    pub const EncryptDecrypt2: Self = Self::new(0x00000193);
    pub const ACGetCapability: Self = Self::new(0x00000194);
    pub const ACSend: Self = Self::new(0x00000195);
    pub const PolicyACSendSelect: Self = Self::new(0x00000196);
    pub const CertifyX509: Self = Self::new(0x00000197);
    pub const ACTSetTimeout: Self = Self::new(0x00000198);
    pub const ECCEncrypt: Self = Self::new(0x00000199);
    pub const ECCDecrypt: Self = Self::new(0x0000019A);
    pub const PolicyCapability: Self = Self::new(0x0000019B);
    pub const PolicyParameters: Self = Self::new(0x0000019C);
    pub const NVDefineSpace2: Self = Self::new(0x0000019D);
    pub const NVReadPublic2: Self = Self::new(0x0000019E);
    pub const SetCapability: Self = Self::new(0x0000019F);
    pub const ReadOnlyControl: Self = Self::new(0x000001A0);
    pub const PolicyTransportSPDM: Self = Self::new(0x000001A1);
    pub const VerifySequenceComplete: Self = Self::new(0x000001A3);
    pub const SignSequenceComplete: Self = Self::new(0x000001A4);
    pub const VerifyDigestSignature: Self = Self::new(0x000001A5);
    pub const SignDigest: Self = Self::new(0x000001A6);
    pub const Encapsulate: Self = Self::new(0x000001A7);
    pub const Decapsulate: Self = Self::new(0x000001A8);
    pub const VerifySequenceStart: Self = Self::new(0x000001A9);
    pub const SignSequenceStart: Self = Self::new(0x000001AA);
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

/// `TPM_EO` (Evaluation Option) defined in TPM 2.0 Part 2: Structures, Section 6.10 (Table 17).
///
/// Defines comparison and arithmetic operations used in conditional policy assertions
/// (such as `TPM2_PolicyNV` and `TPM2_PolicyAuthorizeNV`).
#[doc(alias = "TPM_EO")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmEo {
    #[default]
    Eq = 0x0000,
    Neq = 0x0001,
    SignedGT = 0x0002,
    UnsignedGT = 0x0003,
    SignedLT = 0x0004,
    UnsignedLT = 0x0005,
    SignedGE = 0x0006,
    UnsignedGE = 0x0007,
    SignedLE = 0x0008,
    UnsignedLE = 0x0009,
    BitSet = 0x000A,
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
            _ => Err(UnmarshalError),
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

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u16::from(*self).marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmEo {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u16::unmarshal(src)?.try_into()
    }
}

/// `TPM_ST` (Structure Tags) defined in TPM 2.0 Part 2: Structures, Section 6.9 (Table 16).
///
/// Represents 16-bit structure tags used in command/response packet framing headers
/// (`TPM_ST_NO_SESSIONS`, `TPM_ST_SESSIONS`), attestation structures (e.g. `TPMS_ATTEST`),
/// ticket tags, and context save/restore formats.
#[doc(alias = "TPM_ST")]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TpmSt(u16);

impl TpmSt {
    /// Creates a new [`TpmSt`] from raw 16-bit structure tag numerical value.
    /// This checks that the value is in a valid range, using `assert!`, so the
    /// constants can be checked at compile time.
    pub const fn new(id: u16) -> Self {
        assert!(id >= 0x8000);
        Self(id)
    }
    /// Returns the raw 16-bit structure tag.
    pub const fn id(self) -> u16 {
        self.0
    }
    /// Enum discriminant value to use in `Tpmt*`/`Tpmi*` types.
    pub(crate) const fn tag(self) -> isize {
        self.0 as isize
    }

    pub const NULL: Self = Self::new(0x8000);
    pub const NO_SESSIONS: Self = Self::new(0x8001);
    pub const SESSIONS: Self = Self::new(0x8002);
    pub const ATTEST_NV: Self = Self::new(0x8014);
    pub const ATTEST_COMMAND_AUDIT: Self = Self::new(0x8015);
    pub const ATTEST_SESSION_AUDIT: Self = Self::new(0x8016);
    pub const ATTEST_CERTIFY: Self = Self::new(0x8017);
    pub const ATTEST_QUOTE: Self = Self::new(0x8018);
    pub const ATTEST_TIME: Self = Self::new(0x8019);
    pub const ATTEST_CREATION: Self = Self::new(0x801A);
    pub const ATTEST_NV_DIGEST: Self = Self::new(0x801C);
    pub const CREATION: Self = Self::new(0x8021);
    pub const VERIFIED: Self = Self::new(0x8022);
    pub const AUTH_SECRET: Self = Self::new(0x8023);
    pub const HASHCHECK: Self = Self::new(0x8024);
    pub const AUTH_SIGNED: Self = Self::new(0x8025);
    pub const MESSAGE_VERIFIED: Self = Self::new(0x8026);
    pub const DIGEST_VERIFIED: Self = Self::new(0x8027);
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

/// `TPM_SU` (Startup Type) defined in TPM 2.0 Part 2: Structures, Section 6.11 (Table 18).
///
/// Indicates the startup and shutdown type for the TPM:
/// - [`Clear`](Self::Clear) (`TPM_SU_CLEAR`): Full cold restart or state reset.
/// - [`State`](Self::State) (`TPM_SU_STATE`): Restores previously saved TPM state.
///
/// Passed as a parameter to `TPM2_Startup` and `TPM2_Shutdown`.
#[doc(alias = "TPM_SU")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmSu {
    #[default]
    Clear = 0x0000,
    State = 0x0001,
}

impl TryFrom<u16> for TpmSu {
    type Error = UnmarshalError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0000 => Ok(Self::Clear),
            0x0001 => Ok(Self::State),
            _ => Err(UnmarshalError),
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

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u16::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmSu {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u16::unmarshal(src)?.try_into()
    }
}

/// `TPM_SE` (Session Type) defined in TPM 2.0 Part 2: Structures, Section 6.12 (Table 19).
///
/// Selects the authorization session type:
/// - [`HMAC`](Self::HMAC) (`TPM_SE_HMAC`): Authorization session using HMAC.
/// - [`Policy`](Self::Policy) (`TPM_SE_POLICY`): Authorization session evaluated against policy assertions.
/// - [`Trial`](Self::Trial) (`TPM_SE_TRIAL`): Trial policy session used to compute a policy digest without verifying authorizations.
///
/// Passed to `TPM2_StartAuthSession`.
#[doc(alias = "TPM_SE")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmSe {
    #[default]
    HMAC = 0x00,
    Policy = 0x01,
    Trial = 0x03,
}

impl TryFrom<u8> for TpmSe {
    type Error = UnmarshalError;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x00 => Ok(Self::HMAC),
            0x01 => Ok(Self::Policy),
            0x03 => Ok(Self::Trial),
            _ => Err(UnmarshalError),
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

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u8::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmSe {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u8::unmarshal(src)?.try_into()
    }
}

/// `TPM_CAP` (Capabilities) defined in TPM 2.0 Part 2: Structures, Section 6.13 (Table 20).
///
/// Selects the capability category queried in `TPM2_GetCapability` and `TPM2_TestParms`,
/// and acts as the selector tag for `TPMS_CAPABILITY_DATA`.
#[doc(alias = "TPM_CAP")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmCap {
    #[default]
    Algs = 0x00000000,
    Handles = 0x00000001,
    Commands = 0x00000002,
    PPCommands = 0x00000003,
    AuditCommands = 0x00000004,
    PCRs = 0x00000005,
    TPMProperties = 0x00000006,
    PCRProperties = 0x00000007,
    ECCCurves = 0x00000008,
    AuthPolicies = 0x00000009,
    ACT = 0x0000000A,
    PubKeys = 0x0000000B,
    SpdmSessionInfo = 0x0000000C,
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
            _ => Err(UnmarshalError),
        }
    }
}
impl From<TpmCap> for u32 {
    fn from(value: TpmCap) -> Self {
        value as u32
    }
}

impl Marshal for TpmCap {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u32::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmCap {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u32::unmarshal(src)?.try_into()
    }
}

/// `TPM_PT` (TPM Properties) defined in TPM 2.0 Part 2: Structures, Section 6.14 (Table 21).
///
/// Identifies properties queried using `TPM2_GetCapability` with `capability = TPM_CAP_TPM_PROPERTIES` ([`TpmCap::TPMProperties`]).
/// Properties are divided into fixed/invariant properties (`PT_FIXED`, group 1) and variable properties (`PT_VAR`, group 2).
#[doc(alias = "TPM_PT")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmPt {
    // a 4-octet character string containing the TPM Family value
    // (TPM_SPEC_FAMILY)
    #[default]
    FamilyIndicator = 0x00000100,
    // the level of the specification
    Level = 0x00000101,
    // the specification Revision times 100
    Revision = 0x00000102,
    // the specification day of year using TCG calendar
    DayofYear = 0x00000103,
    // the specification year using the CE
    Year = 0x00000104,
    // the vendor ID unique to each TPM manufacturer
    Manufacturer = 0x00000105,
    // the first four characters of the vendor ID string
    VendorString1 = 0x00000106,
    // the second four characters of the vendor ID string
    VendorString2 = 0x00000107,
    // the third four characters of the vendor ID string
    VendorString3 = 0x00000108,
    // the fourth four characters of the vendor ID string
    VendorString4 = 0x00000109,
    // vendor-defined value indicating the TPM model
    VendorTPMType = 0x0000010A,
    // the most-significant 32 bits of a TPM vendor-specific value
    // indicating the version number of the firmware.
    FirmwareVersion1 = 0x0000010B,
    // the least-significant 32 bits of a TPM vendor-specific value
    // indicating the version number of the firmware.
    FirmwareVersion2 = 0x0000010C,
    // the maximum size of a parameter (TPM2B_MAX_BUFFER)
    InputBuffer = 0x0000010D,
    // the minimum number of transient objects that can be held in TPM RAM
    HRTransientMin = 0x0000010E,
    // the minimum number of persistent objects that can be held in TPM NV
    // memory
    HRPersistentMin = 0x0000010F,
    // the minimum number of authorization sessions that can be held in TPM
    // RAM
    HRLoadedMin = 0x00000110,
    // the number of authorization sessions that may be active at a time
    ActiveSessionsMax = 0x00000111,
    // the number of PCR implemented
    PCRCount = 0x00000112,
    // the minimum number of octets in a TPMS_PCR_SELECT.sizeOfSelect
    PCRSelectMin = 0x00000113,
    // the maximum allowed difference (unsigned) between the contextID
    // values of two saved session contexts
    ContextGapMax = 0x00000114,
    // the maximum number of NV Indexes that are allowed to have the
    // TPM_NT_COUNTER attribute
    NVCountersMax = 0x00000116,
    // the maximum size of an NV Index data area
    NVIndexMax = 0x00000117,
    // a TPMA_MEMORY indicating the memory management method for the TPM
    Memory = 0x00000118,
    // interval, in milliseconds, between updates to the copy of
    // TPMS_CLOCK_INFO.clock in NV
    ClockUpdate = 0x00000119,
    // the algorithm used for the integrity HMAC on saved contexts and for
    // hashing the fuData of TPM2_FirmwareRead()
    ContextHash = 0x0000011A,
    // TPM_ALG_ID, the algorithm used for encryption of saved contexts
    ContextSym = 0x0000011B,
    // TPM_KEY_BITS, the size of the key used for encryption of saved contexts
    ContextSymSize = 0x0000011C,
    // the modulus - 1 of the count for NV update of an orderly counter
    OrderlyCount = 0x0000011D,
    // the maximum value for commandSize in a command
    MaxCommandSize = 0x0000011E,
    // the maximum value for responseSize in a response
    MaxResponseSize = 0x0000011F,
    // the maximum size of a digest that can be produced by the TPM
    MaxDigest = 0x00000120,
    // the maximum size of an object context that will be returned by
    // TPM2_ContextSave
    MaxObjectContext = 0x00000121,
    // the maximum size of a session context that will be returned by
    // TPM2_ContextSave
    MaxSessionContext = 0x00000122,
    // platform-specific family (a TPM_PS value)(see Table 25)
    PSFamilyIndicator = 0x00000123,
    // the level of the platform-specific specification
    PSLevel = 0x00000124,
    // a platform specific value
    PSRevision = 0x00000125,
    // the platform-specific TPM specification day of year using TCG
    // calendar
    PSDayOfYear = 0x00000126,
    // the platform-specific TPM specification year using the CE
    PSYear = 0x00000127,
    // the number of split signing operations supported by the TPM
    SplitMax = 0x00000128,
    // total number of commands implemented in the TPM
    TotalCommands = 0x00000129,
    // number of commands from the TPM library that are implemented
    LibraryCommands = 0x0000012A,
    // number of vendor commands that are implemented
    VendorCommands = 0x0000012B,
    // the maximum data size in one NV write, NV read, NV extend, or NV
    // certify command
    NVBufferMax = 0x0000012C,
    // a TPMA_MODES value, indicating that the TPM is designed for these
    // modes.
    Modes = 0x0000012D,
    // the maximum size of a TPMS_CAPABILITY_DATA structure returned in
    // TPM2_GetCapability().
    MaxCapBuffer = 0x0000012E,
    // TPMA_PERMANENT
    Permanent = 0x00000200,
    // TPMA_STARTUP_CLEAR
    StartupClear = 0x00000201,
    // the number of NV Indexes currently defined
    HRNVIndex = 0x00000202,
    // the number of authorization sessions currently loaded into TPM RAM
    HRLoaded = 0x00000203,
    // the number of additional authorization sessions, of any type, that
    // could be loaded into TPM RAM
    HRLoadedAvail = 0x00000204,
    // the number of active authorization sessions currently being tracked
    // by the TPM
    HRActive = 0x00000205,
    // the number of additional authorization sessions, of any type, that
    // could be created
    HRActiveAvail = 0x00000206,
    // estimate of the number of additional transient objects that could be
    // loaded into TPM RAM
    HRTransientAvail = 0x00000207,
    // the number of persistent objects currently loaded into TPM NV memory
    HRPersistent = 0x00000208,
    // the number of additional persistent objects that could be loaded into
    // NV memory
    HRPersistentAvail = 0x00000209,
    // the number of defined NV Indexes that have the TPM_NT_COUNTER
    // attribute
    NVCounters = 0x0000020A,
    // the number of additional NV Indexes that can be defined with their
    // TPM_NT of TPM_NV_COUNTER and the TPMA_NV_ORDERLY attribute SET
    NVCountersAvail = 0x0000020B,
    // code that limits the algorithms that may be used with the TPM
    AlgorithmSet = 0x0000020C,
    // the number of loaded ECC curves
    LoadedCurves = 0x0000020D,
    // the current value of the lockout counter (failedTries)
    LockoutCounter = 0x0000020E,
    // the number of authorization failures before DA lockout is invoked
    MaxAuthFail = 0x0000020F,
    // the number of seconds before the value reported by
    // TPM_PT_LOCKOUT_COUNTER is decremented
    LockoutInterval = 0x00000210,
    // the number of seconds after a lockoutAuth failure before use of
    // lockoutAuth may be attempted again
    LockoutRecovery = 0x00000211,
    // number of milliseconds before the TPM will accept another command
    // that will modify NV
    NVWriteRecovery = 0x00000212,
    // the high-order 32 bits of the command audit counter
    AuditCounter0 = 0x00000213,
    // the low-order 32 bits of the command audit counter
    AuditCounter1 = 0x00000214,
}

impl TryFrom<u32> for TpmPt {
    type Error = UnmarshalError;
    fn try_from(val: u32) -> Result<Self, Self::Error> {
        match val {
            0x00000100 => Ok(Self::FamilyIndicator),
            0x00000101 => Ok(Self::Level),
            0x00000102 => Ok(Self::Revision),
            0x00000103 => Ok(Self::DayofYear),
            0x00000104 => Ok(Self::Year),
            0x00000105 => Ok(Self::Manufacturer),
            0x00000106 => Ok(Self::VendorString1),
            0x00000107 => Ok(Self::VendorString2),
            0x00000108 => Ok(Self::VendorString3),
            0x00000109 => Ok(Self::VendorString4),
            0x0000010A => Ok(Self::VendorTPMType),
            0x0000010B => Ok(Self::FirmwareVersion1),
            0x0000010C => Ok(Self::FirmwareVersion2),
            0x0000010D => Ok(Self::InputBuffer),
            0x0000010E => Ok(Self::HRTransientMin),
            0x0000010F => Ok(Self::HRPersistentMin),
            0x00000110 => Ok(Self::HRLoadedMin),
            0x00000111 => Ok(Self::ActiveSessionsMax),
            0x00000112 => Ok(Self::PCRCount),
            0x00000113 => Ok(Self::PCRSelectMin),
            0x00000114 => Ok(Self::ContextGapMax),
            0x00000116 => Ok(Self::NVCountersMax),
            0x00000117 => Ok(Self::NVIndexMax),
            0x00000118 => Ok(Self::Memory),
            0x00000119 => Ok(Self::ClockUpdate),
            0x0000011A => Ok(Self::ContextHash),
            0x0000011B => Ok(Self::ContextSym),
            0x0000011C => Ok(Self::ContextSymSize),
            0x0000011D => Ok(Self::OrderlyCount),
            0x0000011E => Ok(Self::MaxCommandSize),
            0x0000011F => Ok(Self::MaxResponseSize),
            0x00000120 => Ok(Self::MaxDigest),
            0x00000121 => Ok(Self::MaxObjectContext),
            0x00000122 => Ok(Self::MaxSessionContext),
            0x00000123 => Ok(Self::PSFamilyIndicator),
            0x00000124 => Ok(Self::PSLevel),
            0x00000125 => Ok(Self::PSRevision),
            0x00000126 => Ok(Self::PSDayOfYear),
            0x00000127 => Ok(Self::PSYear),
            0x00000128 => Ok(Self::SplitMax),
            0x00000129 => Ok(Self::TotalCommands),
            0x0000012A => Ok(Self::LibraryCommands),
            0x0000012B => Ok(Self::VendorCommands),
            0x0000012C => Ok(Self::NVBufferMax),
            0x0000012D => Ok(Self::Modes),
            0x0000012E => Ok(Self::MaxCapBuffer),
            0x00000200 => Ok(Self::Permanent),
            0x00000201 => Ok(Self::StartupClear),
            0x00000202 => Ok(Self::HRNVIndex),
            0x00000203 => Ok(Self::HRLoaded),
            0x00000204 => Ok(Self::HRLoadedAvail),
            0x00000205 => Ok(Self::HRActive),
            0x00000206 => Ok(Self::HRActiveAvail),
            0x00000207 => Ok(Self::HRTransientAvail),
            0x00000208 => Ok(Self::HRPersistent),
            0x00000209 => Ok(Self::HRPersistentAvail),
            0x0000020A => Ok(Self::NVCounters),
            0x0000020B => Ok(Self::NVCountersAvail),
            0x0000020C => Ok(Self::AlgorithmSet),
            0x0000020D => Ok(Self::LoadedCurves),
            0x0000020E => Ok(Self::LockoutCounter),
            0x0000020F => Ok(Self::MaxAuthFail),
            0x00000210 => Ok(Self::LockoutInterval),
            0x00000211 => Ok(Self::LockoutRecovery),
            0x00000212 => Ok(Self::NVWriteRecovery),
            0x00000213 => Ok(Self::AuditCounter0),
            0x00000214 => Ok(Self::AuditCounter1),
            _ => Err(UnmarshalError),
        }
    }
}
impl From<TpmPt> for u32 {
    fn from(val: TpmPt) -> Self {
        val as u32
    }
}

impl Marshal for TpmPt {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u32::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmPt {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u32::unmarshal(src)?.try_into()
    }
}

/// `TPM_PT_PCR` (PCR Properties) defined in TPM 2.0 Part 2: Structures, Section 6.15 (Table 22).
///
/// Defines PCR property tags queried using `TPM2_GetCapability` with `capability = TPM_CAP_PCR_PROPERTIES` ([`TpmCap::PCRProperties`]).
/// Each tag identifies a bit position in a `TPMS_PCR_SELECT` bitmap indicating attributes and behavior of the selected PCRs.
#[doc(alias = "TPM_PT_PCR")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmPtPcr {
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR is saved and
    // restored by TPM_SU_STATE
    #[default]
    Save = 0x00000000,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
    // extended from locality 0
    ExtendL0 = 0x00000001,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
    // by TPM2_PCR_Reset() from locality 0
    ResetL0 = 0x00000002,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
    // extended from locality 1
    ExtendL1 = 0x00000003,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
    // by TPM2_PCR_Reset() from locality 1
    ResetL1 = 0x00000004,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
    // extended from locality 2
    ExtendL2 = 0x00000005,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
    // by TPM2_PCR_Reset() from locality 2
    ResetL2 = 0x00000006,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
    // extended from locality 3
    ExtendL3 = 0x00000007,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
    // by TPM2_PCR_Reset() from locality 3
    ResetL3 = 0x00000008,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
    // extended from locality 4
    ExtendL4 = 0x00000009,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
    // by TPM2_PCR_Reset() from locality 4
    ResetL4 = 0x0000000A,
    // a SET bit in the TPMS_PCR_SELECT indicates that modifications to this
    // PCR (reset or Extend) will not increment the pcrUpdateCounter
    NoIncrement = 0x00000011,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR is reset by a
    // D-RTM event
    DRTMReset = 0x00000012,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled
    // by policy
    Policy = 0x00000013,
    // a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled
    // by an authorization value
    Auth = 0x00000014,
}

impl TryFrom<u32> for TpmPtPcr {
    type Error = UnmarshalError;
    fn try_from(val: u32) -> Result<Self, Self::Error> {
        match val {
            0x00000000 => Ok(Self::Save),
            0x00000001 => Ok(Self::ExtendL0),
            0x00000002 => Ok(Self::ResetL0),
            0x00000003 => Ok(Self::ExtendL1),
            0x00000004 => Ok(Self::ResetL1),
            0x00000005 => Ok(Self::ExtendL2),
            0x00000006 => Ok(Self::ResetL2),
            0x00000007 => Ok(Self::ExtendL3),
            0x00000008 => Ok(Self::ResetL3),
            0x00000009 => Ok(Self::ExtendL4),
            0x0000000A => Ok(Self::ResetL4),
            0x00000011 => Ok(Self::NoIncrement),
            0x00000012 => Ok(Self::DRTMReset),
            0x00000013 => Ok(Self::Policy),
            0x00000014 => Ok(Self::Auth),
            _ => Err(UnmarshalError),
        }
    }
}
impl From<TpmPtPcr> for u32 {
    fn from(val: TpmPtPcr) -> Self {
        val as u32
    }
}

impl Marshal for TpmPtPcr {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u32::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmPtPcr {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u32::unmarshal(src)?.try_into()
    }
}

/// `TPM_HT` (Handle Types) defined in TPM 2.0 Part 2: Structures, Section 6.7 (Table 13).
///
/// Represents the handle type encoded in the most significant byte (bits 31..24) of a 32-bit TPM handle ([`Handle`]).
/// Used to classify handles (PCRs, NV Indices, HMAC/Policy sessions, Permanent handles, Transient/Persistent objects).
#[doc(alias = "TPM_HT")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmHt {
    #[default]
    PCR = 0x00,
    NVIndex = 0x01,
    HMACSession = 0x02,
    PolicySession = 0x03,
    Permanent = 0x40,
    Transient = 0x80,
    Persistent = 0x81,
    AC = 0x90,
}

impl TryFrom<u8> for TpmHt {
    type Error = UnmarshalError;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x00 => Ok(Self::PCR),
            0x01 => Ok(Self::NVIndex),
            0x02 => Ok(Self::HMACSession),
            0x03 => Ok(Self::PolicySession),
            0x40 => Ok(Self::Permanent),
            0x80 => Ok(Self::Transient),
            0x81 => Ok(Self::Persistent),
            0x90 => Ok(Self::AC),
            _ => Err(UnmarshalError),
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

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u8::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmHt {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u8::unmarshal(src)?.try_into()
    }
}

/// `TPM_HANDLE`, `TPM_RH`, and `TPM_HC` defined in TPM 2.0 Part 2: Structures, Section 7 (Tables 28–30) and Section 9 (Tables 40–50).
///
/// Represents 32-bit numeric handles used to reference TPM resources (transient/persistent objects,
/// NV indices, PCRs, authorization sessions, and permanent reserved handles such as `RH_OWNER`, `RH_PLATFORM`, `RH_NULL`).
/// The top 8 bits determine the handle type ([`TpmHt`]).
#[doc(alias = "TPM_HANDLE")]
#[doc(alias = "TPM_RH")]
#[doc(alias = "TPM_HC")]
#[doc(alias = "TPMI_DH_OBJECT")]
#[doc(alias = "TPMI_DH_PARENT")]
#[doc(alias = "TPMI_DH_PERSISTENT")]
#[doc(alias = "TPMI_DH_ENTITY")]
#[doc(alias = "TPMI_DH_PCR")]
#[doc(alias = "TPMI_SH_AUTH_SESSION")]
#[doc(alias = "TPMI_DH_CONTEXT")]
#[doc(alias = "TPMI_RH_HIERARCHY")]
#[doc(alias = "TPMI_RH_NV_INDEX")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Handle(pub u32);

impl Handle {
    pub fn handle_type(self) -> Option<TpmHt> {
        ((self.0 >> 24) as u8).try_into().ok()
    }

    pub const NV_INDEX_FIRST: Handle = Handle(0x01000000);
    pub const NV_INDEX_LAST: Handle = Handle(0x01FFFFFF);
    pub const RH_OWNER: Handle = Handle(0x40000001);
    pub const RH_NULL: Handle = Handle(0x40000007);
    pub const RS_PW: Handle = Handle(0x40000009);
    pub const RH_LOCKOUT: Handle = Handle(0x4000000A);
    pub const RH_ENDORSEMENT: Handle = Handle(0x4000000B);
    pub const RH_PLATFORM: Handle = Handle(0x4000000C);
    pub const RH_PLATFORM_NV: Handle = Handle(0x4000000D);
    pub const RH_FW_OWNER: Handle = Handle(0x40000140);
    pub const RH_FW_ENDORSEMENT: Handle = Handle(0x40000141);
    pub const RH_FW_PLATFORM: Handle = Handle(0x40000142);
    pub const RH_FW_NULL: Handle = Handle(0x40000143);
    pub const RH_SVN_OWNER_BASE: Handle = Handle(0x40010000);
    pub const RH_SVN_ENDORSEMENT_BASE: Handle = Handle(0x40020000);
    pub const RH_SVN_PLATFORM_BASE: Handle = Handle(0x40030000);
    pub const RH_SVN_NULL_BASE: Handle = Handle(0x40040000);
}

impl Marshal for Handle {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for Handle {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Unmarshal::unmarshal(src).map(Self)
    }
}

/// `TPM_NT` (NV Index Types) defined in TPM 2.0 Part 2: Structures, Section 13.4 (Table 206).
///
/// Encoded in bits 7:4 of `TPMA_NV` attributes to define the type and behavior of an NV Index
/// (Ordinary data blob, Counter, Bitfield, Extend digest, or PIN counter).
#[doc(alias = "TPM_NT")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmNt {
    // contains data that is opaque to the TPM that can only be modified
    // using TPM2_NV_Write().
    #[default]
    Ordinary = 0x0,
    // contains an 8-octet value that is to be used as a counter and can
    // only be modified with TPM2_NV_Increment()
    Counter = 0x1,
    // contains an 8-octet value to be used as a bit field and can only be
    // modified with TPM2_NV_SetBits().
    Bits = 0x2,
    // contains a digest-sized value used like a PCR. The Index can only be
    // modified using TPM2_NV_Extend(). The extend will use the nameAlg of
    // the Index.
    Extend = 0x4,
    // contains pinCount that increments on a PIN authorization failure and
    // a pinLimit
    PinFail = 0x8,
    // contains pinCount that increments on a PIN authorization success and
    // a pinLimit
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
            _ => Err(UnmarshalError),
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

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        u8::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmNt {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        u8::unmarshal(src)?.try_into()
    }
}

/// `TPM_CLOCK_ADJUST` defined in TPM 2.0 Part 2: Structures, Section 6.8 (Table 15).
///
/// Represents the adjustment steps (-3 to +3) passed to `TPM2_ClockRateAdjust` to calibrate
/// the TPM Clock update rate relative to external reference time without disrupting the clock epoch.
#[doc(alias = "TPM_CLOCK_ADJUST")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TpmClockAdjust {
    /// Slow the Clock update rate by one coarse adjustment step (-3).
    CoarseSlower = -3,
    /// Slow the Clock update rate by one medium adjustment step (-2).
    MediumSlower = -2,
    /// Slow the Clock update rate by one fine adjustment step (-1).
    FineSlower = -1,
    /// No change to the Clock update rate (0).
    #[default]
    NoChange = 0,
    /// Speed the Clock update rate by one fine adjustment step (1).
    FineFaster = 1,
    /// Speed the Clock update rate by one medium adjustment step (2).
    MediumFaster = 2,
    /// Speed the Clock update rate by one coarse adjustment step (3).
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
            _ => Err(UnmarshalError),
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

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        i8::from(*self).marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmClockAdjust {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        i8::unmarshal(src)?.try_into()
    }
}

/// `TPM_GENERATED` defined in TPM 2.0 Part 2: Structures, Section 6.6 (Table 12).
///
/// Constant 4-byte magic value (`\xffTCG` / `0xFF544347`) placed at the start of attestation
/// structures (such as `TPMS_ATTEST`) to indicate that the structure was generated by the TPM.
#[doc(alias = "TPM_GENERATED")]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct TpmGenerated;
impl TpmGenerated {
    pub const VALUE: [u8; 4] = *b"\xffTCG";
}

impl Marshal for TpmGenerated {
    const MAX_SIZE: usize = 4;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        Self::VALUE.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for TpmGenerated {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        match Unmarshal::unmarshal(src)? {
            Self::VALUE => Ok(Self),
            _ => Err(UnmarshalError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_eo_size_and_conversions() {
        assert_eq!(core::mem::size_of::<TpmEo>(), 1);
        assert_eq!(u16::from(TpmEo::Eq), 0x0000);
        assert_eq!(u16::from(TpmEo::BitClear), 0x000B);
        assert_eq!(TpmEo::try_from(0x0000), Ok(TpmEo::Eq));
        assert_eq!(TpmEo::try_from(0x000B), Ok(TpmEo::BitClear));
        assert!(TpmEo::try_from(0x000C).is_err());
    }

    #[test]
    fn test_tpm_cap_size_and_conversions() {
        assert_eq!(core::mem::size_of::<TpmCap>(), 1);
        assert_eq!(u32::from(TpmCap::Algs), 0x00000000);
        assert_eq!(u32::from(TpmCap::ACT), 0x0000000A);
        assert_eq!(u32::from(TpmCap::PubKeys), 0x0000000B);
        assert_eq!(u32::from(TpmCap::SpdmSessionInfo), 0x0000000C);

        assert_eq!(TpmCap::try_from(0x00000000), Ok(TpmCap::Algs));
        assert_eq!(TpmCap::try_from(0x0000000C), Ok(TpmCap::SpdmSessionInfo));
        assert!(TpmCap::try_from(0x0000000D).is_err());
        assert!(TpmCap::try_from(0x00000100).is_err());
    }

    #[test]
    fn test_tpm_cap_marshal_unmarshal() {
        let mut buf = [0u8; 4];
        let len = TpmCap::SpdmSessionInfo.marshal(&mut buf);
        assert_eq!(len, 4);
        assert_eq!(buf, [0x00, 0x00, 0x00, 0x0C]);

        let mut slice: &[u8] = &buf;
        let cap = TpmCap::unmarshal(&mut slice).unwrap();
        assert_eq!(cap, TpmCap::SpdmSessionInfo);
        assert!(slice.is_empty());
    }

    #[test]
    fn test_alg_debug_formatting() {
        assert_eq!(format!("{:?}", Alg::RSA), "Alg::RSA");
        assert_eq!(format!("{:?}", Alg::SHA256), "Alg::SHA256");
        assert_eq!(format!("{:?}", Alg::NULL), "Alg::NULL");
        assert_eq!(format!("{:?}", Alg::KEYEDHASH), "Alg::KEYEDHASH");
        assert_eq!(format!("{:?}", Alg::SYMCIPHER), "Alg::SYMCIPHER");
        assert_eq!(format!("{:?}", Alg::SM3_256), "Alg::SM3_256");
        assert_eq!(format!("{:?}", Alg::KDF1_SP800_56A), "Alg::KDF1_SP800_56A");
        assert_eq!(format!("{:?}", Alg::ECSCHNORR), "Alg::ECSCHNORR");
        assert_eq!(format!("{:?}", Alg::MLKEM), "Alg::MLKEM");
        assert_eq!(format!("{:?}", Alg::MLDSA), "Alg::MLDSA");
        assert_eq!(format!("{:?}", Alg::HASH_MLDSA), "Alg::HASH_MLDSA");
        assert_eq!(format!("{:?}", Alg::EDDSA), "Alg::EDDSA");
        assert_eq!(format!("{:?}", Alg::HASH_EDDSA), "Alg::HASH_EDDSA");
        assert_eq!(format!("{:?}", Alg::new(0x1234)), "Alg(0x1234)");
    }

    #[test]
    fn test_tpm_ecc_curve_conversions() {
        assert_eq!(core::mem::size_of::<TpmEccCurve>(), 1);
        assert_eq!(u16::from(TpmEccCurve::NistP192), 0x0001);
        assert_eq!(u16::from(TpmEccCurve::BpP256R1), 0x0030);
        assert_eq!(u16::from(TpmEccCurve::Curve448), 0x0041);
        assert_eq!(TpmEccCurve::try_from(0x0001), Ok(TpmEccCurve::NistP192));
        assert_eq!(TpmEccCurve::try_from(0x0030), Ok(TpmEccCurve::BpP256R1));
        assert_eq!(TpmEccCurve::try_from(0x0041), Ok(TpmEccCurve::Curve448));
        assert!(TpmEccCurve::try_from(0x0000).is_err());
        assert!(TpmEccCurve::try_from(0x0042).is_err());
    }

    #[test]
    fn test_tpm_pt_pcr_conversions() {
        assert_eq!(core::mem::size_of::<TpmPtPcr>(), 1);
        assert_eq!(u32::from(TpmPtPcr::Save), 0x00000000);
        assert_eq!(u32::from(TpmPtPcr::DRTMReset), 0x00000012);
        assert_eq!(u32::from(TpmPtPcr::Auth), 0x00000014);
        assert_eq!(TpmPtPcr::try_from(0x00000000), Ok(TpmPtPcr::Save));
        assert_eq!(TpmPtPcr::try_from(0x00000012), Ok(TpmPtPcr::DRTMReset));
        assert_eq!(TpmPtPcr::try_from(0x00000014), Ok(TpmPtPcr::Auth));
        assert!(TpmPtPcr::try_from(0x0000000B).is_err());
    }

    #[test]
    fn test_tpm_pt_conversions() {
        assert_eq!(core::mem::size_of::<TpmPt>(), 2);
        assert_eq!(u32::from(TpmPt::FamilyIndicator), 0x00000100);
        assert_eq!(u32::from(TpmPt::AuditCounter1), 0x00000214);
        assert_eq!(TpmPt::try_from(0x00000100), Ok(TpmPt::FamilyIndicator));
        assert_eq!(TpmPt::try_from(0x00000214), Ok(TpmPt::AuditCounter1));
        assert!(TpmPt::try_from(0x00000000).is_err());
    }

    #[test]
    fn test_tpm_nt_and_clock_adjust_conversions() {
        assert_eq!(core::mem::size_of::<TpmNt>(), 1);
        assert_eq!(u8::from(TpmNt::Ordinary), 0x0);
        assert_eq!(u8::from(TpmNt::PinPass), 0x9);
        assert_eq!(TpmNt::try_from(0x0), Ok(TpmNt::Ordinary));
        assert_eq!(TpmNt::try_from(0x9), Ok(TpmNt::PinPass));
        assert!(TpmNt::try_from(0x3).is_err());

        assert_eq!(core::mem::size_of::<TpmClockAdjust>(), 1);
        assert_eq!(i8::from(TpmClockAdjust::CoarseSlower), -3);
        assert_eq!(i8::from(TpmClockAdjust::NoChange), 0);
        assert_eq!(i8::from(TpmClockAdjust::CoarseFaster), 3);
        assert_eq!(
            TpmClockAdjust::try_from(-3),
            Ok(TpmClockAdjust::CoarseSlower)
        );
        assert_eq!(TpmClockAdjust::try_from(0), Ok(TpmClockAdjust::NoChange));
        assert_eq!(
            TpmClockAdjust::try_from(3),
            Ok(TpmClockAdjust::CoarseFaster)
        );
        assert!(TpmClockAdjust::try_from(4).is_err());
    }

    #[test]
    fn test_handle_and_tpm_st_constants() {
        assert_eq!(Handle::RH_OWNER.0, 0x40000001);
        assert_eq!(Handle::RH_OWNER.handle_type(), Some(TpmHt::Permanent));
        assert_eq!(Handle(0x00000001).handle_type(), Some(TpmHt::PCR));
        assert_eq!(Handle(0x01000001).handle_type(), Some(TpmHt::NVIndex));
        assert_eq!(Handle(0x02000001).handle_type(), Some(TpmHt::HMACSession));
        assert_eq!(Handle(0x03000001).handle_type(), Some(TpmHt::PolicySession));
        assert_eq!(Handle(0x80000001).handle_type(), Some(TpmHt::Transient));
        assert_eq!(Handle(0x81000001).handle_type(), Some(TpmHt::Persistent));
        assert_eq!(Handle(0x90000001).handle_type(), Some(TpmHt::AC));
        assert_eq!(Handle(0xFF000001).handle_type(), None);

        assert_eq!(TpmSt::NULL.id(), 0x8000);
        assert_eq!(TpmSt::NO_SESSIONS.id(), 0x8001);
        assert_eq!(TpmSt::SESSIONS.id(), 0x8002);
        assert_eq!(TpmSt::MESSAGE_VERIFIED.id(), 0x8026);
        assert_eq!(TpmSt::DIGEST_VERIFIED.id(), 0x8027);
        assert_eq!(TpmSt::FU_MANIFEST.id(), 0x8029);

        assert_eq!(Alg::default(), Alg::NULL);
        assert_eq!(TpmSt::default(), TpmSt::NULL);
        assert_eq!(TpmPtPcr::default(), TpmPtPcr::Save);
        assert_eq!(TpmHt::default(), TpmHt::PCR);
    }
}
