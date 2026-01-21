#![allow(dead_code, clippy::large_enum_variant)]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

use crate::marshal::{Marshalable, MarshalableVariant, Tpm2bStruct, UnmarshalBuf};
use crate::{constants::*, errors::*};
use bitflags::bitflags;
use core::cmp::min;
use core::convert::{From, TryFrom};
use core::mem::size_of;
use open_enum::open_enum;
use safe_discriminant::Discriminant;
pub use tpm2_rs_errors as errors;
pub use tpm2_rs_marshalable as marshal;
use tpm2_rs_unionify::UnionSize;

pub mod commands;
pub mod constants;

/// Returns an attribute field built by applying the mask/shift to the value.
const fn new_attribute_field(value: u32, mask: u32, shift: u32) -> u32 {
    (value << shift) & mask
}
/// Returns the attribute field retrieved from the value with the mask/shift.
const fn get_attribute_field(value: u32, mask: u32, shift: u32) -> u32 {
    (value & mask) >> shift
}
/// Sets the attribute field defined by mask/shift in the value to the field value, and returns the result.
const fn set_attribute_field(value: u32, field_value: u32, mask: u32, shift: u32) -> u32 {
    (value & !mask) | new_attribute_field(field_value, mask, shift)
}

/// TpmaLocality represents the locality attribute (TPMA_LOCALITY).
/// See definition in Part 2: Structures, section 8.5.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmaLocality(pub u8);
bitflags! {
    impl TpmaLocality : u8 {
        const LOC_ZERO = 1 << 0;
        const LOC_ONE = 1 << 1;
        const LOC_TWO = 1 << 2;
        const LOC_THREE = 1 << 3;
        const LOC_FOUR = 1 << 4;
        // If any other bits are set, an extended locality is indicated.
        const _ = !0;
    }
}
impl TpmaLocality {
    const EXTENDED_LOCALITY_MASK: u8 = 0xE0;
    /// Returns whether this attribute indicates an extended locality.
    fn is_extended(&self) -> bool {
        (self.0 & Self::EXTENDED_LOCALITY_MASK) != 0
    }
}

/// TpmNv represents the NV index attributes (TPMA_NV).
/// See definition in Part 2: Structures, section 13.4.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmaNv(pub u32);
bitflags! {
    impl TpmaNv : u32 {
        /// Whether the index data can be written if platform authorization is provided.
        const PPWRITE = 1 << 0;
        /// Whether the index data can be written if owner authorization is provided.
        const OWNERWRITE = 1 <<  1;
        /// Whether authorizations to change the index contents that require USER role may be provided with an HMAC session or password.
        const AUTHWRITE = 1 << 2;
        /// Whether authorizations to change the index contents that require USER role may be provided with a policy session.
        const POLICYWRITE = 1 << 3;
        /// If set, the index may not be deteled unless the auth_policy is satisfied using nv_undefined_space_special.
        /// If clear, the index may be deleted with proper platform/owner authorization using nv_undefine_space.
        const POLICY_DELETE = 1 << 10;
        /// Whether the index can NOT be written.
        const WRITELOCKED = 1 << 11;
        /// Whether a partial write of the index data is NOT allowed.
        const WRITEALL = 1 << 12;
        /// Whether nv_write_lock may be used to prevent futher writes to this location.
        const WRITEDEFINE = 1 << 13;
        /// Whether nv_write_lock may be used to prevent further writes to this location until the next TPM reset/restart.
        const WRITE_STCLEAR = 1 << 14;
        /// Whether WRITELOCKED is set if nv_global_write_lock is successful.
        const GLOBALLOCK = 1 << 15;
        /// Whether the index data can be read if platform authorization is provided.
        const PPREAD = 1 << 16;
        /// Whether the index data can be read if owner authorization is provided.
        const OWNERREAD = 1 << 17;
        /// Whether the index data can be read if auth_value is provided.
        const AUTHREAD = 1 << 18;
        /// Whether the index data can be read if the auth_policy is satisfied.
        const POLICYREAD = 1 << 19;
        /// If set, authorizationn failures of the index do not affect the DA logic and authorization of the index is not blocked when the TPM is in Lockout mode.
        /// If clear, authorization failures of the index will increment the authorization failure counter and authorizations of this index are not allowed when the TPM is in Lockout mode.
        const NO_DA = 1 << 25;
        /// Whether NV index state is required to be saved only when the TPM performs an orderly shutdown.
        const ORDERLY = 1 << 26;
        /// Whether WRITTEN is cleared by TPM reset/restart.
        const CLEAR_STCLEAR = 1 << 27;
        /// Whether reads of the index are blocked  until the next TPM reset/restart.
        const READLOCKED = 1 << 28;
        /// Whether the index has been written.
        const WRITTEN = 1 << 29;
        /// If set, the index may be undefined with platform authorization but not owner authorization.
        /// If clear, the index may be undefined with owner authorization but not platform authorization.
        const PLATFORMCREATE = 1 << 30;
        /// Whether nv_read_lock may be used to set READLOCKED for this index.
        const READ_STCLEAR = 1 << 31;
        // See multi-bit type field below.
        const _ = !0;
    }
}
impl TpmaNv {
    /// Mask for the index type field.
    const NT_MASK: u32 = 0xF0;
    /// Shift of the index type field.
    const NT_SHIFT: u32 = 4;

    /// Returns the attribute for an index type (with all other field clear).
    const fn from_index_type(index_type: TpmNt) -> TpmaNv {
        TpmaNv(new_attribute_field(
            index_type.0 as u32,
            Self::NT_MASK,
            Self::NT_SHIFT,
        ))
    }

    /// Returns the type of the index.
    pub fn get_index_type(&self) -> TpmNt {
        TpmNt(get_attribute_field(self.0, Self::NT_MASK, Self::NT_SHIFT) as u8)
    }
    /// Sets the type of the index.
    pub fn set_type(&mut self, index_type: TpmNt) {
        self.0 = set_attribute_field(self.0, index_type.0 as u32, Self::NT_MASK, Self::NT_SHIFT);
    }
}
impl From<TpmNt> for TpmaNv {
    fn from(value: TpmNt) -> Self {
        Self::from_index_type(value)
    }
}

/// TpmiAlgHash represents all of the hash algorithms (TPMI_ALG_HASH).
/// See definition in Part 2: Structures, section 9.27.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
pub enum TpmiAlgHash {
    SHA1 = TpmAlgId::SHA1.0,
    SHA256  = TpmAlgId::SHA256.0,
    SHA384   = TpmAlgId::SHA384.0,
    SHA512 = TpmAlgId::SHA512.0,
    SM3256 = TpmAlgId::SM3256.0,
    SHA3256 = TpmAlgId::SHA3256.0,
    SHA3384 = TpmAlgId::SHA3384.0,
    SHA3512 = TpmAlgId::SHA3512.0,
}

/// TpmiAlgKdf represents all of key derivation functions (TPMI_ALG_KDF).
/// See definition in Part 2: Structures, section 9.32.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
pub enum TpmiAlgKdf {
    MGF1 = TpmAlgId::MGF1.0,
    KDF1SP80056A = TpmAlgId::KDF1SP80056A.0,
    KDF2 = TpmAlgId::KDF2.0,
    KDF1SP800108 = TpmAlgId::KDF1SP800108.0,
}

/// TpmiAlgPublic represents all object types (TPMI_ALG_PUBLIC).
/// See definition in Part 2: Structures, section 12.2.2.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgPublic{
    RSA = TpmAlgId::RSA.0,
    KeyedHash = TpmAlgId::KeyedHash.0,
    ECC = TpmAlgId::ECC.0,
    SymCipher = TpmAlgId::SymCipher.0,
}

/// TpmiAlgSymMode represents all of block-cipher modes of operation (TPMI_ALG_SYM_MODE).
/// See definition in Part 2: Structures, section 9.31.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgSymMode{
    CMAC = TpmAlgId::CMAC.0,
    CTR = TpmAlgId::CTR.0,
    OFB = TpmAlgId::OFB.0,
    CBC = TpmAlgId::CBC.0,
    CFB = TpmAlgId::CFB.0,
    ECB = TpmAlgId::ECB.0,
}

/// TpmiAlgSymObject represents all of the symmetric algorithms that may be used as a companion encryption algortihm for an asymmetric object (TPMI_ALG_SYM_OBJECT).
/// See definition in Part 2: Structures, section 9.30.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgSymObject{
    TDES = TpmAlgId::TDES.0,
    AES = TpmAlgId::AES.0,
    SM4 = TpmAlgId::SM4.0,
    Camellia = TpmAlgId::Camellia.0,
}

/// TpmiAlgKeyedhashScheme represents values that may appear in a keyed_hash as the scheme parameter (TPMI_ALG_KEYEDHASH_SCHEME).
/// See definition in Part 2: Structures, section 11.1.19.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgKeyedhashScheme{
    HMAC = TpmAlgId::HMAC.0,
    XOR = TpmAlgId::XOR.0,
}

/// TpmiAlgRsaScheme represents values that may appear in the scheme parameter of a TpmsRsaParms (TPMI_ALG_RSA_SCHEME).
/// See definition in Part 2: Structures, section 11.2.4.1.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgRsaScheme{
    RSAPSS = TpmAlgId::RSAPSS.0,
    RSASSA = TpmAlgId::RSASSA.0,
    ECDSA = TpmAlgId::ECDSA.0,
    ECDAA = TpmAlgId::ECDAA.0,
    SM2 = TpmAlgId::SM2.0,
    ECSchnorr = TpmAlgId::ECSchnorr.0,
    RSAES = TpmAlgId::RSAES.0,
    OAEP = TpmAlgId::OAEP.0,
}

/// TpmiAlgSigScheme represents values that may appear in the scheme parameter of a TpmtSigScheme (TPMI_ALG_SIG_SCHEME).
/// See definition in Part 2: Structures, section 9.37.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgSigScheme {
    RSAPSS = TpmAlgId::RSAPSS.0,
    RSASSA = TpmAlgId::RSASSA.0,
    ECDSA = TpmAlgId::ECDSA.0,
    ECDAA = TpmAlgId::ECDAA.0,
    SM2 = TpmAlgId::SM2.0,
    ECSchnorr = TpmAlgId::ECSchnorr.0,
    HMAC = TpmAlgId::HMAC.0,
}

/// TpmiAlgEccScheme represents values that may appear in the scheme parameter of a TpmtEccScheme (TPMI_ALG_ECC_SCHEME).
/// See definition in Part 2: Structures, section 11.2.5.4.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgEccScheme{
    RSAPSS = TpmAlgId::RSAPSS.0,
    RSASSA = TpmAlgId::RSASSA.0,
    ECDSA = TpmAlgId::ECDSA.0,
    ECDAA = TpmAlgId::ECDAA.0,
    SM2 = TpmAlgId::SM2.0,
    ECSchnorr = TpmAlgId::ECSchnorr.0,
    ECDH = TpmAlgId::ECDH.0,
    ECMQV = TpmAlgId::ECMQV.0,
}

/// TpmiAlgAsymScheme represents all the scheme types for any asymmetric algortihm (TPMI_ALG_ASYM_SCHEME).
/// See definition in Part 2: Structures, section 11.2.3.4.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgAsymScheme{
    SM2 = TpmAlgId::SM2.0,
    ECDH = TpmAlgId::ECDH.0,
    ECMQV = TpmAlgId::ECMQV.0,
    RSAPSS = TpmAlgId::RSAPSS.0,
    RSASSA = TpmAlgId::RSASSA.0,
    ECDSA = TpmAlgId::ECDSA.0,
    ECDAA = TpmAlgId::ECDAA.0,
    ECSchnorr = TpmAlgId::ECSchnorr.0,
    RSAES = TpmAlgId::RSAES.0,
    OAEP = TpmAlgId::OAEP.0,
}

/// TpmiRhNvIndex represents an NV location (TPMI_RH_NV_INDEX).
/// See definition in Part 2: Structures, section 9.24.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmiRhNvIndex(u32);
impl TryFrom<u32> for TpmiRhNvIndex {
    type Error = TpmRcError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if TpmHc::is_nv_index(value) {
            Ok(TpmiRhNvIndex(value))
        } else {
            Err(TpmRcError::Value)
        }
    }
}

/// TpmiShAuthSessions represents handles referring to an authorization session (TPMI_SH_AUTH_SESSION).
/// See definition in Part 2: Structures, section 9.8.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmiShAuthSession(u32);
impl TryFrom<u32> for TpmiShAuthSession {
    type Error = TpmRcError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if TpmHc::is_hmac_session(value)
            || TpmHc::is_policy_session(value)
            || (value == Self::RS_PW.0)
        {
            Ok(TpmiShAuthSession(value))
        } else {
            Err(TpmRcError::Value)
        }
    }
}
impl TpmiShAuthSession {
    /// A password authorization.
    pub const RS_PW: TpmiShAuthSession = TpmiShAuthSession(TpmHandle::RSPW.0);
}

/// TpmiEccCurve represents an implemented ECC curve (TPMI_ECC_SCHEME).
/// See definition in Part 2: Structures, section 11.2.5.5.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmiEccCurve(TpmEccCurve);

/// TpmiYesNo is used in place of a boolean.
/// See TPMI_YES_NO definition in Part 2: Structures, section 9.2.
#[open_enum]
#[repr(u8)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
pub enum TpmiYesNo {
    NO = 0,
    YES = 1,
}

/// TpmiStAttest represents an attestation structure type (TPMI_ST_ATTEST).
/// See definition in Part 2: Structures, section 10.12.10.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
pub enum TpmiStAttest {
    AttestCertify = TpmSt::AttestCertify.0,
    AttestQuote = TpmSt::AttestQuote.0,
    AttestSessionAudit = TpmSt::AttestSessionAudit.0,
    AttestCommandAudit = TpmSt::AttestCommandAudit.0,
    AttestTime = TpmSt::AttestTime.0,
    AttestCreation = TpmSt::AttestCreation.0,
    AttestNV = TpmSt::AttestNV.0,
    AttestNVDigest = TpmSt::AttestNVDigest.0,
}

/// The number of bits in an AES key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmiAesKeyBits(u16);
/// The number of bits in an SM4 key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmiSm4KeyBits(u16);
/// The number of bits in a Camellia key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmiCamelliaKeyBits(u16);
/// The number of bits in an RSA key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmiRsaKeyBits(u16);

/// TpmaObject indicates an object's use, authorization types, and relationship to other objects (TPMA_OBJECT).
/// See definition in Part 2: Structures, section 8.3.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmaObject(pub u32);
bitflags! {
    impl TpmaObject : u32 {
        /// Whether the hierarchy of the object may NOT change.
        const FIXED_TPM = 1 << 1;
        /// Whether saved contexts of this object may NO be loaded after startup(CLEAR).
        const ST_CLEAR = 1 << 2;
        /// Whether the parent of the object may NOT change.
        const FIXED_PARENT = 1 << 4;
        /// Whether the TPM generated all of the sensitive data, other than auth_value, when the object was created.
        const SENSITIVE_DATA_ORIGIN = 1 << 5;
        /// Whether approval of USER role actions with the object may be with an HMAC session or password using the auth_value of the object or a policy session.
        const USER_WITH_AUTH = 1 << 6;
        /// Whether approval of ADMIN role actions with the object may ONLY be done with a policy session.
        const ADMIN_WITH_POLICY = 1 << 7;
        /// Whether the object is NOT subject to dictionary attack protections.
        const NO_DA = 1 << 10;
        /// Whether, if the object is duplicated, symmetric_alg and new_parent_handle shall not be null.
        const ENCRYPTED_DUPLICATION = 1 << 11;
        /// Whether key usage is restricated to manipulate structures of known format.
        const RESTRICTED = 1 << 16;
        /// Whether the private portion of the key may be used to decrypt.
        const DECRYPT = 1 << 17;
        /// Whether the private portion of the key may be used to encrypt (for symmetric cipher objects) or sign.
        const SIGN_ENCRYPT = 1 << 18;
        /// Whether this is an asymmetric key that may not be used to sign with sign().
        const X509_SIGN = 1 << 19;
    }
}

/// TpmaAlgorithm defines the attributes of an algorithm (TPMA_ALGORITHM).
/// See definition in Part 2: Structures, section 8.2.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmaAlgorithm(pub u32);
bitflags! {
    impl TpmaAlgorithm : u32 {
        /// Indicates an asymmetric algorithm with public and private portions.
        const ASYMMETRIC = 1 << 0;
        /// Indicates a symmetric block cipher.
        const SYMMETRIC = 1 << 1;
        /// Indicates a hash algorithm.
        const HASH = 1 << 2;
        /// Indicates an algorithm that may be used as an object type.
        const OBJECT = 1 << 3;
        /// Indicates a signing algorithm.
        const SIGNING = 1 << 8;
        /// Indicates an encryption/decryption algorithm.
        const ENCRYPTING = 1 << 9;
        /// Indicates a method such as a key derivative function.
        const METHOD = 1 << 10;
    }
}

/// TpmaSession defines the attributes of a session (TPMA_SESSION).
/// See definition in Part 2: Structures, section 8.4.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmaSession(pub u8);
bitflags! {
    impl TpmaSession : u8 {
        /// Indicates if the session is to remain active (in commands) or does remain active (in reponses) after successful completion of the command.
        const CONTINUE_SESSION = 1 << 0;
        /// Indicates if the command should only be executed if the session is exclusive at the start of the command (in commands) or is exclusive (in responses).
        const AUDIT_EXCLUSIVE = 1 << 1;
        /// Indicates if the audit digest of the session should be initialized and exclusive status set in commands.
        const AUDIT_RESET = 1 << 2;
        /// Indicates if the first parameter in the command is symmetrically encrpyted.
        const DECRYPT = 1 << 5;
        /// Indicates if the session should (in commands) or did (in responses) encrypt the first parameter in the response.
        const ENCRYPT = 1 << 6;
        /// Indicates that the session is for audit, and that AUDIT_EXLCUSIVE/AUDIT_RESET have meaning.
        const AUDIT = 1 << 7;
    }
}

/// TpmaCc defines the attributes of a command (TPMA_CC).
/// See definition in Part 2: Structures, section 8.9.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmaCc(pub u32);
bitflags! {
    impl TpmaCc : u32 {
        /// Whether the command may write to NV.
        const NV  = 1 << 22;
        /// Whether the command could flush any number of loaded contexts.
        const EXTENSIVE = 1 << 23;
        /// Whether the conext associated with any transient handle in the command will be flushed when this command completes.
        const FLUSHED = 1 << 24;
        /// Wether there is a handle area in the response.
        const R_HANDLE = 1 << 28;
        /// Whether the command is vendor-specific.
        const V = 1 << 29;
        // See multi-bit fields below.
        const _ = !0;
    }
}
impl TpmaCc {
    /// Shift for the command index field.
    const COMMAND_INDEX_SHIFT: u32 = 0;
    /// Mask for the command index field.
    const COMMAND_INDEX_MASK: u32 = 0xFFFF;
    /// Shift for the command handles field.
    const C_HANDLES_SHIFT: u32 = 25;
    /// Mask for the command handles field.
    const C_HANDLES_MASK: u32 = 0x7 << TpmaCc::C_HANDLES_SHIFT;

    /// Creates a TpmaCc with the command index field set to the provided value.
    const fn command_index(index: u16) -> TpmaCc {
        TpmaCc(new_attribute_field(
            index as u32,
            Self::COMMAND_INDEX_MASK,
            Self::COMMAND_INDEX_SHIFT,
        ))
    }
    /// Creates a TpmaCc with the command handles field set to the provided value.
    const fn c_handles(count: u32) -> TpmaCc {
        TpmaCc(new_attribute_field(
            count,
            Self::C_HANDLES_MASK,
            Self::C_HANDLES_SHIFT,
        ))
    }

    /// Returns the command being selected.
    fn get_command_index(&self) -> u16 {
        get_attribute_field(self.0, Self::COMMAND_INDEX_MASK, Self::COMMAND_INDEX_SHIFT) as u16
    }
    /// Returns the number of handles in the handle area for this command.
    fn get_c_handles(&self) -> u32 {
        get_attribute_field(self.0, Self::C_HANDLES_MASK, Self::C_HANDLES_SHIFT)
    }

    /// Sets the command being selected.
    fn set_command_index(&mut self, index: u16) {
        self.0 = set_attribute_field(
            self.0,
            index as u32,
            Self::COMMAND_INDEX_MASK,
            Self::COMMAND_INDEX_SHIFT,
        );
    }
    /// Sets the number of handles in the handle area for this command.
    fn set_c_handles(&mut self, count: u32) {
        self.0 = set_attribute_field(self.0, count, Self::C_HANDLES_MASK, Self::C_HANDLES_SHIFT);
    }
}

/// TpmiStCommandTag defines the command tags (TPMI_ST_COMMAND_TAG).
/// See definition in Part 2: Structures, section 9.35.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshalable)]
pub enum TpmiStCommandTag{
    NoSessions = TpmSt::NoSessions.0,
    Sessions = TpmSt::Sessions.0,
}

const TPM2_MAX_CAP_DATA: usize =
    TPM2_MAX_CAP_BUFFER as usize - size_of::<TpmCap>() - size_of::<u32>();
const TPM2_MAX_CAP_ALGS: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsAlgProperty>();
const TPM2_MAX_CAP_HANDLES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmHandle>();
const TPM2_MAX_CAP_CC: usize = TPM2_MAX_CAP_DATA / size_of::<TpmCc>();
const TPM2_MAX_TPM_PROPERTIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedProperty>();
const TPM2_MAX_PCR_PROPERTIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedPcrSelect>();
const TPM2_MAX_ECC_CURVES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmEccCurve>();
const TPM2_MAX_TAGGED_POLICIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedPolicy>();
const TPML_DIGEST_MAX_DIGESTS: usize = 8;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsEmpty;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable, UnionSize)]
pub enum TpmtHa {
    Sha1([u8; constants::TPM2_SHA_DIGEST_SIZE as usize]) = TpmAlgId::SHA1.0,
    Sha256([u8; constants::TPM2_SHA256_DIGEST_SIZE as usize]) = TpmAlgId::SHA256.0,
    Sha384([u8; constants::TPM2_SHA384_DIGEST_SIZE as usize]) = TpmAlgId::SHA384.0,
    Sha512([u8; constants::TPM2_SHA512_DIGEST_SIZE as usize]) = TpmAlgId::SHA512.0,
    Sm3_256([u8; constants::TPM2_SM3_256_DIGEST_SIZE as usize]) = TpmAlgId::SM3256.0,
}

impl Default for TpmtHa {
    fn default() -> Self {
        TpmtHa::Sha1([0; constants::TPM2_SHA1_DIGEST_SIZE as usize])
    }
}

#[derive(UnionSize)]
#[repr(C, u16)]
enum TpmuName {
    Digest(TpmtHa),
    Handle(TpmHandle),
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bDigest {
    size: u16,
    buffer: [u8; TpmtHa::UNION_SIZE],
}

pub type Tpm2bNonce = Tpm2bDigest;
pub type Tpm2bOperand = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bData {
    size: u16,
    buffer: [u8; TpmtHa::UNION_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bEvent {
    size: u16,
    buffer: [u8; 1024],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bMaxBuffer {
    size: u16,
    buffer: [u8; TPM2_MAX_DIGEST_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bMaxNvBuffer {
    size: u16,
    buffer: [u8; TPM2_MAX_NV_BUFFER_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bIv {
    size: u16,
    buffer: [u8; TPM2_MAX_SYM_BLOCK_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bName {
    size: u16,
    name: [u8; TpmuName::UNION_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxCapBuffer {
    size: u16,
    buffer: [u8; TPM2_MAX_CAP_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: TpmiYesNo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshalable)]
pub struct TpmsPcrSelection {
    pub hash: TpmiAlgHash,
    pub sizeof_select: u8,
    #[marshalable(length=sizeof_select)]
    pub pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmlPcrSelection {
    count: u32,
    #[marshalable(length=count)]
    pcr_selections: [TpmsPcrSelection; TPM2_NUM_PCR_BANKS as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsQuoteInfo {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsCreationInfo {
    pub object_name: Tpm2bName,
    pub creation_hash: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsCertifyInfo {
    pub name: Tpm2bName,
    pub qualified_name: Tpm2bName,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct TpmsCommandAuditInfo {
    pub audit_counter: u64,
    pub digest_alg: u16,
    pub audit_digest: Tpm2bDigest,
    pub command_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsSessionAuditInfo {
    pub exclusive_session: TpmiYesNo,
    pub session_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsTimeInfo {
    pub time: u64,
    pub clock_info: TpmsClockInfo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsTimeAttestInfo {
    pub time: TpmsTimeInfo,
    pub firmware_version: u64,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsNvCertifyInfo {
    pub index_name: Tpm2bName,
    pub offset: u16,
    pub nv_contents: Tpm2bMaxNvBuffer,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Discriminant, Marshalable)]
pub enum TpmuAttest {
    Certify(TpmsCertifyInfo) = TpmSt::AttestCertify.0,
    Creation(TpmsCreationInfo) = TpmSt::AttestCreation.0,
    Quote(TpmsQuoteInfo) = TpmSt::AttestQuote.0,
    CommandAudit(TpmsCommandAuditInfo) = TpmSt::AttestCommandAudit.0,
    SessionAudit(TpmsSessionAuditInfo) = TpmSt::AttestSessionAudit.0,
    Time(TpmsTimeAttestInfo) = TpmSt::AttestTime.0,
    Nv(TpmsNvCertifyInfo) = TpmSt::AttestNV.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub struct TpmsAttest {
    pub magic: TpmGenerated,
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub attested: TpmuAttest,
}
// Custom overload of Marshalable, because the selector for attested is {un}marshaled separate from the field.
impl Marshalable for TpmsAttest {
    fn try_marshal(&self, buffer: &mut [u8]) -> tpm2_rs_marshalable::Result<usize> {
        let mut written = 0;
        written += self.magic.try_marshal(&mut buffer[written..])?;
        written += self
            .attested
            .discriminant()
            .try_marshal(&mut buffer[written..])?;
        written += self.qualified_signer.try_marshal(&mut buffer[written..])?;
        written += self.extra_data.try_marshal(&mut buffer[written..])?;
        written += self.clock_info.try_marshal(&mut buffer[written..])?;
        written += self.firmware_version.try_marshal(&mut buffer[written..])?;
        written += self.attested.try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }

    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> tpm2_rs_marshalable::Result<Self> {
        let magic = TpmGenerated::try_unmarshal(buffer)?;
        let selector = u16::try_unmarshal(buffer)?;
        Ok(TpmsAttest {
            magic,
            qualified_signer: Tpm2bName::try_unmarshal(buffer)?,
            extra_data: Tpm2bData::try_unmarshal(buffer)?,
            clock_info: TpmsClockInfo::try_unmarshal(buffer)?,
            firmware_version: u64::try_unmarshal(buffer)?,
            attested: TpmuAttest::try_unmarshal_variant(selector, buffer)?,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bAttest {
    size: u16,
    attestation_data: [u8; size_of::<TpmsAttest>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bSymKey {
    size: u16,
    buffer: [u8; TPM2_MAX_SYM_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bLabel {
    size: u16,
    buffer: [u8; TPM2_LABEL_MAX_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsDerive {
    pub label: Tpm2bLabel,
    pub context: Tpm2bLabel,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDerive {
    size: u16,
    buffer: [u8; size_of::<TpmsDerive>()],
}
#[derive(UnionSize)]
#[repr(C, u16)]
enum TpmuSensitiveCreate {
    Create([u8; constants::TPM2_MAX_SYM_DATA as usize]),
    Derive(TpmsDerive),
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bSensitiveData {
    size: u16,
    buffer: [u8; TpmuSensitiveCreate::UNION_SIZE],
}

pub type Tpm2bAuth = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable, Default)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2bAuth,
    pub data: Tpm2bSensitiveData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable, Tpm2bStruct)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bSensitiveCreate {
    size: u16,
    sensitive: [u8; size_of::<TpmsSensitiveCreate>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bPublicKeyRsa {
    size: u16,
    buffer: [u8; TPM2_MAX_RSA_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bPrivateKeyRsa {
    size: u16,
    buffer: [u8; (TPM2_MAX_RSA_KEY_BYTES / 2) as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bEccParameter {
    size: u16,
    buffer: [u8; TPM2_MAX_ECC_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsEccPoint {
    pub x: Tpm2bEccParameter,
    pub y: Tpm2bEccParameter,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccPoint {
    size: u16,
    point: [u8; size_of::<TpmsEccPoint>()],
}

#[derive(UnionSize)]
#[repr(C, u16)]
enum TpmuEncryptedSecret {
    Ecc([u8; size_of::<TpmsEccPoint>()]),
    Rsa([u8; constants::TPM2_MAX_RSA_KEY_BYTES as usize]),
    Symmetric([u8; size_of::<Tpm2bDigest>()]),
    KeyedHash([u8; size_of::<Tpm2bDigest>()]),
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bEncryptedSecret {
    size: u16,
    secret: [u8; TpmuEncryptedSecret::UNION_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsSchemeXor {
    pub hash_alg: TpmiAlgHash,
    pub kdf: TpmiAlgKdf,
}

pub type TpmsSchemeHmac = TpmsSchemeHash;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable)]
pub enum TpmtKeyedHashScheme {
    Hmac(TpmsSchemeHmac) = TpmAlgId::HMAC.0,
    ExclusiveOr(TpmsSchemeXor) = TpmAlgId::XOR.0,
    Null(TpmsEmpty) = TpmAlgId::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsKeyedHashParms {
    pub scheme: TpmtKeyedHashScheme,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable)]
pub enum TpmtSymDefObject {
    Aes(TpmiAesKeyBits, TpmiAlgSymMode) = TpmAlgId::AES.0,
    Sm4(TpmiSm4KeyBits, TpmiAlgSymMode) = TpmAlgId::SM4.0,
    Camellia(TpmiCamelliaKeyBits, TpmiAlgSymMode) = TpmAlgId::Camellia.0,
    ExclusiveOr(TpmiAlgHash, TpmsEmpty) = TpmAlgId::XOR.0,
    Null(TpmsEmpty, TpmsEmpty) = TpmAlgId::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsSymCipherParms {
    pub sym: TpmtSymDefObject,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsSignatureRsa {
    pub hash: TpmiAlgHash,
    pub sig: Tpm2bPublicKeyRsa,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsSignatureEcc {
    pub hash: TpmiAlgHash,
    pub signature_r: Tpm2bEccParameter,
    pub signature_s: Tpm2bEccParameter,
}

pub type TpmsSignatureRsassa = TpmsSignatureRsa;
pub type TpmsSignatureRsapss = TpmsSignatureRsa;
pub type TpmsSignatureEcdsa = TpmsSignatureEcc;
pub type TpmsSignatureEcdaa = TpmsSignatureEcc;
pub type TpmsSignatureSm2 = TpmsSignatureEcc;
pub type TpmsSignatureEcschnorr = TpmsSignatureEcc;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable)]
pub enum TpmtSignature {
    Rsassa(TpmsSignatureRsassa) = TpmAlgId::RSASSA.0,
    Rsapss(TpmsSignatureRsapss) = TpmAlgId::RSAPSS.0,
    Ecdsa(TpmsSignatureEcdsa) = TpmAlgId::ECDSA.0,
    Ecdaa(TpmsSignatureEcdaa) = TpmAlgId::ECDAA.0,
    Sm2(TpmsSignatureSm2) = TpmAlgId::SM2.0,
    Ecschnorr(TpmsSignatureEcschnorr) = TpmAlgId::ECSchnorr.0,
    Hmac(TpmtHa) = TpmAlgId::HMAC.0,
    Null(TpmsEmpty) = TpmAlgId::Null.0,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable)]
pub enum TpmtSigScheme {
    Rsassa(TpmsSigSchemeRsassa) = TpmAlgId::RSASSA.0,
    Rsapss(TpmsSigSchemeRsapss) = TpmAlgId::RSAPSS.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TpmAlgId::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TpmAlgId::ECDAA.0,
    Sm2(TpmsSigSchemeSm2) = TpmAlgId::SM2.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TpmAlgId::ECSchnorr.0,
    Hmac(TpmsSchemeHmac) = TpmAlgId::HMAC.0,
    Null(TpmsEmpty) = TpmAlgId::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsSchemeHash {
    pub hash_alg: TpmiAlgHash,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsSchemeEcdaa {
    pub hash_alg: TpmiAlgHash,
    pub count: u16,
}

pub type TpmsKeySchemeEcdh = TpmsSchemeHash;
pub type TpmsKeySchemeEcmqv = TpmsSchemeHash;
pub type TpmsSigSchemeRsassa = TpmsSchemeHash;
pub type TpmsSigSchemeRsapss = TpmsSchemeHash;
pub type TpmsSigSchemeEcdsa = TpmsSchemeHash;
pub type TpmsSigSchemeSm2 = TpmsSchemeHash;
pub type TpmsSigSchemeEcschnorr = TpmsSchemeHash;
pub type TpmsSigSchemeEcdaa = TpmsSchemeEcdaa;
pub type TpmsEncSchemeOaep = TpmsSchemeHash;
pub type TpmsEncSchemeRsaes = TpmsEmpty;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable)]
pub enum TpmtRsaScheme {
    Rsapss(TpmsSigSchemeRsapss) = TpmAlgId::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TpmAlgId::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TpmAlgId::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TpmAlgId::ECDAA.0,
    Sm2(TpmsSigSchemeSm2) = TpmAlgId::SM2.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TpmAlgId::ECSchnorr.0,
    Rsaes(TpmsEncSchemeRsaes) = TpmAlgId::RSAES.0,
    Oaep(TpmsEncSchemeOaep) = TpmAlgId::OAEP.0,
    Null(TpmsEmpty) = TpmAlgId::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsRsaParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtRsaScheme,
    pub key_bits: TpmiRsaKeyBits,
    pub exponent: u32,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable)]
pub enum TpmtEccScheme {
    Rsapss(TpmsSigSchemeRsapss) = TpmAlgId::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TpmAlgId::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TpmAlgId::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TpmAlgId::ECDAA.0,
    Sm2(TpmsSigSchemeSm2) = TpmAlgId::SM2.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TpmAlgId::ECSchnorr.0,
    Ecdh(TpmsKeySchemeEcdh) = TpmAlgId::ECDH.0,
    Ecmqv(TpmsKeySchemeEcmqv) = TpmAlgId::ECMQV.0,
    Null(TpmsEmpty) = TpmAlgId::Null.0,
}

pub type TpmsSchemeMgf1 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_56a = TpmsSchemeHash;
pub type TpmsSchemeKdf2 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_108 = TpmsSchemeHash;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable)]
pub enum TpmtKdfScheme {
    Mgf1(TpmsSchemeMgf1) = TpmAlgId::MGF1.0,
    Kdf1Sp800_56a(TpmsSchemeKdf1Sp800_56a) = TpmAlgId::KDF1SP80056A.0,
    Kdf2(TpmsSchemeKdf2) = TpmAlgId::KDF2.0,
    Kdf1Sp800_108(TpmsSchemeKdf1Sp800_108) = TpmAlgId::KDF1SP800108.0,
    Null(TpmsEmpty) = TpmAlgId::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsEccParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtEccScheme,
    pub curve_id: TpmiEccCurve,
    pub kdf: TpmtKdfScheme,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable)]
pub enum TpmtAsymScheme {
    Ecdh(TpmsKeySchemeEcdh) = TpmAlgId::ECDH.0,
    Ecmqv(TpmsKeySchemeEcmqv) = TpmAlgId::ECMQV.0,
    Sm2(TpmsSigSchemeSm2) = TpmAlgId::SM2.0,
    Rsapss(TpmsSigSchemeRsapss) = TpmAlgId::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TpmAlgId::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TpmAlgId::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TpmAlgId::ECDAA.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TpmAlgId::ECSchnorr.0,
    Rsaes(TpmsEncSchemeRsaes) = TpmAlgId::RSAES.0,
    Oaep(TpmsEncSchemeOaep) = TpmAlgId::OAEP.0,
    Null(TpmsEmpty) = TpmAlgId::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsAsymParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtAsymScheme,
}

#[repr(C)]
union TpmuPublicId {
    pub keyed_hash: Tpm2bDigest,
    pub sym: Tpm2bDigest,
    pub rsa: Tpm2bPublicKeyRsa,
    pub ecc: TpmsEccPoint,
    pub derive: TpmsDerive,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable)]
pub enum PublicParmsAndId {
    KeyedHash(TpmsKeyedHashParms, Tpm2bDigest) = TpmAlgId::KeyedHash.0,
    Sym(TpmsSymCipherParms, Tpm2bDigest) = TpmAlgId::SymCipher.0,
    Rsa(TpmsRsaParms, Tpm2bPublicKeyRsa) = TpmAlgId::RSA.0,
    Ecc(TpmsEccParms, TpmsEccPoint) = TpmAlgId::ECC.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmtPublic {
    pub name_alg: TpmiAlgHash,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest,
    pub parms_and_id: PublicParmsAndId,
}
// Custom overload of Marshalable, because the selector for parms_and_id is {un}marshaled first.
impl Marshalable for TpmtPublic {
    fn try_marshal(&self, buffer: &mut [u8]) -> tpm2_rs_marshalable::Result<usize> {
        let mut written = 0;
        written += self
            .parms_and_id
            .discriminant()
            .try_marshal(&mut buffer[written..])?;
        written += self.name_alg.try_marshal(&mut buffer[written..])?;
        written += self.object_attributes.try_marshal(&mut buffer[written..])?;
        written += self.auth_policy.try_marshal(&mut buffer[written..])?;
        written += self
            .parms_and_id
            .try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }
    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> tpm2_rs_marshalable::Result<Self> {
        let selector = u16::try_unmarshal(buffer)?;
        Ok(TpmtPublic {
            name_alg: TpmiAlgHash::try_unmarshal(buffer)?,
            object_attributes: TpmaObject::try_unmarshal(buffer)?,
            auth_policy: Tpm2bDigest::try_unmarshal(buffer)?,
            parms_and_id: PublicParmsAndId::try_unmarshal_variant(selector, buffer)?,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable, Tpm2bStruct)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bPublic {
    size: u16,
    public_area: [u8; size_of::<TpmtPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bTemplate {
    size: u16,
    buffer: [u8; size_of::<TpmtPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bPrivateVendorSpecific {
    size: u16,
    buffer: [u8; TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES as usize],
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable)]
pub enum TpmuSensitiveComposite {
    Rsa(Tpm2bPrivateKeyRsa) = TpmAlgId::RSA.0,
    Ecc(Tpm2bEccParameter) = TpmAlgId::ECC.0,
    Bits(Tpm2bSensitiveData) = TpmAlgId::KeyedHash.0,
    Sym(Tpm2bSymKey) = TpmAlgId::SymCipher.0,
    /* For size purposes only */
    Any(Tpm2bPrivateVendorSpecific) = TpmAlgId::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmtSensitive {
    pub auth_value: Tpm2bAuth,
    pub seed_value: Tpm2bDigest,
    pub sensitive: TpmuSensitiveComposite,
}
// Custom overload of Marshalable, because the selector for sensitive is {un}marshaled first.
impl Marshalable for TpmtSensitive {
    fn try_marshal(&self, buffer: &mut [u8]) -> tpm2_rs_marshalable::Result<usize> {
        let mut written = 0;
        written += self
            .sensitive
            .discriminant()
            .try_marshal(&mut buffer[written..])?;
        written += self.auth_value.try_marshal(&mut buffer[written..])?;
        written += self.seed_value.try_marshal(&mut buffer[written..])?;
        written += self.sensitive.try_marshal_variant(&mut buffer[written..])?;
        Ok(written)
    }

    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> tpm2_rs_marshalable::Result<Self> {
        let selector = u16::try_unmarshal(buffer)?;
        Ok(TpmtSensitive {
            auth_value: Tpm2bAuth::try_unmarshal(buffer)?,
            seed_value: Tpm2bDigest::try_unmarshal(buffer)?,
            sensitive: TpmuSensitiveComposite::try_unmarshal_variant(selector, buffer)?,
        })
    }
}

#[repr(C, u32)]
#[derive(Clone, Copy, PartialEq, Debug, Discriminant, Marshalable)]
pub enum TpmsCapabilityData {
    Algorithms(TpmlAlgProperty) = TpmCap::Algs.0,
    Handles(TpmlHandle) = TpmCap::Handles.0,
    Command(TpmlCca) = TpmCap::Commands.0,
    PpCommands(TpmlCc) = TpmCap::PPCommands.0,
    AuditCommands(TpmlCc) = TpmCap::AuditCommands.0,
    AssignedPcr(TpmlPcrSelection) = TpmCap::PCRs.0,
    TpmProperties(TpmlTaggedTpmProperty) = TpmCap::TPMProperties.0,
    PcrProperties(TpmlTaggedPcrProperty) = TpmCap::PCRProperties.0,
    EccCurves(TpmlEccCurve) = TpmCap::ECCCurves.0,
    AuthPolicies(TpmlTaggedPolicy) = TpmCap::AuthPolicies.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmlAlgProperty {
    count: u32,
    #[marshalable(length=count)]
    alg_properties: [TpmsAlgProperty; TPM2_MAX_CAP_ALGS],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmlHandle {
    count: u32,
    #[marshalable(length=count)]
    handle: [TpmHandle; TPM2_MAX_CAP_HANDLES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmlCca {
    count: u32,
    #[marshalable(length=count)]
    command_attributes: [TpmaCc; TPM2_MAX_CAP_CC],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmlCc {
    count: u32,
    #[marshalable(length=count)]
    command_codes: [TpmCc; TPM2_MAX_CAP_CC],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmlTaggedTpmProperty {
    pub count: u32,
    #[marshalable(length=count)]
    pub tpm_property: [TpmsTaggedProperty; TPM2_MAX_TPM_PROPERTIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmlTaggedPcrProperty {
    count: u32,
    #[marshalable(length=count)]
    pcr_property: [TpmsTaggedPcrSelect; TPM2_MAX_PCR_PROPERTIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmlEccCurve {
    count: u32,
    #[marshalable(length=count)]
    ecc_curves: [TpmEccCurve; TPM2_MAX_ECC_CURVES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmlTaggedPolicy {
    count: u32,
    #[marshalable(length=count)]
    policies: [TpmsTaggedPolicy; TPM2_MAX_TAGGED_POLICIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Debug, Marshalable)]
pub struct TpmsAlgProperty {
    pub alg: TpmAlgId,
    pub alg_properties: TpmaAlgorithm,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Debug, Marshalable)]
pub struct TpmsTaggedProperty {
    pub property: TpmPt,
    pub value: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Debug, Marshalable)]
pub struct TpmsTaggedPcrSelect {
    tag: TpmPtPcr,
    size_of_select: u8,
    #[marshalable(length=size_of_select)]
    pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable, Default)]
pub struct TpmsTaggedPolicy {
    handle: TpmHandle,
    policy_hash: TpmtHa,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmlDigest {
    count: u32,
    #[marshalable(length=count)]
    digests: [Tpm2bDigest; TPML_DIGEST_MAX_DIGESTS],
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Debug, Marshalable)]
pub struct TpmsAuthCommand {
    pub session_handle: TpmiShAuthSession,
    pub nonce: Tpm2bNonce,
    pub session_attributes: TpmaSession,
    pub hmac: Tpm2bAuth,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Debug, Marshalable)]
pub struct TpmsAuthResponse {
    pub nonce: Tpm2bNonce,
    pub session_attributes: TpmaSession,
    pub hmac: Tpm2bData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitive {
    size: u16,
    sensitive_area: [u8; size_of::<TpmtSensitive>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct _PRIVATE {
    integrity_outer: Tpm2bDigest,
    integrity_inner: Tpm2bDigest,
    sensitive: Tpm2bSensitive,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bPrivate {
    size: u16,
    buffer: [u8; size_of::<_PRIVATE>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsIdObject {
    pub integrity_hmac: Tpm2bDigest,
    pub enc_identity: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bIdObject {
    size: u16,
    credential: [u8; size_of::<TpmsIdObject>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsNvPublic {
    pub nv_index: TpmiRhNvIndex,
    pub name_alg: TpmiAlgHash,
    pub attributes: TpmaNv,
    pub auth_policy: Tpm2bDigest,
    pub data_size: u16,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bNvPublic {
    size: u16,
    nv_public: [u8; size_of::<TpmsNvPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bContextSensitive {
    size: u16,
    buffer: [u8; TPM2_MAX_CONTEXT_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsContextData {
    pub integrity: Tpm2bDigest,
    pub encrypted: Tpm2bContextSensitive,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bContextData {
    size: u16,
    buffer: [u8; size_of::<TpmsContextData>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct TpmsCreationData {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
    pub locality: TpmaLocality,
    pub parent_name_alg: TpmAlgId,
    pub parent_name: Tpm2bName,
    pub parent_qualified_name: Tpm2bName,
    pub outside_info: Tpm2bData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable, Tpm2bStruct)]
#[marshalable(tpm2b_simple)]
pub struct Tpm2bCreationData {
    size: u16,
    creation_data: [u8; size_of::<TpmsCreationData>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct TpmtTkCreation {
    pub rc: TpmRc,            // If success, represents TPM_ST_CREATION.
    pub hierarchy: TpmHandle, // RH hierarchy expected.
    pub digest: Tpm2bDigest,
}

impl Marshalable for TpmtTkCreation {
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize> {
        let mut written = 0;
        if self.rc == TpmRc::Success {
            written += TpmSt::AttestCreation.try_marshal(&mut buffer[written..])?;
        } else {
            written += self.rc.try_marshal(&mut buffer[written..])?;
        }
        written += self.hierarchy.try_marshal(&mut buffer[written..])?;
        written += self.digest.try_marshal(&mut buffer[written..])?;
        Ok(written)
    }
    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self> {
        let tag = u32::try_unmarshal(buffer)?;
        let rc = if tag == TpmSt::AttestCreation.0 as u32 {
            TpmRc::Success
        } else {
            TpmRc(tag)
        };
        Ok(TpmtTkCreation {
            rc: rc,
            hierarchy: TpmHandle::try_unmarshal(buffer)?,
            digest: Tpm2bDigest::try_unmarshal(buffer)?,
        })
    }
}

// Helper for splitting up ranges of an unmarshal buffer.

pub trait Tpm2bSimple {
    const MAX_BUFFER_SIZE: usize;
    fn get_size(&self) -> u16;
    fn get_buffer(&self) -> &[u8];
    fn from_bytes(buffer: &[u8]) -> tpm2_rs_marshalable::Result<Self>
    where
        Self: Sized;
}

/// Provides conversion to/from a struct type for TPM2B types that don't hold a bytes buffer.
pub trait Tpm2bStruct: Tpm2bSimple {
    type StructType: Marshalable;

    /// Marshals the value into the 2b holder.
    fn from_struct(val: &Self::StructType) -> tpm2_rs_marshalable::Result<Self>
    where
        Self: Sized;

    /// Extracts the struct value from the 2b holder.
    fn to_struct(&self) -> tpm2_rs_marshalable::Result<Self::StructType>;
}

// Adds common helpers for TPML type $T.
macro_rules! impl_tpml {
    ($T:ty,  $ListField:ident, $ListType:ty, $ListCapacity:ident) => {
        // Implement Default for the type. This cannot usually be derived, because $ListCapacity is too large.
        impl Default for $T {
            fn default() -> Self {
                Self {
                    count: 0,
                    $ListField: [<$ListType>::default(); $ListCapacity as usize],
                }
            }
        }

        impl $T {
            pub fn new(elements: &[$ListType]) -> TpmRcResult<$T> {
                if elements.len() > $ListCapacity as usize {
                    // TODO: Should this return error in server or client value space?
                    return Err(TpmRcError::Size.into());
                }
                let mut x = Self::default();
                x.count = elements.len() as u32;
                x.$ListField[..elements.len()].copy_from_slice(elements);
                Ok(x)
            }

            pub fn add(&mut self, element: &$ListType) -> TpmRcResult<()> {
                if self.count() >= self.$ListField.len() {
                    // TODO: Should this return error in server or client value space?
                    return Err(TpmRcError::Size.into());
                }
                self.$ListField[self.count()] = *element;
                self.count += 1;
                Ok(())
            }

            pub fn count(&self) -> usize {
                self.count as usize
            }

            pub fn $ListField(&self) -> &[$ListType] {
                &self.$ListField[..min(self.count(), $ListCapacity as usize)]
            }
        }
    };
}
impl_tpml! {TpmlPcrSelection, pcr_selections, TpmsPcrSelection, TPM2_NUM_PCR_BANKS}
impl_tpml! {TpmlAlgProperty, alg_properties, TpmsAlgProperty, TPM2_MAX_CAP_ALGS}
impl_tpml! {TpmlHandle, handle, TpmHandle, TPM2_MAX_CAP_HANDLES}
impl_tpml! {TpmlCc, command_codes, TpmCc, TPM2_MAX_CAP_CC}
impl_tpml! {TpmlTaggedTpmProperty, tpm_property, TpmsTaggedProperty, TPM2_MAX_TPM_PROPERTIES}
impl_tpml! {TpmlTaggedPcrProperty, pcr_property, TpmsTaggedPcrSelect, TPM2_MAX_PCR_PROPERTIES}
impl_tpml! {TpmlEccCurve, ecc_curves, TpmEccCurve, TPM2_MAX_ECC_CURVES}
impl_tpml! {TpmlTaggedPolicy, policies, TpmsTaggedPolicy, TPM2_MAX_TAGGED_POLICIES}
impl_tpml! {TpmlDigest, digests, Tpm2bDigest, TPML_DIGEST_MAX_DIGESTS}

#[cfg(test)]
mod tests;
