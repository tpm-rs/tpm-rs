#![allow(dead_code, clippy::large_enum_variant)]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

use crate::{constants::*, errors::*, marshal::*};
use bitflags::bitflags;
use core::cmp::min;
use core::mem::size_of;
use open_enum::open_enum;
pub use tpm2_rs_errors as errors;
pub use tpm2_rs_marshal as marshal;
use unionify::UnionSize;

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
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
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
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
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
    const fn from_index_type(index_type: TPM2NT) -> TpmaNv {
        TpmaNv(new_attribute_field(
            index_type.0 as u32,
            Self::NT_MASK,
            Self::NT_SHIFT,
        ))
    }

    /// Returns the type of the index.
    pub fn get_index_type(&self) -> TPM2NT {
        TPM2NT(get_attribute_field(self.0, Self::NT_MASK, Self::NT_SHIFT) as u8)
    }
    /// Sets the type of the index.
    pub fn set_type(&mut self, index_type: TPM2NT) {
        self.0 = set_attribute_field(self.0, index_type.0 as u32, Self::NT_MASK, Self::NT_SHIFT);
    }
}
impl From<TPM2NT> for TpmaNv {
    fn from(value: TPM2NT) -> Self {
        Self::from_index_type(value)
    }
}

/// TpmiAlgHash represents all of the hash algorithms (TPMI_ALG_HASH).
/// See definition in Part 2: Structures, section 9.27.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
pub enum TpmiAlgHash {
    SHA1 = TPM2AlgID::SHA1.0,
    SHA256  = TPM2AlgID::SHA256.0,
    SHA384   = TPM2AlgID::SHA384.0,
    SHA512 = TPM2AlgID::SHA512.0,
    SM3256 = TPM2AlgID::SM3256.0,
    SHA3256 = TPM2AlgID::SHA3256.0,
    SHA3384 = TPM2AlgID::SHA3384.0,
    SHA3512 = TPM2AlgID::SHA3512.0,
}

/// TpmiAlgKdf represents all of key derivation functions (TPMI_ALG_KDF).
/// See definition in Part 2: Structures, section 9.32.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
pub enum TpmiAlgKdf {
    MGF1 = TPM2AlgID::MGF1.0,
    KDF1SP80056A = TPM2AlgID::KDF1SP80056A.0,
    KDF2 = TPM2AlgID::KDF2.0,
    KDF1SP800108 = TPM2AlgID::KDF1SP800108.0,
}

/// TpmiAlgPublic represents all object types (TPMI_ALG_PUBLIC).
/// See definition in Part 2: Structures, section 12.2.2.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgPublic{
    RSA = TPM2AlgID::RSA.0,
    KeyedHash = TPM2AlgID::KeyedHash.0,
    ECC = TPM2AlgID::ECC.0,
    SymCipher = TPM2AlgID::SymCipher.0,
}

/// TpmiAlgSymMode represents all of block-cipher modes of operation (TPMI_ALG_SYM_MODE).
/// See definition in Part 2: Structures, section 9.31.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgSymMode{
    CMAC = TPM2AlgID::CMAC.0,
    CTR = TPM2AlgID::CTR.0,
    OFB = TPM2AlgID::OFB.0,
    CBC = TPM2AlgID::CBC.0,
    CFB = TPM2AlgID::CFB.0,
    ECB = TPM2AlgID::ECB.0,
}

/// TpmiAlgSymObject represents all of the symmetric algorithms that may be used as a companion encryption algortihm for an asymmetric object (TPMI_ALG_SYM_OBJECT).
/// See definition in Part 2: Structures, section 9.30.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgSymObject{
    TDES = TPM2AlgID::TDES.0,
    AES = TPM2AlgID::AES.0,
    SM4 = TPM2AlgID::SM4.0,
    Camellia = TPM2AlgID::Camellia.0,
}

/// TpmiAlgKeyedhashScheme represents values that may appear in a keyed_hash as the scheme parameter (TPMI_ALG_KEYEDHASH_SCHEME).
/// See definition in Part 2: Structures, section 11.1.19.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgKeyedhashScheme{
    HMAC = TPM2AlgID::HMAC.0,
    XOR = TPM2AlgID::XOR.0,
}

/// TpmiAlgRsaScheme represents values that may appear in the scheme parameter of a TpmsRsaParms (TPMI_ALG_RSA_SCHEME).
/// See definition in Part 2: Structures, section 11.2.4.1.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgRsaScheme{
    RSAPSS = TPM2AlgID::RSAPSS.0,
    RSASSA = TPM2AlgID::RSASSA.0,
    ECDSA = TPM2AlgID::ECDSA.0,
    ECDAA = TPM2AlgID::ECDAA.0,
    SM2 = TPM2AlgID::SM2.0,
    ECSchnorr = TPM2AlgID::ECSchnorr.0,
    RSAES = TPM2AlgID::RSAES.0,
    OAEP = TPM2AlgID::OAEP.0,
}

/// TpmiAlgEccScheme represents values that may appear in the scheme parameter of a TpmtEccScheme (TPMI_ALG_ECC_SCHEME).
/// See definition in Part 2: Structures, section 11.2.5.4.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgEccScheme{
    RSAPSS = TPM2AlgID::RSAPSS.0,
    RSASSA = TPM2AlgID::RSASSA.0,
    ECDSA = TPM2AlgID::ECDSA.0,
    ECDAA = TPM2AlgID::ECDAA.0,
    SM2 = TPM2AlgID::SM2.0,
    ECSchnorr = TPM2AlgID::ECSchnorr.0,
    ECDH = TPM2AlgID::ECDH.0,
    ECMQV = TPM2AlgID::ECMQV.0,
}

/// TpmiAlgAsymScheme represents all the scheme types for any asymmetric algortihm (TPMI_ALG_ASYM_SCHEME).
/// See definition in Part 2: Structures, section 11.2.3.4.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgAsymScheme{
    SM2 = TPM2AlgID::SM2.0,
    ECDH = TPM2AlgID::ECDH.0,
    ECMQV = TPM2AlgID::ECMQV.0,
    RSAPSS = TPM2AlgID::RSAPSS.0,
    RSASSA = TPM2AlgID::RSASSA.0,
    ECDSA = TPM2AlgID::ECDSA.0,
    ECDAA = TPM2AlgID::ECDAA.0,
    ECSchnorr = TPM2AlgID::ECSchnorr.0,
    RSAES = TPM2AlgID::RSAES.0,
    OAEP = TPM2AlgID::OAEP.0,
}

/// TpmiRhNvIndex represents an NV location (TPMI_RH_NV_INDEX).
/// See definition in Part 2: Structures, section 9.24.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
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
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
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
    pub const RS_PW: TpmiShAuthSession = TpmiShAuthSession(TPM2Handle::RSPW.0);
}

/// TpmiEccCurve represents an implemented ECC curve (TPMI_ECC_SCHEME).
/// See definition in Part 2: Structures, section 11.2.5.5.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiEccCurve(TPM2ECCCurve);

/// TpmiYesNo is used in place of a boolean.
/// See TPMI_YES_NO definition in Part 2: Structures, section 9.2.
#[open_enum]
#[repr(u8)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
pub enum TpmiYesNo {
    NO = 0,
    YES = 1,
}

/// TpmiStAttest represents an attestation structure type (TPMI_ST_ATTEST).
/// See definition in Part 2: Structures, section 10.12.10.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
pub enum TpmiStAttest {
    AttestCertify = TPM2ST::AttestCertify.0,
    AttestQuote = TPM2ST::AttestQuote.0,
    AttestSessionAudit = TPM2ST::AttestSessionAudit.0,
    AttestCommandAudit = TPM2ST::AttestCommandAudit.0,
    AttestTime = TPM2ST::AttestTime.0,
    AttestCreation = TPM2ST::AttestCreation.0,
    AttestNV = TPM2ST::AttestNV.0,
    AttestNVDigest = TPM2ST::AttestNVDigest.0,
}

/// The number of bits in an AES key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAesKeyBits(u16);
/// The number of bits in an SM4 key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiSm4KeyBits(u16);
/// The number of bits in a Camellia key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiCamelliaKeyBits(u16);
/// The number of bits in an RSA key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiRsaKeyBits(u16);

/// TpmaObject indicates an object's use, authorization types, and relationship to other objects (TPMA_OBJECT).
/// See definition in Part 2: Structures, section 8.3.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
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
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
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
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
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
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
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
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
pub enum TpmiStCommandTag{
    NoSessions = TPM2ST::NoSessions.0,
    Sessions = TPM2ST::Sessions.0,
}

const TPM2_MAX_CAP_DATA: usize =
    TPM2_MAX_CAP_BUFFER as usize - size_of::<TPM2Cap>() - size_of::<u32>();
const TPM2_MAX_CAP_ALGS: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsAlgProperty>();
const TPM2_MAX_CAP_HANDLES: usize = TPM2_MAX_CAP_DATA / size_of::<TPM2Handle>();
const TPM2_MAX_CAP_CC: usize = TPM2_MAX_CAP_DATA / size_of::<TPM2CC>();
const TPM2_MAX_TPM_PROPERTIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedProperty>();
const TPM2_MAX_PCR_PROPERTIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedPcrSelect>();
const TPM2_MAX_ECC_CURVES: usize = TPM2_MAX_CAP_DATA / size_of::<TPM2ECCCurve>();
const TPM2_MAX_TAGGED_POLICIES: usize = TPM2_MAX_CAP_DATA / size_of::<TpmsTaggedPolicy>();
const TPML_DIGEST_MAX_DIGESTS: usize = 8;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsEmpty;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal, UnionSize)]
pub enum TpmtHa {
    Sha1([u8; constants::TPM2_SHA_DIGEST_SIZE as usize]) = TPM2AlgID::SHA1.0,
    Sha256([u8; constants::TPM2_SHA256_DIGEST_SIZE as usize]) = TPM2AlgID::SHA256.0,
    Sha384([u8; constants::TPM2_SHA384_DIGEST_SIZE as usize]) = TPM2AlgID::SHA384.0,
    Sha512([u8; constants::TPM2_SHA512_DIGEST_SIZE as usize]) = TPM2AlgID::SHA512.0,
    Sm3_256([u8; constants::TPM2_SM3_256_DIGEST_SIZE as usize]) = TPM2AlgID::SM3256.0,
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
    Handle(TPM2Handle),
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDigest {
    size: u16,
    pub buffer: [u8; TpmtHa::UNION_SIZE],
}

pub type Tpm2bNonce = Tpm2bDigest;
pub type Tpm2bOperand = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bData {
    size: u16,
    pub buffer: [u8; TpmtHa::UNION_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEvent {
    size: u16,
    pub buffer: [u8; 1024],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_DIGEST_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxNvBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_NV_BUFFER_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bIv {
    size: u16,
    pub buffer: [u8; TPM2_MAX_SYM_BLOCK_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bName {
    size: u16,
    pub name: [u8; TpmuName::UNION_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bMaxCapBuffer {
    size: u16,
    pub buffer: [u8; TPM2_MAX_CAP_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: TpmiYesNo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmsPcrSelection {
    pub hash: TpmiAlgHash,
    pub sizeof_select: u8,
    #[length(sizeof_select)]
    pub pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlPcrSelection {
    count: u32,
    #[length(count)]
    pcr_selections: [TpmsPcrSelection; TPM2_NUM_PCR_BANKS as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsQuoteInfo {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsCreationInfo {
    pub object_name: Tpm2bName,
    pub creation_hash: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsCertifyInfo {
    pub name: Tpm2bName,
    pub qualified_name: Tpm2bName,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct TpmsCommandAuditInfo {
    pub audit_counter: u64,
    pub digest_alg: u16,
    pub audit_digest: Tpm2bDigest,
    pub command_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSessionAuditInfo {
    pub exclusive_session: TpmiYesNo,
    pub session_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsTimeInfo {
    pub time: u64,
    pub clock_info: TpmsClockInfo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsTimeAttestInfo {
    pub time: TpmsTimeInfo,
    pub firmware_version: u64,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsNvCertifyInfo {
    pub index_name: Tpm2bName,
    pub offset: u16,
    pub nv_contents: Tpm2bMaxNvBuffer,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub enum TpmuAttest {
    Certify(TpmsCertifyInfo) = TPM2ST::AttestCertify.0,
    Creation(TpmsCreationInfo) = TPM2ST::AttestCreation.0,
    Quote(TpmsQuoteInfo) = TPM2ST::AttestQuote.0,
    CommandAudit(TpmsCommandAuditInfo) = TPM2ST::AttestCommandAudit.0,
    SessionAudit(TpmsSessionAuditInfo) = TPM2ST::AttestSessionAudit.0,
    Time(TpmsTimeAttestInfo) = TPM2ST::AttestTime.0,
    Nv(TpmsNvCertifyInfo) = TPM2ST::AttestNV.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub struct TpmsAttest {
    pub magic: TPM2Generated,
    pub qualified_signer: Tpm2bName,
    pub extra_data: Tpm2bData,
    pub clock_info: TpmsClockInfo,
    pub firmware_version: u64,
    pub attested: TpmuAttest,
}
// Custom overload of Marshalable, because the selector for attested is {un}marshaled separate from the field.
impl Marshalable for TpmsAttest {
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize> {
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

    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self> {
        let magic = TPM2Generated::try_unmarshal(buffer)?;
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
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bAttest {
    size: u16,
    pub attestation_data: [u8; size_of::<TpmsAttest>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSymKey {
    size: u16,
    pub buffer: [u8; TPM2_MAX_SYM_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bLabel {
    size: u16,
    pub buffer: [u8; TPM2_LABEL_MAX_BUFFER as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsDerive {
    pub label: Tpm2bLabel,
    pub context: Tpm2bLabel,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bDerive {
    size: u16,
    pub buffer: [u8; size_of::<TpmsDerive>()],
}
#[derive(UnionSize)]
#[repr(C, u16)]
enum TpmuSensitiveCreate {
    Create([u8; constants::TPM2_MAX_SYM_DATA as usize]),
    Derive(TpmsDerive),
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitiveData {
    size: u16,
    pub buffer: [u8; TpmuSensitiveCreate::UNION_SIZE],
}

pub type Tpm2bAuth = Tpm2bDigest;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2bAuth,
    pub data: Tpm2bSensitiveData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitiveCreate {
    size: u16,
    pub sensitive: [u8; size_of::<TpmsSensitiveCreate>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublicKeyRsa {
    size: u16,
    pub buffer: [u8; TPM2_MAX_RSA_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateKeyRsa {
    size: u16,
    pub buffer: [u8; (TPM2_MAX_RSA_KEY_BYTES / 2) as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccParameter {
    size: u16,
    pub buffer: [u8; TPM2_MAX_ECC_KEY_BYTES as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsEccPoint {
    pub x: Tpm2bEccParameter,
    pub y: Tpm2bEccParameter,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEccPoint {
    size: u16,
    pub point: [u8; size_of::<TpmsEccPoint>()],
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
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bEncryptedSecret {
    size: u16,
    pub secret: [u8; TpmuEncryptedSecret::UNION_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSchemeXor {
    pub hash_alg: TpmiAlgHash,
    pub kdf: TpmiAlgKdf,
}

pub type TpmsSchemeHmac = TpmsSchemeHash;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtKeyedHashScheme {
    Hmac(TpmsSchemeHmac) = TPM2AlgID::HMAC.0,
    ExclusiveOr(TpmsSchemeXor) = TPM2AlgID::XOR.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsKeyedHashParms {
    pub scheme: TpmtKeyedHashScheme,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtSymDefObject {
    Aes(TpmiAesKeyBits, TpmiAlgSymMode) = TPM2AlgID::AES.0,
    Sm4(TpmiSm4KeyBits, TpmiAlgSymMode) = TPM2AlgID::SM4.0,
    Camellia(TpmiCamelliaKeyBits, TpmiAlgSymMode) = TPM2AlgID::Camellia.0,
    ExclusiveOr(TpmiAlgHash, TpmsEmpty) = TPM2AlgID::XOR.0,
    Null(TpmsEmpty, TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSymCipherParms {
    pub sym: TpmtSymDefObject,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSchemeHash {
    pub hash_alg: TpmiAlgHash,
}

pub type TpmsKeySchemeEcdh = TpmsSchemeHash;
pub type TpmsKeySchemeEcmqv = TpmsSchemeHash;
pub type TpmsSigSchemeRsassa = TpmsSchemeHash;
pub type TpmsSigSchemeRsapss = TpmsSchemeHash;
pub type TpmsSigSchemeEcdsa = TpmsSchemeHash;
pub type TpmsSigSchemeSm2 = TpmsSchemeHash;
pub type TpmsSigSchemeEcschnorr = TpmsSchemeHash;
pub type TpmsSigSchemeEcdaa = TpmsSchemeHash;
pub type TpmsEncSchemeOaep = TpmsSchemeHash;
pub type TpmsEncSchemeRsaes = TpmsEmpty;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtRsaScheme {
    Rsapss(TpmsSigSchemeRsapss) = TPM2AlgID::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TPM2AlgID::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2AlgID::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2AlgID::ECDAA.0,
    Sm2(TpmsSigSchemeSm2) = TPM2AlgID::SM2.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2AlgID::ECSchnorr.0,
    Rsaes(TpmsEncSchemeRsaes) = TPM2AlgID::RSAES.0,
    Oaep(TpmsEncSchemeOaep) = TPM2AlgID::OAEP.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsRsaParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtRsaScheme,
    pub key_bits: TpmiRsaKeyBits,
    pub exponent: u32,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtEccScheme {
    Rsapss(TpmsSigSchemeRsapss) = TPM2AlgID::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TPM2AlgID::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2AlgID::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2AlgID::ECDAA.0,
    Sm2(TpmsSigSchemeSm2) = TPM2AlgID::SM2.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2AlgID::ECSchnorr.0,
    Ecdh(TpmsKeySchemeEcdh) = TPM2AlgID::ECDH.0,
    Ecmqv(TpmsKeySchemeEcmqv) = TPM2AlgID::ECMQV.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

pub type TpmsSchemeMgf1 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_56a = TpmsSchemeHash;
pub type TpmsSchemeKdf2 = TpmsSchemeHash;
pub type TpmsSchemeKdf1Sp800_108 = TpmsSchemeHash;

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtKdfScheme {
    Mgf1(TpmsSchemeMgf1) = TPM2AlgID::MGF1.0,
    Kdf1Sp800_56a(TpmsSchemeKdf1Sp800_56a) = TPM2AlgID::KDF1SP80056A.0,
    Kdf2(TpmsSchemeKdf2) = TPM2AlgID::KDF2.0,
    Kdf1Sp800_108(TpmsSchemeKdf1Sp800_108) = TPM2AlgID::KDF1SP800108.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsEccParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtEccScheme,
    pub curve_id: TpmiEccCurve,
    pub kdf: TpmtKdfScheme,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtAsymScheme {
    Ecdh(TpmsKeySchemeEcdh) = TPM2AlgID::ECDH.0,
    Ecmqv(TpmsKeySchemeEcmqv) = TPM2AlgID::ECMQV.0,
    Sm2(TpmsSigSchemeSm2) = TPM2AlgID::SM2.0,
    Rsapss(TpmsSigSchemeRsapss) = TPM2AlgID::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TPM2AlgID::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2AlgID::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2AlgID::ECDAA.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2AlgID::ECSchnorr.0,
    Rsaes(TpmsEncSchemeRsaes) = TPM2AlgID::RSAES.0,
    Oaep(TpmsEncSchemeOaep) = TPM2AlgID::OAEP.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
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
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum PublicParmsAndId {
    KeyedHash(TpmsKeyedHashParms, Tpm2bDigest) = TPM2AlgID::KeyedHash.0,
    Sym(TpmsSymCipherParms, Tpm2bDigest) = TPM2AlgID::SymCipher.0,
    Rsa(TpmsRsaParms, Tpm2bPublicKeyRsa) = TPM2AlgID::RSA.0,
    Ecc(TpmsEccParms, TpmsEccPoint) = TPM2AlgID::ECC.0,
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
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize> {
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
    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self> {
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
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPublic {
    size: u16,
    pub public_area: [u8; size_of::<TpmtPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bTemplate {
    size: u16,
    pub buffer: [u8; size_of::<TpmtPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivateVendorSpecific {
    size: u16,
    pub buffer: [u8; TPM2_PRIVATE_VENDOR_SPECIFIC_BYTES as usize],
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmuSensitiveComposite {
    Rsa(Tpm2bPrivateKeyRsa) = TPM2AlgID::RSA.0,
    Ecc(Tpm2bEccParameter) = TPM2AlgID::ECC.0,
    Bits(Tpm2bSensitiveData) = TPM2AlgID::KeyedHash.0,
    Sym(Tpm2bSymKey) = TPM2AlgID::SymCipher.0,
    /* For size purposes only */
    Any(Tpm2bPrivateVendorSpecific) = TPM2AlgID::Null.0,
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
    fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize> {
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

    fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self> {
        let selector = u16::try_unmarshal(buffer)?;
        Ok(TpmtSensitive {
            auth_value: Tpm2bAuth::try_unmarshal(buffer)?,
            seed_value: Tpm2bDigest::try_unmarshal(buffer)?,
            sensitive: TpmuSensitiveComposite::try_unmarshal_variant(selector, buffer)?,
        })
    }
}

#[repr(C, u32)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmsCapabilityData {
    Algorithms(TpmlAlgProperty) = TPM2Cap::Algs.0,
    Handles(TpmlHandle) = TPM2Cap::Handles.0,
    Command(TpmlCca) = TPM2Cap::Commands.0,
    PpCommands(TpmlCc) = TPM2Cap::PPCommands.0,
    AuditCommands(TpmlCc) = TPM2Cap::AuditCommands.0,
    AssignedPcr(TpmlPcrSelection) = TPM2Cap::PCRs.0,
    TpmProperties(TpmlTaggedTpmProperty) = TPM2Cap::TPMProperties.0,
    PcrProperties(TpmlTaggedPcrProperty) = TPM2Cap::PCRProperties.0,
    EccCurves(TpmlEccCurve) = TPM2Cap::ECCCurves.0,
    AuthPolicies(TpmlTaggedPolicy) = TPM2Cap::AuthPolicies.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlAlgProperty {
    count: u32,
    #[length(count)]
    alg_properties: [TpmsAlgProperty; TPM2_MAX_CAP_ALGS],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlHandle {
    count: u32,
    #[length(count)]
    handle: [TPM2Handle; TPM2_MAX_CAP_HANDLES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlCca {
    count: u32,
    #[length(count)]
    command_attributes: [TpmaCc; TPM2_MAX_CAP_CC],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlCc {
    count: u32,
    #[length(count)]
    command_codes: [TPM2CC; TPM2_MAX_CAP_CC],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlTaggedTpmProperty {
    count: u32,
    #[length(count)]
    tpm_property: [TpmsTaggedProperty; TPM2_MAX_TPM_PROPERTIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlTaggedPcrProperty {
    count: u32,
    #[length(count)]
    pcr_property: [TpmsTaggedPcrSelect; TPM2_MAX_PCR_PROPERTIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlEccCurve {
    count: u32,
    #[length(count)]
    ecc_curves: [TPM2ECCCurve; TPM2_MAX_ECC_CURVES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlTaggedPolicy {
    count: u32,
    #[length(count)]
    policies: [TpmsTaggedPolicy; TPM2_MAX_TAGGED_POLICIES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Debug, Marshal)]
pub struct TpmsAlgProperty {
    pub alg: TPM2AlgID,
    pub alg_properties: TpmaAlgorithm,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Debug, Marshal)]
pub struct TpmsTaggedProperty {
    pub property: TPM2PT,
    pub value: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Debug, Marshal)]
pub struct TpmsTaggedPcrSelect {
    tag: TPM2PTPCR,
    size_of_select: u8,
    #[length(size_of_select)]
    pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal, Default)]
pub struct TpmsTaggedPolicy {
    handle: TPM2Handle,
    policy_hash: TpmtHa,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmlDigest {
    count: u32,
    #[length(count)]
    digests: [Tpm2bDigest; TPML_DIGEST_MAX_DIGESTS],
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Debug, Marshal)]
pub struct TpmsAuthCommand {
    pub session_handle: TpmiShAuthSession,
    pub nonce: Tpm2bNonce,
    pub session_attributes: TpmaSession,
    pub hmac: Tpm2bAuth,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Debug, Marshal)]
pub struct TpmsAuthResponse {
    pub nonce: Tpm2bNonce,
    pub session_attributes: TpmaSession,
    pub hmac: Tpm2bData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bSensitive {
    size: u16,
    pub sensitive_area: [u8; size_of::<TpmtSensitive>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct _PRIVATE {
    integrity_outer: Tpm2bDigest,
    integrity_inner: Tpm2bDigest,
    sensitive: Tpm2bSensitive,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bPrivate {
    size: u16,
    pub buffer: [u8; size_of::<_PRIVATE>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsIdObject {
    pub integrity_hmac: Tpm2bDigest,
    pub enc_identity: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bIdObject {
    size: u16,
    pub credential: [u8; size_of::<TpmsIdObject>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
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
    pub nv_public: [u8; size_of::<TpmsNvPublic>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bContextSensitive {
    size: u16,
    pub buffer: [u8; TPM2_MAX_CONTEXT_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsContextData {
    pub integrity: Tpm2bDigest,
    pub encrypted: Tpm2bContextSensitive,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bContextData {
    size: u16,
    pub buffer: [u8; size_of::<TpmsContextData>()],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsCreationData {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
    pub locality: TpmaLocality,
    pub parent_name_alg: TPM2AlgID,
    pub parent_name: Tpm2bName,
    pub parent_qualified_name: Tpm2bName,
    pub outside_info: Tpm2bData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tpm2bCreationData {
    size: u16,
    pub creation_data: [u8; size_of::<TpmsCreationData>()],
}

// Helper for splitting up ranges of an unmarshal buffer.

pub trait Tpm2bSimple {
    const MAX_BUFFER_SIZE: usize;
    fn get_size(&self) -> u16;
    fn get_buffer(&self) -> &[u8];
    fn from_bytes(buffer: &[u8]) -> TpmRcResult<Self>
    where
        Self: Sized;
}

macro_rules! impl_try_marshalable_tpm2b_simple {
    ($T:ty, $F:ident) => {
        impl Tpm2bSimple for $T {
            const MAX_BUFFER_SIZE: usize = size_of::<$T>() - size_of::<u16>();

            fn get_size(&self) -> u16 {
                self.size
            }

            fn get_buffer(&self) -> &[u8] {
                &self.$F[0..self.get_size() as usize]
            }

            fn from_bytes(buffer: &[u8]) -> TpmRcResult<Self> {
                // Overflow check
                if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
                    return Err(TpmRcError::Size);
                }

                let mut dest: Self = Self {
                    size: buffer.len() as u16,
                    $F: [0; Self::MAX_BUFFER_SIZE],
                };
                dest.$F[..buffer.len()].copy_from_slice(buffer);
                Ok(dest)
            }
        }

        impl Default for $T {
            fn default() -> Self {
                Self {
                    size: 0,
                    $F: [0; Self::MAX_BUFFER_SIZE],
                }
            }
        }

        impl Marshalable for $T {
            fn try_unmarshal(buffer: &mut UnmarshalBuf) -> TpmRcResult<Self> {
                let got_size = u16::try_unmarshal(buffer)?;
                // Ensure the buffer is large enough to fullfill the size indicated
                let sized_buffer = buffer.get(got_size as usize);
                if !sized_buffer.is_some() {
                    return Err(TpmRcError::Memory);
                }

                let mut dest: Self = Self {
                    size: got_size,
                    $F: [0; Self::MAX_BUFFER_SIZE],
                };

                // Make sure the size indicated isn't too large for the types buffer
                if sized_buffer.unwrap().len() > dest.$F.len() {
                    return Err(TpmRcError::Memory);
                }
                dest.$F[..got_size.into()].copy_from_slice(&sized_buffer.unwrap());

                Ok(dest)
            }

            fn try_marshal(&self, buffer: &mut [u8]) -> TpmRcResult<usize> {
                let used = self.size.try_marshal(buffer)?;
                let (_, rest) = buffer.split_at_mut(used);
                let buffer_marsh = self.get_size() as usize;
                if buffer_marsh > (core::cmp::max(Self::MAX_BUFFER_SIZE, rest.len())) {
                    return Err(TpmRcError::Memory);
                }
                rest[..buffer_marsh].copy_from_slice(&self.$F[..buffer_marsh]);
                Ok(used + buffer_marsh)
            }
        }
    };
}

impl_try_marshalable_tpm2b_simple! {Tpm2bName, name}
impl_try_marshalable_tpm2b_simple! {Tpm2bAttest, attestation_data}
impl_try_marshalable_tpm2b_simple! {Tpm2bContextData, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bContextSensitive, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bData, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bDigest, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bEccParameter, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bEncryptedSecret, secret}
impl_try_marshalable_tpm2b_simple! {Tpm2bEvent, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bIdObject, credential}
impl_try_marshalable_tpm2b_simple! {Tpm2bIv, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bMaxBuffer, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bMaxNvBuffer, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bPrivate, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bPrivateKeyRsa, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bPrivateVendorSpecific, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bPublicKeyRsa, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bSensitiveData, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bSymKey, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bTemplate, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bLabel, buffer}
impl_try_marshalable_tpm2b_simple! {Tpm2bSensitiveCreate, sensitive}
impl_try_marshalable_tpm2b_simple! {Tpm2bPublic, public_area}
impl_try_marshalable_tpm2b_simple! {Tpm2bCreationData, creation_data}

/// Provides conversion to/from a struct type for TPM2B types that don't hold a bytes buffer.
pub trait Tpm2bStruct: Tpm2bSimple {
    type StructType: Marshalable;

    /// Marshals the value into the 2b holder.
    fn from_struct(val: &Self::StructType) -> TpmRcResult<Self>
    where
        Self: Sized;

    /// Extracts the struct value from the 2b holder.
    fn to_struct(&self) -> TpmRcResult<Self::StructType>;
}
macro_rules! impl_try_marshalable_tpm2b_struct {
    ($T:ty, $StructType:ty, $F:ident) => {
        impl Tpm2bStruct for $T {
            type StructType = $StructType;

            fn from_struct(val: &Self::StructType) -> TpmRcResult<Self> {
                let mut x = Self::default();
                x.size = val.try_marshal(&mut x.$F)? as u16;
                Ok(x)
            }

            fn to_struct(&self) -> TpmRcResult<Self::StructType> {
                let mut buf = UnmarshalBuf::new(&self.$F[0..self.get_size() as usize]);
                Self::StructType::try_unmarshal(&mut buf)
            }
        }
    };
}
impl_try_marshalable_tpm2b_struct! {Tpm2bSensitiveCreate, TpmsSensitiveCreate, sensitive}
impl_try_marshalable_tpm2b_struct! {Tpm2bPublic, TpmtPublic, public_area}
impl_try_marshalable_tpm2b_struct! {Tpm2bCreationData, TpmsCreationData, creation_data}

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
impl_tpml! {TpmlHandle, handle, TPM2Handle, TPM2_MAX_CAP_HANDLES}
impl_tpml! {TpmlCc, command_codes, TPM2CC, TPM2_MAX_CAP_CC}
impl_tpml! {TpmlTaggedTpmProperty, tpm_property, TpmsTaggedProperty, TPM2_MAX_TPM_PROPERTIES}
impl_tpml! {TpmlTaggedPcrProperty, pcr_property, TpmsTaggedPcrSelect, TPM2_MAX_PCR_PROPERTIES}
impl_tpml! {TpmlEccCurve, ecc_curves, TPM2ECCCurve, TPM2_MAX_ECC_CURVES}
impl_tpml! {TpmlTaggedPolicy, policies, TpmsTaggedPolicy, TPM2_MAX_TAGGED_POLICIES}
impl_tpml! {TpmlDigest, digests, Tpm2bDigest, TPML_DIGEST_MAX_DIGESTS}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    // Unfortunately, I didn't see a way to generate a function name easily, see
    // https://github.com/rust-lang/rust/issues/29599 for more details. So we just
    // generate the test body here.
    macro_rules! impl_test_tpm2b_simple {
        ($T:ty) => {
            const SIZE_OF_U16: usize = size_of::<u16>();
            const SIZE_OF_TYPE: usize = size_of::<$T>();
            const SIZE_OF_BUFFER: usize = SIZE_OF_TYPE - SIZE_OF_U16;

            /*
             * Generate arrays that are:
             *   - too small
             *   - smaller than buffer limit
             *   - same size as buffer limit
             *   - exceeding buffer limit
             */
            let mut too_small_size_buf: [u8; 1] = [0x00; 1];
            let mut smaller_size_buf: [u8; SIZE_OF_TYPE - 8] = [0xFF; SIZE_OF_TYPE - 8];
            let mut same_size_buf: [u8; SIZE_OF_TYPE] = [0xFF; SIZE_OF_TYPE];
            let mut bigger_size_buf: [u8; SIZE_OF_TYPE + 8] = [0xFF; SIZE_OF_TYPE + 8];

            let mut s = (smaller_size_buf.len() - SIZE_OF_U16) as u16;
            assert!(s.try_marshal(&mut smaller_size_buf).is_ok());

            s = (same_size_buf.len() - SIZE_OF_U16) as u16;
            assert!(s.try_marshal(&mut same_size_buf).is_ok());

            s = (bigger_size_buf.len() - SIZE_OF_U16) as u16;
            assert!(s.try_marshal(&mut bigger_size_buf).is_ok());

            // too small should fail
            let mut result: TpmRcResult<$T> =
                <$T>::try_unmarshal(&mut UnmarshalBuf::new(&too_small_size_buf));
            assert!(result.is_err());

            // bigger size should consume only the prefix
            result = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&bigger_size_buf));
            assert!(result.is_err());

            // small, should be good
            result = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&smaller_size_buf));
            assert!(result.is_ok());
            let mut digest = result.unwrap();
            assert_eq!(
                usize::from(digest.get_size()),
                smaller_size_buf.len() - SIZE_OF_U16
            );
            assert_eq!(digest.get_buffer(), &smaller_size_buf[SIZE_OF_U16..]);

            // same size should be good
            result = <$T>::try_unmarshal(&mut UnmarshalBuf::new(&same_size_buf));
            assert!(result.is_ok());
            digest = result.unwrap();
            assert_eq!(
                usize::from(digest.get_size()),
                same_size_buf.len() - size_of::<u16>()
            );
            assert_eq!(digest.get_buffer(), &same_size_buf[size_of::<u16>()..]);

            let mut mres = digest.try_marshal(&mut too_small_size_buf);
            assert!(mres.is_err());

            mres = digest.try_marshal(&mut same_size_buf);
            assert!(mres.is_ok());
            assert_eq!(mres.unwrap(), digest.get_size() as usize + SIZE_OF_U16);
            let mut new_digest =
                <$T>::try_unmarshal(&mut UnmarshalBuf::new(&same_size_buf)).unwrap();
            assert_eq!(digest, new_digest);

            mres = digest.try_marshal(&mut bigger_size_buf);
            assert!(mres.is_ok());
            assert_eq!(mres.unwrap(), digest.get_size() as usize + SIZE_OF_U16);
            new_digest =
                <$T>::try_unmarshal(&mut UnmarshalBuf::new(&bigger_size_buf[..SIZE_OF_TYPE]))
                    .unwrap();
            assert_eq!(digest, new_digest);
        };
    }

    #[test]
    fn test_try_unmarshal_tpm2b_name() {
        impl_test_tpm2b_simple! {Tpm2bName};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_attest() {
        impl_test_tpm2b_simple! {Tpm2bAttest};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_context_data() {
        impl_test_tpm2b_simple! {Tpm2bContextData};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_context_sensitive() {
        impl_test_tpm2b_simple! {Tpm2bContextSensitive};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_data() {
        impl_test_tpm2b_simple! {Tpm2bData};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_digest() {
        impl_test_tpm2b_simple! {Tpm2bDigest};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_ecc_parameter() {
        impl_test_tpm2b_simple! {Tpm2bEccParameter};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_encrypted_secret() {
        impl_test_tpm2b_simple! {Tpm2bEncryptedSecret};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_event() {
        impl_test_tpm2b_simple! {Tpm2bEvent};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_id_object() {
        impl_test_tpm2b_simple! {Tpm2bIdObject};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_iv() {
        impl_test_tpm2b_simple! {Tpm2bIv};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_max_buffer() {
        impl_test_tpm2b_simple! {Tpm2bMaxBuffer};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_max_nv_buffer() {
        impl_test_tpm2b_simple! {Tpm2bMaxNvBuffer};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_private() {
        impl_test_tpm2b_simple! {Tpm2bPrivate};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_private_key_rsa() {
        impl_test_tpm2b_simple! {Tpm2bPrivateKeyRsa};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_private_vendor_specific() {
        impl_test_tpm2b_simple! {Tpm2bPrivateVendorSpecific};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_public_key_rsa() {
        impl_test_tpm2b_simple! {Tpm2bPublicKeyRsa};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_sensitive_data() {
        impl_test_tpm2b_simple! {Tpm2bSensitiveData};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_sym_key() {
        impl_test_tpm2b_simple! {Tpm2bSymKey};
    }

    #[test]
    fn test_try_unmarshal_tpm2b_template() {
        impl_test_tpm2b_simple! {Tpm2bTemplate};
    }

    #[test]
    fn test_impl_tpml_new() {
        let elements: Vec<TPM2Handle> = (0..TPM2_MAX_CAP_HANDLES + 1)
            .map(|i| TPM2Handle(i as u32))
            .collect();
        for x in 0..TPM2_MAX_CAP_HANDLES {
            let slice = &elements.as_slice()[..x];
            let list = TpmlHandle::new(&slice).unwrap();
            assert_eq!(list.count(), x);
            assert_eq!(list.handle(), slice);
        }
        assert!(
            TpmlHandle::new(elements.as_slice()).is_err(),
            "Creating a TpmlHandle with more elements than capacity should fail."
        );
    }

    #[test]
    fn test_impl_tpml_default_add() {
        let elements: Vec<TPM2Handle> = (0..TPM2_MAX_CAP_HANDLES + 1)
            .map(|i| TPM2Handle(i as u32))
            .collect();
        let mut list = TpmlHandle::default();
        for x in 0..TPM2_MAX_CAP_HANDLES {
            let slice = &elements.as_slice()[..x];
            assert_eq!(list.handle(), slice);

            list.add(&elements.get(x).unwrap()).unwrap();
            assert_eq!(list.count(), x + 1);
        }
        assert!(
            TpmlHandle::new(elements.as_slice()).is_err(),
            "Creating a TpmlHandle with more elements than capacity should fail."
        );
    }

    #[test]
    fn test_marshal_struct_derive() {
        let name_buffer: [u8; 4] = [1, 2, 3, 4];
        let index_name = Tpm2bName::from_bytes(&name_buffer).unwrap();
        let nv_buffer = [24u8; 10];
        let nv_contents = Tpm2bMaxNvBuffer::from_bytes(&nv_buffer).unwrap();
        let info: TpmsNvCertifyInfo = TpmsNvCertifyInfo {
            index_name,
            offset: 10,
            nv_contents,
        };
        let mut marshal_buffer = [0u8; 48];
        let bytes = info.try_marshal(&mut marshal_buffer).unwrap();

        // Build the expected output manually.
        let mut expected = Vec::with_capacity(bytes);
        expected.extend_from_slice(&index_name.get_size().to_be_bytes());
        expected.extend_from_slice(&name_buffer);
        expected.extend_from_slice(&info.offset.to_be_bytes());
        expected.extend_from_slice(&nv_contents.get_size().to_be_bytes());
        expected.extend_from_slice(&nv_buffer);

        assert_eq!(expected.len(), bytes);
        assert_eq!(expected, marshal_buffer[..expected.len()]);

        let unmarshaled = TpmsNvCertifyInfo::try_unmarshal(&mut UnmarshalBuf::new(&marshal_buffer));
        assert_eq!(unmarshaled.unwrap(), info);
    }

    #[test]
    fn test_marshal_enum_override() {
        let hmac = TpmsSchemeHmac {
            hash_alg: TpmiAlgHash::SHA256,
        };
        let scheme = TpmtKeyedHashScheme::Hmac(hmac);
        let mut buffer = [0u8; size_of::<TpmtKeyedHashScheme>()];
        assert!(scheme.try_marshal(&mut buffer).is_ok());
    }

    #[test]
    fn test_marshal_tpmt_public() {
        let xor_sym_def_obj = TpmtSymDefObject::ExclusiveOr(TpmiAlgHash::SHA256, TpmsEmpty {});
        let mut buffer = [0u8; size_of::<TpmtSymDefObject>()];
        let mut marsh = xor_sym_def_obj.try_marshal(&mut buffer);
        // Because XOR does not populate TpmuSymMode, we have bytes left over.
        assert!(marsh.unwrap() < buffer.len());
        let rsa_scheme = TpmtRsaScheme::Ecdsa(TpmsSigSchemeEcdsa {
            hash_alg: TpmiAlgHash::SHA256,
        });

        let rsa_parms = TpmsRsaParms {
            symmetric: xor_sym_def_obj,
            scheme: rsa_scheme,
            key_bits: TpmiRsaKeyBits(74),
            exponent: 2,
        };

        let pubkey_buf = [9u8; 24];
        let pubkey = Tpm2bPublicKeyRsa::from_bytes(&pubkey_buf).unwrap();

        let example = TpmtPublic {
            name_alg: TpmiAlgHash::SHA256,
            object_attributes: TpmaObject::RESTRICTED | TpmaObject::SENSITIVE_DATA_ORIGIN,
            auth_policy: Tpm2bDigest::from_bytes(&[2, 2, 4, 4]).unwrap(),
            parms_and_id: PublicParmsAndId::Rsa(rsa_parms, pubkey),
        };

        // Test a round-trip marshaling and unmarshaling, confirm that we get the same output.
        let mut buffer = [0u8; 256];
        marsh = example.try_marshal(&mut buffer);
        assert!(marsh.is_ok());
        let expected: [u8; 54] = [
            0, 1, 0, 11, 0, 1, 0, 32, 0, 4, 2, 2, 4, 4, 0, 10, 0, 11, 0, 24, 0, 11, 0, 74, 0, 0, 0,
            2, 0, 24, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        ];
        //assert_eq!(expected.len(), marsh.unwrap());
        assert_eq!(buffer[..expected.len()], expected);
        let unmarsh_buf = buffer.clone();
        let mut unmarsh = TpmtPublic::try_unmarshal(&mut UnmarshalBuf::new(&unmarsh_buf));
        let bytes_example = unmarsh.unwrap();
        assert_eq!(bytes_example.object_attributes, example.object_attributes);
        let mut remarsh_buffer = [1u8; 256];
        let remarsh = unmarsh.unwrap().try_marshal(&mut remarsh_buffer);
        assert_eq!(remarsh, marsh);
        assert_eq!(remarsh_buffer[..marsh.unwrap()], buffer[..marsh.unwrap()]);

        // Test invalid selector value.
        assert!(TPM2AlgID::SHA256.try_marshal(&mut buffer).is_ok());
        unmarsh = TpmtPublic::try_unmarshal(&mut UnmarshalBuf::new(&buffer));
        assert_eq!(unmarsh.err(), Some(TpmRcError::Selector.into()));
    }

    #[test]
    fn test_attributes_field() {
        let mut cc = TpmaCc::NV | TpmaCc::FLUSHED | TpmaCc::command_index(0x8);
        assert_eq!(cc.get_command_index(), 0x8);
        cc.set_command_index(0xA0);
        assert_eq!(cc.get_command_index(), 0xA0);

        // Set a field to a value that is wider than the field.
        cc.set_c_handles(0xFFFFFFFF);
        assert_eq!(cc.get_c_handles(), 0x7, "Only the field bits should be set");
        assert_eq!(cc.get_command_index(), 0xA0);
        assert!(cc.contains(TpmaCc::NV));
        assert!((cc & TpmaCc::FLUSHED).0 != 0);
    }

    #[test]
    fn test_nv_index_range() {
        let lowest_ok = TpmHc::NVIndexFirst.get();
        assert!(TpmiRhNvIndex::try_from(lowest_ok - 1).is_err());
        assert!(TpmiRhNvIndex::try_from(lowest_ok).is_ok());
        assert!(TpmiRhNvIndex::try_from(lowest_ok + 432).is_ok());
        let highest_ok = TpmHc::NVIndexLast.get();
        assert!(TpmiRhNvIndex::try_from(highest_ok).is_ok());
        assert!(TpmiRhNvIndex::try_from(highest_ok + 1).is_err());
    }

    #[test]
    fn test_2b_struct() {
        let creation_data = TpmsCreationData {
            pcr_select: TpmlPcrSelection::new(&[TpmsPcrSelection {
                hash: TpmiAlgHash::SHA256,
                sizeof_select: 2,
                pcr_select: [0xF, 0xF, 0x0, 0x0],
            }])
            .unwrap(),
            pcr_digest: Tpm2bDigest::from_bytes(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9])
                .unwrap(),
            locality: TpmaLocality(0xA),
            parent_name_alg: TPM2AlgID::SHA384,
            parent_name: Tpm2bName::from_bytes(&[0xA, 0xB, 0xC, 0xD, 0xE, 0xF]).unwrap(),
            parent_qualified_name: Tpm2bName::default(),
            outside_info: Tpm2bData::from_bytes(&[0x1; 32]).unwrap(),
        };
        let creation_data_2b = Tpm2bCreationData::from_struct(&creation_data).unwrap();
        let out_creation_data = creation_data_2b.to_struct().unwrap();
        assert_eq!(creation_data, out_creation_data);
    }
}
