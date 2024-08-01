// =============================================================================
// USES
// =============================================================================

use bitflags::bitflags;
use tpm2_rs_marshal::Marshal;

// =============================================================================
// MODULES
// =============================================================================

mod cc;
pub use cc::*;
mod locality;
pub use locality::*;
mod nv;
pub use nv::*;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

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

// =============================================================================
// TYPES
// =============================================================================

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
