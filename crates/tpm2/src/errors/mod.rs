//! TPM 2.0 Error Types
//!
//! This module implements the TPM 2.0 Response Codes (TPM_RC) defined in
//! **Part 2: Structures, Section 6** of the TPM 2.0 Specification, as well as
//! error types for unmarshalling and hash algorithm operations:
//!
//! - [`TpmRc`]: TPM 2.0 response codes (`TPM_RC`) returned by the TPM device itself.
//! - [`UnmarshalError`]: Error returned when unmarshalling data fails, identifying
//!   the Format-One response code for the failure.
//!
//! When a TPM command fails, the TPM returns a 32-bit response code (`TPM_RC`) that
//! describes the failure. The specification defines two formats for response codes:
//!
//! - **Format 0 (Simple)**: Standard error codes that indicate general TPM failures
//!   (e.g., initialization state, resource exhaustion, self-test failures).
//! - **Format 1 (Format-On-Error)**: Detailed error codes that pinpoint the exact
//!   position (parameter, handle, or session) and reason for failure
//!   (e.g., parameter value out of range, invalid handle, session authorization failure).
use core::{error, fmt};

mod tpm_rc;
pub use tpm_rc::{Fmt1, Position, TpmRc};

/// Error returned when unmarshalling data fails.
///
/// Each variant corresponds to the Format-One response code (see [`Self::fmt1`])
/// that the TPM 2.0 specification assigns to that kind of unmarshalling failure.
/// The code carries no [`Position`]; unmarshalling a command or response
/// ([`UnmarshalMessage`](crate::commands::UnmarshalMessage)) adds the position
/// of the failing parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmarshalError {
    /// The input ended before the structure was complete (`TPM_RC_INSUFFICIENT`).
    Insufficient,
    /// A size or count is out of range or inconsistent with the data (`TPM_RC_SIZE`).
    Size,
    /// A value is not one of its allowed values (`TPM_RC_VALUE`).
    Value,
    /// A hash algorithm is not supported or not allowed (`TPM_RC_HASH`).
    Hash,
    /// A symmetric algorithm is not supported or not allowed (`TPM_RC_SYMMETRIC`).
    Symmetric,
    /// A symmetric cipher mode is not supported or not allowed (`TPM_RC_MODE`).
    Mode,
    /// A key derivation function is not supported or not allowed (`TPM_RC_KDF`).
    Kdf,
    /// A scheme is not supported or not allowed (`TPM_RC_SCHEME`).
    Scheme,
    /// An elliptic curve is not supported (`TPM_RC_CURVE`).
    Curve,
    /// An object type is not supported or not allowed (`TPM_RC_TYPE`).
    Type,
    /// A structure tag is incorrect (`TPM_RC_TAG`).
    Tag,
    /// A union selector is incorrect (`TPM_RC_SELECTOR`).
    Selector,
    /// A reserved bit is set (`TPM_RC_RESERVED_BITS`).
    ReservedBits,
    /// A parameter set is not supported (`TPM_RC_PARMS`).
    Parms,
}

impl UnmarshalError {
    /// The Format-One response code (without position) for this error.
    pub const fn fmt1(self) -> Fmt1 {
        match self {
            Self::Insufficient => TpmRc::INSUFFICIENT,
            Self::Size => TpmRc::SIZE,
            Self::Value => TpmRc::VALUE,
            Self::Hash => TpmRc::HASH,
            Self::Symmetric => TpmRc::SYMMETRIC,
            Self::Mode => TpmRc::MODE,
            Self::Kdf => TpmRc::KDF,
            Self::Scheme => TpmRc::SCHEME,
            Self::Curve => TpmRc::CURVE,
            Self::Type => TpmRc::TYPE,
            Self::Tag => TpmRc::TAG,
            Self::Selector => TpmRc::SELECTOR,
            Self::ReservedBits => TpmRc::RESERVED_BITS,
            Self::Parms => TpmRc::PARMS,
        }
    }
}

impl From<UnmarshalError> for Fmt1 {
    fn from(err: UnmarshalError) -> Self {
        err.fmt1()
    }
}

impl From<UnmarshalError> for TpmRc {
    fn from(err: UnmarshalError) -> Self {
        err.fmt1().to_rc()
    }
}

impl fmt::Display for UnmarshalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unmarshal error: {self:?} ({})", self.fmt1().to_rc())
    }
}

impl error::Error for UnmarshalError {}
