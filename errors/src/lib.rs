#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

use core::convert::TryFrom;
use core::error::Error;
use core::fmt;
use core::num::NonZeroU32;
use core::result::{Result, Result::*};
pub use tpm_rc::*;
pub use tss_rc::*;

mod tpm_rc;
mod tss_rc;

/// Represents success or [`TssError`] failure, which can happen at any layer.
pub type TssResult<T> = Result<T, TssError>;

/// A TSS error that can occur any any layer, e.g. Service (`TpmRcError`) and Client errors
/// can be coalesced into this error type.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TssError(NonZeroU32);
impl TssError {
    /// Returns the underlying non-zero `u32`.
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Error returned when trying to convert `0` into `TssError`.
#[cfg_attr(test, derive(Debug))]
pub struct TssErrorCannotBeZero;

impl TryFrom<u32> for TssError {
    type Error = TssErrorCannotBeZero;
    fn try_from(val: u32) -> Result<Self, Self::Error> {
        match NonZeroU32::try_from(val) {
            Ok(val) => Ok(TssError(val)),
            Err(_) => Err(TssErrorCannotBeZero),
        }
    }
}

/// Represents success or [`MarshalingError`] failure, which is used for unmarshal/marshal functionality.
pub type MarshalingResult<T> = Result<T, MarshalingError>;

impl Error for MarshalingError {}

impl fmt::Display for MarshalingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArrayLengthExceeded => {
                write!(f, "length of array is larger than the type allows")
            }
            Self::UnexpectedEndOfBuffer => {
                write!(f, "expected to have more buffer data but found none")
            }
            Self::UnknownSelector => {
                write!(f, "selector targeted is not known to the unmarshaling code")
            }
            Self::MarshalingDeriveError => write!(f, "unexpected derive error"),
        }
    }
}

impl From<MarshalingError> for TpmRcError {
    fn from(orig: MarshalingError) -> Self {
        match orig {
            MarshalingError::ArrayLengthExceeded => TpmRcError::Size,
            MarshalingError::UnexpectedEndOfBuffer => TpmRcError::Memory,
            MarshalingError::UnknownSelector => TpmRcError::Selector,
            MarshalingError::MarshalingDeriveError => TpmRcError::Failure,
        }
    }
}

impl From<MarshalingError> for TssError {
    fn from(orig: MarshalingError) -> Self {
        match orig {
            MarshalingError::ArrayLengthExceeded => TpmRcError::Size.into(),
            MarshalingError::UnexpectedEndOfBuffer => TpmRcError::Memory.into(),
            MarshalingError::UnknownSelector => TpmRcError::Selector.into(),
            MarshalingError::MarshalingDeriveError => TpmRcError::Failure.into(),
        }
    }
}

// The MarshalingError defines Unmarshaling/Marshaling errors codes,
// providing more explicit error codes for try_marshal* and try_unmarchal*.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum MarshalingError {
    ArrayLengthExceeded,
    UnexpectedEndOfBuffer,
    UnknownSelector,
    MarshalingDeriveError,
}
