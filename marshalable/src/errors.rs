use core::fmt;
use tpm2_rs_errors::{TpmRcError, TssError};

/// The [`Result`] represents success or [`Error`] failure, which is used for unmarshal/marshal functionality.
pub type Result<T> = core::result::Result<T, Error>;

/// The [`Error`] defines Unmarshaling/Marshaling errors codes,
/// providing more explicit error codes for try_marshal* and try_unmarshal*.
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug, Hash)]
pub enum Error {
    ArrayLengthExceeded,
    UnexpectedEndOfBuffer,
    UnknownSelector,
}

impl fmt::Display for Error {
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
        }
    }
}

impl From<Error> for TpmRcError {
    fn from(orig: Error) -> Self {
        match orig {
            Error::ArrayLengthExceeded => TpmRcError::Size,
            Error::UnexpectedEndOfBuffer => TpmRcError::Memory,
            Error::UnknownSelector => TpmRcError::Selector,
        }
    }
}

impl From<Error> for TssError {
    fn from(orig: Error) -> Self {
        TpmRcError::from(orig).into()
    }
}
