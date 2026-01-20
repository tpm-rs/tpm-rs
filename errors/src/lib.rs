#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

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

impl fmt::Display for TssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.get())
    }
}

impl Error for TssError {}

#[cfg(feature = "std")]
impl From<std::io::Error> for TssError {
    fn from(_: std::io::Error) -> Self {
        // Note that this impl drops information from the io error.
        // We should make our error type more robust than TssError.
        TssError(NonZeroU32::new(0xFFFFFFFF).unwrap())
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
