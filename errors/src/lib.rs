#![forbid(unsafe_code)]

use core::num::NonZeroU32;

pub use tpm_rc::*;
pub use tss_rc::*;

mod tpm_rc;
mod tss_rc;

/// Represents success or [`TpmError`] failure, which can happen at any layer.
pub type TpmResult<T> = Result<T, TpmError>;

/// A TPM error that can occur any any layer, e.g. Service (`TpmRcError`) and Client errors
/// can be coalesced into this error type.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TpmError(NonZeroU32);
impl TpmError {
    /// Returns the underlying non-zero `u32`.
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Error returned when trying to convert `0` into `TpmError`.
#[cfg_attr(test, derive(Debug))]
pub struct TpmErrorCannotBeZero;

impl TryFrom<u32> for TpmError {
    type Error = TpmErrorCannotBeZero;
    fn try_from(val: u32) -> Result<Self, Self::Error> {
        match NonZeroU32::try_from(val) {
            Ok(val) => Ok(TpmError(val)),
            Err(_) => Err(TpmErrorCannotBeZero),
        }
    }
}
