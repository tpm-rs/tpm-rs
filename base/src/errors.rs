#![allow(dead_code)]
use core::convert::From;
use core::num::{NonZeroU32, TryFromIntError};

pub type Tpm2Rc = u32;
pub type Tss2Rc = Tpm2Rc;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TpmError(pub NonZeroU32);
impl TpmError {
    const fn new_const(val: u32) -> Self {
        match NonZeroU32::new(val) {
            Some(val) => Self(val),
            None => panic!("TpmError cannot be 0"),
        }
    }

    const TSS2_RC_LAYER_SHIFT_VAL: u32 = 16;
    pub const TSS2_RC_LAYER_SHIFT: TpmError = TpmError::new_const(Self::TSS2_RC_LAYER_SHIFT_VAL);
    pub const TSS2_RC_LAYER_MASK: TpmError =
        TpmError::new_const(0xFF << Self::TSS2_RC_LAYER_SHIFT_VAL);
    const TSS2_MU_RC_LAYER_VAL: u32 = 9 << Self::TSS2_RC_LAYER_SHIFT_VAL;
    pub const TSS2_MU_RC_LAYER: TpmError = TpmError::new_const(Self::TSS2_MU_RC_LAYER_VAL);

    pub const TSS2_BASE_RC_GENERAL_FAILURE: TpmError = TpmError::new_const(1);
    pub const TSS2_BASE_RC_NOT_IMPLEMENTED: TpmError = TpmError::new_const(2);
    pub const TSS2_BASE_RC_BAD_CONTEXT: TpmError = TpmError::new_const(3);
    pub const TSS2_BASE_RC_ABI_MISMATCH: TpmError = TpmError::new_const(4);
    pub const TSS2_BASE_RC_BAD_REFERENCE: TpmError = TpmError::new_const(5);
    const TSS2_BASE_RC_INSUFFICIENT_BUFFER_VAL: u32 = 6;
    pub const TSS2_BASE_RC_INSUFFICIENT_BUFFER: TpmError =
        TpmError::new_const(Self::TSS2_BASE_RC_INSUFFICIENT_BUFFER_VAL);
    pub const TSS2_BASE_RC_BAD_SEQUENCE: TpmError = TpmError::new_const(7);
    pub const TSS2_BASE_RC_NO_CONNECTION: TpmError = TpmError::new_const(8);
    pub const TSS2_BASE_RC_TRY_AGAIN: TpmError = TpmError::new_const(9);
    pub const TSS2_BASE_RC_IO_ERROR: TpmError = TpmError::new_const(10);
    pub const TSS2_BASE_RC_BAD_VALUE: TpmError = TpmError::new_const(11);
    pub const TSS2_BASE_RC_NOT_PERMITTED: TpmError = TpmError::new_const(12);
    pub const TSS2_BASE_RC_INVALID_SESSIONS: TpmError = TpmError::new_const(13);
    pub const TSS2_BASE_RC_NO_DECRYPT_PARAM: TpmError = TpmError::new_const(14);
    pub const TSS2_BASE_RC_NO_ENCRYPT_PARAM: TpmError = TpmError::new_const(15);
    const TSS2_BASE_RC_BAD_SIZE_VAL: u32 = 16;
    pub const TSS2_BASE_RC_BAD_SIZE: TpmError =
        TpmError::new_const(Self::TSS2_BASE_RC_BAD_SIZE_VAL);
    pub const TSS2_BASE_RC_MALFORMED_RESPONSE: TpmError = TpmError::new_const(17);
    pub const TSS2_BASE_RC_INSUFFICIENT_CONTEXT: TpmError = TpmError::new_const(18);
    pub const TSS2_BASE_RC_INSUFFICIENT_RESPONSE: TpmError = TpmError::new_const(19);

    pub const TSS2_MU_RC_INSUFFICIENT_BUFFER: TpmError = TpmError::new_const(
        Self::TSS2_MU_RC_LAYER_VAL | Self::TSS2_BASE_RC_INSUFFICIENT_BUFFER_VAL,
    );
    pub const TSS2_MU_RC_BAD_SIZE: TpmError =
        TpmError::new_const(Self::TSS2_MU_RC_LAYER_VAL | Self::TSS2_BASE_RC_BAD_SIZE_VAL);

    const TPM2_RC_FMT1: u32 = 0x080;
    pub const TPM2_RC_SIZE: TpmError = TpmError::new_const(Self::TPM2_RC_FMT1 + 0x015);
    pub const TPM2_RC_SELECTOR: TpmError = TpmError::new_const(Self::TPM2_RC_FMT1 + 0x018);
}

impl From<core::num::NonZeroU32> for crate::TpmError {
    fn from(val: core::num::NonZeroU32) -> Self {
        crate::TpmError(val)
    }
}

impl From<TpmError> for core::num::NonZeroU32 {
    fn from(val: TpmError) -> Self {
        val.0
    }
}

impl From<TpmError> for u32 {
    fn from(val: TpmError) -> Self {
        core::num::NonZeroU32::from(val).get()
    }
}

impl TryFrom<u32> for TpmError {
    type Error = TryFromIntError;
    fn try_from(val: u32) -> Result<Self, TryFromIntError> {
        match NonZeroU32::try_from(val) {
            Ok(val) => Ok(TpmError(val)),
            Err(err) => Err(err),
        }
    }
}

pub type TpmResult<T> = Result<T, TpmError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from() {
        assert!(TpmError::try_from(0).is_err());
        assert_eq!(
            Ok(TpmError::TSS2_BASE_RC_BAD_SEQUENCE),
            TpmError::try_from(7)
        );
    }
}
