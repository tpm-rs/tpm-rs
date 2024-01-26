use core::num::NonZeroU32;

/// Represents success or [`TssRcError`] failure.
pub type TssRcResult<T> = Result<T, TssRcError>;

/// Represents a client side error.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TssRcError(NonZeroU32);

// Allow constant to have enum-style case.
#[allow(non_upper_case_globals)]
impl TssRcError {
    // TODO add comments from spec
    pub const GeneralFailure: Self = Self::new_mu(1);
    pub const NotImplemented: Self = Self::new_mu(2);
    pub const BadContext: Self = Self::new_mu(3);
    pub const AbiMismatch: Self = Self::new_mu(4);
    pub const BadReference: Self = Self::new_mu(5);
    pub const InsufficientBuffer: Self = Self::new_mu(6);
    pub const BadSequence: Self = Self::new_mu(7);
    pub const NoConnection: Self = Self::new_mu(8);
    pub const TryAgain: Self = Self::new_mu(9);
    pub const IoError: Self = Self::new_mu(10);
    pub const BadValue: Self = Self::new_mu(11);
    pub const NotPermitted: Self = Self::new_mu(12);
    pub const InvalidSessions: Self = Self::new_mu(13);
    pub const NoDecryptParam: Self = Self::new_mu(14);
    pub const NoEncryptParam: Self = Self::new_mu(15);
    pub const BadSize: Self = Self::new_mu(16);
    pub const MalformedResponse: Self = Self::new_mu(17);
    pub const InsufficientContext: Self = Self::new_mu(18);
    pub const InsufficientResponse: Self = Self::new_mu(19);

    /// Returns the underlying non-zero `u32`.
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// Creates a new [`TssRc`] in the MU errors space by OR'ing it with the provided value.
    const fn new_mu(val: u32) -> Self {
        match NonZeroU32::new(val | 0x90000) {
            Some(val) => Self(val),
            None => unreachable!(),
        }
    }
}

impl From<TssRcError> for super::TpmError {
    fn from(val: TssRcError) -> Self {
        super::TpmError(val.0)
    }
}
