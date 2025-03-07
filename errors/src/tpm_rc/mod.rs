use core::num::NonZeroU32;
use core::option::{Option, Option::*};
use core::result::Result;

/// Represents success or [`TpmRcError`] failure.
pub type TpmRcResult<T> = Result<T, TpmRcError>;

/// Represents a TPM 2.0 service error as defined in specification as TPM_RC.
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct TpmRcError(NonZeroU32);

// Allow constant to have enum-style case.
#[allow(non_upper_case_globals)]
impl TpmRcError {
    /// Offset for Format 1 style TPM_RC error codes.
    const RC_FMT1: u32 = 0x080;

    /// Asymmetric algorithm not supported or not correct (`TPM_RC_ASYMMETRIC`).
    pub const Asymmetric: Self = Self::new(Self::RC_FMT1 + 0x001);

    /// Asymmetric algorithm not supported or not correct for the specified
    /// parameters (`TPM_RC_ASYMMETRIC`).
    #[allow(non_snake_case)]
    pub const fn AsymmetricFor(on: ErrorType, pos: ErrorPosition) -> Self {
        Self::new(Self::Asymmetric.0.get() | on.to_mask() | pos.to_mask())
    }

    /// Value is out of range or is not correct for the context (`TPM_RC_VALUE`).
    pub const Value: Self = Self::new(Self::RC_FMT1 + 0x004);

    /// Value is out of range or is not correct for the context for the specified
    /// parameters (`TPM_RC_VALUE`).
    #[allow(non_snake_case)]
    pub const fn ValueFor(on: ErrorType, pos: ErrorPosition) -> Self {
        Self::new(Self::Value.0.get() | on.to_mask() | pos.to_mask())
    }

    /// Structure is the wrong size (`TPM_RC_SIZE`).
    pub const Size: Self = Self::new(Self::RC_FMT1 + 0x015);

    /// Structure is the wrong size for the specified parameters (`TPM_RC_SIZE`).
    #[allow(non_snake_case)]
    pub const fn SizeFor(on: ErrorType, pos: ErrorPosition) -> Self {
        Self::new(Self::Size.0.get() | on.to_mask() | pos.to_mask())
    }

    /// Union selector is incorrect (`TPM_RC_SELECTOR`).
    pub const Selector: Self = Self::new(Self::RC_FMT1 + 0x018);

    /// Union selector is incorrect for the specified parameters (`TPM_RC_SELECTOR`).
    #[allow(non_snake_case)]
    pub const fn SelectorFor(on: ErrorType, pos: ErrorPosition) -> Self {
        Self::new(Self::Selector.0.get() | on.to_mask() | pos.to_mask())
    }

    /// The tag is bad (`TPM_RC_BAD_TAG`).
    pub const BadTag: Self = Self::new(0x1e);

    /// TPM not initialized by TPM2_Startup or already initialized (`TPM_RC_INITIALIZE`).
    pub const Initialize: Self = Self::new(0x100);
    /// Commands not being accepted because of a TPM failure (`TPM_RC_FAILURE`).
    pub const Failure: Self = Self::new(0x101);
    /// Improper use of a sequence handle (`TPM_RC_SEQUENCE`).
    pub const Sequence: Self = Self::new(0x102);

    /// Command commandSize value is inconsistent with contents of the command buffer; either the
    /// size is not the same as the octets loaded by the hardware interface layer or the value is
    /// not large enough to hold a command header (`TPM_RC_COMMAND_SIZE`).
    pub const CommandSize: Self = Self::new(0x142);

    /// Command code not supported (`TPM_RC_COMMAND_CODE`).
    pub const CommandCode: Self = Self::new(0x143);

    /// Gap for context ID is too large (`TPM_RC_CONTEXT_GAP`).
    pub const ContextGap: Self = Self::new(0x901);

    /// Out of memory for object contexts (`TPM_RC_OBJECT_MEMORY`).
    pub const ObjectMemory: Self = Self::new(0x902);

    /// Out of memory for session contexts (`TPM_RC_SESSION_MEMORY`).
    pub const SessionMemory: Self = Self::new(0x903);

    /// Out of shared object/session memory or need space for internal operations (`TPM_RC_MEMORY`).
    pub const Memory: Self = Self::new(0x904);

    /// Returns the underlying non-zero `u32`.
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// Returns true if the response code is a warning and the command was not necessarily in error.
    /// This command indicates that the TPM is busy or that the resources of the TPM have to be
    /// adjusted in order to allow the command to execute.
    pub const fn is_warning(self) -> bool {
        // Format0 (0x80 is unset; 0x100 is set) with warning (0x800 is set)
        self.0.get() & 0x980 == 0x900
    }

    /// Returns the format1 type and position parameters if this is a format1 error type.
    pub const fn format1_parameter(self) -> Option<(ErrorType, ErrorPosition)> {
        match (
            ErrorType::from_mask(self.get()),
            ErrorPosition::from_mask(self.get()),
        ) {
            // TODO: Is it possible to have ErrorType without ErrorPosition?
            (Some(on), Some(pos)) => Some((on, pos)),
            _ => None,
        }
    }

    /// Creates a new [`TpmRcError`] from a non-zero value.
    ///
    /// # Panics
    ///
    /// Panics if the value is `0`.
    const fn new(val: u32) -> Self {
        match NonZeroU32::new(val) {
            Some(val) => Self(val),
            None => panic!("TpmRcError cannot be 0"),
        }
    }
}

/// Represents the type of error for a Format1 `TpmRcError` code.
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum ErrorType {
    /// Error occurred with a Handle.
    Handle,
    /// Error occurred with a Parameter.
    Parameter,
    /// Error occurred with a Session/
    Session,
}

impl ErrorType {
    const PARAMETER_MASK: u32 = 0x40;
    const SESSION_MASK: u32 = 0x800;
    const HANDLE_MASK: u32 = 0x0;

    const fn to_mask(self) -> u32 {
        match self {
            Self::Handle => Self::HANDLE_MASK,
            Self::Parameter => Self::PARAMETER_MASK,
            Self::Session => Self::SESSION_MASK,
        }
    }

    const fn from_mask(val: u32) -> Option<Self> {
        if val & 0x80 == 0 {
            return None;
        }
        if val & Self::PARAMETER_MASK != 0 {
            Some(Self::Parameter)
        } else if Self::SESSION_MASK != 0 {
            Some(Self::Session)
        } else {
            Some(Self::Handle)
        }
    }
}

/// Represents the positional parameter of the error starting from 1 of a Format1 [`TpmRcError`].
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum ErrorPosition {
    /// First handle/parameter/session caused the failure.
    Pos1 = 1,
    /// Second handle/parameter/session caused the failure.
    Pos2,
    /// Third handle/parameter/session caused the failure.
    Pos3,
    /// Forth handle/parameter/session caused the failure.
    Pos4,
    /// Fifth handle/parameter/session caused the failure.
    Pos5,
    /// Sixth handle/parameter/session caused the failure.
    Pos6,
    /// Seventh handle/parameter/session caused the failure.
    Pos7,
    /// Eighth handle/parameter/session caused the failure.
    Pos8,
    /// Ninth handle/parameter/session caused the failure.
    Pos9,
    /// Tenth handle/parameter/session caused the failure.
    PosA,
    /// Eleventh handle/parameter/session caused the failure.
    PosB,
    /// Twelfth handle/parameter/session caused the failure.
    PosC,
    /// Thirteenth handle/parameter/session caused the failure.
    PosD,
    /// Fourteenth handle/parameter/session caused the failure.
    PosE,
    /// Fifteenth handle/parameter/session caused the failure.
    PosF,
}

impl ErrorPosition {
    const fn to_mask(self) -> u32 {
        (self as u32) << 8
    }

    const fn from_mask(val: u32) -> Option<Self> {
        if val & 0x80 == 0 {
            return None;
        }
        match val & 0xF00 {
            0x100 => Some(Self::Pos1),
            0x200 => Some(Self::Pos2),
            0x300 => Some(Self::Pos3),
            0x400 => Some(Self::Pos4),
            0x500 => Some(Self::Pos5),
            0x600 => Some(Self::Pos6),
            0x700 => Some(Self::Pos7),
            0x800 => Some(Self::Pos8),
            0x900 => Some(Self::Pos9),
            0xA00 => Some(Self::PosA),
            0xB00 => Some(Self::PosB),
            0xC00 => Some(Self::PosC),
            0xD00 => Some(Self::PosD),
            0xE00 => Some(Self::PosE),
            0xF00 => Some(Self::PosF),
            _ => None,
        }
    }
}

impl From<TpmRcError> for super::TssError {
    fn from(val: TpmRcError) -> Self {
        super::TssError(val.0)
    }
}

#[cfg(test)]
mod tests;
