//! TPM 2.0 Error Types
//!
//! This module implements the TPM 2.0 Response Codes (TPM_RC) defined in
//! **Part 2: Structures, Section 6** of the TPM 2.0 Specification, as well as
//! error types for unmarshalling and hash algorithm operations:
//!
//! - [`TpmRc`]: TPM 2.0 response codes (`TPM_RC`) returned by the TPM device itself.
//! - [`UnmarshalError`]: Error returned when unmarshalling data fails.
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
/// Preserves the specific TPM 2.0 response code (`TPM_RC`) and the optional handle,
/// parameter, or session position index (`Position`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnmarshalError {
    /// The underlying TPM response code (`TPM_RC`).
    pub rc: TpmRc,
    /// Optional handle, parameter, or session index where the failure occurred.
    pub position: Option<Position>,
}

impl UnmarshalError {
    /// `TPM_RC_INSUFFICIENT`: Not enough data in the buffer (`0x09A`).
    pub const INSUFFICIENT: Self = Self::from_fmt1(TpmRc::INSUFFICIENT);
    /// `TPM_RC_SIZE`: Structure is the wrong size (`0x095`).
    pub const SIZE: Self = Self::from_fmt1(TpmRc::SIZE);
    /// `TPM_RC_VALUE`: Value is out of range or is not correct for the context (`0x084`).
    pub const VALUE: Self = Self::from_fmt1(TpmRc::VALUE);
    /// `TPM_RC_RESERVED_BITS`: Reserved bits in a structure are not zero (`0x0A1`).
    pub const RESERVED_BITS: Self = Self::from_fmt1(TpmRc::RESERVED_BITS);
    /// `TPM_RC_CURVE`: Unsupported elliptic curve (`0x0A6`).
    pub const CURVE: Self = Self::from_fmt1(TpmRc::CURVE);
    /// `TPM_RC_HASH`: Unsupported hash algorithm (`0x083`).
    pub const HASH: Self = Self::from_fmt1(TpmRc::HASH);
    /// `TPM_RC_MODE`: Unsupported symmetric mode (`0x089`).
    pub const MODE: Self = Self::from_fmt1(TpmRc::MODE);
    /// `TPM_RC_SCHEME`: Unsupported or incompatible scheme (`0x092`).
    pub const SCHEME: Self = Self::from_fmt1(TpmRc::SCHEME);
    /// `TPM_RC_SELECTOR`: Union selector is incorrect (`0x098`).
    pub const SELECTOR: Self = Self::from_fmt1(TpmRc::SELECTOR);
    /// `TPM_RC_SYMMETRIC`: Unsupported symmetric algorithm or key size (`0x096`).
    pub const SYMMETRIC: Self = Self::from_fmt1(TpmRc::SYMMETRIC);
    /// `TPM_RC_TAG`: Incorrect structure tag (`0x097`).
    pub const TAG: Self = Self::from_fmt1(TpmRc::TAG);
    /// `TPM_RC_HIERARCHY`: Invalid hierarchy (`0x085`).
    pub const HIERARCHY: Self = Self::from_fmt1(TpmRc::HIERARCHY);
    /// `TPM_RC_ASYMMETRIC`: Unsupported asymmetric algorithm (`0x081`).
    pub const ASYMMETRIC: Self = Self::from_fmt1(TpmRc::ASYMMETRIC);
    /// `TPM_RC_KEY_SIZE`: Unsupported key size (`0x087`).
    pub const KEY_SIZE: Self = Self::from_fmt1(TpmRc::KEY_SIZE);
    /// `TPM_RC_TYPE`: Invalid type (`0x08A`).
    pub const TYPE: Self = Self::from_fmt1(TpmRc::TYPE);
    /// `TPM_RC_HANDLE`: Invalid handle (`0x08B`).
    pub const HANDLE: Self = Self::from_fmt1(TpmRc::HANDLE);
    /// `TPM_RC_ATTRIBUTES`: Inconsistent attributes (`0x082`).
    pub const ATTRIBUTES: Self = Self::from_fmt1(TpmRc::ATTRIBUTES);
    /// `TPM_RC_KDF`: Unsupported KDF (`0x08C`).
    pub const KDF: Self = Self::from_fmt1(TpmRc::KDF);
    /// `TPM_RC_MGF`: Unsupported MGF (`0x088`).
    pub const MGF: Self = Self::from_fmt1(TpmRc::MGF);
    /// `TPM_RC_RANGE`: Value out of allowed range (`0x08D`).
    pub const RANGE: Self = Self::from_fmt1(TpmRc::RANGE);
    /// `TPM_RC_ECC_POINT`: Point is not on the required curve (`0x0A7`).
    pub const ECC_POINT: Self = Self::from_fmt1(TpmRc::ECC_POINT);
    /// `TPM_RC_PARMS`: Parameter set not supported (`0x0AA`).
    pub const PARMS: Self = Self::from_fmt1(TpmRc::PARMS);
    /// `TPM_RC_BAD_TAG`: Invalid command tag (`0x01E`).
    pub const BAD_TAG: Self = Self::new(TpmRc::BAD_TAG);
    /// `TPM_RC_PCR`: PCR index out of range (`0x127`).
    pub const PCR: Self = Self::new(TpmRc::PCR);

    /// Alias for [`Self::INSUFFICIENT`].
    #[allow(non_upper_case_globals)]
    pub const Insufficient: Self = Self::INSUFFICIENT;
    /// Alias for [`Self::SIZE`].
    #[allow(non_upper_case_globals)]
    pub const Size: Self = Self::SIZE;
    /// Alias for [`Self::VALUE`].
    #[allow(non_upper_case_globals)]
    pub const Value: Self = Self::VALUE;
    /// Alias for [`Self::RESERVED_BITS`].
    #[allow(non_upper_case_globals)]
    pub const ReservedBits: Self = Self::RESERVED_BITS;
    /// Alias for [`Self::CURVE`].
    #[allow(non_upper_case_globals)]
    pub const Curve: Self = Self::CURVE;
    /// Alias for [`Self::HASH`].
    #[allow(non_upper_case_globals)]
    pub const Hash: Self = Self::HASH;
    /// Alias for [`Self::MODE`].
    #[allow(non_upper_case_globals)]
    pub const Mode: Self = Self::MODE;
    /// Alias for [`Self::SCHEME`].
    #[allow(non_upper_case_globals)]
    pub const Scheme: Self = Self::SCHEME;
    /// Alias for [`Self::SELECTOR`].
    #[allow(non_upper_case_globals)]
    pub const Selector: Self = Self::SELECTOR;
    /// Alias for [`Self::SYMMETRIC`].
    #[allow(non_upper_case_globals)]
    pub const Symmetric: Self = Self::SYMMETRIC;
    /// Alias for [`Self::TAG`].
    #[allow(non_upper_case_globals)]
    pub const Tag: Self = Self::TAG;
    /// Alias for [`Self::HIERARCHY`].
    #[allow(non_upper_case_globals)]
    pub const Hierarchy: Self = Self::HIERARCHY;
    /// Alias for [`Self::ASYMMETRIC`].
    #[allow(non_upper_case_globals)]
    pub const Asymmetric: Self = Self::ASYMMETRIC;
    /// Alias for [`Self::KEY_SIZE`].
    #[allow(non_upper_case_globals)]
    pub const KeySize: Self = Self::KEY_SIZE;
    /// Alias for [`Self::TYPE`].
    #[allow(non_upper_case_globals)]
    pub const Type: Self = Self::TYPE;
    /// Alias for [`Self::HANDLE`].
    #[allow(non_upper_case_globals)]
    pub const Handle: Self = Self::HANDLE;
    /// Alias for [`Self::ATTRIBUTES`].
    #[allow(non_upper_case_globals)]
    pub const Attributes: Self = Self::ATTRIBUTES;
    /// Alias for [`Self::KDF`].
    #[allow(non_upper_case_globals)]
    pub const Kdf: Self = Self::KDF;
    /// Alias for [`Self::MGF`].
    #[allow(non_upper_case_globals)]
    pub const Mgf: Self = Self::MGF;
    /// Alias for [`Self::RANGE`].
    #[allow(non_upper_case_globals)]
    pub const Range: Self = Self::RANGE;
    /// Alias for [`Self::ECC_POINT`].
    #[allow(non_upper_case_globals)]
    pub const EccPoint: Self = Self::ECC_POINT;
    /// Alias for [`Self::PARMS`].
    #[allow(non_upper_case_globals)]
    pub const Parms: Self = Self::PARMS;
    /// Alias for [`Self::BAD_TAG`].
    #[allow(non_upper_case_globals)]
    pub const BadTag: Self = Self::BAD_TAG;
    /// Alias for [`Self::PCR`].
    #[allow(non_upper_case_globals)]
    pub const Pcr: Self = Self::PCR;

    /// Creates a new `UnmarshalError` with the given `TpmRc`, extracting any
    /// position already encoded in `rc` and normalizing `self.rc` to the base
    /// Format-1 code when applicable.
    #[inline]
    pub const fn new(rc: TpmRc) -> Self {
        let (rc, position) = match rc.to_fmt1() {
            Some((fmt1, pos)) => (fmt1.to_rc(), pos),
            None => (rc, None),
        };
        Self { rc, position }
    }

    /// Creates a new `UnmarshalError` from a `Fmt1` base error code.
    #[inline]
    pub const fn from_fmt1(rc: Fmt1) -> Self {
        Self {
            rc: rc.to_rc(),
            position: None,
        }
    }

    /// Attaches a `Position` to this error if one has not already been attached,
    /// and the underlying `rc` does not already encode a position.
    #[inline]
    pub const fn with_position(mut self, pos: Position) -> Self {
        match (self.rc.to_fmt1(), self.position) {
            (Some((fmt1, Some(existing_pos))), None) => {
                self.rc = fmt1.to_rc();
                self.position = Some(existing_pos);
            }
            (Some((fmt1, _)), Some(_)) => {
                self.rc = fmt1.to_rc();
            }
            (_, None) => {
                self.position = Some(pos);
            }
            (None, Some(_)) => {}
        }
        self
    }

    /// Attaches a 1-based handle position (`Position::handle(n)`) if not already positioned.
    #[inline]
    pub const fn in_handle(self, n: u8) -> Self {
        self.with_position(Position::handle(n))
    }

    /// Attaches a parameter position (`Position::parameter(n)`) if not already positioned.
    #[inline]
    pub const fn in_parameter(self, n: u8) -> Self {
        self.with_position(Position::parameter(n))
    }

    /// Attaches a session position (`Position::session(n)`) if not already positioned.
    #[inline]
    pub const fn in_session(self, n: u8) -> Self {
        self.with_position(Position::session(n))
    }

    /// Attaches an unspecified parameter position (`Position::unspecified_parameter()`) if not already positioned.
    #[inline]
    pub const fn in_unspecified_parameter(self) -> Self {
        self.with_position(Position::unspecified_parameter())
    }

    /// Attaches an unspecified session position (`Position::unspecified_session()`) if not already positioned.
    #[inline]
    pub const fn in_unspecified_session(self) -> Self {
        self.with_position(Position::unspecified_session())
    }

    /// Converts this unmarshalling error into the full `TpmRc`, incorporating any handle,
    /// parameter, or session position if the error is a Format-1 error code.
    #[inline]
    pub const fn to_rc(self) -> TpmRc {
        match self.position {
            Some(pos) => self.rc.with_position(pos),
            None => self.rc,
        }
    }
}

impl Default for UnmarshalError {
    #[inline]
    fn default() -> Self {
        Self::SIZE
    }
}

impl From<Fmt1> for UnmarshalError {
    #[inline]
    fn from(rc: Fmt1) -> Self {
        Self::from_fmt1(rc)
    }
}

impl From<TpmRc> for UnmarshalError {
    #[inline]
    fn from(rc: TpmRc) -> Self {
        Self::new(rc)
    }
}

impl fmt::Display for UnmarshalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unmarshal error ({})", self.to_rc())
    }
}

impl error::Error for UnmarshalError {}

impl From<UnmarshalError> for TpmRc {
    #[inline]
    fn from(err: UnmarshalError) -> Self {
        err.to_rc()
    }
}
