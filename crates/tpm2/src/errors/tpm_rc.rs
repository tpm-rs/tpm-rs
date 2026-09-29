use core::{error, fmt, num::NonZero};

use crate::{Marshal, Unmarshal, errors::UnmarshalError};

/// Represents a TPM 2.0 service error as defined in specification as `TPM_RC`.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct TpmRc(NonZero<u32>);

impl TpmRc {
    /// Create a raw TpmRc from a `u32` value.
    pub const fn new(x: u32) -> Option<Self> {
        match NonZero::new(x) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }
    /// Get the raw non-zero `u32` value.
    pub const fn get(self) -> u32 {
        self.0.get()
    }
    const RESERVED: u32 = 0xFFFF_F000;
}

impl Marshal for Result<(), TpmRc> {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut [u8; Self::MAX_SIZE]) -> usize {
        self.err().map_or(0, TpmRc::get).marshal(dst)
    }
}
impl Unmarshal<'_> for Result<(), TpmRc> {
    fn unmarshal(src: &mut &'_ [u8]) -> Result<Self, UnmarshalError> {
        let x = u32::unmarshal(src)?;
        match TpmRc::new(x) {
            Some(x) => Ok(Err(x)),
            None => Ok(Ok(())),
        }
    }
}
impl fmt::Display for TpmRc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TPM_RC(0x{:03X})", self.0.get())
    }
}
impl fmt::Debug for TpmRc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl error::Error for TpmRc {}

// Format-Zero
impl TpmRc {
    const FMT0_E_MASK: u32 = 0b0111_1111;
    const VER1: u32 = 1 << 8;
    const FMT0_RESERVED: u32 = 1 << 9;
    const VEND: u32 = 1 << 10;
    const WARN: u32 = 1 << 11;

    /// Creates a Format-Zero Response Code (bit 7 must be clear).
    #[inline]
    const fn fmt0(e: u8) -> Self {
        let x = e as u32;
        assert!(x & Self::FMT0_E_MASK == x);
        Self::new(x | Self::VER1).unwrap()
    }
    /// Returns true if this is a Format-Zero Response Code.
    pub const fn is_fmt0(self) -> bool {
        const MASK: u32 = TpmRc::FMT1 | TpmRc::FMT0_RESERVED | TpmRc::RESERVED;
        self.get() & MASK == 0
    }
    /// Returns true if this is a TPM 2.0 Format-Zero Response Code (bit 8 `V` is set).
    pub const fn is_ver1(self) -> bool {
        self.is_fmt0() && (self.get() & Self::VER1 == Self::VER1)
    }
    /// Returns true if this is a legacy (TPM 1.2) Format-Zero Response Code (bit 8 `V` is clear).
    pub const fn is_legacy(self) -> bool {
        self.is_fmt0() && (self.get() & Self::VER1 == 0)
    }
    /// Set the warning bit (must be Format-Zero).
    #[inline]
    const fn warning(self) -> Self {
        assert!(self.is_fmt0());
        assert!(!self.is_warning());
        Self::new(self.get() | Self::WARN).unwrap()
    }
    /// Returns true if this is Format-Zero and a Warning.
    pub const fn is_warning(self) -> bool {
        self.is_fmt0() && (self.get() & Self::WARN == Self::WARN)
    }
    /// Returns true if this is a Vendor-specific Error or Warning.
    pub const fn is_vendor(self) -> bool {
        self.is_fmt0() && (self.get() & Self::VEND == Self::VEND)
    }
    /// Create a Vendor-specific Error (bit 7 is ignored).
    pub const fn vendor_error(e: u8) -> Self {
        let x = (e as u32) & Self::FMT0_E_MASK;
        Self::new(x | Self::VER1 | Self::VEND).unwrap()
    }
    /// Create a Vendor-specific Warning (bit 7 is ignored).
    pub const fn vendor_warning(e: u8) -> Self {
        Self::vendor_error(e).warning()
    }
}

// Format-One
impl TpmRc {
    const FMT1_E_MASK: u32 = 0b0000_0011_1111;
    const FMT1_P: u32 = 1 << 6;
    const FMT1: u32 = 1 << 7;
    const FMT1_N_MASK: u32 = 0b1111_0000_0000;
    const FMT1_S: u32 = 1 << 11;
    /// Create a Format-One Response Code (bits 6 & 7 must be clear).
    #[inline]
    const fn fmt1(e: u8) -> Fmt1 {
        let x = e as u32;
        assert!(x & Self::FMT1_E_MASK == x);
        Fmt1(NonZero::new((x & Self::FMT1_E_MASK) | Self::FMT1).unwrap())
    }
    /// Returns true if this is a Format-One Response Code.
    pub const fn is_fmt1(self) -> bool {
        const MASK: u32 = TpmRc::FMT1 | TpmRc::RESERVED;
        self.get() & MASK == Self::FMT1
    }
    /// Extracts the bare [`Fmt1`] and [`Position`] information.
    pub const fn to_fmt1(self) -> Option<(Fmt1, Option<Position>)> {
        if !self.is_fmt1() {
            return None;
        }
        let fmt1 = (self.get() & Self::FMT1_E_MASK) | Self::FMT1;
        let pos = match self.get() & (Self::FMT1_P | Self::FMT1_N_MASK) {
            0x000 => None,
            pos => Some(Position(NonZero::new(pos).unwrap())),
        };
        Some((Fmt1(NonZero::new(fmt1).unwrap()), pos))
    }

    /// Attaches a [`Position`] to this response code if it is a Format-One code without a position.
    #[inline]
    pub const fn with_position(self, pos: Position) -> Self {
        match self.to_fmt1() {
            Some((fmt1, None)) => fmt1.with(pos),
            _ => self,
        }
    }
}

/// [`TpmRc`] Error Constants
impl TpmRc {
    /// TPM 1.2 legacy response code returned when command tag is invalid (`TPM_RC_BAD_TAG` / `TPM_BADTAG`).
    pub const BAD_TAG: Self = Self(NonZero::new(0x01E).unwrap());

    // Format-Zero Errors
    /// TPM not initialized by TPM2_Startup() or already initialized (`TPM_RC_INITIALIZE`).
    pub const INITIALIZE: Self = Self::fmt0(0x00);
    /// Commands not being accepted because of a TPM failure (`TPM_RC_FAILURE`).
    pub const FAILURE: Self = Self::fmt0(0x01);
    /// Improper use of a sequence handle (`TPM_RC_SEQUENCE`).
    pub const SEQUENCE: Self = Self::fmt0(0x03);
    /// Not currently used (`TPM_RC_PRIVATE`).
    pub const PRIVATE: Self = Self::fmt0(0x0B);
    /// Not currently used (`TPM_RC_HMAC`).
    pub const HMAC: Self = Self::fmt0(0x19);
    /// The command is disabled (`TPM_RC_DISABLED`).
    pub const DISABLED: Self = Self::fmt0(0x20);
    /// Command failed because audit sequence required exclusivity (`TPM_RC_EXCLUSIVE`).
    pub const EXCLUSIVE: Self = Self::fmt0(0x21);
    /// Authorization handle is not correct for command (`TPM_RC_AUTH_TYPE`).
    pub const AUTH_TYPE: Self = Self::fmt0(0x24);
    /// Command requires an authorization session for handle and it is not present (`TPM_RC_AUTH_MISSING`).
    pub const AUTH_MISSING: Self = Self::fmt0(0x25);
    /// Policy failure in math operation or an invalid authPolicy value (`TPM_RC_POLICY`).
    pub const POLICY: Self = Self::fmt0(0x26);
    /// PCR check fail (`TPM_RC_PCR`).
    pub const PCR: Self = Self::fmt0(0x27);
    /// PCR have changed since checked (`TPM_RC_PCR_CHANGED`).
    pub const PCR_CHANGED: Self = Self::fmt0(0x28);
    /// The TPM is in field upgrade mode or not in field upgrade mode (`TPM_RC_UPGRADE`).
    pub const UPGRADE: Self = Self::fmt0(0x2D);
    /// Context ID counter is at maximum (`TPM_RC_TOO_MANY_CONTEXTS`).
    pub const TOO_MANY_CONTEXTS: Self = Self::fmt0(0x2E);
    /// authValue or authPolicy is not available for selected entity (`TPM_RC_AUTH_UNAVAILABLE`).
    pub const AUTH_UNAVAILABLE: Self = Self::fmt0(0x2F);
    /// A _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation (`TPM_RC_REBOOT`).
    pub const REBOOT: Self = Self::fmt0(0x30);
    /// The protection algorithms (hash and symmetric) are not reasonably balanced (`TPM_RC_UNBALANCED`).
    pub const UNBALANCED: Self = Self::fmt0(0x31);
    /// Command commandSize value is inconsistent with contents of the command buffer (`TPM_RC_COMMAND_SIZE`).
    pub const COMMAND_SIZE: Self = Self::fmt0(0x42);
    /// Command code not supported (`TPM_RC_COMMAND_CODE`).
    pub const COMMAND_CODE: Self = Self::fmt0(0x43);
    /// The value of authorizationSize is out of range or number of octets in Authorization Area is greater than required (`TPM_RC_AUTHSIZE`).
    pub const AUTHSIZE: Self = Self::fmt0(0x44);
    /// Use of an authorization session with a context command or another command that cannot have an authorization session (`TPM_RC_AUTH_CONTEXT`).
    pub const AUTH_CONTEXT: Self = Self::fmt0(0x45);
    /// NV offset + size is out of range (`TPM_RC_NV_RANGE`).
    pub const NV_RANGE: Self = Self::fmt0(0x46);
    /// Requested allocation size is larger than allowed (`TPM_RC_NV_SIZE`).
    pub const NV_SIZE: Self = Self::fmt0(0x47);
    /// NV access locked (`TPM_RC_NV_LOCKED`).
    pub const NV_LOCKED: Self = Self::fmt0(0x48);
    /// NV access authorization fails in command actions (`TPM_RC_NV_AUTHORIZATION`).
    pub const NV_AUTHORIZATION: Self = Self::fmt0(0x49);
    /// An NV Index is used before being initialized (written) or saved state could not be restored (`TPM_RC_NV_UNINITIALIZED`).
    pub const NV_UNINITIALIZED: Self = Self::fmt0(0x4A);
    /// Insufficient space for NV allocation (`TPM_RC_NV_SPACE`).
    pub const NV_SPACE: Self = Self::fmt0(0x4B);
    /// NV Index or persistent object already defined (`TPM_RC_NV_DEFINED`).
    pub const NV_DEFINED: Self = Self::fmt0(0x4C);
    /// Context in TPM2_ContextLoad() is not valid (`TPM_RC_BAD_CONTEXT`).
    pub const BAD_CONTEXT: Self = Self::fmt0(0x50);
    /// cpHash value already set or not correct for use (`TPM_RC_CPHASH`).
    pub const CPHASH: Self = Self::fmt0(0x51);
    /// Handle for parent is not a valid parent (`TPM_RC_PARENT`).
    pub const PARENT: Self = Self::fmt0(0x52);
    /// Some function needs testing (`TPM_RC_NEEDS_TEST`).
    pub const NEEDS_TEST: Self = Self::fmt0(0x53);
    /// Returned when an internal function cannot process a request due to an unspecified problem (`TPM_RC_NO_RESULT`).
    pub const NO_RESULT: Self = Self::fmt0(0x54);
    /// The sensitive area did not unmarshal correctly after decryption (`TPM_RC_SENSITIVE`).
    pub const SENSITIVE: Self = Self::fmt0(0x55);
    /// Command failed because the TPM is in the Read-Only mode of operation (`TPM_RC_READ_ONLY`).
    pub const READ_ONLY: Self = Self::fmt0(0x56);

    // Format-One Errors
    /// Asymmetric algorithm not supported or not correct (`TPM_RC_ASYMMETRIC`).
    pub const ASYMMETRIC: Fmt1 = Self::fmt1(0x01);
    /// Inconsistent attributes (`TPM_RC_ATTRIBUTES`).
    pub const ATTRIBUTES: Fmt1 = Self::fmt1(0x02);
    /// Hash algorithm not supported or not appropriate (`TPM_RC_HASH`).
    pub const HASH: Fmt1 = Self::fmt1(0x03);
    /// Value is out of range or is not correct for the context (`TPM_RC_VALUE`).
    pub const VALUE: Fmt1 = Self::fmt1(0x04);
    /// Hierarchy is not enabled or is not correct for the use (`TPM_RC_HIERARCHY`).
    pub const HIERARCHY: Fmt1 = Self::fmt1(0x05);
    /// Key size is not supported (`TPM_RC_KEY_SIZE`).
    pub const KEY_SIZE: Fmt1 = Self::fmt1(0x07);
    /// Mask generation function not supported (`TPM_RC_MGF`).
    pub const MGF: Fmt1 = Self::fmt1(0x08);
    /// Mode of operation not supported (`TPM_RC_MODE`).
    pub const MODE: Fmt1 = Self::fmt1(0x09);
    /// The type of the value is not appropriate for the use (`TPM_RC_TYPE`).
    pub const TYPE: Fmt1 = Self::fmt1(0x0A);
    /// The handle is not correct for the use (`TPM_RC_HANDLE`).
    pub const HANDLE: Fmt1 = Self::fmt1(0x0B);
    /// Unsupported key derivation function or function not appropriate for use (`TPM_RC_KDF`).
    pub const KDF: Fmt1 = Self::fmt1(0x0C);
    /// Value was out of allowed range (`TPM_RC_RANGE`).
    pub const RANGE: Fmt1 = Self::fmt1(0x0D);
    /// The authorization HMAC check failed and the DA counter was incremented, or use of lockoutAuth is disabled (`TPM_RC_AUTH_FAIL`).
    pub const AUTH_FAIL: Fmt1 = Self::fmt1(0x0E);
    /// Invalid nonce size or nonce value mismatch (`TPM_RC_NONCE`).
    pub const NONCE: Fmt1 = Self::fmt1(0x0F);
    /// Authorization requires assertion of PP (`TPM_RC_PP`).
    pub const PP: Fmt1 = Self::fmt1(0x10);
    /// Unsupported or incompatible scheme (`TPM_RC_SCHEME`).
    pub const SCHEME: Fmt1 = Self::fmt1(0x12);
    /// Structure is the wrong size (`TPM_RC_SIZE`).
    pub const SIZE: Fmt1 = Self::fmt1(0x15);
    /// Unsupported symmetric algorithm or key size, or not appropriate for instance (`TPM_RC_SYMMETRIC`).
    pub const SYMMETRIC: Fmt1 = Self::fmt1(0x16);
    /// Incorrect structure tag (`TPM_RC_TAG`).
    pub const TAG: Fmt1 = Self::fmt1(0x17);
    /// Union selector is incorrect (`TPM_RC_SELECTOR`).
    pub const SELECTOR: Fmt1 = Self::fmt1(0x18);
    /// The TPM was unable to unmarshal a value because there were not enough octets in the input buffer (`TPM_RC_INSUFFICIENT`).
    pub const INSUFFICIENT: Fmt1 = Self::fmt1(0x1A);
    /// The signature is not valid (`TPM_RC_SIGNATURE`).
    pub const SIGNATURE: Fmt1 = Self::fmt1(0x1B);
    /// Key fields are not compatible with the selected use (`TPM_RC_KEY`).
    pub const KEY: Fmt1 = Self::fmt1(0x1C);
    /// A policy check failed (`TPM_RC_POLICY_FAIL`).
    pub const POLICY_FAIL: Fmt1 = Self::fmt1(0x1D);
    /// Integrity check failed (`TPM_RC_INTEGRITY`).
    pub const INTEGRITY: Fmt1 = Self::fmt1(0x1F);
    /// Invalid ticket (`TPM_RC_TICKET`).
    pub const TICKET: Fmt1 = Self::fmt1(0x20);
    /// Reserved bits not set to zero as required (`TPM_RC_RESERVED_BITS`).
    pub const RESERVED_BITS: Fmt1 = Self::fmt1(0x21);
    /// Authorization failure without DA implications (`TPM_RC_BAD_AUTH`).
    pub const BAD_AUTH: Fmt1 = Self::fmt1(0x22);
    /// The policy has expired (`TPM_RC_EXPIRED`).
    pub const EXPIRED: Fmt1 = Self::fmt1(0x23);
    /// The commandCode in the policy is not the commandCode of the command or references an unimplemented command (`TPM_RC_POLICY_CC`).
    pub const POLICY_CC: Fmt1 = Self::fmt1(0x24);
    /// Public and sensitive portions of an object are not cryptographically bound (`TPM_RC_BINDING`).
    pub const BINDING: Fmt1 = Self::fmt1(0x25);
    /// Curve not supported (`TPM_RC_CURVE`).
    pub const CURVE: Fmt1 = Self::fmt1(0x26);
    /// Point is not on the required curve (`TPM_RC_ECC_POINT`).
    pub const ECC_POINT: Fmt1 = Self::fmt1(0x27);
    /// The hierarchy is firmware-limited but the Firmware Secret is unavailable (`TPM_RC_FW_LIMITED`).
    pub const FW_LIMITED: Fmt1 = Self::fmt1(0x28);
    /// The hierarchy is SVN-limited but the Firmware SVN Secret associated with the given SVN is unavailable (`TPM_RC_SVN_LIMITED`).
    pub const SVN_LIMITED: Fmt1 = Self::fmt1(0x29);
    /// Parameter set not supported (`TPM_RC_PARMS`).
    pub const PARMS: Fmt1 = Self::fmt1(0x2A);
    /// External-Mu is not supported (`TPM_RC_EXT_MU`).
    pub const EXT_MU: Fmt1 = Self::fmt1(0x2B);
    /// The TPM does not support signing arbitrarily long messages using this key (`TPM_RC_ONE_SHOT_SIGNATURE`).
    pub const ONE_SHOT_SIGNATURE: Fmt1 = Self::fmt1(0x2C);
    /// The key being used to finish the signature context is not the same as the one that was used to start it (`TPM_RC_SIGN_CONTEXT_KEY`).
    pub const SIGN_CONTEXT_KEY: Fmt1 = Self::fmt1(0x2D);
    /// Command requires secure channel protection (`TPM_RC_CHANNEL`).
    pub const CHANNEL: Fmt1 = Self::fmt1(0x30);
    /// Secure channel was not established with required requester or TPM key (`TPM_RC_CHANNEL_KEY`).
    pub const CHANNEL_KEY: Fmt1 = Self::fmt1(0x31);

    // Format-Zero Warnings
    /// Gap for context ID is too large (`TPM_RC_CONTEXT_GAP`).
    pub const CONTEXT_GAP: Self = Self::fmt0(0x01).warning();
    /// Out of memory for object contexts (`TPM_RC_OBJECT_MEMORY`).
    pub const OBJECT_MEMORY: Self = Self::fmt0(0x02).warning();
    /// Out of memory for session contexts (`TPM_RC_SESSION_MEMORY`).
    pub const SESSION_MEMORY: Self = Self::fmt0(0x03).warning();
    /// Out of shared object/session memory or need space for internal operations (`TPM_RC_MEMORY`).
    pub const MEMORY: Self = Self::fmt0(0x04).warning();
    /// Out of session handles (`TPM_RC_SESSION_HANDLES`).
    pub const SESSION_HANDLES: Self = Self::fmt0(0x05).warning();
    /// Out of object handles (`TPM_RC_OBJECT_HANDLES`).
    pub const OBJECT_HANDLES: Self = Self::fmt0(0x06).warning();
    /// Bad locality (`TPM_RC_LOCALITY`).
    pub const LOCALITY: Self = Self::fmt0(0x07).warning();
    /// The TPM has suspended operation on the command; forward progress was made and the command may be retried (`TPM_RC_YIELDED`).
    pub const YIELDED: Self = Self::fmt0(0x08).warning();
    /// The command was canceled (`TPM_RC_CANCELED`).
    pub const CANCELED: Self = Self::fmt0(0x09).warning();
    /// TPM is performing self-tests (`TPM_RC_TESTING`).
    pub const TESTING: Self = Self::fmt0(0x0A).warning();
    /// The 1st handle in the handle area references a transient object or session that is not loaded (`TPM_RC_REFERENCE_H0`).
    pub const REFERENCE_H0: Self = Self::fmt0(0x10).warning();
    /// The 2nd handle in the handle area references a transient object or session that is not loaded (`TPM_RC_REFERENCE_H1`).
    pub const REFERENCE_H1: Self = Self::fmt0(0x11).warning();
    /// The 3rd handle in the handle area references a transient object or session that is not loaded (`TPM_RC_REFERENCE_H2`).
    pub const REFERENCE_H2: Self = Self::fmt0(0x12).warning();
    /// The 4th handle in the handle area references a transient object or session that is not loaded (`TPM_RC_REFERENCE_H3`).
    pub const REFERENCE_H3: Self = Self::fmt0(0x13).warning();
    /// The 5th handle in the handle area references a transient object or session that is not loaded (`TPM_RC_REFERENCE_H4`).
    pub const REFERENCE_H4: Self = Self::fmt0(0x14).warning();
    /// The 6th handle in the handle area references a transient object or session that is not loaded (`TPM_RC_REFERENCE_H5`).
    pub const REFERENCE_H5: Self = Self::fmt0(0x15).warning();
    /// The 7th handle in the handle area references a transient object or session that is not loaded (`TPM_RC_REFERENCE_H6`).
    pub const REFERENCE_H6: Self = Self::fmt0(0x16).warning();
    /// The 1st authorization session handle references a session that is not loaded (`TPM_RC_REFERENCE_S0`).
    pub const REFERENCE_S0: Self = Self::fmt0(0x18).warning();
    /// The 2nd authorization session handle references a session that is not loaded (`TPM_RC_REFERENCE_S1`).
    pub const REFERENCE_S1: Self = Self::fmt0(0x19).warning();
    /// The 3rd authorization session handle references a session that is not loaded (`TPM_RC_REFERENCE_S2`).
    pub const REFERENCE_S2: Self = Self::fmt0(0x1A).warning();
    /// The 4th authorization session handle references a session that is not loaded (`TPM_RC_REFERENCE_S3`).
    pub const REFERENCE_S3: Self = Self::fmt0(0x1B).warning();
    /// The 5th session handle references a session that is not loaded (`TPM_RC_REFERENCE_S4`).
    pub const REFERENCE_S4: Self = Self::fmt0(0x1C).warning();
    /// The 6th session handle references a session that is not loaded (`TPM_RC_REFERENCE_S5`).
    pub const REFERENCE_S5: Self = Self::fmt0(0x1D).warning();
    /// The 7th authorization session handle references a session that is not loaded (`TPM_RC_REFERENCE_S6`).
    pub const REFERENCE_S6: Self = Self::fmt0(0x1E).warning();
    /// The TPM is rate-limiting accesses to prevent wear out of NV (`TPM_RC_NV_RATE`).
    pub const NV_RATE: Self = Self::fmt0(0x20).warning();
    /// Authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode (`TPM_RC_LOCKOUT`).
    pub const LOCKOUT: Self = Self::fmt0(0x21).warning();
    /// The TPM was not able to start the command (`TPM_RC_RETRY`).
    pub const RETRY: Self = Self::fmt0(0x22).warning();
    /// The command may require writing of NV and NV is not currently accessible (`TPM_RC_NV_UNAVAILABLE`).
    pub const NV_UNAVAILABLE: Self = Self::fmt0(0x23).warning();
}

/// A Format-One Response Code without any [`Position`] information.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Fmt1(NonZero<u32>);

impl Fmt1 {
    /// Get the raw non-zero `u32` value.
    pub const fn get(self) -> u32 {
        self.0.get()
    }
    /// Converts to a [`TpmRc`] without [`Position`] information.
    pub const fn to_rc(self) -> TpmRc {
        TpmRc(self.0)
    }
    /// Converts to a [`TpmRc`] with the specified [`Position`] information.
    pub const fn with(self, p: Position) -> TpmRc {
        TpmRc::new(self.0.get() | p.0.get()).unwrap()
    }
}

impl fmt::Display for Fmt1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fmt1(0x{:03X})", self.0.get())
    }
}
impl fmt::Debug for Fmt1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl PartialEq<Fmt1> for TpmRc {
    fn eq(&self, other: &Fmt1) -> bool {
        match self.to_fmt1() {
            Some((fmt1, _)) => fmt1 == *other,
            None => false,
        }
    }
}
impl PartialEq<TpmRc> for Fmt1 {
    fn eq(&self, other: &TpmRc) -> bool {
        other.eq(self)
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Position(NonZero<u32>);

impl Position {
    /// Position modifier for an unspecified parameter (`TPM_RC_P`, index 0).
    pub const UNSPECIFIED_PARAMETER: Self = Self::parameter(0);

    /// Position modifier for an unspecified session (`TPM_RC_S`, index 0).
    pub const UNSPECIFIED_SESSION: Self = Self::session(0);

    /// Creates a position modifier for an unspecified parameter (`TPM_RC_P`).
    #[inline]
    pub const fn unspecified_parameter() -> Self {
        Self::UNSPECIFIED_PARAMETER
    }

    /// Creates a position modifier for an unspecified session (`TPM_RC_S`).
    #[inline]
    pub const fn unspecified_session() -> Self {
        Self::UNSPECIFIED_SESSION
    }

    /// Position for a handle (1-based index, 1..=7).
    #[inline]
    pub const fn handle(n: u8) -> Self {
        assert!(n >= 1 && n <= 7, "handle index must be 1..=7");
        let raw_n = (n as u32) << 8;
        Self(NonZero::new(raw_n).unwrap())
    }

    /// Position for a session (0..=7, where 0 indicates an unspecified session `TPM_RC_S`).
    #[inline]
    pub const fn session(n: u8) -> Self {
        assert!(n <= 7, "session index must be 0..=7");
        let raw_n = (n as u32) << 8;
        Self(NonZero::new(raw_n | TpmRc::FMT1_S).unwrap())
    }

    /// Position for a parameter (0..=15, where 0 indicates an unspecified parameter `TPM_RC_P`).
    #[inline]
    pub const fn parameter(n: u8) -> Self {
        assert!(n <= 15, "parameter index must be 0..=15");
        let raw_n = (n as u32) << 8;
        Self(NonZero::new(raw_n | TpmRc::FMT1_P).unwrap())
    }

    /// Returns the raw `u32` bits of this position modifier.
    #[inline]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// Returns true if this position represents an unspecified parameter or session (index 0).
    #[inline]
    pub const fn is_unspecified(self) -> bool {
        self.0.get() == TpmRc::FMT1_P || self.0.get() == TpmRc::FMT1_S
    }

    /// Returns the 1-based handle index (1..=7) if this position represents a handle.
    pub const fn handle_num(self) -> Option<u8> {
        if self.0.get() & (TpmRc::FMT1_P | TpmRc::FMT1_S) == 0 {
            let n = (self.0.get() >> 8) as u8;
            if n < 8 {
                return Some(n);
            }
        }
        None
    }

    /// Returns the session index (0..=7) if this position represents a session,
    /// where 0 indicates an unspecified session (`TPM_RC_S`).
    pub const fn session_num(self) -> Option<u8> {
        if self.0.get() & (TpmRc::FMT1_P | TpmRc::FMT1_S) == TpmRc::FMT1_S {
            let n = (self.0.get() >> 8) as u8;
            if n >= 8 {
                return Some(n - 8);
            }
        }
        None
    }

    /// Returns the parameter index (0..=15) if this position represents a parameter,
    /// where 0 indicates an unspecified parameter (`TPM_RC_P`).
    pub const fn parameter_num(self) -> Option<u8> {
        if self.0.get() & TpmRc::FMT1_P == TpmRc::FMT1_P {
            return Some((self.0.get() >> 8) as u8);
        }
        None
    }
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(n) = self.handle_num() {
            write!(f, "Position::handle({})", n)
        } else if let Some(n) = self.session_num() {
            if n == 0 {
                write!(f, "Position::unspecified_session()")
            } else {
                write!(f, "Position::session({})", n)
            }
        } else if let Some(n) = self.parameter_num() {
            if n == 0 {
                write!(f, "Position::unspecified_parameter()")
            } else {
                write!(f, "Position::parameter({})", n)
            }
        } else {
            write!(f, "Position(0x{:03X})", self.0.get())
        }
    }
}
impl fmt::Debug for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
