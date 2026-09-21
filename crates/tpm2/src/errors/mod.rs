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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnmarshalError;

impl fmt::Display for UnmarshalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unmarshal error")
    }
}

impl error::Error for UnmarshalError {}
