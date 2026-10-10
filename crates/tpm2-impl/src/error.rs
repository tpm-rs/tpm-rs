//! System-level and platform-related error types.
//!
//! This module defines errors representing fatal platform, hardware, or host system-level issues
//! that occur independently of standard TPM protocol transactions.
//!
//! ## Purpose
//!
//! [InternalError] represents a failure of the host system, hardware platform, or environment itself
//! (such as a hardware RNG failure or failure to initialize the simulator). These errors indicate that the
//! TPM execution environment cannot function.
//!
//! ## Relationship with `TpmRc`
//!
//! - **[TpmRc](../../tpm2/src/errors/tpm_rc/mod.rs)**: Represents TPM 2.0 protocol response
//!   codes. These are returned to the client (host OS/driver) to indicate validation errors, authorization mismatches,
//!   or illegal command parameters. They represent standard, recoverable protocol-level failures.
//! - **[InternalError]**: Represents fatal backend execution failures that prevent the TPM server/service from completing
//!   actions or executing commands. These represent unrecoverable server-level failures.

use core::error::Error;
use core::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalError {
    HardwareError,
}

impl Display for InternalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InternalError::HardwareError => write!(f, "Hardware operation failed"),
        }
    }
}

impl Error for InternalError {}
