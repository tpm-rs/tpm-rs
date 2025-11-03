//! Errors used thoughout this base crate.
//!
//! Currently, these errors are just unit structs as we get things working.
//! TODO: Flesh out these structures (or move them from `base`).

/// Any error which can happen when marshalling
pub struct MarshalError;
/// Any error which can happen when unmarshalling
pub struct UnmarshalError;
/// Specific error type corresponding to TPM_RC_HASH
pub struct HashError;

impl From<HashError> for UnmarshalError {
    fn from(_: HashError) -> Self {
        Self
    }
}
