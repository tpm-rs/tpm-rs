use tpm2::{TpmsAuthCommand, TpmsAuthResponse};

/// Error occurring during session authorization validation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AuthError {
    /// Authorization response attributes, nonce, or HMAC were invalid.
    InvalidResponse,
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidResponse => write!(f, "invalid authorization response"),
        }
    }
}

impl core::error::Error for AuthError {}

/// Trait for types representing TPM sessions.
pub trait Session {
    /// Computes the authorization HMAC for this session.
    fn auth_command(&self) -> TpmsAuthCommand<'_>;
    /// Validates the authorization response for this session.
    fn validate_auth_response(&self, auth: &TpmsAuthResponse) -> Result<(), AuthError>;
}
