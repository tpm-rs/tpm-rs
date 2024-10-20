mod buffer;
mod crypto;

pub use buffer::*;
pub use crypto::*;

/// Specifies all of the dependent types for `Service`.
pub trait ServiceDeps {
    /// Interface to perform cryptographic operations.
    type Crypto: Crypto;
    /// The type of the input request buffer for command processing.
    type Request: TpmReadBuffer + ?Sized;
    /// The type of the output response buffer for command processing.
    type Response: TpmWriteBuffer + ?Sized;
}

/// Specifies all of the dependent types for the `CommandContext` parameter that all command handler
/// functions get access to to handle their specific command.
pub trait ContextDeps {
    /// Interface to perform cryptographic operations.
    type Crypto: Crypto;
}

// Implement the `ContextDeps` for all types that implement `ServiceDeps` since ContextDeps is a
// subset.
impl<T: ServiceDeps> ContextDeps for T {
    type Crypto = T::Crypto;
}
