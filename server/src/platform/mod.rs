mod buffer;
mod crypto;

pub use buffer::*;
pub use crypto::*;

/// Specifies all of the dependent types for `Service`.
pub trait TpmContextDeps {
    /// Interface to perform cryptographic operations.
    type Crypto: Crypto;
    /// The type of the input request buffer for command processing.
    type Request: TpmReadBuffer + ?Sized;
    /// The type of the output response buffer for command processing.
    type Response: TpmWriteBuffer + ?Sized;
}
