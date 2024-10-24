mod buffer;
pub mod drbg;
pub use buffer::*;
use drbg::Drbg;

/// Provides access to cryptographic operations.
pub trait Crypto: Drbg {}

// For all types that implement every Crypto sub trait, also implement the combined trait.
impl<T> Crypto for T where T: Drbg {}

/// Specifies all of the dependent types for [`TpmContext`].
///
/// [`TpmContext`]: crate::tpmctx::TpmContext
pub trait TpmContextDeps {
    /// Interface to perform cryptographic operations.
    type Crypto: Crypto;
    /// The type of the input request buffer for command processing.
    type Request: TpmReadBuffer + ?Sized;
    /// The type of the output response buffer for command processing.
    type Response: TpmWriteBuffer + ?Sized;
}
