mod buffer;
pub mod crypto;

pub use buffer::*;
use crypto::{Drbg, EntropySource};

/// Specifies all of the dependent types for [`TpmContext`].
///
/// [`TpmContext`]: crate::tpmctx::TpmContext
pub trait TpmContextDeps {
    /// Type for managing DRBG instances
    type Drbg: Drbg;
    /// Types for getting real entropy input
    type EntropySource: EntropySource;
    /// The type of the input request buffer for command processing.
    type Request: TpmReadBuffer + ?Sized;
    /// The type of the output response buffer for command processing.
    type Response: TpmWriteBuffer + ?Sized;
}
