mod random;

use crate::{crypto::Crypto, platform::TpmContextDeps, ServerError};

/// The context that all command handler functions are given access to in order for them to process
/// their given command.
pub struct CommandHandler<Deps: TpmContextDeps> {
    /// Gives access to cryptographic operations.
    crypto: Crypto<Deps>,
}

impl<Deps: TpmContextDeps> CommandHandler<Deps> {
    /// Creates a new [`TpmContext`] object that processes incoming TPM requests.
    pub fn new() -> Result<Self, ServerError<Deps>> {
        Ok(Self {
            crypto: Crypto::new()?,
        })
    }
}
