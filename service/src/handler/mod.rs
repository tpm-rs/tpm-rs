use crate::buffer::{BufferAccessor, RequestThenResponse};
use crate::crypto::{Crypto, CryptoRandom as _};
use crate::error::TpmError;

/// Specifies all of the dependent types for the `CommandContext` parameter that all command handler
/// functions get access to to handle their specific command.
pub trait ContextDeps {
    /// Interface to perform cryptographic operations.
    type Crypto: Crypto;
}

/// The context that all command handler functions are given access to in order for them to process
/// their given command.
pub struct CommandContext<'a, Deps: ContextDeps> {
    /// Gives access to cryptographic operations.
    pub crypto: &'a mut Deps::Crypto,
}

/// Handles the `TPM_CC_GetRandom` (`0x17B`) command.
pub fn get_random(
    request_response: RequestThenResponse<impl BufferAccessor>,
    context: &mut CommandContext<impl ContextDeps>,
) -> Result<(), TpmError> {
    let mut request = request_response;
    let requested_bytes = request.read_be_u16().ok_or(TpmError::CommandSize)? as usize;

    let mut response = request.into_response();
    response
        .write_callback(requested_bytes, |buffer| {
            context.crypto.get_random_bytes(buffer)
        })
        .map_err(|_| TpmError::Memory)?;

    Ok(())
}
