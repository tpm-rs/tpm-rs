use crate::{
    platform::{CryptoRandom, TpmBuffers, TpmContextDeps},
    req_resp::RequestThenResponse,
};
use tpm2_rs_base::errors::TpmRcError;

/// The context that all command handler functions are given access to in order for them to process
/// their given command.
pub struct CommandHandler<'a, Deps: TpmContextDeps> {
    /// Gives access to cryptographic operations.
    pub crypto: &'a mut Deps::Crypto,
}

/// Handles the `TPM_CC_GetRandom` (`0x17B`) command.
pub fn get_random(
    request_response: RequestThenResponse<impl TpmBuffers>,
    context: &mut CommandHandler<impl TpmContextDeps>,
) -> Result<(), TpmRcError> {
    let mut request = request_response;
    let requested_bytes = request.read_be_u16().ok_or(TpmRcError::CommandSize)? as usize;

    let mut response = request.into_response();
    response
        .write_callback(requested_bytes, |buffer| {
            context.crypto.get_random_bytes(buffer)
        })
        .map_err(|_| TpmRcError::Memory)?;

    Ok(())
}
