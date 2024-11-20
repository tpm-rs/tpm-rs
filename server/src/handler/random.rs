use tpm2_rs_base::errors::TpmRcError;

use crate::{
    handler::CommandHandler,
    platform::{
        crypto::{Drbg, EntropySource},
        TpmBuffers, TpmContextDeps,
    },
    req_resp::RequestThenResponse,
    ServerError,
};

impl<Deps: TpmContextDeps> CommandHandler<Deps> {
    fn try_get_random(&mut self, buffer: &mut [u8]) -> Result<(), ServerError> {
        if self.crypto.drbg.requires_reseeding() {
            let mut seed = <Deps::Drbg as Drbg>::Entropy::default();
            self.crypto.entropy.fill_entropy(seed.as_mut());
            self.crypto.drbg.reseed(&seed, &[])?;
        }
        self.crypto.drbg.fill_bytes(&[], buffer).map_err(Into::into)
    }

    fn get_random_or_faiure_mode(&mut self, buffer: &mut [u8]) {
        if self.try_get_random(buffer).is_err() {
            todo!() // goto failure mode
        }
    }
    /// Handles the [TpmCc::GetRandom] (`0x17B`) command.
    pub fn get_random(
        &mut self,
        request_response: RequestThenResponse<impl TpmBuffers>,
    ) -> Result<(), TpmRcError> {
        let mut request = request_response;
        let requested_bytes = request.read_be_u16().ok_or(TpmRcError::CommandSize)? as usize;

        let mut response = request.into_response();
        response
            .write_callback(requested_bytes, |buffer| {
                self.get_random_or_faiure_mode(buffer)
            })
            .map_err(|_| TpmRcError::Memory)?;
        Ok(())
    }
}
