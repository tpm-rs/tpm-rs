#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::StirRandom;
use tpm2::errors::{Position, TpmRc};

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{InternalError, handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::crypto::{CryptoProvider, Rng};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    fn try_get_random(&mut self, buffer: &mut [u8]) -> Result<(), InternalError> {
        self.context
            .platform
            .rng
            .get_random(buffer)
            .map_err(|_| InternalError::HardwareError)
    }

    /// Handles the [TpmCc::GetRandom] (`0x17B`) command.
    ///
    /// # Description
    /// This command returns the specified number of bytes of random data obtained from the TPM's internal entropy source.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 16.1 (TPM2_GetRandom).
    ///
    /// # Relationships
    /// - It relies directly on the platform's hardware random number generator.
    /// - Used externally by applications to generate cryptographic keys, salts, or nonces.
    pub fn get_random(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let cmd = request.try_unmarshal::<tpm2::commands::GetRandom>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let requested_bytes = cmd.bytes_requested as usize;
        let returned_bytes = core::cmp::min(requested_bytes, tpm2::Tpm2bDigest::MAX_BUFFER_SIZE);

        // Generate the random bytes before building the response so that an entropy-source
        // failure fails the command with TPM_RC_FAILURE (the C reference enters failure mode via
        // `FAIL()`) instead of aborting the TPM.
        let mut random_bytes = [0u8; tpm2::Tpm2bDigest::MAX_BUFFER_SIZE];
        self.try_get_random(&mut random_bytes[..returned_bytes])
            .map_err(|_| TpmRc::FAILURE)?;

        let mut response = request.into_response();
        response
            .write(&(returned_bytes as u16).to_be_bytes())
            .map_err(|_| TpmRc::MEMORY)?;
        response
            .write(&random_bytes[..returned_bytes])
            .map_err(|_| TpmRc::MEMORY)?;
        Ok(())
    }

    /// Handles the [TpmCc::StirRandom] (`0x146`) command.
    ///
    /// # Description
    /// This command adds additional entropy to the TPM's internal random number generator (RNG) state.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 16.2 (TPM2_StirRandom).
    ///
    /// # Relationships
    /// - Mixes caller-provided entropy (`inData`, up to 128 octets) into the internal RNG state.
    pub fn stir_random(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let cmd = request.try_unmarshal::<StirRandom>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if cmd.in_data.get_size() > 128 {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        self.crypto()
            .stir_random(cmd.in_data.get_buffer())
            .map_err(|_| TpmRc::FAILURE)?;
        let _ = self
            .context
            .platform
            .rng
            .stir_random(cmd.in_data.get_buffer());

        let _response = request.into_response();
        Ok(())
    }
}
