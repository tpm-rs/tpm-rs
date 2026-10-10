#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{GetRandom, StirRandom};
use tpm2::errors::{Position, TpmRc};

use crate::Crypto;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{InternalError, handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::crypto::Rng;

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    fn try_get_random(&mut self, buffer: &mut [u8]) -> Result<(), InternalError> {
        self.fill_random(buffer)
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
        let cmd = request.try_unmarshal_command::<GetRandom>([])?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let requested_bytes = usize::from(cmd.bytes_requested);
        let returned_bytes = core::cmp::min(requested_bytes, tpm2::Tpm2bDigest::CAP);

        // PORTING: exp filled the response buffer in place and hit `todo!()`
        // ("goto failure mode") on RNG failure. The bytes are now generated
        // before the response is started so an RNG failure returns
        // TPM_RC_FAILURE instead.
        let mut random = [0u8; tpm2::Tpm2bDigest::CAP];
        let random = random.get_mut(..returned_bytes).ok_or(TpmRc::FAILURE)?;
        self.try_get_random(random).map_err(|_| TpmRc::FAILURE)?;
        let size = u16::try_from(returned_bytes).map_err(|_| TpmRc::FAILURE)?;

        let mut response = request.into_response();
        response
            .write(&size.to_be_bytes())
            .map_err(|_| TpmRc::MEMORY)?;
        response.write(random).map_err(|_| TpmRc::MEMORY)?;
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
        let cmd = request.try_unmarshal_command::<StirRandom>([])?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if cmd.in_data.as_slice().len() > 128 {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        // PORTING: exp stirred both `CryptoProvider::stir_random` and the
        // platform RNG. The new API has a single global RNG
        // ([`crate::TpmPlatform::rng`]), reseeded via [`Rng::reseed`].
        self.context
            .platform
            .rng
            .reseed(cmd.in_data.as_slice())
            .map_err(|_| TpmRc::FAILURE)?;

        let _response = request.into_response();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{TestEngine, execute, with_test_engine};
    use crate::{GlobalState, MAX_ACTIVE_SESSIONS};
    use alloc::vec::Vec;
    use tpm2::errors::{Position, TpmRc};
    use tpm2::{Tpm2bDigest, TpmCc};

    fn startup(tpm: &mut TestEngine<'_>, gs: &mut GlobalState) {
        assert_eq!(execute(tpm, gs, TpmCc::Startup, &[0, 0]).0, 0);
    }

    /// Sends `TPM2_GetRandom(bytes_requested)` and returns the `randomBytes` buffer.
    fn get_random(tpm: &mut TestEngine<'_>, gs: &mut GlobalState, bytes_requested: u16) -> Vec<u8> {
        let (rc, body) = execute(tpm, gs, TpmCc::GetRandom, &bytes_requested.to_be_bytes());
        assert_eq!(rc, 0);
        let (size, random) = body.split_at(2);
        assert_eq!(
            usize::from(u16::from_be_bytes([size[0], size[1]])),
            random.len()
        );
        random.to_vec()
    }

    #[test]
    fn get_random_returns_requested_bytes() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            let random = get_random(tpm, gs, 8);
            assert_eq!(random.len(), 8);
            // FakeRng is a counter, so the output is consecutive.
            for pair in random.windows(2) {
                assert_eq!(pair[1], pair[0].wrapping_add(1));
            }
            assert_eq!(get_random(tpm, gs, 0), Vec::new());
        });
    }

    #[test]
    fn get_random_is_capped_at_digest_size() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            assert_eq!(get_random(tpm, gs, 1000).len(), Tpm2bDigest::CAP);
        });
    }

    #[test]
    fn get_random_rejects_trailing_bytes() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            let (rc, _) = execute(tpm, gs, TpmCc::GetRandom, &[0, 8, 0]);
            assert_eq!(rc, TpmRc::SIZE.to_rc().get());
        });
    }

    #[test]
    fn stir_random_reseeds_the_global_rng() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            let before = get_random(tpm, gs, 1)[0];
            // TPM2B_SENSITIVE_DATA { size: 1, buffer: [5] }
            assert_eq!(
                execute(tpm, gs, TpmCc::StirRandom, &[0, 1, 5]),
                (0, Vec::new())
            );
            // FakeRng::reseed adds the input bytes to its counter.
            assert_eq!(get_random(tpm, gs, 1)[0], before.wrapping_add(1 + 5));
        });
    }

    #[test]
    fn stir_random_rejects_oversized_input() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            let mut body = Vec::from(129u16.to_be_bytes());
            body.resize(2 + 129, 0xA5);
            let (rc, _) = execute(tpm, gs, TpmCc::StirRandom, &body);
            assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(1)).get());
        });
    }

    /// Sends `TPM2_GetRandom(8)` with one session using `session_handle`; returns the response code.
    fn get_random_with_session(
        tpm: &mut TestEngine<'_>,
        gs: &mut GlobalState,
        session_handle: u32,
    ) -> u32 {
        // sessionHandle | nonceCaller (empty) | sessionAttributes (continueSession) | hmac (empty)
        let mut auth = Vec::from(session_handle.to_be_bytes());
        auth.extend_from_slice(&[0, 0, 1, 0, 0]);
        let auth_size = u32::try_from(auth.len()).unwrap();
        let size = u32::try_from(10 + 4 + auth.len() + 2).unwrap();
        let mut request = Vec::from(0x8002u16.to_be_bytes());
        request.extend_from_slice(&size.to_be_bytes());
        request.extend_from_slice(&TpmCc::GetRandom.code().to_be_bytes());
        request.extend_from_slice(&auth_size.to_be_bytes());
        request.extend_from_slice(&auth);
        request.extend_from_slice(&8u16.to_be_bytes());

        let mut response = [0u8; 4096];
        let len = tpm.execute_command_separate(gs, &request, &mut response);
        assert!(len >= 10, "response shorter than a header: {len} bytes");
        u32::from_be_bytes([response[6], response[7], response[8], response[9]])
    }

    #[test]
    fn session_area_rejects_handles_outside_tpmi_sh_auth_session_plus() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            for handle in [0x8000_0000, 0x4000_0001, 0x0200_0000 + MAX_ACTIVE_SESSIONS] {
                assert_eq!(
                    get_random_with_session(tpm, gs, handle),
                    TpmRc::VALUE.with(Position::session(1)).get(),
                    "{handle:#010x}"
                );
            }
        });
    }
}
