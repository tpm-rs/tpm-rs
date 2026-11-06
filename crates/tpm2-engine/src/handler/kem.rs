//! `TPM2_Encapsulate()` and `TPM2_Decapsulate()` (TPM 2.0 Part 3, version 185; features
//! `cc-encapsulate` and `cc-decapsulate`).
//!
//! The KEM keys of this TPM are ML-KEM keys (`mlkem`). Part 1, "ECC Key Encapsulation
//! Mechanism", also defines a DHKEM for ECC decryption keys with a non-NULL *kdf*; this TPM
//! requires the *kdf* of an ECC key to be `TPM_ALG_NULL` (as the TCG reference does, which also
//! implements only ML-KEM in these commands), so an ECC key is never a KEM key here.

use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Tpm2bSharedSecret;
use tpm2::crypto::{Crypto, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles [tpm2::TpmCc::Encapsulate] (`0x1A7`).
    ///
    /// TPM 2.0 Part 3, TPM2_Encapsulate: "Given a recipient's public key, `TPM2_Encapsulate()`
    /// returns a random *sharedSecret* and an accompanying *ciphertext* that can be decapsulated
    /// using the corresponding private key to produce the same *sharedSecret*. The key
    /// referenced by *keyHandle* shall be a KEM key (`TPM_RC_KEY`). ... The TPM does not verify
    /// the *objectAttributes* of the key."
    #[cfg(feature = "cc-encapsulate")]
    pub fn encapsulate(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<tpm2::commands::Encapsulate>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal_command::<tpm2::commands::Encapsulate>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let key = self.resolve_object(key_handle.0, Position::handle(1))?;
        let Some((param_set, public_key)) = super::pqc::mlkem_key(&key) else {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        };
        let mut ciphertext = [0u8; tpm2::TPM2_MAX_MLKEM_CT_SIZE];
        let mut shared_secret = [0u8; tpm2::TpmiMlkemParms::SHARED_SECRET_BYTES];
        let ciphertext_len =
            self.mlkem_encapsulate(param_set, public_key, &mut ciphertext, &mut shared_secret)?;

        let rsp = tpm2::commands::responses::Encapsulate {
            shared_secret: Tpm2bSharedSecret::from_bytes(&shared_secret)
                .map_err(|_| TpmRc::FAILURE)?,
            ciphertext: tpm2::Tpm2bKemCiphertext::from_bytes(&ciphertext[..ciphertext_len])
                .map_err(|_| TpmRc::FAILURE)?,
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])
    }

    /// Handles [tpm2::TpmCc::Decapsulate] (`0x1A8`).
    ///
    /// TPM 2.0 Part 3, TPM2_Decapsulate: "Given a private key, `TPM2_Decapsulate()` takes a
    /// *ciphertext* ... and returns the same *sharedSecret* that was produced during the
    /// encapsulation. The key referenced by *keyHandle* shall be a KEM key (`TPM_RC_KEY`) with
    /// *restricted* CLEAR and *decrypt* SET (`TPM_RC_ATTRIBUTES`)."
    #[cfg(feature = "cc-decapsulate")]
    pub fn decapsulate(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<tpm2::commands::Decapsulate>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<tpm2::commands::Decapsulate>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let key = self.resolve_object(key_handle.0, Position::handle(1))?;
        if super::pqc::mlkem_key(&key).is_none() {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        let attributes = key.public.object_attributes;
        if attributes.contains(tpm2::TpmaObject::RESTRICTED)
            || !attributes.contains(tpm2::TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        // "This command uses the private key of *keyHandle*": a public-only object has none.
        if key.public_only {
            return Err(TpmRc::HANDLE.with(Position::handle(1)));
        }
        let mut shared_secret = [0u8; tpm2::TpmiMlkemParms::SHARED_SECRET_BYTES];
        self.mlkem_decapsulate(&key, cmd.ciphertext.get_buffer(), &mut shared_secret)?;

        let rsp = tpm2::commands::responses::Decapsulate {
            shared_secret: Tpm2bSharedSecret::from_bytes(&shared_secret)
                .map_err(|_| TpmRc::FAILURE)?,
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])
    }
}
