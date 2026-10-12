//! Key encapsulation commands: `TPM2_Encapsulate` and `TPM2_Decapsulate`.

use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::owned::{OwnedPublicParmsAndId, OwnedSensitiveComposite};
#[allow(unused_imports)]
use tpm2::TpmCc;
#[allow(deprecated)]
use tpm2::commands::{Decapsulate, Encapsulate, responses};
use tpm2::crypto::Mlkem;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2b, TpmaObject, TpmiMlkemParms};

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::Encapsulate] (`0x1A7`) command.
    pub fn encapsulate(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<Encapsulate>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal_command::<Encapsulate>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;
        let OwnedPublicParmsAndId::Mlkem(parms, unique) = &obj.public.parms_and_id else {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        };

        let pub_key = Mlkem::load_public(self.crypto(), parms.parameter_set, unique.as_tpm2b())
            .ok()
            .flatten()
            .ok_or(TpmRc::KEY.with(Position::handle(1)))?;
        let mut ct_buf = [0u8; TpmiMlkemParms::MAX_CT_BYTES];
        let mut ss_buf = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
        let crypto = self.crypto();
        let (ciphertext, shared_secret) = Mlkem::encapsulate(
            crypto,
            &mut self.context.platform.rng,
            &pub_key,
            &mut ct_buf,
            &mut ss_buf,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let rsp = responses::Encapsulate {
            shared_secret,
            ciphertext,
        };
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::Decapsulate] (`0x1A8`) command.
    pub fn decapsulate(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<Decapsulate>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<Decapsulate>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;
        let OwnedPublicParmsAndId::Mlkem(parms, _) = &obj.public.parms_and_id else {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        };

        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
            || !obj.public.object_attributes.contains(TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        let OwnedSensitiveComposite::Mlkem(seed) = &obj.sensitive else {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        };

        let priv_key = Mlkem::derive_key(self.crypto(), parms.parameter_set, Tpm2b(seed))
            .map_err(|_| TpmRc::KEY.with(Position::handle(1)))?;
        let mut ss_buf = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
        let shared_secret =
            Mlkem::decapsulate(self.crypto(), &priv_key, cmd.ciphertext, &mut ss_buf)
                .ok()
                .flatten()
                .ok_or(TpmRc::VALUE.with(Position::parameter(1)))?;

        let rsp = responses::Decapsulate { shared_secret };
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
