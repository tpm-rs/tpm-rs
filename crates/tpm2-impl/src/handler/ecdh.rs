use super::crypt_ops::{
    PaddedEccPoint, ecc_param_size, ecc_point_multiply, ecc_public_point, load_ecc_public,
};
use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, owned::OwnedPublicParmsAndId, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{ECDHKeyGen, responses};
use tpm2::crypto::Ecc;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2b, TpmaObject};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [tpm2::TpmCc::ECDHKeyGen] (`0x163`) command.
    ///
    /// # Description
    /// This command uses the TPM to generate an ephemeral key pair (d_e, Q_e where Q_e := \[d_e\]G).
    /// It uses the private ephemeral key and a loaded public key (Q_s) to compute the shared secret value (Z := h\[d_e\]Q_s).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 15.6 (TPM2_ECDH_KeyGen).
    pub fn ecdh_keygen(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<ECDHKeyGen>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal_command::<ECDHKeyGen>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;

        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
            || !obj.public.object_attributes.contains(TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        let (curve, qs_point) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Ecc(ecc_parms, qs_point) => (ecc_parms.curve_id, qs_point),
            _ => {
                return Err(TpmRc::KEY.with(Position::handle(1)));
            }
        };

        let param_size = ecc_param_size(curve).ok_or(TpmRc::VALUE.to_rc())?;

        let qs_x = qs_point.x.get_buffer();
        let qs_y = qs_point.y.get_buffer();
        if qs_x.len() > param_size
            || qs_y.len() > param_size
            || (qs_x.is_empty() && qs_y.is_empty())
        {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        let qs = PaddedEccPoint::new(qs_x, qs_y, param_size)
            .ok_or(TpmRc::KEY.with(Position::handle(1)))?;

        // PORTING: exp's `generate_key(Alg::ECC, ..)` raw-buffer API is now
        // `Ecc::generate_key` with the TPM's global RNG.
        let crypto = self.crypto();
        let ephemeral = Ecc::generate_key(crypto, &mut self.context.platform.rng, curve)
            .map_err(|_| TpmRc::FAILURE)?;

        // PORTING: exp's `point_multiply(curve, d_e, Q_s)`; an invalid `Q_s` (which now fails to
        // load) is reported like a failing multiplication.
        let z_point = load_ecc_public(crypto, curve, &qs)
            .and_then(|qs| ecc_point_multiply(crypto, &ephemeral, &qs, param_size).ok())
            .flatten()
            .ok_or(TpmRc::KEY.with(Position::handle(1)))?;

        let pub_point = ecc_public_point::<C>(&ephemeral, param_size).ok_or(TpmRc::FAILURE)?;

        let rsp = responses::ECDHKeyGen {
            z_point: Tpm2b(z_point.as_tpms()?),
            pub_point: Tpm2b(pub_point.as_tpms()?),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
