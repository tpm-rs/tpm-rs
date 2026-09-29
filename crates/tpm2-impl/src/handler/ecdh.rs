use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, owned::OwnedPublicParmsAndId, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmEccCurve;
use tpm2::commands::responses;
use tpm2::commands::{ECDHKeyGen, ECDHKeyGenHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bEccParameter, TpmaObject, TpmsEccPoint};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
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

        let handles = request.try_unmarshal::<ECDHKeyGenHandles>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal::<ECDHKeyGen>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(handles.key_handle.0, Position::handle(1))?;

        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
            || !obj.public.object_attributes.contains(TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        let curve = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Ecc(ecc_parms, _) => ecc_parms.curve_id,
            _ => {
                return Err(TpmRc::KEY.with(Position::handle(1)));
            }
        };

        let param_size = match curve {
            TpmEccCurve::NistP224 => 28,
            TpmEccCurve::NistP256 | TpmEccCurve::BNP256 => 32,
            TpmEccCurve::NistP384 => 48,
            TpmEccCurve::NistP521 => 66,
            _ => return Err(TpmRc::VALUE.to_rc()),
        };

        let qs_point = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Ecc(_, p) => p,
            _ => unreachable!(),
        };

        let qs_x = qs_point.x.get_buffer();
        let qs_y = qs_point.y.get_buffer();
        if qs_x.len() > param_size
            || qs_y.len() > param_size
            || (qs_x.is_empty() && qs_y.is_empty())
        {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        let mut qs_bytes = [0u8; 256];
        qs_bytes[param_size - qs_x.len()..param_size].copy_from_slice(qs_x);
        qs_bytes[2 * param_size - qs_y.len()..2 * param_size].copy_from_slice(qs_y);

        let mut de_buf = [0u8; 128];
        let mut qe_buf = [0u8; 256];
        let (pub_len, priv_len) = self
            .crypto()
            .generate_key(
                tpm2::Alg::ECC,
                Some(tpm2::crypto::asymmetric::KeyParams::Ecc(curve)),
                &mut qe_buf,
                &mut de_buf,
                None,
            )
            .map_err(|_| TpmRc::FAILURE)?;

        let mut z_raw = [0u8; 256];
        if self
            .crypto()
            .point_multiply(
                curve,
                &de_buf[..priv_len],
                &qs_bytes[..2 * param_size],
                &mut z_raw[..2 * param_size],
            )
            .is_err()
        {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        let qe_x =
            Tpm2bEccParameter::from_bytes(&qe_buf[..param_size]).map_err(|_| TpmRc::FAILURE)?;
        let qe_y = Tpm2bEccParameter::from_bytes(&qe_buf[param_size..pub_len])
            .map_err(|_| TpmRc::FAILURE)?;
        let pub_point = tpm2::Tpm2b(TpmsEccPoint { x: qe_x, y: qe_y });

        let z_x =
            Tpm2bEccParameter::from_bytes(&z_raw[..param_size]).map_err(|_| TpmRc::FAILURE)?;
        let z_y = Tpm2bEccParameter::from_bytes(&z_raw[param_size..2 * param_size])
            .map_err(|_| TpmRc::FAILURE)?;
        let z_point = tpm2::Tpm2b(TpmsEccPoint { x: z_x, y: z_y });

        let rsp = responses::ECDHKeyGen { z_point, pub_point };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
