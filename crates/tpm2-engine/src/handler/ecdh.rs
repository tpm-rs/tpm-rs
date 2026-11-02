use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, owned::OwnedPublicParmsAndId, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmEccCurve;
use tpm2::commands::ECDHKeyGen;
use tpm2::commands::responses;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bEccParameter, TpmsEccPoint};

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

        let handles = request.try_unmarshal_handles::<ECDHKeyGen>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let _cmd = request.try_unmarshal_command::<ECDHKeyGen>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;

        // Only the public point of `keyHandle` is used, so the only requirement is that it is
        // a loaded ECC key (`ECDH_KeyGen.c`); its attributes are not checked.
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

        // The public point of `keyHandle` is checked only by the point multiplication, after the
        // ephemeral key pair has been generated (C `TPM2_ECDH_KeyGen()`: `CryptoEcc_NewKeyPair()`
        // first, then `TPM_RC_ECC_POINT` from `CryptoEcc_PointMultiply()` becomes `TPM_RC_KEY`),
        // so a bad point still consumes the random numbers of the ephemeral key.
        let qs_x = qs_point.x.get_buffer();
        let qs_y = qs_point.y.get_buffer();
        let qs_unusable = qs_x.len() > param_size
            || qs_y.len() > param_size
            || (qs_x.is_empty() && qs_y.is_empty());

        let mut qs_bytes = [0u8; 256];
        if !qs_unusable {
            qs_bytes[param_size - qs_x.len()..param_size].copy_from_slice(qs_x);
            qs_bytes[2 * param_size - qs_y.len()..2 * param_size].copy_from_slice(qs_y);
        }

        let mut de_buf = [0u8; 128];
        let mut qe_buf = [0u8; 256];
        // `CryptEccNewKeyPair()`: with `reference-rng`, from the TPM's DRBG as in the reference.
        #[cfg(feature = "reference-rng")]
        let (pub_len, priv_len) = {
            let len = self.reference_ecc_new_key_pair(curve, &mut de_buf, &mut qe_buf)?;
            (2 * len, len)
        };
        // (`CryptEccNewKeyPair()` tests ECDH before it generates the key.)
        #[cfg(not(feature = "reference-rng"))]
        self.do_self_test(tpm2::Alg::ECDH)?;
        #[cfg(not(feature = "reference-rng"))]
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

        if qs_unusable {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        let mut z_raw = [0u8; 256];
        // Any failure, a point at infinity / invalid point (`Ok(None)`) or a crypto error, is
        // `TPM_RC_KEY` on `keyHandle`, as in exp.
        if !matches!(
            self.crypto().point_multiply(
                curve,
                &de_buf[..priv_len],
                &qs_bytes[..2 * param_size],
                &mut z_raw[..2 * param_size],
            ),
            Ok(Some(_))
        ) {
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
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
