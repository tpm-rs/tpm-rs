//! The two-phase ECC key exchange: `TPM2_EC_Ephemeral` (`cc-ec-ephemeral`) and
//! `TPM2_ZGen_2Phase` (`cc-zgen-2phase`) with the schemes `TPM_ALG_ECDH` (Full Unified Model),
//! `TPM_ALG_ECMQV` (Full MQV, `ecmqv`) and `TPM_ALG_SM2` (SM2 key exchange, `sm2`), TPM 2.0
//! Part 1, "Two-Phase Key Exchange Protocols" and "SM2 Key Exchange".
//!
//! Both commands use the commit mechanism of `TPM2_Commit` (`commit.rs`): `TPM2_EC_Ephemeral`
//! derives the ephemeral private key `r` from the current commit counter and commits it, and
//! `TPM2_ZGen_2Phase` recovers `r` from its `counter` parameter and retires the commitment when
//! it succeeds.

// Only a build with every one of these features uses every item (the point helpers are shared
// with `ecc_encrypt_decrypt.rs`, the MQV/SM2 arithmetic needs `ecmqv`/`sm2`).
#![cfg_attr(
    not(all(
        feature = "cc-ec-ephemeral",
        feature = "cc-zgen-2phase",
        feature = "cc-ecc-encrypt",
        feature = "cc-ecc-decrypt",
        feature = "ecmqv",
        feature = "sm2"
    )),
    allow(dead_code, unused_imports)
)]

use super::encrypt_decrypt::crypto_len;
use crate::ecc_curves::{CurveParams, curve_params};
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::crypto::{Crypto, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bEccParameter, Tpm2bEccPoint, TpmEccCurve, TpmsEccPoint};

/// The largest ECC coordinate (and scalar) size of the `tpm2` features of this build.
pub(crate) const MAX_COORDINATE_SIZE: usize = Tpm2bEccParameter::CAP;
/// A buffer for an affine point `x || y` of any curve of this build.
pub(crate) type PointBuffer = [u8; 2 * MAX_COORDINATE_SIZE];
/// A buffer for a scalar (modulo the order of any curve of this build).
pub(crate) type ScalarBuffer = [u8; MAX_COORDINATE_SIZE];

/// Copies the coordinates of `point` into `out` as `x || y`, each left-padded with zeros to
/// `size` bytes. Leading zero bytes of a coordinate are ignored (the coordinates are integers, as
/// in the references' `TPM2B` to big-number conversion). Returns `false` if a coordinate does not
/// fit, i.e. is not smaller than `2^(8 * size)` (then the point is not on the curve).
pub(crate) fn pad_point(point: &TpmsEccPoint<'_>, size: usize, out: &mut [u8]) -> bool {
    pad_coordinates(point.x.get_buffer(), point.y.get_buffer(), size, out)
}

/// [`pad_point`] for coordinates given as byte strings.
pub(crate) fn pad_coordinates(x: &[u8], y: &[u8], size: usize, out: &mut [u8]) -> bool {
    let x = strip_leading_zeros(x);
    let y = strip_leading_zeros(y);
    if x.len() > size || y.len() > size || out.len() < 2 * size {
        return false;
    }
    out[..2 * size].fill(0);
    out[size - x.len()..size].copy_from_slice(x);
    out[2 * size - y.len()..2 * size].copy_from_slice(y);
    true
}

/// Left-pads the big-endian integer `value` with zeros to `out.len()` bytes; returns `false`
/// if it does not fit.
pub(crate) fn pad_scalar(value: &[u8], out: &mut [u8]) -> bool {
    let value = strip_leading_zeros(value);
    if value.len() > out.len() {
        return false;
    }
    let offset = out.len() - value.len();
    out[..offset].fill(0);
    out[offset..].copy_from_slice(value);
    true
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    &bytes[skip..]
}

/// The response form of the affine point `x || y` (`size`-byte coordinates, as the references'
/// `TpmEcc_PointTo2B()` writes them), or the Empty Point for `None` (the point at infinity).
pub(crate) fn response_point(
    point: Option<&[u8]>,
    size: usize,
) -> Result<Tpm2bEccPoint<'_>, TpmRc> {
    let point = match point {
        Some(p) => TpmsEccPoint {
            x: Tpm2bEccParameter::from_bytes(&p[..size]).map_err(|_| TpmRc::FAILURE)?,
            y: Tpm2bEccParameter::from_bytes(&p[size..2 * size]).map_err(|_| TpmRc::FAILURE)?,
        },
        None => TpmsEccPoint::default(),
    };
    Ok(tpm2::Tpm2b(point))
}

/// The number of significant bits of the big-endian integer `n` (`ceil(log2(n))` for an `n`
/// that is not a power of two, which holds for every curve order).
fn bit_length(n: &[u8]) -> usize {
    let n = strip_leading_zeros(n);
    match n.first() {
        Some(&b) => (n.len() - 1) * 8 + (8 - b.leading_zeros() as usize),
        None => 0,
    }
}

/// The associated value of the coordinate `x`: `2^f + (x mod 2^f)`, written to `out`
/// (big-endian, `out.len()` bytes, which must exceed `f / 8`).
///
/// TPM 2.0 Part 1, "Full MQV" (`avf()`): f = ceil(ceil(log2(n)) / 2); "SM2 Key Exchange"
/// (`avfSM2()`): f = ceil(ceil(log2(n)) / 2) - 1.
fn associated_value(x: &[u8], f: usize, out: &mut [u8]) {
    out.fill(0);
    let len = out.len();
    // The low `f` bits of `x`: whole bytes, then the remaining bits of the next byte.
    for i in 0..f.div_ceil(8) {
        let byte = if i < x.len() { x[x.len() - 1 - i] } else { 0 };
        let bits = f - 8 * i;
        out[len - 1 - i] = if bits >= 8 {
            byte
        } else {
            byte & ((1u8 << bits) - 1)
        };
    }
    out[len - 1 - f / 8] |= 1 << (f % 8);
}

/// The scalar `h * t mod n` of the final point multiplication of the MQV and SM2 key
/// exchanges, from the secret `t` (already reduced modulo `n`), written to `out` (`n.len()`
/// bytes).
///
/// `crate::modular::mul_mod` branches on the bits of its first operand, so the public cofactor
/// is that operand; a cofactor of 1 (every curve of this TPM) leaves `t` unchanged.
fn times_cofactor(params: &CurveParams, t: &[u8], out: &mut [u8]) {
    let h = strip_leading_zeros(params.h);
    if h == [1] {
        out.copy_from_slice(t);
    } else {
        crate::modular::mul_mod(h, t, params.n, out);
    }
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::ECEphemeral] (`0x18E`) command.
    ///
    /// # Description
    /// Creates an ephemeral key for a two-phase key exchange with the commit mechanism: derives
    /// the random value `r` from the current commit counter, computes `Q := [r]G` on `curveID`
    /// and commits the counter value, which is returned as `counter`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, TPM2_EC_Ephemeral; Part 1,
    /// "TPM2_EC_Ephemeral()" and "Two-Phase Key Exchange Protocols".
    ///
    /// # Relationships
    /// - `counter` selects `r` again in a later [TpmCc::ZGen2Phase], which retires it.
    /// - Shares the commit counter and the commit array with [TpmCc::Commit](commit.rs).
    #[cfg(feature = "cc-ec-ephemeral")]
    pub fn ec_ephemeral(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        use tpm2::commands::{ECEphemeral, responses};

        let mut request = request_response;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        // An unimplemented curve fails while unmarshaling `TPMI_ECC_CURVE` (`TPM_RC_CURVE + RC_P1`).
        let cmd = request.try_unmarshal_command::<ECEphemeral>([])?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let curve = cmd.curve_id;
        let size = curve_params(curve)
            .ok_or(TpmRc::CURVE.with(Position::parameter(1)))?
            .p
            .len();

        let mut q = [0u8; 2 * MAX_COORDINATE_SIZE];
        let counter = loop {
            // `CryptGenerateR()` without a counter: `r` for the current commit counter value
            // (this does not commit it).
            let (r, r_len) = self
                .generate_r(self.context.state.commit_counter, &[], curve)
                .ok_or(TpmRc::NO_RESULT)?;
            let result =
                self.crypto()
                    .point_multiply_generator(curve, &r[..r_len], &mut q[..2 * size]);
            match result {
                Ok(Some(_)) => break self.crypt_commit(),
                // A point at infinity also commits the counter value, so that this `r` is
                // skipped (as in the references; it cannot occur for 0 < r < n).
                Ok(None) => {
                    self.crypt_commit();
                }
                Err(_) => return Err(TpmRc::FAILURE),
            }
        };

        let rsp = responses::ECEphemeral {
            q: response_point(Some(&q), size)?,
            counter,
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::ZGen2Phase] (`0x18D`) command.
    ///
    /// # Description
    /// The second phase of a two-phase key exchange: recovers the ephemeral private key
    /// `d_e,A = r` of `counter` (from [TpmCc::ECEphemeral]) and computes, with the static private
    /// key `d_s,A` of `keyA` and the other party's static and ephemeral public keys `Q_s,B`
    /// (`inQsB`) and `Q_e,B` (`inQeB`), the values of the selected scheme:
    /// - `TPM_ALG_ECDH`: `outZ1 := [d_s,A]Q_s,B` and `outZ2 := [d_e,A]Q_e,B`;
    /// - `TPM_ALG_ECMQV`: `outZ1 := [h · t_A](Q_e,B + [avf(Q_e,B)]Q_s,B)` with
    ///   `t_A := (d_e,A + d_s,A · avf(Q_e,A)) mod n`, and an Empty Point `outZ2`;
    /// - `TPM_ALG_SM2`: `outZ1 := [h · t_A](Q_s,B + [avfSM2(Q_e,B)]Q_e,B)` with
    ///   `t_A := (d_s,A + d_e,A · avfSM2(Q_e,A)) mod n`, and an Empty Point `outZ2`.
    ///
    /// A Z value that is the point at infinity is an Empty Point (Part 3: "If a computation of
    /// either Z produces the point at infinity, then the corresponding Z value will be an Empty
    /// Point"). For SM2, Part 1 ("SM2 Key Exchange Protocol", step 6) says "if Z is the point at
    /// infinity, return failure"; Part 3 wins: it defines the command's response for every
    /// scheme it supports, while Part 1 describes the protocol without a response code. When the
    /// command succeeds, the commitment of `counter` is retired.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, TPM2_ZGen_2Phase; Part 1,
    /// "Two-Phase Key Exchange Protocols", "Recovering the Private Ephemeral Key" and "SM2 Key
    /// Exchange".
    #[cfg(feature = "cc-zgen-2phase")]
    pub fn zgen_2phase(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        use crate::owned::OwnedPublicParmsAndId;
        use tpm2::TpmaObject;
        use tpm2::commands::{ZGen2Phase, responses};

        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<ZGen2Phase>()?;
        let [key_a] = handles;
        check(key_a, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<ZGen2Phase>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_a.0, Position::handle(1))?;

        // `keyA` is "an unrestricted ECC decryption key" (Part 3): an ECC key (`TPM_RC_KEY`),
        // then `restricted` CLEAR and `decrypt` SET (`TPM_RC_ATTRIBUTES`).
        let (curve, key_scheme) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Ecc(parms, _) => (parms.curve_id, parms.scheme),
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };
        let attributes = obj.public.object_attributes;
        if attributes.contains(TpmaObject::RESTRICTED) || !attributes.contains(TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        // A key scheme other than `TPM_ALG_NULL` must be the scheme of the command
        // (`TPM_RC_SCHEME`); `inScheme` itself cannot be `TPM_ALG_NULL` (`TPMI_ECC_KEY_EXCHANGE`
        // without `+`, rejected while unmarshaling).
        let scheme = cmd.in_scheme;
        if let Some(key_scheme) = key_scheme
            && key_scheme.scheme() != tpm2::Alg::from(scheme)
        {
            return Err(TpmRc::SCHEME.with(Position::parameter(3)));
        }
        // Defense in depth: a public-only key cannot be authorized (its USER role needs the
        // authValue or authPolicy), so it never gets here.
        if obj.private_len == 0 {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        let params = curve_params(curve).ok_or(TpmRc::CURVE.with(Position::handle(1)))?;
        let size = params.p.len();
        let n_len = params.n.len();

        // `inQsB` and `inQeB` must be on the curve of `keyA` (`TPM_RC_ECC_POINT`).
        let mut qs_b = [0u8; 2 * MAX_COORDINATE_SIZE];
        let mut qe_b = [0u8; 2 * MAX_COORDINATE_SIZE];
        for (point, buf, pos) in [
            (&cmd.in_qs_b, &mut qs_b, Position::parameter(1)),
            (&cmd.in_qe_b, &mut qe_b, Position::parameter(2)),
        ] {
            let on_curve = point.to_struct().is_ok_and(|p| pad_point(&p, size, buf))
                && matches!(
                    crate::ecc_curves::validate_point::<C>(curve, &buf[..2 * size]),
                    Ok(true)
                );
            if !on_curve {
                return Err(TpmRc::ECC_POINT.with(pos));
            }
        }

        // Recover d_e,A = r (Part 1, "Recovering the Private Ephemeral Key"): a counter that was
        // not committed, was already used, or lies outside the window of the commit counter is
        // `TPM_RC_VALUE`.
        let (r, r_len) = self
            .generate_committed_r(cmd.counter, &[], curve)
            .map_err(|_| TpmRc::VALUE.with(Position::parameter(4)))?;
        let de_a = &r[..r_len];
        let mut ds_a = [0u8; MAX_COORDINATE_SIZE];
        if !pad_scalar(&obj.private[..obj.private_len], &mut ds_a[..n_len]) {
            return Err(TpmRc::FAILURE);
        }
        let ds_a = &ds_a[..n_len];

        let mut z1 = [0u8; 2 * MAX_COORDINATE_SIZE];
        let mut z2 = [0u8; 2 * MAX_COORDINATE_SIZE];
        let (z1_is_point, z2_is_point) = match scheme {
            tpm2::TpmiEccKeyExchange::Ecdh => (
                self.ecc_multiply(curve, ds_a, &qs_b[..2 * size], &mut z1[..2 * size])?,
                self.ecc_multiply(curve, de_a, &qe_b[..2 * size], &mut z2[..2 * size])?,
            ),
            #[cfg(feature = "ecmqv")]
            tpm2::TpmiEccKeyExchange::Ecmqv => (
                self.mqv_or_sm2(
                    curve,
                    params,
                    KeyExchange::Mqv,
                    ds_a,
                    de_a,
                    &qs_b[..2 * size],
                    &qe_b[..2 * size],
                    &mut z1[..2 * size],
                )?,
                false,
            ),
            #[cfg(feature = "sm2")]
            tpm2::TpmiEccKeyExchange::Sm2 => (
                self.mqv_or_sm2(
                    curve,
                    params,
                    KeyExchange::Sm2,
                    ds_a,
                    de_a,
                    &qs_b[..2 * size],
                    &qe_b[..2 * size],
                    &mut z1[..2 * size],
                )?,
                false,
            ),
            // A scheme that `tpm2` accepts but this TPM does not implement.
            #[allow(unreachable_patterns)]
            _ => return Err(TpmRc::SCHEME.with(Position::parameter(3))),
        };

        // The command succeeded: retire the commitment (`CryptEndCommit()`).
        self.end_commit(cmd.counter);

        let rsp = responses::ZGen2Phase {
            out_z1: response_point(z1_is_point.then_some(&z1[..]), size)?,
            out_z2: response_point(z2_is_point.then_some(&z2[..]), size)?,
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// `out := [scalar]point`; returns `false` if the product is the point at infinity (or the
    /// scalar is zero).
    fn ecc_multiply(
        &self,
        curve: TpmEccCurve,
        scalar: &[u8],
        point: &[u8],
        out: &mut [u8],
    ) -> Result<bool, TpmRc> {
        match self.crypto().point_multiply(curve, scalar, point, out) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(_) => Err(TpmRc::FAILURE),
        }
    }

    /// The Z value of the Full MQV (Part 1, "Full MQV") or SM2 (Part 1, "SM2 Key Exchange
    /// Protocol") key exchange, written to `z_out` (`x || y`); returns `false` if Z is the point
    /// at infinity.
    #[allow(clippy::too_many_arguments)]
    fn mqv_or_sm2(
        &self,
        curve: TpmEccCurve,
        params: &CurveParams,
        exchange: KeyExchange,
        ds_a: &[u8],
        de_a: &[u8],
        qs_b: &[u8],
        qe_b: &[u8],
        z_out: &mut [u8],
    ) -> Result<bool, TpmRc> {
        let n = params.n;
        let n_len = n.len();
        let size = params.p.len();
        let f = match exchange {
            KeyExchange::Mqv => bit_length(n).div_ceil(2),
            KeyExchange::Sm2 => bit_length(n).div_ceil(2) - 1,
        };

        // Q_e,A := [d_e,A]G.
        let mut qe_a: PointBuffer = [0u8; 2 * MAX_COORDINATE_SIZE];
        crypto_len(
            self.crypto()
                .point_multiply_generator(curve, de_a, &mut qe_a[..2 * size]),
            TpmRc::NO_RESULT,
        )?;

        // MQV: t_A := (d_e,A + d_s,A · avf(Q_e,A)) mod n;
        // SM2: t_A := (d_s,A + d_e,A · avfSM2(Q_e,A)) mod n.
        let (multiplied, added) = match exchange {
            KeyExchange::Mqv => (ds_a, de_a),
            KeyExchange::Sm2 => (de_a, ds_a),
        };
        let mut avf_a: ScalarBuffer = [0u8; MAX_COORDINATE_SIZE];
        associated_value(&qe_a[..size], f, &mut avf_a[..n_len]);
        let mut multiplied_padded: ScalarBuffer = [0u8; MAX_COORDINATE_SIZE];
        if !pad_scalar(multiplied, &mut multiplied_padded[..n_len]) {
            return Err(TpmRc::FAILURE);
        }
        // `crate::modular::mul_mod` branches on the bits of its first operand: that is the public
        // associated value, not the private key.
        let mut product: ScalarBuffer = [0u8; MAX_COORDINATE_SIZE];
        crate::modular::mul_mod(
            &avf_a[..n_len],
            &multiplied_padded[..n_len],
            n,
            &mut product[..n_len],
        );
        let mut added_padded: ScalarBuffer = [0u8; MAX_COORDINATE_SIZE];
        if !pad_scalar(added, &mut added_padded[..n_len]) {
            return Err(TpmRc::FAILURE);
        }
        let mut t_a: ScalarBuffer = [0u8; MAX_COORDINATE_SIZE];
        crate::modular::add_mod(
            &product[..n_len],
            &added_padded[..n_len],
            n,
            &mut t_a[..n_len],
        );
        let mut scalar: ScalarBuffer = [0u8; MAX_COORDINATE_SIZE];
        times_cofactor(params, &t_a[..n_len], &mut scalar[..n_len]);

        // MQV: P := Q_e,B + [avf(Q_e,B)]Q_s,B; SM2: P := Q_s,B + [avfSM2(Q_e,B)]Q_e,B.
        let mut avf_b: ScalarBuffer = [0u8; MAX_COORDINATE_SIZE];
        associated_value(&qe_b[..size], f, &mut avf_b[..n_len]);
        let (multiplied_point, added_point) = match exchange {
            KeyExchange::Mqv => (qs_b, qe_b),
            KeyExchange::Sm2 => (qe_b, qs_b),
        };
        let mut term: PointBuffer = [0u8; 2 * MAX_COORDINATE_SIZE];
        if !self.ecc_multiply(
            curve,
            &avf_b[..n_len],
            multiplied_point,
            &mut term[..2 * size],
        )? {
            // [avf]Q is never the point at infinity for a point Q of prime order n and
            // 0 < avf < n.
            return Err(TpmRc::NO_RESULT);
        }
        let mut sum: PointBuffer = [0u8; 2 * MAX_COORDINATE_SIZE];
        if crate::ecc_curves::point_add(params, added_point, &term[..2 * size], &mut sum).is_none()
        {
            return Ok(false);
        }

        // Z := [h · t_A]P.
        self.ecc_multiply(curve, &scalar[..n_len], &sum[..2 * size], z_out)
    }
}

/// The key exchanges with an associated value function.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyExchange {
    /// Full MQV (`TPM_ALG_ECMQV`).
    Mqv,
    /// The SM2 key exchange (`TPM_ALG_SM2`).
    #[cfg_attr(not(feature = "sm2"), allow(dead_code))]
    Sm2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn associated_value_keeps_low_bits_and_sets_bit_f() {
        let mut out = [0u8; 4];
        // f = 4: 2^4 + (0xABCD mod 16) = 0x1D.
        associated_value(&[0xAB, 0xCD], 4, &mut out);
        assert_eq!(out, [0, 0, 0, 0x1D]);
        // f = 12: 2^12 + (0xABCD mod 4096) = 0x1BCD.
        associated_value(&[0xAB, 0xCD], 12, &mut out);
        assert_eq!(out, [0, 0, 0x1B, 0xCD]);
        // f = 16: 2^16 + 0xABCD.
        associated_value(&[0xAB, 0xCD], 16, &mut out);
        assert_eq!(out, [0, 0x01, 0xAB, 0xCD]);
    }

    #[test]
    fn bit_length_of_orders() {
        assert_eq!(bit_length(&[0x00, 0x01]), 1);
        assert_eq!(bit_length(&[0x01, 0xFF]), 9);
        assert_eq!(bit_length(&[0xFF; 32]), 256);
    }
}
