use super::crypt_ops::{
    PaddedEccPoint, ecc_param_size, ecc_point_multiply, ecc_public_point, load_ecc_private,
    load_ecc_public,
};
use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::TransientObject;
use crate::owned::OwnedPublicParmsAndId;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{Commit, responses};
use tpm2::crypto::Ecc;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2b, Tpm2bEccParameter, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmsEccPoint};

/// The validated `P1` input of `TPM2_Commit`: its (padded) coordinates and the loaded point.
type CommitPoint<C> = (PaddedEccPoint, <C as Ecc>::PublicKey);

/// The validated inputs of `TPM2_Commit`: `P1` (if not empty) and the loaded point
/// `B = (H(s2), y2)` (if `s2` and `y2` were provided).
type CommitInputs<C> = (Option<CommitPoint<C>>, Option<<C as Ecc>::PublicKey>);

/// The points `K`, `L` and `E` computed by `TPM2_Commit` (`K` is only computed if `P1` or
/// `s2`/`y2` were provided).
struct CommitPoints {
    k: Option<PaddedEccPoint>,
    l: PaddedEccPoint,
    e: PaddedEccPoint,
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::Commit] (`0x18B`) command.
    ///
    /// # Description
    /// This command is used with ECC keys in signature schemes (like ECDAA) that require a commit step.
    /// It performs point multiplications using a TPM-internal random scalar `r` to generate points K, L, and E,
    /// and increments the commit counter.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 19.2 (TPM2_Commit).
    ///
    /// # Relationships
    /// - The `sign_handle` must reference a loaded ECC signing-only key created by [TpmCc::Create](create.rs)
    ///   or [TpmCc::CreatePrimary](create_primary.rs).
    /// - The outputs and the returned `counter` are subsequently used in [TpmCc::Sign] to construct the signature.
    pub fn commit(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<Commit>()?;
        let [sign_handle] = handles;
        check(sign_handle, Tpmi::DhObject, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        // 1. Lookup signing key and validate attributes
        let (sign_key, curve, hash_alg) =
            self.validate_commit_object_attributes(sign_handle, num_sessions)?;

        let cmd = request.try_unmarshal_command::<Commit>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 2. Validate input point P1 and parameters S2/Y2
        let param_size = ecc_param_size(curve).ok_or(TpmRc::VALUE.to_rc())?;
        let (p1, b) = self.validate_commit_inputs(&cmd, curve, hash_alg, param_size)?;

        // 3. Execute ECC point multiplication algorithms
        let old_counter = self.global_state.commit_counter;
        let points = self.execute_commit_multiplications(
            curve,
            &sign_key,
            p1.as_ref().map(|(_, p1)| p1),
            b.as_ref(),
            param_size,
            old_counter,
        )?;

        // Store the X coordinate of the committed point (E if P1 present or s2 absent, else L)
        self.global_state.commit_x.fill(0);
        self.global_state.commit_p1.fill(0);
        if let Some((p1_point, _)) = &p1 {
            // `x || y` of P1, truncated to the size of `commit_p1`.
            let p1_bytes = p1_point.x().iter().chain(p1_point.y());
            for (dst, src) in self.global_state.commit_p1.iter_mut().zip(p1_bytes) {
                *dst = *src;
            }
        }
        let committed = if p1.is_some() || b.is_none() {
            &points.e
        } else {
            &points.l
        };
        for (dst, src) in self.global_state.commit_x.iter_mut().zip(committed.x()) {
            *dst = *src;
        }

        // Update state
        self.global_state.commit_counter = self.global_state.commit_counter.wrapping_add(1);

        let empty = TpmsEccPoint {
            x: Tpm2bEccParameter::default(),
            y: Tpm2bEccParameter::default(),
        };
        let (k, l) = match (&points.k, b.is_some()) {
            (Some(k), true) => (k.as_tpms()?, points.l.as_tpms()?),
            _ => (empty, empty),
        };
        let e = if p1.is_some() || b.is_none() {
            points.e.as_tpms()?
        } else {
            empty
        };

        let rsp = responses::Commit {
            k: Tpm2b(k),
            l: Tpm2b(l),
            e: Tpm2b(e),
            counter: old_counter,
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Resolves the signing object and validates its attributes to ensure it is
    /// an ECC signing-only key.
    ///
    /// PORTING: returns the whole (cloned) object instead of exp's
    /// `(public, private, curve, hash_alg, name)` tuple.
    fn validate_commit_object_attributes(
        &self,
        sign_handle: Handle,
        num_sessions: usize,
    ) -> Result<(TransientObject, TpmEccCurve, TpmiAlgHash), TpmRc> {
        let obj = self
            .global_state
            .find_transient_object(sign_handle.0)
            .ok_or(TpmRc::HANDLE.to_rc())?
            .clone();

        if num_sessions == 0 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let attributes = obj.public.object_attributes;
        if !attributes.contains(TpmaObject::USER_WITH_AUTH) {
            return Err(TpmRc::AUTH_TYPE);
        }

        if attributes.contains(TpmaObject::DECRYPT) {
            let pos = Position::handle(1);
            return Err(TpmRc::ATTRIBUTES.with(pos));
        }

        if !attributes.contains(TpmaObject::SIGN_ENCRYPT) {
            let pos = Position::handle(1);
            return Err(TpmRc::ATTRIBUTES.with(pos));
        }

        let (curve, hash_alg) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Ecc(ecc_parms, _) => {
                let curve = ecc_parms.curve_id;
                let hash_alg = match &ecc_parms.scheme {
                    Some(tpm2::TpmtEccScheme::Ecdaa(s)) => s.hash_alg,
                    _ => obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?,
                };
                (curve, hash_alg)
            }
            _ => {
                let pos = Position::handle(1);
                return Err(TpmRc::KEY.with(pos));
            }
        };

        Ok((obj, curve, hash_alg))
    }

    /// Validates `P1`, `s2`, and `y2` parameters for the `Commit` command.
    ///
    /// Returns the validated `P1` (if not empty) and the point `B = (H(s2), y2)` (if `s2` and
    /// `y2` are provided), both loaded into the crypto backend.
    ///
    /// PORTING: exp validated the points with `validate_point` on raw `x || y` buffers; they are
    /// now validated by [`Ecc::load_public`]. exp's fallback to the `nameAlg` digest size for a
    /// zero-sized hash is gone (every [`TpmiAlgHash`] has a non-zero digest size).
    fn validate_commit_inputs(
        &self,
        cmd: &Commit<'_>,
        curve: TpmEccCurve,
        hash_alg: TpmiAlgHash,
        param_size: usize,
    ) -> Result<CommitInputs<C>, TpmRc> {
        let digest_size = hash_alg.digest_size();

        if cmd.s2.as_slice().len() > digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(2)));
        }

        // PORTING: exp's `cmd.p1.to_struct()` (`TPM_RC_SIZE` + P1) is now done when the command
        // is unmarshaled.
        let p1_struct = cmd.p1.0;
        let p1_x = p1_struct.x.as_slice();
        let p1_y = p1_struct.y.as_slice();
        let p1_is_empty = p1_x.is_empty() && p1_y.is_empty();

        let crypto = self.crypto();
        let p1 = if !p1_is_empty {
            let p1_point = PaddedEccPoint::new(p1_x, p1_y, param_size)
                .ok_or(TpmRc::ECC_POINT.with(Position::parameter(1)))?;
            let p1 = load_ecc_public(crypto, curve, &p1_point)
                .ok_or(TpmRc::ECC_POINT.with(Position::parameter(1)))?;
            Some((p1_point, p1))
        } else {
            None
        };

        let s2_buf = cmd.s2.as_slice();
        let y2_buf = cmd.y2.as_slice();

        if s2_buf.is_empty() != y2_buf.is_empty() {
            return Err(TpmRc::SIZE.with(Position::parameter(3)));
        }

        let b = if !s2_buf.is_empty() && !y2_buf.is_empty() {
            let (digest_buf, digest_len) = self.compute_hash(hash_alg, &[s2_buf])?;
            if y2_buf.len() > param_size {
                return Err(TpmRc::SIZE.with(Position::parameter(3)));
            }
            // x2 := H(s2), right-aligned if shorter than the curve size, else truncated to its
            // leftmost `param_size` bytes.
            let digest = digest_buf.get(..digest_len).ok_or(TpmRc::FAILURE)?;
            let x2 = digest.get(..param_size).unwrap_or(digest);
            let xy2 = PaddedEccPoint::new(x2, y2_buf, param_size).ok_or(TpmRc::FAILURE)?;

            let b = load_ecc_public(crypto, curve, &xy2)
                .ok_or(TpmRc::ECC_POINT.with(Position::parameter(3)))?;

            Some(b)
        } else {
            None
        };

        Ok((p1, b))
    }

    /// Evaluates the ECC multiplication and generator-based multiplications to compute points K, L, and E.
    ///
    /// PORTING: the new [`Ecc`] trait has no raw scalar multiplication (exp's `point_multiply` /
    /// `point_multiply_generator`). Multiplications by the signing key's `d` use [`Ecc::ecdh`]
    /// with the loaded private key. For the commit random `r`, the KDFa output of
    /// [`CommandHandler::compute_commit_r`] seeds [`tpm2::crypto::Random::rng_seeded`], from
    /// which [`Ecc::generate_key`] derives the key `(r, [r]G)`: still deterministic in
    /// `(commitNonce, name, counter)`, but `r` is the backend-derived scalar rather than exp's
    /// raw KDFa output, so `L` and `E` differ from exp's values.
    fn execute_commit_multiplications(
        &self,
        curve: TpmEccCurve,
        sign_key: &TransientObject,
        p1: Option<&<C as Ecc>::PublicKey>,
        xy2: Option<&<C as Ecc>::PublicKey>,
        param_size: usize,
        commit_counter: u16,
    ) -> Result<CommitPoints, TpmRc> {
        let crypto = self.crypto();
        let r_seed =
            self.compute_commit_r(commit_counter, sign_key.name.get_buffer(), param_size)?;
        let r = r_seed.get(..param_size).ok_or(TpmRc::FAILURE)?;
        let r_key = crypto
            .rng_seeded(r)
            .and_then(|mut rng| Ecc::generate_key(crypto, &mut rng, curve))
            .map_err(|_| TpmRc::NO_RESULT)?;

        let multiply = |key: &<C as Ecc>::PrivateKey, point: &<C as Ecc>::PublicKey| {
            ecc_point_multiply(crypto, key, point, param_size)
                .ok()
                .flatten()
                .ok_or(TpmRc::NO_RESULT)
        };
        let signing_key = || {
            let OwnedPublicParmsAndId::Ecc(_, point) = &sign_key.public.parms_and_id else {
                return Err(TpmRc::NO_RESULT);
            };
            load_ecc_private(crypto, curve, point, &sign_key.sensitive).ok_or(TpmRc::NO_RESULT)
        };
        let generator_multiple =
            || ecc_public_point::<C>(&r_key, param_size).ok_or(TpmRc::NO_RESULT);

        let (k, l) = if let Some(xy2) = xy2 {
            let d_key = signing_key()?;
            (Some(multiply(&d_key, xy2)?), multiply(&r_key, xy2)?)
        } else {
            let k = match p1 {
                Some(p1) => Some(multiply(&signing_key()?, p1)?),
                None => None,
            };
            (k, generator_multiple()?)
        };

        let e = match p1 {
            Some(p1) => multiply(&r_key, p1)?,
            None => generator_multiple()?,
        };
        Ok(CommitPoints { k, l, e })
    }
}
