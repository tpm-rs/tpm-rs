use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{Commit, CommitHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bEccParameter, TpmEccCurve, TpmaObject, TpmsEccPoint};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
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

        let handles = request.try_unmarshal::<CommitHandles>()?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        // 1. Lookup signing key and validate attributes
        let (in_public, actual_private_key, curve, hash_alg, key_name) =
            self.validate_commit_object_attributes(handles.sign_handle, num_sessions)?;

        let cmd = request.try_unmarshal::<Commit>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 2. Validate input point P1 and parameters S2/Y2
        let param_size = match curve {
            TpmEccCurve::NistP224 => 28,
            TpmEccCurve::NistP256 | TpmEccCurve::BNP256 => 32,
            TpmEccCurve::NistP384 => 48,
            TpmEccCurve::NistP521 => 66,
            _ => return Err(TpmRc::VALUE.to_rc()),
        };
        let mut p1_buf = [0u8; 256];
        let (p1_is_empty, xy2_opt) = self.validate_commit_inputs(
            &in_public,
            &cmd,
            curve,
            hash_alg,
            param_size,
            &mut p1_buf,
        )?;

        // 3. Execute ECC point multiplication algorithms
        let mut k_buf = [0u8; 256];
        let mut l_buf = [0u8; 256];
        let mut e_buf = [0u8; 256];
        let old_counter = self.global_state.commit_counter;
        self.execute_commit_multiplications(
            curve,
            &actual_private_key,
            &p1_buf,
            p1_is_empty,
            xy2_opt.as_ref(),
            &mut k_buf,
            &mut l_buf,
            &mut e_buf,
            param_size,
            old_counter,
            key_name.get_buffer(),
        )?;

        // Store the X coordinate of the committed point (E if P1 present or s2 absent, else L)
        self.global_state.commit_x.fill(0);
        self.global_state.commit_p1.fill(0);
        if !p1_is_empty {
            let len = (param_size * 2).min(64);
            self.global_state.commit_p1[..len].copy_from_slice(&p1_buf[..len]);
        }
        if !p1_is_empty || xy2_opt.is_none() {
            let len = param_size.min(32);
            self.global_state.commit_x[..len].copy_from_slice(&e_buf[..len]);
        } else {
            let len = param_size.min(32);
            self.global_state.commit_x[..len].copy_from_slice(&l_buf[..len]);
        }

        // Update state
        self.global_state.commit_counter = self.global_state.commit_counter.wrapping_add(1);

        let mut k_x = Tpm2bEccParameter::default();
        let mut k_y = Tpm2bEccParameter::default();
        let mut l_x = Tpm2bEccParameter::default();
        let mut l_y = Tpm2bEccParameter::default();
        if xy2_opt.is_some() {
            k_x = Tpm2bEccParameter::from_bytes(&k_buf[..param_size])
                .expect("k_buf has size param_size");
            k_y = Tpm2bEccParameter::from_bytes(&k_buf[param_size..param_size * 2])
                .expect("k_buf has size param_size");
            l_x = Tpm2bEccParameter::from_bytes(&l_buf[..param_size])
                .expect("l_buf has size param_size");
            l_y = Tpm2bEccParameter::from_bytes(&l_buf[param_size..param_size * 2])
                .expect("l_buf has size param_size");
        }

        let mut e_x = Tpm2bEccParameter::default();
        let mut e_y = Tpm2bEccParameter::default();
        if !p1_is_empty || xy2_opt.is_none() {
            e_x = Tpm2bEccParameter::from_bytes(&e_buf[..param_size])
                .expect("e_buf has size param_size");
            e_y = Tpm2bEccParameter::from_bytes(&e_buf[param_size..param_size * 2])
                .expect("e_buf has size param_size");
        }

        let rsp = responses::Commit {
            k: tpm2::Tpm2b(TpmsEccPoint { x: k_x, y: k_y }),
            l: tpm2::Tpm2b(TpmsEccPoint { x: l_x, y: l_y }),
            e: tpm2::Tpm2b(TpmsEccPoint { x: e_x, y: e_y }),
            counter: old_counter,
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Resolves the signing object and validates its attributes to ensure it is
    /// an ECC signing-only key.
    fn validate_commit_object_attributes(
        &self,
        sign_handle: Handle,
        num_sessions: usize,
    ) -> Result<
        (
            crate::owned::OwnedPublic,
            [u8; 1536],
            TpmEccCurve,
            tpm2::TpmiAlgHash,
            crate::owned::OwnedName,
        ),
        TpmRc,
    > {
        let obj = self
            .global_state
            .find_transient_object(sign_handle.0)
            .ok_or(TpmRc::HANDLE.to_rc())?;
        let in_public = obj.public;
        let actual_private_key = obj.private;
        let obj_name = obj.name;

        if num_sessions == 0 {
            return Err(TpmRc::AUTH_MISSING);
        }

        if (in_public.object_attributes.0 & TpmaObject::USER_WITH_AUTH.0) == 0 {
            return Err(TpmRc::AUTH_TYPE);
        }

        if (in_public.object_attributes.0 & TpmaObject::DECRYPT.0) != 0 {
            let pos = Position::handle(1);
            return Err(TpmRc::ATTRIBUTES.with(pos));
        }

        if (in_public.object_attributes.0 & TpmaObject::SIGN_ENCRYPT.0) == 0 {
            let pos = Position::handle(1);
            return Err(TpmRc::ATTRIBUTES.with(pos));
        }

        let (curve, hash_alg) = match &in_public.parms_and_id {
            crate::owned::OwnedPublicParmsAndId::Ecc(ecc_parms, _) => {
                let curve = ecc_parms.curve_id;
                let hash_alg = match &ecc_parms.scheme {
                    Some(tpm2::TpmtEccScheme::Ecdaa(s)) => s.hash_alg,
                    _ => in_public.name_alg.ok_or(TpmRc::HASH.to_rc())?,
                };
                (curve, hash_alg)
            }
            _ => {
                let pos = Position::handle(1);
                return Err(TpmRc::KEY.with(pos));
            }
        };

        Ok((in_public, actual_private_key, curve, hash_alg, obj_name))
    }

    /// Validates `P1`, `s2`, and `y2` parameters for the `Commit` command.
    fn validate_commit_inputs(
        &self,
        in_public: &crate::owned::OwnedPublic,
        cmd: &Commit<'_>,
        curve: TpmEccCurve,
        hash_alg: tpm2::TpmiAlgHash,
        param_size: usize,
        p1_buf: &mut [u8; 256],
    ) -> Result<(bool, Option<[u8; 256]>), TpmRc> {
        let mut digest_size = hash_alg.digest_size();
        if digest_size == 0 {
            digest_size = in_public.name_alg.ok_or(TpmRc::HASH.to_rc())?.digest_size();
            if digest_size == 0 {
                digest_size = 32;
            }
        }

        if cmd.s2.get_size() as usize > digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(2)));
        }

        let p1_struct = cmd
            .p1
            .to_struct()
            .map_err(|_| TpmRc::SIZE.with(Position::parameter(1)))?;
        let p1_x = p1_struct.x.get_buffer();
        let p1_y = p1_struct.y.get_buffer();
        let p1_is_empty = p1_x.is_empty() && p1_y.is_empty();

        if !p1_is_empty {
            if p1_x.len() > param_size || p1_y.len() > param_size {
                return Err(TpmRc::ECC_POINT.with(Position::parameter(1)));
            }
            p1_buf[param_size - p1_x.len()..param_size].copy_from_slice(p1_x);
            p1_buf[param_size * 2 - p1_y.len()..param_size * 2].copy_from_slice(p1_y);

            self.crypto()
                .validate_point(curve, &p1_buf[..param_size * 2])
                .map_err(|_| TpmRc::ECC_POINT.with(Position::parameter(1)))?;
        }

        let s2_buf = cmd.s2.get_buffer();
        let y2_buf = cmd.y2.get_buffer();

        if s2_buf.is_empty() != y2_buf.is_empty() {
            return Err(TpmRc::SIZE.with(Position::parameter(3)));
        }

        let xy2_opt = if !s2_buf.is_empty() && !y2_buf.is_empty() {
            let (digest_buf, digest_len) = self.compute_hash(hash_alg, &[s2_buf])?;
            if y2_buf.len() > param_size {
                return Err(TpmRc::SIZE.with(Position::parameter(3)));
            }
            let mut xy2 = [0u8; 256];
            if digest_len <= param_size {
                xy2[param_size - digest_len..param_size].copy_from_slice(&digest_buf[..digest_len]);
            } else {
                xy2[..param_size].copy_from_slice(&digest_buf[..param_size]);
            }
            xy2[param_size * 2 - y2_buf.len()..param_size * 2].copy_from_slice(y2_buf);

            self.crypto()
                .validate_point(curve, &xy2[..param_size * 2])
                .map_err(|_| TpmRc::ECC_POINT.with(Position::parameter(3)))?;

            Some(xy2)
        } else {
            None
        };

        Ok((p1_is_empty, xy2_opt))
    }

    /// Evaluates the ECC multiplication and generator-based multiplications to compute points K, L, and E.
    #[allow(clippy::too_many_arguments)]
    fn execute_commit_multiplications(
        &self,
        curve: TpmEccCurve,
        actual_private_key: &[u8],
        p1_buf: &[u8; 256],
        p1_is_empty: bool,
        xy2_opt: Option<&[u8; 256]>,
        k_buf: &mut [u8; 256],
        l_buf: &mut [u8; 256],
        e_buf: &mut [u8; 256],
        param_size: usize,
        commit_counter: u16,
        key_name: &[u8],
    ) -> Result<(), TpmRc> {
        let r_256 = self.compute_commit_r(commit_counter, key_name, param_size)?;
        let r = &r_256[..param_size];

        if let Some(xy2) = xy2_opt {
            self.crypto()
                .point_multiply(
                    curve,
                    &actual_private_key[..param_size],
                    &xy2[..param_size * 2],
                    &mut k_buf[..param_size * 2],
                )
                .map_err(|_| TpmRc::NO_RESULT)?;

            self.crypto()
                .point_multiply(
                    curve,
                    &r[..param_size],
                    &xy2[..param_size * 2],
                    &mut l_buf[..param_size * 2],
                )
                .map_err(|_| TpmRc::NO_RESULT)?;
        } else {
            if !p1_is_empty {
                self.crypto()
                    .point_multiply(
                        curve,
                        &actual_private_key[..param_size],
                        &p1_buf[..param_size * 2],
                        &mut k_buf[..param_size * 2],
                    )
                    .map_err(|_| TpmRc::NO_RESULT)?;
            }

            self.crypto()
                .point_multiply_generator(curve, &r[..param_size], &mut l_buf[..param_size * 2])
                .map_err(|_| TpmRc::NO_RESULT)?;
        }

        if !p1_is_empty {
            self.crypto()
                .point_multiply(
                    curve,
                    &r[..param_size],
                    &p1_buf[..param_size * 2],
                    &mut e_buf[..param_size * 2],
                )
                .map_err(|_| TpmRc::NO_RESULT)?;
        } else {
            self.crypto()
                .point_multiply_generator(curve, &r[..param_size], &mut e_buf[..param_size * 2])
                .map_err(|_| TpmRc::NO_RESULT)?;
        }
        Ok(())
    }
}
