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

        // Parameters are unmarshaled before any command-specific validation (as in C, where
        // `Commit_In_Unmarshal` runs before `TPM2_Commit`).
        let cmd = request.try_unmarshal::<Commit>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Lookup signing key and validate attributes
        let (in_public, actual_private_key, curve, hash_alg, key_name) =
            self.validate_commit_object_attributes(handles.sign_handle, num_sessions)?;

        // 2. Validate input point P1 and parameters S2/Y2
        let param_size = match curve {
            TpmEccCurve::NistP224 => 28,
            TpmEccCurve::NistP256 | TpmEccCurve::BNP256 => 32,
            TpmEccCurve::NistP384 => 48,
            TpmEccCurve::NistP521 => 66,
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
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
            let len = param_size * 2;
            self.global_state.commit_p1[..len].copy_from_slice(&p1_buf[..len]);
        }
        if !p1_is_empty || xy2_opt.is_none() {
            self.global_state.commit_x[..param_size].copy_from_slice(&e_buf[..param_size]);
        } else {
            self.global_state.commit_x[..param_size].copy_from_slice(&l_buf[..param_size]);
        }

        // The commit computation succeeded, so complete the commitment (`CryptCommit`): mark
        // the counter value as outstanding and advance the counter.
        let committed = self.crypt_commit();
        debug_assert_eq!(committed, old_counter);

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

    /// Resolves the signing object and validates it for `TPM2_Commit` (`Commit.c`).
    ///
    /// Mirrors the C reference order:
    /// 1. `signHandle` is resolved like any other object handle (transient or persistent).
    /// 2. The key must be an ECC key (`TPM_RC_KEY + RC_H1`).
    /// 3. The key's scheme must be an anonymous scheme, i.e. `TPM_ALG_ECDAA`
    ///    (`CryptIsSchemeAnonymous`, `TPM_RC_SCHEME + RC_H1`).
    ///
    /// Authorization (including `userWithAuth` / policy requirements) is enforced by the
    /// session layer, so no authorization-mode checks are repeated here.
    fn validate_commit_object_attributes(
        &mut self,
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
        let obj = self.resolve_object(sign_handle.0, Position::handle(1))?;
        let in_public = obj.public;
        let actual_private_key = obj.private;
        let obj_name = obj.name;

        if num_sessions == 0 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let (curve, hash_alg) = match &in_public.parms_and_id {
            crate::owned::OwnedPublicParmsAndId::Ecc(ecc_parms, _) => {
                let hash_alg = match &ecc_parms.scheme {
                    Some(tpm2::TpmtEccScheme::Ecdaa(s)) => s.hash_alg,
                    _ => return Err(TpmRc::SCHEME.with(Position::handle(1))),
                };
                (ecc_parms.curve_id, hash_alg)
            }
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };

        // An ECDAA scheme can only be attached to a sign-only key, so these checks are not
        // reachable for objects that passed creation/load validation; they are kept as
        // defense in depth.
        if in_public.object_attributes.contains(TpmaObject::DECRYPT)
            || !in_public
                .object_attributes
                .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

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
        // Commit phase of `CryptGenerateR`: derive `r` from the current counter value. The
        // counter is only committed (`CryptCommit`) after all multiplications succeed.
        let (r_buf, r_len) = self
            .generate_r(commit_counter, key_name, curve)
            .ok_or(TpmRc::NO_RESULT)?;
        debug_assert_eq!(r_len, param_size);
        let r = &r_buf[..param_size];

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

    /// Commits the current commit counter value (`CryptCommit`, `CryptEccMain.c`).
    ///
    /// Sets the `commit_array` bit associated with the current counter value, increments the
    /// counter, and returns the (low 16 bits of the) counter value that was committed. This
    /// value is returned to the caller of `TPM2_Commit` and later passed as
    /// `inScheme.details.ecdaa.count` to consume the commitment.
    pub(crate) fn crypt_commit(&mut self) -> u16 {
        let old_count = self.global_state.commit_counter;
        self.global_state.commit_counter = old_count.wrapping_add(1);
        let bit = usize::from(old_count & COMMIT_INDEX_MASK);
        self.global_state.commit_array[bit / 8] |= 1 << (bit % 8);
        old_count
    }

    /// Retires a commitment after it was used for a successful signature (`CryptEndCommit`).
    ///
    /// Clears the `commit_array` bit associated with `count` so that the same `r` can never be
    /// used for a second signature (reusing `r` for two different digests reveals the private
    /// key). Must only be called once the signing operation has succeeded, because the TPM
    /// state is not modified by a failing command.
    pub(crate) fn end_commit(&mut self, count: u16) {
        let bit = usize::from(count & COMMIT_INDEX_MASK);
        self.global_state.commit_array[bit / 8] &= !(1 << (bit % 8));
    }

    /// Recomputes the `r` value of an outstanding commitment for the signing phase of a split
    /// signing scheme (ECDAA), mirroring `CryptGenerateR` with a non-NULL `c`.
    ///
    /// Fails with a bare `TPM_RC_VALUE` (the code returned by `TpmEcc_SignEcdaa`) when:
    /// - the `commit_array` bit for `count` is not set (never committed or already consumed), or
    /// - `count` lies outside the window of the current commit counter (its upper bits do not
    ///   match the counter value that was current when the commitment was made).
    ///
    /// On success returns the scalar `r` (big-endian, left-aligned in a 66-byte buffer) and its
    /// length in bytes (the size of the curve order). The commitment is *not* retired; callers
    /// must invoke [`Self::end_commit`] after the signature has been produced successfully.
    pub(crate) fn generate_committed_r(
        &self,
        count: u16,
        name: &[u8],
        curve: TpmEccCurve,
    ) -> Result<([u8; MAX_ECC_ORDER_SIZE], usize), TpmRc> {
        let bit = usize::from(count & COMMIT_INDEX_MASK);
        if self.global_state.commit_array[bit / 8] & (1 << (bit % 8)) == 0 {
            return Err(TpmRc::VALUE.to_rc());
        }
        // Figure out what the counter value was when the commitment was made. If the low bits
        // of `count` are greater than or equal to the low bits of the current counter, the
        // counter has wrapped the window since then.
        let mut current = self.global_state.commit_counter;
        if (count & COMMIT_INDEX_MASK) >= (current & COMMIT_INDEX_MASK) {
            current = current.wrapping_sub(COMMIT_INDEX_MASK + 1);
        }
        if (current & !COMMIT_INDEX_MASK) != (count & !COMMIT_INDEX_MASK) {
            return Err(TpmRc::VALUE.to_rc());
        }
        self.generate_r(count, name, curve)
            .ok_or_else(|| TpmRc::VALUE.to_rc())
    }

    /// Derives the commit scalar `r` for `count` (the KDF loop of `CryptGenerateR`).
    ///
    /// `r = KDFa(CONTEXT_INTEGRITY_HASH_ALG, commitNonce, "ECDAA Commit", name, count, |n|*8)`,
    /// where the KDF iteration counter continues across attempts (as with C's `counterInOut`),
    /// and a candidate is accepted only if `r < n` and at least one byte in the upper half of
    /// `r` is non-zero. Returns `None` if the curve is unsupported or no acceptable value was
    /// found.
    pub(crate) fn generate_r(
        &self,
        count: u16,
        name: &[u8],
        curve: TpmEccCurve,
    ) -> Option<([u8; MAX_ECC_ORDER_SIZE], usize)> {
        let n = curve_order(curve)?;
        let n_len = n.len();
        let size_in_bits = (n_len as u32) * 8;
        // C marshals the full (64-bit) commit counter; the upper 48 bits are always zero here
        // because the counter is 16 bits wide.
        let cntr = u64::from(count).to_be_bytes();
        let digest_size = COMMIT_KDF_HASH.digest_size();

        let mut r = [0u8; MAX_ECC_ORDER_SIZE];
        let mut iterations: u32 = 1;
        while iterations < 1_000_000 {
            // One CryptKDFa() call producing `n_len` bytes, continuing the block counter.
            let mut generated = 0;
            while generated < n_len {
                iterations += 1;
                let mut hmac = tpm2::crypto::HmacCtx::new(
                    self.crypto(),
                    COMMIT_KDF_HASH,
                    &self.global_state.commit_nonce,
                )
                .ok()?;
                hmac.update(&iterations.to_be_bytes()).ok()?;
                hmac.update(COMMIT_STRING).ok()?;
                hmac.update(name).ok()?;
                hmac.update(&cntr).ok()?;
                hmac.update(&size_in_bits.to_be_bytes()).ok()?;
                let mut mac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
                let mac = hmac.finalize(&mut mac_buf).ok()?;
                let take = digest_size.min(n_len - generated);
                r[generated..generated + take].copy_from_slice(&mac.digest()[..take]);
                generated += take;
            }

            // The "random" value must be less than the curve order...
            if r[..n_len] >= *n {
                continue;
            }
            // ...and at least one byte in the upper half of the number must be set.
            if r[..=n_len / 2].iter().any(|&b| b != 0) {
                return Some((r, n_len));
            }
        }
        None
    }
}

/// `COMMIT_INDEX_MASK` (`Global.h`): one less than the number of bits in `commit_array`.
const COMMIT_INDEX_MASK: u16 = (16 * 8 - 1) as u16;

/// The `COMMIT_STRING` KDF label (`Global.c`), including its terminating NUL.
const COMMIT_STRING: &[u8] = b"ECDAA Commit\0";

/// The KDF hash used for commit values (`CONTEXT_INTEGRITY_HASH_ALG`, SHA-512 in the reference
/// profile).
const COMMIT_KDF_HASH: tpm2::TpmiAlgHash = tpm2::TpmiAlgHash::Sha512;

/// Size in bytes of the largest supported curve order (NIST P-521).
pub(crate) const MAX_ECC_ORDER_SIZE: usize = 66;

/// Returns the big-endian group order `n` of `curve`, or `None` for unsupported curves.
pub(crate) fn curve_order(curve: TpmEccCurve) -> Option<&'static [u8]> {
    const NIST_P224_N: [u8; 28] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x16,
        0xa2, 0xe0, 0xb8, 0xf0, 0x3e, 0x13, 0xdd, 0x29, 0x45, 0x5c, 0x5c, 0x2a, 0x3d,
    ];
    const NIST_P256_N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    const BN_P256_N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0xf0, 0xcd, 0x46, 0xe5, 0xf2, 0x5e, 0xee, 0x71, 0xa4,
        0x9e, 0x0c, 0xdc, 0x65, 0xfb, 0x12, 0x99, 0x92, 0x1a, 0xf6, 0x2d, 0x53, 0x6c, 0xd1, 0x0b,
        0x50, 0x0d,
    ];
    const NIST_P384_N: [u8; 48] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37,
        0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc,
        0xc5, 0x29, 0x73,
    ];
    const NIST_P521_N: [u8; 66] = [
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01,
        0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f,
        0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09,
    ];
    match curve {
        TpmEccCurve::NistP224 => Some(&NIST_P224_N),
        TpmEccCurve::NistP256 => Some(&NIST_P256_N),
        TpmEccCurve::BNP256 => Some(&BN_P256_N),
        TpmEccCurve::NistP384 => Some(&NIST_P384_N),
        TpmEccCurve::NistP521 => Some(&NIST_P521_N),
        _ => None,
    }
}
