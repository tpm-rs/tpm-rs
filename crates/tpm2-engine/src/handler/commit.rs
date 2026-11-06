use super::encrypt_decrypt::{crypto_check, crypto_len};
use crate::handle_checks::{Tpmi, check};
use crate::handler::MAX_PRIVATE_KEY_SIZE;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{Commit, responses};
use tpm2::crypto::{Crypto, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bEccParameter, TpmEccCurve, TpmaObject, TpmsEccPoint};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer, R: Rng + Sync>
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

        let handles = request.try_unmarshal_handles::<Commit>()?;
        let [sign_handle] = handles;
        check(sign_handle, Tpmi::DhObject, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        // Parameters are unmarshaled before any command-specific validation (as in C, where
        // `Commit_In_Unmarshal` runs before `TPM2_Commit`).
        let cmd = request.try_unmarshal_command::<Commit>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Lookup signing key and validate attributes
        let (in_public, actual_private_key, curve, hash_alg, key_name) =
            self.validate_commit_object_attributes(cmd.sign_handle, num_sessions)?;

        // 2. Validate input point P1 and parameters S2/Y2
        let param_size = match crate::ecc_curves::param_size(curve) {
            Some(size) => size,
            None => return Err(TpmRc::KEY.with(Position::handle(1))),
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
        let old_counter = self.context.state.commit_counter;
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

        // The commit computation succeeded, so complete the commitment (`CryptCommit`): mark
        // the counter value as outstanding and advance the counter.
        let committed = self.crypt_commit();
        debug_assert_eq!(committed, old_counter as u16);

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
            counter: committed,
        };

        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;

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
            [u8; MAX_PRIVATE_KEY_SIZE],
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

        let s2_buf = cmd.s2.get_buffer();
        let y2_buf = cmd.y2.get_buffer();

        // C `Commit.c`: `if((in->s2.t.size == 0) != (in->y2.t.size == 0)) return TPM_RCS_SIZE + RC_Commit_y2;`
        // precedes the `in->s2.t.size > digestSize` check.
        if s2_buf.is_empty() != y2_buf.is_empty() {
            return Err(TpmRc::SIZE.with(Position::parameter(3)));
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

            crypto_check(
                crate::ecc_curves::validate_point::<C>(curve, &p1_buf[..param_size * 2]),
                TpmRc::ECC_POINT.with(Position::parameter(1)),
            )?;
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

            crypto_check(
                crate::ecc_curves::validate_point::<C>(curve, &xy2[..param_size * 2]),
                TpmRc::ECC_POINT.with(Position::parameter(3)),
            )?;

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
        commit_counter: u64,
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
            crypto_len(
                self.crypto().point_multiply(
                    curve,
                    &actual_private_key[..param_size],
                    &xy2[..param_size * 2],
                    &mut k_buf[..param_size * 2],
                ),
                TpmRc::NO_RESULT,
            )?;

            crypto_len(
                self.crypto().point_multiply(
                    curve,
                    &r[..param_size],
                    &xy2[..param_size * 2],
                    &mut l_buf[..param_size * 2],
                ),
                TpmRc::NO_RESULT,
            )?;
        } else {
            if !p1_is_empty {
                crypto_len(
                    self.crypto().point_multiply(
                        curve,
                        &actual_private_key[..param_size],
                        &p1_buf[..param_size * 2],
                        &mut k_buf[..param_size * 2],
                    ),
                    TpmRc::NO_RESULT,
                )?;
            }

            crypto_len(
                self.crypto().point_multiply_generator(
                    curve,
                    &r[..param_size],
                    &mut l_buf[..param_size * 2],
                ),
                TpmRc::NO_RESULT,
            )?;
        }

        if !p1_is_empty {
            crypto_len(
                self.crypto().point_multiply(
                    curve,
                    &r[..param_size],
                    &p1_buf[..param_size * 2],
                    &mut e_buf[..param_size * 2],
                ),
                TpmRc::NO_RESULT,
            )?;
        } else {
            crypto_len(
                self.crypto().point_multiply_generator(
                    curve,
                    &r[..param_size],
                    &mut e_buf[..param_size * 2],
                ),
                TpmRc::NO_RESULT,
            )?;
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
        let old_count = self.context.state.commit_counter as u16;
        self.context.state.commit_counter = self.context.state.commit_counter.wrapping_add(1);
        let bit = usize::from(old_count & COMMIT_INDEX_MASK);
        self.context.state.commit_array[bit / 8] |= 1 << (bit % 8);
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
        self.context.state.commit_array[bit / 8] &= !(1 << (bit % 8));
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
        if self.context.state.commit_array[bit / 8] & (1 << (bit % 8)) == 0 {
            return Err(TpmRc::VALUE.to_rc());
        }
        // Figure out what the counter value was when the commitment was made. If the low bits
        // of `count` are greater than or equal to the low bits of the current counter, the
        // counter has wrapped the window since then.
        let mut current = self.context.state.commit_counter;
        if (count & COMMIT_INDEX_MASK) >= (current as u16 & COMMIT_INDEX_MASK) {
            current = current.wrapping_sub(u64::from(COMMIT_INDEX_MASK) + 1);
        }
        if (current as u16 & !COMMIT_INDEX_MASK) != (count & !COMMIT_INDEX_MASK) {
            return Err(TpmRc::VALUE.to_rc());
        }
        // The counter value when the commitment was made: the upper 48 bits of the current
        // counter (as adjusted above) and the 16 bits of `count`.
        let committed = (current & !0xFFFF) | u64::from(count);
        self.generate_r(committed, name, curve)
            .ok_or_else(|| TpmRc::VALUE.to_rc())
    }

    /// Computes an ECDAA signature (TPM 2.0 Part 1, "ECDAA Sign Operation"; C
    /// `TpmEcc_SignEcdaa`) over the value to sign `p` with the private key `d` and the
    /// committed `r` (from [`Self::generate_committed_r`]):
    ///
    /// 1. `k` is random with `0 < k < n` (FIPS 186-5 extra random bits, C
    ///    `TpmEcc_GenPrivateScalar`);
    /// 2. `T := H_hashAlg(k || p) mod n` (`k` in minimal big-endian form, as C hashes it);
    /// 3. `s := (r + T·d) mod n`; a zero `T mod n` or `s` restarts with a new `k`.
    ///
    /// Writes `k` (minimal length, the signature's R field) and `s` (padded to the order size)
    /// and returns their lengths.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn ecdaa_sign(
        &mut self,
        curve: TpmEccCurve,
        hash_alg: tpm2::TpmiAlgHash,
        r: &[u8],
        d: &[u8],
        p: &[u8],
        k_out: &mut [u8],
        s_out: &mut [u8],
    ) -> Result<(usize, usize), TpmRc> {
        let n = curve_order(curve).ok_or(TpmRc::VALUE.to_rc())?;
        let n_len = n.len();
        if r.len() > n_len || d.len() > n_len || k_out.len() < n_len || s_out.len() < n_len {
            return Err(TpmRc::FAILURE);
        }
        let mut r_buf = [0u8; MAX_ECC_ORDER_SIZE];
        r_buf[n_len - r.len()..n_len].copy_from_slice(r);
        let mut d_buf = [0u8; MAX_ECC_ORDER_SIZE];
        d_buf[n_len - d.len()..n_len].copy_from_slice(d);

        for _ in 0..1000 {
            let mut c = [0u8; MAX_ECC_ORDER_SIZE + 8];
            // `TpmEcc_GenPrivateScalar()` with the TPM's random source.
            self.context.random_crypto(&mut c[..n_len + 8])?;
            let mut k = [0u8; MAX_ECC_ORDER_SIZE];
            crate::modular::ecc_scalar_from_extra_bits(&c[..n_len + 8], n, &mut k[..n_len]);
            let skip = k[..n_len].iter().take_while(|&&b| b == 0).count();
            let k_min = &k[skip..n_len];

            let (t_digest, t_len) = self.compute_hash(hash_alg, &[k_min, p])?;
            let mut t = [0u8; MAX_ECC_ORDER_SIZE];
            crate::modular::reduce(&t_digest[..t_len], n, &mut t[..n_len]);
            if crate::modular::is_zero(&t[..n_len]) {
                continue;
            }
            let mut td = [0u8; MAX_ECC_ORDER_SIZE];
            crate::modular::mul_mod(&t[..n_len], &d_buf[..n_len], n, &mut td[..n_len]);
            let mut s = [0u8; MAX_ECC_ORDER_SIZE];
            crate::modular::add_mod(&td[..n_len], &r_buf[..n_len], n, &mut s[..n_len]);
            if crate::modular::is_zero(&s[..n_len]) {
                continue;
            }
            k_out[..k_min.len()].copy_from_slice(k_min);
            s_out[..n_len].copy_from_slice(&s[..n_len]);
            return Ok((k_min.len(), n_len));
        }
        Err(TpmRc::NO_RESULT)
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
        count: u64,
        name: &[u8],
        curve: TpmEccCurve,
    ) -> Option<([u8; MAX_ECC_ORDER_SIZE], usize)> {
        let n = curve_order(curve)?;
        // `CryptKDFa()` tests KDFa first (`TPM_DO_SELF_TEST(TPM_ALG_KDF1_SP800_108)`).
        self.crypto().do_self_test(tpm2::Alg::KDF1_SP800_108).ok()?;
        let n_len = n.len();
        let size_in_bits = (n_len as u32) * 8;
        // C marshals the full (64-bit) commit counter.
        let cntr = count.to_be_bytes();
        let digest_size = commit_kdf_hash().digest_size();

        let mut r = [0u8; MAX_ECC_ORDER_SIZE];
        let mut iterations: u32 = 1;
        while iterations < 1_000_000 {
            // One CryptKDFa() call producing `n_len` bytes, continuing the block counter.
            let mut generated = 0;
            while generated < n_len {
                iterations += 1;
                let mut hmac = self
                    .crypto()
                    .hmac_stream(commit_kdf_hash(), &self.context.state.commit_nonce)
                    .ok()?;
                hmac.update(&iterations.to_be_bytes()).ok()?;
                hmac.update(COMMIT_STRING).ok()?;
                hmac.update(name).ok()?;
                hmac.update(&cntr).ok()?;
                hmac.update(&size_in_bits.to_be_bytes()).ok()?;
                let mut mac_buf = [0u8; tpm2::TpmiAlgHash::MAX_DIGEST_BYTES];
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
fn commit_kdf_hash() -> tpm2::TpmiAlgHash {
    crate::handler::context_integrity_hash_alg()
}

/// Size in bytes of the largest supported curve order.
pub(crate) const MAX_ECC_ORDER_SIZE: usize = tpm2::TpmEccCurve::MAX_ECC_KEY_BYTES;

/// Returns the big-endian group order `n` of `curve`, or `None` for unsupported curves.
pub(crate) fn curve_order(curve: TpmEccCurve) -> Option<&'static [u8]> {
    crate::ecc_curves::curve_params(curve).map(|c| c.n)
}
