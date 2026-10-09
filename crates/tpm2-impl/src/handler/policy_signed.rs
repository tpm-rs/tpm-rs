use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{PolicySigned, PolicySignedHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bDigest, Tpm2bTimeout, TpmSe, TpmtSignature, TpmtTkAuth};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicySigned] (`0x160`) command.
    ///
    /// # Description
    /// This command makes the policy session conditional on an asymmetric signature verified using the public key
    /// of an authority object (`auth_object`). It extends the policy digest and optionally returns an authorization ticket.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.3 (TPM2_PolicySigned).
    ///
    /// # Relationships
    /// - Performs asymmetric cryptographic verification using the public key of a loaded object (`auth_object`).
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    /// - Generates a verification ticket (`policy_ticket`) that can be used later to satisfy authorization requirements.
    pub fn policy_signed(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<PolicySignedHandles>()?;
        let auth_object = handles.auth_object.0;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<PolicySigned>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // `authObject` (handle 1, `TPMI_DH_OBJECT`) must reference a loaded object for every
        // session type (C validates it with `EntityGetLoadStatus` before the command runs).
        let obj = self.resolve_object(auth_object, Position::handle(1))?;

        // Validate session expiration
        self.validate_policy_session(policy_session, Position::handle(2))?;

        // 1. Retrieve policy session details

        let (auth_hash, policy_digest, policy_digest_len, session_type) = {
            let session_state = self
                .global_state
                .session(policy_session)
                .ok_or(TpmRc::REFERENCE_H1)?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::HANDLE.with(Position::handle(2)));
            }
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
                session_state.session_type,
            )
        };

        let mut auth_timeout = 0u64;
        if session_type == TpmSe::Policy {
            let session_state = self
                .global_state
                .session(policy_session)
                .ok_or(TpmRc::REFERENCE_H1)?;
            auth_timeout = self.compute_auth_timeout(session_state, cmd.expiration, &cmd.nonce_tpm);
            self.policy_parameter_checks(
                session_state,
                auth_timeout,
                &cmd.cp_hash_a,
                &cmd.nonce_tpm,
                (
                    Position::parameter(1),
                    Position::parameter(2),
                    Position::parameter(4),
                ),
            )?;

            // toBeSigned ≔ nonceTPM ∥ expiration ∥ cpHashA ∥ policyRef
            let mut to_be_signed = [0u8; 1024];
            let mut offset = 0;

            to_be_signed[offset..offset + cmd.nonce_tpm.get_size() as usize]
                .copy_from_slice(cmd.nonce_tpm.get_buffer());
            offset += cmd.nonce_tpm.get_size() as usize;

            to_be_signed[offset..offset + 4].copy_from_slice(&cmd.expiration.to_be_bytes());
            offset += 4;

            to_be_signed[offset..offset + cmd.cp_hash_a.get_size() as usize]
                .copy_from_slice(cmd.cp_hash_a.get_buffer());
            offset += cmd.cp_hash_a.get_size() as usize;

            to_be_signed[offset..offset + cmd.policy_ref.get_size() as usize]
                .copy_from_slice(cmd.policy_ref.get_buffer());
            offset += cmd.policy_ref.get_size() as usize;

            // Validate the signature with the public key or HMAC key of authObject
            // (C `CryptValidateSignature`; errors get `RC_PolicySigned_auth`).
            if let crate::owned::OwnedPublicParmsAndId::KeyedHash(scheme, _) =
                &obj.public.parms_and_id
            {
                // An HMAC key whose sensitive area is not loaded cannot verify anything.
                if obj.public_only {
                    return Err(TpmRc::HANDLE.with(Position::parameter(5)));
                }
                // C `CryptHMACVerifySignature`.
                let ha = match &cmd.auth {
                    TpmtSignature::Hmac(h) => h,
                    _ => {
                        return Err(TpmRc::SCHEME.with(Position::parameter(5)));
                    }
                };
                // A key with a non-NULL scheme only validates signatures of that exact scheme.
                match scheme {
                    None => {}
                    Some(tpm2::TpmtKeyedHashScheme::Hmac(expected_hash))
                        if ha.hash_alg() == *expected_hash => {}
                    Some(_) => return Err(TpmRc::SIGNATURE.with(Position::parameter(5))),
                }
                let (digest_bytes, digest_len) =
                    self.compute_hash(ha.hash_alg(), &[&to_be_signed[..offset]])?;
                let (hmac_bytes, hmac_len) = self.compute_hmac(
                    ha.hash_alg(),
                    &obj.private[..obj.private_len],
                    &[&digest_bytes[..digest_len]],
                )?;
                if ha.digest() != &hmac_bytes[..hmac_len] {
                    return Err(TpmRc::SIGNATURE.with(Position::parameter(5)));
                }
            } else {
                let mut pub_buf = [0u8; 512];
                let pub_len;

                match obj.public.parms_and_id {
                    crate::owned::OwnedPublicParmsAndId::Rsa(parms, ref unique) => {
                        let key_size = (parms.key_bits.0 / 8) as usize;
                        let u_buf = unique.get_buffer();
                        if u_buf.len() > key_size || key_size > pub_buf.len() {
                            return Err(TpmRc::KEY_SIZE.to_rc());
                        }
                        let offset = key_size - u_buf.len();
                        pub_buf[offset..key_size].copy_from_slice(u_buf);
                        pub_len = key_size;
                    }
                    crate::owned::OwnedPublicParmsAndId::Ecc(parms, ref point) => {
                        let curve = parms.curve_id;
                        let param_size = match curve {
                            tpm2::TpmEccCurve::NistP192 => 24,
                            tpm2::TpmEccCurve::NistP224 => 28,
                            tpm2::TpmEccCurve::NistP256 | tpm2::TpmEccCurve::BNP256 => 32,
                            tpm2::TpmEccCurve::NistP384 => 48,
                            tpm2::TpmEccCurve::NistP521 => 66,
                            _ => return Err(TpmRc::KEY_SIZE.to_rc()),
                        };
                        pub_len = param_size * 2;
                        if pub_len > pub_buf.len() {
                            return Err(TpmRc::KEY_SIZE.to_rc());
                        }
                        let x_buf = point.x.get_buffer();
                        let y_buf = point.y.get_buffer();
                        if x_buf.len() > param_size || y_buf.len() > param_size {
                            return Err(TpmRc::KEY_SIZE.to_rc());
                        }
                        pub_buf[param_size - x_buf.len()..param_size].copy_from_slice(x_buf);
                        pub_buf[param_size * 2 - y_buf.len()..pub_len].copy_from_slice(y_buf);
                    }
                    _ => {
                        return Err(TpmRc::KEY.with(Position::handle(1)));
                    }
                }

                // Recompute the digest being signed
                let mut sig_buf = [0u8; 512];
                let sig_len;

                // The signature algorithm must belong to the key type
                // (C `CryptRsaValidateSignature` / `CryptEccValidateSignature`).
                let is_rsa_key = matches!(
                    obj.public.parms_and_id,
                    crate::owned::OwnedPublicParmsAndId::Rsa(..)
                );
                let sig_matches_key = match cmd.auth {
                    TpmtSignature::Rsassa(_) | TpmtSignature::Rsapss(_) => is_rsa_key,
                    TpmtSignature::Ecdsa(_)
                    | TpmtSignature::Ecschnorr(_)
                    | TpmtSignature::Sm2(_) => !is_rsa_key,
                    _ => false,
                };
                if !sig_matches_key {
                    return Err(TpmRc::SCHEME.with(Position::parameter(5)));
                }

                let (sign_alg, hash_alg) = match cmd.auth {
                    TpmtSignature::Rsassa(ref sig) => {
                        let bytes = sig.sig.get_buffer();
                        if bytes.len() > pub_len || pub_len > sig_buf.len() {
                            return Err(TpmRc::SIZE.with(Position::parameter(5)));
                        }
                        sig_len = pub_len;
                        let offset = pub_len - bytes.len();
                        sig_buf[offset..pub_len].copy_from_slice(bytes);
                        (tpm2::Alg::RSASSA, tpm2::Alg::from(sig.hash))
                    }
                    TpmtSignature::Rsapss(ref sig) => {
                        let bytes = sig.sig.get_buffer();
                        if bytes.len() > pub_len || pub_len > sig_buf.len() {
                            return Err(TpmRc::SIZE.with(Position::parameter(5)));
                        }
                        sig_len = pub_len;
                        let offset = pub_len - bytes.len();
                        sig_buf[offset..pub_len].copy_from_slice(bytes);
                        (tpm2::Alg::RSAPSS, tpm2::Alg::from(sig.hash))
                    }
                    TpmtSignature::Ecdsa(ref sig) => {
                        let param_size = pub_len / 2;
                        let r_bytes = sig.signature_r.get_buffer();
                        let s_bytes = sig.signature_s.get_buffer();
                        if r_bytes.len() > param_size
                            || s_bytes.len() > param_size
                            || pub_len > sig_buf.len()
                        {
                            return Err(TpmRc::SIZE.with(Position::parameter(5)));
                        }
                        sig_len = pub_len;
                        sig_buf[param_size - r_bytes.len()..param_size].copy_from_slice(r_bytes);
                        sig_buf[param_size * 2 - s_bytes.len()..param_size * 2]
                            .copy_from_slice(s_bytes);
                        (tpm2::Alg::ECDSA, tpm2::Alg::from(sig.hash))
                    }
                    _ => {
                        return Err(TpmRc::SCHEME.with(Position::parameter(5)));
                    }
                };

                let tpmi_hash = tpm2::TpmiAlgHash::try_from(hash_alg)
                    .map_err(|_| TpmRc::HASH.with(Position::parameter(5)))?;
                let (digest_bytes, digest_len) =
                    self.compute_hash(tpmi_hash, &[&to_be_signed[..offset]])?;
                let digest_ha = tpm2::TpmtHa::new(tpmi_hash, &digest_bytes[..digest_len])
                    .ok_or_else(|| TpmRc::SIGNATURE.with(Position::parameter(5)))?;

                self.crypto()
                    .verify_inner(
                        sign_alg,
                        &pub_buf[..pub_len],
                        digest_ha,
                        &sig_buf[..sig_len],
                    )
                    .map_err(|_| TpmRc::SIGNATURE.with(Position::parameter(5)))?;
            }
        }

        // 2. Authorization object name (of the loaded object, for trial sessions too)
        let auth_name = obj.name;

        // 3. Compute new policy digest
        // digest1 = hash(policyDigest_old || TPM_CC_PolicySigned || authName)
        let (digest1, digest1_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &0x00000160u32.to_be_bytes(), // TPM_CC_PolicySigned
                auth_name.get_buffer(),
            ],
        )?;

        // new_digest = hash(digest1 || policyRef)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[&digest1[..digest1_len], cmd.policy_ref.get_buffer()],
        )?;

        // Update session state in global_state
        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.to_rc())?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            if !cmd.cp_hash_a.get_buffer().is_empty() {
                session_state.policy_hash[..cmd.cp_hash_a.get_size() as usize]
                    .copy_from_slice(cmd.cp_hash_a.get_buffer());
                session_state.policy_hash_len = cmd.cp_hash_a.get_size() as usize;
                session_state.is_cp_hash_defined = true;
            }
            if auth_timeout != 0
                && (session_state.timeout == 0 || session_state.timeout > auth_timeout)
            {
                session_state.timeout = auth_timeout;
            }
        }

        // 4. Generate policy ticket & response timeout
        let mut hmac_digest_bytes = [0u8; 64];
        let timeout_bytes;
        let (timeout, policy_ticket) = if cmd.expiration < 0 && session_type == TpmSe::Policy {
            let key_hierarchy = obj.hierarchy;

            let (proof_bytes, proof_len, ticket_hierarchy) =
                self.resolve_hierarchy_proof(key_hierarchy);

            let mut hmac_input = [0u8; 512];
            let mut offset = 0;

            // 1. tag (2 bytes, big endian 0x8025): 0x8025u16.to_be_bytes()
            hmac_input[offset..offset + 2].copy_from_slice(&0x8025u16.to_be_bytes());
            offset += 2;

            // 2. cpHashA raw bytes
            let cp_hash_len = cmd.cp_hash_a.get_size() as usize;
            hmac_input[offset..offset + cp_hash_len].copy_from_slice(cmd.cp_hash_a.get_buffer());
            offset += cp_hash_len;

            // 3. policyRef raw bytes
            let policy_ref_len = cmd.policy_ref.get_size() as usize;
            hmac_input[offset..offset + policy_ref_len]
                .copy_from_slice(cmd.policy_ref.get_buffer());
            offset += policy_ref_len;

            // 4. entityName raw bytes
            let entity_name_len = auth_name.get_size() as usize;
            hmac_input[offset..offset + entity_name_len].copy_from_slice(auth_name.get_buffer());
            offset += entity_name_len;

            // 5. timeout (8 bytes, big endian auth_timeout_masked)
            let auth_timeout_masked = auth_timeout & !(1u64 << 63);
            hmac_input[offset..offset + 8].copy_from_slice(&auth_timeout_masked.to_be_bytes());
            offset += 8;

            // 6. If auth_timeout != 0
            if auth_timeout != 0 {
                // epoch (8 bytes, big endian self.global_state.time_epoch)
                let epoch_val = self.global_state.time_epoch;
                hmac_input[offset..offset + 8].copy_from_slice(&epoch_val.to_be_bytes());
                offset += 8;

                // If expiresOnReset (i.e. cmd.nonce_tpm.get_buffer().is_empty())
                if cmd.nonce_tpm.get_buffer().is_empty() {
                    // resetCount (8 bytes, big endian self.global_state.total_reset_count)
                    let reset_count_val = self.global_state.total_reset_count;
                    hmac_input[offset..offset + 8].copy_from_slice(&reset_count_val.to_be_bytes());
                    offset += 8;
                }
            }

            let hmac_digest = tpm2::crypto::hmac(
                self.crypto(),
                tpm2::TpmiAlgHash::Sha256,
                &proof_bytes[..proof_len],
                &hmac_input[..offset],
                &mut hmac_digest_bytes,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            let hmac_len = hmac_digest.digest().len();

            let ticket_digest = Tpm2bDigest::from_bytes(&hmac_digest_bytes[..hmac_len]).unwrap();
            let ticket = TpmtTkAuth::Signed(tpm2::Handle(ticket_hierarchy), ticket_digest);

            let mut timeout_val = auth_timeout;
            if cmd.nonce_tpm.get_buffer().is_empty() {
                timeout_val |= 1u64 << 63; // EXPIRATION_BIT
            }
            timeout_bytes = timeout_val.to_be_bytes();
            let timeout = Tpm2bTimeout::from_bytes(&timeout_bytes).unwrap();

            (timeout, ticket)
        } else {
            (
                Tpm2bTimeout::default(),
                TpmtTkAuth::Signed(tpm2::Handle(0x40000007), Tpm2bDigest::default()),
            )
        };

        let rsp = responses::PolicySigned {
            timeout,
            policy_ticket,
        };

        // 5. Write response
        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
