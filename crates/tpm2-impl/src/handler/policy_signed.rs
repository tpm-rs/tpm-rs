use super::crypt_ops::{PaddedEccPoint, left_pad, load_ecc_public, load_rsa_public};
use super::session::ecc_coordinate_size;
use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::owned::OwnedPublicParmsAndId;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::{PolicySigned, responses};
use tpm2::crypto::{VerifyingKey, verify};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, Tpm2bTimeout, TpmCc, TpmHt, TpmSe,
    TpmSt, TpmiAlgHash, TpmiRsaKeyBits, TpmsSignatureEcc, TpmsSignatureRsa, TpmtKeyedHashScheme,
    TpmtSignature, TpmtTkAuth,
};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
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

        let handles = request.try_unmarshal_handles::<PolicySigned>()?;
        let [auth_object, policy_session] = handles;
        check(auth_object, Tpmi::DhObject, Position::handle(1))?;
        check(policy_session, Tpmi::ShPolicy, Position::handle(2))?;
        let auth_object = auth_object.0;
        let policy_session = policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<PolicySigned>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

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

        let nonce_tpm = cmd.nonce_tpm.as_slice();
        let cp_hash_a = cmd.cp_hash_a.as_slice();
        let policy_ref = cmd.policy_ref.as_slice();

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

            to_be_signed[offset..offset + nonce_tpm.len()].copy_from_slice(nonce_tpm);
            offset += nonce_tpm.len();

            to_be_signed[offset..offset + 4].copy_from_slice(&cmd.expiration.to_be_bytes());
            offset += 4;

            to_be_signed[offset..offset + cp_hash_a.len()].copy_from_slice(cp_hash_a);
            offset += cp_hash_a.len();

            to_be_signed[offset..offset + policy_ref.len()].copy_from_slice(policy_ref);
            offset += policy_ref.len();

            // Resolve public key or HMAC key of authObject
            let obj = self.resolve_object(auth_object, Position::handle(1))?;
            if let OwnedPublicParmsAndId::KeyedHash(scheme, _) = &obj.public.parms_and_id {
                let ha = match &cmd.auth {
                    TpmtSignature::Hmac(h) => h,
                    _ => {
                        return Err(TpmRc::SCHEME.with(Position::parameter(5)));
                    }
                };
                match scheme {
                    Some(TpmtKeyedHashScheme::Hmac(expected_hash)) => {
                        if ha.hash_alg() != *expected_hash {
                            return Err(TpmRc::SCHEME.with(Position::parameter(5)));
                        }
                    }
                    Some(_) => return Err(TpmRc::SCHEME.with(Position::handle(1))),
                    None => {}
                }
                // A public-only object has no HMAC key, so anyone could compute the HMAC
                // (reference CryptValidateSignature returns TPM_RC_HANDLE).
                if obj.sensitive.as_bytes().is_empty() {
                    return Err(TpmRc::HANDLE.with(Position::handle(1)));
                }
                let (digest_bytes, digest_len) =
                    self.compute_hash(ha.hash_alg(), &[&to_be_signed[..offset]])?;
                let (hmac_bytes, hmac_len) = self.compute_hmac(
                    ha.hash_alg(),
                    obj.sensitive.as_bytes(),
                    &[&digest_bytes[..digest_len]],
                )?;
                if !crate::util::constant_time_eq(ha.digest(), &hmac_bytes[..hmac_len]) {
                    return Err(TpmRc::SIGNATURE.with(Position::parameter(5)));
                }
            } else {
                // Size of the (left-padded) public key: the RSA modulus, or `x || y`.
                let pub_len = match &obj.public.parms_and_id {
                    OwnedPublicParmsAndId::Rsa(parms, unique) => {
                        let key_size = usize::from(parms.key_bits.as_u16() / 8);
                        if unique.get_buffer().len() > key_size
                            || key_size > TpmiRsaKeyBits::MAX_PUB_KEY_BYTES
                        {
                            return Err(TpmRc::KEY_SIZE.to_rc());
                        }
                        key_size
                    }
                    OwnedPublicParmsAndId::Ecc(parms, point) => {
                        let param_size =
                            ecc_coordinate_size(parms.curve_id).ok_or(TpmRc::KEY_SIZE.to_rc())?;
                        if point.x.get_buffer().len() > param_size
                            || point.y.get_buffer().len() > param_size
                        {
                            return Err(TpmRc::KEY_SIZE.to_rc());
                        }
                        param_size * 2
                    }
                    _ => {
                        return Err(TpmRc::KEY.with(Position::handle(1)));
                    }
                };

                // Recompute the digest being signed
                let sig_err = TpmRc::SIGNATURE.with(Position::parameter(5));
                let size_err = TpmRc::SIZE.with(Position::parameter(5));
                let mut sig_buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];

                // PORTING: exp left-padded the signature into `sig_buf` and passed the raw
                // bytes to `verify_inner`; the padded signature is now rebuilt as a
                // `TpmtSignature` for `tpm2::crypto::verify`.
                let signature = match cmd.auth {
                    TpmtSignature::Rsassa(ref sig) | TpmtSignature::Rsapss(ref sig) => {
                        left_pad(&mut sig_buf, sig.sig.as_slice(), pub_len).ok_or(size_err)?;
                        let padded = TpmsSignatureRsa {
                            hash: sig.hash,
                            sig: Tpm2bPublicKeyRsa::new(&sig_buf[..pub_len]).ok_or(sig_err)?,
                        };
                        if matches!(cmd.auth, TpmtSignature::Rsassa(_)) {
                            TpmtSignature::Rsassa(padded)
                        } else {
                            TpmtSignature::Rsapss(padded)
                        }
                    }
                    TpmtSignature::Ecdsa(ref sig) => {
                        let param_size = pub_len / 2;
                        let (r_buf, s_buf) =
                            sig_buf.split_at_mut_checked(param_size).ok_or(size_err)?;
                        left_pad(r_buf, sig.signature_r.as_slice(), param_size).ok_or(size_err)?;
                        left_pad(s_buf, sig.signature_s.as_slice(), param_size).ok_or(size_err)?;
                        TpmtSignature::Ecdsa(TpmsSignatureEcc {
                            hash: sig.hash,
                            signature_r: Tpm2bEccParameter::new(&sig_buf[..param_size])
                                .ok_or(sig_err)?,
                            signature_s: Tpm2bEccParameter::new(
                                &sig_buf[param_size..param_size * 2],
                            )
                            .ok_or(sig_err)?,
                        })
                    }
                    _ => {
                        return Err(TpmRc::SCHEME.with(Position::parameter(5)));
                    }
                };
                let tpmi_hash = match signature {
                    TpmtSignature::Rsassa(sig) | TpmtSignature::Rsapss(sig) => sig.hash,
                    TpmtSignature::Ecdsa(sig) => sig.hash,
                    _ => return Err(TpmRc::SCHEME.with(Position::parameter(5))),
                };

                let (digest_bytes, digest_len) =
                    self.compute_hash(tpmi_hash, &[&to_be_signed[..offset]])?;
                let digest = &digest_bytes[..digest_len];

                // PORTING: exp's `verify_inner` took the raw (padded) public key bytes; the key
                // is now loaded with `Rsa::load_public` / `Ecc::load_public`. Any load or
                // verification failure is `TPM_RC_SIGNATURE`, as before.
                let crypto = self.crypto();
                let verified = match &obj.public.parms_and_id {
                    OwnedPublicParmsAndId::Rsa(parms, unique) => {
                        match load_rsa_public(crypto, parms, unique.get_buffer()) {
                            Some(key) => verify(crypto, VerifyingKey::Rsa(&key), digest, signature),
                            None => Ok(false),
                        }
                    }
                    OwnedPublicParmsAndId::Ecc(parms, point) => {
                        match PaddedEccPoint::new(
                            point.x.get_buffer(),
                            point.y.get_buffer(),
                            pub_len / 2,
                        )
                        .and_then(|point| load_ecc_public(crypto, parms.curve_id, &point))
                        {
                            Some(key) => verify(crypto, VerifyingKey::Ecc(&key), digest, signature),
                            None => Ok(false),
                        }
                    }
                    _ => Ok(false),
                };
                if !matches!(verified, Ok(true)) {
                    return Err(sig_err);
                }
            }
        }

        // 2. Compute authorization object name
        let auth_name = self.context.handle_name(self.global_state, auth_object);

        // 3. Compute new policy digest
        // digest1 = hash(policyDigest_old || TPM_CC_PolicySigned || authName)
        let (digest1, digest1_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &TpmCc::PolicySigned.code().to_be_bytes(),
                auth_name.get_buffer(),
            ],
        )?;

        // new_digest = hash(digest1 || policyRef)
        let (new_digest, new_digest_len) =
            self.compute_hash(auth_hash, &[&digest1[..digest1_len], policy_ref])?;

        // Update session state in global_state
        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.to_rc())?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            if !cp_hash_a.is_empty() {
                session_state.policy_hash[..cp_hash_a.len()].copy_from_slice(cp_hash_a);
                session_state.policy_hash_len = cp_hash_a.len();
                session_state.is_cp_hash_defined = true;
            }
            if auth_timeout != 0
                && (session_state.timeout == 0 || session_state.timeout > auth_timeout)
            {
                session_state.timeout = auth_timeout;
            }
        }

        // 4. Generate policy ticket & response timeout
        let mut hmac_digest_bytes = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let timeout_bytes;
        let (timeout, policy_ticket) = if cmd.expiration < 0 && session_type == TpmSe::Policy {
            let key_hierarchy = if matches!(
                Handle(auth_object).handle_type(),
                Some(TpmHt::Transient | TpmHt::Persistent)
            ) {
                let obj = self.resolve_object(auth_object, Position::handle(1))?;
                obj.hierarchy
            } else {
                auth_object
            };

            let (proof_bytes, proof_len, ticket_hierarchy) =
                self.resolve_hierarchy_proof(key_hierarchy);

            let mut hmac_input = [0u8; 512];
            let mut offset = 0;

            // 1. tag (2 bytes, big endian 0x8025): TPM_ST_AUTH_SIGNED
            hmac_input[offset..offset + 2].copy_from_slice(&TpmSt::AUTH_SIGNED.id().to_be_bytes());
            offset += 2;

            // 2. cpHashA raw bytes
            let cp_hash_len = cp_hash_a.len();
            hmac_input[offset..offset + cp_hash_len].copy_from_slice(cp_hash_a);
            offset += cp_hash_len;

            // 3. policyRef raw bytes
            let policy_ref_len = policy_ref.len();
            hmac_input[offset..offset + policy_ref_len].copy_from_slice(policy_ref);
            offset += policy_ref_len;

            // 4. entityName raw bytes
            let entity_name = auth_name.get_buffer();
            let entity_name_len = entity_name.len();
            hmac_input[offset..offset + entity_name_len].copy_from_slice(entity_name);
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

                // If expiresOnReset (i.e. nonceTPM is empty)
                if nonce_tpm.is_empty() {
                    // resetCount (8 bytes, big endian self.global_state.total_reset_count)
                    let reset_count_val = self.global_state.total_reset_count;
                    hmac_input[offset..offset + 8].copy_from_slice(&reset_count_val.to_be_bytes());
                    offset += 8;
                }
            }

            let hmac_digest = tpm2::crypto::hmac(
                self.crypto(),
                TpmiAlgHash::Sha256,
                &proof_bytes[..proof_len],
                &hmac_input[..offset],
                &mut hmac_digest_bytes,
            )
            .map_err(|_| TpmRc::FAILURE)?;

            let ticket_digest = Tpm2bDigest::new(hmac_digest.digest()).ok_or(TpmRc::FAILURE)?;
            let ticket = TpmtTkAuth::Signed(Handle(ticket_hierarchy), ticket_digest);

            let mut timeout_val = auth_timeout;
            if nonce_tpm.is_empty() {
                timeout_val |= 1u64 << 63; // EXPIRATION_BIT
            }
            timeout_bytes = timeout_val.to_be_bytes();
            let timeout = Tpm2bTimeout::new(&timeout_bytes).ok_or(TpmRc::FAILURE)?;

            (timeout, ticket)
        } else {
            (
                Tpm2bTimeout::default(),
                TpmtTkAuth::Signed(Handle::RH_NULL, Tpm2bDigest::default()),
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
