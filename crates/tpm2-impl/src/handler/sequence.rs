use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{
    EventSequenceComplete, HMACStart, Hash, HashSequenceStart, SequenceComplete, SequenceUpdate,
    responses,
};
use tpm2::crypto::HmacStream;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Tpm2bDigest, TpmaObject, TpmiAlgHash, TpmlDigestValues, TpmtHa, TpmtKeyedHashScheme,
    TpmtTkHashcheck,
};

/// Returns `true` for the hash algorithms supported by the hash, HMAC and event sequences
/// (SHA-1, SHA-256, SHA-384 and SHA-512, matching [`crate::hash_state::StreamingHashState`]).
pub(super) fn is_sequence_hash(hash_alg: TpmiAlgHash) -> bool {
    matches!(
        hash_alg,
        TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
    )
}

/// Returns `true` if `hierarchy` is `TPM_RH_OWNER`, `TPM_RH_ENDORSEMENT`, `TPM_RH_PLATFORM` or
/// `TPM_RH_NULL`.
fn is_ticket_hierarchy(hierarchy: Handle) -> bool {
    matches!(
        hierarchy,
        Handle::RH_OWNER | Handle::RH_ENDORSEMENT | Handle::RH_PLATFORM | Handle::RH_NULL
    )
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::Hash] (`0x17D`) command.
    ///
    /// # Description
    /// This command performs a single-step hash operation on a data buffer, returning the digest
    /// and a hashcheck validation ticket.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 15.3 (TPM2_Hash).
    ///
    /// # Relationships
    /// - For multi-part hashing, see [TpmCc::HashSequenceStart](sequence.rs).
    /// - The returned validation ticket is used to prove to the TPM that a digest was computed by the TPM itself
    ///   (e.g., when signing a user-provided digest using [TpmCc::Sign](crypt_ops.rs) with a restricted key).
    pub fn hash(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<Hash>([])?;
        check(cmd.hierarchy, Tpmi::RhHierarchy, Position::parameter(3))?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if !is_sequence_hash(cmd.hash_alg) {
            return Err(TpmRc::HASH.with(Position::parameter(2)));
        }

        let hierarchy = cmd.hierarchy;
        if !is_ticket_hierarchy(hierarchy) {
            return Err(TpmRc::VALUE.with(Position::parameter(3)));
        }

        let (digest_bytes, digest_len) = self.compute_hash(cmd.hash_alg, &[cmd.data.as_slice()])?;
        let digest = digest_bytes.get(..digest_len).ok_or(TpmRc::FAILURE)?;

        let ticket_hmac;
        let validation = if hierarchy == Handle::RH_NULL
            || cmd.data.as_slice().starts_with(&[0xFF, b'T', b'C', b'G'])
        {
            TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default())
        } else {
            ticket_hmac = self.compute_hashcheck_ticket(hierarchy, cmd.hash_alg, digest)?;
            TpmtTkHashcheck::Hashcheck(
                hierarchy,
                Tpm2bDigest::new(&ticket_hmac).ok_or(TpmRc::FAILURE)?,
            )
        };

        let rsp = responses::Hash {
            out_hash: Tpm2bDigest::new(digest).ok_or(TpmRc::FAILURE)?,
            validation,
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::HashSequenceStart] (`0x186`) command.
    ///
    /// # Description
    /// This command starts a multi-step hash or event sequence, returning a sequence handle to track the state.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 17.3 (TPM2_HashSequenceStart).
    ///
    /// # Relationships
    /// - Use [TpmCc::SequenceUpdate](sequence.rs) to feed data to the sequence.
    /// - Use [TpmCc::SequenceComplete](sequence.rs) or [TpmCc::EventSequenceComplete](sequence.rs) to finish it.
    pub fn hash_sequence_start(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<HashSequenceStart>([])?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if let Some(alg) = cmd.hash_alg
            && !is_sequence_hash(alg)
        {
            return Err(TpmRc::HASH.to_rc());
        }

        let (index, handle) = self.global_state.find_empty_sequence_slot()?;

        let sequence_type = match cmd.hash_alg {
            None => crate::SequenceType::Event,
            Some(alg) => crate::SequenceType::Hash { alg },
        };

        let slot = self
            .global_state
            .active_sequences
            .get_mut(index)
            .ok_or(TpmRc::FAILURE)?;
        *slot = Some(crate::ActiveSequence::new(
            handle,
            crate::owned::OwnedAuth::from(cmd.auth),
            sequence_type,
        ));

        // PORTING: exp's `HashSequenceStartHandles` response handle area is now just the
        // [`Handle`] (`responses::HashSequenceStart::sequence_handle`).
        let sequence_handle = Handle(handle);

        let response = request.into_response();
        self.write_response_handles(
            response,
            &sequence_handle,
            &session_responses[..num_sessions],
        )?;

        Ok(())
    }

    /// Handles the [TpmCc::SequenceUpdate] (`0x15C`) command.
    ///
    /// # Description
    /// This command appends a chunk of data to an active hash, HMAC, or event sequence.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 17.4 (TPM2_SequenceUpdate).
    ///
    /// # Relationships
    /// - Updates a sequence started by [TpmCc::HashSequenceStart](sequence.rs)
    ///   or [TpmCc::MACStart](sequence.rs).
    pub fn sequence_update(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<SequenceUpdate>()?;
        let [sequence_handle] = handles;
        check(sequence_handle, Tpmi::DhObject, Position::handle(1))?;
        let sequence_handle = sequence_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<SequenceUpdate>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if self
            .global_state
            .find_active_sequence(sequence_handle)
            .is_none()
        {
            if self
                .resolve_object(sequence_handle, Position::handle(1))
                .is_ok()
            {
                return Err(TpmRc::MODE.with(Position::handle(1)));
            } else {
                return Err(TpmRc::HANDLE.with(Position::handle(1)));
            }
        }

        let data = cmd.buffer.as_slice();

        let seq_obj = self
            .global_state
            .find_active_sequence_mut(sequence_handle)
            .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;

        if seq_obj.first_bytes_len < 4 {
            let start = seq_obj.first_bytes_len;
            let take = (4 - start).min(data.len());
            if let (Some(dst), Some(src)) = (
                seq_obj.first_bytes.get_mut(start..start + take),
                data.get(..take),
            ) {
                dst.copy_from_slice(src);
                seq_obj.first_bytes_len += take;
            }
        }

        let offset = seq_obj.sequence_len;
        let new_len = offset + data.len();
        let buffer = seq_obj
            .sequence_buffer
            .get_mut(offset..new_len)
            .ok_or(TpmRc::MEMORY)?;
        buffer.copy_from_slice(data);
        seq_obj.sequence_len = new_len;
        seq_obj.update_hash_states(data);

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::SequenceComplete] (`0x13E`) command.
    ///
    /// # Description
    /// This command adds the final chunk of data to a hash or HMAC sequence and returns the calculated digest/HMAC.
    /// It also invalidates (flushes) the sequence handle.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 17.5 (TPM2_SequenceComplete).
    ///
    /// # Relationships
    /// - Completes a sequence started by [TpmCc::HashSequenceStart](sequence.rs)
    ///   or [TpmCc::MACStart](sequence.rs).
    /// - Returns a validation ticket if a hash sequence is completed, similar to [TpmCc::Hash](sequence.rs).
    pub fn sequence_complete(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<SequenceComplete>()?;
        let [sequence_handle] = handles;
        check(sequence_handle, Tpmi::DhObject, Position::handle(1))?;
        let sequence_handle = sequence_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<SequenceComplete>(handles)?;
        check(cmd.hierarchy, Tpmi::RhHierarchy, Position::parameter(2))?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let hierarchy = cmd.hierarchy;
        if !is_ticket_hierarchy(hierarchy) {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }

        let final_chunk = cmd.buffer.as_slice();

        if self
            .global_state
            .find_active_sequence(sequence_handle)
            .is_none()
        {
            if self
                .resolve_object(sequence_handle, Position::handle(1))
                .is_ok()
            {
                return Err(TpmRc::MODE.with(Position::handle(1)));
            } else {
                return Err(TpmRc::HANDLE.with(Position::handle(1)));
            }
        }

        let ticket_hmac;
        let (digest_bytes, digest_len, validation) = {
            let seq_obj = self
                .global_state
                .find_active_sequence(sequence_handle)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;

            let mut state = seq_obj.hash_states[0];
            state.update(final_chunk);

            match &seq_obj.sequence_type {
                crate::SequenceType::Event
                | crate::SequenceType::Sign { .. }
                | crate::SequenceType::Verify { .. } => return Err(TpmRc::MODE.to_rc()),
                crate::SequenceType::Hash { alg } => {
                    let (digest_bytes, digest_len) = state.finalize();

                    // The first 4 bytes of the whole sequence: the (up to 4) bytes recorded
                    // by `SequenceUpdate`, followed by the final chunk.
                    let first_len = seq_obj.first_bytes_len.min(4);
                    let sequence_bytes = seq_obj
                        .first_bytes
                        .iter()
                        .take(first_len)
                        .chain(final_chunk);
                    let mut first4 = [0u8; 4];
                    let mut first4_len = 0;
                    for (dst, src) in first4.iter_mut().zip(sequence_bytes) {
                        *dst = *src;
                        first4_len += 1;
                    }
                    let is_tpm_generated = first4_len == 4 && first4 == [0xFF, b'T', b'C', b'G'];

                    let validation = if hierarchy == Handle::RH_NULL || is_tpm_generated {
                        TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default())
                    } else {
                        ticket_hmac = self.compute_hashcheck_ticket(
                            hierarchy,
                            *alg,
                            digest_bytes.get(..digest_len).ok_or(TpmRc::FAILURE)?,
                        )?;
                        TpmtTkHashcheck::Hashcheck(
                            hierarchy,
                            Tpm2bDigest::new(&ticket_hmac).ok_or(TpmRc::FAILURE)?,
                        )
                    };
                    (digest_bytes, digest_len, validation)
                }
                crate::SequenceType::Hmac { hash_alg, key } => {
                    let (digest_bytes, digest_len) =
                        crate::hash_state::finalize_hmac_from_inner_state(
                            *hash_alg,
                            key.get_buffer(),
                            &state,
                        );
                    let validation =
                        TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default());
                    (digest_bytes, digest_len, validation)
                }
            }
        };

        let rsp = responses::SequenceComplete {
            result: digest_bytes
                .get(..digest_len)
                .and_then(Tpm2bDigest::new)
                .ok_or(TpmRc::FAILURE)?,
            validation,
        };

        self.global_state.remove_active_sequence(sequence_handle)?;

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Handles the [TpmCc::MACStart] (`0x15B`) command (sometimes referred to as `TPM2_MAC_Start`).
    ///
    /// # Description
    /// This command starts a multi-step HMAC sequence using a loaded symmetric signing key.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 17.2 (TPM2_HMAC_Start).
    ///
    /// # Relationships
    /// - The key referenced by `handle` must be an unrestricted symmetric signing key.
    /// - Use [TpmCc::SequenceUpdate](sequence.rs) to feed data to the HMAC.
    /// - Use [TpmCc::SequenceComplete](sequence.rs) to finish it and retrieve the HMAC.
    pub fn mac_start(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<HMACStart>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<HMACStart>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let key_obj = self.resolve_object(key_handle.0, Position::handle(1))?;

        let scheme = match &key_obj.public.parms_and_id {
            crate::owned::OwnedPublicParmsAndId::KeyedHash(scheme, _) => scheme,
            _ => return Err(TpmRc::TYPE.with(Position::handle(1))),
        };

        if !key_obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        if key_obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        if key_obj.sensitive.as_bytes().is_empty() {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        // PORTING: exp compared `Alg`s with `TPM_ALG_NULL` standing for an absent hash; the
        // command's `hashAlg` is now an `Option<TpmiAlgHash>`.
        let cmd_hash_alg = cmd.hash_alg;

        let key_hash_alg = match scheme {
            Some(TpmtKeyedHashScheme::Hmac(hash_alg)) => {
                if cmd_hash_alg.is_some_and(|cmd_hash_alg| cmd_hash_alg != *hash_alg) {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                *hash_alg
            }
            Some(TpmtKeyedHashScheme::Xor(..)) => {
                return Err(TpmRc::TYPE.with(Position::handle(1)));
            }
            None => cmd_hash_alg.ok_or(TpmRc::VALUE.with(Position::parameter(2)))?,
        };

        if !is_sequence_hash(key_hash_alg) {
            return Err(TpmRc::HASH.with(Position::parameter(2)));
        }

        let (index, handle) = self.global_state.find_empty_sequence_slot()?;

        let key_data = crate::owned::OwnedSensitiveData::new(key_obj.sensitive.as_bytes())
            .ok_or(TpmRc::FAILURE)?;

        let slot = self
            .global_state
            .active_sequences
            .get_mut(index)
            .ok_or(TpmRc::FAILURE)?;
        *slot = Some(crate::ActiveSequence::new(
            handle,
            crate::owned::OwnedAuth::from(cmd.auth),
            crate::SequenceType::Hmac {
                hash_alg: key_hash_alg,
                key: key_data,
            },
        ));

        // PORTING: exp's `HmacStartRespHandles` response handle area is now just the
        // [`Handle`] (`responses::HMACStart::sequence_handle`).
        let sequence_handle = Handle(handle);

        let response = request.into_response();
        self.write_response_handles(
            response,
            &sequence_handle,
            &session_responses[..num_sessions],
        )?;

        Ok(())
    }

    /// Handles the [TpmCc::EventSequenceComplete] (`0x185`) command.
    ///
    /// # Description
    /// This command adds the final chunk of data to an event sequence, calculates the digest values,
    /// and extends them into a specified PCR.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 17.6 (TPM2_EventSequenceComplete).
    ///
    /// # Relationships
    /// - Completes an event sequence started by [TpmCc::HashSequenceStart](sequence.rs) with a null hash algorithm.
    /// - Extends the target PCR, similar to [TpmCc::PCRExtend](pcr.rs) or [TpmCc::PCREvent](pcr.rs).
    pub fn event_sequence_complete(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<EventSequenceComplete>()?;
        let [pcr_handle_h, sequence_handle_h] = handles;
        check(pcr_handle_h, Tpmi::DhPcrOrNull, Position::handle(1))?;
        check(sequence_handle_h, Tpmi::DhObject, Position::handle(2))?;
        let pcr_handle = pcr_handle_h.0;
        let sequence_handle = sequence_handle_h.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<EventSequenceComplete>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let pcr_index = if pcr_handle != Handle::RH_NULL.0 {
            // The TPM 2.0 specification defines 24 PCRs for PC Client profiles
            // (TPM 2.0 Library Specification Part 4: Support Structures, Section 8.1).
            let Ok(idx) = usize::try_from(pcr_handle) else {
                return Err(TpmRc::VALUE.to_rc());
            };
            if idx >= 24 {
                return Err(TpmRc::VALUE.to_rc());
            }
            let locality = self.global_state.locality;
            if locality > 4 {
                return Err(TpmRc::LOCALITY);
            }
            let extend_mask = crate::handler::pcr::PCR_EXTEND_LOCALITY[idx];
            if (extend_mask & (1 << locality)) == 0 {
                return Err(TpmRc::LOCALITY);
            }
            if idx < 16 {
                self.nv_clear_orderly()?;
            }
            Some(idx)
        } else {
            None
        };

        let (sha1_d, sha256_d, sha384_d) = {
            let seq_obj = match self.global_state.find_active_sequence(sequence_handle) {
                Some(seq) => seq,
                None => {
                    if self
                        .resolve_object(sequence_handle, Position::handle(1))
                        .is_ok()
                    {
                        return Err(TpmRc::MODE.with(Position::handle(1)));
                    }
                    return Err(TpmRc::HANDLE.with(Position::handle(1)));
                }
            };

            if seq_obj.sequence_type != crate::SequenceType::Event {
                return Err(TpmRc::MODE.to_rc());
            }

            let final_chunk = cmd.buffer.as_slice();

            let mut sha1_state = seq_obj.hash_states[0];
            let mut sha256_state = seq_obj.hash_states[1];
            let mut sha384_state = seq_obj.hash_states[2];
            sha1_state.update(final_chunk);
            sha256_state.update(final_chunk);
            sha384_state.update(final_chunk);

            let (sha1_d, _) = sha1_state.finalize();
            let (sha256_d, _) = sha256_state.finalize();
            let (sha384_d, _) = sha384_state.finalize();

            (sha1_d, sha256_d, sha384_d)
        };

        let mut d_sha1 = [0u8; 20];
        d_sha1.copy_from_slice(&sha1_d[..20]);

        let mut d_sha256 = [0u8; 32];
        d_sha256.copy_from_slice(&sha256_d[..32]);

        let mut d_sha384 = [0u8; 48];
        d_sha384.copy_from_slice(&sha384_d[..48]);

        let results = TpmlDigestValues::new(&[
            TpmtHa::Sha1(&d_sha1),
            TpmtHa::Sha256(&d_sha256),
            TpmtHa::Sha384(&d_sha384),
        ])
        .ok_or(TpmRc::FAILURE)?;

        if let Some(pcr_index) = pcr_index {
            let old_sha1 = &self.global_state.pcrs.sha1[pcr_index];
            let (new_sha1, _) = self.compute_hash(TpmiAlgHash::Sha1, &[old_sha1, &d_sha1])?;
            self.global_state.pcrs.sha1[pcr_index].copy_from_slice(&new_sha1[..20]);

            let old_sha256 = &self.global_state.pcrs.sha256[pcr_index];
            let (new_sha256, _) =
                self.compute_hash(TpmiAlgHash::Sha256, &[old_sha256, &d_sha256])?;
            self.global_state.pcrs.sha256[pcr_index].copy_from_slice(&new_sha256[..32]);

            let old_sha384 = &self.global_state.pcrs.sha384[pcr_index];
            let (new_sha384, _) =
                self.compute_hash(TpmiAlgHash::Sha384, &[old_sha384, &d_sha384])?;
            self.global_state.pcrs.sha384[pcr_index].copy_from_slice(&new_sha384[..48]);

            self.global_state.pcrs.update_counter =
                self.global_state.pcrs.update_counter.wrapping_add(1);
        }

        self.global_state.remove_active_sequence(sequence_handle)?;

        let rsp = responses::EventSequenceComplete { results };
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Computes the HMAC of the concatenation of `buffers` with `key` and `hash_alg`.
    ///
    /// Returns the digest buffer and the digest length. Fails with `TPM_RC_VALUE` if the
    /// backend cannot create the HMAC context, and `TPM_RC_FAILURE` on later backend errors.
    ///
    /// PORTING: the digest buffer is `[u8; TpmiAlgHash::MAX_DIGEST_BYTES]` (exp: `[u8; 64]`, the
    /// same size with the default `tpm2` features).
    pub(crate) fn compute_hmac(
        &self,
        hash_alg: TpmiAlgHash,
        key: &[u8],
        buffers: &[&[u8]],
    ) -> Result<([u8; TpmiAlgHash::MAX_DIGEST_BYTES], usize), TpmRc> {
        let mut state =
            HmacStream::new(self.crypto(), hash_alg, key).map_err(|_| TpmRc::VALUE.to_rc())?;
        for buf in buffers {
            state.update(buf).map_err(|_| TpmRc::FAILURE)?;
        }
        let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let len = state
            .finalize(&mut digest_buf)
            .map_err(|_| TpmRc::FAILURE)?
            .digest()
            .len();
        Ok((digest_buf, len))
    }
}
