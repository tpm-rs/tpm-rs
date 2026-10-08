use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{
    EventSequenceComplete, EventSequenceCompleteHandles, Hash, HashSequenceStart,
    HashSequenceStartHandles, HmacStart, HmacStartHandles, HmacStartRespHandles, SequenceComplete,
    SequenceCompleteHandles, SequenceUpdate, SequenceUpdateHandles,
};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, Tpm2bDigest, TpmaObject, TpmiAlgHash, TpmlDigestValues, TpmtHa, TpmtKeyedHashScheme,
};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
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
        let cmd = request.try_unmarshal::<Hash>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if cmd.hash_alg != TpmiAlgHash::Sha1
            && cmd.hash_alg != TpmiAlgHash::Sha256
            && cmd.hash_alg != TpmiAlgHash::Sha384
            && cmd.hash_alg != TpmiAlgHash::Sha512
        {
            return Err(TpmRc::HASH.with(Position::parameter(2)));
        }

        let hierarchy = cmd.hierarchy;
        if hierarchy.0 != Handle::RH_OWNER.0
            && hierarchy.0 != Handle::RH_ENDORSEMENT.0
            && hierarchy.0 != Handle::RH_PLATFORM.0
            && hierarchy.0 != Handle::RH_NULL.0
        {
            return Err(TpmRc::VALUE.with(Position::parameter(3)));
        }

        let (digest_bytes, digest_len) =
            self.compute_hash(cmd.hash_alg, &[cmd.data.get_buffer()])?;

        let ticket_hmac;
        let validation = if hierarchy.0 == Handle::RH_NULL.0
            || cmd.data.get_buffer().starts_with(&[0xFF, b'T', b'C', b'G'])
        {
            tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default())
        } else {
            ticket_hmac = self.compute_hashcheck_ticket(
                hierarchy,
                cmd.hash_alg,
                &digest_bytes[..digest_len],
            )?;
            tpm2::TpmtTkHashcheck::Hashcheck(
                hierarchy,
                Tpm2bDigest::from_bytes(&ticket_hmac).unwrap(),
            )
        };

        let rsp = responses::Hash {
            out_hash: Tpm2bDigest::from_bytes(&digest_bytes[..digest_len]).unwrap(),
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
        let cmd = request.try_unmarshal::<HashSequenceStart>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if let Some(alg) = cmd.hash_alg
            && alg != TpmiAlgHash::Sha1
            && alg != TpmiAlgHash::Sha256
            && alg != TpmiAlgHash::Sha384
            && alg != TpmiAlgHash::Sha512
        {
            return Err(TpmRc::HASH.to_rc());
        }

        let (index, handle) = self.global_state.find_empty_sequence_slot()?;

        let sequence_type = match cmd.hash_alg {
            None => crate::SequenceType::Event,
            Some(alg) => crate::SequenceType::Hash { alg },
        };

        self.global_state.active_sequences[index] = Some(crate::ActiveSequence::new(
            handle,
            crate::owned::OwnedAuth::from(cmd.auth),
            sequence_type,
        ));

        let resp_handles = HashSequenceStartHandles {
            sequence_handle: Handle(handle),
        };

        let response = request.into_response();
        self.write_response_handles(response, &resp_handles, &session_responses[..num_sessions])?;

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
        let handles = request.try_unmarshal::<SequenceUpdateHandles>()?;
        let sequence_handle = handles.sequence_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<SequenceUpdate>()?;
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

        let data = cmd.buffer.get_buffer();

        let seq_obj = self
            .global_state
            .find_active_sequence_mut(sequence_handle)
            .unwrap();

        if seq_obj.first_bytes_len < 4 {
            let needed = 4 - seq_obj.first_bytes_len;
            let take = needed.min(data.len());
            seq_obj.first_bytes[seq_obj.first_bytes_len..seq_obj.first_bytes_len + take]
                .copy_from_slice(&data[..take]);
            seq_obj.first_bytes_len += take;
        }

        let new_len = seq_obj.sequence_len + data.len();
        if new_len > seq_obj.sequence_buffer.len() {
            return Err(TpmRc::MEMORY);
        }

        let offset = seq_obj.sequence_len;
        seq_obj.sequence_buffer[offset..new_len].copy_from_slice(data);
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
        let handles = request.try_unmarshal::<SequenceCompleteHandles>()?;
        let sequence_handle = handles.sequence_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<SequenceComplete>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let hierarchy = cmd.hierarchy;
        if hierarchy.0 != Handle::RH_OWNER.0
            && hierarchy.0 != Handle::RH_ENDORSEMENT.0
            && hierarchy.0 != Handle::RH_PLATFORM.0
            && hierarchy.0 != Handle::RH_NULL.0
        {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }

        let final_chunk = cmd.buffer.get_buffer();

        let ticket_hmac;
        let (digest_bytes, digest_len, validation) = {
            let seq_obj = match self.global_state.find_active_sequence(sequence_handle) {
                Some(seq) => seq,
                None => {
                    if self
                        .resolve_object(sequence_handle, Position::handle(1))
                        .is_ok()
                    {
                        return Err(TpmRc::MODE.with(Position::handle(1)));
                    } else {
                        return Err(TpmRc::HANDLE.with(Position::handle(1)));
                    }
                }
            };

            let mut state = seq_obj.hash_states[0];
            state.update(final_chunk);

            match &seq_obj.sequence_type {
                crate::SequenceType::Event => return Err(TpmRc::MODE.to_rc()),
                crate::SequenceType::Hash { alg } => {
                    let (digest_bytes, digest_len) = state.finalize();

                    let is_tpm_generated = if seq_obj.first_bytes_len >= 4 {
                        seq_obj.first_bytes == [0xFF, b'T', b'C', b'G']
                    } else if seq_obj.first_bytes_len + final_chunk.len() >= 4 {
                        let mut first4 = [0u8; 4];
                        first4[..seq_obj.first_bytes_len]
                            .copy_from_slice(&seq_obj.first_bytes[..seq_obj.first_bytes_len]);
                        first4[seq_obj.first_bytes_len..]
                            .copy_from_slice(&final_chunk[..4 - seq_obj.first_bytes_len]);
                        first4 == [0xFF, b'T', b'C', b'G']
                    } else {
                        false
                    };

                    let validation = if hierarchy.0 == Handle::RH_NULL.0 || is_tpm_generated {
                        tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default())
                    } else {
                        ticket_hmac = self.compute_hashcheck_ticket(
                            hierarchy,
                            *alg,
                            &digest_bytes[..digest_len],
                        )?;
                        tpm2::TpmtTkHashcheck::Hashcheck(
                            hierarchy,
                            Tpm2bDigest::from_bytes(&ticket_hmac).unwrap(),
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
                        tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default());
                    (digest_bytes, digest_len, validation)
                }
            }
        };

        let rsp = responses::SequenceComplete {
            result: Tpm2bDigest::from_bytes(&digest_bytes[..digest_len]).unwrap(),
            validation,
        };

        self.global_state.remove_active_sequence(sequence_handle)?;

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

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
        let handles = request.try_unmarshal::<EventSequenceCompleteHandles>()?;
        let pcr_handle = handles.pcr_handle.0;
        let sequence_handle = handles.sequence_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<EventSequenceComplete>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if pcr_handle != Handle::RH_NULL.0 {
            // The TPM 2.0 specification defines 24 PCRs for PC Client profiles
            // (TPM 2.0 Library Specification Part 4: Support Structures, Section 8.1).
            if pcr_handle >= 24 {
                return Err(TpmRc::VALUE.to_rc());
            }
            let locality = self.global_state.locality;
            if locality > 4 {
                return Err(TpmRc::LOCALITY);
            }
            let extend_mask = crate::handler::pcr::PCR_EXTEND_LOCALITY[pcr_handle as usize];
            if (extend_mask & (1 << locality)) == 0 {
                return Err(TpmRc::LOCALITY);
            }
            if pcr_handle < 16 {
                self.nv_clear_orderly()?;
            }
        }

        let (sha1_d, sha256_d, sha384_d) = {
            let seq_obj = match self.global_state.find_active_sequence(sequence_handle) {
                Some(seq) => seq,
                None => {
                    if self
                        .resolve_object(sequence_handle, Position::handle(1))
                        .is_ok()
                    {
                        return Err(TpmRc::MODE.with(Position::handle(1)));
                    } else {
                        return Err(TpmRc::HANDLE.with(Position::handle(1)));
                    }
                }
            };

            if seq_obj.sequence_type != crate::SequenceType::Event {
                return Err(TpmRc::MODE.to_rc());
            }

            let final_chunk = cmd.buffer.get_buffer();

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

        let mut results = TpmlDigestValues::default();
        let mut d_sha1 = [0u8; 20];
        d_sha1.copy_from_slice(&sha1_d[..20]);
        results.add(&TpmtHa::Sha1(&d_sha1))?;

        let mut d_sha256 = [0u8; 32];
        d_sha256.copy_from_slice(&sha256_d[..32]);
        results.add(&TpmtHa::Sha256(&d_sha256))?;

        let mut d_sha384 = [0u8; 48];
        d_sha384.copy_from_slice(&sha384_d[..48]);
        results.add(&TpmtHa::Sha384(&d_sha384))?;

        if pcr_handle != Handle::RH_NULL.0 {
            let old_sha1 = &self.global_state.pcrs.sha1[pcr_handle as usize];
            let (new_sha1, _) = self.compute_hash(TpmiAlgHash::Sha1, &[old_sha1, &d_sha1])?;
            self.global_state.pcrs.sha1[pcr_handle as usize].copy_from_slice(&new_sha1[..20]);

            let old_sha256 = &self.global_state.pcrs.sha256[pcr_handle as usize];
            let (new_sha256, _) =
                self.compute_hash(TpmiAlgHash::Sha256, &[old_sha256, &d_sha256])?;
            self.global_state.pcrs.sha256[pcr_handle as usize].copy_from_slice(&new_sha256[..32]);

            let old_sha384 = &self.global_state.pcrs.sha384[pcr_handle as usize];
            let (new_sha384, _) =
                self.compute_hash(TpmiAlgHash::Sha384, &[old_sha384, &d_sha384])?;
            self.global_state.pcrs.sha384[pcr_handle as usize].copy_from_slice(&new_sha384[..48]);

            self.global_state.pcrs.update_counter =
                self.global_state.pcrs.update_counter.wrapping_add(1);
        }

        self.global_state.remove_active_sequence(sequence_handle)?;

        let rsp = responses::EventSequenceComplete { results };
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
        let handles = request.try_unmarshal::<HmacStartHandles>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal::<HmacStart>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let key_handle = handles.handle.0;
        let key_obj = self.resolve_object(key_handle, Position::handle(1))?;

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
        if key_obj.private_len == 0 {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        let cmd_hash_alg = match cmd.hash_alg {
            Some(alg) => Alg::from(alg),
            None => Alg::NULL,
        };

        let key_hash_alg = match scheme {
            Some(TpmtKeyedHashScheme::Hmac(hash_alg)) => {
                let key_hash_alg = Alg::from(*hash_alg);
                if cmd_hash_alg != Alg::NULL && cmd_hash_alg != key_hash_alg {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                key_hash_alg
            }
            Some(TpmtKeyedHashScheme::ExclusiveOr(..)) => {
                return Err(TpmRc::TYPE.with(Position::handle(1)));
            }
            None => {
                if cmd_hash_alg == Alg::NULL {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                cmd_hash_alg
            }
        };

        if key_hash_alg != Alg::SHA1
            && key_hash_alg != Alg::SHA256
            && key_hash_alg != Alg::SHA384
            && key_hash_alg != Alg::SHA512
        {
            return Err(TpmRc::HASH.with(Position::parameter(2)));
        }
        let key_hash_alg = TpmiAlgHash::try_from(key_hash_alg)
            .map_err(|_| TpmRc::HASH.with(Position::parameter(2)))?;

        let (index, handle) = self.global_state.find_empty_sequence_slot()?;

        let key_data =
            crate::owned::OwnedSensitiveData::from_bytes(&key_obj.private[..key_obj.private_len])
                .map_err(|_| TpmRc::FAILURE)?;

        self.global_state.active_sequences[index] = Some(crate::ActiveSequence::new(
            handle,
            crate::owned::OwnedAuth::from(cmd.auth),
            crate::SequenceType::Hmac {
                hash_alg: key_hash_alg,
                key: key_data,
            },
        ));

        let resp_handles = HmacStartRespHandles {
            sequence_handle: Handle(handle),
        };

        let response = request.into_response();
        self.write_response_handles(response, &resp_handles, &session_responses[..num_sessions])?;

        Ok(())
    }

    pub(crate) fn compute_hmac(
        &self,
        hash_alg: TpmiAlgHash,
        key: &[u8],
        buffers: &[&[u8]],
    ) -> Result<([u8; 64], usize), TpmRc> {
        let mut state = tpm2::crypto::HmacCtx::new(self.crypto(), hash_alg, key)
            .map_err(|_| TpmRc::VALUE.to_rc())?;
        for buf in buffers {
            state.update(buf).map_err(|_| TpmRc::FAILURE)?;
        }
        let mut digest_buf = [0u8; 64];
        let digest = state
            .finalize(&mut digest_buf)
            .map_err(|_| TpmRc::FAILURE)?;
        let len = digest.digest().len();
        Ok((digest_buf, len))
    }
}
