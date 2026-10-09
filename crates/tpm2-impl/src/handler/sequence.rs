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
            // C rejects unimplemented hashes while unmarshaling `hashAlg`
            // (`TPM_RC_HASH + RC_HashSequenceStart_hashAlg`).
            return Err(TpmRc::HASH.with(Position::parameter(2)));
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

        // For hash sequences, only the first data block decides whether a ticket may be
        // produced (`TicketIsSafe` on the first block in `SequenceUpdate.c`).
        if matches!(seq_obj.sequence_type, crate::SequenceType::Hash { .. }) {
            record_first_block(seq_obj, data);
        }

        // The data is consumed by the streaming hash states, so there is no limit on the total
        // length of a sequence (C has none either).
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
                crate::SequenceType::Event => {
                    return Err(TpmRc::MODE.with(Position::handle(1)));
                }
                crate::SequenceType::Hash { alg } => {
                    let (digest_bytes, digest_len) = state.finalize();

                    // If no data block was received yet, the final chunk is the first block.
                    let ticket_safe = if seq_obj.first_bytes_len == 0 {
                        ticket_is_safe(final_chunk)
                    } else {
                        first_block_was_safe(seq_obj)
                    };

                    let validation = if hierarchy.0 == Handle::RH_NULL.0 || !ticket_safe {
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

        // EventSequenceComplete.c order: `sequenceHandle` (Handle 2) must reference an event
        // sequence before the PCR locality / orderly checks are made.
        let final_chunk = cmd.buffer.get_buffer();
        let mut digests = [(TpmiAlgHash::Sha1, [0u8; 64], 0usize); 4];
        {
            let seq_obj = match self.global_state.find_active_sequence(sequence_handle) {
                Some(seq) => seq,
                None => {
                    if self
                        .resolve_object(sequence_handle, Position::handle(2))
                        .is_ok()
                    {
                        return Err(TpmRc::MODE.with(Position::handle(2)));
                    } else {
                        return Err(TpmRc::HANDLE.with(Position::handle(2)));
                    }
                }
            };

            if seq_obj.sequence_type != crate::SequenceType::Event {
                return Err(TpmRc::MODE.with(Position::handle(2)));
            }

            // Event sequences track every implemented hash (SHA-1, SHA-256, SHA-384, SHA-512).
            for (digest, state) in digests.iter_mut().zip(seq_obj.hash_states.iter()) {
                let mut state = *state;
                state.update(final_chunk);
                let (bytes, len) = state.finalize();
                digest.0 = state.alg;
                digest.1[..len].copy_from_slice(&bytes[..len]);
                digest.2 = len;
            }
        }

        if pcr_handle != Handle::RH_NULL.0 {
            // The TPM 2.0 specification defines 24 PCRs for PC Client profiles
            // (TPM 2.0 Library Specification Part 4: Support Structures, Section 8.1).
            if pcr_handle >= 24 {
                return Err(TpmRc::VALUE.with(Position::handle(1)));
            }
            if !self.pcr_is_extend_allowed(pcr_handle) {
                return Err(TpmRc::LOCALITY);
            }
            if crate::handler::pcr::pcr_is_state_saved(pcr_handle) {
                self.nv_clear_orderly()?;
            }
        }

        let mut results = TpmlDigestValues::default();
        for (alg, bytes, len) in digests.iter() {
            let ha = TpmtHa::new(*alg, &bytes[..*len]).ok_or(TpmRc::FAILURE)?;
            results.add(&ha)?;
            // PCRExtend(): only allocated banks are extended, and changes to the TCB group
            // (PCRs 20-22) do not increment the PCR update counter.
            if pcr_handle != Handle::RH_NULL.0 {
                self.pcr_extend_bank(pcr_handle, *alg, &bytes[..*len])?;
            }
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

        let cmd_hash_alg = match cmd.hash_alg {
            Some(alg) => Alg::from(alg),
            None => Alg::NULL,
        };

        // CryptSelectMac(): a non-NULL key scheme provides the MAC algorithm. For an XOR key
        // this is its hash (C reads `details.hmac.hashAlg`, which aliases the XOR hash); such
        // keys can't sign and are rejected by the attribute checks below.
        let key_hash_alg = match scheme {
            Some(TpmtKeyedHashScheme::Hmac(hash_alg))
            | Some(TpmtKeyedHashScheme::ExclusiveOr(tpm2::TpmsSchemeXor { hash_alg, .. })) => {
                let key_hash_alg = Alg::from(*hash_alg);
                if cmd_hash_alg != Alg::NULL && cmd_hash_alg != key_hash_alg {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                key_hash_alg
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

        // MAC_Start.c order: the MAC scheme selection (`CryptSelectMac`, above) comes first,
        // then the key must be unrestricted, and only then must it be a signing key.
        if key_obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        if !key_obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        // Defense in depth: a public-only key cannot be authorized in C (AUTH_UNAVAILABLE).
        if key_obj.private_len == 0 {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

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

/// The value that begins every TPM-generated structure (`TPM_GENERATED_VALUE`).
const TPM_GENERATED_VALUE: [u8; 4] = [0xFF, b'T', b'C', b'G'];

/// `TicketIsSafe` (`Ticket.c`): a hash ticket may only be produced if the first data block is at
/// least 4 bytes long and does not start with `TPM_GENERATED_VALUE`, so that a ticket can never
/// vouch for a digest over data that could be mistaken for a TPM-generated structure.
fn ticket_is_safe(first_block: &[u8]) -> bool {
    first_block.len() >= 4 && first_block[..4] != TPM_GENERATED_VALUE
}

/// Records the first data block of a hash sequence (`firstBlock` / `ticketSafe` attributes).
///
/// The persisted `first_bytes` / `first_bytes_len` fields encode the result:
/// - `first_bytes_len == 0`: no data block has been received yet;
/// - `1..=3`: the first block was shorter than 4 bytes (including an empty block), so a ticket
///   is not safe;
/// - `4`: `first_bytes` holds the first 4 bytes of the first block.
///
/// Later blocks do not change the decision.
fn record_first_block(seq: &mut crate::ActiveSequence, data: &[u8]) {
    if seq.first_bytes_len != 0 {
        return;
    }
    let take = data.len().min(4);
    seq.first_bytes = [0u8; 4];
    seq.first_bytes[..take].copy_from_slice(&data[..take]);
    seq.first_bytes_len = take.max(1);
}

/// Returns whether the first block recorded by [`record_first_block`] makes a ticket safe.
fn first_block_was_safe(seq: &crate::ActiveSequence) -> bool {
    seq.first_bytes_len == 4 && seq.first_bytes != TPM_GENERATED_VALUE
}
