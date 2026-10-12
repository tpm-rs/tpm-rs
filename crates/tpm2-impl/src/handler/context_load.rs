use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::{
    ActiveSequence, MAX_SEQUENCE_BUFFER, SequenceType, StreamingHashState,
    handler::{CommandHandler, SessionState, TransientObject},
    owned::{
        OwnedAuth, OwnedDigest, OwnedName, OwnedNonce, OwnedPublic, OwnedSensitiveComposite,
        OwnedSensitiveData,
    },
    req_resp::RequestThenResponse,
    storage::NvStorage,
    timer::TpmTimer,
};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::Unmarshal;
use tpm2::crypto::{ModeIv, SymmetricKey, kdfa};
use tpm2::errors::{Position, TpmRc};
use tpm2::limits::MAX_CONTEXT_SIZE;
use tpm2::{AlgSym, Handle, Tpm2bContextData, Tpm2bDigest, TpmHt, TpmtSymDef};
use tpm2::{TpmSe, TpmiAlgHash};

struct TransientObjectFields {
    seed: OwnedDigest,
    name: OwnedName,
    auth: OwnedAuth,
    public: OwnedPublic,
    sensitive: OwnedSensitiveComposite,
    qualified_name: OwnedName,
}

/// Reads a `u16` length followed by that many bytes from `slice` into the start of `dst`,
/// returning the length. Fails with `TPM_RC_FAILURE` if `slice` is too short or the length
/// exceeds `dst`.
fn read_sized(slice: &mut &[u8], dst: &mut [u8]) -> Result<usize, TpmRc> {
    let len = usize::from(u16::unmarshal(slice).map_err(|_| TpmRc::FAILURE)?);
    let (data, rest) = slice.split_at_checked(len).ok_or(TpmRc::FAILURE)?;
    dst.get_mut(..len)
        .ok_or(TpmRc::FAILURE)?
        .copy_from_slice(data);
    *slice = rest;
    Ok(len)
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::ContextLoad] (`0x113`) command.
    ///
    /// # Description
    /// This command is used to reload an object or session context back into the TPM's volatile memory
    /// from a context blob that was previously returned by [TpmCc::ContextSave](context_save.rs).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 28.2 (TPM2_ContextLoad).
    ///
    /// # Relationships
    /// - Re-establishes a saved session or transient object previously serialized by [TpmCc::ContextSave](context_save.rs).
    /// - Unlike transient objects, persistent objects cannot be saved or loaded using context commands (use [TpmCc::EvictControl](evict_control.rs) instead).
    pub fn context_load(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let sequence = request.try_unmarshal_at::<u64>(Position::parameter(1))?;
        let saved_handle = request.try_unmarshal_at::<Handle>(Position::parameter(1))?;
        // PORTING: exp accepted any HMAC / policy session handle (`0x02xx_xxxx` / `0x03xx_xxxx`)
        // or `0x8000_0000..=0x8000_0002` here; this is now the `TPMI_DH_SAVED` check (session
        // handles limited to `MAX_ACTIVE_SESSIONS`), with the same response code. It also made
        // exp's later "not a session, sequence or object context" check (`TPM_RC_VALUE` +
        // handle 1) unreachable, so that check is gone.
        check(saved_handle, Tpmi::DhSaved, Position::parameter(1))?;
        let hierarchy = request.try_unmarshal_at::<Handle>(Position::parameter(1))?;
        if !matches!(
            hierarchy,
            Handle::RH_OWNER | Handle::RH_ENDORSEMENT | Handle::RH_PLATFORM | Handle::RH_NULL
        ) {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let blob_size = usize::from(request.try_unmarshal_at::<u16>(Position::parameter(1))?);
        if blob_size > Tpm2bContextData::CAP {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        if request.remaining_bytes() < blob_size {
            return Err(TpmRc::INSUFFICIENT.with(Position::parameter(1)));
        }
        if request.remaining_bytes() > blob_size {
            return Err(TpmRc::SIZE.to_rc());
        }
        let blob = request
            .read_slice(blob_size)
            .ok_or(TpmRc::INSUFFICIENT.with(Position::parameter(1)))?;

        if hierarchy == Handle::RH_OWNER && !self.global_state.sh_enable {
            return Err(TpmRc::HIERARCHY.with(Position::parameter(1)));
        }
        if hierarchy == Handle::RH_ENDORSEMENT && !self.global_state.eh_enable {
            return Err(TpmRc::HIERARCHY.with(Position::parameter(1)));
        }
        if hierarchy == Handle::RH_PLATFORM && !self.global_state.ph_enable {
            return Err(TpmRc::HIERARCHY.with(Position::parameter(1)));
        }

        let mut slice = blob;
        let integrity = Tpm2bDigest::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let enc_size = usize::from(u16::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?);
        let enc_slice = slice.get(..enc_size).ok_or(TpmRc::FAILURE)?;

        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(hierarchy.0);
        let proof = proof_bytes.get(..proof_len).ok_or(TpmRc::FAILURE)?;

        // 1. Verify HMAC integrity signature
        self.verify_context_integrity(
            proof,
            sequence,
            saved_handle,
            enc_slice,
            integrity.as_slice(),
        )?;

        // 2. Decrypt context sensitive area
        let mut sensitive_buf = [0u8; MAX_CONTEXT_SIZE];
        if enc_size > sensitive_buf.len() {
            return Err(TpmRc::FAILURE);
        }
        self.decrypt_context_sensitive(
            proof,
            sequence,
            saved_handle,
            enc_slice,
            &mut sensitive_buf,
        )?;
        let sensitive = &sensitive_buf[..enc_size];

        let is_session = matches!(
            saved_handle.handle_type(),
            Some(TpmHt::HMACSession | TpmHt::PolicySession)
        );
        let is_sequence = saved_handle.0 == 0x80000001;

        if (is_session || is_sequence) && hierarchy != Handle::RH_NULL {
            return Err(TpmRc::HIERARCHY.with(Position::handle(1)));
        }

        let loaded_handle = if is_session {
            self.nv_clear_orderly()?;
            // 3. Deserialize session context
            let sess = Self::deserialize_session(sensitive)?;
            if self.global_state.session(sess.session_handle).is_some() {
                return Err(TpmRc::HANDLE.to_rc());
            }
            let handle = sess.session_handle;
            for slot in self.global_state.saved_sessions.iter_mut() {
                if *slot == Some(handle) {
                    *slot = None;
                }
            }
            self.global_state.add_session(sess)?;
            handle
        } else if is_sequence {
            let mut seq = Self::deserialize_sequence(sensitive)?;
            let (slot, handle) = self.global_state.find_empty_sequence_slot()?;
            seq.handle = handle;
            self.global_state.active_sequences[slot] = Some(seq);
            handle
        } else {
            // 3. Unmarshal decrypted buffer into fields
            let (fields, ancestor_has_st_clear) = Self::unmarshal_decrypted_context(sensitive)?;

            // 4. Resolve empty slot and load transient object
            let (slot, handle) = self.global_state.find_empty_transient_slot(true)?;

            self.global_state.transient_parents[slot] = None;
            self.global_state.transient_objects[slot] = Some(TransientObject {
                handle,
                seed: fields.seed,
                name: fields.name,
                auth: fields.auth,
                public: fields.public,
                sensitive: fields.sensitive,
                qualified_name: fields.qualified_name,
                hierarchy: hierarchy.0,
                st_clear: ancestor_has_st_clear,
            });
            handle
        };

        let response = request.into_response();
        self.write_response_handles(
            response,
            &Handle(loaded_handle),
            &session_responses[..num_sessions],
        )?;

        Ok(())
    }

    /// Verifies the integrity of a context blob using SHA-256 HMAC keyed with the hierarchy proof.
    fn verify_context_integrity(
        &self,
        proof: &[u8],
        sequence: u64,
        saved_handle: Handle,
        encrypted_data: &[u8],
        expected_mac: &[u8],
    ) -> Result<(), TpmRc> {
        let total_reset_count = self.global_state.total_reset_count.to_be_bytes();
        let clear_count = self.global_state.clear_count.to_be_bytes();
        let sequence_bytes = sequence.to_be_bytes();
        let handle_bytes = saved_handle.0.to_be_bytes();
        let (mac, mac_len) = if saved_handle.0 == 0x80000002 {
            self.compute_hmac(
                TpmiAlgHash::Sha256,
                proof,
                &[
                    &total_reset_count,
                    &clear_count,
                    &sequence_bytes,
                    &handle_bytes,
                    encrypted_data,
                ],
            )
        } else {
            self.compute_hmac(
                TpmiAlgHash::Sha256,
                proof,
                &[
                    &total_reset_count,
                    &sequence_bytes,
                    &handle_bytes,
                    encrypted_data,
                ],
            )
        }
        .map_err(|_| TpmRc::FAILURE)?;

        if !mac
            .get(..mac_len)
            .is_some_and(|mac| crate::util::constant_time_eq(mac, expected_mac))
        {
            return Err(TpmRc::INTEGRITY.to_rc());
        }
        Ok(())
    }

    /// Decrypts the CFB-mode AES-128 encrypted context payload using the hierarchy proof.
    fn decrypt_context_sensitive(
        &self,
        proof: &[u8],
        sequence: u64,
        saved_handle: Handle,
        encrypted_data: &[u8],
        sensitive_buf: &mut [u8],
    ) -> Result<(), TpmRc> {
        let sequence_bytes = sequence.to_be_bytes();
        let handle_bytes = saved_handle.0.to_be_bytes();
        let mut sym_key_iv = [0u8; 32];
        kdfa(
            self.crypto(),
            TpmiAlgHash::Sha256,
            proof,
            c"CONTEXT",
            &sequence_bytes,
            &handle_bytes,
            &mut sym_key_iv,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let (sym_key, iv) = sym_key_iv.split_first_chunk::<16>().ok_or(TpmRc::FAILURE)?;
        let mut iv: [u8; AlgSym::BLOCK_SIZE] = iv.try_into().map_err(|_| TpmRc::FAILURE)?;

        let enc_len = encrypted_data.len();
        let data = sensitive_buf.get_mut(..enc_len).ok_or(TpmRc::FAILURE)?;
        data.copy_from_slice(encrypted_data);

        tpm2::crypto::decrypt(
            self.crypto(),
            SymmetricKey::Aes128(sym_key),
            ModeIv::Cfb(&mut iv),
            data,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }

    /// Unmarshals serialized fields from decrypted raw bytes.
    ///
    /// PORTING: the private area is the `TPM2B`-encoded `TPMU_SENSITIVE_COMPOSITE` member
    /// selected by the object type (see `serialize_transient_object`).
    fn unmarshal_decrypted_context(
        sensitive_buf: &[u8],
    ) -> Result<(TransientObjectFields, bool), TpmRc> {
        let mut slice = sensitive_buf;
        let _h = u32::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let seed = OwnedDigest::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let name = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let auth = OwnedAuth::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let public = OwnedPublic::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let sensitive = OwnedSensitiveComposite::unmarshal_variant(public.algorithm(), &mut slice)
            .map_err(|_| TpmRc::FAILURE)?;
        let qualified_name = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let ancestor_has_st_clear = slice.first().is_some_and(|&b| b != 0);

        Ok((
            TransientObjectFields {
                seed,
                name,
                auth,
                public,
                sensitive,
                qualified_name,
            },
            ancestor_has_st_clear,
        ))
    }

    fn deserialize_session(buf: &[u8]) -> Result<SessionState, TpmRc> {
        let mut slice = buf;

        let session_handle = u32::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let session_type = TpmSe::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let auth_hash = TpmiAlgHash::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let nonce_tpm = OwnedNonce::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let nonce_caller = OwnedNonce::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let mut session_key = [0u8; 128];
        let session_key_len = read_sized(&mut slice, &mut session_key)?;

        let symmetric = Option::<TpmtSymDef>::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let bind_entity = Handle::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let bound_entity = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let has_audit_digest = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;
        let (audit_digest, audit_digest_len) = if has_audit_digest {
            let mut digest = [0u8; 64];
            let digest_len = read_sized(&mut slice, &mut digest)?;
            (Some(digest), digest_len)
        } else {
            (None, 0)
        };

        let mut audit_cp_hash = [0u8; 64];
        let audit_cp_hash_len = read_sized(&mut slice, &mut audit_cp_hash)?;

        let mut policy_hash = [0u8; 64];
        let policy_hash_len = read_sized(&mut slice, &mut policy_hash)?;

        let is_cp_hash_defined = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;
        let is_name_hash_defined = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;
        let is_template_hash_defined = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;

        let mut policy_digest = [0u8; 64];
        let policy_digest_len = read_sized(&mut slice, &mut policy_digest)?;

        let command_code = u32::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let start_time = u64::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let timeout = u64::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let epoch = u64::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let is_auth_value_needed = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;
        let is_password_needed = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;

        let has_pcr_counter = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;
        let pcr_counter = if has_pcr_counter {
            Some(u32::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?)
        } else {
            None
        };

        let check_nv_written = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;
        let nv_written_state = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;
        let command_locality = if !slice.is_empty() {
            u8::unmarshal(&mut slice).unwrap_or(0)
        } else {
            0
        };

        Ok(SessionState {
            session_handle,
            session_type,
            auth_hash,
            nonce_tpm,
            nonce_caller,
            session_key,
            session_key_len,
            symmetric,
            bind_entity,
            bound_entity,
            audit_digest,
            audit_digest_len,
            audit_cp_hash,
            audit_cp_hash_len,
            policy_hash,
            policy_hash_len,
            is_cp_hash_defined,
            is_name_hash_defined,
            is_template_hash_defined,
            policy_digest,
            policy_digest_len,
            command_code,
            start_time,
            timeout,
            epoch,
            is_auth_value_needed,
            is_password_needed,
            pcr_counter,
            check_nv_written,
            nv_written_state,
            command_locality,
            include_auth: false,
        })
    }

    fn deserialize_sequence(buf: &[u8]) -> Result<ActiveSequence, TpmRc> {
        let mut slice = buf;
        let handle = u32::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let auth = OwnedAuth::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let tag_byte = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let sequence_type = match tag_byte {
            1 => {
                let alg = TpmiAlgHash::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
                SequenceType::Hash { alg }
            }
            2 => {
                let hash_alg = TpmiAlgHash::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
                let key = OwnedSensitiveData::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
                SequenceType::Hmac { hash_alg, key }
            }
            3 => {
                let associated_name =
                    OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
                let scheme = <Option<tpm2::TpmtSigScheme>>::unmarshal(&mut slice)
                    .map_err(|_| TpmRc::FAILURE)?
                    .ok_or(TpmRc::FAILURE)?;
                let context = crate::owned::OwnedSignatureCtx::unmarshal(&mut slice)
                    .map_err(|_| TpmRc::FAILURE)?;
                SequenceType::Sign {
                    associated_name,
                    scheme,
                    context,
                }
            }
            4 => {
                let associated_name =
                    OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
                let scheme = <Option<tpm2::TpmtSigScheme>>::unmarshal(&mut slice)
                    .map_err(|_| TpmRc::FAILURE)?
                    .ok_or(TpmRc::FAILURE)?;
                let context = crate::owned::OwnedSignatureCtx::unmarshal(&mut slice)
                    .map_err(|_| TpmRc::FAILURE)?;
                SequenceType::Verify {
                    associated_name,
                    scheme,
                    context,
                }
            }
            0 => SequenceType::Event,
            _ => return Err(TpmRc::FAILURE),
        };
        let sequence_len = u32::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let sequence_len = usize::try_from(sequence_len).map_err(|_| TpmRc::FAILURE)?;
        if sequence_len > MAX_SEQUENCE_BUFFER {
            return Err(TpmRc::FAILURE);
        }
        if slice.len() < 5 + 4 * StreamingHashState::SERIALIZED_SIZE {
            return Err(TpmRc::FAILURE);
        }
        let (first_bytes, rest) = slice.split_first_chunk::<4>().ok_or(TpmRc::FAILURE)?;
        let (&first_bytes_len, rest) = rest.split_first().ok_or(TpmRc::FAILURE)?;
        let first_bytes_len = usize::from(first_bytes_len).min(4);
        slice = rest;

        let mut hash_states = [StreamingHashState::default(); 4];
        for state in &mut hash_states {
            *state = StreamingHashState::deserialize(slice).ok_or(TpmRc::FAILURE)?;
            slice = slice
                .get(StreamingHashState::SERIALIZED_SIZE..)
                .ok_or(TpmRc::FAILURE)?;
        }

        let mut sequence_buffer = [0u8; MAX_SEQUENCE_BUFFER];
        if matches!(
            sequence_type,
            SequenceType::Sign { .. } | SequenceType::Verify { .. }
        ) {
            let data = slice.get(..sequence_len).ok_or(TpmRc::FAILURE)?;
            sequence_buffer[..sequence_len].copy_from_slice(data);
        }
        Ok(ActiveSequence {
            handle,
            intermediate_digest: OwnedDigest::default(),
            auth,
            sequence_type,
            sequence_buffer,
            sequence_len,
            first_bytes: *first_bytes,
            first_bytes_len,
            hash_states,
        })
    }
}
