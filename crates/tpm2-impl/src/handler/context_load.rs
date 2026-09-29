use crate::{
    handler::{CommandHandler, SessionState, TransientObject},
    owned::{OwnedAuth, OwnedDigest, OwnedName, OwnedNonce, OwnedPublic, OwnedSensitiveData},
    req_resp::RequestThenResponse,
    storage::NvStorage,
    timer::TpmTimer,
};

struct TransientObjectFields {
    seed: [u8; 32],
    name: OwnedName,
    auth: OwnedAuth,
    public: OwnedPublic,
    private: [u8; 1536],
    private_len: usize,
    qualified_name: OwnedName,
}
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::Unmarshal;
use tpm2::commands::ContextLoadRespHandles;
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TPM2_MAX_CONTEXT_SIZE, TpmHt, TpmiAlgSymMode, TpmtSymDefObject};
use tpm2::{TpmSe, TpmiAlgHash};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
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

        let sequence = request
            .try_unmarshal::<u64>()
            .map_err(|e| e.with_position(Position::parameter(1)))?;
        let saved_handle = request
            .try_unmarshal::<Handle>()
            .map_err(|e| e.with_position(Position::parameter(1)))?;
        let is_valid_saved_handle = matches!(saved_handle.0, 0x8000_0000..=0x8000_0002)
            || matches!(saved_handle.0 >> 24, 0x02 | 0x03);
        if !is_valid_saved_handle {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let hierarchy = request
            .try_unmarshal::<Handle>()
            .map_err(|e| e.with_position(Position::parameter(1)))?;
        if !matches!(
            hierarchy,
            Handle::RH_OWNER | Handle::RH_ENDORSEMENT | Handle::RH_PLATFORM | Handle::RH_NULL
        ) {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let blob_size = request
            .try_unmarshal::<u16>()
            .map_err(|e| e.with_position(Position::parameter(1)))? as usize;
        if blob_size > tpm2::Tpm2bContextData::MAX_BUFFER_SIZE {
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

        if hierarchy.0 == Handle::RH_OWNER.0 && !self.global_state.sh_enable {
            return Err(TpmRc::HIERARCHY.with(Position::parameter(1)));
        }
        if hierarchy.0 == Handle::RH_ENDORSEMENT.0 && !self.global_state.eh_enable {
            return Err(TpmRc::HIERARCHY.with(Position::parameter(1)));
        }
        if hierarchy.0 == Handle::RH_PLATFORM.0 && !self.global_state.ph_enable {
            return Err(TpmRc::HIERARCHY.with(Position::parameter(1)));
        }

        let mut slice = blob;
        let integrity = tpm2::Tpm2bDigest::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let enc_size = u16::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? as usize;
        if slice.len() < enc_size {
            return Err(TpmRc::FAILURE);
        }
        let (enc_slice, _) = slice.split_at(enc_size);

        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(hierarchy.0);
        let proof = &proof_bytes[..proof_len];

        // 1. Verify HMAC integrity signature
        self.verify_context_integrity(
            proof,
            sequence,
            saved_handle,
            enc_slice,
            integrity.get_buffer(),
        )?;

        // 2. Decrypt context sensitive area
        let mut sensitive_buf = [0u8; TPM2_MAX_CONTEXT_SIZE as usize];
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

        let is_session = matches!(
            Handle(saved_handle.0).handle_type(),
            Some(TpmHt::HMACSession | TpmHt::PolicySession)
        );
        let is_sequence = saved_handle.0 == 0x80000001;
        let is_transient = saved_handle.0 == 0x80000000 || saved_handle.0 == 0x80000002;

        if !is_session && !is_sequence && !is_transient {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        if (is_session || is_sequence) && hierarchy.0 != Handle::RH_NULL.0 {
            return Err(TpmRc::HIERARCHY.with(Position::handle(1)));
        }

        let loaded_handle = if is_session {
            self.nv_clear_orderly()?;
            // 3. Deserialize session context
            let sess = Self::deserialize_session(&sensitive_buf[..enc_size])?;
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
            let mut seq = Self::deserialize_sequence(&sensitive_buf[..enc_size])?;
            let (slot, handle) = self.global_state.find_empty_sequence_slot()?;
            seq.handle = handle;
            self.global_state.active_sequences[slot] = Some(seq);
            handle
        } else {
            // 3. Unmarshal decrypted buffer into fields
            let (fields, ancestor_has_st_clear) =
                Self::unmarshal_decrypted_context(&sensitive_buf[..enc_size])?;

            // 4. Resolve empty slot and load transient object
            let (slot, handle) = self.global_state.find_empty_transient_slot(true)?;

            self.global_state.transient_parents[slot] = None;
            self.global_state.transient_objects[slot] = Some(TransientObject {
                handle,
                seed: fields.seed,
                name: fields.name,
                auth: fields.auth,
                public: fields.public,
                private: fields.private,
                private_len: fields.private_len,
                qualified_name: fields.qualified_name,
                hierarchy: hierarchy.0,
                st_clear: ancestor_has_st_clear,
            });
            handle
        };

        let handles_rsp = ContextLoadRespHandles {
            loaded_handle: Handle(loaded_handle),
        };

        let response = request.into_response();
        self.write_response_handles(response, &handles_rsp, &session_responses[..num_sessions])?;

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
        let mut mac_ctx = tpm2::crypto::HmacCtx::new(self.crypto(), TpmiAlgHash::Sha256, proof)
            .map_err(|_| TpmRc::FAILURE)?;
        mac_ctx
            .update(&self.global_state.total_reset_count.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        if saved_handle.0 == 0x80000002 {
            mac_ctx
                .update(&self.global_state.clear_count.to_be_bytes())
                .map_err(|_| TpmRc::FAILURE)?;
        }
        mac_ctx
            .update(&sequence.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        mac_ctx
            .update(&saved_handle.0.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        mac_ctx.update(encrypted_data).map_err(|_| TpmRc::FAILURE)?;
        let mut mac_buf = [0u8; 64];
        let mac = mac_ctx.finalize(&mut mac_buf).map_err(|_| TpmRc::FAILURE)?;

        if mac.digest() != expected_mac {
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
            b"CONTEXT",
            &sequence_bytes,
            &handle_bytes,
            256,
            &mut sym_key_iv,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let mut sym_key = [0u8; 16];
        sym_key.copy_from_slice(&sym_key_iv[0..16]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&sym_key_iv[16..32]);

        let enc_len = encrypted_data.len();
        sensitive_buf[..enc_len].copy_from_slice(encrypted_data);

        tpm2::crypto::decrypt(
            self.crypto(),
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            &sym_key,
            &mut iv,
            &mut sensitive_buf[..enc_len],
        )
        .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }

    /// Unmarshals serialized fields from decrypted raw bytes.
    fn unmarshal_decrypted_context(
        sensitive_buf: &[u8],
    ) -> Result<(TransientObjectFields, bool), TpmRc> {
        let mut slice = sensitive_buf;
        let _h = u32::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        if slice.len() < 32 {
            return Err(TpmRc::FAILURE);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&slice[..32]);
        slice = &slice[32..];

        let name = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let auth = OwnedAuth::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let public = OwnedPublic::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let priv_len = u16::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? as usize;
        if slice.len() < priv_len {
            return Err(TpmRc::FAILURE);
        }
        let mut priv_buf = [0u8; 1536];
        priv_buf[..priv_len].copy_from_slice(&slice[..priv_len]);
        slice = &slice[priv_len..];
        let qualified_name = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let ancestor_has_st_clear = if !slice.is_empty() {
            slice[0] != 0
        } else {
            false
        };

        Ok((
            TransientObjectFields {
                seed,
                name,
                auth,
                public,
                private: priv_buf,
                private_len: priv_len,
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

        let session_key_len = u16::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? as usize;
        if slice.len() < session_key_len {
            return Err(TpmRc::FAILURE);
        }
        let mut session_key = [0u8; 128];
        session_key[..session_key_len].copy_from_slice(&slice[..session_key_len]);
        slice = &slice[session_key_len..];

        let symmetric =
            <Option<tpm2::TpmtSymDef>>::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let bind_entity = Handle::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let bound_entity = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let has_audit_digest = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;
        let (audit_digest, audit_digest_len) = if has_audit_digest {
            let digest_len = u16::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? as usize;
            if slice.len() < digest_len {
                return Err(TpmRc::FAILURE);
            }
            let mut digest = [0u8; 64];
            digest[..digest_len].copy_from_slice(&slice[..digest_len]);
            slice = &slice[digest_len..];
            (Some(digest), digest_len)
        } else {
            (None, 0)
        };

        let audit_cp_hash_len = u16::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? as usize;
        if slice.len() < audit_cp_hash_len {
            return Err(TpmRc::FAILURE);
        }
        let mut audit_cp_hash = [0u8; 64];
        audit_cp_hash[..audit_cp_hash_len].copy_from_slice(&slice[..audit_cp_hash_len]);
        slice = &slice[audit_cp_hash_len..];

        let policy_hash_len = u16::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? as usize;
        if slice.len() < policy_hash_len {
            return Err(TpmRc::FAILURE);
        }
        let mut policy_hash = [0u8; 64];
        policy_hash[..policy_hash_len].copy_from_slice(&slice[..policy_hash_len]);
        slice = &slice[policy_hash_len..];

        let is_cp_hash_defined = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;
        let is_name_hash_defined = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? != 0;

        let policy_digest_len = u16::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? as usize;
        if slice.len() < policy_digest_len {
            return Err(TpmRc::FAILURE);
        }
        let mut policy_digest = [0u8; 64];
        policy_digest[..policy_digest_len].copy_from_slice(&slice[..policy_digest_len]);
        slice = &slice[policy_digest_len..];

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
            is_template_hash_defined: false,
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

    fn deserialize_sequence(buf: &[u8]) -> Result<crate::ActiveSequence, TpmRc> {
        let mut slice = buf;
        let handle = u32::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let auth = OwnedAuth::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let tag_byte = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let sequence_type = match tag_byte {
            1 => {
                let alg = TpmiAlgHash::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
                crate::SequenceType::Hash { alg }
            }
            2 => {
                let hash_alg = TpmiAlgHash::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
                let key = OwnedSensitiveData::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
                crate::SequenceType::Hmac { hash_alg, key }
            }
            0 => crate::SequenceType::Event,
            _ => return Err(TpmRc::FAILURE),
        };
        let sequence_len = u32::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? as usize;
        if sequence_len > crate::MAX_SEQUENCE_BUFFER {
            return Err(TpmRc::FAILURE);
        }
        if slice.len() < 5 + 4 * crate::StreamingHashState::SERIALIZED_SIZE {
            return Err(TpmRc::FAILURE);
        }
        let mut first_bytes = [0u8; 4];
        first_bytes.copy_from_slice(&slice[..4]);
        let first_bytes_len = (slice[4] as usize).min(4);
        slice = &slice[5..];

        let mut hash_states = [crate::StreamingHashState::default(); 4];
        for state in &mut hash_states {
            *state = crate::StreamingHashState::deserialize(slice).ok_or(TpmRc::FAILURE)?;
            slice = &slice[crate::StreamingHashState::SERIALIZED_SIZE..];
        }

        let sequence_buffer = [0u8; crate::MAX_SEQUENCE_BUFFER];
        Ok(crate::ActiveSequence {
            handle,
            intermediate_digest: OwnedDigest::default(),
            auth,
            sequence_type,
            sequence_buffer,
            sequence_len,
            first_bytes,
            first_bytes_len,
            hash_states,
        })
    }
}
