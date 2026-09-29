use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{
    handler::{CommandHandler, SessionState, TransientObject},
    owned::OwnedDigest,
    req_resp::RequestThenResponse,
};
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmaObject;
use tpm2::commands::{ContextSave, ContextSaveHandles};
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TPM2_MAX_CONTEXT_SIZE, TpmHt, TpmiAlgSymMode, TpmtSymDefObject};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::ContextSave] (`0x112`) command.
    ///
    /// # Description
    /// This command serializes the volatile state of a transient object or session into an encrypted
    /// and integrity-protected blob, allowing it to be stored off-TPM.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 28.1 (TPM2_ContextSave).
    ///
    /// # Relationships
    /// - Serializes state that can be reloaded into the TPM using [TpmCc::ContextLoad](context_load.rs).
    /// - If the saved entity is a session, it remains active but its slot in volatile memory is freed.
    /// - For transient objects, saving a context does not flush it; a separate call to [TpmCc::FlushContext](flush_context.rs) is needed to remove it from RAM.
    pub fn context_save(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<ContextSaveHandles>()?;
        let save_handle = handles.save_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        self.nv_clear_orderly()?;

        let _cmd = request.try_unmarshal::<ContextSave>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let is_session = matches!(
            Handle(save_handle).handle_type(),
            Some(TpmHt::HMACSession | TpmHt::PolicySession)
        );
        if !is_session && (save_handle >> 24) != (TpmHt::Transient as u8 as u32) {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }
        if is_session && (save_handle & 0x00FF_FFFF) >= tpm2::TPM2_MAX_ACTIVE_SESSIONS {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }
        if (save_handle >> 24) == (TpmHt::Transient as u8 as u32)
            && (save_handle & 0x00FF_FFFF) >= 256
        {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let mut sensitive_buf = [0u8; TPM2_MAX_CONTEXT_SIZE as usize];
        let mut is_session = false;
        let mut _is_sequence = false;

        let (obj_hierarchy, out_saved_handle, offset) =
            if let Some(obj) = self.global_state.find_transient_object(save_handle) {
                let obj_hierarchy = obj.hierarchy;
                let is_st_clear =
                    obj.st_clear || obj.public.object_attributes.contains(TpmaObject::ST_CLEAR);

                let offset = Self::serialize_transient_object(obj, &mut sensitive_buf)?;

                let out_saved_handle = if is_st_clear {
                    0x80000002_u32
                } else {
                    0x80000000_u32
                };
                (obj_hierarchy, out_saved_handle, offset)
            } else if let Some(sess) = self.global_state.session(save_handle) {
                is_session = true;
                let obj_hierarchy = Handle::RH_NULL.0;

                let offset = Self::serialize_session(sess, &mut sensitive_buf)?;

                (obj_hierarchy, save_handle, offset)
            } else if let Some(seq) = self.global_state.find_active_sequence(save_handle) {
                _is_sequence = true;
                let obj_hierarchy = Handle::RH_NULL.0;

                let offset = Self::serialize_sequence(seq, &mut sensitive_buf)?;

                (obj_hierarchy, 0x80000001_u32, offset)
            } else {
                return Err(TpmRc::REFERENCE_H0);
            };

        let handle_bytes = out_saved_handle.to_be_bytes();
        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(obj_hierarchy);
        let mut proof_buf = [0u8; 64];
        proof_buf[..proof_len].copy_from_slice(&proof_bytes[..proof_len]);
        let proof = &proof_buf[..proof_len];

        let sequence = if is_session {
            let s = self.global_state.context_counter;
            self.global_state.context_counter += 1;
            s
        } else {
            let s = self.global_state.object_context_counter;
            self.global_state.object_context_counter += 1;
            s
        };
        let sequence_bytes = sequence.to_be_bytes();

        // 2. Encrypt sensitive serialized data
        self.encrypt_saved_context(
            proof,
            &sequence_bytes,
            &handle_bytes,
            &mut sensitive_buf[..offset],
        )?;

        // 3. Compute HMAC integrity check
        let integrity = self.compute_context_integrity_hmac(
            proof,
            &sequence_bytes,
            &handle_bytes,
            out_saved_handle,
            &sensitive_buf[..offset],
        )?;

        let raw_rsp = RawContextSaveRsp {
            sequence,
            saved_handle: out_saved_handle,
            hierarchy: obj_hierarchy,
            integrity: &integrity,
            encrypted: &sensitive_buf[..offset],
        };

        let response = request.into_response();
        self.write_response_rsp(response, &raw_rsp, &session_responses[..num_sessions])?;

        if is_session {
            for slot in self.global_state.saved_sessions.iter_mut() {
                if slot.is_none() {
                    *slot = Some(save_handle);
                    break;
                }
            }
            self.global_state.remove_session(save_handle);
        }

        Ok(())
    }

    /// Serializes key seed, handle, public and private templates, name, and attributes
    /// of a transient object into a raw buffer for saving.
    fn serialize_transient_object(obj: &TransientObject, buf: &mut [u8]) -> Result<usize, TpmRc> {
        if buf.len() < 4096 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut offset = 0;

        buf[offset..offset + 4].copy_from_slice(&obj.handle.to_be_bytes());
        offset += 4;

        buf[offset..offset + 32].copy_from_slice(&obj.seed);
        offset += 32;

        offset += obj.name.marshal(
            (&mut buf[offset..offset + tpm2::Tpm2bName::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += obj.auth.marshal(
            (&mut buf[offset..offset + tpm2::Tpm2bAuth::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += obj.public.marshal(
            (&mut buf[offset..offset + tpm2::TpmtPublic::MAX_SIZE])
                .try_into()
                .unwrap(),
        );

        buf[offset..offset + 2].copy_from_slice(&(obj.private_len as u16).to_be_bytes());
        offset += 2;

        buf[offset..offset + obj.private_len].copy_from_slice(&obj.private[..obj.private_len]);
        offset += obj.private_len;

        offset += obj.qualified_name.marshal(
            (&mut buf[offset..offset + tpm2::Tpm2bName::MAX_SIZE])
                .try_into()
                .unwrap(),
        );

        let ancestor_has_st_clear: bool = obj.st_clear;
        buf[offset] = if ancestor_has_st_clear { 1 } else { 0 };
        offset += 1;

        Ok(offset)
    }

    /// Derives symmetric keys using the hierarchy proof and context/sequence/handle labels,
    /// then CFB-encrypts the serialized payload.
    fn encrypt_saved_context(
        &self,
        proof: &[u8],
        sequence_bytes: &[u8; 8],
        handle_bytes: &[u8; 4],
        sensitive_buf: &mut [u8],
    ) -> Result<(), TpmRc> {
        let mut sym_key_iv = [0u8; 32];
        kdfa(
            self.crypto(),
            tpm2::TpmiAlgHash::Sha256,
            proof,
            b"CONTEXT",
            sequence_bytes,
            handle_bytes,
            256,
            &mut sym_key_iv,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let mut sym_key = [0u8; 16];
        sym_key.copy_from_slice(&sym_key_iv[0..16]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&sym_key_iv[16..32]);

        tpm2::crypto::encrypt(
            self.crypto(),
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            &sym_key,
            &mut iv,
            sensitive_buf,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }

    /// Computes a SHA-256 HMAC signature keyed with the hierarchy proof across total_reset_count,
    /// clear_count (if ST_CLEAR handle 0x80000002), sequence, saved_handle, and encrypted data.
    fn compute_context_integrity_hmac(
        &self,
        proof: &[u8],
        sequence_bytes: &[u8; 8],
        handle_bytes: &[u8; 4],
        saved_handle: u32,
        sensitive_buf: &[u8],
    ) -> Result<OwnedDigest, TpmRc> {
        let mut mac_ctx =
            tpm2::crypto::HmacCtx::new(self.crypto(), tpm2::TpmiAlgHash::Sha256, proof)
                .map_err(|_| TpmRc::FAILURE)?;
        mac_ctx
            .update(&self.global_state.total_reset_count.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        if saved_handle == 0x80000002 {
            mac_ctx
                .update(&self.global_state.clear_count.to_be_bytes())
                .map_err(|_| TpmRc::FAILURE)?;
        }
        mac_ctx.update(sequence_bytes).map_err(|_| TpmRc::FAILURE)?;
        mac_ctx.update(handle_bytes).map_err(|_| TpmRc::FAILURE)?;
        mac_ctx.update(sensitive_buf).map_err(|_| TpmRc::FAILURE)?;

        let mut mac_buf = [0u8; 64];
        let mac = mac_ctx.finalize(&mut mac_buf).map_err(|_| TpmRc::FAILURE)?;
        OwnedDigest::from_bytes(mac.digest()).map_err(|_| TpmRc::FAILURE)
    }

    fn serialize_session(sess: &SessionState, buf: &mut [u8]) -> Result<usize, TpmRc> {
        if buf.len() < 1024 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut offset = 0;

        buf[offset..offset + 4].copy_from_slice(&sess.session_handle.to_be_bytes());
        offset += 4;

        offset += sess.session_type.marshal(
            (&mut buf[offset..offset + tpm2::TpmSe::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += sess.auth_hash.marshal(
            (&mut buf[offset..offset + tpm2::TpmiAlgHash::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += sess.nonce_tpm.marshal(
            (&mut buf[offset..offset + tpm2::Tpm2bNonce::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += sess.nonce_caller.marshal(
            (&mut buf[offset..offset + tpm2::Tpm2bNonce::MAX_SIZE])
                .try_into()
                .unwrap(),
        );

        buf[offset..offset + 2].copy_from_slice(&(sess.session_key_len as u16).to_be_bytes());
        offset += 2;
        buf[offset..offset + sess.session_key_len]
            .copy_from_slice(&sess.session_key[..sess.session_key_len]);
        offset += sess.session_key_len;

        offset += sess.symmetric.marshal(
            (&mut buf[offset..offset + <Option<tpm2::TpmtSymDef>>::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += sess.bind_entity.marshal(
            (&mut buf[offset..offset + tpm2::Handle::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += sess.bound_entity.marshal(
            (&mut buf[offset..offset + tpm2::Tpm2bName::MAX_SIZE])
                .try_into()
                .unwrap(),
        );

        if let Some(digest) = sess.audit_digest {
            buf[offset] = 1;
            offset += 1;
            buf[offset..offset + 2].copy_from_slice(&(sess.audit_digest_len as u16).to_be_bytes());
            offset += 2;
            buf[offset..offset + sess.audit_digest_len]
                .copy_from_slice(&digest[..sess.audit_digest_len]);
            offset += sess.audit_digest_len;
        } else {
            buf[offset] = 0;
            offset += 1;
        }

        buf[offset..offset + 2].copy_from_slice(&(sess.audit_cp_hash_len as u16).to_be_bytes());
        offset += 2;
        buf[offset..offset + sess.audit_cp_hash_len]
            .copy_from_slice(&sess.audit_cp_hash[..sess.audit_cp_hash_len]);
        offset += sess.audit_cp_hash_len;

        buf[offset..offset + 2].copy_from_slice(&(sess.policy_hash_len as u16).to_be_bytes());
        offset += 2;
        buf[offset..offset + sess.policy_hash_len]
            .copy_from_slice(&sess.policy_hash[..sess.policy_hash_len]);
        offset += sess.policy_hash_len;

        buf[offset] = if sess.is_cp_hash_defined { 1 } else { 0 };
        offset += 1;

        buf[offset] = if sess.is_name_hash_defined { 1 } else { 0 };
        offset += 1;

        buf[offset..offset + 2].copy_from_slice(&(sess.policy_digest_len as u16).to_be_bytes());
        offset += 2;
        buf[offset..offset + sess.policy_digest_len]
            .copy_from_slice(&sess.policy_digest[..sess.policy_digest_len]);
        offset += sess.policy_digest_len;

        buf[offset..offset + 4].copy_from_slice(&sess.command_code.to_be_bytes());
        offset += 4;

        buf[offset..offset + 8].copy_from_slice(&sess.start_time.to_be_bytes());
        offset += 8;

        buf[offset..offset + 8].copy_from_slice(&sess.timeout.to_be_bytes());
        offset += 8;

        buf[offset..offset + 8].copy_from_slice(&sess.epoch.to_be_bytes());
        offset += 8;

        buf[offset] = if sess.is_auth_value_needed { 1 } else { 0 };
        offset += 1;

        buf[offset] = if sess.is_password_needed { 1 } else { 0 };
        offset += 1;

        if let Some(counter) = sess.pcr_counter {
            buf[offset] = 1;
            offset += 1;
            buf[offset..offset + 4].copy_from_slice(&counter.to_be_bytes());
            offset += 4;
        } else {
            buf[offset] = 0;
            offset += 1;
        }

        buf[offset] = if sess.check_nv_written { 1 } else { 0 };
        offset += 1;

        buf[offset] = if sess.nv_written_state { 1 } else { 0 };
        offset += 1;

        buf[offset] = sess.command_locality;
        offset += 1;

        Ok(offset)
    }

    fn serialize_sequence(seq: &crate::ActiveSequence, buf: &mut [u8]) -> Result<usize, TpmRc> {
        if buf.len() < 2048 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut offset = 0;

        buf[offset..offset + 4].copy_from_slice(&seq.handle.to_be_bytes());
        offset += 4;

        offset += seq.auth.marshal(
            (&mut buf[offset..offset + tpm2::Tpm2bAuth::MAX_SIZE])
                .try_into()
                .unwrap(),
        );

        match &seq.sequence_type {
            crate::SequenceType::Hash { alg } => {
                buf[offset] = 1;
                offset += 1;
                offset += alg.marshal(
                    (&mut buf[offset..offset + tpm2::TpmiAlgHash::MAX_SIZE])
                        .try_into()
                        .unwrap(),
                );
            }
            crate::SequenceType::Hmac { hash_alg, key } => {
                buf[offset] = 2;
                offset += 1;
                let alg_len = hash_alg.marshal(
                    (&mut buf[offset..offset + tpm2::TpmiAlgHash::MAX_SIZE])
                        .try_into()
                        .unwrap(),
                );
                offset += alg_len;
                let key_len = key.marshal(
                    (&mut buf[offset..offset + tpm2::Tpm2bSensitiveData::MAX_SIZE])
                        .try_into()
                        .unwrap(),
                );
                offset += key_len;
            }
            crate::SequenceType::Event => {
                buf[offset] = 0;
                offset += 1;
            }
        }

        buf[offset..offset + 4].copy_from_slice(&(seq.sequence_len as u32).to_be_bytes());
        offset += 4;

        buf[offset..offset + 4].copy_from_slice(&seq.first_bytes);
        offset += 4;
        buf[offset] = seq.first_bytes_len as u8;
        offset += 1;

        for state in &seq.hash_states {
            offset += state.serialize(&mut buf[offset..]);
        }

        Ok(offset)
    }
}

struct RawContextSaveRsp<'a> {
    sequence: u64,
    saved_handle: u32,
    hierarchy: u32,
    integrity: &'a OwnedDigest,
    encrypted: &'a [u8],
}

impl<'a> Marshal for RawContextSaveRsp<'a> {
    const MAX_SIZE: usize = 8 + 4 + 4 + 2 + (2 + OwnedDigest::MAX_SIZE + 2 + 4096);
    type MaxBuffer = [u8; 8 + 4 + 4 + 2 + (2 + OwnedDigest::MAX_SIZE + 2 + 4096)];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let integrity_size = self.integrity.get_size() as usize;
        let encrypted_size = self.encrypted.len();
        let context_data_size = 2 + integrity_size + 2 + encrypted_size;
        let mut offset = 0;
        offset += self
            .sequence
            .marshal((&mut dst[offset..offset + 8]).try_into().unwrap());
        offset += self
            .saved_handle
            .marshal((&mut dst[offset..offset + 4]).try_into().unwrap());
        offset += self
            .hierarchy
            .marshal((&mut dst[offset..offset + 4]).try_into().unwrap());
        offset +=
            (context_data_size as u16).marshal((&mut dst[offset..offset + 2]).try_into().unwrap());
        offset += self.integrity.marshal(
            (&mut dst[offset..offset + tpm2::Tpm2bDigest::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset +=
            (encrypted_size as u16).marshal((&mut dst[offset..offset + 2]).try_into().unwrap());
        dst[offset..offset + encrypted_size].copy_from_slice(self.encrypted);
        offset += encrypted_size;
        offset
    }
}
