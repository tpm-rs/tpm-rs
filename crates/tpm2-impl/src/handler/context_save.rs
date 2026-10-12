use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{
    ActiveSequence, SequenceType, StreamingHashState,
    handler::{CommandHandler, SessionState, TransientObject},
    owned::OwnedDigest,
    req_resp::RequestThenResponse,
};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmaObject;
use tpm2::commands::{ContextSave, responses};
use tpm2::crypto::{ModeIv, SymmetricKey, kdfa};
use tpm2::errors::{Position, TpmRc};
use tpm2::limits::MAX_CONTEXT_SIZE;
use tpm2::{AlgSym, Handle, Tpm2bContextData, TpmiAlgHash, TpmsContext};

use super::duplicate::Writer;

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
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

        let handles = request.try_unmarshal_handles::<ContextSave>()?;
        let [save_handle] = handles;
        check(save_handle, Tpmi::DhContext, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        self.nv_clear_orderly()?;

        let _cmd = request.try_unmarshal_command::<ContextSave>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // PORTING: exp re-checked here that `save_handle` is a session handle below
        // `TPM2_MAX_ACTIVE_SESSIONS` or a transient handle below `0x8000_0100`
        // (`TPM_RC_VALUE` + handle 1). `TPMI_DH_CONTEXT` (checked above, as exp's typed handle
        // unmarshal did) only admits such handles, so those checks were unreachable.
        let save_handle = save_handle.0;

        let mut sensitive_buf = [0u8; MAX_CONTEXT_SIZE];
        let mut is_session = false;

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
                let obj_hierarchy = Handle::RH_NULL.0;

                let offset = Self::serialize_sequence(seq, &mut sensitive_buf)?;

                (obj_hierarchy, 0x80000001_u32, offset)
            } else {
                return Err(TpmRc::REFERENCE_H0);
            };

        let handle_bytes = out_saved_handle.to_be_bytes();
        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(obj_hierarchy);
        let mut proof_buf = [0u8; 64];
        let mut writer = Writer::new(&mut proof_buf);
        writer.bytes(proof_bytes.get(..proof_len).ok_or(TpmRc::FAILURE)?)?;
        let proof_len = writer.offset();
        let proof = &proof_buf[..proof_len];

        let sequence = if is_session {
            let s = self.global_state.context_counter;
            self.global_state.context_counter = s.wrapping_add(1);
            s
        } else {
            let s = self.global_state.object_context_counter;
            self.global_state.object_context_counter = s.wrapping_add(1);
            s
        };
        let sequence_bytes = sequence.to_be_bytes();

        // 2. Encrypt sensitive serialized data
        let encrypted = &mut sensitive_buf[..offset];
        self.encrypt_saved_context(proof, &sequence_bytes, &handle_bytes, encrypted)?;

        // 3. Compute HMAC integrity check
        let integrity = self.compute_context_integrity_hmac(
            proof,
            &sequence_bytes,
            &handle_bytes,
            out_saved_handle,
            encrypted,
        )?;

        // TPMS_CONTEXT_DATA: integrity (TPM2B_DIGEST) followed by the encrypted context
        // (TPM2B_CONTEXT_SENSITIVE).
        //
        // PORTING: exp marshaled the `TPMS_CONTEXT` response by hand (`RawContextSaveRsp`); it is
        // now a `tpm2::commands::ContextSaveRsp` with the same encoding.
        let mut context_data = [0u8; Tpm2bContextData::CAP];
        let mut writer = Writer::new(&mut context_data);
        writer.sized(integrity.get_buffer())?;
        writer.sized(encrypted)?;
        let context_data_len = writer.offset();

        let rsp = responses::ContextSave {
            context: TpmsContext {
                sequence,
                saved_handle: Handle(out_saved_handle),
                hierarchy: Handle(obj_hierarchy),
                context_blob: Tpm2bContextData::new(&context_data[..context_data_len])
                    .ok_or(TpmRc::FAILURE)?,
            },
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

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
    ///
    /// Layout: `handle(u32) | seed | name | auth | public | sensitive | qualified_name |
    /// st_clear(u8)`, where `seed` is a `TPM2B_DIGEST`.
    ///
    /// PORTING: `sensitive` is the `TPM2B`-encoded `TPMU_SENSITIVE_COMPOSITE` member of
    /// [`TransientObject::sensitive`], in place of exp's `u16 len | private[len]` provider blob.
    /// Fails with `TPM_RC_FAILURE` if `buf` is too small (exp required at least 4096 bytes,
    /// `TPM_RC_SIZE`).
    fn serialize_transient_object(obj: &TransientObject, buf: &mut [u8]) -> Result<usize, TpmRc> {
        let mut writer = Writer::new(buf);

        writer.bytes(&obj.handle.to_be_bytes())?;
        writer.value(&obj.seed)?;
        writer.value(&obj.name)?;
        writer.value(&obj.auth)?;
        writer.value(&obj.public)?;
        writer.value(&obj.sensitive)?;
        writer.value(&obj.qualified_name)?;

        let ancestor_has_st_clear: bool = obj.st_clear;
        writer.bytes(&[u8::from(ancestor_has_st_clear)])?;

        Ok(writer.offset())
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
            TpmiAlgHash::Sha256,
            proof,
            c"CONTEXT",
            sequence_bytes,
            handle_bytes,
            &mut sym_key_iv,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let (sym_key, iv) = sym_key_iv.split_first_chunk::<16>().ok_or(TpmRc::FAILURE)?;
        let mut iv: [u8; AlgSym::BLOCK_SIZE] = iv.try_into().map_err(|_| TpmRc::FAILURE)?;

        tpm2::crypto::encrypt(
            self.crypto(),
            SymmetricKey::Aes128(sym_key),
            ModeIv::Cfb(&mut iv),
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
        let total_reset_count = self.global_state.total_reset_count.to_be_bytes();
        let clear_count = self.global_state.clear_count.to_be_bytes();
        let (mac, mac_len) = if saved_handle == 0x80000002 {
            self.compute_hmac(
                TpmiAlgHash::Sha256,
                proof,
                &[
                    &total_reset_count,
                    &clear_count,
                    sequence_bytes,
                    handle_bytes,
                    sensitive_buf,
                ],
            )
        } else {
            self.compute_hmac(
                TpmiAlgHash::Sha256,
                proof,
                &[
                    &total_reset_count,
                    sequence_bytes,
                    handle_bytes,
                    sensitive_buf,
                ],
            )
        }
        .map_err(|_| TpmRc::FAILURE)?;

        OwnedDigest::from_bytes(mac.get(..mac_len).ok_or(TpmRc::FAILURE)?)
            .map_err(|_| TpmRc::FAILURE)
    }

    /// Serializes an authorization session into a raw buffer for saving.
    ///
    /// Fails with `TPM_RC_FAILURE` if `buf` is too small (exp required at least 1024 bytes,
    /// `TPM_RC_SIZE`) or a length field of `sess` exceeds its buffer.
    fn serialize_session(sess: &SessionState, buf: &mut [u8]) -> Result<usize, TpmRc> {
        let mut writer = Writer::new(buf);

        writer.bytes(&sess.session_handle.to_be_bytes())?;
        writer.value(&sess.session_type)?;
        writer.value(&sess.auth_hash)?;
        writer.value(&sess.nonce_tpm)?;
        writer.value(&sess.nonce_caller)?;

        writer.sized(
            sess.session_key
                .get(..sess.session_key_len)
                .ok_or(TpmRc::FAILURE)?,
        )?;

        writer.value(&sess.symmetric)?;
        writer.value(&sess.bind_entity)?;
        writer.value(&sess.bound_entity)?;

        if let Some(digest) = &sess.audit_digest {
            writer.bytes(&[1])?;
            writer.sized(digest.get(..sess.audit_digest_len).ok_or(TpmRc::FAILURE)?)?;
        } else {
            writer.bytes(&[0])?;
        }

        writer.sized(
            sess.audit_cp_hash
                .get(..sess.audit_cp_hash_len)
                .ok_or(TpmRc::FAILURE)?,
        )?;

        writer.sized(
            sess.policy_hash
                .get(..sess.policy_hash_len)
                .ok_or(TpmRc::FAILURE)?,
        )?;

        writer.bytes(&[u8::from(sess.is_cp_hash_defined)])?;
        writer.bytes(&[u8::from(sess.is_name_hash_defined)])?;
        writer.bytes(&[u8::from(sess.is_template_hash_defined)])?;

        writer.sized(
            sess.policy_digest
                .get(..sess.policy_digest_len)
                .ok_or(TpmRc::FAILURE)?,
        )?;

        writer.bytes(&sess.command_code.to_be_bytes())?;
        writer.bytes(&sess.start_time.to_be_bytes())?;
        writer.bytes(&sess.timeout.to_be_bytes())?;
        writer.bytes(&sess.epoch.to_be_bytes())?;

        writer.bytes(&[u8::from(sess.is_auth_value_needed)])?;
        writer.bytes(&[u8::from(sess.is_password_needed)])?;

        if let Some(counter) = sess.pcr_counter {
            writer.bytes(&[1])?;
            writer.bytes(&counter.to_be_bytes())?;
        } else {
            writer.bytes(&[0])?;
        }

        writer.bytes(&[u8::from(sess.check_nv_written)])?;
        writer.bytes(&[u8::from(sess.nv_written_state)])?;
        writer.bytes(&[sess.command_locality])?;

        Ok(writer.offset())
    }

    /// Serializes an active hash, HMAC or event sequence into a raw buffer for saving.
    ///
    /// Fails with `TPM_RC_FAILURE` if `buf` is too small (exp required at least 2048 bytes,
    /// `TPM_RC_SIZE`).
    fn serialize_sequence(seq: &ActiveSequence, buf: &mut [u8]) -> Result<usize, TpmRc> {
        let mut writer = Writer::new(buf);

        writer.bytes(&seq.handle.to_be_bytes())?;
        writer.value(&seq.auth)?;

        match &seq.sequence_type {
            SequenceType::Hash { alg } => {
                writer.bytes(&[1])?;
                writer.value(alg)?;
            }
            SequenceType::Hmac { hash_alg, key } => {
                writer.bytes(&[2])?;
                writer.value(hash_alg)?;
                writer.value(key)?;
            }
            SequenceType::Event => {
                writer.bytes(&[0])?;
            }
            SequenceType::Sign {
                associated_name,
                scheme,
                context,
            } => {
                writer.bytes(&[3])?;
                writer.value(associated_name)?;
                writer.value(&Some(*scheme))?;
                writer.value(context)?;
            }
            SequenceType::Verify {
                associated_name,
                scheme,
                context,
            } => {
                writer.bytes(&[4])?;
                writer.value(associated_name)?;
                writer.value(&Some(*scheme))?;
                writer.value(context)?;
            }
        }

        let sequence_len = u32::try_from(seq.sequence_len).map_err(|_| TpmRc::FAILURE)?;
        writer.bytes(&sequence_len.to_be_bytes())?;

        writer.bytes(&seq.first_bytes)?;
        let first_bytes_len = u8::try_from(seq.first_bytes_len).map_err(|_| TpmRc::FAILURE)?;
        writer.bytes(&[first_bytes_len])?;

        for state in &seq.hash_states {
            state.serialize(writer.reserve(StreamingHashState::SERIALIZED_SIZE)?);
        }

        if matches!(
            seq.sequence_type,
            SequenceType::Sign { .. } | SequenceType::Verify { .. }
        ) {
            writer.bytes(
                seq.sequence_buffer
                    .get(..seq.sequence_len)
                    .ok_or(TpmRc::FAILURE)?,
            )?;
        }

        Ok(writer.offset())
    }
}
