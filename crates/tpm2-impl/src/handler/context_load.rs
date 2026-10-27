use crate::{
    handler::{CommandHandler, SessionState, TransientObject},
    owned::{OwnedAuth, OwnedDigest, OwnedName, OwnedNonce, OwnedPublic, OwnedSensitiveData},
    req_resp::RequestThenResponse,
    storage::NvStorage,
    timer::TpmTimer,
};

struct TransientObjectFields {
    seed: [u8; 64],
    seed_len: usize,
    external: bool,
    public_only: bool,
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
use tpm2::commands::responses;
use tpm2::crypto::kdf::kdfa_bits;
use tpm2::crypto::{CryptoProvider, Direction, HmacStream, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TPM2_MAX_CONTEXT_SIZE, TpmHt};
use tpm2::{TpmSe, TpmiAlgHash};

use super::context_save::{CONTEXT_ENCRYPTION_ALG, CONTEXT_FINGERPRINT_SIZE};

/// `MAX_CONTEXT_SIZE` of this TPM's profile: the capacity of `TPM2B_CONTEXT_SENSITIVE` (TPM 2.0
/// Part 2, Table "Definition of TPM2B_CONTEXT_SENSITIVE Structure": "buffer\[size\]{:MAX_CONTEXT_SIZE}").
/// The value is implementation-specific; the C references are configured with the same value
/// (`testing/patches/*/profile-max-context-size.patch`).
const MAX_CONTEXT_SIZE: usize = 2264;

/// The capacity of `TPM2B_CONTEXT_DATA`: TPM 2.0 Part 2, Table "Definition of TPM2B_CONTEXT_DATA
/// Structure": "buffer\[size\] {:sizeof(TPMS_CONTEXT_DATA)}", where Table "Definition of
/// TPMS_CONTEXT_DATA Structure" is "integrity | TPM2B_DIGEST" followed by "encrypted |
/// TPM2B_CONTEXT_SENSITIVE": `(2 + sizeof(TPMU_HA)) + (2 + MAX_CONTEXT_SIZE)`, with the largest
/// implemented digest (SHA-512, 64 octets). A larger `contextBlob` size is `TPM_RC_SIZE` while it
/// is unmarshaled, before any missing bytes (`TPM_RC_INSUFFICIENT`).
pub(crate) const CONTEXT_DATA_CAPACITY: usize = (2 + 64) + (2 + MAX_CONTEXT_SIZE);

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
        // TPM 2.0 Part 2, Table "Definition of (TPM_HANDLE) TPMI_DH_SAVED Type": "{HMAC_SESSION_FIRST
        // : HMAC_SESSION_LAST} | an HMAC session context", "{POLICY_SESSION_FIRST:POLICY_SESSION_LAST}
        // | a policy session context", "0x80000000", "0x80000001", "0x80000002", "#TPM_RC_VALUE";
        // and TPM_HC: "HMAC_SESSION_LAST | (HMAC_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1)". A
        // session handle beyond MAX_ACTIVE_SESSIONS fails here, before `hierarchy` is read.
        if tpm2::TpmiDhSaved::try_from(saved_handle).is_err() {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let hierarchy = request
            .try_unmarshal::<Handle>()
            .map_err(|e| e.with_position(Position::parameter(1)))?;
        // `TPMI_RH_HIERARCHY+`, including the firmware-limited and SVN-limited hierarchies (Part 2,
        // Table "Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY Type"), whose unavailable proof
        // then fails the integrity check (`resolve_hierarchy_proof`, `limited_hierarchy_error`).
        if tpm2::TpmiRhHierarchy::try_from(hierarchy).is_err() {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let blob_size = request
            .try_unmarshal::<u16>()
            .map_err(|e| e.with_position(Position::parameter(1)))? as usize;
        if blob_size > CONTEXT_DATA_CAPACITY {
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

        // Context blob layout (see `TPM2_ContextSave`):
        //   integrity: TPM2B_DIGEST
        //   encrypted: TPM2B_CONTEXT_SENSITIVE = size || CFB(sequence || entity)
        //
        // Malformed input is rejected with TPM_RC_SIZE / TPM_RC_INTEGRITY. Only
        // inconsistencies detected *after* the integrity HMAC has been verified
        // (i.e. in a blob the TPM itself produced) are treated as a TPM failure.
        let mut slice = blob;
        // `TPM2B_DIGEST_Unmarshal` of the integrity value: its result (e.g. a bare
        // `TPM_RC_INSUFFICIENT` for an empty or truncated blob) is returned unmodified.
        let integrity = tpm2::Tpm2bDigest::unmarshal(&mut slice).map_err(|e| e.to_rc())?;
        // The integrity value must be exactly one digest of the integrity hash.
        if integrity.get_size() as usize
            != crate::handler::context_integrity_hash_alg().digest_size()
        {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        // The protected area must at least be the size of the sequence fingerprint before the
        // integrity check (the TCG reference: "Make sure that the context blob has enough space
        // for the fingerprint.", `size < sizeof(in->context.sequence)`), so a short blob of a
        // limited hierarchy reaches the unavailable proof (`TPM_RC_FW_LIMITED`/
        // `TPM_RC_SVN_LIMITED`) first. The encrypted size field is checked after it.
        if slice.len() < CONTEXT_FINGERPRINT_SIZE {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        // Everything after the integrity value is integrity protected.
        let protected = slice;

        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(hierarchy.0)?;
        let proof = &proof_bytes[..proof_len];

        // 1. Verify HMAC integrity signature before looking at any protected
        // byte (TPM 2.0 Part 1, "Context Confidentiality Protection").
        self.verify_context_integrity(
            proof,
            sequence,
            saved_handle,
            protected,
            integrity.get_buffer(),
        )?;

        // From here on the blob is known to have been produced by this TPM, so
        // any inconsistency indicates a TPM failure rather than bad input.
        let mut protected_slice = protected;
        let enc_size = u16::unmarshal(&mut protected_slice)
            .map_err(|_| TpmRc::INTEGRITY.with(Position::parameter(1)))?
            as usize;
        if protected_slice.len() != enc_size || enc_size < CONTEXT_FINGERPRINT_SIZE {
            // An authentic blob of another context layout (see `malformed_context`).
            return Err(TpmRc::INTEGRITY.with(Position::parameter(1)));
        }
        let enc_slice = protected_slice;

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

        // 3. The decrypted fingerprint must match `sequence`; otherwise the TPM
        // is being attacked or is broken (TPM 2.0 Part 1, "Context
        // Confidentiality Protection" / Part 3, TPM2_ContextLoad).
        if sensitive_buf[..CONTEXT_FINGERPRINT_SIZE] != sequence.to_be_bytes() {
            return Err(TpmRc::FAILURE);
        }
        let plaintext = &sensitive_buf[CONTEXT_FINGERPRINT_SIZE..enc_size];

        let is_session = matches!(
            Handle(saved_handle.0).handle_type(),
            Some(TpmHt::HMACSession | TpmHt::PolicySession)
        );
        let is_sequence = saved_handle.0 == 0x80000001;
        let is_transient = saved_handle.0 == 0x80000000 || saved_handle.0 == 0x80000002;

        // `TPM2_ContextLoad` has no handles: every context error refers to parameter 1
        // (`RC_ContextLoad_context`).
        if !is_session && !is_sequence && !is_transient {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        if (is_session || is_sequence) && hierarchy.0 != Handle::RH_NULL.0 {
            return Err(TpmRc::HIERARCHY.with(Position::parameter(1)));
        }

        // `HierarchyIsEnabled` is checked for object contexts after the integrity check.
        let hierarchy_disabled = (hierarchy.0 == Handle::RH_OWNER.0
            && !self.context.state.sh_enable)
            || (hierarchy.0 == Handle::RH_ENDORSEMENT.0 && !self.context.state.eh_enable)
            || (hierarchy.0 == Handle::RH_PLATFORM.0 && !self.context.state.ph_enable);
        if !is_session && hierarchy_disabled {
            return Err(TpmRc::HIERARCHY.with(Position::parameter(1)));
        }

        let loaded_handle = if is_session {
            self.nv_clear_orderly()?;
            // `SequenceNumberForSavedContextIsValid`: only the latest saved context of a session
            // that is currently saved (neither loaded nor flushed) can be loaded.
            if !self
                .context
                .state
                .saved_session_sequence_is_valid(saved_handle.0, sequence)
            {
                return Err(TpmRc::HANDLE.with(Position::parameter(1)));
            }
            // `SessionContextLoad`: a free session slot is required, and when only one is left
            // while the context gap is exhausted, only the oldest saved context may use it.
            let free_slots = self
                .context
                .state
                .active_sessions
                .iter()
                .filter(|s| s.is_none())
                .count();
            if free_slots == 0 {
                return Err(TpmRc::SESSION_MEMORY);
            }
            let slot = (saved_handle.0 & 0x00FF_FFFF) as usize;
            if free_slots == 1
                && self.context.state.context_gap_exhausted()
                && self.context.state.oldest_saved_session_slot() != Some(slot)
            {
                return Err(TpmRc::CONTEXT_GAP);
            }
            // 3. Deserialize session context
            let sess = Self::deserialize_session(plaintext).map_err(malformed_context)?;
            let handle = sess.session_handle;
            self.context.state.remove_saved_session(handle);
            self.context.state.add_session(sess)?;
            handle
        } else if is_sequence {
            let mut seq = Self::deserialize_sequence(plaintext).map_err(malformed_context)?;
            let (slot, handle) = self.context.state.find_empty_sequence_slot()?;
            seq.handle = handle;
            self.context.state.active_sequences[slot] = Some(seq);
            handle
        } else {
            // 3. Unmarshal decrypted buffer into fields
            let (fields, ancestor_has_st_clear) =
                Self::unmarshal_decrypted_context(plaintext).map_err(malformed_context)?;

            // 4. Resolve empty slot and load transient object
            let (slot, handle) = self.context.state.find_empty_transient_slot(true)?;

            self.context.state.transient_parents[slot] = None;
            self.context.state.transient_objects[slot] = Some(TransientObject {
                handle,
                seed: fields.seed,
                seed_len: fields.seed_len,
                external: fields.external,
                public_only: fields.public_only,
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

        let rsp = responses::ContextLoad {
            loaded_handle: Handle(loaded_handle),
        };

        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Verifies the integrity of a context blob: an HMAC with `CONTEXT_INTEGRITY_HASH_ALG` keyed with
    /// the hierarchy proof.
    ///
    /// `protected_data` is every byte of the context blob after the integrity
    /// value (`encrypted.size || encrypted.buffer` for well-formed blobs), so
    /// any modification of the size field or appended bytes is detected.
    fn verify_context_integrity(
        &self,
        proof: &[u8],
        sequence: u64,
        saved_handle: Handle,
        protected_data: &[u8],
        expected_mac: &[u8],
    ) -> Result<(), TpmRc> {
        let mut mac_ctx = HmacStream::new(
            self.crypto(),
            crate::handler::context_integrity_hash_alg(),
            proof,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        mac_ctx
            .update(&self.context.state.total_reset_count.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        if saved_handle.0 == 0x80000002 {
            mac_ctx
                .update(&self.context.state.clear_count.to_be_bytes())
                .map_err(|_| TpmRc::FAILURE)?;
        }
        mac_ctx
            .update(&sequence.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        mac_ctx
            .update(&saved_handle.0.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        mac_ctx.update(protected_data).map_err(|_| TpmRc::FAILURE)?;
        let mut mac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mac = mac_ctx.finalize(&mut mac_buf).map_err(|_| TpmRc::FAILURE)?;

        if mac.digest() != expected_mac {
            return Err(TpmRc::INTEGRITY.with(Position::parameter(1)));
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
        kdfa_bits(
            self.crypto(),
            crate::handler::context_integrity_hash_alg(),
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

        self.sym_encrypt_decrypt(
            CONTEXT_ENCRYPTION_ALG,
            &sym_key,
            &mut iv,
            Direction::Decrypt,
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

        // seedValue: 1-byte length followed by the seed bytes (see `serialize_transient_object`).
        let seed_len = u8::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? as usize;
        if seed_len > 64 || slice.len() < seed_len {
            return Err(TpmRc::FAILURE);
        }
        let (seed, seed_len) = TransientObject::seed_from_bytes(&slice[..seed_len]);
        slice = &slice[seed_len..];

        let name = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let auth = OwnedAuth::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        // The saved public area may have `nameAlg = TPM_ALG_NULL`: TPM 2.0 Part 3,
        // TPM2_LoadExternal: "If *nameAlg* is `TPM_ALG_NULL`, then the Name is the Empty
        // Buffer." Such an object can be saved and loaded again like any other, so
        // the area is read as a `TPMT_PUBLIC+` (strict unmarshaling turned a valid context of
        // such an object into TPM_RC_FAILURE).
        let public = OwnedPublic::unmarshal_nullable(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let priv_len = u16::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? as usize;
        if slice.len() < priv_len {
            return Err(TpmRc::FAILURE);
        }
        let mut priv_buf = [0u8; 1536];
        priv_buf[..priv_len].copy_from_slice(&slice[..priv_len]);
        slice = &slice[priv_len..];
        let qualified_name = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        // Flags byte: bit 0 = ancestor stClear, bit 1 = external, bit 2 = public-only.
        let flags = slice.first().copied().unwrap_or(0);
        let ancestor_has_st_clear = flags & 1 != 0;

        Ok((
            TransientObjectFields {
                seed,
                seed_len,
                external: flags & 2 != 0,
                public_only: flags & 4 != 0,
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
        // Session flags byte (see `serialize_session`): bit 0 = `isTemplateHashDefined`,
        // bit 1 = `isDaBound`, bit 2 = `isLockoutBound`.
        let session_flags = if !slice.is_empty() {
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
            is_template_hash_defined: session_flags & 1 != 0,
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
            is_da_bound: session_flags & 0b010 != 0,
            is_lockout_bound: session_flags & 0b100 != 0,
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

/// The error for an authentic context (its integrity HMAC is valid and its decrypted fingerprint
/// matches) whose contents do not have this TPM's context layout, e.g. a context saved by an
/// earlier version of this TPM with the same proof: `TPM_RC_INTEGRITY + P1`. Other errors pass
/// unchanged.
///
/// The specification only requires the fingerprint check (TPM 2.0 Part 3, TPM2_ContextLoad:
/// "The TPM shall perform a check on the decrypted context as described in the \"Context
/// Confidentiality Protection\" clause of TPM 2.0 Part 1 and enter failure mode if the check
/// fails."; the context data itself is not specified: Part 2, `TPM2B_CONTEXT_SENSITIVE`: "This is
/// an informative table that is included in the specification only to allow calculation of the
/// maximum size for `TPM2B_CONTEXT_DATA`."). A blob that is not a valid context of this TPM is
/// not a TPM failure
/// but input the TPM cannot load, the same as a blob whose integrity fails ("If the integrity HMAC
/// of the saved context is not valid, the TPM shall return `TPM_RC_INTEGRITY`.").
fn malformed_context(rc: TpmRc) -> TpmRc {
    if rc == TpmRc::FAILURE {
        TpmRc::INTEGRITY.with(Position::parameter(1))
    } else {
        rc
    }
}
