use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{PolicySecret, PolicySecretHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bDigest, Tpm2bTimeout, TpmHt, TpmNt, TpmSe, TpmaNv, TpmtTkAuth};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicySecret] (`0x151`) command.
    ///
    /// # Description
    /// This command makes the policy session conditional on the caller proving knowledge of a secret (such as the authValue
    /// of a hierarchy or key) via an authorization session. It extends the policy digest and optionally returns an authorization ticket.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.4 (TPM2_PolicySecret).
    ///
    /// # Relationships
    /// - Requires validation of the authority's authorization (`auth_handle`) in the session buffer.
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    /// - Generates a verification ticket (`policy_ticket`) that can be used later to satisfy authorization requirements.
    pub fn policy_secret(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<PolicySecretHandles>()?;
        let auth_handle = handles.auth_handle.0;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<PolicySecret>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Validate session expiration
        self.validate_policy_session(policy_session, Position::handle(2))?;

        // 1. Retrieve policy session state details

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

        // Validate policy session parameters if Policy session
        let mut auth_timeout = 0u64;
        if session_type == TpmSe::Policy {
            let session_state = self
                .global_state
                .session(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(2)))?;
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
        }

        // 2. Compute authorization object name
        let auth_name = self.context.handle_name(self.global_state, auth_handle);

        // 3. Compute new policy digest
        // Step 1: digest1 = hash(policyDigest_old || TPM_CC_PolicySecret || authName)
        let (digest1, digest1_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &0x00000151u32.to_be_bytes(), // TPM_CC_PolicySecret
                auth_name.get_buffer(),
            ],
        )?;

        // Step 2: new_digest = hash(digest1 || policyRef)
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

        // 4. Generate policy ticket & response timeout. No ticket is produced for a trial session
        //    or for a PIN Pass NV Index (a ticket would allow replaying the authorization without
        //    incrementing pinCount), as in C `TPM2_PolicySecret`.
        let is_pin_pass_index = Handle(auth_handle).handle_type() == Some(TpmHt::NVIndex)
            && self.read_nv_public(auth_handle).is_some_and(|nv_public| {
                nv_public.attributes.get_index_type() == Ok(TpmNt::PinPass)
            });
        let mut hmac_digest_bytes = [0u8; 64];
        let timeout_bytes;
        let (timeout, policy_ticket) = if cmd.expiration < 0
            && session_type == TpmSe::Policy
            && !is_pin_pass_index
        {
            let key_hierarchy = self.entity_get_hierarchy(auth_handle)?;

            let (proof_bytes, proof_len, ticket_hierarchy) =
                self.resolve_hierarchy_proof(key_hierarchy);

            let mut hmac_input = [0u8; 512];
            let mut offset = 0;

            // 1. tag (2 bytes, big endian 0x8023): 0x8023u16.to_be_bytes()
            hmac_input[offset..offset + 2].copy_from_slice(&0x8023u16.to_be_bytes());
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

            let ticket_digest = Tpm2bDigest::from_bytes(hmac_digest.digest()).unwrap();
            let ticket = TpmtTkAuth::Secret(tpm2::Handle(ticket_hierarchy), ticket_digest);

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
                TpmtTkAuth::Secret(tpm2::Handle(0x40000007), Tpm2bDigest::default()),
            )
        };

        let rsp = responses::PolicySecret {
            timeout,
            policy_ticket,
        };

        // 5. Write response
        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Returns the hierarchy an authorization entity belongs to, as C `EntityGetHierarchy`
    /// (Entity.c) does; used to select the proof for `TPM2_PolicySecret` tickets.
    ///
    /// - `TPM_RH_PLATFORM`, `TPM_RH_ENDORSEMENT` and `TPM_RH_NULL` belong to themselves; every
    ///   other permanent handle (`TPM_RH_OWNER`, `TPM_RH_LOCKOUT`, ...) and every PCR belongs to
    ///   `TPM_RH_OWNER`.
    /// - An NV Index belongs to `TPM_RH_PLATFORM` if `TPMA_NV_PLATFORMCREATE` is set, otherwise to
    ///   `TPM_RH_OWNER`.
    /// - An object belongs to its own hierarchy.
    fn entity_get_hierarchy(&mut self, handle: u32) -> Result<u32, TpmRc> {
        match Handle(handle).handle_type() {
            Some(TpmHt::Permanent) => Ok(
                if handle == Handle::RH_PLATFORM.0
                    || handle == Handle::RH_ENDORSEMENT.0
                    || handle == Handle::RH_NULL.0
                {
                    handle
                } else {
                    Handle::RH_OWNER.0
                },
            ),
            Some(TpmHt::NVIndex) => {
                let platform_create = self
                    .read_nv_public(handle)
                    .is_some_and(|nv_public| nv_public.attributes.contains(TpmaNv::PLATFORMCREATE));
                Ok(if platform_create {
                    Handle::RH_PLATFORM.0
                } else {
                    Handle::RH_OWNER.0
                })
            }
            Some(TpmHt::Transient) | Some(TpmHt::Persistent) => {
                Ok(self.resolve_object(handle, Position::handle(1))?.hierarchy)
            }
            Some(TpmHt::PCR) => Ok(Handle::RH_OWNER.0),
            _ => Ok(Handle::RH_NULL.0),
        }
    }
}
