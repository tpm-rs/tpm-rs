use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::PolicyTicket;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Ticket, TpmCc, TpmSe, TpmSt, TpmiAlgHash};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::PolicyTicket] (`0x172`) command.
    ///
    /// # Description
    /// This command allows policy authorization to be evaluated using a previously generated ticket
    /// instead of re-verifying a secret or an asymmetric/HMAC signature directly. The ticket represents
    /// a validated authorization that was produced by commands such as `TPM2_PolicySigned` or `TPM2_PolicySecret`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.5 (TPM2_PolicyTicket).
    ///
    /// # Relationships
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    /// - Validates authorization tickets returned by [TpmCc::PolicySigned](policy_signed.rs) or [TpmCc::PolicySecret](policy_secret.rs).
    pub fn policy_ticket(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PolicyTicket>()?;
        let [policy_session] = handles;
        check(policy_session, Tpmi::ShPolicy, Position::handle(1))?;
        let policy_session = policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<PolicyTicket>(handles)?;
        // PORTING: exp's `TpmtTkAuth` unmarshal typed the ticket hierarchy as
        // `TPMI_RH_HIERARCHY`; the new type holds a plain `Handle`.
        check(
            cmd.ticket.hierarchy(),
            Tpmi::RhHierarchy,
            Position::parameter(5),
        )?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.validate_policy_session(policy_session, Position::handle(1))?;

        let (auth_hash, policy_digest, policy_digest_len, session_type) = {
            let session_state = self
                .global_state
                .session(policy_session)
                .ok_or(TpmRc::REFERENCE_H1)?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::HANDLE.with(Position::handle(1)));
            }
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
                session_state.session_type,
            )
        };

        let ticket_tag = cmd.ticket.tag();
        if ticket_tag != TpmSt::AUTH_SECRET && ticket_tag != TpmSt::AUTH_SIGNED {
            return Err(TpmRc::VALUE.with(Position::parameter(5)));
        }

        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(cmd.ticket.hierarchy().0);

        let cp_hash_a = cmd.cp_hash_a.as_slice();
        let policy_ref = cmd.policy_ref.as_slice();
        let auth_name = cmd.auth_name.as_slice();

        let mut hmac_input = [0u8; 512];
        let mut offset = 0;

        // 1. tag
        hmac_input[offset..offset + 2].copy_from_slice(&ticket_tag.id().to_be_bytes());
        offset += 2;

        // 2. cpHashA raw bytes
        let cp_hash_len = cp_hash_a.len();
        hmac_input[offset..offset + cp_hash_len].copy_from_slice(cp_hash_a);
        offset += cp_hash_len;

        // 3. policyRef raw bytes
        let policy_ref_len = policy_ref.len();
        hmac_input[offset..offset + policy_ref_len].copy_from_slice(policy_ref);
        offset += policy_ref_len;

        // 4. authName raw bytes
        let auth_name_len = auth_name.len();
        hmac_input[offset..offset + auth_name_len].copy_from_slice(auth_name);
        offset += auth_name_len;

        let timeout = cmd.timeout.as_slice();
        let mut timeout_val = 0u64;
        if !timeout.is_empty() {
            let Ok(buf) = <[u8; 8]>::try_from(timeout) else {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            };
            timeout_val = u64::from_be_bytes(buf);
        }
        let expires_on_reset = (timeout_val & (1u64 << 63)) != 0;
        let auth_timeout_masked = timeout_val & !(1u64 << 63);

        // 5. timeout (8 bytes, big endian auth_timeout_masked)
        hmac_input[offset..offset + 8].copy_from_slice(&auth_timeout_masked.to_be_bytes());
        offset += 8;

        // 6. If auth_timeout_masked != 0
        if auth_timeout_masked != 0 {
            // epoch (8 bytes, big endian self.global_state.time_epoch)
            let epoch_val = self.global_state.time_epoch;
            hmac_input[offset..offset + 8].copy_from_slice(&epoch_val.to_be_bytes());
            offset += 8;

            // If expiresOnReset
            if expires_on_reset {
                // resetCount (8 bytes, big endian self.global_state.total_reset_count)
                let reset_count_val = self.global_state.total_reset_count;
                hmac_input[offset..offset + 8].copy_from_slice(&reset_count_val.to_be_bytes());
                offset += 8;
            }
        }

        let mut hmac_digest_bytes = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let hmac_digest = tpm2::crypto::hmac(
            self.crypto(),
            TpmiAlgHash::Sha256,
            &proof_bytes[..proof_len],
            &hmac_input[..offset],
            &mut hmac_digest_bytes,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        if !crate::util::constant_time_eq(cmd.ticket.digest().as_slice(), hmac_digest.digest()) {
            return Err(TpmRc::TICKET.with(Position::parameter(5)));
        }

        if session_type == TpmSe::Policy && auth_timeout_masked != 0 {
            let current_time = self.global_state.tpm_time_ms;
            if auth_timeout_masked < current_time {
                return Err(TpmRc::EXPIRED.with(Position::parameter(1)));
            }
        }

        if !cp_hash_a.is_empty() {
            if cp_hash_a.len() != policy_digest_len {
                return Err(TpmRc::SIZE.with(Position::parameter(2)));
            }
            let session_state = self
                .global_state
                .session(policy_session)
                .ok_or(TpmRc::REFERENCE_H1)?;
            if session_state.policy_hash_len != 0
                && cp_hash_a != &session_state.policy_hash[..session_state.policy_hash_len]
            {
                return Err(TpmRc::CPHASH);
            }
        }

        let cc_val: u32 = if ticket_tag == TpmSt::AUTH_SIGNED {
            TpmCc::PolicySigned.code()
        } else {
            TpmCc::PolicySecret.code()
        };

        // digest1 = hash(policyDigest_old || cc_val || authName)
        let (digest1, digest1_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &cc_val.to_be_bytes(),
                auth_name,
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
                .ok_or(TpmRc::REFERENCE_H1)?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            if !cp_hash_a.is_empty() {
                session_state.policy_hash[..cp_hash_a.len()].copy_from_slice(cp_hash_a);
                session_state.policy_hash_len = cp_hash_a.len();
                session_state.is_cp_hash_defined = true;
            }
            if auth_timeout_masked != 0
                && (session_state.timeout == 0 || session_state.timeout > auth_timeout_masked)
            {
                session_state.timeout = auth_timeout_masked;
            }
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
