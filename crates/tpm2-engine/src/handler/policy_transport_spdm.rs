use crate::Platform;
use crate::handle_checks::{Tpmi, check};
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::commands::PolicyTransportSPDM;
use tpm2::crypto::Crypto;
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmCc, TpmSe, TpmiAlgHash};

/// Validates an optional key Name parameter of `TPM2_PolicyTransportSPDM()` (TPM 2.0 Part 3):
/// "If the *reqKeyName* or *tpmKeyName* parameter is provided (not Empty Buffer), it is
/// required to be a valid object Name using *nameAlg* other than `TPM_ALG_NULL`. If the first
/// two octets of *reqKeyName* or *tpmKeyName* are not a valid hash algorithm, the TPM shall
/// return `TPM_RC_HASH`. If the remainder of the Name is not the size of the indicated digest,
/// the TPM shall return `TPM_RC_SIZE`." A Name shorter than its algorithm ID cannot be a valid
/// object Name either (`TPM_RC_SIZE`).
fn check_key_name(name: &[u8], pos: Position) -> Result<(), TpmRc> {
    if name.is_empty() {
        return Ok(());
    }
    let [hi, lo, digest @ ..] = name else {
        return Err(TpmRc::SIZE.with(pos));
    };
    let hash =
        TpmiAlgHash::try_from(u16::from_be_bytes([*hi, *lo])).map_err(|_| TpmRc::HASH.with(pos))?;
    if digest.len() != hash.digest_size() {
        return Err(TpmRc::SIZE.with(pos));
    }
    Ok(())
}

impl<'b, C: Crypto, P: Platform<Crypto = C>> CommandHandler<'b, P> {
    /// Handles the [TpmCc::PolicyTransportSPDM] (`0x1A1`) command.
    ///
    /// # Description
    /// This command gates a policy on the presence of an SPDM secure channel, optionally
    /// established with a specific requester key and/or TPM key. It is a deferred assertion:
    /// the channel and the keys are checked when the session is used for authorization
    /// (`TPM_RC_CHANNEL`, `TPM_RC_CHANNEL_KEY`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, TPM2_PolicyTransportSPDM (added in
    /// version 184).
    ///
    /// # Relationships
    /// - Extends the policy digest of a policy or trial session created via `StartAuthSession`.
    /// - The TPM SPDM key Names can be computed from `TPM2_GetCapability(TPM_CAP_PUB_KEYS)`.
    pub fn policy_transport_spdm(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PolicyTransportSPDM>()?;
        let [policy_session] = handles;
        check(policy_session, Tpmi::ShPolicy, Position::handle(1))?;
        let policy_session = policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<PolicyTransportSPDM>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.validate_policy_session(policy_session, Position::handle(1))?;

        let (auth_hash, policy_digest, policy_digest_len, sec_channel) = {
            let session_state = self
                .context
                .state
                .session(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::HANDLE.with(Position::handle(1)));
            }
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
                session_state.sec_channel,
            )
        };

        // "If policySession→checkSecureChannel is SET (i.e., TPM2_PolicyTransportSPDM() has
        // been previously executed), the TPM shall return TPM_RC_VALUE."
        if sec_channel.check_secure_channel {
            return Err(TpmRc::VALUE.to_rc());
        }

        let req_key_name = cmd.req_key_name.get_buffer();
        let tpm_key_name = cmd.tpm_key_name.get_buffer();
        check_key_name(req_key_name, Position::parameter(1))?;
        check_key_name(tpm_key_name, Position::parameter(2))?;

        // scKeyNameHash, if either Name is provided; otherwise the Empty Buffer.
        let (sc_key_name_hash, sc_key_name_hash_len) =
            if !req_key_name.is_empty() || !tpm_key_name.is_empty() {
                self.context
                    .sc_key_name_hash(auth_hash, req_key_name, tpm_key_name)?
            } else {
                ([0u8; 64], 0)
            };

        // policyDigest_new = H_policyAlg(policyDigest_old || TPM_CC_PolicyTransportSPDM ||
        // scKeyNameHash)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &TpmCc::PolicyTransportSPDM.code().to_be_bytes(),
                &sc_key_name_hash[..sc_key_name_hash_len],
            ],
        )?;

        {
            let session_state = self
                .context
                .state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            let sc = &mut session_state.sec_channel;
            sc.check_secure_channel = true;
            sc.check_req_key = !req_key_name.is_empty();
            sc.check_tpm_key = !tpm_key_name.is_empty();
            sc.sc_key_name_hash = sc_key_name_hash;
            sc.sc_key_name_hash_len = sc_key_name_hash_len;
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
