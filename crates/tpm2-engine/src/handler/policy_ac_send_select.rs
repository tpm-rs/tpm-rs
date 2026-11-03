// `TPM2_Policy_AC_SendSelect()` was deprecated in version 184 (so is its `tpm2` command
// structure); a TPM may still implement it, as the TCG reference does.
#![allow(deprecated)]

use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::PolicyACSendSelect;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmCc, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyACSendSelect] (`0x196`) command.
    ///
    /// # Description
    /// TPM 2.0 Part 3, TPM2_Policy_AC_SendSelect (deprecated in version 184): "This command
    /// allows qualification of the sending (copying) of an Object to an Attached Component
    /// (AC)." "If either policySession→cpHash or policySession→nameHash has been previously
    /// set, the TPM shall return `TPM_RC_CPHASH`. Otherwise, policySession→nameHash will be set
    /// to nameHash ≔ H_policyAlg(objectName ∥ authHandleName ∥ acName)", the policyDigest is
    /// extended with H_policyAlg(policyDigest_old ∥ TPM_CC_Policy_AC_SendSelect ∥
    /// [objectName ∥] authHandleName ∥ acName ∥ includeObject) (objectName only if
    /// *includeObject* is SET), and "*policySession*→*commandCode* is set to
    /// `TPM_CC_AC_Send`".
    ///
    /// The spec is silent on a session whose commandCode is already set; as the TCG reference,
    /// that is `TPM_RC_COMMAND_CODE`. This TPM implements no Attached Component (no
    /// `TPM2_AC_Send`, like every reference), so the session can then authorize nothing. The
    /// nameHash marks the session's cpHash as occupied (*isNameHashDefined*), so that a later
    /// `TPM2_PolicyCpHash`/`NameHash`/`Parameters`/`Template` returns `TPM_RC_CPHASH` (see the
    /// `bug-fix-policy-ac-send-select-name-hash` patch of the differential tests).
    pub fn policy_ac_send_select(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PolicyACSendSelect>()?;
        let [policy_session] = handles;
        check(policy_session, Tpmi::ShPolicy, Position::handle(1))?;
        let policy_session = policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<PolicyACSendSelect>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.validate_policy_session(policy_session, Position::handle(1))?;

        let (auth_hash, policy_digest, policy_digest_len) = {
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
            // cpHash/nameHash (and the pHash/templateHash sharing their memory) already set.
            if session_state.policy_hash_len != 0 {
                return Err(TpmRc::CPHASH);
            }
            if session_state.command_code != 0 {
                return Err(TpmRc::COMMAND_CODE);
            }
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
            )
        };

        let object_name = cmd.object_name.get_buffer();
        let auth_handle_name = cmd.auth_object_name.get_buffer();
        let ac_name = cmd.ac_name.get_buffer();

        // nameHash = H(objectName || authHandleName || acName)
        let (name_hash, name_hash_len) =
            self.compute_hash(auth_hash, &[object_name, auth_handle_name, ac_name])?;

        // policyDigest_new = H(policyDigest_old || TPM_CC_Policy_AC_SendSelect ||
        //                      [objectName ||] authHandleName || acName || includeObject)
        let cc_bytes = TpmCc::PolicyACSendSelect.code().to_be_bytes();
        let include_object = [u8::from(cmd.include_object)];
        let included_name: &[u8] = if cmd.include_object { object_name } else { &[] };
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &cc_bytes,
                included_name,
                auth_handle_name,
                ac_name,
                &include_object,
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
            session_state.policy_hash[..name_hash_len].copy_from_slice(&name_hash[..name_hash_len]);
            session_state.policy_hash_len = name_hash_len;
            session_state.command_code = TpmCc::ACSend.code();
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])
    }
}
