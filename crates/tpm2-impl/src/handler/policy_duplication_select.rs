use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::commands::{PolicyDuplicationSelect, PolicyDuplicationSelectHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyDuplicationSelect] (`0x197`) command.
    ///
    /// # Description
    /// This command binds a target object Name (`object_name`) and a new parent Name (`new_parent_name`) to the policy session,
    /// restricting any subsequent duplication operation to the specified targets.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.15 (TPM2_PolicyDuplicationSelect).
    ///
    /// # Relationships
    /// - Used in conjunction with [TpmCc::Duplicate](duplicate.rs) to restrict which key can be duplicated to which new parent.
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    pub fn policy_duplication_select(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<PolicyDuplicationSelectHandles>()?;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<PolicyDuplicationSelect>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Validate object_name and new_parent_name structures
        if cmd.include_object {
            self.validate_name_structure(&cmd.object_name, Position::parameter(1))?;
        } else if cmd.object_name.get_size() > 66 {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }
        self.validate_name_structure(&cmd.new_parent_name, Position::parameter(2))?;

        // Validate session expiration
        self.validate_policy_session(policy_session, Position::handle(1))?;

        // 1. Retrieve policy session state details
        let (
            auth_hash,
            policy_digest,
            policy_digest_len,
            command_code,
            policy_hash_len,
            bind_entity,
        ) = {
            let session_state = self
                .global_state
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
                session_state.command_code,
                session_state.policy_hash_len,
                session_state.bind_entity,
            )
        };

        if bind_entity != Handle::RH_NULL {
            return Err(TpmRc::CPHASH);
        }

        // nameHash in session context must be empty (i.e. policy_hash_len == 0)
        if policy_hash_len != 0 {
            return Err(TpmRc::CPHASH);
        }

        // commandCode in session context must be empty
        if command_code != 0 {
            return Err(TpmRc::COMMAND_CODE);
        }

        // 2. Compute nameHash = hash(objectName || newParentName)
        let (name_hash, name_hash_len) = self.compute_hash(
            auth_hash,
            &[
                cmd.object_name.get_buffer(),
                cmd.new_parent_name.get_buffer(),
            ],
        )?;

        // 3. Compute new policy digest
        // policyDigest_new = hash(policyDigest_old || TPM_CC_PolicyDuplicationSelect || objectName (if includeObject) || newParentName || includeObject)
        let include_obj = cmd.include_object;
        let include_obj_byte = cmd.include_object as u8;

        let (new_digest, new_digest_len) = if include_obj {
            self.compute_hash(
                auth_hash,
                &[
                    &policy_digest[..policy_digest_len],
                    &(TpmCc::PolicyDuplicationSelect.code()).to_be_bytes(),
                    cmd.object_name.get_buffer(),
                    cmd.new_parent_name.get_buffer(),
                    &[include_obj_byte],
                ],
            )?
        } else {
            self.compute_hash(
                auth_hash,
                &[
                    &policy_digest[..policy_digest_len],
                    &(TpmCc::PolicyDuplicationSelect.code()).to_be_bytes(),
                    cmd.new_parent_name.get_buffer(),
                    &[include_obj_byte],
                ],
            )?
        };

        // 4. Update session state
        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            session_state.policy_hash[..name_hash_len].copy_from_slice(&name_hash[..name_hash_len]);
            session_state.policy_hash_len = name_hash_len;
            session_state.is_name_hash_defined = true;
            session_state.command_code = TpmCc::Duplicate.code();
        }

        // 5. Write response
        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
