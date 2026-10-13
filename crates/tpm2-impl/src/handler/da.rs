use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::commands::{DictionaryAttackLockReset, DictionaryAttackParameters};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the `TPM2_DictionaryAttackLockReset` (`0x00000139`) command.
    ///
    /// # Description
    /// This command cancels the effect of a TPM lockout due to a number of successive authorization failures.
    /// If this command is properly authorized, `failed_tries` is set to zero.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 25.2 (TPM2_DictionaryAttackLockReset).
    pub fn dictionary_attack_lock_reset(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<DictionaryAttackLockReset>()?;
        let [lock_handle] = handles;
        check(lock_handle, Tpmi::RhLockout, Position::handle(1))?;
        let auth_handle = lock_handle.0;
        if auth_handle != tpm2::Handle::RH_LOCKOUT.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.context.state.parsed_auths[..self.context.state.parsed_auths_len]
            .first()
            .cloned();

        if !self.state().in_shadow_execution || provided_auth.is_some() {
            self.validate_lockout_auth(auth_handle, provided_auth)?;
        }

        let _cmd = request.try_unmarshal_command::<DictionaryAttackLockReset>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // The command needs NV update (`RETURN_IF_NV_IS_NOT_AVAILABLE`).
        self.return_if_nv_is_not_available()?;

        self.context.state.failed_tries = 0;
        self.nv_sync_persistent_failed_tries()?;
        self.context.state.da_pending_on_nv = false;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the `TPM2_DictionaryAttackParameters` (`0x0000013A`) command.
    ///
    /// # Description
    /// This command changes the lockout parameters (`max_tries`, `recovery_time`, and `lockout_recovery`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 25.3 (TPM2_DictionaryAttackParameters).
    pub fn dictionary_attack_parameters(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<DictionaryAttackParameters>()?;
        let [lock_handle] = handles;
        check(lock_handle, Tpmi::RhLockout, Position::handle(1))?;
        let auth_handle = lock_handle.0;
        if auth_handle != tpm2::Handle::RH_LOCKOUT.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.context.state.parsed_auths[..self.context.state.parsed_auths_len]
            .first()
            .cloned();

        if !self.state().in_shadow_execution || provided_auth.is_some() {
            self.validate_lockout_auth(auth_handle, provided_auth)?;
        }

        let cmd = request.try_unmarshal_command::<DictionaryAttackParameters>(handles)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // The command needs NV update (`RETURN_IF_NV_IS_NOT_AVAILABLE`).
        self.return_if_nv_is_not_available()?;

        self.context.state.max_tries = cmd.new_max_tries;
        self.context.state.recovery_time = cmd.new_recovery_time;
        self.context.state.lockout_recovery = cmd.lockout_recovery;
        if cmd.new_recovery_time == 0 {
            self.context.state.failed_tries = 0;
        }

        // Record the changes to NV (`NV_SYNC_PERSISTENT` of failedTries, maxTries, recoveryTime
        // and lockoutRecovery); the DA parameters live in the persistent hierarchy data.
        self.nv_sync_persistent_failed_tries()?;
        self.context.state.da_pending_on_nv = false;
        self.context.save_hierarchy_auths();

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
