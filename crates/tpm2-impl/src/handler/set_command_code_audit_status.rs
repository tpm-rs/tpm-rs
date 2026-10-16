use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, owned::OwnedDigest, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::SetCommandCodeAuditStatus;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Alg, TpmiAlgHash};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::SetCommandCodeAuditStatus] (`0x140`) command.
    ///
    /// # Description
    /// Changes the list of audited commands or the hash algorithm of the command audit digest,
    /// but not both at once. `auth` is `TPM_RH_OWNER` or `TPM_RH_PLATFORM` (USER role; the
    /// authorization itself is checked by the engine).
    ///
    /// - If `auditAlg` is a hash algorithm different from the current one, `setList` and
    ///   `clearList` must both be empty (otherwise `TPM_RC_VALUE + RC_auditAlg`); the algorithm
    ///   is changed, the audit digest is cleared, and this execution is not audited.
    /// - Otherwise (`TPM_ALG_NULL` or the current algorithm) the commands in `setList` are added
    ///   to the audit list and then the commands in `clearList` are removed, so a command in both
    ///   lists ends up not audited. Unimplemented commands are ignored, `TPM2_Shutdown` cannot be
    ///   audited and `TPM2_SetCommandCodeAuditStatus` cannot be removed. This execution is
    ///   audited.
    ///
    /// Changes are written to NV, so the command fails with `TPM_RC_NV_UNAVAILABLE` while NV is
    /// unavailable.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, "TPM2_SetCommandCodeAuditStatus";
    /// Part 1: Architecture, "Command Audit". C reference: `SetCommandCodeAuditStatus.c`,
    /// `CommandAudit.c`.
    ///
    /// # Relationships
    /// - The audit list is reported by [TpmCc::GetCapability](capability.rs)
    ///   (`TPM_CAP_AUDIT_COMMANDS`) and digested into the `commandDigest` of
    ///   [TpmCc::GetCommandAuditDigest](get_command_audit_digest.rs).
    /// - The engine extends the command audit digest for every audited command
    ///   ([`crate::command_audit`]).
    pub fn set_command_code_audit_status(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        // TPMI_RH_PROVISION: TPM_RH_OWNER or TPM_RH_PLATFORM.
        let handles = request.try_unmarshal_handles::<SetCommandCodeAuditStatus>()?;
        let [auth] = handles;
        check(auth, Tpmi::RhProvision, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        // TPM 2.0 Part 2, TPMI_ALG_HASH: "`TPMI_ALG_HASH` is an interface type of all the
        // hash algorithms implemented on a specific TPM", and Table "Definition of (TPM_ALG_ID)
        // TPMI_ALG_HASH Type" ends with "+TPM_ALG_NULL" and "#TPM_RC_HASH". Part 3,
        // TPM2_SetCommandCodeAuditStatus: "TPMI_ALG_HASH+ | auditAlg" is the first parameter.
        // The `tpm2` wire type also decodes SM3/SHA-3 identifiers, which this TPM does not
        // implement, so the check belongs to unmarshaling `auditAlg` and precedes any error in
        // the later parameters (`setList`, `clearList`).
        let audit_alg_id = request
            .remaining_slice()
            .get(..2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]));
        if let Some(id) = audit_alg_id
            && id != Alg::NULL.id()
            && TpmiAlgHash::try_from(id).is_ok()
            && !crate::handler::capability::IMPLEMENTED_ALGORITHMS
                .iter()
                .any(|&(implemented, _)| implemented.id() == id)
        {
            return Err(TpmRc::HASH.with(Position::parameter(1)));
        }
        let cmd = request.try_unmarshal_command::<SetCommandCodeAuditStatus>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // The command needs NV update (`RETURN_IF_NV_IS_NOT_AVAILABLE`).
        self.return_if_nv_is_not_available()?;

        let new_alg = cmd.audit_alg.map(|alg| Alg::from(alg).id());
        match new_alg {
            Some(alg) if alg != self.context.state.audit_hash_alg => {
                // Can't change the algorithm and the command list at the same time.
                if cmd.set_list.count() != 0 || cmd.clear_list.count() != 0 {
                    return Err(TpmRc::VALUE.with(Position::parameter(1)));
                }
                self.context.state.audit_hash_alg = alg;
                // The digest is cleared and this execution is not audited.
                self.context.state.command_audit_digest = OwnedDigest::default();
                self.context.state.command_audit_alg_changed = true;
                // NV_SYNC_PERSISTENT(auditHashAlg)
                self.context.save_hierarchy_auths();
            }
            _ => {
                let mut changed = false;
                for &cc in cmd.set_list.as_slice() {
                    changed |= self.context.state.audit_commands.set(cc);
                }
                for &cc in cmd.clear_list.as_slice() {
                    changed |= self.context.state.audit_commands.clear(cc);
                }
                if changed {
                    // NV_SYNC_PERSISTENT(auditCommands)
                    self.context.save_hierarchy_auths();
                }
            }
        }

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
