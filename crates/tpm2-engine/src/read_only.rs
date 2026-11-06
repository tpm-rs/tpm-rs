//! The Read-Only mode of operation (TPM 2.0 Part 1, "Read-Only Mode of Operation"; the
//! `cc-read-only-control` feature).
//!
//! `TPM2_ReadOnlyControl` (Part 3) enters and leaves the mode with Platform Authorization; the
//! current mode is [`crate::State::read_only`], reported as `TPMA_STARTUP_CLEAR.readOnly`.
//! While it is SET:
//!
//! * the commands that are *Not Permitted* in Part 3, "Commands Permitted in Read-Only Mode"
//!   ([`is_disallowed_in_read_only_mode`]) fail with `TPM_RC_READ_ONLY` before any handle or
//!   session processing (the reference's `RO_DISALLOW` command attribute), once the TPM is
//!   started (before `TPM2_Startup` every command but `TPM2_Startup` is `TPM_RC_INITIALIZE`);
//! * `TPM2_NV_Write`, `TPM2_NV_Extend`, `TPM2_NV_SetBits`, `TPM2_NV_WriteLock` and
//!   `TPM2_NV_ReadLock` are permitted "only when the NV index is defined with `TPMA_NV_ORDERLY`
//!   and `TPMA_NV_CLEAR_STCLEAR`" ([`nv_command_permitted`]), and `TPM2_PolicySecret` is "Not
//!   permitted when used with a PIN Pass/Fail NV index". These depend on the entity a handle
//!   references, so they are checked once the handles are validated, but (Part 1: "A device
//!   supporting Read-Only mode must reject any affected command before performing
//!   authorization checks which would be evaluated during the execution of the command")
//!   before the authorization area is processed: a failed authorization of a PIN index would
//!   otherwise update its `pinCount`, and any authorization failure the DA counter.
//!
//! The specification does not define the behavior of vendor-defined commands in Read-Only mode
//! (Part 1); they are permitted, as in the reference.

use tpm2::{TpmCc, TpmaNv};

/// Returns whether `cc` is *Not Permitted* in Read-Only mode (Part 3, TPM2_ReadOnlyControl,
/// "Commands Permitted in Read-Only Mode"; the reference's `RO_DISALLOW` attribute). The list
/// covers every library command of the table, implemented or not.
pub(crate) fn is_disallowed_in_read_only_mode(cc: TpmCc) -> bool {
    matches!(
        cc,
        // Object Commands
        TpmCc::Create
            | TpmCc::ObjectChangeAuth
            | TpmCc::CreateLoaded
            // Command Audit
            | TpmCc::SetCommandCodeAuditStatus
            // Integrity Collection (PCR)
            | TpmCc::PCRAllocate
            | TpmCc::PCRSetAuthPolicy
            | TpmCc::PCRSetAuthValue
            // Hierarchy Commands
            | TpmCc::CreatePrimary
            | TpmCc::HierarchyControl
            | TpmCc::SetPrimaryPolicy
            | TpmCc::ChangePPS
            | TpmCc::ChangeEPS
            | TpmCc::Clear
            | TpmCc::ClearControl
            | TpmCc::HierarchyChangeAuth
            // Dictionary Attack Functions
            | TpmCc::DictionaryAttackParameters
            // Miscellaneous Management Functions
            | TpmCc::PPCommands
            | TpmCc::SetAlgorithmSet
            // Field Upgrade
            | TpmCc::FieldUpgradeStart
            | TpmCc::FieldUpgradeData
            // Context Management
            | TpmCc::EvictControl
            // Clocks and Timers
            | TpmCc::ClockSet
            | TpmCc::ClockRateAdjust
            // Capability Commands
            | TpmCc::SetCapability
            // Non-volatile Storage
            | TpmCc::NVDefineSpace
            | TpmCc::NVUndefineSpace
            | TpmCc::NVUndefineSpaceSpecial
            | TpmCc::NVIncrement
            | TpmCc::NVGlobalWriteLock
            | TpmCc::NVChangeAuth
            | TpmCc::NVDefineSpace2
    )
}

/// Returns the handle index of the NV Index that decides whether `cc` is permitted in Read-Only
/// mode ("Permitted only when the NV index is defined with `TPMA_NV_ORDERLY` and
/// `TPMA_NV_CLEAR_STCLEAR`"), or `None` if `cc` is not such a command. Every one of them has
/// the `nvIndex` as its second handle (`@authHandle, nvIndex`).
pub(crate) fn nv_restricted_index_handle(cc: TpmCc) -> Option<usize> {
    matches!(
        cc,
        TpmCc::NVWrite
            | TpmCc::NVExtend
            | TpmCc::NVSetBits
            | TpmCc::NVWriteLock
            | TpmCc::NVReadLock
    )
    .then_some(1)
}

/// Returns whether an NV command of [`nv_restricted_index_handle`] is permitted in Read-Only
/// mode on an NV Index with `attributes`: only an Index with both `TPMA_NV_ORDERLY` and
/// `TPMA_NV_CLEAR_STCLEAR`, whose contents are never written to NV before an orderly shutdown
/// and are lost at TPM Reset/Restart (C `NvReadOnlyModeChecks()`).
pub(crate) fn nv_command_permitted(attributes: TpmaNv) -> bool {
    attributes.contains(TpmaNv::ORDERLY | TpmaNv::CLEAR_STCLEAR)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The *Not Permitted* rows of Part 3's table, and some permitted commands.
    #[test]
    fn disallowed_commands_follow_the_part3_table() {
        for cc in [
            TpmCc::Create,
            TpmCc::CreatePrimary,
            TpmCc::CreateLoaded,
            TpmCc::EvictControl,
            TpmCc::NVDefineSpace,
            TpmCc::NVDefineSpace2,
            TpmCc::NVUndefineSpace,
            TpmCc::NVUndefineSpaceSpecial,
            TpmCc::NVIncrement,
            TpmCc::NVGlobalWriteLock,
            TpmCc::NVChangeAuth,
            TpmCc::HierarchyChangeAuth,
            TpmCc::DictionaryAttackParameters,
            TpmCc::ClockSet,
            TpmCc::ClockRateAdjust,
            TpmCc::SetCapability,
        ] {
            assert!(is_disallowed_in_read_only_mode(cc), "{cc:?}");
        }
        for cc in [
            TpmCc::Startup,
            TpmCc::Shutdown,
            TpmCc::ReadOnlyControl,
            TpmCc::NVWrite,
            TpmCc::NVRead,
            TpmCc::NVReadPublic2,
            TpmCc::Load,
            TpmCc::ContextSave,
            TpmCc::PCRExtend,
            TpmCc::PolicySecret,
            TpmCc::DictionaryAttackLockReset,
            TpmCc::ACTSetTimeout,
            TpmCc::VendorTcgTest,
        ] {
            assert!(!is_disallowed_in_read_only_mode(cc), "{cc:?}");
        }
    }

    /// Only ORDERLY + CLEAR_STCLEAR Indexes may be updated in Read-Only mode.
    #[test]
    fn nv_updates_need_orderly_clear_stclear_indexes() {
        assert!(nv_command_permitted(
            TpmaNv::ORDERLY | TpmaNv::CLEAR_STCLEAR
        ));
        assert!(!nv_command_permitted(TpmaNv::ORDERLY));
        assert!(!nv_command_permitted(TpmaNv::CLEAR_STCLEAR));
        assert_eq!(nv_restricted_index_handle(TpmCc::NVWrite), Some(1));
        assert_eq!(nv_restricted_index_handle(TpmCc::NVReadLock), Some(1));
        assert_eq!(nv_restricted_index_handle(TpmCc::NVIncrement), None);
        assert_eq!(nv_restricted_index_handle(TpmCc::NVRead), None);
    }
}
