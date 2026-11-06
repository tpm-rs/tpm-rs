//! Physical Presence and the other platform settings kept in NV: the list of commands that
//! require Physical Presence (`gp.ppList`) and the algorithm set (`gp.algorithmSet`).
//!
//! TPM 2.0 Part 1, "Physical Presence Authorization": "The TPM maintains a table of the
//! commands that require that PP be asserted to authorize command execution. Only certain
//! commands can be included in this table. If, in Part 3, the schematic for a command has
//! `TPM_RH_PLATFORM` in the "Description" column for one of the handles, then that command can
//! be added to the list of commands that require PP. Otherwise, it cannot." and "When the
//! authorization handle is `TPM_RH_PLATFORM`, the TPM checks the table to see if the command
//! requires confirmation with PP. If so, PP is checked before the TPM performs any other
//! authorization checks." `TPM2_PP_Commands()` "cannot be removed from the list".
//!
//! Physical Presence itself is a platform input ([`State::physical_presence`], set by
//! [`TpmEngine::set_physical_presence`], the `PhysicalPresenceOn`/`Off` platform signals of the
//! simulator).
//!
//! [`State::physical_presence`]: crate::State::physical_presence

use crate::Platform;
use crate::engine::{TpmEngine, is_command_supported};
use crate::storage::Tpm2Storage;
use crate::storage::manager::StorageManager;
use tpm2::TpmCc;
use tpm2::crypto::Crypto;

/// The commands that can be gated with Physical Presence (C `PP_COMMAND`/`PP_REQUIRED`): the
/// commands with a `TPMI_RH_PLATFORM`, `TPMI_RH_PROVISION`, `TPMI_RH_CLEAR`, `TPMI_RH_HIERARCHY`
/// (or `TPMI_RH_HIERARCHY_AUTH`/`_POLICY`) handle, i.e. with `TPM_RH_PLATFORM` in the Part 3
/// "Description" column of one of their handles (`TPM_RH_PLATFORM+{PP}`, and
/// `TPM_RH_PLATFORM+PP` for `TPM2_PP_Commands`), in ascending command-code order.
///
/// `TPM2_SetAlgorithmSet` (handle `TPMI_RH_PLATFORM`, Description `TPM_RH_PLATFORM`) is one of
/// them as Part 1 and Part 3 TPM2_PP_Commands ("Only commands with handle types of
/// `TPMI_RH_PLATFORM`, `TPMI_RH_PROVISION`, `TPMI_RH_CLEAR`, or `TPMI_RH_HIERARCHY` can be gated
/// with Physical Presence") define it, even though its Part 3 table lacks the `+{PP}` note (as
/// in the TCG reference version 185; the earlier references omit it, see the
/// `bug-fix-set-algorithm-set-pp-command` patches of the differential tests).
///
/// Bit `i` of a [`PpList`] stands for entry `i`. Only the implemented ones
/// (in the command list of `TPM_CAP_COMMANDS`) ever require Physical Presence.
pub const PP_GATABLE_COMMANDS: [TpmCc; 25] = [
    TpmCc::NVUndefineSpaceSpecial,
    TpmCc::EvictControl,
    TpmCc::HierarchyControl,
    TpmCc::NVUndefineSpace,
    TpmCc::ChangeEPS,
    TpmCc::ChangePPS,
    TpmCc::Clear,
    TpmCc::ClearControl,
    TpmCc::ClockSet,
    TpmCc::HierarchyChangeAuth,
    TpmCc::NVDefineSpace,
    TpmCc::PCRAllocate,
    TpmCc::PCRSetAuthPolicy,
    TpmCc::PPCommands,
    TpmCc::SetPrimaryPolicy,
    TpmCc::FieldUpgradeStart,
    TpmCc::ClockRateAdjust,
    TpmCc::CreatePrimary,
    TpmCc::NVGlobalWriteLock,
    TpmCc::SetAlgorithmSet,
    TpmCc::SetCommandCodeAuditStatus,
    TpmCc::CreateLoaded,
    TpmCc::NVDefineSpace2,
    TpmCc::SetCapability,
    TpmCc::ReadOnlyControl,
];

/// The position of `cc` in [`PP_GATABLE_COMMANDS`], if it can be gated with Physical Presence.
fn gatable_index(cc: TpmCc) -> Option<usize> {
    PP_GATABLE_COMMANDS.iter().position(|&c| c == cc)
}

/// The list of commands that require Physical Presence when they are authorized with
/// `TPM_RH_PLATFORM` (C `gp.ppList`), a bit map over [`PP_GATABLE_COMMANDS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PpList(u32);

impl Default for PpList {
    fn default() -> Self {
        Self::manufacture_default()
    }
}

impl PpList {
    /// The list after manufacture (C `PhysicalPresencePreInstall_Init()`): only
    /// `TPM2_PP_Commands` (`PP_REQUIRED`), which always requires Physical Presence.
    pub const fn manufacture_default() -> Self {
        // `TPM2_PP_Commands` is entry 13 of `PP_GATABLE_COMMANDS`.
        Self(1 << 13)
    }

    /// The raw bit map (for the NV record).
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The list of a raw bit map read from NV. `TPM2_PP_Commands` is always on it and bits
    /// beyond [`PP_GATABLE_COMMANDS`] are dropped.
    pub const fn from_bits(bits: u32) -> Self {
        let valid = (1u32 << PP_GATABLE_COMMANDS.len()) - 1;
        Self((bits & valid) | Self::manufacture_default().0)
    }

    /// Whether `cc` requires Physical Presence when it is authorized with `TPM_RH_PLATFORM`
    /// (C `PhysicalPresenceIsRequired()`); only an implemented command can.
    pub fn is_required(self, cc: TpmCc) -> bool {
        is_command_supported(cc) && gatable_index(cc).is_some_and(|i| self.0 & (1 << i) != 0)
    }

    /// Adds `cc` to the list (C `PhysicalPresenceCommandSet()`): a command that is not
    /// implemented or cannot be gated with Physical Presence is ignored.
    pub fn set(&mut self, cc: TpmCc) {
        if let Some(i) = gatable_index(cc).filter(|_| is_command_supported(cc)) {
            self.0 |= 1 << i;
        }
    }

    /// Removes `cc` from the list (C `PhysicalPresenceCommandClear()`): a command that is not
    /// implemented or cannot be gated with Physical Presence, and `TPM2_PP_Commands` itself, are
    /// ignored.
    pub fn clear(&mut self, cc: TpmCc) {
        if cc == TpmCc::PPCommands {
            return;
        }
        if let Some(i) = gatable_index(cc).filter(|_| is_command_supported(cc)) {
            self.0 &= !(1 << i);
        }
    }
}

/// Reserved handle of the internal NV record holding the platform settings `gp.ppList` and
/// `gp.algorithmSet` ([`crate::storage::nv::NvPlatformSettingsRecord`]).
pub(crate) use crate::storage::nv::PLATFORM_SETTINGS_HANDLE;

impl<C: Crypto, P: Platform<Crypto = C>> TpmEngine<P> {
    /// Sets whether Physical Presence is asserted (C `_plat__Signal_PhysicalPresenceOn()` /
    /// `_plat__Signal_PhysicalPresenceOff()`). The platform keeps it across `_TPM_Init`.
    pub fn set_physical_presence(&mut self, asserted: bool) {
        self.state.physical_presence = asserted;
    }

    /// Whether `cc`, authorized with `TPM_RH_PLATFORM`, cannot proceed because it requires
    /// Physical Presence and Physical Presence is not asserted (C `CheckAuthSession()`:
    /// `PhysicalPresenceIsRequired(command->index) && !_plat__PhysicalPresenceAsserted()`).
    pub(crate) fn physical_presence_missing(&self, cc: TpmCc) -> bool {
        self.state.nv.persistent.pp_list.is_required(cc) && !self.state.physical_presence
    }

    #[cfg(any(feature = "cc-pp-commands", feature = "cc-set-algorithm-set"))]
    /// Writes `gp.ppList` and `gp.algorithmSet` to NV (`NV_SYNC_PERSISTENT(ppList)` /
    /// `NV_SYNC_PERSISTENT(algorithmSet)`).
    pub(crate) fn save_platform_settings(&mut self) {
        crate::storage::nv::NvPlatformSettingsRecord {
            pp_list: self.state.nv.persistent.pp_list.bits(),
            algorithm_set: self.state.nv.persistent.algorithm_set,
        }
        .write(self.platform.storage_mut());
    }

    /// Reloads `gp.ppList` and `gp.algorithmSet` from NV at `_TPM_Init`; without a record (as
    /// after manufacture) they keep their manufacture defaults.
    pub(crate) fn restore_platform_settings(&mut self) {
        if let Some(record) =
            crate::storage::nv::NvPlatformSettingsRecord::read(self.platform.storage_mut())
        {
            self.state.nv.persistent.pp_list = PpList::from_bits(record.pp_list);
            self.state.nv.persistent.algorithm_set = record.algorithm_set;
        }
    }

    /// Forgets the platform settings record (manufacture).
    pub(crate) fn clear_platform_settings(&mut self) {
        let mut storage = StorageManager::new(self.platform.storage_mut());
        let _ = storage.undefine_space(PLATFORM_SETTINGS_HANDLE);
        self.state.nv.persistent.pp_list = PpList::manufacture_default();
        self.state.nv.persistent.algorithm_set = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manufacture_default_is_pp_commands() {
        assert_eq!(PP_GATABLE_COMMANDS[13], TpmCc::PPCommands);
        assert_eq!(
            PpList::manufacture_default().is_required(TpmCc::PPCommands),
            is_command_supported(TpmCc::PPCommands)
        );
        assert!(!PpList::manufacture_default().is_required(TpmCc::Clear));
    }

    #[test]
    fn gatable_commands_are_in_ascending_order() {
        assert!(
            PP_GATABLE_COMMANDS
                .windows(2)
                .all(|w| w[0].code() < w[1].code())
        );
    }

    #[test]
    fn set_and_clear() {
        let mut list = PpList::manufacture_default();
        list.set(TpmCc::Clear);
        assert!(list.is_required(TpmCc::Clear));
        // Not gatable: ignored.
        list.set(TpmCc::GetRandom);
        assert!(!list.is_required(TpmCc::GetRandom));
        list.clear(TpmCc::Clear);
        assert!(!list.is_required(TpmCc::Clear));
        // `TPM2_PP_Commands` stays on the list.
        list.clear(TpmCc::PPCommands);
        assert_eq!(list, PpList::manufacture_default());
    }

    #[test]
    fn from_bits_keeps_pp_commands() {
        assert_eq!(PpList::from_bits(0), PpList::manufacture_default());
        assert_eq!(PpList::from_bits(u32::MAX).bits(), (1 << 25) - 1);
    }
}
