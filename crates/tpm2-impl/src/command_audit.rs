//! Command audit (TPM 2.0 Part 1, "Command Audit"; `CommandAudit.c` and the command-audit
//! parts of `SessionProcess.c` in the C reference).
//!
//! The TPM keeps a persistent list of audited commands ([`CommandAuditList`], `gp.auditCommands`),
//! the persistent audit hash algorithm (`gp.auditHashAlg`) and audit counter (`gp.auditCounter`),
//! and the command audit digest register (`gr.commandAuditDigest`), which is preserved across
//! TPM Restart/Resume and cleared on TPM Reset.
//!
//! Every successful execution of an audited command extends the digest register
//! (Part 1, equation "audit"):
//!
//! ```text
//! auditDigest_new := H_auditAlg(auditDigest_old || cpHash || rpHash)
//! ```
//!
//! where `cpHash` and `rpHash` are computed with the audit hash algorithm over the parameter
//! areas as they appear on the wire (so encrypted parameters are hashed in encrypted form). When
//! the register is empty at the time of an audit event, a new audit log starts: the register is
//! set to all zeros and the audit counter is incremented (and written to NV).
//!
//! The list itself is changed by `TPM2_SetCommandCodeAuditStatus` (see
//! [`crate::handler`]); `TPM2_SetCommandCodeAuditStatus` is always audited (it can never be
//! cleared from the list), except when it changes the audit hash algorithm, in which case the
//! digest register is cleared and that execution is not audited.

use crate::engine::{
    AUDIT_EXT_LEN, AUDIT_EXT_MARKER, GlobalState, TpmEngine, command_resp_handles_size,
    is_command_supported,
};
use crate::owned::OwnedDigest;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::crypto::{CryptoProvider, HashStream, Rng};
use tpm2::errors::TpmRc;
use tpm2::{TpmCc, TpmiAlgHash, TpmtHa};

/// Lowest library command code (`TPM_CC_FIRST`); bit `i` of the audit bitmap belongs to command
/// code `AUDIT_CC_FIRST + i`.
const AUDIT_CC_FIRST: u32 = 0x0000_011F;

/// Size in bytes of the persistent audit bitmap ([`CommandAuditList::as_bytes`]). It covers the
/// command codes `0x11F..=0x1DE`, which includes every command this TPM implements.
pub const COMMAND_AUDIT_LIST_SIZE: usize = 24;

/// The set of audited commands (`gp.auditCommands`).
///
/// Only implemented commands can be in the list (`CommandAuditSet()` ignores unimplemented
/// command codes), so `TPM2_GetCapability(TPM_CAP_AUDIT_COMMANDS)` never reports a command that
/// the TPM does not implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandAuditList {
    bits: [u8; COMMAND_AUDIT_LIST_SIZE],
}

impl Default for CommandAuditList {
    /// Returns the manufacture default ([`Self::manufacture_default`]).
    fn default() -> Self {
        Self::manufacture_default()
    }
}

impl CommandAuditList {
    /// The list as installed at manufacture (`CommandAuditPreInstall_Init()`): only
    /// `TPM2_SetCommandCodeAuditStatus` is audited.
    pub fn manufacture_default() -> Self {
        let mut list = Self {
            bits: [0; COMMAND_AUDIT_LIST_SIZE],
        };
        list.set(TpmCc::SetCommandCodeAuditStatus);
        list
    }

    /// Returns the bit position of `cc`, or `None` if `cc` is not an implemented command (or
    /// lies outside the range covered by the bitmap).
    fn bit_index(cc: TpmCc) -> Option<usize> {
        if !is_command_supported(cc) {
            return None;
        }
        let index = cc.code().checked_sub(AUDIT_CC_FIRST)? as usize;
        (index < COMMAND_AUDIT_LIST_SIZE * 8).then_some(index)
    }

    /// Returns whether `cc` is audited (`CommandAuditIsRequired()` /
    /// `CommandAuditCapGetOneCC()`). Unimplemented commands are never audited.
    pub fn is_audited(&self, cc: TpmCc) -> bool {
        Self::bit_index(cc).is_some_and(|i| self.bits[i / 8] & (1 << (i % 8)) != 0)
    }

    /// Adds `cc` to the list (`CommandAuditSet()`). Unimplemented commands and
    /// `TPM2_Shutdown` (which cannot be audited) are ignored. Returns whether the list changed.
    pub fn set(&mut self, cc: TpmCc) -> bool {
        if cc == TpmCc::Shutdown || self.is_audited(cc) {
            return false;
        }
        match Self::bit_index(cc) {
            Some(i) => {
                self.bits[i / 8] |= 1 << (i % 8);
                true
            }
            None => false,
        }
    }

    /// Removes `cc` from the list (`CommandAuditClear()`). `TPM2_SetCommandCodeAuditStatus`
    /// can never be removed, and unimplemented commands are ignored. Returns whether the list
    /// changed.
    pub fn clear(&mut self, cc: TpmCc) -> bool {
        if cc == TpmCc::SetCommandCodeAuditStatus || !self.is_audited(cc) {
            return false;
        }
        match Self::bit_index(cc) {
            Some(i) => {
                self.bits[i / 8] &= !(1 << (i % 8));
                true
            }
            None => false,
        }
    }

    /// Iterates over the audited commands in ascending command-code order.
    pub fn iter(&self) -> impl Iterator<Item = TpmCc> + '_ {
        (0..COMMAND_AUDIT_LIST_SIZE * 8)
            .filter(|&i| self.bits[i / 8] & (1 << (i % 8)) != 0)
            .map(|i| TpmCc::new(AUDIT_CC_FIRST + i as u32))
    }

    /// The persistent (NV) encoding of the list: a bitmap where bit `i % 8` of byte `i / 8`
    /// represents command code `0x11F + i`.
    pub fn as_bytes(&self) -> &[u8; COMMAND_AUDIT_LIST_SIZE] {
        &self.bits
    }

    /// Decodes the encoding produced by [`Self::as_bytes`]. Bits of command codes that are not
    /// implemented are dropped.
    pub fn from_bytes(bytes: &[u8; COMMAND_AUDIT_LIST_SIZE]) -> Self {
        let mut list = Self {
            bits: [0; COMMAND_AUDIT_LIST_SIZE],
        };
        for i in 0..COMMAND_AUDIT_LIST_SIZE * 8 {
            if bytes[i / 8] & (1 << (i % 8)) != 0 {
                list.set(TpmCc::new(AUDIT_CC_FIRST + i as u32));
            }
        }
        list
    }
}

impl GlobalState {
    /// The command audit hash algorithm (`gp.auditHashAlg`). An invalid stored value (which a
    /// TPM state never contains) falls back to the manufacture default, SHA-512.
    pub fn command_audit_hash_alg(&self) -> TpmiAlgHash {
        TpmiAlgHash::try_from(self.audit_hash_alg).unwrap_or(TpmiAlgHash::Sha512)
    }
}

/// Writes the persistent command audit record (`AUDIT_EXT_MARKER || auditHashAlg ||
/// auditCounter || auditCommands`, big-endian) into `dst`, which must hold at least
/// [`AUDIT_EXT_LEN`] bytes. Returns the number of bytes written.
pub(crate) fn encode_audit_ext(global_state: &GlobalState, dst: &mut [u8]) -> usize {
    dst[0] = AUDIT_EXT_MARKER;
    dst[1..3].copy_from_slice(&global_state.audit_hash_alg.to_be_bytes());
    dst[3..11].copy_from_slice(&global_state.audit_counter.to_be_bytes());
    dst[11..AUDIT_EXT_LEN].copy_from_slice(global_state.audit_commands.as_bytes());
    AUDIT_EXT_LEN
}

/// Loads the persistent command audit record written by [`encode_audit_ext`] from the start of
/// `src`. Returns `false` (leaving `global_state` untouched) if `src` does not start with a
/// complete record or the record names an unsupported hash algorithm.
pub(crate) fn decode_audit_ext(global_state: &mut GlobalState, src: &[u8]) -> bool {
    let Some(ext) = src.get(..AUDIT_EXT_LEN) else {
        return false;
    };
    let alg = u16::from_be_bytes([ext[1], ext[2]]);
    if ext[0] != AUDIT_EXT_MARKER || TpmiAlgHash::try_from(alg).is_err() {
        return false;
    }
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&ext[3..11]);
    let mut bits = [0u8; COMMAND_AUDIT_LIST_SIZE];
    bits.copy_from_slice(&ext[11..AUDIT_EXT_LEN]);
    global_state.audit_hash_alg = alg;
    global_state.audit_counter = u64::from_be_bytes(counter);
    global_state.audit_commands = CommandAuditList::from_bytes(&bits);
    true
}

impl<C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync> TpmEngine<'_, C, S, T, R> {
    /// Prepares the command audit of `cc` before the command is executed (`CheckCommandAudit()`,
    /// called from `ParseSessionBuffer()` / `CheckAuthNoSession()` once authorization has
    /// succeeded and before any parameter decryption).
    ///
    /// If `cc` is audited:
    /// - fails with `TPM_RC_NV_UNAVAILABLE` if NV is unavailable and the audit counter may have
    ///   to be incremented (the digest register is empty) or the command is
    ///   `TPM2_GetCommandAuditDigest`;
    /// - computes the command's `cpHash` with the audit hash algorithm over the command code, the
    ///   Names of `handles` and the wire-format `parameters`, and keeps it for
    ///   [`Self::command_audit`].
    pub(crate) fn check_command_audit(
        &mut self,
        cc: TpmCc,
        handles: &[u32],
        parameters: &[u8],
    ) -> Result<(), TpmRc> {
        self.state.command_audit_cp_hash = None;
        if !self.state.audit_commands.is_audited(cc) {
            return Ok(());
        }
        if (self.state.command_audit_digest.get_size() == 0 || cc == TpmCc::GetCommandAuditDigest)
            && !self.state.nv_available
        {
            return Err(TpmRc::NV_UNAVAILABLE);
        }
        let alg = self.state.command_audit_hash_alg();
        let mut ctx = HashStream::new(&*self.platform.crypto, alg).map_err(|_| TpmRc::FAILURE)?;
        ctx.update(&cc.code().to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        for &handle in handles {
            let name = self.handle_name(handle);
            ctx.update(name.get_buffer()).map_err(|_| TpmRc::FAILURE)?;
        }
        ctx.update(parameters).map_err(|_| TpmRc::FAILURE)?;
        let mut buf = [0u8; TpmtHa::MAX_DIGEST_SIZE];
        let cp_hash = ctx.finalize(&mut buf).map_err(|_| TpmRc::FAILURE)?;
        self.state.command_audit_cp_hash =
            Some(OwnedDigest::from_bytes(cp_hash.digest()).map_err(|_| TpmRc::FAILURE)?);
        Ok(())
    }

    /// Records the successful execution of an audited command in the command audit digest
    /// (`CommandAudit()` in `SessionProcess.c`). `response` is the complete response; its
    /// parameter area (as sent, i.e. after parameter encryption) is hashed into the `rpHash`.
    ///
    /// Does nothing unless [`Self::check_command_audit`] prepared a `cpHash` for this command.
    /// If the command changed the audit hash algorithm (`TPM2_SetCommandCodeAuditStatus`), the
    /// digest stays cleared and this execution is not audited. If the digest register is empty,
    /// a new audit log starts: the register is zeroed and the audit counter is incremented and
    /// written to NV.
    pub(crate) fn command_audit(&mut self, cc: TpmCc, response: &[u8]) -> Result<(), TpmRc> {
        let Some(cp_hash) = self.state.command_audit_cp_hash.take() else {
            return Ok(());
        };
        if core::mem::take(&mut self.state.command_audit_alg_changed) {
            self.state.command_audit_digest = OwnedDigest::default();
            return Ok(());
        }
        let rp_params = response_parameters(cc, response).ok_or(TpmRc::FAILURE)?;
        let alg = self.state.command_audit_hash_alg();
        let digest_size = alg.digest_size();

        let mut ctx = HashStream::new(&*self.platform.crypto, alg).map_err(|_| TpmRc::FAILURE)?;
        ctx.update(&0u32.to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        ctx.update(&cc.code().to_be_bytes())
            .map_err(|_| TpmRc::FAILURE)?;
        ctx.update(rp_params).map_err(|_| TpmRc::FAILURE)?;
        let mut rp_buf = [0u8; TpmtHa::MAX_DIGEST_SIZE];
        let rp_hash = ctx.finalize(&mut rp_buf).map_err(|_| TpmRc::FAILURE)?;

        if self.state.command_audit_digest.get_size() == 0 {
            let zeros = [0u8; TpmtHa::MAX_DIGEST_SIZE];
            self.state.command_audit_digest =
                OwnedDigest::from_bytes(&zeros[..digest_size]).map_err(|_| TpmRc::FAILURE)?;
            self.state.audit_counter = self.state.audit_counter.wrapping_add(1);
            // NV_SYNC_PERSISTENT(auditCounter)
            self.save_hierarchy_auths();
        }

        let mut ctx = HashStream::new(&*self.platform.crypto, alg).map_err(|_| TpmRc::FAILURE)?;
        ctx.update(self.state.command_audit_digest.get_buffer())
            .map_err(|_| TpmRc::FAILURE)?;
        ctx.update(cp_hash.get_buffer())
            .map_err(|_| TpmRc::FAILURE)?;
        ctx.update(rp_hash.digest()).map_err(|_| TpmRc::FAILURE)?;
        let mut buf = [0u8; TpmtHa::MAX_DIGEST_SIZE];
        let digest = ctx.finalize(&mut buf).map_err(|_| TpmRc::FAILURE)?;
        self.state.command_audit_digest =
            OwnedDigest::from_bytes(digest.digest()).map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }

    /// Computes the digest of the list of audited commands reported as `commandDigest` by
    /// `TPM2_GetCommandAuditDigest` (`CommandAuditGetDigest()`): the hash, with the audit hash
    /// algorithm, of the concatenated big-endian command codes of all audited commands in
    /// ascending order.
    pub(crate) fn command_audit_list_digest(&self) -> Result<OwnedDigest, TpmRc> {
        let alg = self.state.command_audit_hash_alg();
        let mut ctx = HashStream::new(&*self.platform.crypto, alg).map_err(|_| TpmRc::FAILURE)?;
        for cc in self.state.audit_commands.iter() {
            ctx.update(&cc.code().to_be_bytes())
                .map_err(|_| TpmRc::FAILURE)?;
        }
        let mut buf = [0u8; TpmtHa::MAX_DIGEST_SIZE];
        let digest = ctx.finalize(&mut buf).map_err(|_| TpmRc::FAILURE)?;
        OwnedDigest::from_bytes(digest.digest()).map_err(|_| TpmRc::FAILURE)
    }
}

/// Returns the response parameter area of a successful response to `cc` (without the handle
/// area, the `parameterSize` field and the authorization area), or `None` if `response` is
/// malformed.
fn response_parameters(cc: TpmCc, response: &[u8]) -> Option<&[u8]> {
    let tag = u16::from_be_bytes(response.get(0..2)?.try_into().ok()?);
    let at = 10 + command_resp_handles_size(cc);
    if tag == 0x8002 {
        let size = u32::from_be_bytes(response.get(at..at + 4)?.try_into().ok()?) as usize;
        response.get(at + 4..at + 4 + size)
    } else {
        response.get(at..)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::SUPPORTED_COMMANDS;

    #[test]
    fn manufacture_default_audits_only_set_command_code_audit_status() {
        let list = CommandAuditList::manufacture_default();
        let audited: alloc::vec::Vec<TpmCc> = list.iter().collect();
        assert_eq!(audited, [TpmCc::SetCommandCodeAuditStatus]);
        assert_eq!(CommandAuditList::default(), list);
    }

    #[test]
    fn bitmap_covers_every_supported_command() {
        for cc in SUPPORTED_COMMANDS {
            assert!(
                CommandAuditList::bit_index(cc).is_some(),
                "command {cc:?} does not fit in the audit bitmap"
            );
        }
    }

    #[test]
    fn set_and_clear_report_changes() {
        let mut list = CommandAuditList::manufacture_default();
        assert!(list.set(TpmCc::GetRandom));
        assert!(!list.set(TpmCc::GetRandom), "already audited");
        assert!(list.is_audited(TpmCc::GetRandom));
        assert!(list.clear(TpmCc::GetRandom));
        assert!(!list.clear(TpmCc::GetRandom), "not audited");
        assert!(!list.is_audited(TpmCc::GetRandom));
    }

    #[test]
    fn shutdown_cannot_be_audited() {
        let mut list = CommandAuditList::manufacture_default();
        assert!(!list.set(TpmCc::Shutdown));
        assert!(!list.is_audited(TpmCc::Shutdown));
    }

    #[test]
    fn set_command_code_audit_status_cannot_be_cleared() {
        let mut list = CommandAuditList::manufacture_default();
        assert!(!list.clear(TpmCc::SetCommandCodeAuditStatus));
        assert!(list.is_audited(TpmCc::SetCommandCodeAuditStatus));
    }

    #[test]
    fn unimplemented_commands_are_ignored() {
        let mut list = CommandAuditList::manufacture_default();
        for code in [
            0x0000_0000,
            0x0000_011E,
            0x0000_013F,
            0x0000_01FF,
            0x2000_0000,
        ] {
            let cc = TpmCc::new(code);
            assert!(!list.set(cc), "{code:#x}");
            assert!(!list.is_audited(cc), "{code:#x}");
            assert!(!list.clear(cc), "{code:#x}");
        }
        assert_eq!(list, CommandAuditList::manufacture_default());
    }

    #[test]
    fn iteration_is_in_ascending_command_code_order() {
        let mut list = CommandAuditList::manufacture_default();
        list.set(TpmCc::GetRandom);
        list.set(TpmCc::Clear);
        list.set(TpmCc::PCRRead);
        let codes: alloc::vec::Vec<u32> = list.iter().map(|cc| cc.code()).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        assert_eq!(codes, sorted);
        assert_eq!(codes.len(), 4);
    }

    #[test]
    fn byte_encoding_round_trips_and_drops_unimplemented_bits() {
        let mut list = CommandAuditList::manufacture_default();
        list.set(TpmCc::GetRandom);
        list.set(TpmCc::NVRead);
        let bytes = *list.as_bytes();
        assert_eq!(CommandAuditList::from_bytes(&bytes), list);

        // 0x13F (bit 32, TPM2_SetAlgorithmSet) is not an implemented command.
        let mut tampered = bytes;
        tampered[32 / 8] |= 1 << (32 % 8);
        assert_eq!(CommandAuditList::from_bytes(&tampered), list);
    }

    #[test]
    fn audit_ext_round_trips() {
        let mut state = GlobalState {
            audit_hash_alg: 0x000B, // TPM_ALG_SHA256
            audit_counter: 0x1122_3344_5566_7788,
            ..Default::default()
        };
        state.audit_commands.set(TpmCc::NVRead);
        let mut buf = [0u8; AUDIT_EXT_LEN + 3];
        assert_eq!(encode_audit_ext(&state, &mut buf), AUDIT_EXT_LEN);
        assert_eq!(buf[0], AUDIT_EXT_MARKER);

        let mut restored = GlobalState::default();
        assert!(decode_audit_ext(&mut restored, &buf));
        assert_eq!(restored.audit_hash_alg, state.audit_hash_alg);
        assert_eq!(restored.audit_counter, state.audit_counter);
        assert_eq!(restored.audit_commands, state.audit_commands);
    }

    #[test]
    fn audit_ext_rejects_malformed_records() {
        let state = GlobalState {
            audit_counter: 5,
            ..Default::default()
        };
        let mut buf = [0u8; AUDIT_EXT_LEN];
        encode_audit_ext(&state, &mut buf);

        let mut target = GlobalState::default();
        assert!(
            !decode_audit_ext(&mut target, &buf[..AUDIT_EXT_LEN - 1]),
            "short"
        );
        let mut bad_marker = buf;
        bad_marker[0] = 0xBB;
        assert!(!decode_audit_ext(&mut target, &bad_marker), "marker");
        let mut bad_alg = buf;
        bad_alg[1..3].copy_from_slice(&0x0001u16.to_be_bytes()); // TPM_ALG_RSA
        assert!(!decode_audit_ext(&mut target, &bad_alg), "hash algorithm");
        assert_eq!(target.audit_counter, 0, "state untouched");
    }

    #[test]
    fn response_parameters_skip_handles_and_parameter_size() {
        // TPM_ST_SESSIONS response of TPM2_CreatePrimary: handle, parameterSize = 2, params.
        let rsp = [
            0x80, 0x02, 0, 0, 0, 0x14, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 2, 0xAA, 0xBB, 0xCC,
        ];
        assert_eq!(
            response_parameters(TpmCc::CreatePrimary, &rsp),
            Some(&[0xAA, 0xBB][..])
        );
        // TPM_ST_NO_SESSIONS response of TPM2_GetRandom.
        let rsp = [0x80, 0x01, 0, 0, 0, 0x0D, 0, 0, 0, 0, 0, 1, 7];
        assert_eq!(
            response_parameters(TpmCc::GetRandom, &rsp),
            Some(&[0, 1, 7][..])
        );
        // A truncated parameter area is malformed.
        let rsp = [0x80, 0x02, 0, 0, 0, 0x0E, 0, 0, 0, 0, 0, 0, 0, 9];
        assert_eq!(response_parameters(TpmCc::GetRandom, &rsp), None);
    }
}
