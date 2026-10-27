//! TPM firmware identity: the Firmware Secret, the Firmware SVN Secrets and the firmware's
//! Security Version Numbers (SVNs).
//!
//! TPM 2.0 Part 1, "TPM Firmware-Limited and SVN-Limited Objects": a firmware-limited hierarchy
//! (`TPM_RH_FW_{OWNER,ENDORSEMENT,PLATFORM,NULL}`) derives its seed and proof from its base
//! hierarchy's values and the *Firmware Secret*, "cryptographically limited to the current
//! firmware image running on the current TPM instance"; an SVN-limited hierarchy
//! (`TPM_RH_SVN_{OWNER,ENDORSEMENT,PLATFORM,NULL}_BASE + SVN`) uses the *Firmware SVN Secret* of
//! its SVN instead: "TPM firmware with SVN X can derive every SVN Secret bound to an SVN <= X,
//! and cannot be able to derive an SVN Secret for any SVN > X". How these secrets are obtained
//! (e.g. from a bootloader or hardware registers) "is outside the scope of this specification",
//! so it is the platform's job: the [`TpmFirmware`] trait.
//!
//! A platform without a [`TpmFirmware`] (`TpmPlatform::firmware` is `None`) supports neither
//! kind of limited hierarchy: their handles fail with `TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED`
//! ("the Firmware Secret is unavailable").
//!
//! [`SimulatedFirmware`] is the *insecure* implementation of the TCG reference platform
//! (`Platform/src/VendorInfo.c`), for simulators and tests.

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

/// The error of a [`TpmFirmware`] secret request: the secret is not available (TPM 2.0 Part 2,
/// `TPM_RC_FW_LIMITED`: "the Firmware Secret is unavailable"; `TPM_RC_SVN_LIMITED`: "the
/// Firmware SVN Secret associated with the given SVN is unavailable").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareSecretUnavailable;

/// The platform interface to the firmware identity of the TPM (the counterpart of the TCG
/// reference platform's `_plat__GetTpmFirmwareSvn`, `_plat__GetTpmFirmwareMaxSvn`,
/// `_plat__GetTpmFirmwareSecret` and `_plat__GetTpmFirmwareSvnSecret`).
pub trait TpmFirmware {
    /// The SVN of the running firmware, reported as `TPM_PT_FIRMWARE_SVN` (TPM 2.0 Part 2: "the
    /// current Security Version Number of the TPM firmware"). SVN-limited hierarchies of a
    /// larger SVN are unavailable (`TPM_RC_SVN_LIMITED`).
    fn firmware_svn(&self) -> u16;

    /// The largest SVN the firmware may take in the future, reported as
    /// `TPM_PT_FIRMWARE_MAX_SVN`.
    fn firmware_max_svn(&self) -> u16;

    /// Writes the Firmware Secret of the running firmware into `out` and returns its length
    /// (at most `out.len()`). The TPM asks for as many bytes as the seed or proof it derives
    /// from the secret.
    fn firmware_secret(&self, out: &mut [u8]) -> Result<usize, FirmwareSecretUnavailable>;

    /// Writes the Firmware SVN Secret bound to `svn` into `out` and returns its length (at most
    /// `out.len()`). Fails for an SVN larger than [`TpmFirmware::firmware_svn`].
    fn firmware_svn_secret(
        &self,
        svn: u16,
        out: &mut [u8],
    ) -> Result<usize, FirmwareSecretUnavailable>;
}

/// The *insecure* dummy firmware of the TCG reference platform (`Platform/src/VendorInfo.c`),
/// for simulators and tests only: its secrets are public functions of the firmware hash and of
/// the SVN.
///
/// * The Firmware Secret repeats the 32-bit firmware hash in little-endian byte order (the
///   reference copies the bytes of a native `uint32_t` on little-endian hosts).
/// * The Firmware SVN Secret of `svn` repeats `svn` in little-endian byte order, and is
///   available only for `svn <= firmware_svn`.
/// * [`SimulatedFirmware::set_firmware_svn`] caps the SVN at the maximum SVN, like
///   `_plat__SetTpmFirmwareSvn`.
///
/// The hash and SVN are atomics, so a simulator can install another firmware image through a
/// shared reference while the TPM borrows the same [`SimulatedFirmware`] as its
/// [`TpmFirmware`].
///
/// [`SimulatedFirmware::default`] has the values of the patched TCG references of the
/// differential tests: firmware hash 0 (`FIRMWARE_V2`, the low 32 bits of the firmware version),
/// SVN 10 and maximum SVN 255.
#[derive(Debug)]
pub struct SimulatedFirmware {
    hash: AtomicU32,
    svn: AtomicU16,
    max_svn: u16,
}

impl SimulatedFirmware {
    /// The reference platform's initial firmware hash (`currentHash = FIRMWARE_V2`, which the
    /// differential tests patch to tpm-rs's `TPM_PT_FIRMWARE_VERSION_2`, 0).
    pub const DEFAULT_HASH: u32 = 0;
    /// The reference platform's initial SVN (`currentSvn = 10`).
    pub const DEFAULT_SVN: u16 = 10;
    /// The reference platform's maximum SVN (`MAX_SVN`).
    pub const DEFAULT_MAX_SVN: u16 = 255;

    /// A simulated firmware with the given hash, SVN and maximum SVN (the SVN is capped at the
    /// maximum SVN).
    pub const fn new(hash: u32, svn: u16, max_svn: u16) -> Self {
        Self {
            hash: AtomicU32::new(hash),
            svn: AtomicU16::new(if svn > max_svn { max_svn } else { svn }),
            max_svn,
        }
    }

    /// The firmware hash the Firmware Secret is derived from.
    pub fn firmware_hash(&self) -> u32 {
        self.hash.load(Ordering::Relaxed)
    }

    /// Installs a firmware image with another hash (the MSSIM `TPM_SET_FW_HASH` signal,
    /// `_plat__SetTpmFirmwareHash`): the Firmware Secret changes.
    pub fn set_firmware_hash(&self, hash: u32) {
        self.hash.store(hash, Ordering::Relaxed);
    }

    /// Installs a firmware image with another SVN (the MSSIM `TPM_SET_FW_SVN` signal,
    /// `_plat__SetTpmFirmwareSvn`), capped at the maximum SVN.
    pub fn set_firmware_svn(&self, svn: u16) {
        self.svn
            .store(core::cmp::min(svn, self.max_svn), Ordering::Relaxed);
    }
}

impl Default for SimulatedFirmware {
    fn default() -> Self {
        Self::new(Self::DEFAULT_HASH, Self::DEFAULT_SVN, Self::DEFAULT_MAX_SVN)
    }
}

/// Fills `out` with `pattern` repeated.
fn repeat_into(pattern: &[u8], out: &mut [u8]) -> usize {
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = pattern[i % pattern.len()];
    }
    out.len()
}

impl TpmFirmware for SimulatedFirmware {
    fn firmware_svn(&self) -> u16 {
        self.svn.load(Ordering::Relaxed)
    }

    fn firmware_max_svn(&self) -> u16 {
        self.max_svn
    }

    fn firmware_secret(&self, out: &mut [u8]) -> Result<usize, FirmwareSecretUnavailable> {
        Ok(repeat_into(&self.firmware_hash().to_le_bytes(), out))
    }

    fn firmware_svn_secret(
        &self,
        svn: u16,
        out: &mut [u8],
    ) -> Result<usize, FirmwareSecretUnavailable> {
        if svn > self.firmware_svn() {
            return Err(FirmwareSecretUnavailable);
        }
        Ok(repeat_into(&svn.to_le_bytes(), out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_the_reference_platform() {
        let fw = SimulatedFirmware::default();
        assert_eq!(fw.firmware_svn(), 10);
        assert_eq!(fw.firmware_max_svn(), 255);
        assert_eq!(fw.firmware_hash(), 0);
        let mut secret = [0xAAu8; 64];
        assert_eq!(fw.firmware_secret(&mut secret), Ok(64));
        assert_eq!(secret, [0u8; 64]);
    }

    #[test]
    fn firmware_secret_repeats_the_hash_little_endian() {
        let fw = SimulatedFirmware::new(0x0102_0304, 1, 2);
        let mut secret = [0u8; 10];
        assert_eq!(fw.firmware_secret(&mut secret), Ok(10));
        assert_eq!(secret, [4, 3, 2, 1, 4, 3, 2, 1, 4, 3]);
    }

    #[test]
    fn svn_secret_is_available_up_to_the_current_svn() {
        let fw = SimulatedFirmware::new(0, 0x0203, 0xFFFF);
        let mut secret = [0u8; 5];
        assert_eq!(fw.firmware_svn_secret(0x0203, &mut secret), Ok(5));
        assert_eq!(secret, [3, 2, 3, 2, 3]);
        assert_eq!(fw.firmware_svn_secret(0, &mut secret), Ok(5));
        assert_eq!(secret, [0; 5]);
        assert_eq!(
            fw.firmware_svn_secret(0x0204, &mut secret),
            Err(FirmwareSecretUnavailable)
        );
    }

    #[test]
    fn svn_is_capped_at_the_maximum() {
        let fw = SimulatedFirmware::new(0, 300, 255);
        assert_eq!(fw.firmware_svn(), 255);
        fw.set_firmware_svn(3);
        assert_eq!(fw.firmware_svn(), 3);
        fw.set_firmware_svn(u16::MAX);
        assert_eq!(fw.firmware_svn(), 255);
        fw.set_firmware_hash(7);
        assert_eq!(fw.firmware_hash(), 7);
    }
}
