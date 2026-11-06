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
//! so it is the platform's job (`tpm2_engine::Platform::firmware_secret`/`firmware_svn_secret`;
//! the firmware's hash, SVN and maximum SVN are part of the platform information,
//! `tpm2_engine::Firmware`).
//!
//! A platform that provides no Firmware Secret supports no limited hierarchy: their handles fail
//! with `TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED` ("the Firmware Secret is unavailable").
//!
//! [`reference_firmware_secret`] and [`reference_firmware_svn_secret`] are the *insecure* dummy
//! secrets of the TCG reference platform (`Platform/src/VendorInfo.c`), for simulators and tests.

/// The error of a firmware secret request: the secret is not available (TPM 2.0 Part 2,
/// `TPM_RC_FW_LIMITED`: "the Firmware Secret is unavailable"; `TPM_RC_SVN_LIMITED`: "the
/// Firmware SVN Secret associated with the given SVN is unavailable").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareSecretUnavailable;

/// The reference platform's initial firmware hash (`currentHash = FIRMWARE_V2`, which the
/// differential tests patch to tpm-rs's `TPM_PT_FIRMWARE_VERSION_2`, 0).
pub const REFERENCE_FIRMWARE_HASH: u32 = 0;
/// The reference platform's initial firmware SVN (`currentSvn = 10`).
pub const REFERENCE_FIRMWARE_SVN: u16 = 10;
/// The reference platform's maximum firmware SVN (`MAX_SVN`).
pub const REFERENCE_FIRMWARE_MAX_SVN: u16 = 255;

/// Fills `out` with `pattern` repeated.
fn repeat_into(pattern: &[u8], out: &mut [u8]) -> usize {
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = pattern[i % pattern.len()];
    }
    out.len()
}

/// The *insecure* dummy Firmware Secret of the TCG reference platform
/// (`_plat__GetTpmFirmwareSecret`): the 32-bit firmware `hash` repeated in little-endian byte
/// order (the reference copies the bytes of a native `uint32_t` on little-endian hosts), filling
/// `out`. Returns `out.len()`.
pub fn reference_firmware_secret(hash: u32, out: &mut [u8]) -> usize {
    repeat_into(&hash.to_le_bytes(), out)
}

/// The *insecure* dummy Firmware SVN Secret of `svn` of the TCG reference platform
/// (`_plat__GetTpmFirmwareSvnSecret`): `svn` repeated in little-endian byte order, filling
/// `out`; available only for `svn <= current_svn` (the firmware's SVN).
pub fn reference_firmware_svn_secret(
    current_svn: u16,
    svn: u16,
    out: &mut [u8],
) -> Result<usize, FirmwareSecretUnavailable> {
    if svn > current_svn {
        return Err(FirmwareSecretUnavailable);
    }
    Ok(repeat_into(&svn.to_le_bytes(), out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_values() {
        assert_eq!(
            (
                REFERENCE_FIRMWARE_HASH,
                REFERENCE_FIRMWARE_SVN,
                REFERENCE_FIRMWARE_MAX_SVN
            ),
            (0, 10, 255)
        );
        let mut secret = [0xAAu8; 64];
        assert_eq!(
            reference_firmware_secret(REFERENCE_FIRMWARE_HASH, &mut secret),
            64
        );
        assert_eq!(secret, [0u8; 64]);
    }

    #[test]
    fn firmware_secret_repeats_the_hash_little_endian() {
        let mut secret = [0u8; 10];
        assert_eq!(reference_firmware_secret(0x0102_0304, &mut secret), 10);
        assert_eq!(secret, [4, 3, 2, 1, 4, 3, 2, 1, 4, 3]);
    }

    #[test]
    fn svn_secret_is_available_up_to_the_current_svn() {
        let mut secret = [0u8; 5];
        assert_eq!(
            reference_firmware_svn_secret(0x0203, 0x0203, &mut secret),
            Ok(5)
        );
        assert_eq!(secret, [3, 2, 3, 2, 3]);
        assert_eq!(reference_firmware_svn_secret(0x0203, 0, &mut secret), Ok(5));
        assert_eq!(secret, [0; 5]);
        assert_eq!(
            reference_firmware_svn_secret(0x0203, 0x0204, &mut secret),
            Err(FirmwareSecretUnavailable)
        );
    }
}
