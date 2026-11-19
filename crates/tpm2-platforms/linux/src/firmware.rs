//! The firmware identity of the TCG reference platform (`Platform/src/VendorInfo.c`): its initial
//! firmware hash and Security Version Numbers, and its *insecure* dummy Firmware Secret and
//! Firmware SVN Secrets, which [`crate::LinuxPlatform`] provides to the TPM (for simulators and
//! tests, like the reference platform; a real platform obtains its secrets from its boot chain,
//! see `tpm2::platform::firmware`).

use tpm2::platform::FirmwareSecretUnavailable;

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
