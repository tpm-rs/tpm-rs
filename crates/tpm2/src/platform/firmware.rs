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
//! The *insecure* dummy secrets of the TCG reference platform (`Platform/src/VendorInfo.c`), for
//! simulators and tests, are provided by the reference platform (`tpm2_platform_linux`).

/// The error of a firmware secret request: the secret is not available (TPM 2.0 Part 2,
/// `TPM_RC_FW_LIMITED`: "the Firmware Secret is unavailable"; `TPM_RC_SVN_LIMITED`: "the
/// Firmware SVN Secret associated with the given SVN is unavailable").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareSecretUnavailable;
