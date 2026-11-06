//! The platform a [`TpmEngine`](crate::TpmEngine) runs on.
//!
//! Everything the engine needs from its environment is behind the [`Platform`] trait: the
//! cryptography backend, the monotonic timer, the platform random number generator, the type
//! of the structure that holds the NV data ([`IndexState`], kept in the TPM state as
//! [`Nv::index`]), the firmware identity, the secure transport layer and the immutable
//! platform [`Info`]. The platform also decides how the NV data reaches external storage
//! ([`Platform::load_nv`], [`Platform::store_nv`]) and how the runtime state is serialized
//! for migration ([`Platform::serialize`], [`Platform::deserialize`]). The component interfaces themselves ([`crate::storage::NvStorage`], [`TpmTimer`],
//! [`TpmFirmware`], [`SecureChannel`]) live in [`tpm2::platform`].
//!
//! Every platform crate defines its own platform type implementing [`Platform`] (e.g.
//! `tpm2_platform_linux::LinuxPlatform`) and builds a [`TpmEngine`](crate::TpmEngine) over it.

use crate::state::Nv;
use crate::state::State;
use crate::storage::IndexState;
use crate::timer::TpmTimer;
use tpm2::crypto::{Crypto, Rng};
use tpm2::errors::TpmRc;
use tpm2::platform::{SecureChannel, TpmFirmware};
use tpm2::{TpmCc, TpmaCc};

/// Immutable information about the platform and the TPM vendor, reported by
/// `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)` and in attestation structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    /// `TPM_PT_MANUFACTURER`: the vendor ID (four ASCII characters, big-endian).
    pub manufacturer: u32,
    /// `TPM_PT_VENDOR_STRING_1` .. `TPM_PT_VENDOR_STRING_4`: the vendor-specific description
    /// of the TPM (four ASCII characters each, big-endian; zero-padded).
    pub vendor_strings: [u32; 4],
    /// `TPM_PT_VENDOR_TPM_TYPE`: the vendor-defined TPM model.
    pub vendor_tpm_type: u32,
    /// `TPM_PT_FIRMWARE_VERSION_1` (`gp.firmwareV1`): the most-significant 32 bits of the
    /// vendor-specific firmware version.
    pub firmware_version_1: u32,
    /// `TPM_PT_FIRMWARE_VERSION_2` (`gp.firmwareV2`): the least-significant 32 bits of the
    /// vendor-specific firmware version.
    pub firmware_version_2: u32,
}

impl Info {
    /// The information `tpm-rs` reports by default: manufacturer `"GOOG"`, vendor string
    /// `"TPM-RUST"`, TPM type 1 and firmware version 1.0.
    pub const DEFAULT: Self = Self {
        manufacturer: 0x474F_4F47,                        // "GOOG"
        vendor_strings: [0x5450_4D2D, 0x5255_5354, 0, 0], // "TPM-", "RUST"
        vendor_tpm_type: 1,
        firmware_version_1: 1,
        firmware_version_2: 0,
    };

    /// The firmware version in attestation structures (`TPMS_ATTEST.firmwareVersion`):
    /// `(TPM_PT_FIRMWARE_VERSION_1 << 32) | TPM_PT_FIRMWARE_VERSION_2` (`FillInAttestInfo()`).
    pub const fn attest_firmware_version(&self) -> u64 {
        ((self.firmware_version_1 as u64) << 32) | self.firmware_version_2 as u64
    }
}

impl Default for Info {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Trait all platforms must implement to use `tpm2-engine`.
///
/// A platform provides the components the engine uses (as associated types, so that the
/// engine is monomorphized over them), the immutable platform [`Info`] and the
/// customizations of how the TPM state reaches storage: loading and storing the NV data
/// ([`Platform::load_nv`], [`Platform::store_nv`]) and serializing the runtime state
/// ([`Platform::serialize`], [`Platform::deserialize`]).
pub trait Platform: Sized {
    /// Cryptography backend ([`Crypto`]). The backend's interfaces are static (its algorithms
    /// are associated types); the platform only selects it.
    type Crypto: Crypto;
    /// Monotonic timer.
    type Timer: TpmTimer;
    /// Platform random number generator ([`Rng::fill_bytes`] draws random bytes,
    /// [`Rng::stir_bytes`] mixes additional entropy into its state and [`Rng::init`]
    /// reinitializes its entropy source at `_TPM_Init`).
    type Rng: Rng + Sync;
    /// Structure used to hold the NV data (the `Handle -> [u8]` mapping of the NV Indices,
    /// persistent objects and internal records, see [`IndexState`]). The TPM state owns it
    /// ([`Nv::index`]); every [`crate::storage::NvStorage`] medium is one.
    type IndexState: IndexState;

    /// Immutable info from the platform (firmware version, vendor ID, ...). Defaults to
    /// [`Info::DEFAULT`].
    fn info(&self) -> &Info {
        &Info::DEFAULT
    }

    /// The monotonic timer.
    fn timer(&self) -> &Self::Timer;

    /// The platform random number generator.
    fn rng(&mut self) -> &mut Self::Rng;

    /// Firmware identity ([`TpmFirmware`]: the Firmware Secret, the Firmware SVN Secrets and
    /// the current and maximum firmware SVN). `None` (the default) is a TPM without
    /// firmware-limited and SVN-limited hierarchies: their handles fail with
    /// `TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED`, they are not listed by `TPM2_GetCapability`,
    /// and `TPM_PT_FIRMWARE_SVN`/`TPM_PT_FIRMWARE_MAX_SVN` are 0. The firmware is shared
    /// (`Sync`) so that a platform can change it (e.g. a simulated firmware update) while the
    /// TPM uses it.
    fn firmware(&self) -> Option<&(dyn TpmFirmware + Sync)> {
        None
    }

    /// Secure channel information of the TPM's secure transport layer ([`SecureChannel`]: the
    /// TPM SPDM authentication public keys and the SPDM session protecting the current
    /// command), used with the `sec-channel` feature. `None` (the default) is a TPM without
    /// SPDM keys that never receives a command within an SPDM session.
    fn secure_channel(&self) -> Option<&(dyn SecureChannel + Sync)> {
        None
    }

    /// The vendor-specific commands the platform implements (in addition to the engine's
    /// `TPM2_Vendor_TCG_Test`), at most [`MAX_PLATFORM_VENDOR_COMMANDS`]; see
    /// [`VendorCommand`]. The engine lists them in `TPM2_GetCapability` (`TPM_CAP_COMMANDS`,
    /// `TPM_PT_VENDOR_COMMANDS`, `TPM_PT_TOTAL_COMMANDS`), lets them be audited and executes
    /// them with [`Platform::execute_vendor_command`]. The list must not change while the TPM
    /// runs. Defaults to none.
    fn vendor_commands(&self) -> &[VendorCommand] {
        &[]
    }

    /// Executes the vendor command `code` (one of [`Platform::vendor_commands`]) with the
    /// parameter area `parameters` (the command after its header: a vendor command has no
    /// handles and no sessions) and writes its response parameters to the start of `response`,
    /// returning their size. An error is returned as the response code of the command (e.g.
    /// `TPM_RC_SIZE` for unexpected parameter octets).
    ///
    /// The engine calls it after the common command checks (command size, `TPM2_Startup`, no
    /// session area); the command's state lives in the platform. The default fails with
    /// `TPM_RC_COMMAND_CODE`.
    fn execute_vendor_command(
        &mut self,
        code: TpmCc,
        parameters: &[u8],
        response: &mut [u8],
    ) -> Result<usize, TpmRc> {
        let _ = (code, parameters, response);
        Err(TpmRc::COMMAND_CODE)
    }

    /// Reads the NV data from external storage into `nv`.
    ///
    /// Called at `_TPM_Init` ([`crate::TpmEngine::reset`]), before the engine reloads its
    /// NV-synced state ([`crate::PersistentState`], [`crate::OrderlyState`] and the state saved
    /// by `TPM2_Shutdown(TPM_SU_STATE)`) from [`Nv::index`]. A platform whose
    /// [`Platform::IndexState`] is the NV medium itself (the default) has nothing to do.
    fn load_nv(&mut self, nv: &mut Nv<Self>) {
        let _ = nv;
    }

    /// Syncs the NV data in `nv` back to external storage.
    ///
    /// Called after every command, `_TPM_Init` and manufacture
    /// ([`crate::TpmEngine::init_storage`]), once the engine has written its NV-synced state
    /// to [`Nv::index`]. A platform whose [`Platform::IndexState`] is the NV medium itself
    /// (the default) has nothing to do.
    fn store_nv(&mut self, nv: &Nv<Self>) {
        let _ = nv;
    }

    /// Serializes the runtime state `state` (with its NV data) into `out`, for migrating the
    /// TPM, and returns the number of octets written. The format is the platform's.
    ///
    /// # Panics
    /// The default implementation panics: a platform that migrates the TPM implements it.
    fn serialize(&self, state: &State<Self>, out: &mut [u8]) -> Result<usize, SerializeError> {
        let _ = (state, out);
        unimplemented!("Platform::serialize is not implemented by this platform")
    }

    /// Restores the runtime state `state` (with its NV data) from `data`, written by
    /// [`Platform::serialize`] (possibly on another platform). A rejected state must leave
    /// `state` unchanged.
    ///
    /// # Panics
    /// The default implementation panics: a platform that migrates the TPM implements it.
    fn deserialize(&self, data: &[u8], state: &mut State<Self>) -> Result<(), DeserializeError> {
        let _ = (data, state);
        unimplemented!("Platform::deserialize is not implemented by this platform")
    }
}

/// Error of [`Platform::serialize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializeError {
    /// The serialized state does not fit the output buffer.
    BufferTooSmall,
    /// The state cannot be serialized (e.g. it is inconsistent or cannot be read).
    InvalidState,
}

impl core::fmt::Display for SerializeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::BufferTooSmall => "the serialized TPM state does not fit the buffer",
            Self::InvalidState => "the TPM state cannot be serialized",
        })
    }
}

impl core::error::Error for SerializeError {}

/// Error of [`Platform::deserialize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeserializeError {
    /// The data is not a valid serialized state.
    InvalidData,
}

impl core::fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidData => "the data is not a valid serialized TPM state",
        })
    }
}

impl core::error::Error for DeserializeError {}

/// The largest number of vendor commands a platform may implement
/// ([`Platform::vendor_commands`]); further ones are ignored.
pub const MAX_PLATFORM_VENDOR_COMMANDS: usize = 16;

/// A vendor-specific command implemented by the platform ([`Platform::vendor_commands`]).
///
/// A platform vendor command has no handles and no authorization sessions (like the
/// references' `NO_SESSIONS` commands: a command with `TPM_ST_SESSIONS` fails with
/// `TPM_RC_AUTH_CONTEXT`); its parameters and response parameters are interpreted by the
/// platform ([`Platform::execute_vendor_command`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorCommand {
    /// The command code; it must have the `V` bit (`TPM_CC_VEND`) and differ from the
    /// engine's `TPM2_Vendor_TCG_Test`.
    pub code: TpmCc,
    /// Further attributes of the command reported in its `TPMA_CC` (e.g. `NV`); the engine
    /// sets `commandIndex` (the low 16 bits of the code) and `V`.
    pub attributes: TpmaCc,
}
