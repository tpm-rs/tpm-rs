//! TPM 2.0 Platform Abstraction Layer
//!
//! The `tpm-rs` library is designed to run across diverse operational environments—ranging
//! from resource-constrained bare-metal embedded firmware (utilizing custom hardware accelerators)
//! to user-space host applications running on a desktop operating system (e.g., Linux, Windows).
//!
//! The `platform` module encapsulates all external dependencies and hardware interfaces (such as
//! cryptography, clocks, non-volatile storage, and physical presence controls) into a clean set
//! of traits. This isolation keeps the core library's state machine, wire-format serialization,
//! and command processing logic completely independent of the execution environment.
//!
//! ### Submodules
//!
//! - [`storage`]: Low-level non-volatile memory (NV) access.
//! - [`timer`]: Monotonic clock/timer interface.
//! - [`pcr`]: Structure containing platform configuration register banks.
//! - [`firmware`]: Firmware identity (Firmware Secret, Firmware SVN Secrets, SVNs) for the
//!   firmware-limited and SVN-limited hierarchies.

pub mod firmware;
pub mod pcr;
pub mod storage;
pub mod timer;

pub use firmware::{FirmwareSecretUnavailable, SimulatedFirmware, TpmFirmware};
pub use pcr::PcrState;
pub use storage::{NvStorage, StorageError};
pub use timer::TpmTimer;

use crate::crypto::{CryptoProvider, Rng};

/// Context defining the resources the TPM engine has access to.
pub struct TpmPlatform<'a, C, S, T, R>
where
    C: CryptoProvider,
    S: NvStorage,
    T: TpmTimer,
    R: Rng,
{
    /// Cryptography provider.
    pub crypto: &'a mut C,
    /// NV storage provider.
    pub storage: &'a mut S,
    /// Monotonic timer.
    pub timer: &'a mut T,
    /// Platform random number generator ([`Rng::fill_bytes`] draws random bytes and
    /// [`Rng::reseed`] mixes additional entropy into its state).
    pub rng: &'a mut R,
    /// Firmware identity ([`TpmFirmware`]: the Firmware Secret, the Firmware SVN Secrets and
    /// the current and maximum firmware SVN). `None` (the default of [`TpmPlatform::new`]) is a
    /// TPM without firmware-limited and SVN-limited hierarchies: their handles fail with
    /// `TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED`, they are not listed by `TPM2_GetCapability`,
    /// and `TPM_PT_FIRMWARE_SVN`/`TPM_PT_FIRMWARE_MAX_SVN` are 0. The firmware is shared
    /// (`Sync`) so that a platform can change it (e.g. a simulated firmware update) while the
    /// TPM borrows it.
    pub firmware: Option<&'a (dyn TpmFirmware + Sync)>,
}

impl<'a, C, S, T, R> TpmPlatform<'a, C, S, T, R>
where
    C: CryptoProvider,
    S: NvStorage,
    T: TpmTimer,
    R: Rng,
{
    /// Constructs a new `TpmPlatform` from mutable references to hardware providers.
    pub fn new(crypto: &'a mut C, storage: &'a mut S, timer: &'a mut T, rng: &'a mut R) -> Self {
        Self {
            crypto,
            storage,
            timer,
            rng,
            firmware: None,
        }
    }

    /// Gives the TPM the firmware identity `firmware`, enabling the firmware-limited and
    /// SVN-limited hierarchies (see [`TpmPlatform::firmware`]).
    pub fn with_firmware(mut self, firmware: &'a (dyn TpmFirmware + Sync)) -> Self {
        self.firmware = Some(firmware);
        self
    }
}
