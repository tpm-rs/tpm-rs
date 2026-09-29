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

pub mod pcr;
pub mod storage;
pub mod timer;

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
    R: Rng + Sync,
{
    /// Cryptography provider.
    pub crypto: &'a mut C,
    /// NV storage provider.
    pub storage: &'a mut S,
    /// Monotonic timer.
    pub timer: &'a mut T,
    /// Random number generator.
    pub rng: &'a R,
}

impl<'a, C, S, T, R> TpmPlatform<'a, C, S, T, R>
where
    C: CryptoProvider,
    S: NvStorage,
    T: TpmTimer,
    R: Rng + Sync,
{
    /// Constructs a new `TpmPlatform` from mutable references to hardware providers.
    pub fn new(crypto: &'a mut C, storage: &'a mut S, timer: &'a mut T, rng: &'a R) -> Self {
        Self {
            crypto,
            storage,
            timer,
            rng,
        }
    }
}
