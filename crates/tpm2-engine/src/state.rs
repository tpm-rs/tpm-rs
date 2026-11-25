//! Volatile and non-volatile TPM state.
//!
//! Non-volatile fields in [`Nv`] follow the partitioning in **Part 1, Section
//! 34 (NV Memory)** of the TPM 2.0 Library Specification.

use tpm2::TpmSu;
use tpm2::crypto::Random;

use crate::platform::Platform;

/// Diagnostic data recorded when the TPM enters failure mode.
#[derive(Default)]
pub struct FailureData {}

/// Top-level TPM state passed to [`Engine::init`](crate::Engine::init).
pub struct State<P: Platform> {
    /// Non-volatile state retained across power cycles.
    pub nv: Nv<P>,
    /// Set when the TPM has entered failure mode.
    pub failure: Option<FailureData>,
    /// Volatile startup phase and RNG state.
    pub(crate) phase: Phase<P>,
}

impl<P: Platform> Default for State<P> {
    fn default() -> Self {
        Self {
            nv: Nv::default(),
            failure: None,
            phase: Phase::NotStarted,
        }
    }
}

/// Volatile startup phase of the TPM.
pub(crate) enum Phase<P: Platform> {
    /// Awaiting `TPM2_Startup`.
    NotStarted,
    /// `TPM2_Startup` completed; owns the active RNG.
    Started(<P::Crypto as Random>::Rng),
}

/// Non-volatile state retained by the platform across power cycles.
///
/// Mirrors **Part 1, Section 34 (NV Memory)** of the TPM 2.0 specification:
/// NV Indices (`index`), persistent objects (`evict`), state saved by
/// `TPM2_Shutdown` (`orderly`, `clear`, `reset`), and persistent data
/// (`persistent`).
#[non_exhaustive]
pub struct Nv<P: Platform> {
    /// NV Index values.
    pub index: P::IndexData,
    /// Objects made persistent by `TPM2_EvictControl`.
    pub evict: P::EvictData,
    /// State saved on any `TPM2_Shutdown`.
    pub orderly: OrderlyData,
    /// State saved by `TPM2_Shutdown(STATE)` and cleared on TPM Reset or TPM Restart.
    pub clear: ClearData,
    /// State saved by `TPM2_Shutdown(STATE)` and cleared on TPM Reset.
    pub reset: ResetData,
    /// Immediately persisted data always present in the TPM.
    pub persistent: PersistentData,
}

impl<P: Platform> Default for Nv<P> {
    fn default() -> Self {
        Self {
            index: P::IndexData::default(),
            evict: P::EvictData::default(),
            orderly: OrderlyData::default(),
            clear: ClearData::default(),
            reset: ResetData::default(),
            persistent: PersistentData::default(),
        }
    }
}

/// Data saved on any `TPM2_Shutdown` and restored on any `TPM2_Startup`.
#[doc(alias("ORDERLY_DATA", "go"))]
#[derive(Clone, Default)]
pub struct OrderlyData {}

/// Data saved by `TPM2_Shutdown(STATE)` and cleared on TPM Reset or TPM Restart.
#[doc(alias("STATE_CLEAR_DATA", "gc"))]
#[derive(Clone, Default)]
pub struct ClearData {}

/// Data saved by `TPM2_Shutdown(STATE)` and cleared on TPM Reset.
#[doc(alias("STATE_RESET_DATA", "gr"))]
#[derive(Clone, Default)]
pub struct ResetData {
    /// Incremented on every TPM Restart or TPM Resume; reset to zero on TPM Reset.
    #[doc(alias = "restartCount")]
    pub restart_count: u32,
    /// Incremented on every TPM Restart; reset to zero on TPM Reset.
    #[doc(alias = "clearCount")]
    pub clear_count: u32,
}

/// Immediately saved persistent NV data.
#[doc(alias("PERSISTENT_DATA", "gp"))]
#[derive(Clone, Default)]
pub struct PersistentData {
    /// Pending orderly shutdown type, or `None` when not orderly.
    #[doc(alias("orderlyState", "SU_NONE_VALUE"))]
    pub orderly_state: Option<TpmSu>,
    /// Counter incremented on every TPM Reset.
    #[doc(alias = "resetCount")]
    pub reset_count: u32,
    /// Lifetime counter incremented on every TPM Reset; overflow enters failure mode.
    #[doc(alias = "totalResetCount")]
    pub total_reset_count: u64,
}
