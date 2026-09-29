//! System Timer Abstraction.
//!
//! Exposes a monotonic interface tracking standard TPM hardware ticks, corresponding to the
//! `clock` parameter defined in the TCG TPM 2.0 Library Specification, Part 2: Structures, Section 11.4 (`TPMS_CLOCK_INFO`).
//!
//! ## Specification Requirements & Rules for Implementers
//!
//! Per the TPM 2.0 specification:
//! - **Strict Monotonicity**: The timer must be a monotonically increasing counter. It must only advance
//!   and must never flow backward or be reset during operation, except when the Storage Primary Seed is changed
//!   (e.g., via `TPM2_Clear()`).
//! - **Millisecond Resolution**: The reference timer must increment once per millisecond (derived from the
//!   TPM oscillator or equivalent hardware platform source).
//!
//! ## Guarantees Provided to Users
//!
//! - **Safe Elapsed-Time Measurement**: Because the clock is guaranteed to never flow backward or jump
//!   arbitrarily, it provides a secure foundation for validating authorization policy expirations, session
//!   timeouts, and dictionary attack lockout durations.
//! - **Attestation Grounding**: Provides the monotonic progress backing for clock attestation (`TPMS_CLOCK_INFO`).

pub use tpm2::platform::TpmTimer;

/// Software-emulated implementation maintaining a static software tick state.
///
/// This acts mainly as a stub for debugging or virtual iterations entirely disconnected
/// from real physical timing characteristics. Users manually bump `.tick`.
pub struct SoftwareTimer {
    pub tick: u64,
}

impl TpmTimer for SoftwareTimer {
    fn timer_read(&self) -> u64 {
        self.tick
    }
}
