//! System Timer Abstraction.

/// Interface defining the abstract monotonic hardware clock ticks used for
/// time attestation and authorization policy expiration checks.
pub trait TpmTimer {
    /// Returns the monotonic hardware timer count in milliseconds.
    fn timer_read(&self) -> u64;
}
