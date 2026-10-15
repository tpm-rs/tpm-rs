//! The seed of a TPM's random-number generation, and how to fix it for
//! reproducing a test run.
//!
//! A [`crate::tpm::Tpm`] reproduces the random-number generation of the C
//! reference TPMs (see `tpm2_impl::reference_rng`), which is seeded from the
//! process ID (`getpid()`) and the initial real-time clock
//! (`_plat__RealTime()`) of the reference. The `Tpm` chooses these values
//! itself ([`ReferenceSeed::choose`]: by default the test process's ID and
//! its current monotonic time), builds its `tpm-rs` simulator from them and,
//! with the `differential` feature, hands them to every C reference process
//! it launches (through [`SEED_ENV`] in the child's environment; the
//! reference binary returns the pid from its `getpid()`, which `build.rs`
//! redirects to `difftest_getpid`, and starts its virtual clock at the real
//! time). All references of a `Tpm` therefore draw the same random values as
//! `tpm-rs`, and are compared with each other through it.
//!
//! Every `Tpm` prints its seed as `TPM_REFERENCE_SEED=<pid>:<realtime_ms>`
//! (shown with the output of a failing test); setting [`SEED_ENV`] to that
//! value makes every `Tpm` use exactly these values again, so the run can be
//! reproduced.

use std::fmt;
use std::sync::OnceLock;
use std::time::Instant;

/// Environment variable that fixes the seed of every `Tpm` (`<pid>:<realtime_ms>`).
pub const SEED_ENV: &str = "TPM_REFERENCE_SEED";

/// The values the random-number generation of a TPM is seeded from: the
/// process ID that `getpid()` returns to the reference and the reference's
/// initial `_plat__RealTime()` in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceSeed {
    /// The process ID.
    pub pid: u32,
    /// The initial real time (milliseconds).
    pub realtime_ms: u64,
}

impl ReferenceSeed {
    /// Parses `<pid>:<realtime_ms>` (surrounding whitespace is ignored).
    pub fn parse(value: &str) -> Result<Self, String> {
        let invalid = || format!("{SEED_ENV}=`{value}`: expected `<pid>:<realtime_ms>`");
        let (pid, realtime) = value.trim().split_once(':').ok_or_else(invalid)?;
        Ok(Self {
            pid: pid.trim().parse().map_err(|_| invalid())?,
            realtime_ms: realtime.trim().parse().map_err(|_| invalid())?,
        })
    }

    /// The seed fixed by [`SEED_ENV`], if the variable is set (and not empty).
    ///
    /// # Panics
    /// If the variable is set to a malformed value.
    pub fn from_env() -> Option<Self> {
        static FIXED: OnceLock<Option<ReferenceSeed>> = OnceLock::new();
        *FIXED.get_or_init(|| {
            let value = std::env::var(SEED_ENV).ok()?;
            if value.trim().is_empty() {
                return None;
            }
            Some(Self::parse(&value).unwrap_or_else(|e| panic!("{e}")))
        })
    }
}

impl ReferenceSeed {
    /// The seed for a new `Tpm`: the one fixed by [`SEED_ENV`], or else the
    /// test process's ID and its current monotonic time ([`monotonic_ms`]),
    /// the values a C reference running in this process would use.
    pub fn choose() -> Self {
        Self::from_env().unwrap_or_else(|| Self {
            pid: std::process::id(),
            realtime_ms: monotonic_ms(),
        })
    }
}

/// A monotonic clock in milliseconds, comparable to the C references'
/// `CLOCK_MONOTONIC` `_plat__RealTime()`: the system uptime (`/proc/uptime`)
/// when first called, plus the time elapsed since then (`Instant`), so that
/// consecutive calls have millisecond resolution. Falls back to the
/// milliseconds since the Unix epoch if `/proc/uptime` is unavailable.
pub fn monotonic_ms() -> u64 {
    static BASE: OnceLock<(u64, Instant)> = OnceLock::new();
    let (base_ms, start) = BASE.get_or_init(|| {
        let uptime = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .map(|secs| (secs * 1000.0) as u64);
        let base = uptime.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64)
        });
        (base, Instant::now())
    });
    base_ms.saturating_add(u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))
}

impl fmt::Display for ReferenceSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.pid, self.realtime_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display_round_trip() {
        let seed = ReferenceSeed::parse(" 4242 : 1234567 ").unwrap();
        assert_eq!(
            seed,
            ReferenceSeed {
                pid: 4242,
                realtime_ms: 1234567
            }
        );
        assert_eq!(ReferenceSeed::parse(&seed.to_string()), Ok(seed));
        assert!(ReferenceSeed::parse("4242").is_err());
        assert!(ReferenceSeed::parse("x:1").is_err());
        assert!(ReferenceSeed::parse("1:-1").is_err());
    }
}
