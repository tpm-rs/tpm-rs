//! Linux Platform Implementation for TPM2
//!
//! Provides Linux-specific implementations of hardware abstraction layer components
//! like `TpmTimer` using `std::time::Instant` and `Rng` using `/dev/urandom`.

#![forbid(unsafe_code)]

#[cfg(not(any(feature = "rust", feature = "crux", feature = "bssl")))]
compile_error!(
    "At least one cryptographic backend feature must be enabled: 'rust', 'crux', or 'bssl'."
);

#[cfg(all(feature = "rust", feature = "crux"))]
compile_error!("Features 'rust' and 'crux' are mutually exclusive.");

#[cfg(all(feature = "rust", feature = "bssl"))]
compile_error!("Features 'rust' and 'bssl' are mutually exclusive.");

#[cfg(all(feature = "crux", feature = "bssl"))]
compile_error!("Features 'crux' and 'bssl' are mutually exclusive.");

use std::fs::File;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::Instant;
use tpm2::crypto::Rng;
use tpm2::crypto::{CryptoError, CryptoProvider};
use tpm2_impl::TpmPlatform;
use tpm2_impl::storage::NvStorage;
use tpm2_impl::timer::TpmTimer;

#[cfg(feature = "rust")]
pub use tpm2_crypto_rust::RustCryptoProvider as PlatformCryptoProvider;

#[cfg(feature = "crux")]
pub use tpm2_crypto_crux::CruxCryptoProvider as PlatformCryptoProvider;

#[cfg(feature = "bssl")]
pub use tpm2_crypto_bssl::BsslCryptoProvider as PlatformCryptoProvider;

#[cfg(feature = "reference-rng")]
mod reference;
#[cfg(feature = "reference-rng")]
pub use reference::{GlibcRand, ReferenceEntropy, VirtualClock};

/// Linux-specific monotonic timer based on `std::time::Instant`.
///
/// With the `reference-rng` feature, [`LinuxTimer::new_virtual`] additionally
/// provides a timer driven by a [`VirtualClock`], which only moves when
/// [`LinuxTimer::advance`] is called, so that time passes exactly as for a C
/// reference TPM driven by the same virtual clock.
pub struct LinuxTimer {
    start: LazyLock<Instant>,
    /// The virtual clock, or `None` for the wall clock.
    #[cfg(feature = "reference-rng")]
    virtual_clock: Option<VirtualClock>,
}

impl LinuxTimer {
    /// Creates a new `LinuxTimer` anchored to the current instant.
    pub const fn new() -> Self {
        Self {
            start: LazyLock::new(Instant::now),
            #[cfg(feature = "reference-rng")]
            virtual_clock: None,
        }
    }

    /// Creates a timer that reads the elapsed time of `clock` (starting at
    /// 0 ms) and only advances through [`LinuxTimer::advance`] (or another
    /// handle of `clock`).
    #[cfg(feature = "reference-rng")]
    pub fn new_virtual(clock: VirtualClock) -> Self {
        Self {
            start: LazyLock::new(Instant::now),
            virtual_clock: Some(clock),
        }
    }

    /// Advances a virtual timer by `ms` milliseconds.
    ///
    /// Returns `false` (and does nothing) for a wall-clock timer, whose time
    /// cannot be moved.
    #[cfg(feature = "reference-rng")]
    pub fn advance(&self, ms: u64) -> bool {
        match &self.virtual_clock {
            Some(clock) => {
                clock.advance(ms);
                true
            }
            None => false,
        }
    }
}

impl TpmTimer for LinuxTimer {
    fn timer_read(&self) -> u64 {
        #[cfg(feature = "reference-rng")]
        if let Some(clock) = &self.virtual_clock {
            return clock.elapsed_ms();
        }
        self.start.elapsed().as_millis() as u64
    }
}

static URANDOM_FILE: OnceLock<Mutex<File>> = OnceLock::new();

/// Linux-specific random number generator reading from OS entropy source.
///
/// Implements the platform [`Rng`] of [`TpmPlatform`]: [`Rng::fill_bytes`]
/// draws from the [`PlatformCryptoProvider`]'s CSPRNG (the `getrandom`
/// syscall), falling back to `/dev/urandom`. [`Rng::reseed`] is a no-op,
/// because the OS entropy source cannot be stirred.
///
/// With the `reference-rng` feature, [`LinuxRng::reference`] additionally
/// provides the entropy source of the C reference TPMs' simulator platform
/// (`_plat__GetEntropy()`, see [`ReferenceEntropy`]), so that a TPM using it
/// draws exactly the platform entropy a C reference TPM process with the same
/// process ID and clock draws.
pub struct LinuxRng {
    /// The reference entropy source, or `None` for OS entropy.
    #[cfg(feature = "reference-rng")]
    reference: Option<ReferenceEntropy>,
}

impl LinuxRng {
    /// Creates a new `LinuxRng`.
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "reference-rng")]
            reference: None,
        }
    }

    /// Creates a `LinuxRng` that reproduces the platform entropy of a C
    /// reference TPM process (see [`ReferenceEntropy::new`]). **Not for
    /// production use.**
    #[cfg(feature = "reference-rng")]
    pub fn reference(entropy: ReferenceEntropy) -> Self {
        Self {
            reference: Some(entropy),
        }
    }

    /// Pre-opens `/dev/urandom` for fallback use in sandboxed environments where opening new files at runtime is forbidden.
    pub fn init_urandom() {
        let _ = URANDOM_FILE.get_or_init(|| {
            Mutex::new(
                File::open("/dev/urandom")
                    .expect("Failed to open /dev/urandom during LinuxRng initialization"),
            )
        });
    }
}

impl Rng for LinuxRng {
    /// Fills `dest` with random bytes from the OS entropy source (or from the
    /// reference entropy source of a [`LinuxRng::reference`] generator).
    ///
    /// # Errors
    /// * [`CryptoError::Internal`] - Neither the `getrandom` syscall nor
    ///   `/dev/urandom` produced `dest.len()` bytes, or the reference entropy
    ///   source failed its continuous test.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        #[cfg(feature = "reference-rng")]
        if let Some(entropy) = &mut self.reference {
            return entropy.fill(dest);
        }

        // 1. Try PlatformCryptoProvider (getrandom syscall) in a loop to handle EINTR.
        for _ in 0..10_000 {
            if PlatformCryptoProvider.get_random(dest).is_ok() {
                return Ok(());
            }
        }

        // 2. If getrandom persistently fails, try reading from pre-opened URANDOM_FILE.
        use std::io::Read as _;
        let file_mutex = URANDOM_FILE.get_or_init(|| {
            Mutex::new(
                File::open("/dev/urandom").expect("Failed to open /dev/urandom for fallback RNG"),
            )
        });

        let mut file = match file_mutex.lock() {
            Ok(f) => f,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut offset = 0;
        let mut attempts = 0;
        while offset < dest.len() && attempts < 100_000 {
            match file.read(&mut dest[offset..]) {
                Ok(0) => attempts += 1,
                Ok(n) => offset += n,
                Err(e)
                    if e.kind() == std::io::ErrorKind::Interrupted
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    attempts += 1;
                }
                Err(_) => {
                    if let Ok(new_file) = File::open("/dev/urandom") {
                        *file = new_file;
                        continue;
                    }
                    attempts += 1;
                }
            }
        }
        if offset == dest.len() {
            return Ok(());
        }

        // 3. Direct open fallback if static lock or fd failed.
        if let Ok(mut file) = File::open("/dev/urandom") {
            let mut offset = 0;
            let mut attempts = 0;
            while offset < dest.len() && attempts < 100_000 {
                match file.read(&mut dest[offset..]) {
                    Ok(0) => attempts += 1,
                    Ok(n) => offset += n,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::Interrupted
                            || e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        attempts += 1;
                    }
                    Err(_) => break,
                }
            }
            if offset == dest.len() {
                return Ok(());
            }
        }

        Err(CryptoError::Internal)
    }

    /// Ignores `data`: the OS entropy source cannot be stirred, so
    /// `TPM2_StirRandom` input has no effect on the platform RNG.
    fn reseed(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }

    /// (Re)seeds the reference entropy source (`_plat__GetEntropy(NULL, 0)`);
    /// nothing for OS entropy.
    fn init(&mut self) -> Result<(), CryptoError> {
        #[cfg(feature = "reference-rng")]
        if let Some(entropy) = &mut self.reference {
            entropy.init();
        }
        Ok(())
    }
}

/// Helper function to instantiate a `TpmPlatform` with Linux hardware components.
pub fn create_linux_platform<'a, C, S>(
    crypto: &'a mut C,
    storage: &'a mut S,
    timer: &'a mut LinuxTimer,
    platform_rng: &'a mut LinuxRng,
) -> TpmPlatform<'a, C, S, LinuxTimer, LinuxRng>
where
    C: CryptoProvider,
    S: NvStorage,
{
    TpmPlatform::new(crypto, storage, timer, platform_rng)
}

impl Default for LinuxTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for LinuxRng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rng_and_timer_use_os_sources() {
        let mut rng = LinuxRng::new();
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        rng.fill_bytes(&mut a).unwrap();
        rng.fill_bytes(&mut b).unwrap();
        assert_ne!(a, b);
        let timer = LinuxTimer::new();
        let t0 = timer.timer_read();
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(timer.timer_read() > t0);
    }

    #[cfg(feature = "reference-rng")]
    #[test]
    fn virtual_timer_only_moves_when_advanced() {
        let clock = VirtualClock::new(1_000_000);
        let timer = LinuxTimer::new_virtual(clock.clone());
        assert_eq!(timer.timer_read(), 0);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(timer.timer_read(), 0);
        assert!(timer.advance(1500));
        assert_eq!(timer.timer_read(), 1500);
        assert_eq!(clock.realtime_ms(), 1_001_500);
        assert!(
            !LinuxTimer::new().advance(10),
            "a wall clock cannot be advanced"
        );
    }
}
