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

/// Seeded stream that can stand in for the crypto provider's randomness within
/// a scope (see `tpm2_crypto_bssl::replay`).
#[cfg(all(feature = "reproducible", feature = "bssl"))]
pub use tpm2_crypto_bssl::replay::ReplayRng as CryptoReplayRng;

/// Pins (or unpins) the crypto provider's randomness on the current thread
/// outside replay scopes (see `tpm2_crypto_bssl::replay::set_thread_default_seed`).
#[cfg(all(feature = "reproducible", feature = "bssl"))]
pub use tpm2_crypto_bssl::replay::set_thread_default_seed as set_crypto_thread_default_seed;

/// Linux-specific monotonic timer based on `std::time::Instant`.
///
/// With the `reproducible` feature, [`LinuxTimer::new_virtual`] additionally
/// provides a virtual clock that only moves when [`LinuxTimer::advance`] is
/// called, so time-dependent TPM output (`ReadClock`, `TPMS_CLOCK_INFO`, …)
/// is identical on every run.
pub struct LinuxTimer {
    start: LazyLock<Instant>,
    /// Current virtual time in milliseconds, or `None` for the wall clock.
    #[cfg(feature = "reproducible")]
    virtual_ms: Option<std::sync::atomic::AtomicU64>,
}

impl LinuxTimer {
    /// Creates a new `LinuxTimer` anchored to the current instant.
    pub const fn new() -> Self {
        Self {
            start: LazyLock::new(Instant::now),
            #[cfg(feature = "reproducible")]
            virtual_ms: None,
        }
    }

    /// Creates a virtual timer that starts at 0 ms and only advances through
    /// [`LinuxTimer::advance`].
    #[cfg(feature = "reproducible")]
    pub const fn new_virtual() -> Self {
        Self {
            start: LazyLock::new(Instant::now),
            virtual_ms: Some(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Advances a virtual timer by `ms` milliseconds.
    ///
    /// Returns `false` (and does nothing) for a wall-clock timer, whose time
    /// cannot be moved.
    #[cfg(feature = "reproducible")]
    pub fn advance(&self, ms: u64) -> bool {
        match &self.virtual_ms {
            Some(now) => {
                now.fetch_add(ms, std::sync::atomic::Ordering::Relaxed);
                true
            }
            None => false,
        }
    }
}

impl TpmTimer for LinuxTimer {
    fn timer_read(&self) -> u64 {
        #[cfg(feature = "reproducible")]
        if let Some(now) = &self.virtual_ms {
            return now.load(std::sync::atomic::Ordering::Relaxed);
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
/// With the `reproducible` feature, [`LinuxRng::seeded`] additionally provides
/// a deterministic ChaCha20 stream, so every TPM value derived from platform
/// entropy (DRBG state, `nonceTPM`, null seed/proof, `GetRandom` output, …)
/// is identical on every run.
pub struct LinuxRng {
    /// Deterministic generator, or `None` for OS entropy.
    #[cfg(feature = "reproducible")]
    seeded: Option<Mutex<rand_chacha::ChaCha20Rng>>,
}

impl LinuxRng {
    /// Creates a new `LinuxRng`.
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "reproducible")]
            seeded: None,
        }
    }

    /// Creates a deterministic `LinuxRng` whose output stream is fully
    /// determined by `seed`. **Not for production use.**
    #[cfg(feature = "reproducible")]
    pub fn seeded(seed: u64) -> Self {
        use rand_chacha::rand_core::SeedableRng as _;
        Self {
            seeded: Some(Mutex::new(rand_chacha::ChaCha20Rng::seed_from_u64(seed))),
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
    /// seeded stream of a [`LinuxRng::seeded`] generator).
    ///
    /// # Errors
    /// * [`CryptoError::Internal`] - Neither the `getrandom` syscall nor
    ///   `/dev/urandom` produced `dest.len()` bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        #[cfg(feature = "reproducible")]
        if let Some(rng) = &self.seeded {
            use rand_chacha::rand_core::RngCore as _;
            let mut rng = match rng.lock() {
                Ok(r) => r,
                Err(poisoned) => poisoned.into_inner(),
            };
            rng.fill_bytes(dest);
            return Ok(());
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

    #[cfg(feature = "reproducible")]
    #[test]
    fn seeded_rng_is_deterministic() {
        let draw = |seed| {
            let mut rng = LinuxRng::seeded(seed);
            let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
            rng.fill_bytes(&mut a).unwrap();
            rng.fill_bytes(&mut b).unwrap();
            assert_ne!(a, b, "the stream advances");
            (a, b)
        };
        assert_eq!(draw(1), draw(1));
        assert_ne!(draw(1), draw(2));
    }

    #[cfg(feature = "reproducible")]
    #[test]
    fn virtual_timer_only_moves_when_advanced() {
        let timer = LinuxTimer::new_virtual();
        assert_eq!(timer.timer_read(), 0);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(timer.timer_read(), 0);
        assert!(timer.advance(1500));
        assert_eq!(timer.timer_read(), 1500);
        assert!(
            !LinuxTimer::new().advance(10),
            "a wall clock cannot be advanced"
        );
    }
}
