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

/// Linux-specific monotonic timer based on `std::time::Instant`.
pub struct LinuxTimer {
    start: LazyLock<Instant>,
}

impl LinuxTimer {
    /// Creates a new `LinuxTimer` anchored to the current instant.
    pub const fn new() -> Self {
        Self {
            start: LazyLock::new(Instant::now),
        }
    }
}

impl TpmTimer for LinuxTimer {
    fn timer_read(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

static URANDOM_FILE: OnceLock<Mutex<File>> = OnceLock::new();

/// Linux-specific random number generator reading from OS entropy source.
pub struct LinuxRng;

impl LinuxRng {
    /// Creates a new `LinuxRng`.
    pub const fn new() -> Self {
        Self
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
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
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

        Err(CryptoError::HardwareFailure)
    }
}

/// Helper function to instantiate a `TpmPlatform` with Linux hardware components.
pub fn create_linux_platform<'a, C, S>(
    crypto: &'a mut C,
    storage: &'a mut S,
    timer: &'a mut LinuxTimer,
    platform_rng: &'a LinuxRng,
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
