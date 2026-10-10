//! Linux Platform Implementation for TPM2
//!
//! Provides Linux-specific implementations of hardware abstraction layer components
//! like `TpmTimer` using `std::time::Instant` and `Rng` using `/dev/urandom`.
//!
//! The cryptography backend is selected by exactly one of the `rustcrypto` (default),
//! `libcrux` or `boringssl` features and exported as [`PlatformCryptoProvider`].

#![forbid(unsafe_code)]

#[cfg(not(any(feature = "rustcrypto", feature = "libcrux", feature = "boringssl")))]
compile_error!(
    "At least one cryptographic backend feature must be enabled: 'rustcrypto', 'libcrux', or 'boringssl'."
);

#[cfg(all(feature = "rustcrypto", feature = "libcrux"))]
compile_error!("Features 'rustcrypto' and 'libcrux' are mutually exclusive.");

#[cfg(all(feature = "rustcrypto", feature = "boringssl"))]
compile_error!("Features 'rustcrypto' and 'boringssl' are mutually exclusive.");

#[cfg(all(feature = "libcrux", feature = "boringssl"))]
compile_error!("Features 'libcrux' and 'boringssl' are mutually exclusive.");

use std::fs::File;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::Instant;
use tpm2::crypto::{CryptoError, Rng};
use tpm2_impl::storage::NvStorage;
use tpm2_impl::timer::TpmTimer;
use tpm2_impl::{Crypto, TpmPlatform};

/// The cryptography backend selected by the crate features.
#[cfg(feature = "boringssl")]
pub use tpm2_boringssl::BoringSsl as PlatformCryptoProvider;

/// The cryptography backend selected by the crate features.
#[cfg(feature = "libcrux")]
pub use tpm2_libcrux::Libcrux as PlatformCryptoProvider;

/// The cryptography backend selected by the crate features.
#[cfg(feature = "rustcrypto")]
pub use tpm2_rustcrypto::RustCrypto as PlatformCryptoProvider;

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
        // PORTING: exp truncated with `as u64`; saturate instead (after ~584 million years).
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// `/dev/urandom`, opened by [`LinuxRng::init_urandom`] or on first fallback use.
///
/// PORTING: exp panicked if `/dev/urandom` could not be opened; `None` records that failure, and
/// [`LinuxRng::get_random`] then tries to open it directly.
static URANDOM_FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();

/// Opens `/dev/urandom`.
fn open_urandom() -> Option<Mutex<File>> {
    File::open("/dev/urandom").ok().map(Mutex::new)
}

/// Linux-specific random number generator reading from OS entropy source.
pub struct LinuxRng;

impl LinuxRng {
    /// Creates a new `LinuxRng`.
    pub const fn new() -> Self {
        Self
    }

    /// Pre-opens `/dev/urandom` for fallback use in sandboxed environments where opening new files at runtime is forbidden.
    pub fn init_urandom() {
        let _ = URANDOM_FILE.get_or_init(open_urandom);
    }

    /// Fills `dest` with random bytes from the operating system's entropy source.
    ///
    /// PORTING: exp implemented this as `tpm2::crypto::Rng::get_random`. The new
    /// [`Rng`] trait takes `&mut self` ([`Rng::fill_bytes`]); this method keeps exp's `&self`
    /// signature.
    pub fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        // 1. Try the getrandom syscall in a loop to handle EINTR.
        // PORTING: exp called `PlatformCryptoProvider.get_random` (the backend's `getrandom`
        // wrapper); the new crypto backends expose no raw OS RNG, so call `getrandom` directly.
        for _ in 0..10_000 {
            if getrandom::fill(dest).is_ok() {
                return Ok(());
            }
        }

        // 2. If getrandom persistently fails, try reading from pre-opened URANDOM_FILE.
        use std::io::Read as _;
        if let Some(file_mutex) = URANDOM_FILE.get_or_init(open_urandom) {
            let mut file = match file_mutex.lock() {
                Ok(f) => f,
                Err(poisoned) => poisoned.into_inner(),
            };
            let mut offset = 0;
            let mut attempts = 0;
            while offset < dest.len() && attempts < 100_000 {
                let Some(remaining) = dest.get_mut(offset..) else {
                    break;
                };
                match file.read(remaining) {
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
        }

        // 3. Direct open fallback if static lock or fd failed.
        if let Ok(mut file) = File::open("/dev/urandom") {
            let mut offset = 0;
            let mut attempts = 0;
            while offset < dest.len() && attempts < 100_000 {
                let Some(remaining) = dest.get_mut(offset..) else {
                    break;
                };
                match file.read(remaining) {
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

        // PORTING: exp returned `CryptoError::HardwareFailure`, which the new `CryptoError`
        // calls `Internal`.
        Err(CryptoError::Internal)
    }
}

impl Rng for LinuxRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        self.get_random(dest)
    }

    /// The kernel entropy pool is not reseeded from user space: `data` is ignored.
    fn reseed(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// Helper function to instantiate a `TpmPlatform` with Linux hardware components.
///
/// PORTING: exp's `TpmPlatform` took the platform RNG (a [`LinuxRng`]) as a separate argument.
/// The TPM's global RNG is now the backend's [`Random::Rng`](tpm2::crypto::Random::Rng): it is
/// created with [`Random::rng`](tpm2::crypto::Random::rng) (seeded by the backend from OS
/// entropy) or, if the backend cannot reach OS entropy, seeded from [`LinuxRng`] with
/// [`Random::rng_seeded`](tpm2::crypto::Random::rng_seeded).
pub fn create_linux_platform<'a, C, S>(
    crypto: &'a C,
    storage: &'a mut S,
    timer: &'a mut LinuxTimer,
) -> Result<TpmPlatform<'a, C, S, LinuxTimer>, CryptoError>
where
    C: Crypto,
    S: NvStorage,
{
    let rng = match crypto.rng() {
        Ok(rng) => rng,
        Err(_) => {
            let mut seed = [0u8; 64];
            LinuxRng::new().get_random(&mut seed)?;
            crypto.rng_seeded(&seed)?
        }
    };
    Ok(TpmPlatform::new(crypto, storage, timer, rng))
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
