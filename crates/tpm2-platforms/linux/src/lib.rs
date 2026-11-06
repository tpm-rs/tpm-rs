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
use std::marker::PhantomData;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::Instant;
use tpm2::crypto::{Crypto, CryptoError, Random, Rng};
use tpm2::platform::{SecureChannel, TpmFirmware};
use tpm2_engine::storage::IndexState;
use tpm2_engine::timer::TpmTimer;
use tpm2_engine::{Info, Nv, Platform};

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
/// Implements the platform [`Rng`] of [`LinuxPlatform`]: [`Rng::fill_bytes`]
/// draws from the [`PlatformCryptoProvider`]'s entropy source
/// ([`Random::rand_bytes`], the `getrandom` syscall), falling back to
/// `/dev/urandom`. [`Rng::stir_bytes`] is a no-op,
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
            if PlatformCryptoProvider::rand_bytes(dest).is_ok() {
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
    fn stir_bytes(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
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

/// The Linux [`Platform`]: the TPM's crypto backend `C`, the Linux timer and platform RNG
/// ([`LinuxTimer`], [`LinuxRng`]), the firmware identity, an optional secure transport layer
/// and the platform [`Info`]. It borrows its components.
///
/// `I` is the TPM's NV data structure ([`Platform::IndexState`], e.g. a mutable reference to
/// an NV medium), which is given to [`tpm2_engine::TpmEngine::new`] together with the
/// platform. The NV data is the medium itself, so the NV hooks ([`Platform::load_nv`],
/// [`Platform::store_nv`]) have nothing to do.
pub struct LinuxPlatform<'a, C: Crypto, I: IndexState> {
    /// The crypto backend ([`Platform::Crypto`]); the reference only selects and borrows it.
    pub crypto: &'a mut C,
    /// The monotonic timer.
    pub timer: &'a mut LinuxTimer,
    /// The platform random number generator.
    pub rng: &'a mut LinuxRng,
    /// The firmware identity (the Firmware Secret, Firmware SVN Secrets and SVNs of the
    /// firmware-limited and SVN-limited hierarchies).
    pub firmware: &'a (dyn TpmFirmware + Sync),
    /// The secure transport layer ([`Platform::secure_channel`]); `None` by default.
    pub secure_channel: Option<&'a (dyn SecureChannel + Sync)>,
    /// The platform information ([`Platform::info`]); [`Info::DEFAULT`] by default.
    pub info: Info,
    /// The type of the TPM's NV data structure.
    index: PhantomData<fn() -> I>,
}

impl<'a, C: Crypto, I: IndexState> LinuxPlatform<'a, C, I> {
    /// A Linux platform with the crypto backend `crypto`, the timer `timer`, the platform RNG
    /// `platform_rng` and the firmware identity `firmware` (a simulator uses
    /// [`tpm2::platform::SimulatedFirmware`]), without a secure transport layer and with
    /// [`Info::DEFAULT`].
    pub fn new(
        crypto: &'a mut C,
        timer: &'a mut LinuxTimer,
        platform_rng: &'a mut LinuxRng,
        firmware: &'a (dyn TpmFirmware + Sync),
    ) -> Self {
        Self {
            crypto,
            timer,
            rng: platform_rng,
            firmware,
            secure_channel: None,
            info: Info::DEFAULT,
            index: PhantomData,
        }
    }

    /// Gives the TPM the secure transport layer `secure_channel` (see
    /// [`Platform::secure_channel`]).
    pub fn with_secure_channel(mut self, secure_channel: &'a (dyn SecureChannel + Sync)) -> Self {
        self.secure_channel = Some(secure_channel);
        self
    }

    /// Gives the TPM the platform information `info` (see [`Platform::info`]).
    pub fn with_info(mut self, info: Info) -> Self {
        self.info = info;
        self
    }
}

impl<C: Crypto, I: IndexState> Platform for LinuxPlatform<'_, C, I> {
    type Crypto = C;
    type Timer = LinuxTimer;
    type Rng = LinuxRng;
    type IndexState = I;

    fn info(&self) -> &Info {
        &self.info
    }

    fn timer(&self) -> &LinuxTimer {
        self.timer
    }

    fn rng(&mut self) -> &mut LinuxRng {
        self.rng
    }

    fn firmware(&self) -> Option<&(dyn TpmFirmware + Sync)> {
        Some(self.firmware)
    }

    fn secure_channel(&self) -> Option<&(dyn SecureChannel + Sync)> {
        self.secure_channel
    }

    fn load_nv(&mut self, _nv: &mut Nv<Self>) {}

    fn store_nv(&mut self, _nv: &Nv<Self>) {}
}

/// Instantiates a [`LinuxPlatform`] ([`LinuxPlatform::new`]).
pub fn create_linux_platform<'a, C, I>(
    crypto: &'a mut C,
    timer: &'a mut LinuxTimer,
    platform_rng: &'a mut LinuxRng,
    firmware: &'a (dyn TpmFirmware + Sync),
) -> LinuxPlatform<'a, C, I>
where
    C: Crypto,
    I: IndexState,
{
    LinuxPlatform::new(crypto, timer, platform_rng, firmware)
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
