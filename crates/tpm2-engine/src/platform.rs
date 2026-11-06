//! The platform a [`TpmEngine`](crate::TpmEngine) runs on.
//!
//! Everything the engine needs from its environment is behind the [`Platform`] trait: the
//! cryptography backend, the monotonic timer, the platform random number generator, the type
//! of the structure that holds the NV data ([`IndexState`], kept in the TPM state as
//! [`Nv::index`]), the firmware identity, the secure transport layer and the immutable
//! platform [`Info`]. The platform also decides how the NV data reaches external storage
//! ([`Platform::load_nv`], [`Platform::store_nv`]) and how the runtime state is serialized
//! for migration (`Platform::serialize`, `Platform::deserialize`, with the `persistence`
//! feature). The component interfaces themselves ([`crate::storage::NvStorage`], [`TpmTimer`],
//! [`TpmFirmware`], [`SecureChannel`]) live in [`tpm2::platform`].
//!
//! [`TpmPlatform`] is the generic platform that borrows its components; most users (the
//! simulator, the Linux platform and the tests) build a [`TpmEngine`](crate::TpmEngine) over it.

use crate::state::Nv;
#[cfg(feature = "persistence")]
use crate::state::State;
use crate::storage::IndexState;
use crate::timer::TpmTimer;
use core::marker::PhantomData;
use tpm2::crypto::{Crypto, Rng};
use tpm2::platform::{SecureChannel, TpmFirmware};

/// Immutable information about the platform and the TPM vendor, reported by
/// `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)` and in attestation structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    /// `TPM_PT_MANUFACTURER`: the vendor ID (four ASCII characters, big-endian).
    pub manufacturer: u32,
    /// `TPM_PT_VENDOR_STRING_1` .. `TPM_PT_VENDOR_STRING_4`: the vendor-specific description
    /// of the TPM (four ASCII characters each, big-endian; zero-padded).
    pub vendor_strings: [u32; 4],
    /// `TPM_PT_VENDOR_TPM_TYPE`: the vendor-defined TPM model.
    pub vendor_tpm_type: u32,
    /// `TPM_PT_FIRMWARE_VERSION_1` (`gp.firmwareV1`): the most-significant 32 bits of the
    /// vendor-specific firmware version.
    pub firmware_version_1: u32,
    /// `TPM_PT_FIRMWARE_VERSION_2` (`gp.firmwareV2`): the least-significant 32 bits of the
    /// vendor-specific firmware version.
    pub firmware_version_2: u32,
}

impl Info {
    /// The information `tpm-rs` reports by default: manufacturer `"GOOG"`, vendor string
    /// `"TPM-RUST"`, TPM type 1 and firmware version 1.0.
    pub const DEFAULT: Self = Self {
        manufacturer: 0x474F_4F47,                        // "GOOG"
        vendor_strings: [0x5450_4D2D, 0x5255_5354, 0, 0], // "TPM-", "RUST"
        vendor_tpm_type: 1,
        firmware_version_1: 1,
        firmware_version_2: 0,
    };

    /// The firmware version in attestation structures (`TPMS_ATTEST.firmwareVersion`):
    /// `(TPM_PT_FIRMWARE_VERSION_1 << 32) | TPM_PT_FIRMWARE_VERSION_2` (`FillInAttestInfo()`).
    pub const fn attest_firmware_version(&self) -> u64 {
        ((self.firmware_version_1 as u64) << 32) | self.firmware_version_2 as u64
    }
}

impl Default for Info {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Trait all platforms must implement to use `tpm2-engine`.
///
/// A platform provides the components the engine uses (as associated types, so that the
/// engine is monomorphized over them), the immutable platform [`Info`] and the
/// customizations of how the TPM state reaches storage: loading and storing the NV data
/// ([`Platform::load_nv`], [`Platform::store_nv`]) and serializing the runtime state
/// (`Platform::serialize`, `Platform::deserialize`, with the `persistence` feature).
pub trait Platform: Sized {
    /// Cryptography backend ([`Crypto`]). The backend's interfaces are static (its algorithms
    /// are associated types); the platform only selects it.
    type Crypto: Crypto;
    /// Monotonic timer.
    type Timer: TpmTimer;
    /// Platform random number generator ([`Rng::fill_bytes`] draws random bytes,
    /// [`Rng::stir_bytes`] mixes additional entropy into its state and [`Rng::init`]
    /// reinitializes its entropy source at `_TPM_Init`).
    type Rng: Rng + Sync;
    /// Structure used to hold the NV data (the `Handle -> [u8]` mapping of the NV Indices,
    /// persistent objects and internal records, see [`IndexState`]). The TPM state owns it
    /// ([`Nv::index`]); every [`crate::storage::NvStorage`] medium is one.
    type IndexState: IndexState;

    /// Immutable info from the platform (firmware version, vendor ID, ...). Defaults to
    /// [`Info::DEFAULT`].
    fn info(&self) -> &Info {
        &Info::DEFAULT
    }

    /// The monotonic timer.
    fn timer(&self) -> &Self::Timer;

    /// The platform random number generator.
    fn rng(&mut self) -> &mut Self::Rng;

    /// Firmware identity ([`TpmFirmware`]: the Firmware Secret, the Firmware SVN Secrets and
    /// the current and maximum firmware SVN). `None` (the default) is a TPM without
    /// firmware-limited and SVN-limited hierarchies: their handles fail with
    /// `TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED`, they are not listed by `TPM2_GetCapability`,
    /// and `TPM_PT_FIRMWARE_SVN`/`TPM_PT_FIRMWARE_MAX_SVN` are 0. The firmware is shared
    /// (`Sync`) so that a platform can change it (e.g. a simulated firmware update) while the
    /// TPM uses it.
    fn firmware(&self) -> Option<&(dyn TpmFirmware + Sync)> {
        None
    }

    /// Secure channel information of the TPM's secure transport layer ([`SecureChannel`]: the
    /// TPM SPDM authentication public keys and the SPDM session protecting the current
    /// command), used with the `sec-channel` feature. `None` (the default) is a TPM without
    /// SPDM keys that never receives a command within an SPDM session.
    fn secure_channel(&self) -> Option<&(dyn SecureChannel + Sync)> {
        None
    }

    /// Reads the NV data from external storage into `nv`.
    ///
    /// Called at `_TPM_Init` ([`crate::TpmEngine::reset`]), before the engine reloads its
    /// NV-synced state ([`crate::PersistentState`], [`crate::OrderlyState`] and the state saved
    /// by `TPM2_Shutdown(TPM_SU_STATE)`) from [`Nv::index`]. A platform whose
    /// [`Platform::IndexState`] is the NV medium itself (the default) has nothing to do.
    fn load_nv(&mut self, nv: &mut Nv<Self>) {
        let _ = nv;
    }

    /// Syncs the NV data in `nv` back to external storage.
    ///
    /// Called after every command, `_TPM_Init` and manufacture
    /// ([`crate::TpmEngine::init_storage`]), once the engine has written its NV-synced state
    /// to [`Nv::index`]. A platform whose [`Platform::IndexState`] is the NV medium itself
    /// (the default) has nothing to do.
    fn store_nv(&mut self, nv: &Nv<Self>) {
        let _ = nv;
    }

    /// Serializes the runtime state `state` (with its NV data) into `out`, for migrating the
    /// TPM, and returns the number of octets written. The default is the compact binary
    /// encoding of [`crate::persistence::try_serialize_to_slice`], relative to the current
    /// reading of the platform timer.
    #[cfg(feature = "persistence")]
    fn serialize(
        &self,
        state: &State<Self>,
        out: &mut [u8],
    ) -> Result<usize, crate::persistence::SerializeError> {
        crate::persistence::try_serialize_to_slice(state, self.timer().timer_read(), out)
    }

    /// Restores the runtime state `state` (with its NV data) from `data`, written by
    /// [`Platform::serialize`] (possibly on another platform). The default
    /// ([`crate::persistence::try_deserialize_from_slice`]) rebases the platform time on the
    /// current reading of the platform timer and recomputes the Names of the loaded objects
    /// with the crypto backend; a rejected state leaves `state` unchanged.
    #[cfg(feature = "persistence")]
    fn deserialize(
        &self,
        data: &[u8],
        state: &mut State<Self>,
    ) -> Result<(), crate::persistence::DeserializeError> {
        crate::persistence::try_deserialize_from_slice::<Self::Crypto, Self>(
            data,
            state,
            self.timer().timer_read(),
        )
    }
}

/// The generic [`Platform`] that borrows its components.
///
/// `I` is the [`Platform::IndexState`] of the TPM, which the engine owns
/// ([`crate::TpmEngine::new`]); typically an NV medium or a mutable reference to one.
pub struct TpmPlatform<'a, C, I, T, R>
where
    C: Crypto,
    I: IndexState,
    T: TpmTimer,
    R: Rng,
{
    /// Cryptography backend ([`Crypto`]). The backend's interfaces are static (its
    /// algorithms are associated types); the reference only selects and borrows it.
    pub crypto: &'a mut C,
    /// Monotonic timer.
    pub timer: &'a mut T,
    /// Platform random number generator ([`Platform::Rng`]).
    pub rng: &'a mut R,
    /// Firmware identity ([`Platform::firmware`]); `None` by default ([`TpmPlatform::new`]).
    pub firmware: Option<&'a (dyn TpmFirmware + Sync)>,
    /// Secure channel information of the TPM's secure transport layer
    /// ([`Platform::secure_channel`]); `None` by default ([`TpmPlatform::new`]).
    pub secure_channel: Option<&'a (dyn SecureChannel + Sync)>,
    /// Immutable platform information ([`Platform::info`]); [`Info::DEFAULT`] by default
    /// ([`TpmPlatform::new`]).
    pub info: Info,
    /// The type of the TPM's NV data structure ([`Platform::IndexState`]).
    index: PhantomData<fn() -> I>,
}

impl<'a, C, I, T, R> TpmPlatform<'a, C, I, T, R>
where
    C: Crypto,
    I: IndexState,
    T: TpmTimer,
    R: Rng,
{
    /// Constructs a new `TpmPlatform` from mutable references to hardware providers.
    pub fn new(crypto: &'a mut C, timer: &'a mut T, rng: &'a mut R) -> Self {
        Self {
            crypto,
            timer,
            rng,
            firmware: None,
            secure_channel: None,
            info: Info::DEFAULT,
            index: PhantomData,
        }
    }

    /// Gives the TPM the firmware identity `firmware`, enabling the firmware-limited and
    /// SVN-limited hierarchies (see [`Platform::firmware`]).
    pub fn with_firmware(mut self, firmware: &'a (dyn TpmFirmware + Sync)) -> Self {
        self.firmware = Some(firmware);
        self
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

impl<C, I, T, R> Platform for TpmPlatform<'_, C, I, T, R>
where
    C: Crypto,
    I: IndexState,
    T: TpmTimer,
    R: Rng + Sync,
{
    type Crypto = C;
    type Timer = T;
    type Rng = R;
    type IndexState = I;

    fn info(&self) -> &Info {
        &self.info
    }

    fn timer(&self) -> &T {
        self.timer
    }

    fn rng(&mut self) -> &mut R {
        self.rng
    }

    fn firmware(&self) -> Option<&(dyn TpmFirmware + Sync)> {
        self.firmware
    }

    fn secure_channel(&self) -> Option<&(dyn SecureChannel + Sync)> {
        self.secure_channel
    }
}
