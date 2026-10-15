//! The TPM's random-number entry points.
//!
//! Every random value the engine and the command handlers produce is drawn through
//! [`TpmEngine::random_platform`] / [`TpmEngine::random_crypto`] (and, for the algorithms that
//! consume random numbers, through [`TpmEngine::ref_rng`]):
//!
//! - By default, `random_platform` draws from the platform RNG ([`TpmPlatform::rng`]) and
//!   `random_crypto` from the crypto provider's CSPRNG ([`CryptoProvider::get_random`]).
//! - With the `reference-rng` feature, both draw from the TPM's own CTR-DRBG (`drbgDefault`,
//!   [`GlobalState::drbg_state`]), the C reference TPMs' DRBG linked from their original code,
//!   seeded from the platform RNG as entropy source ([`crate::reference_rng`]); the call sites
//!   are arranged so that the values are drawn in the order and with the sizes of the reference
//!   code.
//!
//! [`TpmPlatform::rng`]: tpm2::platform::TpmPlatform
//! [`GlobalState::drbg_state`]: crate::GlobalState

use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::TpmRc;

use crate::engine::TpmEngine;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;

#[cfg(feature = "reference-rng")]
use crate::reference_rng::{RefRng, drbg};

impl<'a, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync> TpmEngine<'a, C, S, T, R> {
    /// Random bytes for values that the default build draws from the platform RNG (seeds,
    /// proofs, nonces, `TPM2_GetRandom`, IVs).
    pub(crate) fn random_platform(&mut self, out: &mut [u8]) -> Result<(), TpmRc> {
        #[cfg(feature = "reference-rng")]
        {
            self.crypt_random_generate(out)
        }
        #[cfg(not(feature = "reference-rng"))]
        {
            self.platform
                .rng
                .fill_bytes(out)
                .map_err(|_| TpmRc::FAILURE)
        }
    }

    /// Random bytes for values that the default build draws from the crypto provider's CSPRNG
    /// (response nonces, TPM-generated keys and seeds, secrets).
    pub(crate) fn random_crypto(&mut self, out: &mut [u8]) -> Result<(), TpmRc> {
        #[cfg(feature = "reference-rng")]
        {
            self.crypt_random_generate(out)
        }
        #[cfg(not(feature = "reference-rng"))]
        {
            self.platform
                .crypto
                .get_random(out)
                .map_err(|_| TpmRc::FAILURE)
        }
    }

    /// `CryptRandomGenerate()`: fills `out` from the TPM's DRBG.
    #[cfg(feature = "reference-rng")]
    pub(crate) fn crypt_random_generate(&mut self, out: &mut [u8]) -> Result<(), TpmRc> {
        drbg::fill(&mut self.ref_rng(), None, out)
    }

    /// The TPM's DRBG (`drbgDefault`, the `RAND_STATE` the reference code uses when its `rand`
    /// argument is `NULL`), with the platform RNG as entropy source for instantiation and
    /// automatic reseeding.
    #[cfg(feature = "reference-rng")]
    pub(crate) fn ref_rng(&mut self) -> RefRng<'_> {
        RefRng {
            drbg: Some(&mut self.state.drbg_state),
            entropy: Some(&mut *self.platform.rng),
        }
    }

    /// `CryptRandInit()` (part of `CryptInit()`, run at manufacture and on every `_TPM_Init`):
    /// (re)initializes the platform entropy source (`_plat__GetEntropy(NULL, 0)`).
    #[cfg(feature = "reference-rng")]
    pub(crate) fn crypt_rand_init(&mut self) {
        // The reference ignores the result; a failing source fails later draws instead.
        let _ = self.platform.rng.init();
    }

    /// `CryptRandStartup()` with `_DRBG_STATE_SAVE`: reseeds the DRBG restored from NV with
    /// fresh platform entropy, or instantiates it if NV held no instantiated DRBG.
    #[cfg(feature = "reference-rng")]
    pub(crate) fn crypt_rand_startup(&mut self) -> Result<(), TpmRc> {
        drbg::startup(&mut self.ref_rng())
    }

    /// Writes the DRBG state to NV (`go.drbgState` is written with `ORDERLY_DATA` at
    /// manufacture, `TPM2_Shutdown`, `TPM2_Clear` and Clock updates).
    #[cfg(feature = "reference-rng")]
    pub(crate) fn save_drbg_state(&mut self) {
        let _ = self
            .platform
            .storage
            .write_nv(DRBG_STATE_NV_OFFSET, &self.state.drbg_state.to_bytes());
    }

    /// Reloads the DRBG state from NV (`NvRead(&go, NV_ORDERLY_DATA, ...)` at `_TPM_Init`):
    /// values drawn since the last write are drawn again after a power cycle, as in the
    /// reference code.
    #[cfg(feature = "reference-rng")]
    pub(crate) fn load_drbg_state(&mut self) {
        let mut buf = [0u8; 76];
        if self
            .platform
            .storage
            .read_nv(DRBG_STATE_NV_OFFSET, &mut buf)
            .is_ok()
        {
            self.state.drbg_state = crate::engine::DrbgState::from_bytes(&buf);
        }
    }

    /// The random part of `TPM_Manufacture()` before the hierarchy secrets are drawn:
    /// `CryptInit()` and `CryptStartup(SU_RESET)` (DRBG instantiation and a commit nonce).
    #[cfg(feature = "reference-rng")]
    pub(crate) fn manufacture_rng(&mut self) -> Result<(), TpmRc> {
        self.crypt_rand_init();
        self.state.drbg_state.magic = 0;
        self.crypt_rand_startup()?;
        let mut nonce = [0u8; 64];
        self.crypt_random_generate(&mut nonce)?;
        self.state.commit_nonce = nonce;
        Ok(())
    }
}

/// NV offset of the persisted DRBG state (`go.drbgState`, 76 bytes).
#[cfg(feature = "reference-rng")]
pub(crate) const DRBG_STATE_NV_OFFSET: usize = 36;
