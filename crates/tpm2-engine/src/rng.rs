//! The TPM's random number generator.
//!
//! Every random value the engine and the command handlers produce (seeds, proofs, nonces,
//! `TPM2_GetRandom`, IVs, keys, secrets, and the randomness of the randomized key operations)
//! is drawn from one generator, the TPM's DRBG [`TpmEngine::crypto_rng`] (a `C::Rng` created by
//! [`Platform::crypto_rng`](crate::Platform::crypto_rng)), in the order and with the sizes of
//! the C reference TPMs: raw bytes through [`TpmEngine::crypt_random_generate`]
//! (`CryptRandomGenerate()`), and the algorithms that consume random numbers (the RSA encodings
//! of the `tpm2::crypto` dispatch functions, the key generations and ECC signatures of
//! [`crate::asymmetric`]) with the reference's draws on [`Rng::fill_bytes`]; for the backend's
//! system RNG ([`Rng::is_system_rng`]) the backend's own key generation and ECDSA are kept.
//!
//! The generator's lifecycle follows the reference's `CryptRand.c`: [`Rng::init`] and
//! [`Rng::self_test`] at manufacture and `_TPM_Init` (`CryptInit()`), [`Rng::startup`] at
//! manufacture and `TPM2_Startup` (`CryptRandStartup()`), and its state
//! ([`Rng::STATE_SIZE`] octets, at most [`DRBG_STATE_SIZE`]) is kept in NV like the reference's
//! `go.drbgState` ([`OrderlyState::drbg_state`](crate::OrderlyState), written at manufacture,
//! `TPM2_Shutdown`, `TPM2_Clear` and NV updates of *Clock*, and restored at
//! `_TPM_Init`), so that the values drawn since the last write are drawn again after a power
//! cycle. A generator without state ([`Rng::STATE_SIZE`] 0, e.g. the backend's system RNG)
//! leaves the slot unused.

use crate::Platform;
use crate::engine::{DRBG_STATE_SIZE, DrbgState, TpmEngine};
use crate::storage::IndexState;
use tpm2::crypto::{Random, Rng};
use tpm2::errors::TpmRc;

/// The state size of the TPM's DRBG of the platform `P`.
const fn state_size<P: Platform>() -> usize {
    <<P::Crypto as Random>::Rng as Rng>::STATE_SIZE
}

impl<P: Platform> TpmEngine<P> {
    /// `CryptRandomGenerate()`: fills `out` from the TPM's DRBG.
    pub(crate) fn crypt_random_generate(&mut self, out: &mut [u8]) -> Result<(), TpmRc> {
        self.crypto_rng.fill_bytes(out).map_err(|_| TpmRc::FAILURE)
    }

    /// `CryptRandInit()` (part of `CryptInit()`, run at manufacture and on every `_TPM_Init`):
    /// (re)initializes the DRBG's entropy source (`_plat__GetEntropy(NULL, 0)`).
    pub(crate) fn crypt_rand_init(&mut self) {
        // The reference ignores the result; a failing source fails later draws instead.
        let _ = self.crypto_rng.init();
    }

    /// The DRBG self test of `CryptRandInit()`/`CryptoRand_LibInit()` (`CryptInit()`, after
    /// `CryptInitializeToTest()`): `DRBG_SelfTest()` ([`Rng::self_test`]; the generator keeps
    /// its self-test flags itself). A failed test puts the TPM into Failure mode (`g_inFailureMode
    /// = (CryptInit() == FALSE)`, without a failure location).
    pub(crate) fn crypt_rand_self_test(&mut self) {
        if !self.crypto_rng.self_test().unwrap_or(false) {
            self.self_test.set_failed(true);
        }
    }

    /// `CryptRandStartup()` with `_DRBG_STATE_SAVE`: reseeds the DRBG restored from NV with
    /// fresh entropy, or instantiates it if NV held no instantiated DRBG ([`Rng::startup`]).
    pub(crate) fn crypt_rand_startup(&mut self) -> Result<(), TpmRc> {
        self.crypto_rng.startup().map_err(|_| TpmRc::FAILURE)
    }

    /// Writes the DRBG state to NV (`go.drbgState` is written with `ORDERLY_DATA` at
    /// manufacture, `TPM2_Shutdown`, `TPM2_Clear` and Clock updates). Does nothing for a
    /// generator without state; fails with `TPM_RC_FAILURE` if the state cannot be written.
    pub(crate) fn save_drbg_state(&mut self) -> Result<(), TpmRc> {
        const { assert!(state_size::<P>() <= DRBG_STATE_SIZE) };
        if state_size::<P>() == 0 {
            return Ok(());
        }
        let mut buf = [0u8; DRBG_STATE_SIZE];
        self.crypto_rng
            .save_state(&mut buf[..state_size::<P>()])
            .map_err(|_| TpmRc::FAILURE)?;
        self.state.nv.orderly.drbg_state = DrbgState::from_bytes(&buf);
        self.state
            .nv
            .index
            .write_reserved(DRBG_STATE_NV_OFFSET, &buf)
            .map_err(|_| TpmRc::FAILURE)
    }

    /// Reloads the DRBG state from NV (`NvRead(&go, NV_ORDERLY_DATA, ...)` at `_TPM_Init`):
    /// values drawn since the last write are drawn again after a power cycle, as in the
    /// reference code. Does nothing for a generator without state.
    pub(crate) fn load_drbg_state(&mut self) {
        if state_size::<P>() == 0 {
            return;
        }
        let mut buf = [0u8; DRBG_STATE_SIZE];
        if self
            .state
            .nv
            .index
            .read_reserved(DRBG_STATE_NV_OFFSET, &mut buf)
            .is_ok()
        {
            self.state.nv.orderly.drbg_state = DrbgState::from_bytes(&buf);
            let _ = self.crypto_rng.load_state(&buf[..state_size::<P>()]);
        }
    }

    /// The random part of `TPM_Manufacture()` before the hierarchy secrets are drawn:
    /// `CryptInit()` and `CryptStartup(SU_RESET)` (DRBG instantiation and a commit nonce).
    pub(crate) fn manufacture_rng(&mut self) -> Result<(), TpmRc> {
        self.crypt_rand_init();
        self.crypt_rand_self_test();
        // A new TPM has no DRBG state: the startup instantiates it.
        if state_size::<P>() != 0 {
            self.state.nv.orderly.drbg_state = DrbgState::default();
            let _ = self
                .crypto_rng
                .load_state(&[0u8; DRBG_STATE_SIZE][..state_size::<P>()]);
        }
        self.crypt_rand_startup()?;
        let mut nonce = [0u8; crate::engine::COMMIT_NONCE_SIZE];
        self.crypt_random_generate(&mut nonce)?;
        self.state.nv.reset.commit_nonce = nonce;
        Ok(())
    }
}

/// NV offset of the persisted DRBG state (`go.drbgState`, [`DRBG_STATE_SIZE`] octets).
pub(crate) const DRBG_STATE_NV_OFFSET: usize = crate::storage::nv::NvHeader::DRBG_OFFSET;
