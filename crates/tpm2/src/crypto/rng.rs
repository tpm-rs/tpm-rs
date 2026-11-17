//! Random number generation.
//!
//! A backend's random number generator ([`Random::Rng`], a type implementing
//! [`Rng`]) draws the random values of a TPM. An RNG only provides random bytes
//! ([`Rng::fill_bytes`], with [`Rng::stir_bytes`] to mix in data), plus
//! optional tpm-rs extensions for the lifecycle and the persistent state of a
//! DRBG and [`Rng::is_system_rng`]; it implements no algorithm. The random
//! algorithms that consume its bytes are implemented on [`Rng::fill_bytes`]
//! alone: the RSA encodings of this module ([`rsa_oaep_encode`],
//! [`rsa_pkcs1v15_encode`] and [`rsa_pss_encode`], with the C reference TPMs'
//! draws, which the dispatch functions always use) and, in `tpm2-engine`, the
//! TPM's key generations and ECC signatures.
//!
//! An RNG that draws the same bytes as another TPM implementation's DRBG (for
//! example the reference RNG of `tpm2-platform-linux`, which links the C
//! reference TPMs' DRBG) therefore makes a TPM draw the same keys, nonces,
//! signatures and ciphertexts as that implementation.
//!
//! [`rsa_oaep_encode`]: super::rsa_oaep_encode
//! [`rsa_pkcs1v15_encode`]: super::rsa_pkcs1v15_encode
//! [`rsa_pss_encode`]: super::rsa_pss_encode

use super::CryptoError;

/// Random number generation for a cryptography backend.
///
/// Backends implement this trait alongside the [`backend`](super::backend)
/// family traits, and implement [`Rng`] on their [`Self::Rng`] type.
pub trait Random {
    /// The backend's stateful random number generator.
    type Rng: Rng;

    /// Instantiates a new RNG from the backend's entropy source.
    ///
    /// Used to initialize the global TPM RNG.
    fn from_entropy() -> Result<Self::Rng, CryptoError>;

    /// Instantiates a deterministic RNG from `seed`.
    ///
    /// Used for deterministic primary-key generation (`TPM2_CreatePrimary`).
    /// The same `seed`, followed by the same sequence of [`Rng`] calls, must
    /// always produce the same output (across runs, versions, and platforms).
    fn from_seed(seed: &[u8]) -> Result<Self::Rng, CryptoError>;

    /// Fills `out` with random bytes in one shot.
    ///
    /// Used for stateless random byte generation (e.g. session nonces).
    ///
    /// Defaults to filling `out` from a new [`from_entropy`](Self::from_entropy)
    /// RNG. Backends with a stateless system RNG (e.g. `RAND_bytes`) can
    /// override this.
    #[inline(never)]
    fn rand_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
        // Use the RNG inside the `Result`: moving it out would copy it.
        match &mut Self::from_entropy() {
            Ok(rng) => rng.fill_bytes(out),
            Err(e) => Err(*e),
        }
    }

    /// Instantiates the deterministic RNG of a Primary Object from the
    /// hierarchy's Primary Seed `seed`, the DRBG purpose `purpose` (e.g.
    /// `"Primary Object Creation\0"`), the Name of the object's template
    /// `name` and the caller's sensitive data `additional` (TPM 2.0 Part 1,
    /// "Primary Object Generation"; the reference implementation's
    /// `DRBG_InstantiateSeeded()`).
    ///
    /// This is a tpm-rs extension. The same inputs must always give an RNG
    /// with the same output (see [`from_seed`](Self::from_seed)), and
    /// different inputs should give unrelated RNGs. Defaults to
    /// [`from_seed`](Self::from_seed)`(seed)` followed by
    /// [`Rng::stir_bytes`] of the big-endian 16-bit length and the bytes of
    /// `purpose`, `name` and `additional`, in this order (so that the inputs
    /// are separated); the reference RNG of `tpm2-platform-linux` uses the
    /// reference's own derivation.
    fn instantiate_seeded(
        seed: &[u8],
        purpose: &[u8],
        name: &[u8],
        additional: &[u8],
    ) -> Result<Self::Rng, CryptoError> {
        let mut rng = Self::from_seed(seed)?;
        for input in [purpose, name, additional] {
            let len = u16::try_from(input.len()).map_err(|_| CryptoError::Unsupported)?;
            rng.stir_bytes(&len.to_be_bytes())?;
            rng.stir_bytes(input)?;
        }
        Ok(rng)
    }
}

/// A stateful random number generator.
///
/// Created via [`Random::from_entropy`] (for the global TPM RNG),
/// [`Random::from_seed`] or [`Random::instantiate_seeded`] (for deterministic
/// primary-key generation in `TPM2_CreatePrimary`).
///
/// Every method after [`stir_bytes`](Self::stir_bytes) is an optional
/// tpm-rs extension: the lifecycle hooks ([`init`](Self::init),
/// [`startup`](Self::startup), [`self_test`](Self::self_test)), the
/// persistence of the generator's state ([`STATE_SIZE`](Self::STATE_SIZE),
/// [`save_state`](Self::save_state), [`load_state`](Self::load_state)) and
/// [`is_system_rng`](Self::is_system_rng). An RNG implements no random
/// algorithm: the algorithms draw what they need with
/// [`fill_bytes`](Self::fill_bytes) (see [`is_system_rng`](Self::is_system_rng)
/// and the encodings [`rsa_oaep_encode`](super::rsa_oaep_encode),
/// [`rsa_pkcs1v15_encode`](super::rsa_pkcs1v15_encode) and
/// [`rsa_pss_encode`](super::rsa_pss_encode)).
pub trait Rng {
    /// Fills `out` with generated bytes.
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError>;

    /// Mixes `data` into the RNG state.
    ///
    /// Used for `TPM2_StirRandom` on the global RNG, and for mixing object
    /// parameters and hierarchy proof values into a seeded RNG in
    /// `TPM2_CreatePrimary`. For an RNG created by [`Random::from_seed`], this
    /// must be deterministic.
    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// (Re)initializes the generator's entropy source when the TPM is initialized
    /// (`_TPM_Init`, and at manufacture).
    ///
    /// This is a tpm-rs extension: it is like `_plat__GetEntropy(NULL, 0)` of the
    /// reference implementation's simulator platform, which seeds its software
    /// entropy source. Does nothing by default.
    fn init(&mut self) -> Result<(), CryptoError> {
        Ok(())
    }

    /// Prepares the TPM's RNG for use at `TPM2_Startup` (and at manufacture):
    /// reseeds a generator restored with [`load_state`](Self::load_state), or
    /// instantiates it if it has no state (the reference implementation's
    /// `CryptRandStartup()`).
    ///
    /// This is a tpm-rs extension. Does nothing by default.
    fn startup(&mut self) -> Result<(), CryptoError> {
        Ok(())
    }

    /// Runs the generator's self test when the TPM is initialized (`_TPM_Init`
    /// and manufacture, after [`init`](Self::init)) and returns whether it
    /// passed; a failed test puts the TPM into Failure mode (the reference
    /// implementation's `DRBG_SelfTest()`, run by `CryptInit()`). The
    /// generator keeps the state of its self test (e.g. whether it has passed,
    /// or whether its entropy source has failed since) itself.
    ///
    /// This is a tpm-rs extension. Returns `Ok(true)` by default.
    fn self_test(&mut self) -> Result<bool, CryptoError> {
        Ok(true)
    }

    /// The size of the generator's persistent state ([`save_state`],
    /// [`load_state`]), or 0 (the default) if it has none.
    ///
    /// This is a tpm-rs extension: the TPM keeps the state of its RNG in NV
    /// (the reference implementation's `go.drbgState`, written at manufacture,
    /// `TPM2_Shutdown`, `TPM2_Clear` and NV updates of *Clock*, and restored at
    /// `_TPM_Init`), so that the values drawn since the last write are drawn
    /// again after a power cycle.
    ///
    /// [`save_state`]: Self::save_state
    /// [`load_state`]: Self::load_state
    const STATE_SIZE: usize = 0;

    /// Writes the generator's state ([`STATE_SIZE`](Self::STATE_SIZE) bytes)
    /// to `out`.
    ///
    /// This is a tpm-rs extension. Returns [`CryptoError::Unsupported`] by
    /// default.
    fn save_state(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        let _ = out;
        Err(CryptoError::Unsupported)
    }

    /// Replaces the generator's state with `state` (written by
    /// [`save_state`](Self::save_state)); an all-zero state is that of a new
    /// generator, which the next [`startup`](Self::startup) instantiates.
    ///
    /// This is a tpm-rs extension. Returns [`CryptoError::Unsupported`] by
    /// default.
    fn load_state(&mut self, state: &[u8]) -> Result<(), CryptoError> {
        let _ = state;
        Err(CryptoError::Unsupported)
    }

    /// Whether this RNG is the backend's own system RNG (e.g. BoringSSL's
    /// `RAND_bytes`), so that the backend may use its own randomized
    /// algorithms, which draw from that system RNG themselves, instead of
    /// algorithms that draw every random value from this RNG.
    ///
    /// This is a tpm-rs extension. Returns `false` by default. It selects
    /// between the two implementations of the TPM's random asymmetric
    /// operations (`tpm2-engine`, and the backends' key generation):
    ///
    /// - `true`: the backend's own algorithms where it implements them: RSA
    ///   key generation (e.g. BoringSSL's `RSA_generate_key_ex`), ECC key
    ///   generation and ECDSA signatures (e.g. BoringSSL's hedged ECDSA) on the
    ///   curves the backend's ECDSA covers;
    /// - `false` (e.g. a seeded RNG, a test RNG, or a DRBG that reproduces
    ///   another TPM implementation): the algorithms of the C reference TPMs,
    ///   computed by `tpm2-engine` with every random value drawn by
    ///   [`fill_bytes`](Self::fill_bytes) with the reference's sizes, order and
    ///   retries (the prime search of `CryptRsaGenerateKey()`, the private
    ///   scalars of `TpmEcc_GenPrivateScalar()`, the ECDSA nonces).
    ///
    /// Either way, the operations that the backend's algorithms do not cover
    /// draw from this RNG with the reference's algorithms: SM2 and EC-Schnorr
    /// signatures, ECDSA on the other curves, the ECC pairwise consistency
    /// test, and the RSA encodings of this module ([`rsa_oaep_encode`],
    /// [`rsa_pkcs1v15_encode`], [`rsa_pss_encode`]), which the dispatch
    /// functions use for every RNG.
    ///
    /// [`rsa_oaep_encode`]: super::rsa_oaep_encode
    /// [`rsa_pkcs1v15_encode`]: super::rsa_pkcs1v15_encode
    /// [`rsa_pss_encode`]: super::rsa_pss_encode
    fn is_system_rng(&self) -> bool {
        false
    }
}
