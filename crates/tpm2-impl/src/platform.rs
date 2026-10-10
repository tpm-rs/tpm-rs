//! TPM 2.0 Platform Abstraction Layer
//!
//! The `tpm-rs` library is designed to run across diverse operational environments—ranging
//! from resource-constrained bare-metal embedded firmware (utilizing custom hardware accelerators)
//! to user-space host applications running on a desktop operating system (e.g., Linux, Windows).
//!
//! This module bundles all external dependencies of the engine (cryptography, the global random
//! number generator, clocks and non-volatile storage) into a [`TpmPlatform`]. This isolation keeps
//! the engine's state machine and command processing logic independent of the execution
//! environment.
//!
//! The individual platform traits live next to the code that uses them:
//! - [`NvStorage`]: Low-level non-volatile memory (NV) access.
//! - [`TpmTimer`]: Monotonic clock/timer interface.
//! - [`Crypto`]: The cryptographic backend (a combination of the `tpm2::crypto` traits).
//! - [`PcrState`](crate::pcr::PcrState): Platform configuration register banks.

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::crypto::{
    Cmac, ConstantTimeEq, Ecc, Hash, Hmac, Mldsa, Mlkem, Random, Rsa, Signing, Symmetric,
};

/// The cryptographic backend required by the TPM engine.
///
/// This is the union of the individual [`tpm2::crypto`] traits. It is implemented automatically
/// for every type implementing all of them, so backends never implement it directly. Algorithms a
/// backend does not support are reported through the default trait methods returning
/// [`CryptoError::Unsupported`](tpm2::crypto::CryptoError::Unsupported).
///
/// The associated [`Random::Rng`] type is the engine's global random number generator (see
/// [`TpmPlatform::rng`]).
pub trait Crypto:
    Hash + Hmac + Cmac + Symmetric + Random + Rsa + Ecc + Signing + Mlkem + Mldsa + ConstantTimeEq
{
}

impl<C> Crypto for C where
    C: Hash
        + Hmac
        + Cmac
        + Symmetric
        + Random
        + Rsa
        + Ecc
        + Signing
        + Mlkem
        + Mldsa
        + ConstantTimeEq
{
}

/// Context defining the resources the TPM engine has access to.
pub struct TpmPlatform<'a, C, S, T>
where
    C: Crypto,
    S: NvStorage,
    T: TpmTimer,
{
    /// Cryptography provider.
    pub crypto: &'a C,
    /// NV storage provider.
    pub storage: &'a mut S,
    /// Monotonic timer.
    pub timer: &'a mut T,
    /// The global TPM random number generator.
    ///
    /// Every random value the TPM produces (nonces, seeds, proofs, `TPM2_GetRandom` output and
    /// the entropy recorded in [`DrbgState`](crate::DrbgState)) is drawn from this generator, and
    /// `TPM2_StirRandom` mixes its input into it via [`Rng::reseed`](tpm2::crypto::Rng::reseed).
    pub rng: C::Rng,
}

impl<'a, C, S, T> TpmPlatform<'a, C, S, T>
where
    C: Crypto,
    S: NvStorage,
    T: TpmTimer,
{
    /// Constructs a new `TpmPlatform` from references to hardware providers.
    ///
    /// `rng` is normally obtained from [`Random::rng`] (seeded from platform entropy). Tests can
    /// pass an RNG from [`Random::rng_seeded`] to get reproducible TPM output.
    pub fn new(crypto: &'a C, storage: &'a mut S, timer: &'a mut T, rng: C::Rng) -> Self {
        Self {
            crypto,
            storage,
            timer,
            rng,
        }
    }
}
