//! Cryptographic Dispatch Functions
//!
//! This module contains dispatch functions (and enums) used by TPM
//! implementations and clients to call into [`Crypto`] backends. These
//! functions select an algorithm at runtime (e.g. via
//! [`TpmiAlgHash`](crate::TpmiAlgHash)) and dispatch to the corresponding
//! algorithm's implementation.
//!
//! Users should generally use `C: Crypto` bounds for code that is generic
//! over cryptographic backends.
//!
//! ## One-shot functions
//!
//! Most use-cases can use the simple "one-shot" functions for:
//! - Hashing: [`hash`](hash::hash)
//! - HMACs: [`hmac`](hmac::hmac)
//! - KDFs: [`kdfa`], [`kdfe`]
//! - Encryption and Decryption: [`SymmetricKey::crypt`]
//! - CMACs: [`SymmetricKey::cmac`]
//! - Random bytes: [`Random::rand_bytes`]
//!
//! ## Stateful `enum`s and RNG
//!
//! When cryptographic context must persist across commands, this module also
//! provides stateful dispatch enums (and [`Rng`]) with methods that use/mutate
//! the state:
//! - Hashing: [`HashContext`]
//! - HMACs: [`HmacContext`]
//! - Encryption and Decryption: [`SymmetricContext`]
//! - CMACs: [`CmacContext`]
//! - Random number generation: [`Rng`] (created via [`Random::from_entropy`] or
//!   [`Random::from_seed`])
//!
//! For stack usage and code size guidance, see the
//! [backend optimization notes](backend#optimization-notes).

#[cfg(feature = "cmac")]
mod cmac;
mod hash;
mod hmac;
mod rng;
mod symmetric;

pub mod backend;
#[cfg(feature = "cmac")]
pub use cmac::*;
pub use {hash::*, hmac::*, rng::*, symmetric::*};

/// Common error type for all cryptographic operations.
///
/// We intentionally don't allow cryptography backends to provide rich error
/// information, as we can't do anything other than enter failure mode when we
/// receive [`CryptoError::Internal`].
///
/// `CryptoError` is not used to reject invalid caller input that a TPM should
/// report with a normal response code. Such checks return an [`Option`] or
/// [`bool`] instead (e.g. [`SymmetricKey::new`] or [`CipherInput::new`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The requested algorithm, mode, or key size is unsupported.
    Unsupported,
    /// An internal error, which puts the TPM into failure mode.
    Internal,
}

/// A complete cryptography backend.
///
/// Backends implement [`Random`], the [`backend`] family traits, and then this
/// trait. Generic code should use a `C: Crypto` bound rather than naming the
/// backend traits directly.
pub trait Crypto:
    Random + backend::Hash + backend::Hmac + backend::Cmac + backend::Symmetric
{
    /// Returns `a == b`, in time independent of the slice contents.
    fn ct_eq(a: &[u8], b: &[u8]) -> bool;
}

// Internal helper macros

/// Generates a `match` with one arm per enabled variant of an algorithm enum.
///
/// The first arm is a template: `$Alg` is replaced with each variant name. Its
/// pattern must be a path ending in `$Alg` (optionally followed by `(..)`), and
/// its body must be a `{ .. }` block. Arms after it (following a `,`) are
/// copied unchanged, e.g. for variants outside the algorithm family:
///
/// ```ignore
/// match_ecc_curve!(match self {
///     Self::$Alg(_) => { TpmEccCurve::$Alg },
///     Self::X25519(_) => TpmEccCurve::Curve25519,
/// })
/// ```
///
/// The scrutinee must be a single token tree, e.g. `self` or `(*self)`.
macro_rules! match_variants {
    (
        [$($(#[$m:meta])* $V:ident),* $(,)?]
        match $v:tt {
            $($p:ident ::)+ $d:tt $Alg:ident $(($($f:tt)*))? => $body:tt
            $(, $($extra:tt)*)?
        }
    ) => {{
        // `$d` is the caller's `$`, needed to declare the inner macro's metavariables.
        macro_rules! match_arms {
            ($d($d(#[$d m:meta])* $d $Alg:ident),*) => {
                match $v {
                    $d($d(#[$d m])* $($p ::)+ $d $Alg $(($($f)*))? => $body,)*
                    $($($extra)*)?
                }
            };
        }
        match_arms!($($(#[$m])* $V),*)
    }};
}

/// [`match_variants`] over the [`TpmiAlgHash`](crate::TpmiAlgHash) variants.
macro_rules! match_hash_alg {
    ($($t:tt)*) => {
        $crate::crypto::match_variants!([
            #[cfg(feature = "sha1")] Sha1,
            #[cfg(feature = "sha256")] Sha256,
            #[cfg(feature = "sha384")] Sha384,
            #[cfg(feature = "sha512")] Sha512,
            #[cfg(feature = "sm3_256")] Sm3_256,
            #[cfg(feature = "sha3_256")] Sha3_256,
            #[cfg(feature = "sha3_384")] Sha3_384,
            #[cfg(feature = "sha3_512")] Sha3_512,
        ] $($t)*)
    };
}

/// [`match_variants`] over the [`AlgSym`](crate::AlgSym) variants.
macro_rules! match_sym_alg {
    ($($t:tt)*) => {
        $crate::crypto::match_variants!([
            #[cfg(feature = "aes128")] Aes128,
            #[cfg(feature = "aes192")] Aes192,
            #[cfg(feature = "aes256")] Aes256,
            #[cfg(feature = "sm4_128")] Sm4_128,
            #[cfg(feature = "camellia128")] Camellia128,
            #[cfg(feature = "camellia192")] Camellia192,
            #[cfg(feature = "camellia256")] Camellia256,
        ] $($t)*)
    };
}

// Lets the submodules (declared above) import these macros by path.
use {match_hash_alg, match_sym_alg, match_variants};
