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
//! - KDFs: [`kdfa`], [`kdfa_xor`], [`kdfe`]
//! - Encryption and Decryption: [`SymmetricKey::crypt`]
//! - CMACs: [`SymmetricKey::cmac`]
//! - Random bytes: [`Random::rand_bytes`]
//!
//! ## Stateful `enum`s and RNG
//!
//! When cryptographic context must persist across commands, this module also
//! provides stateful dispatch enums with methods that use/mutate the state:
//! - Hashing: [`HashContext`]
//! - HMACs: [`HmacContext`]
//! - Encryption and Decryption: [`SymmetricContext`]
//! - CMACs: [`CmacContext`]
//! - Random number generation: [`Rng`] (created via [`Random::from_entropy`] or
//!   [`Random::from_seed`])
//! - RSA: [`RsaPublicKey`] (`encrypt`, `verify`) and [`RsaPrivateKey`]
//!   (`decrypt`, `sign`)
//! - ECC: [`EccPublicKey`] (`verify`) and [`EccPrivateKey`] (`ecdh`, `sign`)
//!
//! For stack usage and code size guidance, see the
//! [backend optimization notes](backend#optimization-notes).

#[cfg(feature = "cmac")]
mod cmac;
#[cfg(feature = "ecc")]
mod ecc;
mod hash;
mod hmac;
mod rng;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(any(feature = "rsa", feature = "ecc"))]
mod signing;
mod symmetric;

pub mod backend;
#[cfg(feature = "cmac")]
pub use cmac::*;
#[cfg(feature = "ecc")]
pub use ecc::*;
#[cfg(feature = "rsa")]
pub use rsa::*;
#[cfg(any(feature = "rsa", feature = "ecc"))]
pub use signing::*;
pub use {hash::*, hmac::*, rng::*, symmetric::*};

/// Common error type for all cryptographic operations.
///
/// We intentionally don't allow cryptography backends to provide rich error
/// information, as we can't do anything other than enter failure mode when we
/// receive [`CryptoError::Internal`].
///
/// `CryptoError` is not used to reject invalid caller input that a TPM should
/// report with a normal response code. Such checks return an [`Option`] or
/// [`bool`] instead (e.g. [`SymmetricKey::new`], an off-curve ECC point, invalid
/// RSA padding, or a failed signature verification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The requested algorithm, mode, scheme, exponent, or key size is
    /// unsupported.
    Unsupported,
    /// An internal error, which puts the TPM into failure mode.
    Internal,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported => {
                write!(f, "unsupported cryptographic algorithm, mode, or key size")
            }
            Self::Internal => write!(f, "internal cryptographic error"),
        }
    }
}

impl core::error::Error for CryptoError {}

/// A complete cryptography backend.
///
/// Backends implement [`Random`], the [`backend`] family traits, and then this
/// trait. Generic code should use a `C: Crypto` bound rather than naming the
/// backend traits directly.
pub trait Crypto:
    Random
    + backend::Hash
    + backend::Hmac
    + backend::Cmac
    + backend::Symmetric
    + backend::Rsa
    + backend::Ecc
{
    /// Returns `a == b`, in time independent of the slice contents.
    fn ct_eq(a: &[u8], b: &[u8]) -> bool;
}

// Internal helpers

/// Left-pads a non-empty big-endian integer slice (`1 <= src.len() <= N`) with
/// `0x00` bytes into an `N`-byte array, returning `None` if `src` is empty or
/// longer than `N`.
#[cfg(any(feature = "rsa", feature = "ecc"))]
// Unused if `ecc` is enabled without `rsa` or any Weierstrass curve.
#[cfg_attr(not(feature = "rsa"), allow(dead_code))]
pub(crate) fn left_pad_be<const N: usize>(src: &[u8]) -> Option<[u8; N]> {
    if src.is_empty() || src.len() > N {
        return None;
    }
    let mut out = [0u8; N];
    out[N - src.len()..].copy_from_slice(src);
    Some(out)
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

/// [`match_variants`] over the [`TpmiRsaKeyBits`](crate::TpmiRsaKeyBits)
/// variants.
#[cfg(feature = "rsa")]
macro_rules! match_rsa_bits {
    ($($t:tt)*) => {
        $crate::crypto::match_variants!([
            #[cfg(feature = "rsa1024")] Rsa1024,
            #[cfg(feature = "rsa2048")] Rsa2048,
            #[cfg(feature = "rsa3072")] Rsa3072,
            #[cfg(feature = "rsa4096")] Rsa4096,
        ] $($t)*)
    };
}
#[cfg(feature = "rsa")]
use match_rsa_bits;

/// [`match_variants`] over the Weierstrass [`TpmEccCurve`](crate::TpmEccCurve)
/// variants.
#[cfg(feature = "ecc")]
macro_rules! match_ecc_curve {
    ($($t:tt)*) => {
        $crate::crypto::match_variants!([
            #[cfg(feature = "nist_p192")] NistP192,
            #[cfg(feature = "nist_p224")] NistP224,
            #[cfg(feature = "nist_p256")] NistP256,
            #[cfg(feature = "nist_p384")] NistP384,
            #[cfg(feature = "nist_p521")] NistP521,
            #[cfg(feature = "bn_p256")] BNP256,
            #[cfg(feature = "bn_p638")] BNP638,
            #[cfg(feature = "sm2_p256")] SM2P256,
            #[cfg(feature = "bp_p256_r1")] BpP256R1,
            #[cfg(feature = "bp_p384_r1")] BpP384R1,
            #[cfg(feature = "bp_p512_r1")] BpP512R1,
        ] $($t)*)
    };
}
#[cfg(feature = "ecc")]
use match_ecc_curve;

use {match_hash_alg, match_sym_alg, match_variants};

#[cfg(test)]
mod tests;
