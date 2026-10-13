//! Cryptography Interfaces for TPM implementations and clients
//!
//! ## Error handling
//!
//! Every fallible operation returns [`CryptoError`], which only distinguishes
//! unsupported algorithms/modes/key sizes ([`CryptoError::Unsupported`]) from
//! internal failures that put the TPM into failure mode
//! ([`CryptoError::Internal`]). Semantic failures caused by the inputs (a bad
//! signature, an invalid ECC point, a point at infinity, bad padding or
//! ciphertext, a message too large for a key, an invalid key, ...) are not
//! errors: they are reported in the `Ok` value:
//!   - Verification and validation return `Ok(false)`.
//!   - Operations producing output (signing, encryption, decryption, key
//!     import, ECC point multiplication) return `Ok(None)`.
//!
//! ## Module organization
//!
//! All items are re-exported at the top level of this module (e.g.
//! [`crypto::kdfa`](kdfa)). The [`asymmetric`](mod@asymmetric),
//! [`cmac`](mod@cmac), [`ecc`](mod@ecc), [`kdf`](mod@kdf), [`rng`](mod@rng),
//! and [`symmetric`](mod@symmetric) submodules are also public, so that paths
//! like `tpm2::crypto::kdf::kdfa` and `tpm2::crypto::asymmetric::KeyParams`
//! keep working.
pub mod asymmetric;
pub mod cmac;
pub mod ecc;
mod hash;
mod hmac;
pub mod kdf;
pub mod rng;
pub mod symmetric;
pub use {asymmetric::*, cmac::*, ecc::*, hash::*, hmac::*, kdf::*, rng::*, symmetric::*};

/// Common error type for all cryptographic traits.
///
/// We intentionally don't allow cryptography backends to provide rich error
/// information, as we can't do anything other than enter failure mode when we
/// receive [`CryptoError::Internal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The requested algorithm, mode, or key size is unsupported.
    Unsupported,
    /// An internal error, which puts the TPM into failure mode.
    Internal,
}

/// Selects between encryption and decryption operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

/// Constant-time equality comparison for fixed-length byte arrays.
pub trait ConstantTimeEq {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool;
}

/// Feeds incremental input bytes into an active cryptographic stream context.
pub trait Update {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;
}
/// Consumes a cryptographic stream context and writes the fixed-length output.
///
/// Other traits and functions wrap this to return TPM structs. For example,
/// [`HashStream::finalize`] wraps this to return a [TpmtHa](crate::TpmtHa).
pub trait Finalize<const N: usize> {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError>;
}

impl Update for ! {
    fn update(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        match *self {}
    }
}
impl<const N: usize> Finalize<N> for ! {
    fn finalize(self, _: &mut [u8; N]) -> Result<(), CryptoError> {
        match self {}
    }
}

/// The core cryptography provider factory.
///
/// This acts as the entire Hardware Abstraction Layer mapping: a TPM engine is
/// generic over a single `CryptoProvider`, which bundles every cryptographic
/// interface of this module. Backends implement it explicitly (there is no
/// blanket implementation), after implementing each of the super-traits.
///
/// ## The provider CSPRNG
///
/// Besides the super-traits, a provider supplies the cryptographically secure
/// random number generator used by the TPM engine for nonces, seeds, proofs,
/// and symmetric keys ([`CryptoProvider::get_random`]), which can be stirred
/// with additional data ([`CryptoProvider::stir_random`], used by
/// `TPM2_StirRandom`). It is shared (`&self`): a provider has a single random
/// stream, used by every caller.
///
/// This generator is distinct from:
///   - the platform RNG ([`Rng`] in
///     [`TpmPlatform`](crate::platform::TpmPlatform)), and
///   - the RNG instances created through [`Random`].
///
/// [`CryptoProvider::get_random`] is a **required** method: the TPM engine
/// cannot run without randomness, so a provider without a random source should
/// fail to compile rather than fail at run time with
/// [`CryptoError::Unsupported`]. [`CryptoProvider::stir_random`] defaults to
/// ignoring the additional data (`Ok(())`), which is valid for generators that
/// are continuously reseeded from an entropy source.
///
/// ## Example
///
/// ```
/// # use tpm2::crypto::*;
/// # struct MyBackend;
/// # impl Hash for MyBackend {
/// #     type Sha1Context = !;
/// #     type Sha256Context = !;
/// #     type Sha384Context = !;
/// #     type Sha512Context = !;
/// #     type Sm3_256Context = !;
/// #     type Sha3_256Context = !;
/// #     type Sha3_384Context = !;
/// #     type Sha3_512Context = !;
/// # }
/// # impl Hmac for MyBackend {
/// #     type Sha1Context = !;
/// #     type Sha256Context = !;
/// #     type Sha384Context = !;
/// #     type Sha512Context = !;
/// #     type Sm3_256Context = !;
/// #     type Sha3_256Context = !;
/// #     type Sha3_384Context = !;
/// #     type Sha3_512Context = !;
/// # }
/// # impl Cmac for MyBackend {
/// #     type Aes128Context = !;
/// #     type Aes192Context = !;
/// #     type Aes256Context = !;
/// #     type Sm4_128Context = !;
/// #     type Camellia128Context = !;
/// #     type Camellia192Context = !;
/// #     type Camellia256Context = !;
/// # }
/// # impl Symmetric for MyBackend {}
/// # impl ConstantTimeEq for MyBackend {
/// #     fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
/// #         a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
/// #     }
/// # }
/// # impl Random for MyBackend {
/// #     type Rng = !;
/// # }
/// # impl Asymmetric for MyBackend {}
/// # impl AsymmetricSign for MyBackend {}
/// # impl Ecc for MyBackend {
/// #     type NistP192Context = !;
/// #     type NistP224Context = !;
/// #     type NistP256Context = !;
/// #     type NistP384Context = !;
/// #     type NistP521Context = !;
/// #     type BnP256Context = !;
/// #     type BnP638Context = !;
/// #     type Sm2P256Context = !;
/// #     type BpP256R1Context = !;
/// #     type BpP384R1Context = !;
/// #     type BpP512R1Context = !;
/// #     type Curve25519Context = !;
/// #     type Curve448Context = !;
/// # }
/// impl CryptoProvider for MyBackend {
///     fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
///         // Fill `dest` from the backend's CSPRNG.
///         dest.fill(0x42);
///         Ok(())
///     }
///     // `stir_random` keeps its default (ignore the additional data).
/// }
/// ```
pub trait CryptoProvider:
    Hash + Hmac + Cmac + Symmetric + ConstantTimeEq + Random + Asymmetric + AsymmetricSign + Ecc
{
    /// Fills `dest` with cryptographically secure random bytes from the
    /// provider's CSPRNG.
    ///
    /// # Errors
    /// * [`CryptoError::Internal`] - The underlying entropy source failed
    ///   (e.g. the TRNG ran out of entropy or a continuous health test failed).
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError>;

    /// Mixes `data` into the provider's CSPRNG state (`TPM2_StirRandom`).
    ///
    /// The default implementation ignores `data` and returns `Ok(())`.
    ///
    /// # Errors
    /// * [`CryptoError::Internal`] - The generator failed to absorb `data`.
    fn stir_random(&self, data: &[u8]) -> Result<(), CryptoError> {
        let _ = data;
        Ok(())
    }
}
