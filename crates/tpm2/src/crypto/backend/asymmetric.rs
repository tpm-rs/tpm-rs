//! [`PrivateKey`].

use crate::crypto::{CryptoError, Rng};

/// Key management common to all asymmetric key traits, with encoded public
/// keys of `PUB_SIZE` bytes and encoded private keys of `PRIV_SIZE` bytes.
///
/// Implemented by a backend's validated private key type, which includes its
/// public key ([`as_public`](Self::as_public)). The validated public key type
/// is [`PublicKey`](Self::PublicKey).
///
/// `R` is the backend's [`Random::Rng`](crate::crypto::Random::Rng) type, so
/// randomized operations can use the RNG's internals (e.g. to call a native
/// implementation when the RNG uses the system entropy source). Backends
/// normally implement this trait only for their own `R`.
///
/// `P` are extra key parameters that aren't part of the encoded public key
/// (e.g. the RSA public exponent); `()` for most key types.
///
/// Each key trait (e.g. [`EccCurve`](super::EccCurve)) documents its public
/// and private key encodings.
pub trait PrivateKey<const PUB_SIZE: usize, const PRIV_SIZE: usize, R: Rng, P = ()>: Sized {
    /// Validated public key.
    type PublicKey;

    /// Generates a new private key with `params` using `rng`.
    fn generate(rng: &mut R, params: P) -> Result<Self, CryptoError>;

    /// Validates and loads an encoded private key for `public`.
    ///
    /// Returns `Ok(None)` if `private` is invalid or does not match `public`.
    fn load(
        public: Self::PublicKey,
        private: &[u8; PRIV_SIZE],
    ) -> Result<Option<Self>, CryptoError>;

    /// Writes the encoding of this private key into `out`.
    fn store(&self, out: &mut [u8; PRIV_SIZE]) -> Result<(), CryptoError>;

    /// Borrows the public key of this private key.
    fn as_public(&self) -> &Self::PublicKey;

    /// Validates and loads an encoded public key with `params`.
    ///
    /// Returns `Ok(None)` if `public` is invalid.
    fn load_public(
        params: P,
        public: &[u8; PUB_SIZE],
    ) -> Result<Option<Self::PublicKey>, CryptoError>;

    /// Writes the encoding of `public` into `out`.
    fn store_public(public: &Self::PublicKey, out: &mut [u8; PUB_SIZE]) -> Result<(), CryptoError>;
}

impl<const PUB_SIZE: usize, const PRIV_SIZE: usize, R: Rng, P> PrivateKey<PUB_SIZE, PRIV_SIZE, R, P> for ! {
    type PublicKey = !;

    fn generate(_: &mut R, _: P) -> Result<Self, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn load(public: !, _: &[u8; PRIV_SIZE]) -> Result<Option<Self>, CryptoError> {
        match public {}
    }
    fn store(&self, _: &mut [u8; PRIV_SIZE]) -> Result<(), CryptoError> {
        match *self {}
    }
    fn as_public(&self) -> &! {
        match *self {}
    }
    fn load_public(_: P, _: &[u8; PUB_SIZE]) -> Result<Option<!>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn store_public(public: &!, _: &mut [u8; PUB_SIZE]) -> Result<(), CryptoError> {
        match *public {}
    }
}
