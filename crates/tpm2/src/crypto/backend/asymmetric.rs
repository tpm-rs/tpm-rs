//! [`AsymmetricKey`].

use crate::crypto::{CryptoError, Rng};

/// Key management common to all asymmetric key traits, with encoded public
/// keys of `PUB_SIZE` bytes and encoded private keys of `PRIV_SIZE` bytes.
///
/// `Params` are extra key parameters that aren't part of the encoded public
/// key, e.g. the RSA public exponent; `()` for most key types.
///
/// Each key trait (e.g. [`EccCurve`](super::EccCurve)) documents its public
/// and private key encodings.
pub trait AsymmetricKey<const PUB_SIZE: usize, const PRIV_SIZE: usize, Params: Copy = ()>:
    Sized
{
    /// Validated public key state.
    type Public: Sized;
    /// Validated private key state (including the public key).
    type Private: Sized;

    /// Generates a new keypair with `params` from `rng`.
    fn generate(rng: &mut impl Rng, params: Params) -> Result<Self::Private, CryptoError>;

    /// Validates and loads an encoded public key with `params`.
    ///
    /// Returns `Ok(None)` if `public` is invalid.
    fn load_public(
        params: Params,
        public: &[u8; PUB_SIZE],
    ) -> Result<Option<Self::Public>, CryptoError>;

    /// Writes the encoding of `public` into `out`.
    fn store_public(public: &Self::Public, out: &mut [u8; PUB_SIZE]) -> Result<(), CryptoError>;

    /// Validates and loads an encoded private key for `public`.
    ///
    /// Returns `Ok(None)` if `private` is invalid or does not match `public`.
    fn load_private(
        public: Self::Public,
        private: &[u8; PRIV_SIZE],
    ) -> Result<Option<Self::Private>, CryptoError>;

    /// Writes the encoding of `private` into `out`.
    fn store_private(private: &Self::Private, out: &mut [u8; PRIV_SIZE])
    -> Result<(), CryptoError>;

    /// Borrows the public key of `private`.
    fn as_public(private: &Self::Private) -> &Self::Public;
}

impl<const PUB_SIZE: usize, const PRIV_SIZE: usize, Params: Copy>
    AsymmetricKey<PUB_SIZE, PRIV_SIZE, Params> for !
{
    type Public = !;
    type Private = !;

    fn generate(_: &mut impl Rng, _: Params) -> Result<Self::Private, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn load_public(_: Params, _: &[u8; PUB_SIZE]) -> Result<Option<Self::Public>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn store_public(public: &Self::Public, _: &mut [u8; PUB_SIZE]) -> Result<(), CryptoError> {
        match *public {}
    }
    fn load_private(
        public: Self::Public,
        _: &[u8; PRIV_SIZE],
    ) -> Result<Option<Self::Private>, CryptoError> {
        match public {}
    }
    fn store_private(private: &Self::Private, _: &mut [u8; PRIV_SIZE]) -> Result<(), CryptoError> {
        match *private {}
    }
    fn as_public(private: &Self::Private) -> &Self::Public {
        match *private {}
    }
}
