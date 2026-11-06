//! Hash functions and HMAC: SHA-1, SHA-256, SHA-384 and SHA-512 (`sha1`, `sha2`, `hmac`).

use crate::RustCryptoProvider;
use tpm2::crypto::CryptoError;
use tpm2::crypto::backend::{Hash, HashState, Hmac, HmacState};

/// The streaming state of the RustCrypto hash function `D` (such as `sha2::Sha256`), for
/// `RustCryptoProvider`.
#[derive(Clone)]
pub struct RustCryptoHash<D>(D);

impl<D, const N: usize> HashState<N> for RustCryptoHash<D>
where
    D: sha2::Digest + sha2::digest::FixedOutputReset,
{
    fn init() -> Result<Self, CryptoError> {
        if <D as sha2::Digest>::output_size() != N {
            return Err(CryptoError::Internal);
        }
        Ok(Self(D::new()))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        sha2::Digest::update(&mut self.0, data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.copy_from_slice(&sha2::Digest::finalize_reset(&mut self.0));
        Ok(())
    }
}

/// SHA-1 context for `RustCryptoProvider`.
pub type RustCryptoSha1 = RustCryptoHash<sha1::Sha1>;
/// SHA-256 context for `RustCryptoProvider`.
pub type RustCryptoSha256 = RustCryptoHash<sha2::Sha256>;
/// SHA-384 context for `RustCryptoProvider`.
pub type RustCryptoSha384 = RustCryptoHash<sha2::Sha384>;
/// SHA-512 context for `RustCryptoProvider`.
pub type RustCryptoSha512 = RustCryptoHash<sha2::Sha512>;

impl Hash for RustCryptoProvider {
    type Sha1 = RustCryptoSha1;
    type Sha256 = RustCryptoSha256;
    type Sha384 = RustCryptoSha384;
    type Sha512 = RustCryptoSha512;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}

/// The streaming state of the RustCrypto MAC `M` (such as `hmac::Hmac<sha2::Sha256>`), for
/// `RustCryptoProvider`.
#[derive(Clone)]
pub struct RustCryptoHmac<M>(M);

impl<M, const N: usize> HmacState<N> for RustCryptoHmac<M>
where
    M: hmac::Mac + hmac::digest::KeyInit + hmac::digest::FixedOutputReset,
{
    /// HMAC accepts keys of any length, so `new_from_slice` cannot fail; if it did, that would
    /// be an internal error (`CryptoError::Internal`).
    fn init(key: &[u8]) -> Result<Self, CryptoError> {
        if <M as hmac::digest::OutputSizeUser>::output_size() != N {
            return Err(CryptoError::Internal);
        }
        <M as hmac::Mac>::new_from_slice(key)
            .map(Self)
            .map_err(|_| CryptoError::Internal)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        hmac::Mac::update(&mut self.0, data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.copy_from_slice(&hmac::Mac::finalize_reset(&mut self.0).into_bytes());
        Ok(())
    }
}

/// HMAC-SHA-1 context for `RustCryptoProvider`.
pub type RustCryptoHmacSha1 = RustCryptoHmac<hmac::Hmac<sha1::Sha1>>;
/// HMAC-SHA-256 context for `RustCryptoProvider`.
pub type RustCryptoHmacSha256 = RustCryptoHmac<hmac::Hmac<sha2::Sha256>>;
/// HMAC-SHA-384 context for `RustCryptoProvider`.
pub type RustCryptoHmacSha384 = RustCryptoHmac<hmac::Hmac<sha2::Sha384>>;
/// HMAC-SHA-512 context for `RustCryptoProvider`.
pub type RustCryptoHmacSha512 = RustCryptoHmac<hmac::Hmac<sha2::Sha512>>;

impl Hmac for RustCryptoProvider {
    type Sha1 = RustCryptoHmacSha1;
    type Sha256 = RustCryptoHmacSha256;
    type Sha384 = RustCryptoHmacSha384;
    type Sha512 = RustCryptoHmacSha512;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}
