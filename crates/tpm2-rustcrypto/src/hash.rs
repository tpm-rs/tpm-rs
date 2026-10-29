//! [`Hash`](tpm2::crypto::backend::Hash) and
//! [`Hmac`](tpm2::crypto::backend::Hmac) streaming states.

use hmac::{
    KeyInit, SimpleHmacReset,
    digest::{
        Digest, FixedOutputReset, OutputSizeUser, Update, array::ArraySize, common::BlockSizeUser,
    },
};
use tpm2::crypto::{
    CryptoError,
    backend::{HashState, HmacState},
};

/// Streaming hash context wrapping a RustCrypto [`Digest`].
pub struct HashWrapper<D>(D);

impl<D: Digest + FixedOutputReset, const DIGEST_SIZE: usize> HashState<DIGEST_SIZE>
    for HashWrapper<D>
where
    D::OutputSize: ArraySize<ArrayType<u8> = [u8; DIGEST_SIZE]>,
{
    fn init() -> Result<Self, CryptoError> {
        Ok(Self(D::new()))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        Digest::update(&mut self.0, data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; DIGEST_SIZE]) -> Result<(), CryptoError> {
        FixedOutputReset::finalize_into_reset(&mut self.0, out.into());
        Ok(())
    }
}

/// Streaming HMAC context wrapping [`SimpleHmacReset`].
pub struct HmacWrapper<D: Digest + BlockSizeUser>(SimpleHmacReset<D>);

impl<D: Digest + BlockSizeUser + FixedOutputReset, const DIGEST_SIZE: usize> HmacState<DIGEST_SIZE>
    for HmacWrapper<D>
where
    <D as OutputSizeUser>::OutputSize: ArraySize<ArrayType<u8> = [u8; DIGEST_SIZE]>,
{
    fn init(key: &[u8]) -> Result<Self, CryptoError> {
        SimpleHmacReset::new_from_slice(key)
            .map(Self)
            .map_err(|_| CryptoError::Internal)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        Update::update(&mut self.0, data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; DIGEST_SIZE]) -> Result<(), CryptoError> {
        FixedOutputReset::finalize_into_reset(&mut self.0, out.into());
        Ok(())
    }
}
