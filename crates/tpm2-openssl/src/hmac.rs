//! HMAC, generic over the OpenSSL digest's NID.

use core::ffi::c_int;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl_sys as ffi;
use tpm2::crypto::{
    CryptoError,
    backend::{Hmac, HmacState},
};

use crate::hash::digest;

/// Streaming HMAC state for the `SIZE`-byte OpenSSL digest with NID `NID`.
pub struct OpensslHmac<const NID: c_int, const SIZE: usize>(Signer<'static>);

impl<const NID: c_int, const SIZE: usize> HmacState<SIZE> for OpensslHmac<NID, SIZE> {
    fn init(key: &[u8]) -> Result<Self, CryptoError> {
        // OpenSSL rejects empty HMAC keys. Per RFC 2104, keys are zero-padded
        // to the block size, so `[0]` gives the same HMAC.
        let key = if key.is_empty() { &[0] } else { key };
        let pkey = PKey::hmac(key).map_err(|_| CryptoError::Internal)?;
        let signer = Signer::new(digest(NID)?, &pkey).map_err(|_| CryptoError::Internal)?;
        Ok(Self(signer))
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data).map_err(|_| CryptoError::Internal)
    }
    fn finalize(&mut self, out: &mut [u8; SIZE]) -> Result<(), CryptoError> {
        let sig = self.0.sign_to_vec().map_err(|_| CryptoError::Internal)?;
        out.copy_from_slice(&sig);
        Ok(())
    }
}

impl Hmac for super::OpensslBackend {
    type Sha1 = OpensslHmac<{ ffi::NID_sha1 }, 20>;
    type Sha256 = OpensslHmac<{ ffi::NID_sha256 }, 32>;
    type Sha384 = OpensslHmac<{ ffi::NID_sha384 }, 48>;
    type Sha512 = OpensslHmac<{ ffi::NID_sha512 }, 64>;
    type Sm3_256 = OpensslHmac<{ ffi::NID_sm3 }, 32>;
    type Sha3_256 = OpensslHmac<{ ffi::NID_sha3_256 }, 32>;
    type Sha3_384 = OpensslHmac<{ ffi::NID_sha3_384 }, 48>;
    type Sha3_512 = OpensslHmac<{ ffi::NID_sha3_512 }, 64>;
}
