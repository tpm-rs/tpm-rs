//! HMAC implementations for SHA-1 and SHA-2 (`SHA-256`, `SHA-384`, `SHA-512`)
//! via BoringSSL's `HMAC_*` API.

use core::{ffi::c_uint, ptr};

use tpm2::crypto::{
    CryptoError,
    backend::{Hmac, HmacState},
};

use crate::bssl_sys;
use crate::{
    BoringSsl,
    util::{Owned, check},
};

/// Streaming HMAC state backed by BoringSSL `HMAC_CTX`.
pub struct BoringSslHmacState<const DIGEST_SIZE: usize>(Owned<bssl_sys::HMAC_CTX>);

impl<const DIGEST_SIZE: usize> HmacState<DIGEST_SIZE> for BoringSslHmacState<DIGEST_SIZE> {
    #[inline(never)]
    fn init(key: &[u8]) -> Result<Self, CryptoError> {
        let md = unsafe {
            match DIGEST_SIZE {
                20 => bssl_sys::EVP_sha1(),
                32 => bssl_sys::EVP_sha256(),
                48 => bssl_sys::EVP_sha384(),
                64 => bssl_sys::EVP_sha512(),
                _ => return Err(CryptoError::Unsupported),
            }
        };
        let ctx = Owned::new(unsafe { bssl_sys::HMAC_CTX_new() })?;
        // `key` is never NULL (which would reuse the previous key), even if empty.
        check(unsafe {
            bssl_sys::HMAC_Init_ex(
                ctx.as_ptr(),
                key.as_ptr().cast(),
                key.len(),
                md,
                ptr::null_mut(),
            )
        })?;
        Ok(Self(ctx))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        check(unsafe { bssl_sys::HMAC_Update(self.0.as_ptr(), data.as_ptr(), data.len()) })
    }

    fn finalize(&mut self, out: &mut [u8; DIGEST_SIZE]) -> Result<(), CryptoError> {
        let mut out_len: c_uint = 0;
        check(unsafe {
            bssl_sys::HMAC_Final(self.0.as_ptr(), out.as_mut_ptr(), &raw mut out_len)
        })?;
        if out_len as usize != DIGEST_SIZE {
            return Err(CryptoError::Internal);
        }
        Ok(())
    }
}

impl Hmac for BoringSsl {
    type Sha1 = BoringSslHmacState<20>;
    type Sha256 = BoringSslHmacState<32>;
    type Sha384 = BoringSslHmacState<48>;
    type Sha512 = BoringSslHmacState<64>;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}
