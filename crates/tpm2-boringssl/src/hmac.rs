//! HMAC implementations for SHA-1 and SHA-2 (`SHA-256`, `SHA-384`, `SHA-512`)
//! via BoringSSL's FIPS-module `HMAC_*` API.

use core::ptr::{self, NonNull};

use tpm2::crypto::{
    CryptoError,
    backend::{Hmac, HmacState},
};

use crate::{BoringSsl, bssl_sys};

/// Streaming HMAC state backed by BoringSSL `HMAC_CTX`.
pub struct BoringSslHmacState<const DIGEST_SIZE: usize> {
    ctx: NonNull<bssl_sys::HMAC_CTX>,
}

// SAFETY: `HMAC_CTX` is an independent heap-allocated state with no thread-local affinity.
unsafe impl<const DIGEST_SIZE: usize> Send for BoringSslHmacState<DIGEST_SIZE> {}
unsafe impl<const DIGEST_SIZE: usize> Sync for BoringSslHmacState<DIGEST_SIZE> {}

impl<const DIGEST_SIZE: usize> Drop for BoringSslHmacState<DIGEST_SIZE> {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::HMAC_CTX_free(self.ctx.as_ptr());
        }
    }
}

fn evp_md<const DIGEST_SIZE: usize>() -> Result<*const bssl_sys::EVP_MD, CryptoError> {
    let md = unsafe {
        match DIGEST_SIZE {
            20 => bssl_sys::EVP_sha1(),
            32 => bssl_sys::EVP_sha256(),
            48 => bssl_sys::EVP_sha384(),
            64 => bssl_sys::EVP_sha512(),
            _ => return Err(CryptoError::Unsupported),
        }
    };
    if md.is_null() {
        Err(CryptoError::Internal)
    } else {
        Ok(md)
    }
}

macro_rules! impl_hmac_state {
    ($size:literal) => {
        impl HmacState<$size> for BoringSslHmacState<$size> {
            #[inline(never)]
            fn init(key: &[u8]) -> Result<Self, CryptoError> {
                let md = evp_md::<$size>()?;
                let ctx = NonNull::new(unsafe { bssl_sys::HMAC_CTX_new() })
                    .ok_or(CryptoError::Internal)?;
                let state = Self { ctx };
                let empty = 0u8;
                let key_ptr = if key.is_empty() {
                    (&raw const empty).cast()
                } else {
                    key.as_ptr().cast()
                };
                let ok = unsafe {
                    bssl_sys::HMAC_Init_ex(
                        state.ctx.as_ptr(),
                        key_ptr,
                        key.len(),
                        md,
                        ptr::null_mut(),
                    )
                };
                if ok != 1 {
                    return Err(CryptoError::Internal);
                }
                Ok(state)
            }

            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                if data.is_empty() {
                    return Ok(());
                }
                let ok =
                    unsafe { bssl_sys::HMAC_Update(self.ctx.as_ptr(), data.as_ptr(), data.len()) };
                if ok != 1 {
                    return Err(CryptoError::Internal);
                }
                Ok(())
            }

            fn finalize(&mut self, out: &mut [u8; $size]) -> Result<(), CryptoError> {
                let mut out_len: core::ffi::c_uint = 0;
                let ok = unsafe {
                    bssl_sys::HMAC_Final(self.ctx.as_ptr(), out.as_mut_ptr(), &raw mut out_len)
                };
                if ok != 1 || out_len as usize != $size {
                    return Err(CryptoError::Internal);
                }
                Ok(())
            }
        }
    };
}

impl_hmac_state!(20);
impl_hmac_state!(32);
impl_hmac_state!(48);
impl_hmac_state!(64);

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
