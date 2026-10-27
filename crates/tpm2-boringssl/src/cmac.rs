//! AES-CMAC (`AES-128`, `AES-192`, `AES-256`) implementations via BoringSSL's
//! FIPS-module `CMAC_*` API.

use core::ptr::{self, NonNull};

use tpm2::crypto::{
    Block, CryptoError,
    backend::{Cmac, CmacState},
};

use crate::{BoringSsl, bssl_sys};

/// Streaming AES-CMAC state backed by BoringSSL `CMAC_CTX`.
pub struct BoringSslCmacState<const KEY_SIZE: usize> {
    ctx: NonNull<bssl_sys::CMAC_CTX>,
}

// SAFETY: `CMAC_CTX` is an independent heap-allocated state with no thread-local affinity.
unsafe impl<const KEY_SIZE: usize> Send for BoringSslCmacState<KEY_SIZE> {}
unsafe impl<const KEY_SIZE: usize> Sync for BoringSslCmacState<KEY_SIZE> {}

impl<const KEY_SIZE: usize> Drop for BoringSslCmacState<KEY_SIZE> {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::CMAC_CTX_free(self.ctx.as_ptr());
        }
    }
}

fn evp_aes_cbc<const KEY_SIZE: usize>() -> Result<*const bssl_sys::EVP_CIPHER, CryptoError> {
    let cipher = unsafe {
        match KEY_SIZE {
            16 => bssl_sys::EVP_aes_128_cbc(),
            24 => bssl_sys::EVP_aes_192_cbc(),
            32 => bssl_sys::EVP_aes_256_cbc(),
            _ => return Err(CryptoError::Unsupported),
        }
    };
    if cipher.is_null() {
        Err(CryptoError::Internal)
    } else {
        Ok(cipher)
    }
}

macro_rules! impl_cmac_state {
    ($key_size:literal) => {
        impl CmacState<$key_size> for BoringSslCmacState<$key_size> {
            #[inline(never)]
            fn init(key: &[u8; $key_size]) -> Result<Self, CryptoError> {
                let cipher = evp_aes_cbc::<$key_size>()?;
                let ctx = NonNull::new(unsafe { bssl_sys::CMAC_CTX_new() })
                    .ok_or(CryptoError::Internal)?;
                let state = Self { ctx };
                let ok = unsafe {
                    bssl_sys::CMAC_Init(
                        state.ctx.as_ptr(),
                        key.as_ptr().cast(),
                        $key_size,
                        cipher,
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
                    unsafe { bssl_sys::CMAC_Update(self.ctx.as_ptr(), data.as_ptr(), data.len()) };
                if ok != 1 {
                    return Err(CryptoError::Internal);
                }
                Ok(())
            }

            fn finalize(&mut self, out: &mut Block) -> Result<(), CryptoError> {
                let mut out_len: usize = 0;
                let ok = unsafe {
                    bssl_sys::CMAC_Final(self.ctx.as_ptr(), out.as_mut_ptr(), &raw mut out_len)
                };
                if ok != 1 || out_len != out.len() {
                    return Err(CryptoError::Internal);
                }
                Ok(())
            }
        }
    };
}

impl_cmac_state!(16);
impl_cmac_state!(24);
impl_cmac_state!(32);

impl Cmac for BoringSsl {
    type Aes128 = BoringSslCmacState<16>;
    type Aes192 = BoringSslCmacState<24>;
    type Aes256 = BoringSslCmacState<32>;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}
