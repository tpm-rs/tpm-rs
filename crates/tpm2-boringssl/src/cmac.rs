//! AES-CMAC (`AES-128`, `AES-192`, `AES-256`) implementations via BoringSSL's
//! `CMAC_*` API.

use core::ptr;

use tpm2::crypto::{
    Block, CryptoError,
    backend::{Cmac, CmacState},
};

use crate::bssl_sys;
use crate::{
    BoringSsl,
    util::{Owned, check},
};

/// Streaming AES-CMAC state backed by BoringSSL `CMAC_CTX`.
pub struct BoringSslCmacState<const KEY_SIZE: usize>(Owned<bssl_sys::CMAC_CTX>);

impl<const KEY_SIZE: usize> CmacState<KEY_SIZE> for BoringSslCmacState<KEY_SIZE> {
    #[inline(never)]
    fn init(key: &[u8; KEY_SIZE]) -> Result<Self, CryptoError> {
        let cipher = unsafe {
            match KEY_SIZE {
                16 => bssl_sys::EVP_aes_128_cbc(),
                24 => bssl_sys::EVP_aes_192_cbc(),
                32 => bssl_sys::EVP_aes_256_cbc(),
                _ => return Err(CryptoError::Unsupported),
            }
        };
        let ctx = Owned::new(unsafe { bssl_sys::CMAC_CTX_new() })?;
        check(unsafe {
            bssl_sys::CMAC_Init(
                ctx.as_ptr(),
                key.as_ptr().cast(),
                KEY_SIZE,
                cipher,
                ptr::null_mut(),
            )
        })?;
        Ok(Self(ctx))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        check(unsafe { bssl_sys::CMAC_Update(self.0.as_ptr(), data.as_ptr(), data.len()) })
    }

    fn finalize(&mut self, out: &mut Block) -> Result<(), CryptoError> {
        let mut out_len: usize = 0;
        check(unsafe {
            bssl_sys::CMAC_Final(self.0.as_ptr(), out.as_mut_ptr(), &raw mut out_len)
        })?;
        if out_len != out.len() {
            return Err(CryptoError::Internal);
        }
        Ok(())
    }
}

impl Cmac for BoringSsl {
    type Aes128 = BoringSslCmacState<16>;
    type Aes192 = BoringSslCmacState<24>;
    type Aes256 = BoringSslCmacState<32>;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}
