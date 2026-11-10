//! AES (`AES-128`, `AES-192`, `AES-256`) block cipher implementations in CTR,
//! OFB, CBC, CFB, and ECB modes, via BoringSSL's `AES_*` functions.

use core::{
    ffi::{c_int, c_uint},
    mem,
};

use tpm2::crypto::{
    Block, CryptoError, Direction,
    backend::{Symmetric, SymmetricState},
};

use crate::bssl_sys::{self, AES_KEY};
use crate::{BoringSsl, util::Secret};

/// Pre-expanded AES encryption and decryption key schedules.
pub struct BoringSslAesKey<const KEY_SIZE: usize> {
    enc_key: Secret<AES_KEY>,
    dec_key: Secret<AES_KEY>,
}

impl<const KEY_SIZE: usize> BoringSslAesKey<KEY_SIZE> {
    const fn key(&self, dir: Direction) -> (*const AES_KEY, c_int) {
        match dir {
            Direction::Encrypt => (&self.enc_key.0, bssl_sys::AES_ENCRYPT),
            Direction::Decrypt => (&self.dec_key.0, bssl_sys::AES_DECRYPT),
        }
    }
}

impl<const KEY_SIZE: usize> SymmetricState<KEY_SIZE> for BoringSslAesKey<KEY_SIZE> {
    #[inline(never)]
    fn init(key: &[u8; KEY_SIZE]) -> Result<Self, CryptoError> {
        // SAFETY: `AES_KEY` is plain data.
        let mut this: Self = unsafe { mem::zeroed() };
        let bits = (KEY_SIZE * 8) as c_uint;
        // `AES_set_*_key` return 0 on success, and fail for other key sizes.
        let ok = unsafe {
            bssl_sys::AES_set_encrypt_key(key.as_ptr(), bits, &mut this.enc_key.0) == 0
                && bssl_sys::AES_set_decrypt_key(key.as_ptr(), bits, &mut this.dec_key.0) == 0
        };
        if !ok {
            return Err(CryptoError::Unsupported);
        }
        Ok(this)
    }

    fn ctr(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        let mut ecount_buf = [0u8; 16];
        let mut num: c_uint = 0;
        unsafe {
            bssl_sys::AES_ctr128_encrypt(
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
                &self.enc_key.0,
                iv.as_mut_ptr(),
                ecount_buf.as_mut_ptr(),
                &raw mut num,
            );
        }
        Ok(())
    }

    fn ofb(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        let mut num: c_int = 0;
        unsafe {
            bssl_sys::AES_ofb128_encrypt(
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
                &self.enc_key.0,
                iv.as_mut_ptr(),
                &raw mut num,
            );
        }
        Ok(())
    }

    fn cbc(&self, dir: Direction, iv: &mut Block, data: &mut [Block]) -> Result<(), CryptoError> {
        let flat = data.as_flattened_mut();
        let (key, enc) = self.key(dir);
        unsafe {
            bssl_sys::AES_cbc_encrypt(
                flat.as_ptr(),
                flat.as_mut_ptr(),
                flat.len(),
                key,
                iv.as_mut_ptr(),
                enc,
            );
        }
        Ok(())
    }

    fn cfb(&self, dir: Direction, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        // CFB uses the encryption key schedule in both directions.
        let (_, enc) = self.key(dir);
        let mut num: c_int = 0;
        unsafe {
            bssl_sys::AES_cfb128_encrypt(
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
                &self.enc_key.0,
                iv.as_mut_ptr(),
                &raw mut num,
                enc,
            );
        }
        Ok(())
    }

    fn ecb(&self, dir: Direction, data: &mut [Block]) -> Result<(), CryptoError> {
        let (key, _) = self.key(dir);
        let crypt = match dir {
            Direction::Encrypt => bssl_sys::AES_encrypt,
            Direction::Decrypt => bssl_sys::AES_decrypt,
        };
        for block in data.iter_mut() {
            unsafe { crypt(block.as_ptr(), block.as_mut_ptr(), key) };
        }
        Ok(())
    }
}

impl Symmetric for BoringSsl {
    type Aes128 = BoringSslAesKey<16>;
    type Aes192 = BoringSslAesKey<24>;
    type Aes256 = BoringSslAesKey<32>;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}
