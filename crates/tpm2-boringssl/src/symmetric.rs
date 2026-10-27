//! AES (`AES-128`, `AES-192`, `AES-256`) block cipher implementations in CTR,
//! OFB, CBC, CFB, and ECB modes.
//!
//! Key expansion and single-block ECB encryption/decryption use BoringSSL's
//! BCM entry points (`BCM_aes_set_encrypt_key`, `BCM_aes_set_decrypt_key`,
//! `BCM_aes_encrypt`, `BCM_aes_decrypt`). Multi-block / stream modes (`CTR`,
//! `OFB`, `CBC`, `CFB`) use BoringSSL's FIPS-module `AES_*` mode functions.

use core::mem::{MaybeUninit, size_of};

use tpm2::crypto::{
    Block, CryptoError, Direction,
    backend::{Symmetric, SymmetricState},
};

use crate::{BoringSsl, bcm, bssl_sys};

/// Pre-expanded AES encryption and decryption key schedules.
pub struct BoringSslAesKey<const KEY_SIZE: usize> {
    enc_key: bssl_sys::AES_KEY,
    dec_key: bssl_sys::AES_KEY,
}

impl<const KEY_SIZE: usize> Drop for BoringSslAesKey<KEY_SIZE> {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::OPENSSL_cleanse(
                (&raw mut self.enc_key).cast(),
                size_of::<bssl_sys::AES_KEY>(),
            );
            bssl_sys::OPENSSL_cleanse(
                (&raw mut self.dec_key).cast(),
                size_of::<bssl_sys::AES_KEY>(),
            );
        }
    }
}

macro_rules! impl_aes_key {
    ($key_size:literal) => {
        impl SymmetricState<$key_size> for BoringSslAesKey<$key_size> {
            #[inline(never)]
            fn init(key: &[u8; $key_size]) -> Result<Self, CryptoError> {
                let mut enc_key = MaybeUninit::<bssl_sys::AES_KEY>::uninit();
                let mut dec_key = MaybeUninit::<bssl_sys::AES_KEY>::uninit();
                let bits = ($key_size * 8) as core::ffi::c_uint;
                unsafe {
                    bcm::check_status(bcm::bssl_BCM_aes_set_encrypt_key(
                        key.as_ptr(),
                        bits,
                        enc_key.as_mut_ptr().cast(),
                    ))?;
                    bcm::check_status(bcm::bssl_BCM_aes_set_decrypt_key(
                        key.as_ptr(),
                        bits,
                        dec_key.as_mut_ptr().cast(),
                    ))?;
                    Ok(Self {
                        enc_key: enc_key.assume_init(),
                        dec_key: dec_key.assume_init(),
                    })
                }
            }

            fn ctr(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
                if data.is_empty() {
                    return Ok(());
                }
                let mut ecount_buf = [0u8; 16];
                let mut num: core::ffi::c_uint = 0;
                unsafe {
                    bssl_sys::AES_ctr128_encrypt(
                        data.as_ptr(),
                        data.as_mut_ptr(),
                        data.len(),
                        &raw const self.enc_key,
                        iv.as_mut_ptr(),
                        ecount_buf.as_mut_ptr(),
                        &raw mut num,
                    );
                }
                Ok(())
            }

            fn ofb(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
                if data.is_empty() {
                    return Ok(());
                }
                let mut num: core::ffi::c_int = 0;
                unsafe {
                    bssl_sys::AES_ofb128_encrypt(
                        data.as_ptr(),
                        data.as_mut_ptr(),
                        data.len(),
                        &raw const self.enc_key,
                        iv.as_mut_ptr(),
                        &raw mut num,
                    );
                }
                Ok(())
            }

            fn cbc(
                &self,
                dir: Direction,
                iv: &mut Block,
                data: &mut [Block],
            ) -> Result<(), CryptoError> {
                let flat = data.as_flattened_mut();
                if flat.is_empty() {
                    return Ok(());
                }
                let (key_ptr, enc) = match dir {
                    Direction::Encrypt => (&raw const self.enc_key, bssl_sys::AES_ENCRYPT),
                    Direction::Decrypt => (&raw const self.dec_key, bssl_sys::AES_DECRYPT),
                };
                unsafe {
                    bssl_sys::AES_cbc_encrypt(
                        flat.as_ptr(),
                        flat.as_mut_ptr(),
                        flat.len(),
                        key_ptr,
                        iv.as_mut_ptr(),
                        enc,
                    );
                }
                Ok(())
            }

            fn cfb(
                &self,
                dir: Direction,
                iv: &mut Block,
                data: &mut [u8],
            ) -> Result<(), CryptoError> {
                if data.is_empty() {
                    return Ok(());
                }
                let enc = match dir {
                    Direction::Encrypt => bssl_sys::AES_ENCRYPT,
                    Direction::Decrypt => bssl_sys::AES_DECRYPT,
                };
                let mut num: core::ffi::c_int = 0;
                unsafe {
                    bssl_sys::AES_cfb128_encrypt(
                        data.as_ptr(),
                        data.as_mut_ptr(),
                        data.len(),
                        &raw const self.enc_key,
                        iv.as_mut_ptr(),
                        &raw mut num,
                        enc,
                    );
                }
                Ok(())
            }

            fn ecb(&self, dir: Direction, data: &mut [Block]) -> Result<(), CryptoError> {
                match dir {
                    Direction::Encrypt => {
                        let key_ptr: *const bcm::AES_KEY = (&raw const self.enc_key).cast();
                        for block in data.iter_mut() {
                            unsafe {
                                bcm::bssl_BCM_aes_encrypt(
                                    block.as_ptr(),
                                    block.as_mut_ptr(),
                                    key_ptr,
                                );
                            }
                        }
                    }
                    Direction::Decrypt => {
                        let key_ptr: *const bcm::AES_KEY = (&raw const self.dec_key).cast();
                        for block in data.iter_mut() {
                            unsafe {
                                bcm::bssl_BCM_aes_decrypt(
                                    block.as_ptr(),
                                    block.as_mut_ptr(),
                                    key_ptr,
                                );
                            }
                        }
                    }
                }
                Ok(())
            }
        }
    };
}

impl_aes_key!(16);
impl_aes_key!(24);
impl_aes_key!(32);

impl Symmetric for BoringSsl {
    type Aes128 = BoringSslAesKey<16>;
    type Aes192 = BoringSslAesKey<24>;
    type Aes256 = BoringSslAesKey<32>;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}
