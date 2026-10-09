//! [`Symmetric`] encryption and [`Cmac`].
//!
//! The block cipher modes are implemented as in the TPM reference
//! implementation (`CryptSym.c`), including how the IV is updated.

use cipher::{BlockDecrypt, BlockEncrypt, KeyInit, consts::U16};
use tpm2::{
    AlgSym,
    crypto::{Cmac, CryptoError, Direction, ModeIv, Symmetric},
};

use crate::{MacContext, RustCrypto, xor};

const BLOCK_SIZE: usize = AlgSym::BLOCK_SIZE;

fn encrypt_block<C: BlockEncrypt<BlockSize = U16>>(cipher: &C, block: &mut [u8; BLOCK_SIZE]) {
    cipher.encrypt_block(block.into());
}

fn decrypt_block<C: BlockDecrypt<BlockSize = U16>>(cipher: &C, block: &mut [u8; BLOCK_SIZE]) {
    cipher.decrypt_block(block.into());
}

/// Splits block mode `data` into blocks, failing if it isn't block-aligned
/// (which [`ModeIv`] makes a precondition of [`Symmetric`]).
fn blocks(data: &mut [u8]) -> Result<&mut [[u8; BLOCK_SIZE]], CryptoError> {
    match data.as_chunks_mut() {
        (blocks, []) => Ok(blocks),
        _ => Err(CryptoError::Internal),
    }
}

fn crypt<C>(
    cipher: &C,
    mode: ModeIv<'_>,
    dir: Direction,
    data: &mut [u8],
) -> Result<(), CryptoError>
where
    C: BlockEncrypt<BlockSize = U16> + BlockDecrypt,
{
    match mode {
        // CTR and OFB are identical for encryption and decryption.
        ModeIv::Ctr(iv) => {
            for chunk in data.chunks_mut(BLOCK_SIZE) {
                // Encrypt the current value of the IV (counter).
                let mut pad = *iv;
                encrypt_block(cipher, &mut pad);
                // Increment the (big-endian) counter.
                *iv = u128::from_be_bytes(*iv).wrapping_add(1).to_be_bytes();
                // XOR the encrypted counter value with the data.
                xor(chunk, &pad);
            }
        }
        ModeIv::Ofb(iv) => {
            for chunk in data.chunks_mut(BLOCK_SIZE) {
                // Encrypt the current value of the IV, and XOR it into the data.
                encrypt_block(cipher, iv);
                xor(chunk, iv);
            }
        }
        ModeIv::Cfb(iv) => {
            for chunk in data.chunks_mut(BLOCK_SIZE) {
                // Encrypt the current value of the IV.
                encrypt_block(cipher, iv);
                let pairs = iv.iter_mut().zip(chunk.iter_mut());
                match dir {
                    // XOR the data into the IV to create the ciphertext,
                    // which is also the IV for the next block.
                    Direction::Encrypt => pairs.for_each(|(v, d)| {
                        *v ^= *d;
                        *d = *v;
                    }),
                    // Copy the ciphertext to the IV, and XOR the encrypted
                    // IV into the data to recover the plaintext.
                    Direction::Decrypt => pairs.for_each(|(v, d)| {
                        let c = *d;
                        *d ^= *v;
                        *v = c;
                    }),
                }
                // If the final block was partial, pad out the IV with zeros.
                iv.iter_mut().skip(chunk.len()).for_each(|v| *v = 0);
            }
        }
        ModeIv::Cbc(iv) => {
            for block in blocks(data)? {
                match dir {
                    Direction::Encrypt => {
                        // XOR the data block into the IV, encrypt the IV into
                        // the IV, and then copy the IV to the output.
                        xor(iv, block);
                        encrypt_block(cipher, iv);
                        *block = *iv;
                    }
                    Direction::Decrypt => {
                        // Decrypt the block, XOR in the IV, and make the
                        // ciphertext block the IV for the next block.
                        let ciphertext = *block;
                        decrypt_block(cipher, block);
                        xor(block, iv);
                        *iv = ciphertext;
                    }
                }
            }
        }
        ModeIv::Ecb => {
            for block in blocks(data)? {
                match dir {
                    Direction::Encrypt => encrypt_block(cipher, block),
                    Direction::Decrypt => decrypt_block(cipher, block),
                }
            }
        }
    }
    Ok(())
}

impl Symmetric for RustCrypto {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&aes::Aes128::new(key.into()), mode, dir, data)
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&aes::Aes192::new(key.into()), mode, dir, data)
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&aes::Aes256::new(key.into()), mode, dir, data)
    }

    fn sm4_128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&sm4::Sm4::new(key.into()), mode, dir, data)
    }

    fn camellia128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&camellia::Camellia128::new(key.into()), mode, dir, data)
    }

    fn camellia192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&camellia::Camellia192::new(key.into()), mode, dir, data)
    }

    fn camellia256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&camellia::Camellia256::new(key.into()), mode, dir, data)
    }
}

impl Cmac for RustCrypto {
    type Aes128Context = MacContext<cmac::Cmac<aes::Aes128>>;
    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Context, CryptoError> {
        MacContext::new(key)
    }

    type Aes192Context = MacContext<cmac::Cmac<aes::Aes192>>;
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Context, CryptoError> {
        MacContext::new(key)
    }

    type Aes256Context = MacContext<cmac::Cmac<aes::Aes256>>;
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Context, CryptoError> {
        MacContext::new(key)
    }

    type Sm4_128Context = MacContext<cmac::Cmac<sm4::Sm4>>;
    fn sm4_128(&self, key: &[u8; 16]) -> Result<Self::Sm4_128Context, CryptoError> {
        MacContext::new(key)
    }

    type Camellia128Context = MacContext<cmac::Cmac<camellia::Camellia128>>;
    fn camellia128(&self, key: &[u8; 16]) -> Result<Self::Camellia128Context, CryptoError> {
        MacContext::new(key)
    }

    type Camellia192Context = MacContext<cmac::Cmac<camellia::Camellia192>>;
    fn camellia192(&self, key: &[u8; 24]) -> Result<Self::Camellia192Context, CryptoError> {
        MacContext::new(key)
    }

    type Camellia256Context = MacContext<cmac::Cmac<camellia::Camellia256>>;
    fn camellia256(&self, key: &[u8; 32]) -> Result<Self::Camellia256Context, CryptoError> {
        MacContext::new(key)
    }
}
