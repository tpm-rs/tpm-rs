//! [`Symmetric`] implementation: AES from the RustCrypto `aes` crate, with the
//! block cipher modes implemented here following the TPM reference
//! implementation (`CryptSym.c`).
//!
//! libcrux doesn't expose the raw AES block cipher.

use aes::cipher::{
    BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, consts::U16, generic_array::GenericArray,
};
use aes::{Aes128, Aes192, Aes256};
use tpm2::AlgSym;
use tpm2::crypto::{CryptoError, Direction, ModeIv, Symmetric};

use crate::Libcrux;

const BLOCK_SIZE: usize = AlgSym::BLOCK_SIZE;
type Block = [u8; BLOCK_SIZE];

/// A block cipher with a 128-bit block.
trait Cipher: BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16> {}
impl<C: BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16>> Cipher for C {}

fn encrypt_block(cipher: &impl Cipher, block: &mut Block) {
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}

fn decrypt_block(cipher: &impl Cipher, block: &mut Block) {
    cipher.decrypt_block(GenericArray::from_mut_slice(block));
}

/// XORs `keystream` into `data` (up to the shorter of the two).
fn xor(data: &mut [u8], keystream: &[u8]) {
    for (d, k) in data.iter_mut().zip(keystream) {
        *d ^= k;
    }
}

/// Encrypts or decrypts `data` in place with `cipher` in `mode`, updating
/// `mode`'s IV to the chaining value for the next call.
fn crypt(
    cipher: &impl Cipher,
    mode: ModeIv<'_>,
    dir: Direction,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    // Callers must check block mode lengths; don't panic if they don't.
    if !mode.is_valid_data_len(data.len()) {
        return Err(CryptoError::Internal);
    }
    match (mode, dir) {
        (ModeIv::Ctr(counter), _) => ctr(cipher, counter, data),
        (ModeIv::Ofb(iv), _) => ofb(cipher, iv, data),
        (ModeIv::Cbc(iv), Direction::Encrypt) => cbc_encrypt(cipher, iv, data),
        (ModeIv::Cbc(iv), Direction::Decrypt) => cbc_decrypt(cipher, iv, data),
        (ModeIv::Cfb(iv), Direction::Encrypt) => cfb_encrypt(cipher, iv, data),
        (ModeIv::Cfb(iv), Direction::Decrypt) => cfb_decrypt(cipher, iv, data),
        (ModeIv::Ecb, dir) => ecb(cipher, dir, data),
    }
    Ok(())
}

fn ctr(cipher: &impl Cipher, counter: &mut Block, data: &mut [u8]) {
    for chunk in data.chunks_mut(BLOCK_SIZE) {
        // Encrypt the current value of the counter.
        let mut keystream = *counter;
        encrypt_block(cipher, &mut keystream);
        // Increment the big-endian counter, also after a partial final block.
        *counter = u128::from_be_bytes(*counter).wrapping_add(1).to_be_bytes();
        xor(chunk, &keystream);
    }
}

fn ofb(cipher: &impl Cipher, iv: &mut Block, data: &mut [u8]) {
    for chunk in data.chunks_mut(BLOCK_SIZE) {
        // Encrypt the current value of the IV and XOR it into the data.
        encrypt_block(cipher, iv);
        xor(chunk, iv);
    }
}

fn cbc_encrypt(cipher: &impl Cipher, iv: &mut Block, data: &mut [u8]) {
    let (blocks, _) = data.as_chunks_mut::<BLOCK_SIZE>();
    for block in blocks {
        // XOR the data block into the IV, encrypt the IV into the IV and
        // then copy the IV to the output.
        xor(iv, block);
        encrypt_block(cipher, iv);
        *block = *iv;
    }
}

fn cbc_decrypt(cipher: &impl Cipher, iv: &mut Block, data: &mut [u8]) {
    let (blocks, _) = data.as_chunks_mut::<BLOCK_SIZE>();
    for block in blocks {
        // Decrypt the block, XOR in the IV, and make the ciphertext block the
        // next IV.
        let ciphertext = *block;
        decrypt_block(cipher, block);
        xor(block, iv);
        *iv = ciphertext;
    }
}

fn cfb_encrypt(cipher: &impl Cipher, iv: &mut Block, data: &mut [u8]) {
    for chunk in data.chunks_mut(BLOCK_SIZE) {
        // Encrypt the IV into the IV, then XOR the data into the IV to create
        // the ciphertext and copy it to the output.
        encrypt_block(cipher, iv);
        for (d, v) in chunk.iter_mut().zip(iv.iter_mut()) {
            *v ^= *d;
            *d = *v;
        }
        // After a partial final block, zero the rest of the IV for the next
        // call, like the TPM reference implementation.
        iv[chunk.len()..].fill(0);
    }
}

fn cfb_decrypt(cipher: &impl Cipher, iv: &mut Block, data: &mut [u8]) {
    for chunk in data.chunks_mut(BLOCK_SIZE) {
        // Encrypt the IV, copy the ciphertext to the IV and XOR the encrypted
        // IV into the output.
        let mut keystream = *iv;
        encrypt_block(cipher, &mut keystream);
        for ((d, v), k) in chunk.iter_mut().zip(iv.iter_mut()).zip(keystream) {
            *v = *d;
            *d ^= k;
        }
        // After a partial final block, zero the rest of the IV for the next
        // call, like the TPM reference implementation.
        iv[chunk.len()..].fill(0);
    }
}

fn ecb(cipher: &impl Cipher, dir: Direction, data: &mut [u8]) {
    let (blocks, _) = data.as_chunks_mut::<BLOCK_SIZE>();
    for block in blocks {
        match dir {
            Direction::Encrypt => encrypt_block(cipher, block),
            Direction::Decrypt => decrypt_block(cipher, block),
        }
    }
}

/// Creates a RustCrypto cipher from a key of the cipher's key size.
fn cipher<C: KeyInit>(key: &[u8]) -> Result<C, CryptoError> {
    C::new_from_slice(key).map_err(|_| CryptoError::Internal)
}

impl Symmetric for Libcrux {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&cipher::<Aes128>(key)?, mode, dir, data)
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&cipher::<Aes192>(key)?, mode, dir, data)
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&cipher::<Aes256>(key)?, mode, dir, data)
    }
}
