//! [`Symmetric`] implementation: AES block cipher via BoringSSL (`AES_KEY`),
//! with the block cipher modes implemented following the TPM reference
//! implementation (`CryptSym.c`).

use tpm2::AlgSym;
use tpm2::crypto::{CryptoError, Direction, ModeIv, Symmetric};

use crate::BoringSsl;
use crate::bssl::AesCipher;

const BLOCK_SIZE: usize = AlgSym::BLOCK_SIZE;
type Block = [u8; BLOCK_SIZE];

/// XORs `keystream` into `data` (up to the shorter of the two).
fn xor(data: &mut [u8], keystream: &[u8]) {
    for (d, k) in data.iter_mut().zip(keystream) {
        *d ^= k;
    }
}

/// Encrypts or decrypts `data` in place with `cipher` in `mode`, updating
/// `mode`'s IV to the chaining value for the next call.
fn crypt(
    cipher: &AesCipher,
    mode: ModeIv<'_>,
    dir: Direction,
    data: &mut [u8],
) -> Result<(), CryptoError> {
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

fn ctr(cipher: &AesCipher, counter: &mut Block, data: &mut [u8]) {
    for chunk in data.chunks_mut(BLOCK_SIZE) {
        let mut keystream = *counter;
        cipher.encrypt_block(&mut keystream);
        *counter = u128::from_be_bytes(*counter).wrapping_add(1).to_be_bytes();
        xor(chunk, &keystream);
    }
}

fn ofb(cipher: &AesCipher, iv: &mut Block, data: &mut [u8]) {
    for chunk in data.chunks_mut(BLOCK_SIZE) {
        cipher.encrypt_block(iv);
        xor(chunk, iv);
    }
}

fn cbc_encrypt(cipher: &AesCipher, iv: &mut Block, data: &mut [u8]) {
    let (blocks, _) = data.as_chunks_mut::<BLOCK_SIZE>();
    for block in blocks {
        xor(iv, block);
        cipher.encrypt_block(iv);
        *block = *iv;
    }
}

fn cbc_decrypt(cipher: &AesCipher, iv: &mut Block, data: &mut [u8]) {
    let (blocks, _) = data.as_chunks_mut::<BLOCK_SIZE>();
    for block in blocks {
        let ciphertext = *block;
        cipher.decrypt_block(block);
        xor(block, iv);
        *iv = ciphertext;
    }
}

fn cfb_encrypt(cipher: &AesCipher, iv: &mut Block, data: &mut [u8]) {
    for chunk in data.chunks_mut(BLOCK_SIZE) {
        cipher.encrypt_block(iv);
        for (d, v) in chunk.iter_mut().zip(iv.iter_mut()) {
            *v ^= *d;
            *d = *v;
        }
        iv[chunk.len()..].fill(0);
    }
}

fn cfb_decrypt(cipher: &AesCipher, iv: &mut Block, data: &mut [u8]) {
    for chunk in data.chunks_mut(BLOCK_SIZE) {
        let mut keystream = *iv;
        cipher.encrypt_block(&mut keystream);
        for ((d, v), k) in chunk.iter_mut().zip(iv.iter_mut()).zip(keystream) {
            *v = *d;
            *d ^= k;
        }
        iv[chunk.len()..].fill(0);
    }
}

fn ecb(cipher: &AesCipher, dir: Direction, data: &mut [u8]) {
    let (blocks, _) = data.as_chunks_mut::<BLOCK_SIZE>();
    for block in blocks {
        match dir {
            Direction::Encrypt => cipher.encrypt_block(block),
            Direction::Decrypt => cipher.decrypt_block(block),
        }
    }
}

impl Symmetric for BoringSsl {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&AesCipher::new(key)?, mode, dir, data)
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&AesCipher::new(key)?, mode, dir, data)
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        crypt(&AesCipher::new(key)?, mode, dir, data)
    }
}
