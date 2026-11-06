//! Symmetric block ciphers: AES-128/192/256 and Camellia-128/192/256 in the CTR, OFB, CBC, CFB
//! and ECB modes, and the shared block cipher mode code ([`BlockCipher`] and the mode functions
//! [`ctr`], [`ofb`], [`cbc`], [`cfb`] and [`ecb`]) that the other backends use for their own
//! block ciphers.

use crate::RustCryptoProvider;
use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit};
use tpm2::crypto::backend::{Symmetric, SymmetricState};
use tpm2::crypto::{Block, CryptoError, Direction};

/// A 128-bit block cipher keyed for both directions, the building block of the mode functions
/// of this module (shared with the other backends, which implement it for their own block
/// ciphers).
pub trait BlockCipher {
    /// Encrypts `block` in place.
    fn encrypt_block(&self, block: &mut Block);
    /// Decrypts `block` in place.
    fn decrypt_block(&self, block: &mut Block);
}

/// XORs `keystream` into `data` (`data.len() <= 16`).
fn xor_into(data: &mut [u8], keystream: &Block) {
    for (byte, k) in data.iter_mut().zip(keystream) {
        *byte ^= k;
    }
}

// The mode functions update the IV in place with the output chaining value (`ivOut`) for a
// following call, as the TCG reference implementation (`CryptSymmetricEncrypt()` and
// `CryptSymmetricDecrypt()`) does, and implement the mode methods of
// `tpm2::crypto::backend::SymmetricState`. Empty data leaves the IV unchanged.

/// CTR mode ([`SymmetricState::ctr`]): every block (also a trailing partial block) uses the
/// keystream block `E(counter)`, and the counter is then incremented as a 128-bit big-endian
/// integer (wrapping). `ivOut` is the counter of the block after the last one used.
pub fn ctr(cipher: &impl BlockCipher, counter: &mut Block, data: &mut [u8]) {
    for chunk in data.chunks_mut(16) {
        let mut keystream = *counter;
        cipher.encrypt_block(&mut keystream);
        for byte in counter.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        xor_into(chunk, &keystream);
    }
}

/// OFB mode ([`SymmetricState::ofb`]): every block uses the keystream block
/// `E(previous keystream block)` (the IV for the first one). `ivOut` is the last keystream
/// block, also after a trailing partial block.
pub fn ofb(cipher: &impl BlockCipher, iv: &mut Block, data: &mut [u8]) {
    for chunk in data.chunks_mut(16) {
        cipher.encrypt_block(iv);
        xor_into(chunk, iv);
    }
}

/// CBC mode ([`SymmetricState::cbc`]). `ivOut` is the last ciphertext block.
pub fn cbc(cipher: &impl BlockCipher, dir: Direction, iv: &mut Block, data: &mut [Block]) {
    for block in data {
        match dir {
            Direction::Encrypt => {
                xor_into(block, iv);
                cipher.encrypt_block(block);
                *iv = *block;
            }
            Direction::Decrypt => {
                let ciphertext = *block;
                cipher.decrypt_block(block);
                xor_into(block, iv);
                *iv = ciphertext;
            }
        }
    }
}

/// CFB-128 mode ([`SymmetricState::cfb`]): every keystream block is `E(iv)`, and each processed
/// byte replaces the byte of `iv` at the same block position with the ciphertext byte. After
/// whole blocks `ivOut` is the last ciphertext block; after a trailing partial block of `r`
/// bytes, its first `r` bytes are that partial ciphertext and the remaining bytes those of the
/// previous chaining value (which
/// [`default_crypt`](tpm2::crypto::backend::default_crypt) then pads with zeros).
pub fn cfb(cipher: &impl BlockCipher, dir: Direction, iv: &mut Block, data: &mut [u8]) {
    for chunk in data.chunks_mut(16) {
        let mut keystream = *iv;
        cipher.encrypt_block(&mut keystream);
        for ((byte, k), feedback) in chunk.iter_mut().zip(keystream).zip(iv.iter_mut()) {
            let input = *byte;
            *byte ^= k;
            *feedback = match dir {
                Direction::Encrypt => *byte,
                Direction::Decrypt => input,
            };
        }
    }
}

/// ECB mode ([`SymmetricState::ecb`]); there is no IV.
pub fn ecb(cipher: &impl BlockCipher, dir: Direction, data: &mut [Block]) {
    for block in data {
        match dir {
            Direction::Encrypt => cipher.encrypt_block(block),
            Direction::Decrypt => cipher.decrypt_block(block),
        }
    }
}

/// A RustCrypto block cipher (`cipher` 0.4) with a 128-bit block, such as `aes::Aes128` or
/// `camellia::Camellia256`, implementing [`BlockCipher`] and [`SymmetricState`] (with the mode
/// functions of this module).
#[derive(Clone)]
pub struct RustCryptoCipher<C>(pub C);

impl<C> BlockCipher for RustCryptoCipher<C>
where
    C: BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16>,
{
    fn encrypt_block(&self, block: &mut Block) {
        self.0.encrypt_block(GenericArray::from_mut_slice(block));
    }

    fn decrypt_block(&self, block: &mut Block) {
        self.0.decrypt_block(GenericArray::from_mut_slice(block));
    }
}

impl<C, const K: usize> SymmetricState<K> for RustCryptoCipher<C>
where
    C: BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16> + KeyInit,
{
    /// `key` always has the cipher's key length (the associated types of [`Symmetric`] fix it),
    /// so this cannot fail; if it did, that would be an internal error.
    #[inline(never)]
    fn init(key: &[u8; K]) -> Result<Self, CryptoError> {
        C::new_from_slice(key)
            .map(Self)
            .map_err(|_| CryptoError::Internal)
    }

    fn ctr(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        ctr(self, iv, data);
        Ok(())
    }

    fn ofb(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        ofb(self, iv, data);
        Ok(())
    }

    fn cbc(&self, dir: Direction, iv: &mut Block, data: &mut [Block]) -> Result<(), CryptoError> {
        cbc(self, dir, iv, data);
        Ok(())
    }

    fn cfb(&self, dir: Direction, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        cfb(self, dir, iv, data);
        Ok(())
    }

    fn ecb(&self, dir: Direction, data: &mut [Block]) -> Result<(), CryptoError> {
        ecb(self, dir, data);
        Ok(())
    }
}

/// AES-128, AES-192, AES-256 and Camellia-128, Camellia-192, Camellia-256 in the CTR, OFB, CBC,
/// CFB and ECB modes (see the mode functions for the IV chaining).
///
/// The other block cipher (SM4) is not supported (`!`).
impl Symmetric for RustCryptoProvider {
    type Aes128 = RustCryptoCipher<aes::Aes128>;
    type Aes192 = RustCryptoCipher<aes::Aes192>;
    type Aes256 = RustCryptoCipher<aes::Aes256>;
    type Sm4_128 = !;
    type Camellia128 = RustCryptoCipher<camellia::Camellia128>;
    type Camellia192 = RustCryptoCipher<camellia::Camellia192>;
    type Camellia256 = RustCryptoCipher<camellia::Camellia256>;
}
