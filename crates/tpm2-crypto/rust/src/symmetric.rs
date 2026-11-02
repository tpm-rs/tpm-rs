use crate::RustCryptoProvider;
use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit};
use tpm2::crypto::{CryptoError, Direction, ModeIv, Symmetric};

/// A 128-bit block cipher keyed for both directions, the building block of [`run_mode`] (shared
/// with the other backends, which implement it for their own block ciphers).
pub trait BlockCipher {
    /// Encrypts `block` in place.
    fn encrypt_block(&self, block: &mut [u8; 16]);
    /// Decrypts `block` in place.
    fn decrypt_block(&self, block: &mut [u8; 16]);
}

/// A RustCrypto block cipher (`cipher` 0.4) with a 128-bit block, such as `aes::Aes128` or
/// `camellia::Camellia256`.
pub struct RustCryptoCipher<C>(pub C);

impl<C> BlockCipher for RustCryptoCipher<C>
where
    C: BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16>,
{
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.0.encrypt_block(GenericArray::from_mut_slice(block));
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        self.0.decrypt_block(GenericArray::from_mut_slice(block));
    }
}

/// XORs `keystream` into `data` (`data.len() <= 16`).
fn xor_into(data: &mut [u8], keystream: &[u8; 16]) {
    for (byte, k) in data.iter_mut().zip(keystream) {
        *byte ^= k;
    }
}

/// Encrypts or decrypts (`dir`) `data` in place with `cipher` in the block cipher mode of `mode`,
/// updating the mode's IV in place with the output chaining value (`ivOut`) for a following
/// call, as the TCG reference implementation (`CryptSymmetricEncrypt()` and
/// `CryptSymmetricDecrypt()`) does:
/// - CTR: every block (also a trailing partial block) uses the keystream block `E(counter)`, and
///   the counter is then incremented as a 128-bit big-endian integer (wrapping). `ivOut` is the
///   counter of the block after the last one used.
/// - OFB: every block uses the keystream block `E(previous keystream block)` (the IV for the
///   first one). `ivOut` is the last keystream block, also after a trailing partial block.
/// - CBC: `data.len()` must be a multiple of 16. `ivOut` is the last ciphertext block.
/// - CFB (CFB-128): every keystream block is `E(iv)`, and each processed byte replaces the byte
///   of `iv` at the same block position with the ciphertext byte. After whole blocks `ivOut` is
///   the last ciphertext block; after a trailing partial block of `r` bytes, its first `r` bytes
///   are that partial ciphertext and the remaining bytes those of the previous chaining value
///   (the TPM pads them with zeros instead).
/// - ECB: `data.len()` must be a multiple of 16; there is no IV.
///
/// Empty `data` leaves the IV unchanged. For CBC and ECB, a `data.len()` that is not a multiple
/// of 16 (a precondition violation, see [`ModeIv`]) returns `Err(CryptoError::Internal)` without
/// touching `data` or the IV.
pub fn run_mode(
    cipher: &impl BlockCipher,
    mode: ModeIv<'_>,
    dir: Direction,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    match mode {
        ModeIv::Ctr(counter) => {
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
        ModeIv::Ofb(iv) => {
            for chunk in data.chunks_mut(16) {
                cipher.encrypt_block(iv);
                xor_into(chunk, iv);
            }
        }
        ModeIv::Cbc(iv) => {
            let (blocks, []) = data.as_chunks_mut::<16>() else {
                return Err(CryptoError::Internal);
            };
            for block in blocks {
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
        ModeIv::Cfb(iv) => {
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
        ModeIv::Ecb => {
            let (blocks, []) = data.as_chunks_mut::<16>() else {
                return Err(CryptoError::Internal);
            };
            for block in blocks {
                match dir {
                    Direction::Encrypt => cipher.encrypt_block(block),
                    Direction::Decrypt => cipher.decrypt_block(block),
                }
            }
        }
    }
    Ok(())
}

/// Encrypts or decrypts `data` in place with the RustCrypto block cipher `C` keyed with `key`, in
/// the mode of `mode` (see [`run_mode`]).
pub fn rust_crypto_mode<C>(
    key: &[u8],
    mode: ModeIv<'_>,
    dir: Direction,
    data: &mut [u8],
) -> Result<(), CryptoError>
where
    C: BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16> + KeyInit,
{
    // `key` always has the cipher's key length (the `Symmetric` methods take key arrays), so this
    // cannot fail; if it did, that would be an internal error.
    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::Internal)?;
    run_mode(&RustCryptoCipher(cipher), mode, dir, data)
}

/// AES-128, AES-192, AES-256 and Camellia-128, Camellia-192, Camellia-256 in the CTR, OFB, CBC,
/// CFB and ECB modes (see `run_mode` for the IV chaining).
///
/// The other block cipher (SM4) is not supported and returns `Err(CryptoError::Unsupported)`.
impl Symmetric for RustCryptoProvider {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<aes::Aes128>(key, mode, dir, data)
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<aes::Aes192>(key, mode, dir, data)
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<aes::Aes256>(key, mode, dir, data)
    }

    fn camellia128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<camellia::Camellia128>(key, mode, dir, data)
    }

    fn camellia192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<camellia::Camellia192>(key, mode, dir, data)
    }

    fn camellia256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<camellia::Camellia256>(key, mode, dir, data)
    }
}
