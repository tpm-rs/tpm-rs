//! Block cipher modes, generic over the NID of the OpenSSL block cipher's CBC
//! mode.

use core::ffi::c_int;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl_sys as ffi;
use tpm2::crypto::{
    Block, CryptoError, Direction,
    backend::{Symmetric, SymmetricState},
};

/// The ECB, CBC, CFB-128, and OFB modes of the block cipher whose CBC mode has
/// NID `cbc`.
struct Modes {
    ecb: Cipher,
    cbc: Cipher,
    cfb: Cipher,
    ofb: Cipher,
}

impl Modes {
    fn new(cbc: c_int) -> Result<Self, CryptoError> {
        let [ecb, cbc, cfb, ofb] = match cbc {
            ffi::NID_aes_128_cbc => [
                Cipher::aes_128_ecb(),
                Cipher::aes_128_cbc(),
                Cipher::aes_128_cfb128(),
                Cipher::aes_128_ofb(),
            ],
            ffi::NID_aes_192_cbc => [
                Cipher::aes_192_ecb(),
                Cipher::aes_192_cbc(),
                Cipher::aes_192_cfb128(),
                Cipher::aes_192_ofb(),
            ],
            ffi::NID_aes_256_cbc => [
                Cipher::aes_256_ecb(),
                Cipher::aes_256_cbc(),
                Cipher::aes_256_cfb128(),
                Cipher::aes_256_ofb(),
            ],
            ffi::NID_sm4_cbc => [
                Cipher::sm4_ecb(),
                Cipher::sm4_cbc(),
                Cipher::sm4_cfb128(),
                Cipher::sm4_ofb(),
            ],
            ffi::NID_camellia_128_cbc => [
                Cipher::camellia_128_ecb(),
                Cipher::camellia_128_cbc(),
                Cipher::camellia_128_cfb128(),
                Cipher::camellia_128_ofb(),
            ],
            ffi::NID_camellia_192_cbc => [
                Cipher::camellia_192_ecb(),
                Cipher::camellia_192_cbc(),
                Cipher::camellia_192_cfb128(),
                Cipher::camellia_192_ofb(),
            ],
            ffi::NID_camellia_256_cbc => [
                Cipher::camellia_256_ecb(),
                Cipher::camellia_256_cbc(),
                Cipher::camellia_256_cfb128(),
                Cipher::camellia_256_ofb(),
            ],
            _ => return Err(CryptoError::Unsupported),
        };
        Ok(Self { ecb, cbc, cfb, ofb })
    }
}

const fn mode(dir: Direction) -> Mode {
    match dir {
        Direction::Encrypt => Mode::Encrypt,
        Direction::Decrypt => Mode::Decrypt,
    }
}

/// Runs `cipher` (without padding) over `data` in place.
fn crypt(
    cipher: Cipher,
    mode: Mode,
    key: &[u8],
    iv: Option<&[u8]>,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let internal = |_| CryptoError::Internal;
    let mut c = Crypter::new(cipher, mode, key, iv).map_err(internal)?;
    c.pad(false);
    let mut out = vec![0u8; data.len() + cipher.block_size()];
    let count = c.update(data, &mut out).map_err(internal)?;
    let rest = c.finalize(&mut out[count..]).map_err(internal)?;
    data.copy_from_slice(&out[..count + rest]);
    Ok(())
}

/// Block cipher key for the block cipher with `KEY_SIZE`-byte keys whose CBC
/// mode has NID `CBC`.
pub struct OpensslCipher<const CBC: c_int, const KEY_SIZE: usize> {
    key: [u8; KEY_SIZE],
}

impl<const CBC: c_int, const KEY_SIZE: usize> SymmetricState<KEY_SIZE>
    for OpensslCipher<CBC, KEY_SIZE>
{
    fn init(key: &[u8; KEY_SIZE]) -> Result<Self, CryptoError> {
        Modes::new(CBC)?;
        Ok(Self { key: *key })
    }

    fn ctr(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        if data.is_empty() {
            return Ok(());
        }
        let blocks = data.len().div_ceil(16);
        let mut keystream = Vec::with_capacity(blocks * 16);
        for _ in 0..blocks {
            keystream.extend_from_slice(iv);
            *iv = u128::from_be_bytes(*iv).wrapping_add(1).to_be_bytes();
        }
        crypt(
            Modes::new(CBC)?.ecb,
            Mode::Encrypt,
            &self.key,
            None,
            &mut keystream,
        )?;
        data.iter_mut().zip(keystream).for_each(|(d, k)| *d ^= k);
        Ok(())
    }

    fn ofb(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        if data.is_empty() {
            return Ok(());
        }
        let modes = Modes::new(CBC)?;
        crypt(modes.ofb, Mode::Encrypt, &self.key, Some(iv), data)?;
        // The next IV is the last output block of the block cipher.
        for _ in 0..data.len().div_ceil(16) {
            crypt(modes.ecb, Mode::Encrypt, &self.key, None, iv)?;
        }
        Ok(())
    }

    fn cbc(&self, dir: Direction, iv: &mut Block, data: &mut [Block]) -> Result<(), CryptoError> {
        let Some(&last) = data.last() else {
            return Ok(());
        };
        let flat = data.as_flattened_mut();
        crypt(Modes::new(CBC)?.cbc, mode(dir), &self.key, Some(iv), flat)?;
        // The next IV is the last ciphertext block.
        *iv = match dir {
            Direction::Encrypt => *data.last().unwrap(),
            Direction::Decrypt => last,
        };
        Ok(())
    }

    fn cfb(&self, dir: Direction, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        if data.is_empty() {
            return Ok(());
        }
        let saved_ct = (dir == Direction::Decrypt).then(|| data.to_vec());
        crypt(Modes::new(CBC)?.cfb, mode(dir), &self.key, Some(iv), data)?;
        // The next IV starts with the last (possibly partial) ciphertext block.
        let ct = saved_ct.as_deref().unwrap_or(data);
        let last_len = (ct.len() - 1) % 16 + 1;
        iv[..last_len].copy_from_slice(&ct[ct.len() - last_len..]);
        Ok(())
    }

    fn ecb(&self, dir: Direction, data: &mut [Block]) -> Result<(), CryptoError> {
        if data.is_empty() {
            return Ok(());
        }
        let flat = data.as_flattened_mut();
        crypt(Modes::new(CBC)?.ecb, mode(dir), &self.key, None, flat)
    }
}

impl Symmetric for super::OpensslBackend {
    type Aes128 = OpensslCipher<{ ffi::NID_aes_128_cbc }, 16>;
    type Aes192 = OpensslCipher<{ ffi::NID_aes_192_cbc }, 24>;
    type Aes256 = OpensslCipher<{ ffi::NID_aes_256_cbc }, 32>;
    type Sm4_128 = OpensslCipher<{ ffi::NID_sm4_cbc }, 16>;
    type Camellia128 = OpensslCipher<{ ffi::NID_camellia_128_cbc }, 16>;
    type Camellia192 = OpensslCipher<{ ffi::NID_camellia_192_cbc }, 24>;
    type Camellia256 = OpensslCipher<{ ffi::NID_camellia_256_cbc }, 32>;
}
