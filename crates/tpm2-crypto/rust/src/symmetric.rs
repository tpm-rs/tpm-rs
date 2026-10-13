use crate::RustCryptoProvider;
use aes::cipher::{BlockEncrypt, KeyInit};
use tpm2::crypto::{CryptoError, Direction, ModeIv, Symmetric};

/// Encrypts or decrypts `data` in place with CFB-128 (full-block cipher feedback) over the
/// 128-bit block cipher `cipher`, starting from the chaining value `iv`.
///
/// The keystream for each 16-byte block is `E_K(iv)`, where `iv` is the previous ciphertext block
/// (or the input IV for the first block), so both directions only use the cipher's encryption
/// function. The ciphertext bytes are fed back into `iv` as they are produced (encryption) or
/// consumed (decryption).
///
/// On return, `iv` holds the output chaining value (`ivOut`): if `data` ends on a block boundary,
/// it is the last ciphertext block; if the final block is partial (`n` bytes), its `n` ciphertext
/// bytes replace the first `n` bytes of the previous chaining value (`[c[..n], prev[n..]]`). Empty
/// `data` leaves `iv` unchanged.
fn cfb128<C: BlockEncrypt>(cipher: &C, iv: &mut [u8; 16], dir: Direction, data: &mut [u8]) {
    let mut keystream = [0u8; 16];
    let mut pos = 16;
    for byte in data.iter_mut() {
        if pos == 16 {
            let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(iv);
            cipher.encrypt_block(&mut block);
            keystream.copy_from_slice(&block);
            pos = 0;
        }
        match dir {
            Direction::Encrypt => {
                let c = *byte ^ keystream[pos];
                iv[pos] = c;
                *byte = c;
            }
            Direction::Decrypt => {
                let c = *byte;
                iv[pos] = c;
                *byte = c ^ keystream[pos];
            }
        }
        pos += 1;
    }
}

/// Encrypts or decrypts `data` in place with the block cipher `C` keyed with `key`.
///
/// Only the CFB mode is supported ([`cfb128`], which updates the mode's IV in place); every other
/// mode returns `Err(CryptoError::Unsupported)`.
fn cfb_only<C: BlockEncrypt + KeyInit>(
    key: &[u8],
    mode: ModeIv<'_>,
    dir: Direction,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let ModeIv::Cfb(iv) = mode else {
        return Err(CryptoError::Unsupported);
    };
    // `key` always has the cipher's key length (the `Symmetric` methods take key arrays), so this
    // cannot fail; if it did, that would be an internal error.
    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::Internal)?;
    cfb128(&cipher, iv, dir, data);
    Ok(())
}

/// AES-128, AES-192 and AES-256 in CFB mode.
///
/// The other modes (CTR, OFB, CBC and ECB) and the other block ciphers (SM4 and Camellia) are not
/// supported and return `Err(CryptoError::Unsupported)`.
impl Symmetric for RustCryptoProvider {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        cfb_only::<aes::Aes128>(key, mode, dir, data)
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        cfb_only::<aes::Aes192>(key, mode, dir, data)
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        cfb_only::<aes::Aes256>(key, mode, dir, data)
    }
}
