use crate::BsslCryptoProvider;
use crate::bssl::{Aes128Cfb, Aes192Cfb, Aes256Cfb};
use tpm2::crypto::{CryptoError, Direction, ModeIv, Symmetric};

/// Encrypts or decrypts `$data` in place with the AES-CFB binding `$cipher` and
/// writes the final chaining value back into the CFB IV (TPM 2.0 `ivOut`).
///
/// Only CFB is implemented; every other [`ModeIv`] returns
/// `Err(`[`CryptoError::Unsupported`]`)`.
macro_rules! aes_cfb {
    ($cipher:ty, $key:expr, $mode:expr, $dir:expr, $data:expr) => {{
        let ModeIv::Cfb(iv) = $mode else {
            return Err(CryptoError::Unsupported);
        };
        let mut ctx = match $dir {
            Direction::Encrypt => <$cipher>::new_encrypt($key, iv)?,
            Direction::Decrypt => <$cipher>::new_decrypt($key, iv)?,
        };
        ctx.update($data)?;
        ctx.finalize(iv)?;
        Ok(())
    }};
}

/// AES-128/192/256 in CFB mode (`TPM_ALG_CFB`), the symmetric mode TPM 2.0 uses
/// for parameter encryption and sensitive-area protection. Other modes and
/// ciphers keep the default `Err(`[`CryptoError::Unsupported`]`)`.
impl Symmetric for BsslCryptoProvider {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes_cfb!(Aes128Cfb, key, mode, dir, data)
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes_cfb!(Aes192Cfb, key, mode, dir, data)
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes_cfb!(Aes256Cfb, key, mode, dir, data)
    }
}
