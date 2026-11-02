use crate::BsslCryptoProvider;
use crate::bssl::{Aes128Cfb, Aes192Cfb, Aes256Cfb, AesBlock};
use tpm2::crypto::{CryptoError, Direction, ModeIv, Symmetric};
// The mode loops (and their IV chaining) are shared with the Rust backend. BoringSSL is built
// without Camellia (`OPENSSL_NO_CAMELLIA`), so Camellia falls back to the RustCrypto `camellia`
// crate (`rust_crypto_mode`).
use tpm2_crypto_rust::{BlockCipher, run_mode, rust_crypto_mode};

impl BlockCipher for AesBlock {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        AesBlock::encrypt_block(self, block);
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        AesBlock::decrypt_block(self, block);
    }
}

/// AES (BoringSSL) keyed with `key` in the mode of `mode`: CFB with BoringSSL's
/// `AES_cfb128_encrypt` (the `Aes*Cfb` bindings), the other modes with [`run_mode`] over
/// [`AesBlock`].
macro_rules! aes_mode {
    ($cfb:ty, $key:expr, $mode:expr, $dir:expr, $data:expr) => {{
        match $mode {
            ModeIv::Cfb(iv) => {
                let mut ctx = match $dir {
                    Direction::Encrypt => <$cfb>::new_encrypt($key, iv)?,
                    Direction::Decrypt => <$cfb>::new_decrypt($key, iv)?,
                };
                ctx.update($data)?;
                ctx.finalize(iv)?;
                Ok(())
            }
            mode => run_mode(&AesBlock::new($key)?, mode, $dir, $data),
        }
    }};
}

/// AES-128/192/256 (BoringSSL) and Camellia-128/192/256 (RustCrypto fallback,
/// [`rust_crypto_mode`]) in the CTR, OFB, CBC, CFB and ECB modes (see [`run_mode`] for the IV
/// chaining; CFB is `TPM_ALG_CFB`, the mode TPM 2.0 uses for parameter encryption and
/// sensitive-area protection). The other block cipher (SM4) keeps the default
/// `Err(`[`CryptoError::Unsupported`]`)`.
impl Symmetric for BsslCryptoProvider {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes_mode!(Aes128Cfb, key, mode, dir, data)
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes_mode!(Aes192Cfb, key, mode, dir, data)
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        aes_mode!(Aes256Cfb, key, mode, dir, data)
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
