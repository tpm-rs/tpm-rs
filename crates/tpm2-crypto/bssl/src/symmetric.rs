//! Symmetric block ciphers: AES-128/192/256 with BoringSSL's `AES_*` mode functions
//! ([`crate::bssl::Aes`]); Camellia-128/192/256 with the RustCrypto implementation of
//! `tpm2-crypto-rust`.

use crate::BsslCryptoProvider;
use crate::bssl::Aes;
use tpm2::crypto::backend::{Symmetric, SymmetricState};
use tpm2::crypto::{Block, CryptoError, Direction};
use tpm2_crypto_rust::RustCryptoProvider;

/// An AES key of `KEY` bytes (16, 24 or 32) for `BsslCryptoProvider`, in the CTR, OFB, CBC, CFB
/// and ECB modes of BoringSSL (CFB is `TPM_ALG_CFB`, the mode TPM 2.0 uses for parameter
/// encryption and sensitive-area protection).
pub struct BsslAes<const KEY: usize>(Aes);

impl<const KEY: usize> SymmetricState<KEY> for BsslAes<KEY> {
    fn init(key: &[u8; KEY]) -> Result<Self, CryptoError> {
        Aes::new(key).map(Self).map_err(Into::into)
    }

    fn ctr(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        self.0.ctr(iv, data);
        Ok(())
    }

    fn ofb(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        self.0.ofb(iv, data);
        Ok(())
    }

    fn cbc(&self, dir: Direction, iv: &mut Block, data: &mut [Block]) -> Result<(), CryptoError> {
        self.0.cbc(dir == Direction::Encrypt, iv, data);
        Ok(())
    }

    fn cfb(&self, dir: Direction, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        self.0.cfb(dir == Direction::Encrypt, iv, data);
        Ok(())
    }

    fn ecb(&self, dir: Direction, data: &mut [Block]) -> Result<(), CryptoError> {
        for block in data {
            match dir {
                Direction::Encrypt => self.0.encrypt_block(block),
                Direction::Decrypt => self.0.decrypt_block(block),
            }
        }
        Ok(())
    }
}

/// AES-128 key for `BsslCryptoProvider`.
pub type BsslAes128 = BsslAes<16>;
/// AES-192 key for `BsslCryptoProvider`.
pub type BsslAes192 = BsslAes<24>;
/// AES-256 key for `BsslCryptoProvider`.
pub type BsslAes256 = BsslAes<32>;

/// AES-128/192/256 with BoringSSL. BoringSSL is built without Camellia (`OPENSSL_NO_CAMELLIA`),
/// so Camellia-128/192/256 fall back to the RustCrypto `camellia` crate (the cipher states of
/// `tpm2-crypto-rust`). SM4 is not supported (`!`).
impl Symmetric for BsslCryptoProvider {
    type Aes128 = BsslAes128;
    type Aes192 = BsslAes192;
    type Aes256 = BsslAes256;
    type Sm4_128 = !;
    type Camellia128 = <RustCryptoProvider as Symmetric>::Camellia128;
    type Camellia192 = <RustCryptoProvider as Symmetric>::Camellia192;
    type Camellia256 = <RustCryptoProvider as Symmetric>::Camellia256;
}
