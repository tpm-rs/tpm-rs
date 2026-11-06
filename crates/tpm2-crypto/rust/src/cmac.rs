//! CMAC with AES-128/192/256 and Camellia-128/192/256 (`cmac`).

use crate::RustCryptoProvider;
use tpm2::crypto::backend::{Cmac, CmacState};
use tpm2::crypto::{Block, CryptoError};

/// The streaming state of the RustCrypto MAC `M` (such as `cmac::Cmac<aes::Aes128>`), for
/// `RustCryptoProvider`.
#[derive(Clone)]
pub struct RustCryptoCmac<M>(M);

impl<M, const K: usize> CmacState<K> for RustCryptoCmac<M>
where
    M: cmac::Mac + cmac::digest::KeyInit + cmac::digest::FixedOutputReset,
{
    /// The key arrays always have the cipher's key length, so `new_from_slice` cannot fail; if
    /// it did, that would be an internal error (`CryptoError::Internal`).
    fn init(key: &[u8; K]) -> Result<Self, CryptoError> {
        <M as cmac::Mac>::new_from_slice(key)
            .map(Self)
            .map_err(|_| CryptoError::Internal)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        cmac::Mac::update(&mut self.0, data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut Block) -> Result<(), CryptoError> {
        let tag = cmac::Mac::finalize_reset(&mut self.0).into_bytes();
        if tag.len() != out.len() {
            return Err(CryptoError::Internal);
        }
        out.copy_from_slice(&tag);
        Ok(())
    }
}

/// AES-128-CMAC context for `RustCryptoProvider`.
pub type RustCryptoCmacAes128 = RustCryptoCmac<cmac::Cmac<aes::Aes128>>;
/// AES-192-CMAC context for `RustCryptoProvider`.
pub type RustCryptoCmacAes192 = RustCryptoCmac<cmac::Cmac<aes::Aes192>>;
/// AES-256-CMAC context for `RustCryptoProvider`.
pub type RustCryptoCmacAes256 = RustCryptoCmac<cmac::Cmac<aes::Aes256>>;
/// Camellia-128-CMAC context for `RustCryptoProvider`.
pub type RustCryptoCmacCamellia128 = RustCryptoCmac<cmac::Cmac<camellia::Camellia128>>;
/// Camellia-192-CMAC context for `RustCryptoProvider`.
pub type RustCryptoCmacCamellia192 = RustCryptoCmac<cmac::Cmac<camellia::Camellia192>>;
/// Camellia-256-CMAC context for `RustCryptoProvider`.
pub type RustCryptoCmacCamellia256 = RustCryptoCmac<cmac::Cmac<camellia::Camellia256>>;

impl Cmac for RustCryptoProvider {
    type Aes128 = RustCryptoCmacAes128;
    type Aes192 = RustCryptoCmacAes192;
    type Aes256 = RustCryptoCmacAes256;
    type Sm4_128 = !;
    type Camellia128 = RustCryptoCmacCamellia128;
    type Camellia192 = RustCryptoCmacCamellia192;
    type Camellia256 = RustCryptoCmacCamellia256;
}
