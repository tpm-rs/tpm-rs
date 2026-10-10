//! [`Cmac`] implementation using BoringSSL's `CMAC_CTX`.

use tpm2::crypto::{Cmac, CryptoError, Finalize, Update};

use crate::{BoringSsl, bssl};

macro_rules! cmac_context {
    ($(#[$doc:meta])* $name:ident, $inner:ty) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name($inner);

        impl Update for $name {
            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                self.0.update(data)
            }
        }

        impl Finalize<16> for $name {
            fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
                self.0.finalize(out)
            }
        }
    };
}

cmac_context!(
    /// AES-128-CMAC context for [`Cmac::aes128`].
    CmacAes128,
    bssl::CmacAes128
);
cmac_context!(
    /// AES-192-CMAC context for [`Cmac::aes192`].
    CmacAes192,
    bssl::CmacAes192
);
cmac_context!(
    /// AES-256-CMAC context for [`Cmac::aes256`].
    CmacAes256,
    bssl::CmacAes256
);

impl Cmac for BoringSsl {
    type Aes128Context = CmacAes128;
    fn aes128(&self, key: &[u8; 16]) -> Result<CmacAes128, CryptoError> {
        bssl::CmacAes128::new(key).map(CmacAes128)
    }

    type Aes192Context = CmacAes192;
    fn aes192(&self, key: &[u8; 24]) -> Result<CmacAes192, CryptoError> {
        bssl::CmacAes192::new(key).map(CmacAes192)
    }

    type Aes256Context = CmacAes256;
    fn aes256(&self, key: &[u8; 32]) -> Result<CmacAes256, CryptoError> {
        bssl::CmacAes256::new(key).map(CmacAes256)
    }

    type Sm4_128Context = !;
    type Camellia128Context = !;
    type Camellia192Context = !;
    type Camellia256Context = !;
}
