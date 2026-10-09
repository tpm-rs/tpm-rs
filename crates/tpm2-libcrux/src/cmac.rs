//! [`Cmac`] implementation using the RustCrypto `cmac` and `aes` crates.
//!
//! libcrux doesn't expose the raw AES block cipher needed for CMAC.

use ::cmac::Mac as _;
use aes::{Aes128, Aes192, Aes256};
use tpm2::crypto::{Cmac, CryptoError, Finalize, Update};

use crate::Libcrux;

/// Defines a streaming CMAC context over a RustCrypto block cipher.
macro_rules! cmac_context {
    ($(#[$doc:meta])* $name:ident, $cipher:ty) => {
        $(#[$doc])*
        pub struct $name(::cmac::Cmac<$cipher>);

        impl $name {
            fn new(key: &[u8]) -> Result<Self, CryptoError> {
                // The trait passes keys of the cipher's key size, so this can't fail.
                ::cmac::Cmac::new_from_slice(key)
                    .map(Self)
                    .map_err(|_| CryptoError::Internal)
            }
        }

        impl Update for $name {
            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                self.0.update(data);
                Ok(())
            }
        }

        impl Finalize<16> for $name {
            fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
                out.copy_from_slice(&self.0.finalize().into_bytes());
                Ok(())
            }
        }
    };
}

cmac_context!(
    /// AES-128-CMAC context for [`Cmac::aes128`] (RustCrypto).
    CmacAes128,
    Aes128
);
cmac_context!(
    /// AES-192-CMAC context for [`Cmac::aes192`] (RustCrypto).
    CmacAes192,
    Aes192
);
cmac_context!(
    /// AES-256-CMAC context for [`Cmac::aes256`] (RustCrypto).
    CmacAes256,
    Aes256
);

impl Cmac for Libcrux {
    type Aes128Context = CmacAes128;
    fn aes128(&self, key: &[u8; 16]) -> Result<CmacAes128, CryptoError> {
        CmacAes128::new(key)
    }

    type Aes192Context = CmacAes192;
    fn aes192(&self, key: &[u8; 24]) -> Result<CmacAes192, CryptoError> {
        CmacAes192::new(key)
    }

    type Aes256Context = CmacAes256;
    fn aes256(&self, key: &[u8; 32]) -> Result<CmacAes256, CryptoError> {
        CmacAes256::new(key)
    }

    type Sm4_128Context = !;
    type Camellia128Context = !;
    type Camellia192Context = !;
    type Camellia256Context = !;
}
