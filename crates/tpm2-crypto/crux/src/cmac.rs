//! [`Cmac`] for [`CruxCryptoProvider`] (RustCrypto `cmac` on the `aes` and
//! `camellia` block ciphers; libcrux has neither CMAC nor Camellia).

use crate::CruxCryptoProvider;
use tpm2::crypto::backend::{Cmac, CmacState};
use tpm2::crypto::{Block, CryptoError};

/// Defines a RustCrypto `cmac` state.
///
/// The keys are fixed-size arrays of the cipher's key length, so
/// [`CmacState::init`] only fails ([`CryptoError::Internal`]) if the `cmac`
/// crate rejects a correctly sized key, which it never does.
macro_rules! rust_crypto_cmac {
    ($(#[$doc:meta])* $name:ident, $cipher:ty, $key_size:literal) => {
        $(#[$doc])*
        pub struct $name(cmac::Cmac<$cipher>);

        impl CmacState<$key_size> for $name {
            fn init(key: &[u8; $key_size]) -> Result<Self, CryptoError> {
                use cmac::Mac as _;
                cmac::Cmac::<$cipher>::new_from_slice(key)
                    .map(Self)
                    .map_err(|_| CryptoError::Internal)
            }

            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                use cmac::Mac as _;
                self.0.update(data);
                Ok(())
            }

            fn finalize(&mut self, out: &mut Block) -> Result<(), CryptoError> {
                use cmac::Mac as _;
                out.copy_from_slice(&self.0.finalize_reset().into_bytes());
                Ok(())
            }
        }
    };
}

rust_crypto_cmac!(
    /// AES-128-CMAC state for `CruxCryptoProvider`.
    CruxCmacAes128,
    aes::Aes128,
    16
);
rust_crypto_cmac!(
    /// AES-192-CMAC state for `CruxCryptoProvider`.
    CruxCmacAes192,
    aes::Aes192,
    24
);
rust_crypto_cmac!(
    /// AES-256-CMAC state for `CruxCryptoProvider`.
    CruxCmacAes256,
    aes::Aes256,
    32
);
rust_crypto_cmac!(
    /// Camellia-128-CMAC state for `CruxCryptoProvider`.
    CruxCmacCamellia128,
    camellia::Camellia128,
    16
);
rust_crypto_cmac!(
    /// Camellia-192-CMAC state for `CruxCryptoProvider`.
    CruxCmacCamellia192,
    camellia::Camellia192,
    24
);
rust_crypto_cmac!(
    /// Camellia-256-CMAC state for `CruxCryptoProvider`.
    CruxCmacCamellia256,
    camellia::Camellia256,
    32
);

impl Cmac for CruxCryptoProvider {
    type Aes128 = CruxCmacAes128;
    type Aes192 = CruxCmacAes192;
    type Aes256 = CruxCmacAes256;
    type Sm4_128 = !;
    type Camellia128 = CruxCmacCamellia128;
    type Camellia192 = CruxCmacCamellia192;
    type Camellia256 = CruxCmacCamellia256;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// NIST SP 800-38B, D.1 (AES-128) examples 1 and 2, in one shot and
    /// streamed; SM4 is unsupported.
    #[test]
    fn aes128_cmac_known_answers() {
        const KEY: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let mut tag = [0u8; 16];
        CruxCmacAes128::cmac(&KEY, &[], &mut tag).unwrap();
        assert_eq!(tag, hex!("bb1d6929e95937287fa37d129b756746"));

        let mut state = CruxCmacAes128::init(&KEY).unwrap();
        state.update(&hex!("6bc1bee22e409f96")).unwrap();
        state.update(&hex!("e93d7e117393172a")).unwrap();
        state.finalize(&mut tag).unwrap();
        assert_eq!(tag, hex!("070a16b46b4d4144f79bdd9dd04a287c"));

        assert!(matches!(
            <<CruxCryptoProvider as Cmac>::Sm4_128 as CmacState<16>>::init(&KEY),
            Err(CryptoError::Unsupported)
        ));
    }

    /// NIST SP 800-38B, D.3 (AES-256) example 1, and RFC 4493-style Camellia
    /// tags that differ from the AES ones under the same key.
    #[test]
    fn other_ciphers() {
        const KEY: [u8; 32] =
            hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let mut tag = [0u8; 16];
        CruxCmacAes256::cmac(&KEY, &[], &mut tag).unwrap();
        assert_eq!(tag, hex!("028962f61b7bf89efc6b551f4667d983"));
        let mut camellia = [0u8; 16];
        CruxCmacCamellia256::cmac(&KEY, &[], &mut camellia).unwrap();
        assert_ne!(camellia, tag);
    }
}
