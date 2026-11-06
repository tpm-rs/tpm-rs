//! CMAC: AES-128/192/256 with BoringSSL's `CMAC_CTX`; Camellia-128/192/256 with the RustCrypto
//! implementation of `tpm2-crypto-rust`.

use crate::BsslCryptoProvider;
use tpm2::crypto::backend::{Cmac, CmacState};
use tpm2::crypto::{Block, CryptoError};
use tpm2_crypto_rust::RustCryptoProvider;

/// Implements [`CmacState`] for the AES-CMAC context wrapper `$name` of the binding `$inner`
/// with a `$key`-byte key.
macro_rules! aes_cmac_state {
    ($(#[$m:meta])* $name:ident, $inner:ident, $key:literal) => {
        $(#[$m])*
        pub struct $name(crate::bssl::$inner);

        impl CmacState<$key> for $name {
            fn init(key: &[u8; $key]) -> Result<Self, CryptoError> {
                crate::bssl::$inner::new(key)
                    .map(Self)
                    .map_err(Into::into)
            }

            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                self.0.update(data).map_err(Into::into)
            }

            fn finalize(&mut self, out: &mut Block) -> Result<(), CryptoError> {
                self.0.finalize(out).map_err(Into::into)
            }
        }
    };
}

aes_cmac_state!(
    /// AES-128-CMAC context wrapper for `BsslCryptoProvider`.
    BsslCmacAes128,
    CmacAes128,
    16
);
aes_cmac_state!(
    /// AES-192-CMAC context wrapper for `BsslCryptoProvider`.
    BsslCmacAes192,
    CmacAes192,
    24
);
aes_cmac_state!(
    /// AES-256-CMAC context wrapper for `BsslCryptoProvider`.
    BsslCmacAes256,
    CmacAes256,
    32
);

/// AES-CMAC with BoringSSL. BoringSSL is built without Camellia (`OPENSSL_NO_CAMELLIA`), so
/// Camellia-CMAC falls back to the RustCrypto `cmac` and `camellia` crates (the CMAC states
/// of `tpm2-crypto-rust`). SM4 is not supported (`!`).
impl Cmac for BsslCryptoProvider {
    type Aes128 = BsslCmacAes128;
    type Aes192 = BsslCmacAes192;
    type Aes256 = BsslCmacAes256;
    type Sm4_128 = !;
    type Camellia128 = <RustCryptoProvider as Cmac>::Camellia128;
    type Camellia192 = <RustCryptoProvider as Cmac>::Camellia192;
    type Camellia256 = <RustCryptoProvider as Cmac>::Camellia256;
}
