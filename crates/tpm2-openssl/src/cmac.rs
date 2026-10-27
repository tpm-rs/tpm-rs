use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::Cipher;
use tpm2::crypto::{
    CryptoError,
    backend::{Cmac, CmacState},
};

macro_rules! impl_cmac {
    ($name:ident, $cipher:ident, $key_size:expr) => {
        pub struct $name(Signer<'static>);

        impl CmacState<$key_size> for $name {
            fn init(key: &[u8; $key_size]) -> Result<Self, CryptoError> {
                let pkey =
                    PKey::cmac(&Cipher::$cipher(), key).map_err(|_| CryptoError::Internal)?;
                let signer =
                    Signer::new_without_digest(&pkey).map_err(|_| CryptoError::Internal)?;
                Ok(Self(signer))
            }
            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                self.0.update(data).map_err(|_| CryptoError::Internal)
            }
            fn finalize(&mut self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
                let sig = self.0.sign_to_vec().map_err(|_| CryptoError::Internal)?;
                out.copy_from_slice(&sig);
                Ok(())
            }
        }
    };
}

impl_cmac!(CmacAes128, aes_128_cbc, 16);
impl_cmac!(CmacAes192, aes_192_cbc, 24);
impl_cmac!(CmacAes256, aes_256_cbc, 32);
// SM4 and Camellia might not be supported directly by PKey::cmac with all OpenSSL versions, but
// let's try.
impl_cmac!(CmacSm4, sm4_cbc, 16);
impl_cmac!(CmacCamellia128, camellia_128_cbc, 16);
impl_cmac!(CmacCamellia192, camellia_192_cbc, 24);
impl_cmac!(CmacCamellia256, camellia_256_cbc, 32);

impl Cmac for super::OpensslBackend {
    type Aes128 = CmacAes128;
    type Aes192 = CmacAes192;
    type Aes256 = CmacAes256;
    type Sm4_128 = CmacSm4;
    type Camellia128 = CmacCamellia128;
    type Camellia192 = CmacCamellia192;
    type Camellia256 = CmacCamellia256;
}
