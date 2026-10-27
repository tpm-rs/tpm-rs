use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use tpm2::crypto::{
    CryptoError,
    backend::{Hmac, HmacState},
};

macro_rules! impl_hmac {
    ($name:ident, $md:ident, $size:expr) => {
        pub struct $name(Signer<'static>);

        impl HmacState<$size> for $name {
            fn init(key: &[u8]) -> Result<Self, CryptoError> {
                let pkey = PKey::hmac(key).map_err(|_| CryptoError::Internal)?;
                let signer =
                    Signer::new(MessageDigest::$md(), &pkey).map_err(|_| CryptoError::Internal)?;
                Ok(Self(signer))
            }
            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                self.0.update(data).map_err(|_| CryptoError::Internal)
            }
            fn finalize(&mut self, out: &mut [u8; $size]) -> Result<(), CryptoError> {
                let sig = self.0.sign_to_vec().map_err(|_| CryptoError::Internal)?;
                out.copy_from_slice(&sig);
                Ok(())
            }
        }
    };
}

impl_hmac!(HmacSha1, sha1, 20);
impl_hmac!(HmacSha256, sha256, 32);
impl_hmac!(HmacSha384, sha384, 48);
impl_hmac!(HmacSha512, sha512, 64);
impl_hmac!(HmacSm3, sm3, 32);
impl_hmac!(HmacSha3_256, sha3_256, 32);
impl_hmac!(HmacSha3_384, sha3_384, 48);
impl_hmac!(HmacSha3_512, sha3_512, 64);

impl Hmac for super::OpensslBackend {
    type Sha1 = HmacSha1;
    type Sha256 = HmacSha256;
    type Sha384 = HmacSha384;
    type Sha512 = HmacSha512;
    type Sm3_256 = HmacSm3;
    type Sha3_256 = HmacSha3_256;
    type Sha3_384 = HmacSha3_384;
    type Sha3_512 = HmacSha3_512;
}
