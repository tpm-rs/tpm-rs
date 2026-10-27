use openssl::hash::{Hasher, MessageDigest};
use tpm2::crypto::{
    CryptoError,
    backend::{Hash, HashState},
};

macro_rules! impl_hash {
    ($name:ident, $md:ident, $size:expr) => {
        pub struct $name(Hasher);

        impl HashState<$size> for $name {
            fn init() -> Result<Self, CryptoError> {
                Hasher::new(MessageDigest::$md())
                    .map(Self)
                    .map_err(|_| CryptoError::Internal)
            }
            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                self.0.update(data).map_err(|_| CryptoError::Internal)
            }
            fn finalize(&mut self, out: &mut [u8; $size]) -> Result<(), CryptoError> {
                let digest = self.0.finish().map_err(|_| CryptoError::Internal)?;
                out.copy_from_slice(&digest);
                Ok(())
            }
        }
    };
}

impl_hash!(Sha1, sha1, 20);
impl_hash!(Sha256, sha256, 32);
impl_hash!(Sha384, sha384, 48);
impl_hash!(Sha512, sha512, 64);
impl_hash!(Sm3_256, sm3, 32);
impl_hash!(Sha3_256, sha3_256, 32);
impl_hash!(Sha3_384, sha3_384, 48);
impl_hash!(Sha3_512, sha3_512, 64);

impl Hash for super::OpensslBackend {
    type Sha1 = Sha1;
    type Sha256 = Sha256;
    type Sha384 = Sha384;
    type Sha512 = Sha512;
    type Sm3_256 = Sm3_256;
    type Sha3_256 = Sha3_256;
    type Sha3_384 = Sha3_384;
    type Sha3_512 = Sha3_512;
}
