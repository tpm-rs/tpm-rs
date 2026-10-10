//! [`Hash`] and [`Hmac`] implementations using BoringSSL (`bssl-crypto` and `bssl-sys`).

use tpm2::crypto::{CryptoError, Finalize, Hash, Hmac, Update};

use crate::{BoringSsl, bssl};

macro_rules! bssl_hash_context {
    ($(#[$doc:meta])* $name:ident, $inner:ty, $len:literal) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name($inner);

        impl Update for $name {
            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                self.0.update(data);
                Ok(())
            }
        }

        impl Finalize<$len> for $name {
            fn finalize(self, out: &mut [u8; $len]) -> Result<(), CryptoError> {
                *out = self.0.digest();
                Ok(())
            }
        }
    };
}

bssl_hash_context!(
    /// SHA-1 context for [`Hash::sha1`].
    Sha1,
    bssl_crypto::digest::InsecureSha1,
    20
);
bssl_hash_context!(
    /// SHA-256 context for [`Hash::sha256`].
    Sha256,
    bssl_crypto::digest::Sha256,
    32
);
bssl_hash_context!(
    /// SHA-384 context for [`Hash::sha384`].
    Sha384,
    bssl_crypto::digest::Sha384,
    48
);
bssl_hash_context!(
    /// SHA-512 context for [`Hash::sha512`].
    Sha512,
    bssl_crypto::digest::Sha512,
    64
);

impl Hash for BoringSsl {
    type Sha1Context = Sha1;
    fn sha1(&self) -> Result<Sha1, CryptoError> {
        Ok(Sha1(bssl_crypto::digest::InsecureSha1::new()))
    }

    type Sha256Context = Sha256;
    fn sha256(&self) -> Result<Sha256, CryptoError> {
        Ok(Sha256(bssl_crypto::digest::Sha256::new()))
    }

    type Sha384Context = Sha384;
    fn sha384(&self) -> Result<Sha384, CryptoError> {
        Ok(Sha384(bssl_crypto::digest::Sha384::new()))
    }

    type Sha512Context = Sha512;
    fn sha512(&self) -> Result<Sha512, CryptoError> {
        Ok(Sha512(bssl_crypto::digest::Sha512::new()))
    }

    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}

/// HMAC-SHA-1 context for [`Hmac::sha1`].
#[derive(Clone)]
pub struct HmacSha1(bssl::HmacSha1);

impl Update for HmacSha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data)
    }
}

impl Finalize<20> for HmacSha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        self.0.finalize(out)
    }
}

macro_rules! bssl_hmac_context {
    ($(#[$doc:meta])* $name:ident, $inner:ty, $len:literal) => {
        $(#[$doc])*
        pub struct $name($inner);

        impl Update for $name {
            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                self.0.update(data);
                Ok(())
            }
        }

        impl Finalize<$len> for $name {
            fn finalize(self, out: &mut [u8; $len]) -> Result<(), CryptoError> {
                *out = self.0.digest();
                Ok(())
            }
        }
    };
}

bssl_hmac_context!(
    /// HMAC-SHA-256 context for [`Hmac::sha256`].
    HmacSha256,
    bssl_crypto::hmac::HmacSha256,
    32
);
bssl_hmac_context!(
    /// HMAC-SHA-384 context for [`Hmac::sha384`].
    HmacSha384,
    bssl_crypto::hmac::HmacSha384,
    48
);
bssl_hmac_context!(
    /// HMAC-SHA-512 context for [`Hmac::sha512`].
    HmacSha512,
    bssl_crypto::hmac::HmacSha512,
    64
);

impl Hmac for BoringSsl {
    type Sha1Context = HmacSha1;
    fn sha1(&self, key: &[u8]) -> Result<HmacSha1, CryptoError> {
        bssl::HmacSha1::new_from_slice(key).map(HmacSha1)
    }

    type Sha256Context = HmacSha256;
    fn sha256(&self, key: &[u8]) -> Result<HmacSha256, CryptoError> {
        Ok(HmacSha256(bssl_crypto::hmac::HmacSha256::new_from_slice(
            key,
        )))
    }

    type Sha384Context = HmacSha384;
    fn sha384(&self, key: &[u8]) -> Result<HmacSha384, CryptoError> {
        Ok(HmacSha384(bssl_crypto::hmac::HmacSha384::new_from_slice(
            key,
        )))
    }

    type Sha512Context = HmacSha512;
    fn sha512(&self, key: &[u8]) -> Result<HmacSha512, CryptoError> {
        Ok(HmacSha512(bssl_crypto::hmac::HmacSha512::new_from_slice(
            key,
        )))
    }

    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}
