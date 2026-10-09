//! [`Hmac`] implementation using the RustCrypto `hmac` crate.
//!
//! libcrux-hmac only provides one-shot HMAC, and [`Hmac`] needs streaming
//! contexts.

use ::hmac::Mac as _;
use tpm2::crypto::{CryptoError, Finalize, Hmac, Update};

use crate::Libcrux;

/// Defines a streaming HMAC context over a RustCrypto hash.
macro_rules! hmac_context {
    ($(#[$doc:meta])* $name:ident, $hash:ty, $len:literal) => {
        $(#[$doc])*
        pub struct $name(::hmac::Hmac<$hash>);

        impl $name {
            fn new(key: &[u8]) -> Result<Self, CryptoError> {
                // HMAC accepts keys of any length, so this can't fail.
                ::hmac::Hmac::new_from_slice(key)
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

        impl Finalize<$len> for $name {
            fn finalize(self, out: &mut [u8; $len]) -> Result<(), CryptoError> {
                out.copy_from_slice(&self.0.finalize().into_bytes());
                Ok(())
            }
        }
    };
}

hmac_context!(
    /// HMAC-SHA-1 context for [`Hmac::sha1`] (RustCrypto).
    HmacSha1,
    sha1::Sha1,
    20
);
hmac_context!(
    /// HMAC-SHA-256 context for [`Hmac::sha256`] (RustCrypto).
    HmacSha256,
    sha2::Sha256,
    32
);
hmac_context!(
    /// HMAC-SHA-384 context for [`Hmac::sha384`] (RustCrypto).
    HmacSha384,
    sha2::Sha384,
    48
);
hmac_context!(
    /// HMAC-SHA-512 context for [`Hmac::sha512`] (RustCrypto).
    HmacSha512,
    sha2::Sha512,
    64
);

impl Hmac for Libcrux {
    type Sha1Context = HmacSha1;
    fn sha1(&self, key: &[u8]) -> Result<HmacSha1, CryptoError> {
        HmacSha1::new(key)
    }

    type Sha256Context = HmacSha256;
    fn sha256(&self, key: &[u8]) -> Result<HmacSha256, CryptoError> {
        HmacSha256::new(key)
    }

    type Sha384Context = HmacSha384;
    fn sha384(&self, key: &[u8]) -> Result<HmacSha384, CryptoError> {
        HmacSha384::new(key)
    }

    type Sha512Context = HmacSha512;
    fn sha512(&self, key: &[u8]) -> Result<HmacSha512, CryptoError> {
        HmacSha512::new(key)
    }

    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}
