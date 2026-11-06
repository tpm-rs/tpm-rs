//! SHA-1/SHA-256/SHA-384/SHA-512 hashes (`bssl_crypto::digest`) and HMACs (BoringSSL's
//! `HMAC_CTX`, [`crate::bssl::Hmac`]).

use crate::BsslCryptoProvider;
use tpm2::crypto::CryptoError;
use tpm2::crypto::backend::{Hash, HashState, Hmac, HmacState};

/// Defines the hash state `$name` of the `bssl_crypto` digest `$inner` with an `$n`-byte digest.
macro_rules! digest_state {
    ($(#[$m:meta])* $name:ident, $inner:ty, $n:literal) => {
        $(#[$m])*
        pub struct $name($inner);

        impl HashState<$n> for $name {
            fn init() -> Result<Self, CryptoError> {
                Ok(Self(<$inner>::new()))
            }

            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                self.0.update(data);
                Ok(())
            }

            fn finalize(&mut self, out: &mut [u8; $n]) -> Result<(), CryptoError> {
                // `digest` consumes the context: leave a fresh one behind (the state is spent).
                let ctx = core::mem::replace(&mut self.0, <$inner>::new());
                *out = ctx.digest();
                Ok(())
            }
        }
    };
}

digest_state!(
    /// SHA-1 hash state for `BsslCryptoProvider`.
    BsslSha1,
    bssl_crypto::digest::InsecureSha1,
    20
);
digest_state!(
    /// SHA-256 hash state for `BsslCryptoProvider`.
    BsslSha256,
    bssl_crypto::digest::Sha256,
    32
);
digest_state!(
    /// SHA-384 hash state for `BsslCryptoProvider`.
    BsslSha384,
    bssl_crypto::digest::Sha384,
    48
);
digest_state!(
    /// SHA-512 hash state for `BsslCryptoProvider`.
    BsslSha512,
    bssl_crypto::digest::Sha512,
    64
);

impl Hash for BsslCryptoProvider {
    type Sha1 = BsslSha1;
    type Sha256 = BsslSha256;
    type Sha384 = BsslSha384;
    type Sha512 = BsslSha512;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}

/// HMAC state for `BsslCryptoProvider` with an `N`-byte tag: HMAC-SHA-1 (20), HMAC-SHA-256
/// (32), HMAC-SHA-384 (48) or HMAC-SHA-512 (64), on BoringSSL's `HMAC_CTX`.
pub struct BsslHmac<const N: usize>(crate::bssl::Hmac<N>);

impl<const N: usize> HmacState<N> for BsslHmac<N> {
    fn init(key: &[u8]) -> Result<Self, CryptoError> {
        crate::bssl::Hmac::new_from_slice(key)
            .map(Self)
            .map_err(Into::into)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data).map_err(Into::into)
    }

    fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        self.0.finalize(out).map_err(Into::into)
    }
}

/// HMAC-SHA-1 state for `BsslCryptoProvider`.
pub type BsslHmacSha1 = BsslHmac<20>;
/// HMAC-SHA-256 state for `BsslCryptoProvider`.
pub type BsslHmacSha256 = BsslHmac<32>;
/// HMAC-SHA-384 state for `BsslCryptoProvider`.
pub type BsslHmacSha384 = BsslHmac<48>;
/// HMAC-SHA-512 state for `BsslCryptoProvider`.
pub type BsslHmacSha512 = BsslHmac<64>;

impl Hmac for BsslCryptoProvider {
    type Sha1 = BsslHmacSha1;
    type Sha256 = BsslHmacSha256;
    type Sha384 = BsslHmacSha384;
    type Sha512 = BsslHmacSha512;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}
