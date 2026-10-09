//! [`Hash`], [`Hmac`], and the streaming contexts shared with [`Cmac`](tpm2::crypto::Cmac).

use hmac::digest::{Digest, KeyInit, Mac, OutputSizeUser, typenum::Unsigned};
use tpm2::{
    TpmiAlgHash,
    crypto::{CryptoError, Finalize, Hash, HashStream, Hmac, Update},
};

use crate::RustCrypto;

/// Streaming hash context wrapping a RustCrypto [`Digest`].
#[derive(Clone)]
pub struct HashContext<D>(D);

impl<D: Digest> Update for HashContext<D> {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        Digest::update(&mut self.0, data);
        Ok(())
    }
}

impl<D: Digest, const N: usize> Finalize<N> for HashContext<D> {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        const { assert!(<<D as OutputSizeUser>::OutputSize as Unsigned>::USIZE == N) };
        out.copy_from_slice(&Digest::finalize(self.0));
        Ok(())
    }
}

/// Streaming MAC context wrapping a RustCrypto [`Mac`] (used for both HMAC and CMAC).
#[derive(Clone)]
pub struct MacContext<M>(M);

impl<M: Mac + KeyInit> MacContext<M> {
    pub(crate) fn new(key: &[u8]) -> Result<Self, CryptoError> {
        // HMAC accepts keys of any length, and CMAC keys are fixed-size arrays
        // of exactly the cipher's key length, so this should never fail.
        <M as KeyInit>::new_from_slice(key)
            .map(Self)
            .map_err(|_| CryptoError::Internal)
    }
}

impl<M: Mac> Update for MacContext<M> {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        Mac::update(&mut self.0, data);
        Ok(())
    }
}

impl<M: Mac, const N: usize> Finalize<N> for MacContext<M> {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        const { assert!(<<M as OutputSizeUser>::OutputSize as Unsigned>::USIZE == N) };
        out.copy_from_slice(&Mac::finalize(self.0).into_bytes());
        Ok(())
    }
}

impl Hash for RustCrypto {
    type Sha1Context = HashContext<sha1::Sha1>;
    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha256Context = HashContext<sha2::Sha256>;
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha384Context = HashContext<sha2::Sha384>;
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha512Context = HashContext<sha2::Sha512>;
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sm3_256Context = HashContext<sm3::Sm3>;
    fn sm3_256(&self) -> Result<Self::Sm3_256Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha3_256Context = HashContext<sha3::Sha3_256>;
    fn sha3_256(&self) -> Result<Self::Sha3_256Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha3_384Context = HashContext<sha3::Sha3_384>;
    fn sha3_384(&self) -> Result<Self::Sha3_384Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }

    type Sha3_512Context = HashContext<sha3::Sha3_512>;
    fn sha3_512(&self) -> Result<Self::Sha3_512Context, CryptoError> {
        Ok(HashContext(Digest::new()))
    }
}

impl Hmac for RustCrypto {
    type Sha1Context = MacContext<hmac::Hmac<sha1::Sha1>>;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        MacContext::new(key)
    }

    type Sha256Context = MacContext<hmac::Hmac<sha2::Sha256>>;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        MacContext::new(key)
    }

    type Sha384Context = MacContext<hmac::Hmac<sha2::Sha384>>;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        MacContext::new(key)
    }

    type Sha512Context = MacContext<hmac::Hmac<sha2::Sha512>>;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        MacContext::new(key)
    }

    type Sm3_256Context = MacContext<hmac::Hmac<sm3::Sm3>>;
    fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Context, CryptoError> {
        MacContext::new(key)
    }

    type Sha3_256Context = MacContext<hmac::Hmac<sha3::Sha3_256>>;
    fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Context, CryptoError> {
        MacContext::new(key)
    }

    type Sha3_384Context = MacContext<hmac::Hmac<sha3::Sha3_384>>;
    fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Context, CryptoError> {
        MacContext::new(key)
    }

    type Sha3_512Context = MacContext<hmac::Hmac<sha3::Sha3_512>>;
    fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Context, CryptoError> {
        MacContext::new(key)
    }
}

/// Computes the `alg` digest of the concatenation of `parts` into `out`,
/// returning the digest bytes.
pub(crate) fn hash_concat<'a>(
    alg: TpmiAlgHash,
    parts: &[&[u8]],
    out: &'a mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
) -> Result<&'a [u8], CryptoError> {
    let mut ctx = HashStream::new(&RustCrypto, alg)?;
    for part in parts {
        ctx.update(part)?;
    }
    Ok(ctx.finalize(out)?.digest())
}
