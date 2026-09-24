use super::{CryptoError, Finalize, Update};
use crate::{TpmiAlgHash, TpmtHa};

/// Cryptographic HMAC interfaces for TPM implementations and clients.
///
/// This is extremely similar to [`Hash`] except that the context constructors
/// (like [`Hmac::sha256`]) take in a key.
#[allow(unused_variables)]
pub trait Hmac {
    type Sha1Context: Update + Finalize<20>;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha256Context: Update + Finalize<32>;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha384Context: Update + Finalize<48>;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha512Context: Update + Finalize<64>;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sm3_256Context: Update + Finalize<32>;
    fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha3_256Context: Update + Finalize<32>;
    fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha3_384Context: Update + Finalize<48>;
    fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha3_512Context: Update + Finalize<64>;
    fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// Dynamic HMAC context wrapping algorithm-specific contexts.
///
/// This is for streaming HMAC calculation. One-shot users should use [`hmac`].
pub enum HmacStream<H: Hmac> {
    #[cfg(feature = "sha1")]
    Sha1(H::Sha1Context),
    #[cfg(feature = "sha256")]
    Sha256(H::Sha256Context),
    #[cfg(feature = "sha384")]
    Sha384(H::Sha384Context),
    #[cfg(feature = "sha512")]
    Sha512(H::Sha512Context),
    #[cfg(feature = "sm3_256")]
    Sm3_256(H::Sm3_256Context),
    #[cfg(feature = "sha3_256")]
    Sha3_256(H::Sha3_256Context),
    #[cfg(feature = "sha3_384")]
    Sha3_384(H::Sha3_384Context),
    #[cfg(feature = "sha3_512")]
    Sha3_512(H::Sha3_512Context),
}

impl<H: Hmac> HmacStream<H> {
    /// Initializes an HMAC context for `alg` using backend `h` and `key`.
    pub fn new(h: &H, alg: TpmiAlgHash, key: &[u8]) -> Result<Self, CryptoError> {
        match alg {
            #[cfg(feature = "sha1")]
            TpmiAlgHash::Sha1 => h.sha1(key).map(HmacStream::Sha1),
            #[cfg(feature = "sha256")]
            TpmiAlgHash::Sha256 => h.sha256(key).map(HmacStream::Sha256),
            #[cfg(feature = "sha384")]
            TpmiAlgHash::Sha384 => h.sha384(key).map(HmacStream::Sha384),
            #[cfg(feature = "sha512")]
            TpmiAlgHash::Sha512 => h.sha512(key).map(HmacStream::Sha512),
            #[cfg(feature = "sm3_256")]
            TpmiAlgHash::Sm3_256 => h.sm3_256(key).map(HmacStream::Sm3_256),
            #[cfg(feature = "sha3_256")]
            TpmiAlgHash::Sha3_256 => h.sha3_256(key).map(HmacStream::Sha3_256),
            #[cfg(feature = "sha3_384")]
            TpmiAlgHash::Sha3_384 => h.sha3_384(key).map(HmacStream::Sha3_384),
            #[cfg(feature = "sha3_512")]
            TpmiAlgHash::Sha3_512 => h.sha3_512(key).map(HmacStream::Sha3_512),
        }
    }

    /// Feeds `data` into the active HMAC stream.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            #[cfg(feature = "sha1")]
            HmacStream::Sha1(ctx) => ctx.update(data),
            #[cfg(feature = "sha256")]
            HmacStream::Sha256(ctx) => ctx.update(data),
            #[cfg(feature = "sha384")]
            HmacStream::Sha384(ctx) => ctx.update(data),
            #[cfg(feature = "sha512")]
            HmacStream::Sha512(ctx) => ctx.update(data),
            #[cfg(feature = "sm3_256")]
            HmacStream::Sm3_256(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_256")]
            HmacStream::Sha3_256(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_384")]
            HmacStream::Sha3_384(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_512")]
            HmacStream::Sha3_512(ctx) => ctx.update(data),
        }
    }

    /// Finalizes the MAC into `out` and returns the tagged [`TpmtHa`].
    pub fn finalize<'a>(
        self,
        out: &'a mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
    ) -> Result<TpmtHa<'a>, CryptoError> {
        /// Helper function for handling finalizing into the output buffer.
        fn helper<'a, const N: usize>(
            ctx: impl Finalize<N>,
            out: &'a mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
        ) -> Result<&'a [u8; N], CryptoError> {
            const { assert!(N <= TpmiAlgHash::MAX_DIGEST_BYTES) };
            let digest: &'a mut [u8; N] = out.first_chunk_mut().unwrap();
            ctx.finalize(digest)?;
            Ok(digest)
        }

        match self {
            #[cfg(feature = "sha1")]
            HmacStream::Sha1(ctx) => helper(ctx, out).map(TpmtHa::Sha1),
            #[cfg(feature = "sha256")]
            HmacStream::Sha256(ctx) => helper(ctx, out).map(TpmtHa::Sha256),
            #[cfg(feature = "sha384")]
            HmacStream::Sha384(ctx) => helper(ctx, out).map(TpmtHa::Sha384),
            #[cfg(feature = "sha512")]
            HmacStream::Sha512(ctx) => helper(ctx, out).map(TpmtHa::Sha512),
            #[cfg(feature = "sm3_256")]
            HmacStream::Sm3_256(ctx) => helper(ctx, out).map(TpmtHa::Sm3_256),
            #[cfg(feature = "sha3_256")]
            HmacStream::Sha3_256(ctx) => helper(ctx, out).map(TpmtHa::Sha3_256),
            #[cfg(feature = "sha3_384")]
            HmacStream::Sha3_384(ctx) => helper(ctx, out).map(TpmtHa::Sha3_384),
            #[cfg(feature = "sha3_512")]
            HmacStream::Sha3_512(ctx) => helper(ctx, out).map(TpmtHa::Sha3_512),
        }
    }
}

/// Write a MAC into a caller-provided buffer.
///
/// This is for one-shot HMAC calculation. [`HmacStream`] allows for streaming
/// HMAC calculation.
pub fn hmac<'a>(
    h: &impl Hmac,
    alg: TpmiAlgHash,
    key: &[u8],
    data: &[u8],
    out: &'a mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
) -> Result<TpmtHa<'a>, CryptoError> {
    let mut ctx = HmacStream::new(h, alg, key)?;
    ctx.update(data)?;
    ctx.finalize(out)
}
