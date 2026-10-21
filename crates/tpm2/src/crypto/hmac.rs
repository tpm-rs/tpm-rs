//! Cryptographic HMAC traits and streaming wrappers.

use core::mem::MaybeUninit;

use super::{Active, CryptoError, Finalize, InitFrom, Update};
use crate::{TpmiAlgHash, TpmtHa};

/// Cryptographic HMAC interfaces for TPM implementations and clients.
///
/// This is extremely similar to [`Hash`](super::Hash) except that the context
/// types implement [`InitFrom<[u8]>`](InitFrom) to initialize with a key.
pub trait Hmac {
    type Sha1Context: InitFrom<[u8]> + Update + Finalize<20>;
    type Sha256Context: InitFrom<[u8]> + Update + Finalize<32>;
    type Sha384Context: InitFrom<[u8]> + Update + Finalize<48>;
    type Sha512Context: InitFrom<[u8]> + Update + Finalize<64>;
    type Sm3_256Context: InitFrom<[u8]> + Update + Finalize<32>;
    type Sha3_256Context: InitFrom<[u8]> + Update + Finalize<32>;
    type Sha3_384Context: InitFrom<[u8]> + Update + Finalize<48>;
    type Sha3_512Context: InitFrom<[u8]> + Update + Finalize<64>;
}

/// Uninitialized stack storage for a dynamic HMAC context.
///
/// While a [`Hmac`] implementation can implement whichever algorithms it
/// wants, the variants of this enum will only exist if the corresponding
/// hash algorithm [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum HmacSlot<H: Hmac> {
    #[cfg(feature = "sha1")]
    Sha1(MaybeUninit<H::Sha1Context>),
    #[cfg(feature = "sha256")]
    Sha256(MaybeUninit<H::Sha256Context>),
    #[cfg(feature = "sha384")]
    Sha384(MaybeUninit<H::Sha384Context>),
    #[cfg(feature = "sha512")]
    Sha512(MaybeUninit<H::Sha512Context>),
    #[cfg(feature = "sm3_256")]
    Sm3_256(MaybeUninit<H::Sm3_256Context>),
    #[cfg(feature = "sha3_256")]
    Sha3_256(MaybeUninit<H::Sha3_256Context>),
    #[cfg(feature = "sha3_384")]
    Sha3_384(MaybeUninit<H::Sha3_384Context>),
    #[cfg(feature = "sha3_512")]
    Sha3_512(MaybeUninit<H::Sha3_512Context>),
}

impl<H: Hmac> HmacSlot<H> {
    /// Reserves an uninitialized stack slot for `alg`.
    #[inline]
    pub const fn new(alg: TpmiAlgHash) -> Self {
        match alg {
            #[cfg(feature = "sha1")]
            TpmiAlgHash::Sha1 => Self::Sha1(MaybeUninit::uninit()),
            #[cfg(feature = "sha256")]
            TpmiAlgHash::Sha256 => Self::Sha256(MaybeUninit::uninit()),
            #[cfg(feature = "sha384")]
            TpmiAlgHash::Sha384 => Self::Sha384(MaybeUninit::uninit()),
            #[cfg(feature = "sha512")]
            TpmiAlgHash::Sha512 => Self::Sha512(MaybeUninit::uninit()),
            #[cfg(feature = "sm3_256")]
            TpmiAlgHash::Sm3_256 => Self::Sm3_256(MaybeUninit::uninit()),
            #[cfg(feature = "sha3_256")]
            TpmiAlgHash::Sha3_256 => Self::Sha3_256(MaybeUninit::uninit()),
            #[cfg(feature = "sha3_384")]
            TpmiAlgHash::Sha3_384 => Self::Sha3_384(MaybeUninit::uninit()),
            #[cfg(feature = "sha3_512")]
            TpmiAlgHash::Sha3_512 => Self::Sha3_512(MaybeUninit::uninit()),
        }
    }

    /// Initializes this slot with `key` and returns an active [`HmacStream`].
    #[inline]
    pub fn init(&mut self, key: &[u8]) -> Result<HmacStream<'_, H>, CryptoError> {
        Ok(match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(slot) => HmacStream::Sha1(Active::new_from(slot, key)?),
            #[cfg(feature = "sha256")]
            Self::Sha256(slot) => HmacStream::Sha256(Active::new_from(slot, key)?),
            #[cfg(feature = "sha384")]
            Self::Sha384(slot) => HmacStream::Sha384(Active::new_from(slot, key)?),
            #[cfg(feature = "sha512")]
            Self::Sha512(slot) => HmacStream::Sha512(Active::new_from(slot, key)?),
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(slot) => HmacStream::Sm3_256(Active::new_from(slot, key)?),
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(slot) => HmacStream::Sha3_256(Active::new_from(slot, key)?),
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(slot) => HmacStream::Sha3_384(Active::new_from(slot, key)?),
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(slot) => HmacStream::Sha3_512(Active::new_from(slot, key)?),
        })
    }
}

/// Dynamic HMAC stream wrapping an initialized [`HmacSlot`].
pub enum HmacStream<'a, H: Hmac> {
    #[cfg(feature = "sha1")]
    Sha1(Active<'a, H::Sha1Context>),
    #[cfg(feature = "sha256")]
    Sha256(Active<'a, H::Sha256Context>),
    #[cfg(feature = "sha384")]
    Sha384(Active<'a, H::Sha384Context>),
    #[cfg(feature = "sha512")]
    Sha512(Active<'a, H::Sha512Context>),
    #[cfg(feature = "sm3_256")]
    Sm3_256(Active<'a, H::Sm3_256Context>),
    #[cfg(feature = "sha3_256")]
    Sha3_256(Active<'a, H::Sha3_256Context>),
    #[cfg(feature = "sha3_384")]
    Sha3_384(Active<'a, H::Sha3_384Context>),
    #[cfg(feature = "sha3_512")]
    Sha3_512(Active<'a, H::Sha3_512Context>),
}

impl<H: Hmac> HmacStream<'_, H> {
    /// Feeds `data` into the active HMAC stream.
    #[inline]
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(ctx) => ctx.update(data),
            #[cfg(feature = "sha256")]
            Self::Sha256(ctx) => ctx.update(data),
            #[cfg(feature = "sha384")]
            Self::Sha384(ctx) => ctx.update(data),
            #[cfg(feature = "sha512")]
            Self::Sha512(ctx) => ctx.update(data),
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(ctx) => ctx.update(data),
        }
    }

    /// Finalizes the MAC into `out`, cleans up the stream, and returns the
    /// tagged [`TpmtHa`].
    #[inline]
    pub fn finalize<'a>(self, out: &'a mut [u8]) -> Result<TpmtHa<'a>, CryptoError> {
        /// Bridge between a digest-specific sized output buffer needed for
        /// [`Finalize`] and a runtime-checked slice.
        fn helper<'a, S: Finalize<N>, const N: usize>(
            ctx: Active<'_, S>,
            out: &'a mut [u8],
        ) -> Result<&'a [u8; N], CryptoError> {
            let digest: &'a mut [u8; N] = out.try_into().map_err(|_| CryptoError::Internal)?;
            ctx.finalize(digest)?;
            Ok(digest)
        }

        match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(ctx) => helper(ctx, out).map(TpmtHa::Sha1),
            #[cfg(feature = "sha256")]
            Self::Sha256(ctx) => helper(ctx, out).map(TpmtHa::Sha256),
            #[cfg(feature = "sha384")]
            Self::Sha384(ctx) => helper(ctx, out).map(TpmtHa::Sha384),
            #[cfg(feature = "sha512")]
            Self::Sha512(ctx) => helper(ctx, out).map(TpmtHa::Sha512),
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(ctx) => helper(ctx, out).map(TpmtHa::Sm3_256),
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(ctx) => helper(ctx, out).map(TpmtHa::Sha3_256),
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(ctx) => helper(ctx, out).map(TpmtHa::Sha3_384),
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(ctx) => helper(ctx, out).map(TpmtHa::Sha3_512),
        }
    }
}

/// Write a MAC into a caller-provided buffer.
///
/// This is for one-shot HMAC calculation. [`HmacSlot`] and [`HmacStream`] allow
/// for streaming HMAC calculation.
pub fn hmac<'a, H: Hmac>(
    alg: TpmiAlgHash,
    key: &[u8],
    data: &[u8],
    out: &'a mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
) -> Result<TpmtHa<'a>, CryptoError> {
    let mut slot = HmacSlot::<H>::new(alg);
    let mut stream = slot.init(key)?;
    stream.update(data)?;
    stream.finalize(&mut out[..alg.digest_size()])
}
