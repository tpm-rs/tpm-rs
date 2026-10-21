//! Cryptographic hashing traits and streaming wrappers.

use core::mem::MaybeUninit;

use super::{Active, CryptoError, Finalize, Init, Update};
use crate::{TpmiAlgHash, TpmtHa};

/// Cryptographic hashing interfaces for TPM implementations and clients.
///
/// ## Using [`Hash`]
///
/// Users should generally not use [`Hash`]'s context types (like
/// [`Hash::Sha256Context`]) directly. Instead they should use [`HashSlot`] and
/// [`HashStream`], which allow specifying a particular algorithm via
/// [`TpmiAlgHash`].
///
/// ## Implementing [`Hash`]
///
/// Supported algorithms define a concrete `*Context` type and implement:
///   - [`State`](super::State) for `*Context`
///   - [`Init`] to initialize the context from a [`MaybeUninit`]
///   - [`Update`] for `*Context`
///   - [`Finalize<N>`] for `*Context` (where `N` is the digest length)
///
/// Unimplemented algorithms bind their context type to [`!`], which
/// implements [`Init`] to always return
/// `Err(`[`CryptoError::Unsupported`]`)`.
///
/// ### Example
///
/// ```
/// # use core::mem::MaybeUninit;
/// # use tpm2::crypto::{Active, CryptoError, Finalize, Hash, Init, State, Update};
/// # struct MyBackend;
/// # struct MySha256;
/// impl Hash for MyBackend {
///     type Sha256Context = MySha256;
///
///     // Unsupported algorithms use `!`:
///     type Sha1Context = !;
///     type Sha384Context = !;
///     type Sha512Context = !;
///     type Sm3_256Context = !;
///     type Sha3_256Context = !;
///     type Sha3_384Context = !;
///     type Sha3_512Context = !;
/// }
///
/// impl State for MySha256 {}
/// impl Init for MySha256 {
///     fn init_internal(slot: &mut MaybeUninit<Self>) -> Result<Active<'_, Self>, CryptoError> {
///         todo!()
///     }
/// }
/// impl Update for MySha256 {
///     fn update_internal(&mut self, data: &[u8]) -> Result<(), CryptoError> {
///         todo!()
///     }
/// }
/// impl Finalize<32> for MySha256 {
///     fn finalize_internal(&mut self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
///         todo!()
///     }
/// }
/// ```
pub trait Hash {
    type Sha1Context: Init + Update + Finalize<20>;
    type Sha256Context: Init + Update + Finalize<32>;
    type Sha384Context: Init + Update + Finalize<48>;
    type Sha512Context: Init + Update + Finalize<64>;
    type Sm3_256Context: Init + Update + Finalize<32>;
    type Sha3_256Context: Init + Update + Finalize<32>;
    type Sha3_384Context: Init + Update + Finalize<48>;
    type Sha3_512Context: Init + Update + Finalize<64>;
}

/// Uninitialized stack storage for a dynamic hash context.
///
/// While a [`Hash`] implementation can implement whichever algorithms it
/// wants, the variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum HashSlot<H: Hash> {
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

impl<H: Hash> HashSlot<H> {
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

    /// Initializes this slot and returns an active [`HashStream`].
    #[inline]
    pub fn init(&mut self) -> Result<HashStream<'_, H>, CryptoError> {
        Ok(match self {
            #[cfg(feature = "sha1")]
            Self::Sha1(slot) => HashStream::Sha1(Active::new(slot)?),
            #[cfg(feature = "sha256")]
            Self::Sha256(slot) => HashStream::Sha256(Active::new(slot)?),
            #[cfg(feature = "sha384")]
            Self::Sha384(slot) => HashStream::Sha384(Active::new(slot)?),
            #[cfg(feature = "sha512")]
            Self::Sha512(slot) => HashStream::Sha512(Active::new(slot)?),
            #[cfg(feature = "sm3_256")]
            Self::Sm3_256(slot) => HashStream::Sm3_256(Active::new(slot)?),
            #[cfg(feature = "sha3_256")]
            Self::Sha3_256(slot) => HashStream::Sha3_256(Active::new(slot)?),
            #[cfg(feature = "sha3_384")]
            Self::Sha3_384(slot) => HashStream::Sha3_384(Active::new(slot)?),
            #[cfg(feature = "sha3_512")]
            Self::Sha3_512(slot) => HashStream::Sha3_512(Active::new(slot)?),
        })
    }
}

/// Dynamic hash stream wrapping an initialized [`HashSlot`].
pub enum HashStream<'a, H: Hash> {
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

impl<H: Hash> HashStream<'_, H> {
    /// Feeds `data` into the active hash stream.
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

    /// Finalizes the digest into `out`, cleans up the stream, and returns the
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

/// Write a digest into a caller-provided buffer.
///
/// This is for one-shot hashing. [`HashSlot`] and [`HashStream`] allow for
/// streaming hashing.
pub fn hash<'a, H: Hash>(
    alg: TpmiAlgHash,
    data: &[u8],
    out: &'a mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
) -> Result<TpmtHa<'a>, CryptoError> {
    let mut slot = HashSlot::<H>::new(alg);
    let mut stream = slot.init()?;
    stream.update(data)?;
    stream.finalize(&mut out[..alg.digest_size()])
}

/// Compares two [`TpmtHa`] digests in constant time using [`super::ConstantTimeEq`].
pub fn digest_eq<C: super::ConstantTimeEq>(a: TpmtHa<'_>, b: TpmtHa<'_>) -> bool {
    a.hash_alg() == b.hash_alg() && C::eq(a.digest(), b.digest())
}
