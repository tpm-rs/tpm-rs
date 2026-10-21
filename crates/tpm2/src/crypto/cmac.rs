//! Cryptographic CMAC traits and streaming wrappers.

use core::mem::MaybeUninit;

use super::{Active, CryptoError, Finalize, InitFrom, Symmetric, SymmetricKey, Update};
use crate::AlgSym;

/// Cryptographic CMAC interfaces for TPM implementations and clients.
///
/// This is similar to [`Hash`](super::Hash) and [`Hmac`](super::Hmac) except
/// that the context types are initialized from an already-initialized
/// [`Symmetric`] key (such as [`Symmetric::Aes128Key`]) via [`InitFrom`] and
/// always produce a 16-byte MAC.
pub trait Cmac: Symmetric {
    type Aes128Context: InitFrom<Self::Aes128Key> + Update + Finalize<16>;
    type Aes192Context: InitFrom<Self::Aes192Key> + Update + Finalize<16>;
    type Aes256Context: InitFrom<Self::Aes256Key> + Update + Finalize<16>;
    type Sm4_128Context: InitFrom<Self::Sm4_128Key> + Update + Finalize<16>;
    type Camellia128Context: InitFrom<Self::Camellia128Key> + Update + Finalize<16>;
    type Camellia192Context: InitFrom<Self::Camellia192Key> + Update + Finalize<16>;
    type Camellia256Context: InitFrom<Self::Camellia256Key> + Update + Finalize<16>;
}

/// Uninitialized stack storage for a dynamic CMAC context.
///
/// While a [`Cmac`] implementation can implement whichever algorithms it
/// wants, the variants of this enum will only exist if the corresponding
/// symmetric cipher [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum CmacSlot<C: Cmac> {
    #[cfg(feature = "aes128")]
    Aes128(MaybeUninit<C::Aes128Context>),
    #[cfg(feature = "aes192")]
    Aes192(MaybeUninit<C::Aes192Context>),
    #[cfg(feature = "aes256")]
    Aes256(MaybeUninit<C::Aes256Context>),
    #[cfg(feature = "sm4_128")]
    Sm4_128(MaybeUninit<C::Sm4_128Context>),
    #[cfg(feature = "camellia128")]
    Camellia128(MaybeUninit<C::Camellia128Context>),
    #[cfg(feature = "camellia192")]
    Camellia192(MaybeUninit<C::Camellia192Context>),
    #[cfg(feature = "camellia256")]
    Camellia256(MaybeUninit<C::Camellia256Context>),
}

impl<C: Cmac> CmacSlot<C> {
    /// Reserves an uninitialized stack slot for `alg`.
    #[inline]
    pub const fn new(alg: AlgSym) -> Self {
        match alg {
            #[cfg(feature = "aes128")]
            AlgSym::Aes128 => Self::Aes128(MaybeUninit::uninit()),
            #[cfg(feature = "aes192")]
            AlgSym::Aes192 => Self::Aes192(MaybeUninit::uninit()),
            #[cfg(feature = "aes256")]
            AlgSym::Aes256 => Self::Aes256(MaybeUninit::uninit()),
            #[cfg(feature = "sm4_128")]
            AlgSym::Sm4_128 => Self::Sm4_128(MaybeUninit::uninit()),
            #[cfg(feature = "camellia128")]
            AlgSym::Camellia128 => Self::Camellia128(MaybeUninit::uninit()),
            #[cfg(feature = "camellia192")]
            AlgSym::Camellia192 => Self::Camellia192(MaybeUninit::uninit()),
            #[cfg(feature = "camellia256")]
            AlgSym::Camellia256 => Self::Camellia256(MaybeUninit::uninit()),
        }
    }

    /// Initializes this slot with `key` and returns an active [`CmacStream`].
    #[inline]
    pub fn init(&mut self, key: &SymmetricKey<'_, C>) -> Result<CmacStream<'_, C>, CryptoError> {
        Ok(match (self, key) {
            #[cfg(feature = "aes128")]
            (Self::Aes128(slot), SymmetricKey::Aes128(key)) => {
                CmacStream::Aes128(Active::new_from(slot, key.0)?)
            }
            #[cfg(feature = "aes192")]
            (Self::Aes192(slot), SymmetricKey::Aes192(key)) => {
                CmacStream::Aes192(Active::new_from(slot, key.0)?)
            }
            #[cfg(feature = "aes256")]
            (Self::Aes256(slot), SymmetricKey::Aes256(key)) => {
                CmacStream::Aes256(Active::new_from(slot, key.0)?)
            }
            #[cfg(feature = "sm4_128")]
            (Self::Sm4_128(slot), SymmetricKey::Sm4_128(key)) => {
                CmacStream::Sm4_128(Active::new_from(slot, key.0)?)
            }
            #[cfg(feature = "camellia128")]
            (Self::Camellia128(slot), SymmetricKey::Camellia128(key)) => {
                CmacStream::Camellia128(Active::new_from(slot, key.0)?)
            }
            #[cfg(feature = "camellia192")]
            (Self::Camellia192(slot), SymmetricKey::Camellia192(key)) => {
                CmacStream::Camellia192(Active::new_from(slot, key.0)?)
            }
            #[cfg(feature = "camellia256")]
            (Self::Camellia256(slot), SymmetricKey::Camellia256(key)) => {
                CmacStream::Camellia256(Active::new_from(slot, key.0)?)
            }
            #[allow(unreachable_patterns)]
            _ => return Err(CryptoError::Internal),
        })
    }
}

/// Dynamic CMAC stream wrapping an initialized [`CmacSlot`].
pub enum CmacStream<'a, C: Cmac> {
    #[cfg(feature = "aes128")]
    Aes128(Active<'a, C::Aes128Context>),
    #[cfg(feature = "aes192")]
    Aes192(Active<'a, C::Aes192Context>),
    #[cfg(feature = "aes256")]
    Aes256(Active<'a, C::Aes256Context>),
    #[cfg(feature = "sm4_128")]
    Sm4_128(Active<'a, C::Sm4_128Context>),
    #[cfg(feature = "camellia128")]
    Camellia128(Active<'a, C::Camellia128Context>),
    #[cfg(feature = "camellia192")]
    Camellia192(Active<'a, C::Camellia192Context>),
    #[cfg(feature = "camellia256")]
    Camellia256(Active<'a, C::Camellia256Context>),
}

impl<C: Cmac> CmacStream<'_, C> {
    /// Feeds `data` into the active CMAC stream.
    #[inline]
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            #[cfg(feature = "aes128")]
            Self::Aes128(ctx) => ctx.update(data),
            #[cfg(feature = "aes192")]
            Self::Aes192(ctx) => ctx.update(data),
            #[cfg(feature = "aes256")]
            Self::Aes256(ctx) => ctx.update(data),
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128(ctx) => ctx.update(data),
            #[cfg(feature = "camellia128")]
            Self::Camellia128(ctx) => ctx.update(data),
            #[cfg(feature = "camellia192")]
            Self::Camellia192(ctx) => ctx.update(data),
            #[cfg(feature = "camellia256")]
            Self::Camellia256(ctx) => ctx.update(data),
        }
    }

    /// Finalizes the MAC into `out` and cleans up the stream.
    #[inline]
    pub fn finalize(self, out: &mut [u8]) -> Result<(), CryptoError> {
        let out: &mut [u8; 16] = out.try_into().map_err(|_| CryptoError::Internal)?;
        match self {
            #[cfg(feature = "aes128")]
            Self::Aes128(ctx) => ctx.finalize(out),
            #[cfg(feature = "aes192")]
            Self::Aes192(ctx) => ctx.finalize(out),
            #[cfg(feature = "aes256")]
            Self::Aes256(ctx) => ctx.finalize(out),
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128(ctx) => ctx.finalize(out),
            #[cfg(feature = "camellia128")]
            Self::Camellia128(ctx) => ctx.finalize(out),
            #[cfg(feature = "camellia192")]
            Self::Camellia192(ctx) => ctx.finalize(out),
            #[cfg(feature = "camellia256")]
            Self::Camellia256(ctx) => ctx.finalize(out),
        }
    }
}

/// Write a CMAC into a caller-provided buffer.
///
/// This is for one-shot CMAC calculation. [`CmacSlot`] and [`CmacStream`] allow
/// for streaming CMAC calculation.
pub fn cmac<C: Cmac>(
    key: &SymmetricKey<'_, C>,
    data: &[u8],
    out: &mut [u8; AlgSym::BLOCK_SIZE],
) -> Result<(), CryptoError> {
    let mut slot = CmacSlot::<C>::new(key.alg());
    let mut stream = slot.init(key)?;
    stream.update(data)?;
    stream.finalize(out)
}
