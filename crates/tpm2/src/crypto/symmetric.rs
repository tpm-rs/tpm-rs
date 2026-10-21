//! Symmetric block ciphers, cipher modes, and key wrappers.

use core::mem::MaybeUninit;

use super::{Active, Crypt, CryptoError, InitFrom};
use crate::{AlgSym, TpmiAlgCipherMode};

/// Selects between encryption and decryption operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

/// A symmetric block cipher mode ([`TpmiAlgCipherMode`]) paired with its
/// mutable chaining value / initialization vector (`iv`).
///
/// All the variants of this enum will exist, regardless of which cipher mode
/// [crate features](crate#algorithm-feature-flags) are enabled. If such a
/// feature is disabled, the [`Symmetric`] methods will never be called with
/// the corresponding [`ModeIv`] variant.
///
/// ## Preconditions for `data`
/// - Block modes ([`ModeIv::Ecb`] and [`ModeIv::Cbc`]) require
///   `data.len()` to be a multiple of [`AlgSym::BLOCK_SIZE`] (`16`).
/// - Stream modes ([`ModeIv::Ctr`], [`ModeIv::Ofb`], and
///   [`ModeIv::Cfb`]) accept arbitrary `data` lengths.
///
/// For modes with an IV, the buffer is updated in place with the final chaining
/// value (`ivOut`) upon completion.
#[derive(PartialEq, Eq, Debug)]
pub enum ModeIv<'a> {
    Ctr(&'a mut [u8; AlgSym::BLOCK_SIZE]),
    Ofb(&'a mut [u8; AlgSym::BLOCK_SIZE]),
    Cbc(&'a mut [u8; AlgSym::BLOCK_SIZE]),
    Cfb(&'a mut [u8; AlgSym::BLOCK_SIZE]),
    Ecb,
}

impl<'a> ModeIv<'a> {
    /// Creates a [`ModeIv`] from `mode` and `iv`, returning `None` if
    /// `iv.len()` is invalid for `mode` (must be `0` for `Ecb`, and
    /// [`AlgSym::BLOCK_SIZE`] for all other modes).
    pub fn new(mode: TpmiAlgCipherMode, iv: &'a mut [u8]) -> Option<Self> {
        Some(match mode {
            #[cfg(feature = "ctr")]
            TpmiAlgCipherMode::Ctr => Self::Ctr(iv.try_into().ok()?),
            #[cfg(feature = "ofb")]
            TpmiAlgCipherMode::Ofb => Self::Ofb(iv.try_into().ok()?),
            #[cfg(feature = "cbc")]
            TpmiAlgCipherMode::Cbc => Self::Cbc(iv.try_into().ok()?),
            TpmiAlgCipherMode::Cfb => Self::Cfb(iv.try_into().ok()?),
            #[cfg(feature = "ecb")]
            TpmiAlgCipherMode::Ecb => {
                if !iv.is_empty() {
                    return None;
                }
                Self::Ecb
            }
        })
    }

    /// Returns `true` if `data_len` satisfies the block-alignment requirements of `self`.
    pub const fn is_valid_data_len(&self, data_len: usize) -> bool {
        match self {
            Self::Cbc(_) | Self::Ecb => data_len.is_multiple_of(AlgSym::BLOCK_SIZE),
            Self::Ctr(_) | Self::Ofb(_) | Self::Cfb(_) => true,
        }
    }
}

/// Cryptographic symmetric encryption and decryption interfaces for TPM
/// implementations and clients.
///
/// ## Using [`Symmetric`]
///
/// Users should generally not use [`Symmetric`]'s key types (like
/// [`Symmetric::Aes128Key`]) directly. Instead they should use
/// [`SymmetricSlot`] and [`SymmetricKey`], which allow specifying a particular
/// algorithm via [`AlgSym`].
///
/// ## Implementing [`Symmetric`]
///
/// Supported algorithms define a concrete `*Key` type and implement:
///   - [`State`](super::State) for `*Key`
///   - [`InitFrom<[u8; N]>`](InitFrom) to initialize the key state from a
///     [`MaybeUninit`] and fixed-size key array
///   - [`Crypt`] for `*Key`
///
/// Unimplemented algorithms bind their key type to [`!`], which implements
/// [`InitFrom`] to always return `Err(`[`CryptoError::Unsupported`]`)`.
pub trait Symmetric {
    type Aes128Key: InitFrom<[u8; 16]> + Crypt;
    type Aes192Key: InitFrom<[u8; 24]> + Crypt;
    type Aes256Key: InitFrom<[u8; 32]> + Crypt;
    type Sm4_128Key: InitFrom<[u8; 16]> + Crypt;
    type Camellia128Key: InitFrom<[u8; 16]> + Crypt;
    type Camellia192Key: InitFrom<[u8; 24]> + Crypt;
    type Camellia256Key: InitFrom<[u8; 32]> + Crypt;
}

/// Uninitialized stack storage for a dynamic symmetric key state.
///
/// While a [`Symmetric`] implementation can implement whichever algorithms it
/// wants, the variants of this enum will only exist if the corresponding
/// symmetric cipher [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum SymmetricSlot<S: Symmetric> {
    #[cfg(feature = "aes128")]
    Aes128(MaybeUninit<S::Aes128Key>),
    #[cfg(feature = "aes192")]
    Aes192(MaybeUninit<S::Aes192Key>),
    #[cfg(feature = "aes256")]
    Aes256(MaybeUninit<S::Aes256Key>),
    #[cfg(feature = "sm4_128")]
    Sm4_128(MaybeUninit<S::Sm4_128Key>),
    #[cfg(feature = "camellia128")]
    Camellia128(MaybeUninit<S::Camellia128Key>),
    #[cfg(feature = "camellia192")]
    Camellia192(MaybeUninit<S::Camellia192Key>),
    #[cfg(feature = "camellia256")]
    Camellia256(MaybeUninit<S::Camellia256Key>),
}

impl<S: Symmetric> SymmetricSlot<S> {
    /// Returns the symmetric algorithm for this slot.
    #[inline]
    pub const fn alg(&self) -> AlgSym {
        match self {
            #[cfg(feature = "aes128")]
            Self::Aes128(_) => AlgSym::Aes128,
            #[cfg(feature = "aes192")]
            Self::Aes192(_) => AlgSym::Aes192,
            #[cfg(feature = "aes256")]
            Self::Aes256(_) => AlgSym::Aes256,
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128(_) => AlgSym::Sm4_128,
            #[cfg(feature = "camellia128")]
            Self::Camellia128(_) => AlgSym::Camellia128,
            #[cfg(feature = "camellia192")]
            Self::Camellia192(_) => AlgSym::Camellia192,
            #[cfg(feature = "camellia256")]
            Self::Camellia256(_) => AlgSym::Camellia256,
        }
    }
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

    /// Initializes this slot with `key` and returns an active [`SymmetricKey`].
    #[inline]
    pub fn init(&mut self, key: &[u8]) -> Result<SymmetricKey<'_, S>, CryptoError> {
        /// Bridge between a fixed-size key array needed for [`InitFrom`] and a
        /// runtime-checked slice.
        fn helper<'a, K: InitFrom<[u8; N]>, const N: usize>(
            slot: &'a mut MaybeUninit<K>,
            key: &[u8],
        ) -> Result<Active<'a, K>, CryptoError> {
            let key: &[u8; N] = key.try_into().map_err(|_| CryptoError::Internal)?;
            Active::new_from(slot, key)
        }

        Ok(match self {
            #[cfg(feature = "aes128")]
            Self::Aes128(slot) => SymmetricKey::Aes128(helper(slot, key)?),
            #[cfg(feature = "aes192")]
            Self::Aes192(slot) => SymmetricKey::Aes192(helper(slot, key)?),
            #[cfg(feature = "aes256")]
            Self::Aes256(slot) => SymmetricKey::Aes256(helper(slot, key)?),
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128(slot) => SymmetricKey::Sm4_128(helper(slot, key)?),
            #[cfg(feature = "camellia128")]
            Self::Camellia128(slot) => SymmetricKey::Camellia128(helper(slot, key)?),
            #[cfg(feature = "camellia192")]
            Self::Camellia192(slot) => SymmetricKey::Camellia192(helper(slot, key)?),
            #[cfg(feature = "camellia256")]
            Self::Camellia256(slot) => SymmetricKey::Camellia256(helper(slot, key)?),
        })
    }
}

/// Dynamic symmetric key wrapping an initialized [`SymmetricSlot`].
pub enum SymmetricKey<'a, S: Symmetric> {
    #[cfg(feature = "aes128")]
    Aes128(Active<'a, S::Aes128Key>),
    #[cfg(feature = "aes192")]
    Aes192(Active<'a, S::Aes192Key>),
    #[cfg(feature = "aes256")]
    Aes256(Active<'a, S::Aes256Key>),
    #[cfg(feature = "sm4_128")]
    Sm4_128(Active<'a, S::Sm4_128Key>),
    #[cfg(feature = "camellia128")]
    Camellia128(Active<'a, S::Camellia128Key>),
    #[cfg(feature = "camellia192")]
    Camellia192(Active<'a, S::Camellia192Key>),
    #[cfg(feature = "camellia256")]
    Camellia256(Active<'a, S::Camellia256Key>),
}

impl<S: Symmetric> SymmetricKey<'_, S> {
    /// Returns the symmetric algorithm for this key.
    #[inline]
    pub const fn alg(&self) -> AlgSym {
        match self {
            #[cfg(feature = "aes128")]
            Self::Aes128(_) => AlgSym::Aes128,
            #[cfg(feature = "aes192")]
            Self::Aes192(_) => AlgSym::Aes192,
            #[cfg(feature = "aes256")]
            Self::Aes256(_) => AlgSym::Aes256,
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128(_) => AlgSym::Sm4_128,
            #[cfg(feature = "camellia128")]
            Self::Camellia128(_) => AlgSym::Camellia128,
            #[cfg(feature = "camellia192")]
            Self::Camellia192(_) => AlgSym::Camellia192,
            #[cfg(feature = "camellia256")]
            Self::Camellia256(_) => AlgSym::Camellia256,
        }
    }

    /// Encrypts or decrypts `data` in-place using `mode` (updating `mode`'s IV
    /// in-place).
    #[inline]
    pub fn crypt(
        &self,
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        match self {
            #[cfg(feature = "aes128")]
            Self::Aes128(key) => key.crypt(mode, dir, data),
            #[cfg(feature = "aes192")]
            Self::Aes192(key) => key.crypt(mode, dir, data),
            #[cfg(feature = "aes256")]
            Self::Aes256(key) => key.crypt(mode, dir, data),
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128(key) => key.crypt(mode, dir, data),
            #[cfg(feature = "camellia128")]
            Self::Camellia128(key) => key.crypt(mode, dir, data),
            #[cfg(feature = "camellia192")]
            Self::Camellia192(key) => key.crypt(mode, dir, data),
            #[cfg(feature = "camellia256")]
            Self::Camellia256(key) => key.crypt(mode, dir, data),
        }
    }

    /// Encrypts `data` in-place using `mode` (updating `mode`'s IV in-place).
    #[inline]
    pub fn encrypt(&self, mode: ModeIv<'_>, data: &mut [u8]) -> Result<(), CryptoError> {
        self.crypt(mode, Direction::Encrypt, data)
    }

    /// Decrypts `data` in-place using `mode` (updating `mode`'s IV in-place).
    #[inline]
    pub fn decrypt(&self, mode: ModeIv<'_>, data: &mut [u8]) -> Result<(), CryptoError> {
        self.crypt(mode, Direction::Decrypt, data)
    }
}
