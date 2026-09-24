use super::{CryptoError, Direction};
use crate::{AlgSym, TpmiAlgCipherMode};

/// A tagged symmetric key containing a symmetric algorithm ([`AlgSym`])
/// and its fixed-size key buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SymmetricKey<'a> {
    #[cfg(feature = "aes128")]
    Aes128(&'a [u8; AlgSym::Aes128.key_bytes()]),
    #[cfg(feature = "aes192")]
    Aes192(&'a [u8; AlgSym::Aes192.key_bytes()]),
    #[cfg(feature = "aes256")]
    Aes256(&'a [u8; AlgSym::Aes256.key_bytes()]),
    #[cfg(feature = "sm4_128")]
    Sm4_128(&'a [u8; AlgSym::Sm4_128.key_bytes()]),
    #[cfg(feature = "camellia128")]
    Camellia128(&'a [u8; AlgSym::Camellia128.key_bytes()]),
    #[cfg(feature = "camellia192")]
    Camellia192(&'a [u8; AlgSym::Camellia192.key_bytes()]),
    #[cfg(feature = "camellia256")]
    Camellia256(&'a [u8; AlgSym::Camellia256.key_bytes()]),
}

impl<'a> SymmetricKey<'a> {
    /// Creates a [`SymmetricKey`] for `alg` from `key`, returning `None` if
    /// `key.len()` does not match `alg`'s required key length.
    pub fn new(alg: AlgSym, key: &'a [u8]) -> Option<Self> {
        Some(match alg {
            #[cfg(feature = "aes128")]
            AlgSym::Aes128 => Self::Aes128(key.try_into().ok()?),
            #[cfg(feature = "aes192")]
            AlgSym::Aes192 => Self::Aes192(key.try_into().ok()?),
            #[cfg(feature = "aes256")]
            AlgSym::Aes256 => Self::Aes256(key.try_into().ok()?),
            #[cfg(feature = "sm4_128")]
            AlgSym::Sm4_128 => Self::Sm4_128(key.try_into().ok()?),
            #[cfg(feature = "camellia128")]
            AlgSym::Camellia128 => Self::Camellia128(key.try_into().ok()?),
            #[cfg(feature = "camellia192")]
            AlgSym::Camellia192 => Self::Camellia192(key.try_into().ok()?),
            #[cfg(feature = "camellia256")]
            AlgSym::Camellia256 => Self::Camellia256(key.try_into().ok()?),
        })
    }

    pub const fn alg(self) -> AlgSym {
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

    pub const fn key(self) -> &'a [u8] {
        match self {
            #[cfg(feature = "aes128")]
            Self::Aes128(k) => k,
            #[cfg(feature = "aes192")]
            Self::Aes192(k) => k,
            #[cfg(feature = "aes256")]
            Self::Aes256(k) => k,
            #[cfg(feature = "sm4_128")]
            Self::Sm4_128(k) => k,
            #[cfg(feature = "camellia128")]
            Self::Camellia128(k) => k,
            #[cfg(feature = "camellia192")]
            Self::Camellia192(k) => k,
            #[cfg(feature = "camellia256")]
            Self::Camellia256(k) => k,
        }
    }
}

/// A symmetric block cipher mode ([`TpmiAlgCipherMode`]) paired with its
/// mutable chaining value / initialization vector (`iv`).
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

/// Cryptographic symmetric encryption and decryption interfaces for TPM implementations and clients.
///
/// Users should call [`encrypt_decrypt`], [`encrypt`], or [`decrypt`] rather than invoking trait
/// methods directly.
#[allow(unused_variables)]
pub trait Symmetric {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    fn sm4_128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    fn camellia128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    fn camellia192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    fn camellia256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// Encrypts or decrypts `data` in-place using `key` and `mode` (updating `mode`'s IV in-place).
pub fn encrypt_decrypt(
    s: &impl Symmetric,
    key: SymmetricKey<'_>,
    mode: ModeIv<'_>,
    dir: Direction,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    match key {
        #[cfg(feature = "aes128")]
        SymmetricKey::Aes128(key) => s.aes128(key, mode, dir, data),
        #[cfg(feature = "aes192")]
        SymmetricKey::Aes192(key) => s.aes192(key, mode, dir, data),
        #[cfg(feature = "aes256")]
        SymmetricKey::Aes256(key) => s.aes256(key, mode, dir, data),
        #[cfg(feature = "sm4_128")]
        SymmetricKey::Sm4_128(key) => s.sm4_128(key, mode, dir, data),
        #[cfg(feature = "camellia128")]
        SymmetricKey::Camellia128(key) => s.camellia128(key, mode, dir, data),
        #[cfg(feature = "camellia192")]
        SymmetricKey::Camellia192(key) => s.camellia192(key, mode, dir, data),
        #[cfg(feature = "camellia256")]
        SymmetricKey::Camellia256(key) => s.camellia256(key, mode, dir, data),
    }
}

/// Encrypts `data` in-place using `key` and `mode` (updating `mode`'s IV in-place).
pub fn encrypt(
    s: &impl Symmetric,
    key: SymmetricKey<'_>,
    mode: ModeIv<'_>,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    encrypt_decrypt(s, key, mode, Direction::Encrypt, data)
}

/// Decrypts `data` in-place using `key` and `mode` (updating `mode`'s IV in-place).
pub fn decrypt(
    s: &impl Symmetric,
    key: SymmetricKey<'_>,
    mode: ModeIv<'_>,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    encrypt_decrypt(s, key, mode, Direction::Decrypt, data)
}
