//! Symmetric encryption and decryption.

use super::{
    CryptoError,
    backend::{Symmetric, SymmetricState},
    match_sym_alg,
};
use crate::{AlgSym, TpmiAlgCipherMode};

/// A single cipher block.
///
/// All symmetric ciphers supported by the TPM have a block size of
/// [`AlgSym::BLOCK_SIZE`] (`16`).
pub type Block = [u8; AlgSym::BLOCK_SIZE];

/// Selects between encryption and decryption operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

/// The input to a symmetric cipher operation: a cipher mode
/// ([`TpmiAlgCipherMode`]), its chaining value / initialization vector (`iv`),
/// and the `data` to be encrypted or decrypted in place.
///
/// The variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled (CFB is always
/// enabled). Block modes (CBC and ECB) take their data as whole [`Block`]s,
/// while stream modes (CTR, OFB, and CFB) accept arbitrary data lengths.
///
/// ## Chaining (`ivOut`)
///
/// After an operation, `iv` holds the chaining value (`ivOut`) to use as the
/// IV of a subsequent operation, as defined in TPM 2.0 Part 3 (Table 61,
/// "Symmetric Chaining Process") and the TPM reference implementation:
///
/// | Mode | `ivOut` |
/// |------|---------|
/// | CTR  | the next counter value: `iv` plus the number of blocks processed (a partial final block counts as a block) |
/// | OFB  | the final keystream block |
/// | CBC  | the final ciphertext block |
/// | CFB  | the final ciphertext block, zero padded if it is partial |
///
/// If `data` is empty, `iv` is unchanged.
pub enum CipherInput<'a> {
    /// Counter mode: `(iv, data)`.
    #[cfg(feature = "ctr")]
    Ctr(&'a mut Block, &'a mut [u8]),
    /// Output Feedback mode: `(iv, data)`.
    #[cfg(feature = "ofb")]
    Ofb(&'a mut Block, &'a mut [u8]),
    /// Cipher Block Chaining mode: `(iv, data)`.
    #[cfg(feature = "cbc")]
    Cbc(&'a mut Block, &'a mut [Block]),
    /// Cipher Feedback mode: `(iv, data)`.
    Cfb(&'a mut Block, &'a mut [u8]),
    /// Electronic Codebook mode: `data` (no IV).
    #[cfg(feature = "ecb")]
    Ecb(&'a mut [Block]),
}

impl<'a> CipherInput<'a> {
    /// Creates a [`CipherInput`] from `mode`, `iv`, and `data`.
    ///
    /// Returns `None` if:
    /// - `iv.len()` is invalid for `mode` (it must be `0` for ECB, and
    ///   [`AlgSym::BLOCK_SIZE`] for all other modes), or
    /// - `mode` is a block mode (CBC or ECB) and `data.len()` is not a
    ///   multiple of [`AlgSym::BLOCK_SIZE`].
    pub fn new(mode: TpmiAlgCipherMode, iv: &'a mut [u8], data: &'a mut [u8]) -> Option<Self> {
        Some(match mode {
            #[cfg(feature = "ctr")]
            TpmiAlgCipherMode::Ctr => Self::Ctr(iv.try_into().ok()?, data),
            #[cfg(feature = "ofb")]
            TpmiAlgCipherMode::Ofb => Self::Ofb(iv.try_into().ok()?, data),
            #[cfg(feature = "cbc")]
            TpmiAlgCipherMode::Cbc => Self::Cbc(iv.try_into().ok()?, as_blocks(data)?),
            TpmiAlgCipherMode::Cfb => Self::Cfb(iv.try_into().ok()?, data),
            #[cfg(feature = "ecb")]
            TpmiAlgCipherMode::Ecb => {
                if !iv.is_empty() {
                    return None;
                }
                Self::Ecb(as_blocks(data)?)
            }
        })
    }

    /// Returns the cipher mode of this input.
    pub const fn mode(&self) -> TpmiAlgCipherMode {
        match self {
            #[cfg(feature = "ctr")]
            Self::Ctr(..) => TpmiAlgCipherMode::Ctr,
            #[cfg(feature = "ofb")]
            Self::Ofb(..) => TpmiAlgCipherMode::Ofb,
            #[cfg(feature = "cbc")]
            Self::Cbc(..) => TpmiAlgCipherMode::Cbc,
            Self::Cfb(..) => TpmiAlgCipherMode::Cfb,
            #[cfg(feature = "ecb")]
            Self::Ecb(..) => TpmiAlgCipherMode::Ecb,
        }
    }
}

/// Splits `data` into whole blocks, or returns `None` if it isn't block-aligned.
#[cfg(any(feature = "cbc", feature = "ecb"))]
fn as_blocks(data: &mut [u8]) -> Option<&mut [Block]> {
    let (blocks, tail) = data.as_chunks_mut();
    tail.is_empty().then_some(blocks)
}

/// Symmetric key state for a runtime-selected cipher algorithm.
///
/// Use [`SymmetricKey::crypt`] instead if the key is only used once.
///
/// While a [`Symmetric`] implementation can implement whichever algorithms it
/// wants, the variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum SymmetricContext<S: Symmetric> {
    #[cfg(feature = "aes128")]
    Aes128(S::Aes128),
    #[cfg(feature = "aes192")]
    Aes192(S::Aes192),
    #[cfg(feature = "aes256")]
    Aes256(S::Aes256),
    #[cfg(feature = "sm4_128")]
    Sm4_128(S::Sm4_128),
    #[cfg(feature = "camellia128")]
    Camellia128(S::Camellia128),
    #[cfg(feature = "camellia192")]
    Camellia192(S::Camellia192),
    #[cfg(feature = "camellia256")]
    Camellia256(S::Camellia256),
}

impl<S: Symmetric> SymmetricContext<S> {
    /// Initializes a new [`SymmetricContext`] from `key`.
    // Inlining this reduces peak stack usage (see "Dispatch design notes" in
    // the backend module docs).
    #[inline]
    pub fn new(key: SymmetricKey<'_>) -> Result<Self, CryptoError> {
        match_sym_alg!(match key {
            SymmetricKey::$Alg(k) => { Ok(Self::$Alg(SymmetricState::init(k)?)) },
        })
    }

    /// Returns the cipher algorithm of this context.
    pub const fn alg(&self) -> AlgSym {
        match_sym_alg!(match self {
            Self::$Alg(_) => { AlgSym::$Alg },
        })
    }

    /// Encrypts or decrypts `input` in place, updating its IV (see
    /// [`CipherInput`]).
    pub fn crypt(&self, dir: Direction, input: CipherInput<'_>) -> Result<(), CryptoError> {
        match_sym_alg!(match self {
            Self::$Alg(state) => { state.crypt(dir, input) },
        })
    }
}

/// Raw key bytes for a symmetric cipher algorithm, with the correct length for
/// that algorithm.
///
/// The variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
#[derive(Clone, Copy)]
pub enum SymmetricKey<'a> {
    #[cfg(feature = "aes128")]
    Aes128(&'a [u8; 16]),
    #[cfg(feature = "aes192")]
    Aes192(&'a [u8; 24]),
    #[cfg(feature = "aes256")]
    Aes256(&'a [u8; 32]),
    #[cfg(feature = "sm4_128")]
    Sm4_128(&'a [u8; 16]),
    #[cfg(feature = "camellia128")]
    Camellia128(&'a [u8; 16]),
    #[cfg(feature = "camellia192")]
    Camellia192(&'a [u8; 24]),
    #[cfg(feature = "camellia256")]
    Camellia256(&'a [u8; 32]),
}

impl<'a> SymmetricKey<'a> {
    /// Creates a [`SymmetricKey`] for `alg` from `bytes`, returning `None` if
    /// `bytes.len() != alg.key_bytes()`.
    pub fn new(alg: AlgSym, bytes: &'a [u8]) -> Option<Self> {
        Some(match_sym_alg!(match alg {
            AlgSym::$Alg => { Self::$Alg(bytes.try_into().ok()?) },
        }))
    }

    /// Returns the symmetric algorithm for this key.
    pub const fn alg(&self) -> AlgSym {
        match_sym_alg!(match self {
            Self::$Alg(_) => { AlgSym::$Alg },
        })
    }

    /// Returns the raw key bytes.
    pub const fn bytes(&self) -> &'a [u8] {
        match_sym_alg!(match (*self) {
            Self::$Alg(k) => { k.as_slice() },
        })
    }

    /// Encrypts or decrypts `input` in place with this key, updating its IV
    /// (see [`CipherInput`]).
    ///
    /// This is for keys used once. [`SymmetricContext`] allows for reusing a
    /// key.
    pub fn crypt<S: Symmetric>(
        &self,
        dir: Direction,
        input: CipherInput<'_>,
    ) -> Result<(), CryptoError> {
        match_sym_alg!(match (*self) {
            Self::$Alg(k) => { S::$Alg::crypt_once(k, dir, input) },
        })
    }
}
