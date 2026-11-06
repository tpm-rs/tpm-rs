//! CMAC calculation.

use super::{
    Block, CryptoError, SymmetricKey,
    backend::{Cmac, CmacState},
    match_sym_alg,
};
use crate::AlgSym;

/// Streaming CMAC context for a runtime-selected cipher algorithm.
///
/// Use [`SymmetricKey::cmac`] instead if all the data is available at once.
///
/// While a [`Cmac`] implementation can implement whichever algorithms it
/// wants, the variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum CmacContext<C: Cmac> {
    #[cfg(feature = "aes128")]
    Aes128(C::Aes128),
    #[cfg(feature = "aes192")]
    Aes192(C::Aes192),
    #[cfg(feature = "aes256")]
    Aes256(C::Aes256),
    #[cfg(feature = "sm4_128")]
    Sm4_128(C::Sm4_128),
    #[cfg(feature = "camellia128")]
    Camellia128(C::Camellia128),
    #[cfg(feature = "camellia192")]
    Camellia192(C::Camellia192),
    #[cfg(feature = "camellia256")]
    Camellia256(C::Camellia256),
}

impl<C: Cmac> CmacContext<C> {
    /// Initializes a new [`CmacContext`] from `key`.
    pub fn new(key: SymmetricKey<'_>) -> Result<Self, CryptoError> {
        match_sym_alg!(match key {
            SymmetricKey::$Alg(k) => { Ok(Self::$Alg(CmacState::init(k)?)) },
        })
    }

    /// Returns the cipher algorithm of this context.
    pub const fn alg(&self) -> AlgSym {
        match_sym_alg!(match self {
            Self::$Alg(_) => { AlgSym::$Alg },
        })
    }

    /// Feeds `data` into the context.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match_sym_alg!(match self {
            Self::$Alg(ctx) => { ctx.update(data) },
        })
    }

    /// Writes the MAC into `out`. Consumes the context.
    pub fn finalize(mut self, out: &mut Block) -> Result<(), CryptoError> {
        match_sym_alg!(match (&mut self) {
            Self::$Alg(ctx) => { ctx.finalize(out) },
        })
    }
}

impl SymmetricKey<'_> {
    /// Writes the CMAC of the concatenation of `data` under this key into
    /// `out`.
    ///
    /// This is for one-shot CMAC calculation. [`CmacContext`] allows for
    /// streaming CMAC calculation.
    pub fn cmac<C: Cmac>(&self, data: &[&[u8]], out: &mut Block) -> Result<(), CryptoError> {
        match_sym_alg!(match (*self) {
            Self::$Alg(k) => { C::$Alg::cmac(k, data, out) },
        })
    }
}
