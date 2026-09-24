use super::{CryptoError, Finalize, SymmetricKey, Update};

/// Cryptographic CMAC interfaces for TPM implementations and clients.
///
/// This is extremely similar to [`Hash`](super::Hash) and [`Hmac`](super::Hmac)
/// except that the context constructors (like [`Cmac::aes128`]) take a
/// fixed-size block cipher key and always produce a 16-byte MAC.
#[allow(unused_variables)]
pub trait Cmac {
    type Aes128Context: Update + Finalize<16>;
    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Aes192Context: Update + Finalize<16>;
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Aes256Context: Update + Finalize<16>;
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sm4_128Context: Update + Finalize<16>;
    fn sm4_128(&self, key: &[u8; 16]) -> Result<Self::Sm4_128Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Camellia128Context: Update + Finalize<16>;
    fn camellia128(&self, key: &[u8; 16]) -> Result<Self::Camellia128Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Camellia192Context: Update + Finalize<16>;
    fn camellia192(&self, key: &[u8; 24]) -> Result<Self::Camellia192Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Camellia256Context: Update + Finalize<16>;
    fn camellia256(&self, key: &[u8; 32]) -> Result<Self::Camellia256Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// Dynamic CMAC context wrapping algorithm-specific contexts.
///
/// This is for streaming CMAC calculation. One-shot users should use [`cmac`].
pub enum CmacStream<C: Cmac> {
    #[cfg(feature = "aes128")]
    Aes128(C::Aes128Context),
    #[cfg(feature = "aes192")]
    Aes192(C::Aes192Context),
    #[cfg(feature = "aes256")]
    Aes256(C::Aes256Context),
    #[cfg(feature = "sm4_128")]
    Sm4_128(C::Sm4_128Context),
    #[cfg(feature = "camellia128")]
    Camellia128(C::Camellia128Context),
    #[cfg(feature = "camellia192")]
    Camellia192(C::Camellia192Context),
    #[cfg(feature = "camellia256")]
    Camellia256(C::Camellia256Context),
}

impl<C: Cmac> CmacStream<C> {
    /// Initializes a CMAC context for `key` using backend `c`.
    pub fn new(c: &C, key: SymmetricKey<'_>) -> Result<Self, CryptoError> {
        match key {
            #[cfg(feature = "aes128")]
            SymmetricKey::Aes128(key) => c.aes128(key).map(CmacStream::Aes128),
            #[cfg(feature = "aes192")]
            SymmetricKey::Aes192(key) => c.aes192(key).map(CmacStream::Aes192),
            #[cfg(feature = "aes256")]
            SymmetricKey::Aes256(key) => c.aes256(key).map(CmacStream::Aes256),
            #[cfg(feature = "sm4_128")]
            SymmetricKey::Sm4_128(key) => c.sm4_128(key).map(CmacStream::Sm4_128),
            #[cfg(feature = "camellia128")]
            SymmetricKey::Camellia128(key) => c.camellia128(key).map(CmacStream::Camellia128),
            #[cfg(feature = "camellia192")]
            SymmetricKey::Camellia192(key) => c.camellia192(key).map(CmacStream::Camellia192),
            #[cfg(feature = "camellia256")]
            SymmetricKey::Camellia256(key) => c.camellia256(key).map(CmacStream::Camellia256),
        }
    }

    /// Feeds `data` into the active CMAC stream.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            #[cfg(feature = "aes128")]
            CmacStream::Aes128(ctx) => ctx.update(data),
            #[cfg(feature = "aes192")]
            CmacStream::Aes192(ctx) => ctx.update(data),
            #[cfg(feature = "aes256")]
            CmacStream::Aes256(ctx) => ctx.update(data),
            #[cfg(feature = "sm4_128")]
            CmacStream::Sm4_128(ctx) => ctx.update(data),
            #[cfg(feature = "camellia128")]
            CmacStream::Camellia128(ctx) => ctx.update(data),
            #[cfg(feature = "camellia192")]
            CmacStream::Camellia192(ctx) => ctx.update(data),
            #[cfg(feature = "camellia256")]
            CmacStream::Camellia256(ctx) => ctx.update(data),
        }
    }

    /// Finalizes the MAC into `out`.
    pub fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        match self {
            #[cfg(feature = "aes128")]
            CmacStream::Aes128(ctx) => ctx.finalize(out),
            #[cfg(feature = "aes192")]
            CmacStream::Aes192(ctx) => ctx.finalize(out),
            #[cfg(feature = "aes256")]
            CmacStream::Aes256(ctx) => ctx.finalize(out),
            #[cfg(feature = "sm4_128")]
            CmacStream::Sm4_128(ctx) => ctx.finalize(out),
            #[cfg(feature = "camellia128")]
            CmacStream::Camellia128(ctx) => ctx.finalize(out),
            #[cfg(feature = "camellia192")]
            CmacStream::Camellia192(ctx) => ctx.finalize(out),
            #[cfg(feature = "camellia256")]
            CmacStream::Camellia256(ctx) => ctx.finalize(out),
        }
    }
}

/// Write a CMAC into a caller-provided buffer.
///
/// This is for one-shot CMAC calculation. [`CmacStream`] allows for streaming
/// CMAC calculation.
pub fn cmac(
    c: &impl Cmac,
    key: SymmetricKey<'_>,
    data: &[u8],
    out: &mut [u8; 16],
) -> Result<(), CryptoError> {
    let mut ctx = CmacStream::new(c, key)?;
    ctx.update(data)?;
    ctx.finalize(out)
}
