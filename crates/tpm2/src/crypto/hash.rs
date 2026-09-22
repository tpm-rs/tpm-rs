use super::{ConstantTimeEq, CryptoError, Finalize, Update};
use crate::{TpmiAlgHash, TpmtHa};

/// Cryptographic hashing interfaces for TPM implementations and clients.
///
/// ## Using [`Hash`]
///
/// Users will generally not call [`Hash`]'s methods (like [`Hash::sha256`])
/// directly. Instead they should call functions like [`hash`] or use the
/// [`HashStream`] structure, which allow passing in the desired [`TpmiAlgHash`].
///
/// Digests are written into a caller-provided buffer and returned as a [`TpmtHa`].
///
/// ## Implementing [`Hash`]
///
/// Supported algorithms define a concrete `*Context` type and implement:
///   - A method creating/initializing the context (e.g. [`Hash::sha256()`])
///   - [`Update`] for `*Context`
///   - [`Finalize<N>`] for `*Context` (where `N` is the digest length)
///
/// Unimplemented algorithms bind their context type to [`!`] and
/// omit the method, keeping the default body of
/// `Err(`[`CryptoError::Unsupported`]`)`.
///
/// ### Example
///
/// ```
/// # use tpm2::crypto::{CryptoError, Hash, Finalize, Update};
/// # struct MyBackend;
/// # struct MySha256;
/// impl Hash for MyBackend {
///     type Sha256Context = MySha256;
///     fn sha256(&self) -> Result<MySha256, CryptoError> { todo!() }
///
///     // Unsupported algorithms use `!` and default methods:
///     type Sha1Context = !;
///     type Sha384Context = !;
///     type Sha512Context = !;
///     type Sm3_256Context = !;
///     type Sha3_256Context = !;
///     type Sha3_384Context = !;
///     type Sha3_512Context = !;
/// }
///
/// impl Update for MySha256 {
///     fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> { todo!() }
/// }
/// impl Finalize<32> for MySha256 {
///     fn finalize(self, out: &mut [u8; 32]) -> Result<(), CryptoError> { todo!() }
/// }
/// ```
pub trait Hash {
    type Sha1Context: Update + Finalize<20>;
    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha256Context: Update + Finalize<32>;
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha384Context: Update + Finalize<48>;
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha512Context: Update + Finalize<64>;
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sm3_256Context: Update + Finalize<32>;
    fn sm3_256(&self) -> Result<Self::Sm3_256Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha3_256Context: Update + Finalize<32>;
    fn sha3_256(&self) -> Result<Self::Sha3_256Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha3_384Context: Update + Finalize<48>;
    fn sha3_384(&self) -> Result<Self::Sha3_384Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sha3_512Context: Update + Finalize<64>;
    fn sha3_512(&self) -> Result<Self::Sha3_512Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// Dynamic hash context wrapping algorithm-specific contexts.
///
/// This is for streaming hashing. One-shot users should use [`hash`].
pub enum HashStream<H: Hash> {
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

impl<H: Hash> HashStream<H> {
    /// Initializes a hash context for `alg` using backend `h`.
    pub fn new(h: &H, alg: TpmiAlgHash) -> Result<Self, CryptoError> {
        match alg {
            #[cfg(feature = "sha1")]
            TpmiAlgHash::Sha1 => h.sha1().map(HashStream::Sha1),
            #[cfg(feature = "sha256")]
            TpmiAlgHash::Sha256 => h.sha256().map(HashStream::Sha256),
            #[cfg(feature = "sha384")]
            TpmiAlgHash::Sha384 => h.sha384().map(HashStream::Sha384),
            #[cfg(feature = "sha512")]
            TpmiAlgHash::Sha512 => h.sha512().map(HashStream::Sha512),
            #[cfg(feature = "sm3_256")]
            TpmiAlgHash::Sm3_256 => h.sm3_256().map(HashStream::Sm3_256),
            #[cfg(feature = "sha3_256")]
            TpmiAlgHash::Sha3_256 => h.sha3_256().map(HashStream::Sha3_256),
            #[cfg(feature = "sha3_384")]
            TpmiAlgHash::Sha3_384 => h.sha3_384().map(HashStream::Sha3_384),
            #[cfg(feature = "sha3_512")]
            TpmiAlgHash::Sha3_512 => h.sha3_512().map(HashStream::Sha3_512),
        }
    }

    /// Feeds `data` into the active hash stream.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            #[cfg(feature = "sha1")]
            HashStream::Sha1(ctx) => ctx.update(data),
            #[cfg(feature = "sha256")]
            HashStream::Sha256(ctx) => ctx.update(data),
            #[cfg(feature = "sha384")]
            HashStream::Sha384(ctx) => ctx.update(data),
            #[cfg(feature = "sha512")]
            HashStream::Sha512(ctx) => ctx.update(data),
            #[cfg(feature = "sm3_256")]
            HashStream::Sm3_256(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_256")]
            HashStream::Sha3_256(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_384")]
            HashStream::Sha3_384(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_512")]
            HashStream::Sha3_512(ctx) => ctx.update(data),
        }
    }

    /// Finalizes the digest into `out` and returns the tagged [`TpmtHa`].
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
            HashStream::Sha1(ctx) => helper(ctx, out).map(TpmtHa::Sha1),
            #[cfg(feature = "sha256")]
            HashStream::Sha256(ctx) => helper(ctx, out).map(TpmtHa::Sha256),
            #[cfg(feature = "sha384")]
            HashStream::Sha384(ctx) => helper(ctx, out).map(TpmtHa::Sha384),
            #[cfg(feature = "sha512")]
            HashStream::Sha512(ctx) => helper(ctx, out).map(TpmtHa::Sha512),
            #[cfg(feature = "sm3_256")]
            HashStream::Sm3_256(ctx) => helper(ctx, out).map(TpmtHa::Sm3_256),
            #[cfg(feature = "sha3_256")]
            HashStream::Sha3_256(ctx) => helper(ctx, out).map(TpmtHa::Sha3_256),
            #[cfg(feature = "sha3_384")]
            HashStream::Sha3_384(ctx) => helper(ctx, out).map(TpmtHa::Sha3_384),
            #[cfg(feature = "sha3_512")]
            HashStream::Sha3_512(ctx) => helper(ctx, out).map(TpmtHa::Sha3_512),
        }
    }
}

/// Write a digest into a caller-provided buffer.
///
/// This is for one-shot hashing. [`HashStream`] allows for streaming hashing.
pub fn hash<'a>(
    h: &impl Hash,
    alg: TpmiAlgHash,
    data: &[u8],
    out: &'a mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
) -> Result<TpmtHa<'a>, CryptoError> {
    let mut ctx = HashStream::new(h, alg)?;
    ctx.update(data)?;
    ctx.finalize(out)
}

/// Compares two [`TpmtHa`] digests in constant time using [`ConstantTimeEq`].
pub fn digest_eq(c: &impl ConstantTimeEq, a: TpmtHa<'_>, b: TpmtHa<'_>) -> bool {
    match (a, b) {
        #[cfg(feature = "sha1")]
        (TpmtHa::Sha1(a), TpmtHa::Sha1(b)) => c.constant_time_eq(a, b),
        #[cfg(feature = "sha256")]
        (TpmtHa::Sha256(a), TpmtHa::Sha256(b)) => c.constant_time_eq(a, b),
        #[cfg(feature = "sha384")]
        (TpmtHa::Sha384(a), TpmtHa::Sha384(b)) => c.constant_time_eq(a, b),
        #[cfg(feature = "sha512")]
        (TpmtHa::Sha512(a), TpmtHa::Sha512(b)) => c.constant_time_eq(a, b),
        #[cfg(feature = "sm3_256")]
        (TpmtHa::Sm3_256(a), TpmtHa::Sm3_256(b)) => c.constant_time_eq(a, b),
        #[cfg(feature = "sha3_256")]
        (TpmtHa::Sha3_256(a), TpmtHa::Sha3_256(b)) => c.constant_time_eq(a, b),
        #[cfg(feature = "sha3_384")]
        (TpmtHa::Sha3_384(a), TpmtHa::Sha3_384(b)) => c.constant_time_eq(a, b),
        #[cfg(feature = "sha3_512")]
        (TpmtHa::Sha3_512(a), TpmtHa::Sha3_512(b)) => c.constant_time_eq(a, b),
        #[allow(unreachable_patterns)]
        _ => false,
    }
}
