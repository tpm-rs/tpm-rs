use crate::{
    Alg, TpmiAlgHash, TpmtHa,
    crypto::{Base, Finalize, Update},
};

/// Cryptographic hashing interfaces for TPM implementations and clients.
///
/// Supported algorithms define a concrete `*Ctx` type and implement:
///   - A method creating/initializing the context (e.g. [`Hash::sha256()`])
///   - [`Update<Error>`] for `*Ctx`
///   - [`Finalize<N, Error>`] for `*Ctx` (where `N` is the digest length)
///
/// Unimplemented algorithms bind their context type to [`!`] and
/// omit the method, keeping the default body of
/// [`Err(self.unimplemented(...))`](Base::unimplemented).
///
/// # Example
///
/// ```
/// # use tpm2::{crypto::{Base, Hash, Finalize, Update}, Alg};
/// # struct MyBackend;
/// # struct MyError;
/// # impl Base for MyBackend {
/// #   type Error = MyError;
/// #   fn unimplemented(&self, _: Alg) -> MyError { MyError }
/// # }
/// # struct MySha256;
/// impl Hash for MyBackend {
///     type Sha256Ctx = MySha256;
///     fn sha256(&self) -> Result<MySha256, MyError> { todo!() }
///
///     // Unsupported algorithms use `!` and default methods:
///     type Sha1Ctx = !;
///     type Sha384Ctx = !;
///     type Sha512Ctx = !;
///     type Sm3_256Ctx = !;
///     type Sha3_256Ctx = !;
///     type Sha3_384Ctx = !;
///     type Sha3_512Ctx = !;
/// }
///
/// impl Update<MyError> for MySha256 {
///     fn update(&mut self, data: &[u8]) -> Result<(), MyError> { todo!() }
/// }
/// impl Finalize<32, MyError> for MySha256 {
///     fn finalize(self, out: &mut [u8; 32]) -> Result<(), MyError> { todo!() }
/// }
/// ```
pub trait Hash: Base {
    type Sha1Ctx: Update<Self::Error> + Finalize<20, Self::Error>;
    fn sha1(&self) -> Result<Self::Sha1Ctx, Self::Error> {
        Err(self.unimplemented(Alg::SHA1))
    }

    type Sha256Ctx: Update<Self::Error> + Finalize<32, Self::Error>;
    fn sha256(&self) -> Result<Self::Sha256Ctx, Self::Error> {
        Err(self.unimplemented(Alg::SHA256))
    }

    type Sha384Ctx: Update<Self::Error> + Finalize<48, Self::Error>;
    fn sha384(&self) -> Result<Self::Sha384Ctx, Self::Error> {
        Err(self.unimplemented(Alg::SHA384))
    }

    type Sha512Ctx: Update<Self::Error> + Finalize<64, Self::Error>;
    fn sha512(&self) -> Result<Self::Sha512Ctx, Self::Error> {
        Err(self.unimplemented(Alg::SHA512))
    }

    type Sm3_256Ctx: Update<Self::Error> + Finalize<32, Self::Error>;
    fn sm3_256(&self) -> Result<Self::Sm3_256Ctx, Self::Error> {
        Err(self.unimplemented(Alg::SM3_256))
    }

    type Sha3_256Ctx: Update<Self::Error> + Finalize<32, Self::Error>;
    fn sha3_256(&self) -> Result<Self::Sha3_256Ctx, Self::Error> {
        Err(self.unimplemented(Alg::SHA3_256))
    }

    type Sha3_384Ctx: Update<Self::Error> + Finalize<48, Self::Error>;
    fn sha3_384(&self) -> Result<Self::Sha3_384Ctx, Self::Error> {
        Err(self.unimplemented(Alg::SHA3_384))
    }

    type Sha3_512Ctx: Update<Self::Error> + Finalize<64, Self::Error>;
    fn sha3_512(&self) -> Result<Self::Sha3_512Ctx, Self::Error> {
        Err(self.unimplemented(Alg::SHA3_512))
    }
}

/// Dynamic hash context wrapping algorithm-specific streams.
pub enum HashCtx<H: Hash> {
    #[cfg(feature = "sha1")]
    Sha1(H::Sha1Ctx),
    #[cfg(feature = "sha256")]
    Sha256(H::Sha256Ctx),
    #[cfg(feature = "sha384")]
    Sha384(H::Sha384Ctx),
    #[cfg(feature = "sha512")]
    Sha512(H::Sha512Ctx),
    #[cfg(feature = "sm3_256")]
    Sm3_256(H::Sm3_256Ctx),
    #[cfg(feature = "sha3_256")]
    Sha3_256(H::Sha3_256Ctx),
    #[cfg(feature = "sha3_384")]
    Sha3_384(H::Sha3_384Ctx),
    #[cfg(feature = "sha3_512")]
    Sha3_512(H::Sha3_512Ctx),
}

impl<H: Hash> HashCtx<H> {
    /// Initializes a hash context for `alg` using backend `h`.
    pub fn new(h: &H, alg: TpmiAlgHash) -> Result<Self, H::Error> {
        match alg {
            #[cfg(feature = "sha1")]
            TpmiAlgHash::Sha1 => h.sha1().map(HashCtx::Sha1),
            #[cfg(feature = "sha256")]
            TpmiAlgHash::Sha256 => h.sha256().map(HashCtx::Sha256),
            #[cfg(feature = "sha384")]
            TpmiAlgHash::Sha384 => h.sha384().map(HashCtx::Sha384),
            #[cfg(feature = "sha512")]
            TpmiAlgHash::Sha512 => h.sha512().map(HashCtx::Sha512),
            #[cfg(feature = "sm3_256")]
            TpmiAlgHash::Sm3_256 => h.sm3_256().map(HashCtx::Sm3_256),
            #[cfg(feature = "sha3_256")]
            TpmiAlgHash::Sha3_256 => h.sha3_256().map(HashCtx::Sha3_256),
            #[cfg(feature = "sha3_384")]
            TpmiAlgHash::Sha3_384 => h.sha3_384().map(HashCtx::Sha3_384),
            #[cfg(feature = "sha3_512")]
            TpmiAlgHash::Sha3_512 => h.sha3_512().map(HashCtx::Sha3_512),
        }
    }

    /// Feeds `data` into the active hash stream.
    pub fn update(&mut self, data: &[u8]) -> Result<(), H::Error> {
        match self {
            #[cfg(feature = "sha1")]
            HashCtx::Sha1(ctx) => ctx.update(data),
            #[cfg(feature = "sha256")]
            HashCtx::Sha256(ctx) => ctx.update(data),
            #[cfg(feature = "sha384")]
            HashCtx::Sha384(ctx) => ctx.update(data),
            #[cfg(feature = "sha512")]
            HashCtx::Sha512(ctx) => ctx.update(data),
            #[cfg(feature = "sm3_256")]
            HashCtx::Sm3_256(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_256")]
            HashCtx::Sha3_256(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_384")]
            HashCtx::Sha3_384(ctx) => ctx.update(data),
            #[cfg(feature = "sha3_512")]
            HashCtx::Sha3_512(ctx) => ctx.update(data),
        }
    }

    /// Finalizes the digest into `out` and returns the tagged [`TpmtHa`].
    pub fn finalize<'a>(
        self,
        out: &'a mut [u8; TpmtHa::MAX_DIGEST_SIZE],
    ) -> Result<TpmtHa<'a>, H::Error> {
        /// Helper function for handling finalizing into the output buffer.
        fn helper<'a, const N: usize, Error>(
            ctx: impl Finalize<N, Error>,
            out: &'a mut [u8; TpmtHa::MAX_DIGEST_SIZE],
        ) -> Result<&'a [u8; N], Error> {
            const { assert!(N <= TpmtHa::MAX_DIGEST_SIZE) };
            let digest: &'a mut [u8; N] = out.first_chunk_mut().unwrap();
            ctx.finalize(digest)?;
            Ok(digest)
        }

        match self {
            #[cfg(feature = "sha1")]
            HashCtx::Sha1(ctx) => helper(ctx, out).map(TpmtHa::Sha1),
            #[cfg(feature = "sha256")]
            HashCtx::Sha256(ctx) => helper(ctx, out).map(TpmtHa::Sha256),
            #[cfg(feature = "sha384")]
            HashCtx::Sha384(ctx) => helper(ctx, out).map(TpmtHa::Sha384),
            #[cfg(feature = "sha512")]
            HashCtx::Sha512(ctx) => helper(ctx, out).map(TpmtHa::Sha512),
            #[cfg(feature = "sm3_256")]
            HashCtx::Sm3_256(ctx) => helper(ctx, out).map(TpmtHa::Sm3_256),
            #[cfg(feature = "sha3_256")]
            HashCtx::Sha3_256(ctx) => helper(ctx, out).map(TpmtHa::Sha3_256),
            #[cfg(feature = "sha3_384")]
            HashCtx::Sha3_384(ctx) => helper(ctx, out).map(TpmtHa::Sha3_384),
            #[cfg(feature = "sha3_512")]
            HashCtx::Sha3_512(ctx) => helper(ctx, out).map(TpmtHa::Sha3_512),
        }
    }
}

/// Computes a digest in a stack-allocated buffer using [`HashCtx`].
pub fn hash<'a, H: Hash>(
    h: &H,
    alg: TpmiAlgHash,
    data: &[u8],
    out: &'a mut [u8; TpmtHa::MAX_DIGEST_SIZE],
) -> Result<TpmtHa<'a>, H::Error> {
    let mut ctx = HashCtx::new(h, alg)?;
    ctx.update(data)?;
    ctx.finalize(out)
}
