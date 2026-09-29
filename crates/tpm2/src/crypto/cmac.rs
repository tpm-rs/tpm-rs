use crate::{
    Alg, TpmtSymDefObject,
    crypto::{Base, Finalize, Update},
};

/// Cryptographic CMAC interfaces for TPM implementations and clients.
///
/// Supported algorithms define a concrete `*Ctx` type and implement:
///   - A method creating/initializing the context with a fixed-size key (e.g. [`Cmac::aes128()`])
///   - [`Update<Error>`] for `*Ctx`
///   - [`Finalize<16, Error>`] for `*Ctx`
///
/// Unimplemented algorithms bind their context type to [`!`] and
/// omit the method, keeping the default body of
/// [`Err(self.unimplemented(...))`](Base::unimplemented).
///
/// # Example
///
/// ```
/// # use tpm2::{crypto::{Base, Cmac, Finalize, Update}, Alg};
/// # struct MyBackend;
/// # struct MyError;
/// # impl Base for MyBackend {
/// #   type Error = MyError;
/// #   fn unimplemented(&self, _: Alg) -> MyError { MyError }
/// # }
/// # struct MyCmacAes128;
/// impl Cmac for MyBackend {
///     fn invalid_key(&self) -> MyError { MyError }
///
///     type Aes128Ctx = MyCmacAes128;
///     fn aes128(&self, key: &[u8; 16]) -> Result<MyCmacAes128, MyError> { todo!() }
///
///     // Unsupported algorithms use `!` and default methods:
///     type Aes192Ctx = !;
///     type Aes256Ctx = !;
///     type Sm4_128Ctx = !;
///     type Camellia128Ctx = !;
///     type Camellia192Ctx = !;
///     type Camellia256Ctx = !;
/// }
///
/// impl Update<MyError> for MyCmacAes128 {
///     fn update(&mut self, data: &[u8]) -> Result<(), MyError> { todo!() }
/// }
/// impl Finalize<16, MyError> for MyCmacAes128 {
///     fn finalize(self, out: &mut [u8; 16]) -> Result<(), MyError> { todo!() }
/// }
/// ```
pub trait Cmac: Base {
    /// Returns the error value for invalid key length.
    fn invalid_key(&self) -> Self::Error;

    type Aes128Ctx: Update<Self::Error> + Finalize<16, Self::Error>;
    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Ctx, Self::Error> {
        let _ = key;
        Err(self.unimplemented(Alg::AES))
    }

    type Aes192Ctx: Update<Self::Error> + Finalize<16, Self::Error>;
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Ctx, Self::Error> {
        let _ = key;
        Err(self.unimplemented(Alg::AES))
    }

    type Aes256Ctx: Update<Self::Error> + Finalize<16, Self::Error>;
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Ctx, Self::Error> {
        let _ = key;
        Err(self.unimplemented(Alg::AES))
    }

    type Sm4_128Ctx: Update<Self::Error> + Finalize<16, Self::Error>;
    fn sm4_128(&self, key: &[u8; 16]) -> Result<Self::Sm4_128Ctx, Self::Error> {
        let _ = key;
        Err(self.unimplemented(Alg::SM4))
    }

    type Camellia128Ctx: Update<Self::Error> + Finalize<16, Self::Error>;
    fn camellia128(&self, key: &[u8; 16]) -> Result<Self::Camellia128Ctx, Self::Error> {
        let _ = key;
        Err(self.unimplemented(Alg::CAMELLIA))
    }

    type Camellia192Ctx: Update<Self::Error> + Finalize<16, Self::Error>;
    fn camellia192(&self, key: &[u8; 24]) -> Result<Self::Camellia192Ctx, Self::Error> {
        let _ = key;
        Err(self.unimplemented(Alg::CAMELLIA))
    }

    type Camellia256Ctx: Update<Self::Error> + Finalize<16, Self::Error>;
    fn camellia256(&self, key: &[u8; 32]) -> Result<Self::Camellia256Ctx, Self::Error> {
        let _ = key;
        Err(self.unimplemented(Alg::CAMELLIA))
    }
}

/// Dynamic CMAC context wrapping algorithm-specific streams.
pub enum CmacCtx<C: Cmac> {
    #[cfg(feature = "aes128")]
    Aes128(C::Aes128Ctx),
    #[cfg(feature = "aes192")]
    Aes192(C::Aes192Ctx),
    #[cfg(feature = "aes256")]
    Aes256(C::Aes256Ctx),
    #[cfg(feature = "sm4_128")]
    Sm4_128(C::Sm4_128Ctx),
    #[cfg(feature = "camellia128")]
    Camellia128(C::Camellia128Ctx),
    #[cfg(feature = "camellia192")]
    Camellia192(C::Camellia192Ctx),
    #[cfg(feature = "camellia256")]
    Camellia256(C::Camellia256Ctx),
}

impl<C: Cmac> CmacCtx<C> {
    /// Initializes a CMAC context for `alg` using backend `c` and `key`.
    pub fn new(c: &C, alg: TpmtSymDefObject, key: &[u8]) -> Result<Self, C::Error> {
        match alg {
            #[cfg(feature = "aes128")]
            TpmtSymDefObject::Aes128(_) => {
                let key: &[u8; 16] = key.try_into().map_err(|_| c.invalid_key())?;
                c.aes128(key).map(CmacCtx::Aes128)
            }
            #[cfg(feature = "aes192")]
            TpmtSymDefObject::Aes192(_) => {
                let key: &[u8; 24] = key.try_into().map_err(|_| c.invalid_key())?;
                c.aes192(key).map(CmacCtx::Aes192)
            }
            #[cfg(feature = "aes256")]
            TpmtSymDefObject::Aes256(_) => {
                let key: &[u8; 32] = key.try_into().map_err(|_| c.invalid_key())?;
                c.aes256(key).map(CmacCtx::Aes256)
            }
            #[cfg(feature = "sm4_128")]
            TpmtSymDefObject::Sm4_128(_) => {
                let key: &[u8; 16] = key.try_into().map_err(|_| c.invalid_key())?;
                c.sm4_128(key).map(CmacCtx::Sm4_128)
            }
            #[cfg(feature = "camellia128")]
            TpmtSymDefObject::Camellia128(_) => {
                let key: &[u8; 16] = key.try_into().map_err(|_| c.invalid_key())?;
                c.camellia128(key).map(CmacCtx::Camellia128)
            }
            #[cfg(feature = "camellia192")]
            TpmtSymDefObject::Camellia192(_) => {
                let key: &[u8; 24] = key.try_into().map_err(|_| c.invalid_key())?;
                c.camellia192(key).map(CmacCtx::Camellia192)
            }
            #[cfg(feature = "camellia256")]
            TpmtSymDefObject::Camellia256(_) => {
                let key: &[u8; 32] = key.try_into().map_err(|_| c.invalid_key())?;
                c.camellia256(key).map(CmacCtx::Camellia256)
            }
        }
    }

    /// Feeds `data` into the active CMAC stream.
    pub fn update(&mut self, data: &[u8]) -> Result<(), C::Error> {
        match self {
            #[cfg(feature = "aes128")]
            CmacCtx::Aes128(ctx) => ctx.update(data),
            #[cfg(feature = "aes192")]
            CmacCtx::Aes192(ctx) => ctx.update(data),
            #[cfg(feature = "aes256")]
            CmacCtx::Aes256(ctx) => ctx.update(data),
            #[cfg(feature = "sm4_128")]
            CmacCtx::Sm4_128(ctx) => ctx.update(data),
            #[cfg(feature = "camellia128")]
            CmacCtx::Camellia128(ctx) => ctx.update(data),
            #[cfg(feature = "camellia192")]
            CmacCtx::Camellia192(ctx) => ctx.update(data),
            #[cfg(feature = "camellia256")]
            CmacCtx::Camellia256(ctx) => ctx.update(data),
        }
    }

    /// Finalizes the MAC into `out`.
    pub fn finalize(self, out: &mut [u8; 16]) -> Result<(), C::Error> {
        match self {
            #[cfg(feature = "aes128")]
            CmacCtx::Aes128(ctx) => ctx.finalize(out),
            #[cfg(feature = "aes192")]
            CmacCtx::Aes192(ctx) => ctx.finalize(out),
            #[cfg(feature = "aes256")]
            CmacCtx::Aes256(ctx) => ctx.finalize(out),
            #[cfg(feature = "sm4_128")]
            CmacCtx::Sm4_128(ctx) => ctx.finalize(out),
            #[cfg(feature = "camellia128")]
            CmacCtx::Camellia128(ctx) => ctx.finalize(out),
            #[cfg(feature = "camellia192")]
            CmacCtx::Camellia192(ctx) => ctx.finalize(out),
            #[cfg(feature = "camellia256")]
            CmacCtx::Camellia256(ctx) => ctx.finalize(out),
        }
    }
}

/// Computes a CMAC in a stack-allocated buffer using [`CmacCtx`].
pub fn cmac<C: Cmac>(
    c: &C,
    alg: TpmtSymDefObject,
    key: &[u8],
    data: &[u8],
    out: &mut [u8; 16],
) -> Result<(), C::Error> {
    let mut ctx = CmacCtx::new(c, alg, key)?;
    ctx.update(data)?;
    ctx.finalize(out)
}
