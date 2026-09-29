use crate::{
    Alg, TpmiAlgSymMode, TpmtSymDefObject,
    crypto::{Base, Finalize, UpdateInPlace},
};

/// Cryptographic symmetric encryption and decryption interfaces for TPM implementations and clients.
///
/// Supported algorithms define concrete `*EncryptCtx` and `*DecryptCtx` types and implement:
///   - Methods creating/initializing the encryption and decryption contexts with a mode, key, and IV
///     (e.g. [`Symmetric::aes128_encrypt()`] and [`Symmetric::aes128_decrypt()`])
///   - [`UpdateInPlace<Error>`] for `*EncryptCtx` and `*DecryptCtx`
///   - [`Finalize<16, Error>`] for `*EncryptCtx` and `*DecryptCtx` (writing the updated 16-byte IV)
///
/// Unimplemented algorithms bind their context types to [`!`] and
/// omit the methods, keeping the default body of
/// [`Err(self.unimplemented(...))`](Base::unimplemented).
///
/// # Example
///
/// ```
/// # use tpm2::{crypto::{Base, Symmetric, Finalize, UpdateInPlace}, Alg, TpmiAlgSymMode};
/// # struct MyBackend;
/// # struct MyError;
/// # impl Base for MyBackend {
/// #   type Error = MyError;
/// #   fn unimplemented(&self, _: Alg) -> MyError { MyError }
/// # }
/// # struct MyAes128;
/// impl Symmetric for MyBackend {
///     fn invalid_key(&self) -> MyError { MyError }
///     fn invalid_iv(&self) -> MyError { MyError }
///
///     type Aes128EncryptCtx = MyAes128;
///     fn aes128_encrypt(
///         &self,
///         mode: TpmiAlgSymMode,
///         key: &[u8; 16],
///         iv: &[u8; 16],
///     ) -> Result<MyAes128, MyError> { todo!() }
///
///     type Aes128DecryptCtx = MyAes128;
///     fn aes128_decrypt(
///         &self,
///         mode: TpmiAlgSymMode,
///         key: &[u8; 16],
///         iv: &[u8; 16],
///     ) -> Result<MyAes128, MyError> { todo!() }
///
///     // Unsupported algorithms use `!` and default methods:
///     type Aes192EncryptCtx = !;
///     type Aes192DecryptCtx = !;
///     type Aes256EncryptCtx = !;
///     type Aes256DecryptCtx = !;
///     type Sm4_128EncryptCtx = !;
///     type Sm4_128DecryptCtx = !;
///     type Camellia128EncryptCtx = !;
///     type Camellia128DecryptCtx = !;
///     type Camellia192EncryptCtx = !;
///     type Camellia192DecryptCtx = !;
///     type Camellia256EncryptCtx = !;
///     type Camellia256DecryptCtx = !;
/// }
///
/// impl UpdateInPlace<MyError> for MyAes128 {
///     fn update(&mut self, data: &mut [u8]) -> Result<(), MyError> { todo!() }
/// }
/// impl Finalize<16, MyError> for MyAes128 {
///     fn finalize(self, iv_out: &mut [u8; 16]) -> Result<(), MyError> { todo!() }
/// }
/// ```
pub trait Symmetric: Base {
    /// Returns the error value for invalid key length.
    fn invalid_key(&self) -> Self::Error;

    /// Returns the error value for invalid IV length.
    fn invalid_iv(&self) -> Self::Error;

    type Aes128EncryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn aes128_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Aes128EncryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::AES))
    }

    type Aes128DecryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn aes128_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Aes128DecryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::AES))
    }

    type Aes192EncryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn aes192_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Aes192EncryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::AES))
    }

    type Aes192DecryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn aes192_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Aes192DecryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::AES))
    }

    type Aes256EncryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn aes256_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Aes256EncryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::AES))
    }

    type Aes256DecryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn aes256_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Aes256DecryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::AES))
    }

    type Sm4_128EncryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn sm4_128_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Sm4_128EncryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::SM4))
    }

    type Sm4_128DecryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn sm4_128_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Sm4_128DecryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::SM4))
    }

    type Camellia128EncryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn camellia128_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Camellia128EncryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::CAMELLIA))
    }

    type Camellia128DecryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn camellia128_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Camellia128DecryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::CAMELLIA))
    }

    type Camellia192EncryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn camellia192_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Camellia192EncryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::CAMELLIA))
    }

    type Camellia192DecryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn camellia192_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Camellia192DecryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::CAMELLIA))
    }

    type Camellia256EncryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn camellia256_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Camellia256EncryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::CAMELLIA))
    }

    type Camellia256DecryptCtx: UpdateInPlace<Self::Error> + Finalize<16, Self::Error>;
    fn camellia256_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Camellia256DecryptCtx, Self::Error> {
        let _ = (mode, key, iv);
        Err(self.unimplemented(Alg::CAMELLIA))
    }
}

/// Dynamic encryption context wrapping algorithm-specific cipher streams.
pub enum EncryptCtx<S: Symmetric> {
    #[cfg(feature = "aes128")]
    Aes128(S::Aes128EncryptCtx),
    #[cfg(feature = "aes192")]
    Aes192(S::Aes192EncryptCtx),
    #[cfg(feature = "aes256")]
    Aes256(S::Aes256EncryptCtx),
    #[cfg(feature = "sm4_128")]
    Sm4_128(S::Sm4_128EncryptCtx),
    #[cfg(feature = "camellia128")]
    Camellia128(S::Camellia128EncryptCtx),
    #[cfg(feature = "camellia192")]
    Camellia192(S::Camellia192EncryptCtx),
    #[cfg(feature = "camellia256")]
    Camellia256(S::Camellia256EncryptCtx),
}

impl<S: Symmetric> EncryptCtx<S> {
    /// Initializes a symmetric encryption context for `alg` using backend `s`, `key`, and `iv`.
    pub fn new(s: &S, alg: TpmtSymDefObject, key: &[u8], iv: &[u8]) -> Result<Self, S::Error> {
        let mode = alg.mode().ok_or_else(|| s.unimplemented(Alg::NULL))?;
        let iv_arr: &[u8; 16] = if mode == TpmiAlgSymMode::ECB {
            if !iv.is_empty() {
                return Err(s.invalid_iv());
            }
            &[0u8; 16]
        } else {
            iv.try_into().map_err(|_| s.invalid_iv())?
        };

        match alg {
            #[cfg(feature = "aes128")]
            TpmtSymDefObject::Aes128(_) => {
                let key: &[u8; 16] = key.try_into().map_err(|_| s.invalid_key())?;
                s.aes128_encrypt(mode, key, iv_arr).map(EncryptCtx::Aes128)
            }
            #[cfg(feature = "aes192")]
            TpmtSymDefObject::Aes192(_) => {
                let key: &[u8; 24] = key.try_into().map_err(|_| s.invalid_key())?;
                s.aes192_encrypt(mode, key, iv_arr).map(EncryptCtx::Aes192)
            }
            #[cfg(feature = "aes256")]
            TpmtSymDefObject::Aes256(_) => {
                let key: &[u8; 32] = key.try_into().map_err(|_| s.invalid_key())?;
                s.aes256_encrypt(mode, key, iv_arr).map(EncryptCtx::Aes256)
            }
            #[cfg(feature = "sm4_128")]
            TpmtSymDefObject::Sm4_128(_) => {
                let key: &[u8; 16] = key.try_into().map_err(|_| s.invalid_key())?;
                s.sm4_128_encrypt(mode, key, iv_arr)
                    .map(EncryptCtx::Sm4_128)
            }
            #[cfg(feature = "camellia128")]
            TpmtSymDefObject::Camellia128(_) => {
                let key: &[u8; 16] = key.try_into().map_err(|_| s.invalid_key())?;
                s.camellia128_encrypt(mode, key, iv_arr)
                    .map(EncryptCtx::Camellia128)
            }
            #[cfg(feature = "camellia192")]
            TpmtSymDefObject::Camellia192(_) => {
                let key: &[u8; 24] = key.try_into().map_err(|_| s.invalid_key())?;
                s.camellia192_encrypt(mode, key, iv_arr)
                    .map(EncryptCtx::Camellia192)
            }
            #[cfg(feature = "camellia256")]
            TpmtSymDefObject::Camellia256(_) => {
                let key: &[u8; 32] = key.try_into().map_err(|_| s.invalid_key())?;
                s.camellia256_encrypt(mode, key, iv_arr)
                    .map(EncryptCtx::Camellia256)
            }
        }
    }

    /// Encrypts `data` in-place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), S::Error> {
        match self {
            #[cfg(feature = "aes128")]
            EncryptCtx::Aes128(ctx) => ctx.update(data),
            #[cfg(feature = "aes192")]
            EncryptCtx::Aes192(ctx) => ctx.update(data),
            #[cfg(feature = "aes256")]
            EncryptCtx::Aes256(ctx) => ctx.update(data),
            #[cfg(feature = "sm4_128")]
            EncryptCtx::Sm4_128(ctx) => ctx.update(data),
            #[cfg(feature = "camellia128")]
            EncryptCtx::Camellia128(ctx) => ctx.update(data),
            #[cfg(feature = "camellia192")]
            EncryptCtx::Camellia192(ctx) => ctx.update(data),
            #[cfg(feature = "camellia256")]
            EncryptCtx::Camellia256(ctx) => ctx.update(data),
        }
    }

    /// Finalizes the encryption stream and writes the updated IV into `iv_out` (if 16 bytes).
    pub fn finalize(self, iv_out: &mut [u8]) -> Result<(), S::Error> {
        let mut iv = [0u8; 16];
        match self {
            #[cfg(feature = "aes128")]
            EncryptCtx::Aes128(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "aes192")]
            EncryptCtx::Aes192(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "aes256")]
            EncryptCtx::Aes256(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "sm4_128")]
            EncryptCtx::Sm4_128(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "camellia128")]
            EncryptCtx::Camellia128(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "camellia192")]
            EncryptCtx::Camellia192(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "camellia256")]
            EncryptCtx::Camellia256(ctx) => ctx.finalize(&mut iv)?,
        }
        if iv_out.len() == 16 {
            iv_out.copy_from_slice(&iv);
        }
        Ok(())
    }
}

/// Dynamic decryption context wrapping algorithm-specific cipher streams.
pub enum DecryptCtx<S: Symmetric> {
    #[cfg(feature = "aes128")]
    Aes128(S::Aes128DecryptCtx),
    #[cfg(feature = "aes192")]
    Aes192(S::Aes192DecryptCtx),
    #[cfg(feature = "aes256")]
    Aes256(S::Aes256DecryptCtx),
    #[cfg(feature = "sm4_128")]
    Sm4_128(S::Sm4_128DecryptCtx),
    #[cfg(feature = "camellia128")]
    Camellia128(S::Camellia128DecryptCtx),
    #[cfg(feature = "camellia192")]
    Camellia192(S::Camellia192DecryptCtx),
    #[cfg(feature = "camellia256")]
    Camellia256(S::Camellia256DecryptCtx),
}

impl<S: Symmetric> DecryptCtx<S> {
    /// Initializes a symmetric decryption context for `alg` using backend `s`, `key`, and `iv`.
    pub fn new(s: &S, alg: TpmtSymDefObject, key: &[u8], iv: &[u8]) -> Result<Self, S::Error> {
        let mode = alg.mode().ok_or_else(|| s.unimplemented(Alg::NULL))?;
        let iv_arr: &[u8; 16] = if mode == TpmiAlgSymMode::ECB {
            if !iv.is_empty() {
                return Err(s.invalid_iv());
            }
            &[0u8; 16]
        } else {
            iv.try_into().map_err(|_| s.invalid_iv())?
        };

        match alg {
            #[cfg(feature = "aes128")]
            TpmtSymDefObject::Aes128(_) => {
                let key: &[u8; 16] = key.try_into().map_err(|_| s.invalid_key())?;
                s.aes128_decrypt(mode, key, iv_arr).map(DecryptCtx::Aes128)
            }
            #[cfg(feature = "aes192")]
            TpmtSymDefObject::Aes192(_) => {
                let key: &[u8; 24] = key.try_into().map_err(|_| s.invalid_key())?;
                s.aes192_decrypt(mode, key, iv_arr).map(DecryptCtx::Aes192)
            }
            #[cfg(feature = "aes256")]
            TpmtSymDefObject::Aes256(_) => {
                let key: &[u8; 32] = key.try_into().map_err(|_| s.invalid_key())?;
                s.aes256_decrypt(mode, key, iv_arr).map(DecryptCtx::Aes256)
            }
            #[cfg(feature = "sm4_128")]
            TpmtSymDefObject::Sm4_128(_) => {
                let key: &[u8; 16] = key.try_into().map_err(|_| s.invalid_key())?;
                s.sm4_128_decrypt(mode, key, iv_arr)
                    .map(DecryptCtx::Sm4_128)
            }
            #[cfg(feature = "camellia128")]
            TpmtSymDefObject::Camellia128(_) => {
                let key: &[u8; 16] = key.try_into().map_err(|_| s.invalid_key())?;
                s.camellia128_decrypt(mode, key, iv_arr)
                    .map(DecryptCtx::Camellia128)
            }
            #[cfg(feature = "camellia192")]
            TpmtSymDefObject::Camellia192(_) => {
                let key: &[u8; 24] = key.try_into().map_err(|_| s.invalid_key())?;
                s.camellia192_decrypt(mode, key, iv_arr)
                    .map(DecryptCtx::Camellia192)
            }
            #[cfg(feature = "camellia256")]
            TpmtSymDefObject::Camellia256(_) => {
                let key: &[u8; 32] = key.try_into().map_err(|_| s.invalid_key())?;
                s.camellia256_decrypt(mode, key, iv_arr)
                    .map(DecryptCtx::Camellia256)
            }
        }
    }

    /// Decrypts `data` in-place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), S::Error> {
        match self {
            #[cfg(feature = "aes128")]
            DecryptCtx::Aes128(ctx) => ctx.update(data),
            #[cfg(feature = "aes192")]
            DecryptCtx::Aes192(ctx) => ctx.update(data),
            #[cfg(feature = "aes256")]
            DecryptCtx::Aes256(ctx) => ctx.update(data),
            #[cfg(feature = "sm4_128")]
            DecryptCtx::Sm4_128(ctx) => ctx.update(data),
            #[cfg(feature = "camellia128")]
            DecryptCtx::Camellia128(ctx) => ctx.update(data),
            #[cfg(feature = "camellia192")]
            DecryptCtx::Camellia192(ctx) => ctx.update(data),
            #[cfg(feature = "camellia256")]
            DecryptCtx::Camellia256(ctx) => ctx.update(data),
        }
    }

    /// Finalizes the decryption stream and writes the updated IV into `iv_out` (if 16 bytes).
    pub fn finalize(self, iv_out: &mut [u8]) -> Result<(), S::Error> {
        let mut iv = [0u8; 16];
        match self {
            #[cfg(feature = "aes128")]
            DecryptCtx::Aes128(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "aes192")]
            DecryptCtx::Aes192(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "aes256")]
            DecryptCtx::Aes256(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "sm4_128")]
            DecryptCtx::Sm4_128(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "camellia128")]
            DecryptCtx::Camellia128(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "camellia192")]
            DecryptCtx::Camellia192(ctx) => ctx.finalize(&mut iv)?,
            #[cfg(feature = "camellia256")]
            DecryptCtx::Camellia256(ctx) => ctx.finalize(&mut iv)?,
        }
        if iv_out.len() == 16 {
            iv_out.copy_from_slice(&iv);
        }
        Ok(())
    }
}

/// Dynamic symmetric context wrapping either an encryption or decryption stream.
pub enum SymmetricCtx<S: Symmetric> {
    Encrypt(EncryptCtx<S>),
    Decrypt(DecryptCtx<S>),
}

impl<S: Symmetric> SymmetricCtx<S> {
    /// Initializes an encryption context for `alg` using backend `s`, `key`, and `iv`.
    pub fn new_encrypt(
        s: &S,
        alg: TpmtSymDefObject,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Self, S::Error> {
        EncryptCtx::new(s, alg, key, iv).map(SymmetricCtx::Encrypt)
    }

    /// Initializes a decryption context for `alg` using backend `s`, `key`, and `iv`.
    pub fn new_decrypt(
        s: &S,
        alg: TpmtSymDefObject,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Self, S::Error> {
        DecryptCtx::new(s, alg, key, iv).map(SymmetricCtx::Decrypt)
    }

    /// Initializes a symmetric context for `alg` using backend `s`, `key`, `iv`, and `is_decrypt`.
    pub fn new(
        s: &S,
        alg: TpmtSymDefObject,
        key: &[u8],
        iv: &[u8],
        is_decrypt: bool,
    ) -> Result<Self, S::Error> {
        if is_decrypt {
            Self::new_decrypt(s, alg, key, iv)
        } else {
            Self::new_encrypt(s, alg, key, iv)
        }
    }

    /// Encrypts or decrypts `data` in-place.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), S::Error> {
        match self {
            SymmetricCtx::Encrypt(ctx) => ctx.update(data),
            SymmetricCtx::Decrypt(ctx) => ctx.update(data),
        }
    }

    /// Finalizes the symmetric stream and writes the updated IV into `iv_out` (if 16 bytes).
    pub fn finalize(self, iv_out: &mut [u8]) -> Result<(), S::Error> {
        match self {
            SymmetricCtx::Encrypt(ctx) => ctx.finalize(iv_out),
            SymmetricCtx::Decrypt(ctx) => ctx.finalize(iv_out),
        }
    }
}

/// Encrypts `data` in-place and updates `iv` using [`EncryptCtx`].
pub fn encrypt<S: Symmetric>(
    s: &S,
    alg: TpmtSymDefObject,
    key: &[u8],
    iv: &mut [u8],
    data: &mut [u8],
) -> Result<(), S::Error> {
    let mut ctx = EncryptCtx::new(s, alg, key, iv)?;
    ctx.update(data)?;
    ctx.finalize(iv)
}

/// Decrypts `data` in-place and updates `iv` using [`DecryptCtx`].
pub fn decrypt<S: Symmetric>(
    s: &S,
    alg: TpmtSymDefObject,
    key: &[u8],
    iv: &mut [u8],
    data: &mut [u8],
) -> Result<(), S::Error> {
    let mut ctx = DecryptCtx::new(s, alg, key, iv)?;
    ctx.update(data)?;
    ctx.finalize(iv)
}

/// Encrypts or decrypts `data` in-place and updates `iv` using [`SymmetricCtx`].
pub fn encrypt_decrypt<S: Symmetric>(
    s: &S,
    alg: TpmtSymDefObject,
    key: &[u8],
    iv: &mut [u8],
    is_decrypt: bool,
    data: &mut [u8],
) -> Result<(), S::Error> {
    if is_decrypt {
        decrypt(s, alg, key, iv, data)
    } else {
        encrypt(s, alg, key, iv, data)
    }
}
