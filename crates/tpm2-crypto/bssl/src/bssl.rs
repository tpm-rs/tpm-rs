#![allow(unsafe_code)]

use core::ffi::{c_int, c_uint, c_void};
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};
use tpm2::TpmiAlgHash;
use tpm2::crypto::CryptoError;

// ============================================================================
// Error Type of the Safe Bindings
// ============================================================================

/// Error type of the safe BoringSSL bindings in this module.
///
/// It keeps the failure categories of the bindings apart, so that the
/// `tpm2::crypto` trait implementations of
/// [`BsslCryptoProvider`](crate::BsslCryptoProvider) can map them to the
/// `tpm2::crypto` conventions:
///   - [`BsslError::InvalidData`] is a semantic failure caused by the inputs. The
///     traits report it in the `Ok` value (`Ok(false)` for verification and
///     point validation, `Ok(None)` for operations producing output).
///   - [`BsslError::Unsupported`] becomes [`CryptoError::Unsupported`].
///   - [`BsslError::BufferTooSmall`] and [`BsslError::Internal`] become
///     [`CryptoError::Internal`] (see the [`From`] implementation), as does
///     [`BsslError::InvalidData`] for operations without semantic failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BsslError {
    /// The requested algorithm, hash, curve, or key size is not supported.
    Unsupported,
    /// The input (key, signature, point, scalar, ciphertext, padding, label, ...)
    /// is invalid, or a message is too large for the key.
    InvalidData,
    /// An output buffer is too small for the result.
    BufferTooSmall,
    /// BoringSSL failed internally (e.g. an allocation failure).
    Internal,
}

impl From<BsslError> for CryptoError {
    /// Maps [`BsslError::Unsupported`] to [`CryptoError::Unsupported`] and every
    /// other error to [`CryptoError::Internal`].
    ///
    /// Callers with semantic failures must handle [`BsslError::InvalidData`]
    /// themselves before converting.
    fn from(err: BsslError) -> Self {
        match err {
            BsslError::Unsupported => CryptoError::Unsupported,
            BsslError::InvalidData | BsslError::BufferTooSmall | BsslError::Internal => {
                CryptoError::Internal
            }
        }
    }
}

// ============================================================================
// HMAC Safe Binding over `bssl-sys`
// ============================================================================

/// Safe wrapper around BoringSSL's `HMAC_CTX`, configured for the SHA-1,
/// SHA-256, SHA-384 or SHA-512 HMAC with an `N`-byte tag (20, 32, 48 or 64).
pub struct Hmac<const N: usize> {
    ctx: bssl_sys::HMAC_CTX,
}

impl<const N: usize> Hmac<N> {
    /// Returns the static `EVP_MD` of the SHA-1/SHA-2 hash with an `N`-byte digest.
    fn md() -> Result<*const bssl_sys::EVP_MD, BsslError> {
        // SAFETY: Each `EVP_sha*` function returns a static, immutable `EVP_MD` pointer.
        unsafe {
            match N {
                20 => Ok(bssl_sys::EVP_sha1()),
                32 => Ok(bssl_sys::EVP_sha256()),
                48 => Ok(bssl_sys::EVP_sha384()),
                64 => Ok(bssl_sys::EVP_sha512()),
                _ => Err(BsslError::Unsupported),
            }
        }
    }

    /// Creates a new HMAC context initialized with the provided `key`.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, BsslError> {
        let md = Self::md()?;
        let mut ctx = MaybeUninit::<bssl_sys::HMAC_CTX>::uninit();
        // SAFETY:
        // - `ctx.as_mut_ptr()` is a valid pointer to uninitialized `HMAC_CTX` stack memory.
        // - `md` is a static, valid `EVP_MD` pointer.
        // - `key.as_ptr()` is non-null (even for empty slices in Rust) and valid for `key.len()` bytes.
        let res = unsafe {
            bssl_sys::HMAC_CTX_init(ctx.as_mut_ptr());
            bssl_sys::HMAC_Init_ex(
                ctx.as_mut_ptr(),
                key.as_ptr().cast::<c_void>(),
                key.len(),
                md,
                ptr::null_mut(),
            )
        };
        if res == 1 {
            // SAFETY: `HMAC_CTX_init` and `HMAC_Init_ex` succeeded, so `ctx` is fully initialized.
            Ok(Self {
                ctx: unsafe { ctx.assume_init() },
            })
        } else {
            // SAFETY: `ctx` was initialized by `HMAC_CTX_init` and must be cleaned up on failure.
            unsafe {
                bssl_sys::HMAC_CTX_cleanup(ctx.as_mut_ptr());
            }
            Err(BsslError::Internal)
        }
    }

    /// Updates the HMAC state with `data`.
    pub fn update(&mut self, data: &[u8]) -> Result<(), BsslError> {
        if data.is_empty() {
            return Ok(());
        }
        // SAFETY: `self.ctx` is an initialized `HMAC_CTX`, and `data` is valid for `data.len()` bytes.
        let res = unsafe { bssl_sys::HMAC_Update(&mut self.ctx, data.as_ptr(), data.len()) };
        if res == 1 {
            Ok(())
        } else {
            Err(BsslError::Internal)
        }
    }

    /// Finalizes the HMAC computation and writes the `N`-byte tag into `out`.
    /// The context is then spent.
    pub fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), BsslError> {
        let mut len: c_uint = 0;
        // SAFETY: `self.ctx` is an initialized `HMAC_CTX`, `out` has space for the `N`-byte
        // digest of its hash, and `len` is a valid mutable pointer.
        let res = unsafe { bssl_sys::HMAC_Final(&mut self.ctx, out.as_mut_ptr(), &mut len) };
        if res == 1 && len as usize == N {
            Ok(())
        } else {
            Err(BsslError::Internal)
        }
    }
}

impl<const N: usize> Clone for Hmac<N> {
    fn clone(&self) -> Self {
        let mut ctx = MaybeUninit::<bssl_sys::HMAC_CTX>::uninit();
        // SAFETY: `ctx` is initialized by `HMAC_CTX_init`, and `self.ctx` is a valid initialized `HMAC_CTX`.
        let res = unsafe {
            bssl_sys::HMAC_CTX_init(ctx.as_mut_ptr());
            bssl_sys::HMAC_CTX_copy(ctx.as_mut_ptr(), &self.ctx)
        };
        assert_eq!(res, 1, "bssl_sys::HMAC_CTX_copy failed");
        // SAFETY: `HMAC_CTX_copy` succeeded.
        Self {
            ctx: unsafe { ctx.assume_init() },
        }
    }
}

impl<const N: usize> Drop for Hmac<N> {
    fn drop(&mut self) {
        // SAFETY: `self.ctx` was initialized by `HMAC_CTX_init` in `new_from_slice` or `clone`.
        unsafe {
            bssl_sys::HMAC_CTX_cleanup(&mut self.ctx);
        }
    }
}

/// Overwrites `buf` with zeros using `OPENSSL_cleanse`, which the compiler cannot elide (for
/// secrets such as private scalars and seeds).
pub fn cleanse(buf: &mut [u8]) {
    // SAFETY: `buf` is valid for writing `buf.len()` bytes.
    unsafe { bssl_sys::OPENSSL_cleanse(buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
}

// ============================================================================
// AES-CMAC Safe Bindings over `bssl-sys`
// ============================================================================

/// Internal heap-allocated wrapper around BoringSSL's opaque `CMAC_CTX`.
struct CmacCtx(NonNull<bssl_sys::CMAC_CTX>);

impl CmacCtx {
    fn new(key: &[u8], cipher: *const bssl_sys::EVP_CIPHER) -> Result<Self, BsslError> {
        // SAFETY: `CMAC_CTX_new` allocates a new `CMAC_CTX` on the heap or returns null on failure.
        let ptr = unsafe { bssl_sys::CMAC_CTX_new() };
        let non_null = NonNull::new(ptr).ok_or(BsslError::Internal)?;
        // SAFETY: `non_null` is a valid `CMAC_CTX`, `key` is valid for `key.len()` bytes,
        // and `cipher` is a valid static `EVP_CIPHER` pointer.
        let res = unsafe {
            bssl_sys::CMAC_Init(
                non_null.as_ptr(),
                key.as_ptr().cast::<c_void>(),
                key.len(),
                cipher,
                ptr::null_mut(),
            )
        };
        if res == 1 {
            Ok(Self(non_null))
        } else {
            // SAFETY: Free the allocated `CMAC_CTX` before returning the error.
            unsafe {
                bssl_sys::CMAC_CTX_free(non_null.as_ptr());
            }
            Err(BsslError::InvalidData)
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<(), BsslError> {
        if data.is_empty() {
            return Ok(());
        }
        // SAFETY: `self.0` is an initialized `CMAC_CTX`, and `data` is valid for `data.len()` bytes.
        let res = unsafe { bssl_sys::CMAC_Update(self.0.as_ptr(), data.as_ptr(), data.len()) };
        if res == 1 {
            Ok(())
        } else {
            Err(BsslError::Internal)
        }
    }

    fn finalize(&mut self, out: &mut [u8; 16]) -> Result<(), BsslError> {
        let mut out_len: usize = 0;
        // SAFETY: `self.0` is an initialized `CMAC_CTX`, `out` is a valid 16-byte buffer,
        // and `out_len` is a valid mutable pointer.
        let res = unsafe { bssl_sys::CMAC_Final(self.0.as_ptr(), out.as_mut_ptr(), &mut out_len) };
        if res == 1 && out_len == 16 {
            Ok(())
        } else {
            Err(BsslError::Internal)
        }
    }
}

impl Clone for CmacCtx {
    fn clone(&self) -> Self {
        // SAFETY: Allocates a new `CMAC_CTX` and copies state from `self.0`.
        let ptr = unsafe { bssl_sys::CMAC_CTX_new() };
        let non_null = NonNull::new(ptr).expect("bssl_sys::CMAC_CTX_new failed");
        let res = unsafe { bssl_sys::CMAC_CTX_copy(non_null.as_ptr(), self.0.as_ptr()) };
        assert_eq!(res, 1, "bssl_sys::CMAC_CTX_copy failed");
        Self(non_null)
    }
}

impl Drop for CmacCtx {
    fn drop(&mut self) {
        // SAFETY: `self.0` was allocated by `CMAC_CTX_new` and is freed exactly once on drop.
        unsafe {
            bssl_sys::CMAC_CTX_free(self.0.as_ptr());
        }
    }
}

macro_rules! impl_bssl_cmac {
    ($name:ident, $key_len:literal, $cipher_fn:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name(CmacCtx);

        impl $name {
            /// Creates a new AES-CMAC context initialized with the given key.
            pub fn new(key: &[u8; $key_len]) -> Result<Self, BsslError> {
                // SAFETY: `$cipher_fn()` returns a static, valid `EVP_CIPHER` pointer.
                let cipher = unsafe { bssl_sys::$cipher_fn() };
                CmacCtx::new(key, cipher).map(Self)
            }

            /// Updates the CMAC computation with `data`.
            pub fn update(&mut self, data: &[u8]) -> Result<(), BsslError> {
                self.0.update(data)
            }

            /// Finalizes the CMAC computation and writes the 16-byte tag into `out`.
            /// The context is then spent.
            pub fn finalize(&mut self, out: &mut [u8; 16]) -> Result<(), BsslError> {
                self.0.finalize(out)
            }
        }
    };
}

impl_bssl_cmac!(
    CmacAes128,
    16,
    EVP_aes_128_cbc,
    "Safe wrapper around BoringSSL's `CMAC_CTX` for AES-128-CMAC."
);

impl_bssl_cmac!(
    CmacAes192,
    24,
    EVP_aes_192_cbc,
    "Safe wrapper around BoringSSL's `CMAC_CTX` for AES-192-CMAC."
);

impl_bssl_cmac!(
    CmacAes256,
    32,
    EVP_aes_256_cbc,
    "Safe wrapper around BoringSSL's `CMAC_CTX` for AES-256-CMAC."
);

// ============================================================================
// AES Safe Bindings over `bssl-sys`
// ============================================================================

/// An AES-128, AES-192 or AES-256 key (BoringSSL's `AES_KEY`), expanded for both directions,
/// with the block cipher modes of TPM 2.0 on BoringSSL's `AES_*` mode functions.
///
/// The IV of each mode is updated in place to the chaining value of
/// `tpm2::crypto::backend::SymmetricState`.
pub struct Aes {
    encrypt_key: bssl_sys::AES_KEY,
    decrypt_key: bssl_sys::AES_KEY,
}

impl Aes {
    /// Expands the AES-128, AES-192 or AES-256 key `key` (16, 24 or 32 bytes) into the
    /// encryption and decryption key schedules. Any other key length is
    /// [`BsslError::InvalidData`].
    pub fn new(key: &[u8]) -> Result<Self, BsslError> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(BsslError::InvalidData);
        }
        let bits = (key.len() * 8) as c_uint;
        let mut encrypt_key = MaybeUninit::<bssl_sys::AES_KEY>::uninit();
        let mut decrypt_key = MaybeUninit::<bssl_sys::AES_KEY>::uninit();
        // SAFETY: `key` is valid for `bits / 8` bytes, and both schedules are valid uninitialized
        // memory for an `AES_KEY`.
        let (res_enc, res_dec) = unsafe {
            (
                bssl_sys::AES_set_encrypt_key(key.as_ptr(), bits, encrypt_key.as_mut_ptr()),
                bssl_sys::AES_set_decrypt_key(key.as_ptr(), bits, decrypt_key.as_mut_ptr()),
            )
        };
        // `AES_set_{en,de}crypt_key` return 0 on success and a negative value on error.
        if res_enc != 0 || res_dec != 0 {
            return Err(BsslError::Internal);
        }
        // SAFETY: both calls returned 0, so both schedules are initialized.
        Ok(unsafe {
            Self {
                encrypt_key: encrypt_key.assume_init(),
                decrypt_key: decrypt_key.assume_init(),
            }
        })
    }

    /// Encrypts the 16-byte `block` in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let input = *block;
        // SAFETY: `input` and `block` are valid 16-byte blocks; `self.encrypt_key` is initialized.
        unsafe { bssl_sys::AES_encrypt(input.as_ptr(), block.as_mut_ptr(), &self.encrypt_key) };
    }

    /// Decrypts the 16-byte `block` in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let input = *block;
        // SAFETY: `input` and `block` are valid 16-byte blocks; `self.decrypt_key` is initialized.
        unsafe { bssl_sys::AES_decrypt(input.as_ptr(), block.as_mut_ptr(), &self.decrypt_key) };
    }

    /// CTR mode (`AES_ctr128_encrypt`, a 128-bit big-endian counter starting at `iv`): XORs
    /// `data` in place with the keystream, leaving the next counter value in `iv`.
    pub fn ctr(&self, iv: &mut [u8; 16], data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let mut ecount = [0u8; 16];
        let mut num: c_uint = 0;
        // SAFETY: `data` is valid for in-place processing of `data.len()` bytes, `iv` and
        // `ecount` are 16-byte buffers, and `self.encrypt_key` is initialized.
        unsafe {
            bssl_sys::AES_ctr128_encrypt(
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
                &self.encrypt_key,
                iv.as_mut_ptr(),
                ecount.as_mut_ptr(),
                &mut num,
            );
        }
        cleanse(&mut ecount);
    }

    /// OFB mode (`AES_ofb128_encrypt`): XORs `data` in place with the keystream, leaving the
    /// last (full) keystream block in `iv`.
    pub fn ofb(&self, iv: &mut [u8; 16], data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let mut num: c_int = 0;
        // SAFETY: `data` is valid for in-place processing of `data.len()` bytes, `iv` is a
        // 16-byte buffer, and `self.encrypt_key` is initialized.
        unsafe {
            bssl_sys::AES_ofb128_encrypt(
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
                &self.encrypt_key,
                iv.as_mut_ptr(),
                &mut num,
            );
        }
    }

    /// CBC mode (`AES_cbc_encrypt`): encrypts (`encrypt`) or decrypts the whole blocks of
    /// `data` in place, leaving the last ciphertext block in `iv`.
    pub fn cbc(&self, encrypt: bool, iv: &mut [u8; 16], data: &mut [[u8; 16]]) {
        if data.is_empty() {
            return;
        }
        let (key, enc) = if encrypt {
            (&self.encrypt_key, bssl_sys::AES_ENCRYPT)
        } else {
            (&self.decrypt_key, bssl_sys::AES_DECRYPT)
        };
        let data = data.as_flattened_mut();
        // SAFETY: `data` is valid for in-place processing of `data.len()` bytes (a multiple of
        // 16), `iv` is a 16-byte buffer, and `key` is the initialized schedule of the direction.
        unsafe {
            bssl_sys::AES_cbc_encrypt(
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
                key,
                iv.as_mut_ptr(),
                enc,
            );
        }
    }

    /// CFB mode with full-block feedback (`AES_cfb128_encrypt`): encrypts (`encrypt`) or
    /// decrypts `data` in place. `iv` is left with the last ciphertext block; after a partial
    /// final block of `n` bytes, only `iv[..n]` holds its ciphertext (the rest is keystream).
    pub fn cfb(&self, encrypt: bool, iv: &mut [u8; 16], data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let mut num: c_int = 0;
        let enc = if encrypt {
            bssl_sys::AES_ENCRYPT
        } else {
            bssl_sys::AES_DECRYPT
        };
        // SAFETY:
        // - In CFB mode, the block cipher is always used in the encryption direction (`E_K(IV)`),
        //   so both directions use the encryption schedule.
        // - `data` is valid for in-place processing of `data.len()` bytes and `iv` is a 16-byte
        //   buffer.
        unsafe {
            bssl_sys::AES_cfb128_encrypt(
                data.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
                &self.encrypt_key,
                iv.as_mut_ptr(),
                &mut num,
                enc,
            );
        }
    }
}

impl Drop for Aes {
    fn drop(&mut self) {
        // SAFETY: both key schedules are valid fields of `self`.
        unsafe {
            bssl_sys::OPENSSL_cleanse(
                ptr::from_mut(&mut self.encrypt_key).cast::<c_void>(),
                core::mem::size_of_val(&self.encrypt_key),
            );
            bssl_sys::OPENSSL_cleanse(
                ptr::from_mut(&mut self.decrypt_key).cast::<c_void>(),
                core::mem::size_of_val(&self.decrypt_key),
            );
        }
    }
}

// ============================================================================
// Internal RAII Helpers for BoringSSL Memory, Bignum, RSA, EVP, and EC
// ============================================================================

/// Safe RAII wrapper around `*mut bssl_sys::BIGNUM`.
struct Bignum {
    ptr: NonNull<bssl_sys::BIGNUM>,
}

impl Bignum {
    fn new() -> Result<Self, BsslError> {
        // SAFETY: `BN_new` allocates a new initialized `BIGNUM` or returns NULL.
        let ptr = NonNull::new(unsafe { bssl_sys::BN_new() }).ok_or(BsslError::Internal)?;
        Ok(Self { ptr })
    }

    fn from_bytes_be(bytes: &[u8]) -> Result<Self, BsslError> {
        // SAFETY: `bytes.as_ptr()` is valid for `bytes.len()` bytes. `BN_bin2bn` allocates a new `BIGNUM`.
        let ptr = NonNull::new(unsafe {
            bssl_sys::BN_bin2bn(bytes.as_ptr(), bytes.len(), ptr::null_mut())
        })
        .ok_or(BsslError::InvalidData)?;
        Ok(Self { ptr })
    }

    fn from_u32(val: u32) -> Result<Self, BsslError> {
        let bn = Self::new()?;
        // SAFETY: `bn.as_ptr()` is a valid `BIGNUM` pointer.
        let res = unsafe { bssl_sys::BN_set_word(bn.as_ptr(), val.into()) };
        if res != 1 {
            return Err(BsslError::Internal);
        }
        Ok(bn)
    }

    fn as_ptr(&self) -> *mut bssl_sys::BIGNUM {
        self.ptr.as_ptr()
    }

    fn num_bits(&self) -> usize {
        // SAFETY: `self.ptr` is a valid `BIGNUM` pointer.
        unsafe { bssl_sys::BN_num_bits(self.ptr.as_ptr()) as usize }
    }

    fn is_odd(&self) -> bool {
        // SAFETY: `self.ptr` is a valid `BIGNUM` pointer.
        unsafe { bssl_sys::BN_is_odd(self.ptr.as_ptr()) == 1 }
    }

    fn is_zero(&self) -> bool {
        // SAFETY: `self.ptr` is a valid `BIGNUM` pointer.
        unsafe { bssl_sys::BN_is_zero(self.ptr.as_ptr()) == 1 }
    }

    fn is_prime(&self, ctx: &BnCtx) -> Result<bool, BsslError> {
        let mut is_probably_prime: c_int = 0;
        // SAFETY:
        // - `is_probably_prime` is a valid mutable pointer to `c_int`.
        // - `self.as_ptr()` and `ctx.as_ptr()` are valid non-null pointers.
        let res = unsafe {
            bssl_sys::BN_primality_test(
                &mut is_probably_prime,
                self.as_ptr(),
                bssl_sys::BN_prime_checks_for_generation as c_int,
                ctx.as_ptr(),
                1,
                ptr::null_mut(),
            )
        };
        if res != 1 {
            return Err(BsslError::Internal);
        }
        Ok(is_probably_prime == 1)
    }
}

impl Drop for Bignum {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was allocated by BoringSSL and is uniquely owned by `self`.
        unsafe {
            bssl_sys::BN_free(self.ptr.as_ptr());
        }
    }
}

/// Safe RAII wrapper around `*mut bssl_sys::BN_CTX`.
struct BnCtx {
    ptr: NonNull<bssl_sys::BN_CTX>,
}

impl BnCtx {
    fn new() -> Result<Self, BsslError> {
        // SAFETY: `BN_CTX_new` allocates a new `BN_CTX` or returns NULL.
        let ptr = NonNull::new(unsafe { bssl_sys::BN_CTX_new() }).ok_or(BsslError::Internal)?;
        Ok(Self { ptr })
    }

    fn as_ptr(&self) -> *mut bssl_sys::BN_CTX {
        self.ptr.as_ptr()
    }
}

impl Drop for BnCtx {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was allocated by `BN_CTX_new` and is uniquely owned.
        unsafe {
            bssl_sys::BN_CTX_free(self.ptr.as_ptr());
        }
    }
}

/// Safe RAII wrapper around `*mut bssl_sys::RSA`.
struct RsaKey {
    ptr: NonNull<bssl_sys::RSA>,
}

impl RsaKey {
    /// Allocates a new empty `RSA` structure.
    fn new() -> Result<Self, BsslError> {
        // SAFETY: `RSA_new` allocates an empty `RSA` structure or returns NULL.
        let ptr = NonNull::new(unsafe { bssl_sys::RSA_new() }).ok_or(BsslError::Internal)?;
        Ok(Self { ptr })
    }

    /// Creates an RSA public key from big-endian modulus `n_bytes` and public `exponent`
    /// (`RSA_new_public_key`, which checks the key), or [`BsslError::InvalidData`] if
    /// BoringSSL rejects it.
    fn from_public_key_be(n_bytes: &[u8], exponent: u32) -> Result<Self, BsslError> {
        let n = Bignum::from_bytes_be(n_bytes)?;
        let e = Bignum::from_u32(exponent)?;
        // SAFETY: `n.as_ptr()` and `e.as_ptr()` are valid `BIGNUM`s. `RSA_new_public_key` copies them.
        let rsa_ptr = unsafe { bssl_sys::RSA_new_public_key(n.as_ptr(), e.as_ptr()) };
        let ptr = NonNull::new(rsa_ptr).ok_or(BsslError::InvalidData)?;
        Ok(Self { ptr })
    }

    fn as_ptr(&self) -> *mut bssl_sys::RSA {
        self.ptr.as_ptr()
    }

    fn size(&self) -> usize {
        // SAFETY: `self.ptr` is a valid `RSA` pointer.
        unsafe { bssl_sys::RSA_size(self.ptr.as_ptr()) as usize }
    }

    /// Returns the modulus `n` (borrowed from the key).
    fn n(&self) -> *const bssl_sys::BIGNUM {
        // SAFETY: `self.ptr` is a valid `RSA` pointer; the result lives as long as `self`.
        unsafe { bssl_sys::RSA_get0_n(self.ptr.as_ptr()) }
    }
}

// SAFETY: an `RsaKey` uniquely owns its reference to the `RSA` object, and BoringSSL `RSA`
// objects may be used concurrently from several threads once constructed (their lazily computed
// Montgomery and blinding state is protected by the object's lock).
unsafe impl Send for RsaKey {}
// SAFETY: see `Send`; every operation through `&RsaKey` is a thread-safe BoringSSL operation on a
// constructed key.
unsafe impl Sync for RsaKey {}

impl Drop for RsaKey {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is a valid `RSA` pointer owned by `self`.
        unsafe {
            bssl_sys::RSA_free(self.ptr.as_ptr());
        }
    }
}

/// Safe RAII wrapper around `*mut bssl_sys::EVP_PKEY`.
struct EvpPkey {
    ptr: NonNull<bssl_sys::EVP_PKEY>,
}

impl EvpPkey {
    fn from_rsa(rsa: &RsaKey) -> Result<Self, BsslError> {
        // SAFETY: `EVP_PKEY_new` allocates a new empty `EVP_PKEY`.
        let pkey_ptr =
            NonNull::new(unsafe { bssl_sys::EVP_PKEY_new() }).ok_or(BsslError::Internal)?;
        let pkey = Self { ptr: pkey_ptr };
        // SAFETY: `EVP_PKEY_set1_RSA` increments the refcount of `rsa.as_ptr()` and assigns it to `pkey`.
        if unsafe { bssl_sys::EVP_PKEY_set1_RSA(pkey.as_ptr(), rsa.as_ptr()) } != 1 {
            return Err(BsslError::Internal);
        }
        Ok(pkey)
    }

    fn as_ptr(&self) -> *mut bssl_sys::EVP_PKEY {
        self.ptr.as_ptr()
    }
}

impl Drop for EvpPkey {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is a valid `EVP_PKEY` owned by `self`.
        unsafe {
            bssl_sys::EVP_PKEY_free(self.ptr.as_ptr());
        }
    }
}

/// Safe RAII wrapper around `*mut bssl_sys::EVP_PKEY_CTX`.
struct EvpPkeyCtx {
    ptr: NonNull<bssl_sys::EVP_PKEY_CTX>,
}

impl EvpPkeyCtx {
    fn new(pkey: &EvpPkey) -> Result<Self, BsslError> {
        // SAFETY: `EVP_PKEY_CTX_new` creates a context for `pkey`.
        let ptr =
            NonNull::new(unsafe { bssl_sys::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut()) })
                .ok_or(BsslError::Internal)?;
        Ok(Self { ptr })
    }

    fn as_ptr(&self) -> *mut bssl_sys::EVP_PKEY_CTX {
        self.ptr.as_ptr()
    }
}

impl Drop for EvpPkeyCtx {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is a valid `EVP_PKEY_CTX` owned by `self`.
        unsafe {
            bssl_sys::EVP_PKEY_CTX_free(self.ptr.as_ptr());
        }
    }
}

fn hash_alg_to_nid(hash_alg: TpmiAlgHash) -> Result<c_int, BsslError> {
    match hash_alg {
        TpmiAlgHash::Sha1 => Ok(bssl_sys::NID_sha1 as c_int),
        TpmiAlgHash::Sha256 => Ok(bssl_sys::NID_sha256 as c_int),
        TpmiAlgHash::Sha384 => Ok(bssl_sys::NID_sha384 as c_int),
        // SHA-512 by its algorithm ID: the variant exists only with the `sha512` feature of `tpm2`.
        #[allow(unreachable_patterns)]
        h if tpm2::Alg::from(h) == tpm2::Alg::SHA512 => Ok(bssl_sys::NID_sha512 as c_int),
        #[allow(unreachable_patterns)]
        _ => Err(BsslError::Unsupported),
    }
}

fn hash_alg_to_evp_md(hash_alg: TpmiAlgHash) -> Result<*const bssl_sys::EVP_MD, BsslError> {
    // SAFETY: Each `EVP_sha*` function returns a static, immutable pointer to `EVP_MD`.
    unsafe {
        match hash_alg {
            TpmiAlgHash::Sha1 => Ok(bssl_sys::EVP_sha1()),
            TpmiAlgHash::Sha256 => Ok(bssl_sys::EVP_sha256()),
            TpmiAlgHash::Sha384 => Ok(bssl_sys::EVP_sha384()),
            // SHA-512 by its algorithm ID (see `hash_alg_to_nid`).
            #[allow(unreachable_patterns)]
            h if tpm2::Alg::from(h) == tpm2::Alg::SHA512 => Ok(bssl_sys::EVP_sha512()),
            #[allow(unreachable_patterns)]
            _ => Err(BsslError::Unsupported),
        }
    }
}

/// Checks that the big-endian integer `value` is below the modulus of `rsa`
/// ([`BsslError::InvalidData`] otherwise).
fn check_below_modulus(rsa: &RsaKey, value: &[u8]) -> Result<(), BsslError> {
    let v = Bignum::from_bytes_be(value)?;
    let n = rsa.n();
    // SAFETY: `n` (if non-null) and `v` are valid `BIGNUM`s.
    if n.is_null() || unsafe { bssl_sys::BN_cmp(v.as_ptr(), n) } >= 0 {
        return Err(BsslError::InvalidData);
    }
    Ok(())
}

/// Creates an `EVP_PKEY_CTX` for RSAES-OAEP encryption (`encrypt`) or decryption with `rsa`,
/// with `hash_alg` for the label hash and MGF1, and the OAEP label `label`.
fn oaep_ctx(
    rsa: &RsaKey,
    hash_alg: TpmiAlgHash,
    label: &[u8],
    encrypt: bool,
) -> Result<EvpPkeyCtx, BsslError> {
    let md = hash_alg_to_evp_md(hash_alg)?;
    // `EVP_PKEY_CTX_new` takes its own reference to the key.
    let ctx = EvpPkeyCtx::new(&EvpPkey::from_rsa(rsa)?)?;
    // SAFETY: `ctx.as_ptr()` is a valid `EVP_PKEY_CTX` of an RSA key and `md` a static `EVP_MD`.
    unsafe {
        let init = if encrypt {
            bssl_sys::EVP_PKEY_encrypt_init(ctx.as_ptr())
        } else {
            bssl_sys::EVP_PKEY_decrypt_init(ctx.as_ptr())
        };
        if init != 1
            || bssl_sys::EVP_PKEY_CTX_set_rsa_padding(
                ctx.as_ptr(),
                bssl_sys::RSA_PKCS1_OAEP_PADDING as c_int,
            ) != 1
            || bssl_sys::EVP_PKEY_CTX_set_rsa_oaep_md(ctx.as_ptr(), md) != 1
            || bssl_sys::EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.as_ptr(), md) != 1
        {
            return Err(BsslError::Internal);
        }
    }
    if !label.is_empty() {
        // SAFETY: Allocate a buffer via `OPENSSL_malloc` for `EVP_PKEY_CTX_set0_rsa_oaep_label`, which
        // takes ownership of the pointer on success (1) and frees it when `ctx` is freed.
        let label_ptr = unsafe { bssl_sys::OPENSSL_malloc(label.len()) } as *mut u8;
        if label_ptr.is_null() {
            return Err(BsslError::Internal);
        }
        // SAFETY: `label_ptr` is valid for `label.len()` bytes and does not overlap `label`.
        unsafe {
            ptr::copy_nonoverlapping(label.as_ptr(), label_ptr, label.len());
            if bssl_sys::EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.as_ptr(), label_ptr, label.len()) != 1
            {
                bssl_sys::OPENSSL_free(label_ptr as *mut c_void);
                return Err(BsslError::Internal);
            }
        }
    }
    Ok(ctx)
}

// ============================================================================
// RSA Safe Bindings over `bssl-sys`
// ============================================================================

/// A validated RSA public key: a BoringSSL `RSA` with the modulus `n` and the public exponent
/// `e`.
pub struct RsaPublic {
    rsa: RsaKey,
    exponent: u32,
}

impl RsaPublic {
    /// Creates the public key of the big-endian modulus `modulus` and the public exponent
    /// `exponent` (`RSA_new_public_key`), or [`BsslError::InvalidData`] if BoringSSL rejects
    /// the key (e.g. an even modulus or exponent).
    pub fn new(modulus: &[u8], exponent: u32) -> Result<Self, BsslError> {
        Ok(Self {
            rsa: RsaKey::from_public_key_be(modulus, exponent)?,
            exponent,
        })
    }

    /// Returns the public exponent `e`.
    pub fn exponent(&self) -> u32 {
        self.exponent
    }

    /// Returns the size of the modulus in bytes.
    pub fn size(&self) -> usize {
        self.rsa.size()
    }

    /// Writes the big-endian modulus `n`, left-padded with zeros to `out.len()` bytes.
    pub fn modulus(&self, out: &mut [u8]) -> Result<(), BsslError> {
        let n = self.rsa.n();
        // SAFETY: `out` is valid for `out.len()` bytes and `n` (if non-null) is a valid `BIGNUM`;
        // `BN_bn2bin_padded` fails if `n` does not fit.
        if n.is_null() || unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), out.len(), n) } != 1
        {
            return Err(BsslError::Internal);
        }
        Ok(())
    }

    /// Raw modular exponentiation $c = m^e \bmod n$ (`RSA_encrypt` with `RSA_NO_PADDING`) of the
    /// big-endian `m` (of the modulus size) into `out` (of the modulus size), or
    /// [`BsslError::InvalidData`] if `m >= n`.
    pub fn encrypt_raw(&self, m: &[u8], out: &mut [u8]) -> Result<(), BsslError> {
        let size = self.size();
        if m.len() != size || out.len() != size {
            return Err(BsslError::BufferTooSmall);
        }
        check_below_modulus(&self.rsa, m)?;
        let mut out_len: usize = 0;
        // SAFETY: `m` and `out` are valid for `size` bytes.
        let res = unsafe {
            bssl_sys::RSA_encrypt(
                self.rsa.as_ptr(),
                &mut out_len,
                out.as_mut_ptr(),
                size,
                m.as_ptr(),
                size,
                bssl_sys::RSA_NO_PADDING as c_int,
            )
        };
        if res != 1 || out_len != size {
            return Err(BsslError::Internal);
        }
        Ok(())
    }

    /// Encrypts `data` using RSAES-PKCS1-v1_5 (`RSA_encrypt` with `RSA_PKCS1_PADDING`) into
    /// `out` (of the modulus size), or [`BsslError::InvalidData`] if `data` is too long.
    pub fn encrypt_pkcs1(&self, data: &[u8], out: &mut [u8]) -> Result<(), BsslError> {
        let size = self.size();
        if out.len() != size {
            return Err(BsslError::BufferTooSmall);
        }
        let mut out_len: usize = 0;
        // SAFETY: `out` is valid for `size` bytes and `data` for `data.len()` bytes.
        let res = unsafe {
            bssl_sys::RSA_encrypt(
                self.rsa.as_ptr(),
                &mut out_len,
                out.as_mut_ptr(),
                size,
                data.as_ptr(),
                data.len(),
                bssl_sys::RSA_PKCS1_PADDING as c_int,
            )
        };
        // `RSA_encrypt` fails if `data` is too large for PKCS#1 v1.5 padding with this key.
        if res != 1 {
            return Err(BsslError::InvalidData);
        }
        if out_len != size {
            return Err(BsslError::Internal);
        }
        Ok(())
    }

    /// Encrypts `data` using RSAES-OAEP with `hash_alg` (label hash and MGF1) and the OAEP label
    /// `label` into `out` (of the modulus size), or [`BsslError::InvalidData`] if `data` is too
    /// long.
    pub fn encrypt_oaep(
        &self,
        hash_alg: TpmiAlgHash,
        label: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<(), BsslError> {
        let size = self.size();
        if out.len() != size {
            return Err(BsslError::BufferTooSmall);
        }
        let ctx = oaep_ctx(&self.rsa, hash_alg, label, true)?;
        let mut out_len = out.len();
        // SAFETY: `out` is valid for `out_len` bytes and `data` is valid for `data.len()` bytes.
        let res = unsafe {
            bssl_sys::EVP_PKEY_encrypt(
                ctx.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
                data.as_ptr(),
                data.len(),
            )
        };
        // `EVP_PKEY_encrypt` fails if `data` is too large for OAEP padding with this key.
        if res != 1 {
            return Err(BsslError::InvalidData);
        }
        if out_len != size {
            return Err(BsslError::Internal);
        }
        Ok(())
    }

    /// Verifies the RSASSA-PKCS1-v1_5 signature `signature` over the pre-hashed `digest`
    /// (`RSA_verify`), or [`BsslError::InvalidData`] if it is invalid.
    pub fn verify_pkcs1(
        &self,
        hash_alg: TpmiAlgHash,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<(), BsslError> {
        let nid = hash_alg_to_nid(hash_alg)?;
        // SAFETY:
        // - `digest.as_ptr()` is valid for `digest.len()` bytes.
        // - `signature.as_ptr()` is valid for `signature.len()` bytes.
        // - `self.rsa.as_ptr()` is a valid public `RSA` key.
        let res = unsafe {
            bssl_sys::RSA_verify(
                nid,
                digest.as_ptr(),
                digest.len(),
                signature.as_ptr(),
                signature.len(),
                self.rsa.as_ptr(),
            )
        };
        if res == 1 {
            Ok(())
        } else {
            Err(BsslError::InvalidData)
        }
    }

    /// Verifies the RSASSA-PSS signature `signature` over the pre-hashed `digest`
    /// (`RSA_verify_pss_mgf1` with `RSA_PSS_SALTLEN_AUTO`, so that signatures with any salt
    /// length are accepted, as by TPM 2.0 `PssDecode`), or [`BsslError::InvalidData`] if it is
    /// invalid.
    pub fn verify_pss(
        &self,
        hash_alg: TpmiAlgHash,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<(), BsslError> {
        let md = hash_alg_to_evp_md(hash_alg)?;
        // SAFETY: `signature.as_ptr()` and `digest.as_ptr()` are valid for their respective
        // lengths, `md` is a static `EVP_MD` and `self.rsa` a valid public `RSA` key.
        let res = unsafe {
            bssl_sys::RSA_verify_pss_mgf1(
                self.rsa.as_ptr(),
                digest.as_ptr(),
                digest.len(),
                md,
                md,
                bssl_sys::RSA_PSS_SALTLEN_AUTO,
                signature.as_ptr(),
                signature.len(),
            )
        };
        if res == 1 {
            Ok(())
        } else {
            Err(BsslError::InvalidData)
        }
    }
}

/// A validated RSA private key: a BoringSSL `RSA` with all its CRT components.
pub struct RsaPrivate {
    rsa: RsaKey,
}

impl RsaPrivate {
    /// Imports the RSA private key of the big-endian modulus `modulus`, one of its prime
    /// factors `prime` (either one) and the public `exponent` (`>= 3` and odd), or
    /// [`BsslError::InvalidData`] if `prime` does not factor `modulus` into two primes of
    /// (about) the same size, or the key is otherwise invalid.
    pub fn from_prime(modulus: &[u8], prime: &[u8], exponent: u32) -> Result<Self, BsslError> {
        if exponent < 3 || exponent.is_multiple_of(2) {
            return Err(BsslError::InvalidData);
        }

        let n = Bignum::from_bytes_be(modulus)?;
        let p = Bignum::from_bytes_be(prime)?;
        let e = Bignum::from_u32(exponent)?;

        if !n.is_odd() || !p.is_odd() || p.num_bits() <= 1 || n.num_bits() < 512 {
            return Err(BsslError::InvalidData);
        }

        let ctx = BnCtx::new()?;
        let q = Bignum::new()?;
        let rem = Bignum::new()?;

        // Divide n by p: q = n / p, rem = n % p
        // SAFETY: All `BIGNUM` and `BN_CTX` pointers are valid.
        if unsafe {
            bssl_sys::BN_div(
                q.as_ptr(),
                rem.as_ptr(),
                n.as_ptr(),
                p.as_ptr(),
                ctx.as_ptr(),
            )
        } != 1
        {
            return Err(BsslError::InvalidData);
        }

        if !rem.is_zero()
            || !q.is_odd()
            || q.num_bits() <= 1
            || p.num_bits().abs_diff(q.num_bits()) > 1
        {
            return Err(BsslError::InvalidData);
        }

        // Verify p * q == n
        let prod = Bignum::new()?;
        // SAFETY: All `BIGNUM` and `BN_CTX` pointers are valid.
        if unsafe { bssl_sys::BN_mul(prod.as_ptr(), p.as_ptr(), q.as_ptr(), ctx.as_ptr()) } != 1
            || unsafe { bssl_sys::BN_cmp(prod.as_ptr(), n.as_ptr()) } != 0
        {
            return Err(BsslError::InvalidData);
        }

        // Verify primality of p and q
        if !p.is_prime(&ctx)? || !q.is_prime(&ctx)? {
            return Err(BsslError::InvalidData);
        }

        rsa_construct(&n, &p, &q, &e, &ctx).map(|rsa| Self { rsa })
    }

    /// Generates a key pair with a modulus of `bits` bits (1024 to 4096, a multiple of 128) and
    /// the public `exponent` (`>= 3` and odd) with BoringSSL's `RSA_generate_key_ex` and
    /// BoringSSL's own RNG.
    pub fn generate(bits: usize, exponent: u32) -> Result<Self, BsslError> {
        check_key_generation(bits, exponent)?;
        let e = Bignum::from_u32(exponent)?;
        let rsa = RsaKey::new()?;
        // SAFETY: `rsa.as_ptr()` and `e.as_ptr()` are valid non-null pointers.
        let res = unsafe {
            bssl_sys::RSA_generate_key_ex(rsa.as_ptr(), bits as c_int, e.as_ptr(), ptr::null_mut())
        };
        if res != 1 {
            return Err(BsslError::Internal);
        }
        Ok(Self { rsa })
    }

    /// Generates a key pair as [`generate`](Self::generate), drawing the prime candidates from
    /// `rng` (and testing them with BoringSSL's `BN_primality_test`), so that the key is
    /// deterministic for a deterministic `rng`. The larger prime is `p`.
    pub fn generate_from_rng(
        bits: usize,
        exponent: u32,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<Self, BsslError> {
        check_key_generation(bits, exponent)?;
        let e = Bignum::from_u32(exponent)?;
        let ctx = BnCtx::new()?;
        let prime_bits = bits / 2;

        for _ in 0..32 {
            let mut p = generate_deterministic_prime(rng, prime_bits, &e, &ctx)?;
            let mut q = generate_deterministic_prime(rng, prime_bits, &e, &ctx)?;
            // SAFETY: `p` and `q` are valid non-null `BIGNUM`s.
            let cmp = unsafe { bssl_sys::BN_cmp(p.as_ptr(), q.as_ptr()) };
            if cmp == 0 {
                continue;
            }
            if cmp < 0 {
                core::mem::swap(&mut p, &mut q);
            }

            let n = Bignum::new()?;
            // SAFETY: `n`, `p`, `q`, and `ctx` are valid non-null pointers.
            if unsafe { bssl_sys::BN_mul(n.as_ptr(), p.as_ptr(), q.as_ptr(), ctx.as_ptr()) } != 1 {
                return Err(BsslError::Internal);
            }
            if n.num_bits() != bits {
                continue;
            }
            if let Ok(rsa) = rsa_construct(&n, &p, &q, &e, &ctx) {
                return Ok(Self { rsa });
            }
        }
        Err(BsslError::Internal)
    }

    /// Returns the public key of this key.
    pub fn public(&self) -> Result<RsaPublic, BsslError> {
        // SAFETY: `self.rsa` is a valid `RSA` key; the getters return borrowed pointers (or
        // NULL) that live as long as `self.rsa`.
        let (n, e) = unsafe {
            (
                bssl_sys::RSA_get0_n(self.rsa.as_ptr()),
                bssl_sys::RSA_get0_e(self.rsa.as_ptr()),
            )
        };
        if n.is_null() || e.is_null() {
            return Err(BsslError::Internal);
        }
        // SAFETY: `e` is a valid non-null `BIGNUM`.
        let exponent = u32::try_from(unsafe { bssl_sys::BN_get_word(e) })
            .map_err(|_| BsslError::Unsupported)?;
        // SAFETY: `n` and `e` are valid `BIGNUM`s, which `RSA_new_public_key` copies.
        let rsa_ptr = unsafe { bssl_sys::RSA_new_public_key(n, e) };
        Ok(RsaPublic {
            rsa: RsaKey {
                ptr: NonNull::new(rsa_ptr).ok_or(BsslError::Internal)?,
            },
            exponent,
        })
    }

    /// Writes the prime factor `p` (the one this key was imported with, or the one BoringSSL
    /// calls `p` for a generated key), big-endian and left-padded with zeros to `out.len()`
    /// bytes.
    pub fn prime(&self, out: &mut [u8]) -> Result<(), BsslError> {
        // SAFETY: `self.rsa` is a valid private `RSA` key.
        let p = unsafe { bssl_sys::RSA_get0_p(self.rsa.as_ptr()) };
        // SAFETY: `out` is valid for `out.len()` bytes and `p` (if non-null) is a valid `BIGNUM`;
        // `BN_bn2bin_padded` fails if `p` does not fit.
        if p.is_null() || unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), out.len(), p) } != 1
        {
            return Err(BsslError::Internal);
        }
        Ok(())
    }

    /// Writes the CRT form `[p, q, dP, dQ, qInv]` of this key, where `p` is the larger prime,
    /// `dP = d mod (p - 1)`, `dQ = d mod (q - 1)` and `qInv = q^-1 mod p`, each big-endian and
    /// left-padded with zeros to `N` bytes (see `tpm2::crypto::backend::RsaKey::store_crt`).
    pub fn crt<const N: usize>(&self, out: &mut [[u8; N]; 5]) -> Result<(), BsslError> {
        // SAFETY: `self.rsa` is a valid private `RSA` key; the getters return borrowed
        // pointers (or NULL) that live as long as `self.rsa`.
        let (p, q, d) = unsafe {
            (
                bssl_sys::RSA_get0_p(self.rsa.as_ptr()),
                bssl_sys::RSA_get0_q(self.rsa.as_ptr()),
                bssl_sys::RSA_get0_d(self.rsa.as_ptr()),
            )
        };
        if p.is_null() || q.is_null() || d.is_null() {
            return Err(BsslError::InvalidData);
        }
        // SAFETY: `p` and `q` are valid non-null `BIGNUM`s.
        let (p, q) = if unsafe { bssl_sys::BN_cmp(p, q) } < 0 {
            (q, p)
        } else {
            (p, q)
        };
        let ctx = BnCtx::new()?;
        let one = Bignum::from_u32(1)?;
        let (pm1, qm1) = (Bignum::new()?, Bignum::new()?);
        let (dp, dq, qinv) = (Bignum::new()?, Bignum::new()?, Bignum::new()?);
        // SAFETY: valid `BIGNUM` and `BN_CTX` pointers; the outputs are distinct from the inputs.
        let ok = unsafe {
            bssl_sys::BN_sub(pm1.as_ptr(), p, one.as_ptr()) == 1
                && bssl_sys::BN_sub(qm1.as_ptr(), q, one.as_ptr()) == 1
                && bssl_sys::BN_div(ptr::null_mut(), dp.as_ptr(), d, pm1.as_ptr(), ctx.as_ptr())
                    == 1
                && bssl_sys::BN_div(ptr::null_mut(), dq.as_ptr(), d, qm1.as_ptr(), ctx.as_ptr())
                    == 1
        };
        if !ok {
            return Err(BsslError::Internal);
        }
        // SAFETY: valid `BIGNUM` and `BN_CTX` pointers; NULL if `q` is not invertible mod `p`.
        if unsafe { bssl_sys::BN_mod_inverse(qinv.as_ptr(), q, p, ctx.as_ptr()) }.is_null() {
            return Err(BsslError::InvalidData);
        }
        let values = [p, q, dp.as_ptr(), dq.as_ptr(), qinv.as_ptr()];
        for (value, out) in values.into_iter().zip(out.iter_mut()) {
            // SAFETY: `out` is valid for `N` bytes and `value` is a valid `BIGNUM`;
            // `BN_bn2bin_padded` fails if it does not fit.
            if unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), N, value) } != 1 {
                return Err(BsslError::BufferTooSmall);
            }
        }
        Ok(())
    }

    /// Returns the size of the modulus in bytes.
    pub fn size(&self) -> usize {
        self.rsa.size()
    }

    /// Raw modular exponentiation $m = c^d \bmod n$ (`RSA_decrypt` with `RSA_NO_PADDING`) of the
    /// big-endian `c` (of the modulus size) into `out` (of the modulus size), or
    /// [`BsslError::InvalidData`] if `c >= n`.
    pub fn decrypt_raw(&self, c: &[u8], out: &mut [u8]) -> Result<(), BsslError> {
        let size = self.size();
        if c.len() != size || out.len() != size {
            return Err(BsslError::BufferTooSmall);
        }
        check_below_modulus(&self.rsa, c)?;
        let mut out_len: usize = 0;
        // SAFETY: `c` and `out` are valid for `size` bytes.
        let res = unsafe {
            bssl_sys::RSA_decrypt(
                self.rsa.as_ptr(),
                &mut out_len,
                out.as_mut_ptr(),
                size,
                c.as_ptr(),
                size,
                bssl_sys::RSA_NO_PADDING as c_int,
            )
        };
        if res != 1 || out_len != size {
            return Err(BsslError::Internal);
        }
        Ok(())
    }

    /// Decrypts `ciphertext` using RSAES-PKCS1-v1_5 (`RSA_decrypt` with `RSA_PKCS1_PADDING`)
    /// into `out` (of the modulus size), returning the message length, or
    /// [`BsslError::InvalidData`] if the ciphertext or its padding is invalid.
    pub fn decrypt_pkcs1(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, BsslError> {
        let size = self.size();
        if out.len() != size {
            return Err(BsslError::BufferTooSmall);
        }
        let mut out_len: usize = 0;
        // SAFETY:
        // - `out` is valid for `size` bytes (BoringSSL requires `max_out >= RSA_size`).
        // - `ciphertext` is valid for `ciphertext.len()` bytes.
        let res = unsafe {
            bssl_sys::RSA_decrypt(
                self.rsa.as_ptr(),
                &mut out_len,
                out.as_mut_ptr(),
                size,
                ciphertext.as_ptr(),
                ciphertext.len(),
                bssl_sys::RSA_PKCS1_PADDING as c_int,
            )
        };
        if res != 1 {
            return Err(BsslError::InvalidData);
        }
        Ok(out_len)
    }

    /// Decrypts `ciphertext` using RSAES-OAEP with `hash_alg` (label hash and MGF1) and the
    /// OAEP label `label` into `out` (of the modulus size), returning the message length, or
    /// [`BsslError::InvalidData`] if the ciphertext, its padding, or the label is invalid.
    pub fn decrypt_oaep(
        &self,
        hash_alg: TpmiAlgHash,
        label: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, BsslError> {
        let size = self.size();
        if out.len() != size {
            return Err(BsslError::BufferTooSmall);
        }
        let ctx = oaep_ctx(&self.rsa, hash_alg, label, false)?;
        let mut out_len = size;
        // SAFETY: `out` is valid for `size` bytes and `ciphertext` is valid for
        // `ciphertext.len()` bytes.
        let res = unsafe {
            bssl_sys::EVP_PKEY_decrypt(
                ctx.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            )
        };
        // `EVP_PKEY_decrypt` fails if the ciphertext, its padding, or the label is invalid.
        if res != 1 {
            return Err(BsslError::InvalidData);
        }
        Ok(out_len)
    }

    /// Signs the pre-hashed `digest` using RSASSA-PKCS1-v1_5 (`RSA_sign`) into `out` (of the
    /// modulus size), or [`BsslError::InvalidData`] if the key is too small for the
    /// `DigestInfo` encoding of `digest`.
    pub fn sign_pkcs1(
        &self,
        hash_alg: TpmiAlgHash,
        digest: &[u8],
        out: &mut [u8],
    ) -> Result<(), BsslError> {
        let nid = hash_alg_to_nid(hash_alg)?;
        let size = self.size();
        if out.len() != size {
            return Err(BsslError::BufferTooSmall);
        }
        let mut sig_len: c_uint = 0;
        // SAFETY:
        // - `digest.as_ptr()` is valid for `digest.len()` bytes.
        // - `out.as_mut_ptr()` is valid for `size` bytes.
        // - `self.rsa.as_ptr()` is a valid private `RSA` key.
        let res = unsafe {
            bssl_sys::RSA_sign(
                nid,
                digest.as_ptr(),
                digest.len(),
                out.as_mut_ptr(),
                &mut sig_len,
                self.rsa.as_ptr(),
            )
        };
        // `RSA_sign` fails if the key is too small for the `DigestInfo` encoding of `digest`.
        if res != 1 {
            return Err(BsslError::InvalidData);
        }
        if sig_len as usize != size {
            return Err(BsslError::Internal);
        }
        Ok(())
    }

    /// Signs the pre-hashed `digest` using RSASSA-PSS with `hash_alg` for MGF1 and a salt of
    /// `salt_len` bytes (`RSA_sign_pss_mgf1`) into `out` (of the modulus size), or
    /// [`BsslError::InvalidData`] if the key is too small for the digest and salt.
    pub fn sign_pss(
        &self,
        hash_alg: TpmiAlgHash,
        digest: &[u8],
        salt_len: usize,
        out: &mut [u8],
    ) -> Result<(), BsslError> {
        let md = hash_alg_to_evp_md(hash_alg)?;
        let size = self.size();
        if out.len() != size {
            return Err(BsslError::BufferTooSmall);
        }
        let salt_len = c_int::try_from(salt_len).map_err(|_| BsslError::InvalidData)?;
        let mut sig_len: usize = 0;
        // SAFETY:
        // - `out` has `size` bytes.
        // - `digest.as_ptr()` is valid for `digest.len()` bytes.
        // - `md` is a valid `EVP_MD` pointer.
        let res = unsafe {
            bssl_sys::RSA_sign_pss_mgf1(
                self.rsa.as_ptr(),
                &mut sig_len,
                out.as_mut_ptr(),
                size,
                digest.as_ptr(),
                digest.len(),
                md,
                md,
                salt_len,
            )
        };
        // `RSA_sign_pss_mgf1` fails if the key is too small for the digest and salt.
        if res != 1 {
            return Err(BsslError::InvalidData);
        }
        if sig_len != size {
            return Err(BsslError::Internal);
        }
        Ok(())
    }
}

/// Checks the parameters of an RSA key generation: [`BsslError::Unsupported`] for a modulus size
/// other than 1024 to 4096 bits in steps of 128, or an exponent that is even or below 3.
fn check_key_generation(bits: usize, exponent: u32) -> Result<(), BsslError> {
    if !(1024..=4096).contains(&bits)
        || !bits.is_multiple_of(128)
        || exponent < 3
        || exponent.is_multiple_of(2)
    {
        return Err(BsslError::Unsupported);
    }
    Ok(())
}

/// Derives the private exponent `d = e^-1 mod lcm(p - 1, q - 1)` and the CRT parameters
/// `(dmp1, dmq1, iqmp)` from `(n, p, q, e)` and constructs the RSA private key
/// (`RSA_new_private_key`, which checks it).
fn rsa_construct(
    n: &Bignum,
    p: &Bignum,
    q: &Bignum,
    e: &Bignum,
    ctx: &BnCtx,
) -> Result<RsaKey, BsslError> {
    // Compute p - 1 and q - 1
    let one = Bignum::from_u32(1)?;
    let pm1 = Bignum::new()?;
    let qm1 = Bignum::new()?;
    // SAFETY: Valid `BIGNUM` pointers.
    if unsafe { bssl_sys::BN_sub(pm1.as_ptr(), p.as_ptr(), one.as_ptr()) } != 1
        || unsafe { bssl_sys::BN_sub(qm1.as_ptr(), q.as_ptr(), one.as_ptr()) } != 1
    {
        return Err(BsslError::Internal);
    }

    // Compute lcm(p - 1, q - 1) = ((p - 1) * (q - 1)) / gcd(p - 1, q - 1)
    let gcd = Bignum::new()?;
    let prod_pm1_qm1 = Bignum::new()?;
    let lcm = Bignum::new()?;
    let rem = Bignum::new()?;
    // SAFETY: Valid `BIGNUM` and `BN_CTX` pointers.
    if unsafe { bssl_sys::BN_gcd(gcd.as_ptr(), pm1.as_ptr(), qm1.as_ptr(), ctx.as_ptr()) } != 1
        || unsafe {
            bssl_sys::BN_mul(
                prod_pm1_qm1.as_ptr(),
                pm1.as_ptr(),
                qm1.as_ptr(),
                ctx.as_ptr(),
            )
        } != 1
        || unsafe {
            bssl_sys::BN_div(
                lcm.as_ptr(),
                rem.as_ptr(),
                prod_pm1_qm1.as_ptr(),
                gcd.as_ptr(),
                ctx.as_ptr(),
            )
        } != 1
    {
        return Err(BsslError::Internal);
    }

    // Compute private exponent d = e^-1 mod lcm(p - 1, q - 1)
    let d = Bignum::new()?;
    // SAFETY: `BN_mod_inverse` returns NULL if `e` and `lcm` are not coprime.
    if unsafe { bssl_sys::BN_mod_inverse(d.as_ptr(), e.as_ptr(), lcm.as_ptr(), ctx.as_ptr()) }
        .is_null()
    {
        return Err(BsslError::InvalidData);
    }

    // Compute CRT parameters: dmp1 = d mod (p - 1), dmq1 = d mod (q - 1), iqmp = q^-1 mod p
    let dmp1 = Bignum::new()?;
    let dmq1 = Bignum::new()?;
    let iqmp = Bignum::new()?;
    // SAFETY: Valid `BIGNUM` and `BN_CTX` pointers.
    if unsafe {
        bssl_sys::BN_div(
            ptr::null_mut(),
            dmp1.as_ptr(),
            d.as_ptr(),
            pm1.as_ptr(),
            ctx.as_ptr(),
        )
    } != 1
        || unsafe {
            bssl_sys::BN_div(
                ptr::null_mut(),
                dmq1.as_ptr(),
                d.as_ptr(),
                qm1.as_ptr(),
                ctx.as_ptr(),
            )
        } != 1
        || unsafe { bssl_sys::BN_mod_inverse(iqmp.as_ptr(), q.as_ptr(), p.as_ptr(), ctx.as_ptr()) }
            .is_null()
    {
        return Err(BsslError::InvalidData);
    }

    // Construct the RSA private key
    // SAFETY: All `BIGNUM` parameters are valid and non-null; `RSA_new_private_key` copies them.
    let rsa_ptr = unsafe {
        bssl_sys::RSA_new_private_key(
            n.as_ptr(),
            e.as_ptr(),
            d.as_ptr(),
            p.as_ptr(),
            q.as_ptr(),
            dmp1.as_ptr(),
            dmq1.as_ptr(),
            iqmp.as_ptr(),
        )
    };
    Ok(RsaKey {
        ptr: NonNull::new(rsa_ptr).ok_or(BsslError::InvalidData)?,
    })
}

/// Generates a random prime `p` of `prime_bits` bits with `gcd(p - 1, e) = 1` from `rng` using
/// BoringSSL's `BN_primality_test`.
fn generate_deterministic_prime(
    rng: &mut impl rand_core::RngCore,
    prime_bits: usize,
    e: &Bignum,
    ctx: &BnCtx,
) -> Result<Bignum, BsslError> {
    let prime_bytes = prime_bits / 8;
    let mut buf = [0u8; 256];
    if prime_bytes == 0 || prime_bytes > buf.len() {
        return Err(BsslError::InvalidData);
    }

    rng.fill_bytes(&mut buf[..prime_bytes]);
    // Set top two bits so p >= 3/4 * 2^prime_bits (guarantees n = p * q has exact bit length 2 * prime_bits)
    buf[0] |= 0xC0;
    // Set bottom bit so candidate is odd
    buf[prime_bytes - 1] |= 0x01;

    let cand = Bignum::from_bytes_be(&buf[..prime_bytes])?;
    let one = Bignum::from_u32(1)?;
    let cand_m1 = Bignum::new()?;
    let gcd = Bignum::new()?;

    loop {
        // Check gcd(cand - 1, e) == 1 (for the prime e = 65537: cand % 65537 != 1)
        // SAFETY: valid `BIGNUM` and `BN_CTX` pointers; the outputs are distinct from the inputs.
        let coprime = unsafe {
            bssl_sys::BN_sub(cand_m1.as_ptr(), cand.as_ptr(), one.as_ptr()) == 1
                && bssl_sys::BN_gcd(gcd.as_ptr(), cand_m1.as_ptr(), e.as_ptr(), ctx.as_ptr()) == 1
                && bssl_sys::BN_is_one(gcd.as_ptr()) == 1
        };
        if coprime && cand.is_prime(ctx)? {
            cleanse(&mut buf);
            return Ok(cand);
        }
        // Increment candidate by 2 to test next odd integer
        // SAFETY: `cand.as_ptr()` is a valid non-null `BIGNUM`.
        if unsafe { bssl_sys::BN_add_word(cand.as_ptr(), 2) } != 1 {
            return Err(BsslError::Internal);
        }
        if cand.num_bits() > prime_bits {
            rng.fill_bytes(&mut buf[..prime_bytes]);
            buf[0] |= 0xC0;
            buf[prime_bytes - 1] |= 0x01;
            // SAFETY: `cand.as_ptr()` is a valid non-null `BIGNUM`.
            if unsafe { bssl_sys::BN_bin2bn(buf.as_ptr(), prime_bytes, cand.as_ptr()) }.is_null() {
                return Err(BsslError::Internal);
            }
        }
    }
}

// ============================================================================
// Elliptic Curve Safe Bindings over `bssl-sys` (P-256, P-384, P-521, BN-P256)
// ============================================================================

/// Supported elliptic curves in `tpm2-crypto-bssl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcGroup {
    /// NIST P-224 (`secp224r1`), 28-byte coordinates.
    P224,
    /// NIST P-256 (`secp256r1`), 32-byte coordinates.
    P256,
    /// NIST P-384 (`secp384r1`), 48-byte coordinates.
    P384,
    /// NIST P-521 (`secp521r1`), 66-byte coordinates.
    P521,
    /// Barreto-Naehrig 256-bit curve (`BN-P256`), 32-byte coordinates.
    BnP256,
}

/// Scoped handle to a BoringSSL `EC_GROUP` (either static built-in or custom heap-allocated).
enum EcGroupHandle {
    Static(*const bssl_sys::EC_GROUP),
    Custom(NonNull<bssl_sys::EC_GROUP>),
}

impl EcGroupHandle {
    fn as_ptr(&self) -> *const bssl_sys::EC_GROUP {
        match self {
            Self::Static(ptr) => *ptr,
            Self::Custom(ptr) => ptr.as_ptr(),
        }
    }
}

impl Drop for EcGroupHandle {
    fn drop(&mut self) {
        if let Self::Custom(ptr) = self {
            // SAFETY: `ptr` was allocated by `EC_GROUP_new_curve_GFp` and is freed on drop.
            unsafe {
                bssl_sys::EC_GROUP_free(ptr.as_ptr());
            }
        }
    }
}

/// Constructs the custom BoringSSL `EC_GROUP` for the Barreto-Naehrig 256-bit (`BN-P256`) curve:
/// $y^2 = x^3 + 3 \pmod p$ with generator $G = (1, 2)$.
fn create_bn_p256_group() -> Result<EcGroupHandle, BsslError> {
    const P_BYTES: [u8; 32] =
        hex_literal::hex!("fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013");
    const N_BYTES: [u8; 32] =
        hex_literal::hex!("fffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d");

    let p = Bignum::from_bytes_be(&P_BYTES)?;
    let a = Bignum::from_u32(0)?;
    let b = Bignum::from_u32(3)?;
    let ctx = BnCtx::new()?;

    // SAFETY: `p`, `a`, `b`, and `ctx` are valid non-null pointers.
    let group_ptr = unsafe {
        bssl_sys::EC_GROUP_new_curve_GFp(p.as_ptr(), a.as_ptr(), b.as_ptr(), ctx.as_ptr())
    };
    let group_nn = NonNull::new(group_ptr).ok_or(BsslError::Internal)?;
    let handle = EcGroupHandle::Custom(group_nn);

    let gx = Bignum::from_u32(1)?;
    let gy = Bignum::from_u32(2)?;
    let generator = EcPoint::new(&handle)?;

    // SAFETY: `handle.as_ptr()`, `generator.as_ptr()`, `gx`, `gy`, and `ctx` are valid non-null pointers.
    let coords_ok = unsafe {
        bssl_sys::EC_POINT_set_affine_coordinates_GFp(
            handle.as_ptr(),
            generator.as_ptr(),
            gx.as_ptr(),
            gy.as_ptr(),
            ctx.as_ptr(),
        ) == 1
    };
    if !coords_ok {
        return Err(BsslError::Internal);
    }

    let order = Bignum::from_bytes_be(&N_BYTES)?;
    let cofactor = Bignum::from_u32(1)?;

    // SAFETY: `group_nn` is a custom `EC_GROUP` from `EC_GROUP_new_curve_GFp` and `generator` belongs to it.
    let gen_ok = unsafe {
        bssl_sys::EC_GROUP_set_generator(
            group_nn.as_ptr(),
            generator.as_ptr(),
            order.as_ptr(),
            cofactor.as_ptr(),
        ) == 1
    };
    if !gen_ok {
        return Err(BsslError::Internal);
    }

    Ok(handle)
}

impl EcGroup {
    /// Returns a scoped `EcGroupHandle` for this curve.
    fn handle(self) -> Result<EcGroupHandle, BsslError> {
        // SAFETY: Each `EC_group_p*` function returns a static, immutable `EC_GROUP` pointer.
        unsafe {
            match self {
                Self::P224 => Ok(EcGroupHandle::Static(bssl_sys::EC_group_p224())),
                Self::P256 => Ok(EcGroupHandle::Static(bssl_sys::EC_group_p256())),
                Self::P384 => Ok(EcGroupHandle::Static(bssl_sys::EC_group_p384())),
                Self::P521 => Ok(EcGroupHandle::Static(bssl_sys::EC_group_p521())),
                Self::BnP256 => create_bn_p256_group(),
            }
        }
    }

    /// Returns the coordinate byte length for this curve (28, 32, 48, or 66).
    pub const fn coord_len(self) -> usize {
        match self {
            Self::P224 => 28,
            Self::P256 | Self::BnP256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    /// Validates that `scalar` represents an integer $d$ in the range $1 \le d < \text{order}$.
    fn validate_scalar(
        self,
        group_handle: &EcGroupHandle,
        scalar: &[u8],
    ) -> Result<Bignum, BsslError> {
        let d = Bignum::from_bytes_be(scalar)?;
        if d.is_zero() {
            return Err(BsslError::InvalidData);
        }
        // SAFETY: `group_handle.as_ptr()` is a valid `EC_GROUP`.
        let order = unsafe { bssl_sys::EC_GROUP_get0_order(group_handle.as_ptr()) };
        if order.is_null() || unsafe { bssl_sys::BN_cmp(d.as_ptr(), order) } >= 0 {
            return Err(BsslError::InvalidData);
        }
        Ok(d)
    }
}

/// Safe RAII wrapper around `*mut bssl_sys::EC_POINT`.
struct EcPoint {
    ptr: NonNull<bssl_sys::EC_POINT>,
}

impl EcPoint {
    fn new(group: &EcGroupHandle) -> Result<Self, BsslError> {
        // SAFETY: `EC_POINT_new` allocates a new point on `group`.
        let ptr = NonNull::new(unsafe { bssl_sys::EC_POINT_new(group.as_ptr()) })
            .ok_or(BsslError::Internal)?;
        Ok(Self { ptr })
    }

    fn from_affine_coords(group: &EcGroupHandle, x: &[u8], y: &[u8]) -> Result<Self, BsslError> {
        let pt = Self::new(group)?;
        let x_bn = Bignum::from_bytes_be(x)?;
        let y_bn = Bignum::from_bytes_be(y)?;
        // SAFETY:
        // - `group.as_ptr()` and `pt.as_ptr()` are valid.
        // - `EC_POINT_set_affine_coordinates_GFp` checks that `(x, y)` is on the curve.
        let ok = unsafe {
            bssl_sys::EC_POINT_set_affine_coordinates_GFp(
                group.as_ptr(),
                pt.as_ptr(),
                x_bn.as_ptr(),
                y_bn.as_ptr(),
                ptr::null_mut(),
            ) == 1
                && bssl_sys::EC_POINT_is_on_curve(group.as_ptr(), pt.as_ptr(), ptr::null_mut()) == 1
                && bssl_sys::EC_POINT_is_at_infinity(group.as_ptr(), pt.as_ptr()) == 0
        };
        if !ok {
            return Err(BsslError::InvalidData);
        }
        Ok(pt)
    }

    fn to_affine_coords(
        &self,
        group: &EcGroupHandle,
        coord_len: usize,
        x_out: &mut [u8],
        y_out: &mut [u8],
    ) -> Result<(), BsslError> {
        if x_out.len() < coord_len || y_out.len() < coord_len {
            return Err(BsslError::BufferTooSmall);
        }
        // SAFETY: `group.as_ptr()` and `self.as_ptr()` are valid.
        if unsafe { bssl_sys::EC_POINT_is_at_infinity(group.as_ptr(), self.as_ptr()) } != 0 {
            return Err(BsslError::InvalidData);
        }
        let x_bn = Bignum::new()?;
        let y_bn = Bignum::new()?;
        // SAFETY: All pointers are valid.
        let ok = unsafe {
            bssl_sys::EC_POINT_get_affine_coordinates_GFp(
                group.as_ptr(),
                self.as_ptr(),
                x_bn.as_ptr(),
                y_bn.as_ptr(),
                ptr::null_mut(),
            ) == 1
                && bssl_sys::BN_bn2bin_padded(x_out.as_mut_ptr(), coord_len, x_bn.as_ptr()) == 1
                && bssl_sys::BN_bn2bin_padded(y_out.as_mut_ptr(), coord_len, y_bn.as_ptr()) == 1
        };
        if !ok {
            return Err(BsslError::Internal);
        }
        Ok(())
    }

    fn as_ptr(&self) -> *mut bssl_sys::EC_POINT {
        self.ptr.as_ptr()
    }
}

impl Drop for EcPoint {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was allocated by `EC_POINT_new` and is uniquely owned.
        unsafe {
            bssl_sys::EC_POINT_free(self.ptr.as_ptr());
        }
    }
}

/// Safe RAII wrapper around `*mut bssl_sys::EC_KEY`.
struct EcKey {
    ptr: NonNull<bssl_sys::EC_KEY>,
}

impl EcKey {
    fn new(group: &EcGroupHandle) -> Result<Self, BsslError> {
        // SAFETY: `EC_KEY_new` allocates a new `EC_KEY`.
        let ptr = NonNull::new(unsafe { bssl_sys::EC_KEY_new() }).ok_or(BsslError::Internal)?;
        let key = Self { ptr };
        // SAFETY: `key.as_ptr()` and `group.as_ptr()` are valid.
        if unsafe { bssl_sys::EC_KEY_set_group(key.as_ptr(), group.as_ptr()) } != 1 {
            return Err(BsslError::Internal);
        }
        Ok(key)
    }

    fn from_private_scalar(
        group: EcGroup,
        group_handle: &EcGroupHandle,
        scalar: &[u8],
    ) -> Result<Self, BsslError> {
        let d = group.validate_scalar(group_handle, scalar)?;
        let key = Self::new(group_handle)?;
        // SAFETY: `key.as_ptr()` and `d.as_ptr()` are valid.
        if unsafe { bssl_sys::EC_KEY_set_private_key(key.as_ptr(), d.as_ptr()) } != 1 {
            return Err(BsslError::InvalidData);
        }
        Ok(key)
    }

    fn from_public_point(
        group_handle: &EcGroupHandle,
        x: &[u8],
        y: &[u8],
    ) -> Result<Self, BsslError> {
        let pt = EcPoint::from_affine_coords(group_handle, x, y)?;
        let key = Self::new(group_handle)?;
        // SAFETY: `key.as_ptr()` and `pt.as_ptr()` are valid.
        if unsafe { bssl_sys::EC_KEY_set_public_key(key.as_ptr(), pt.as_ptr()) } != 1 {
            return Err(BsslError::InvalidData);
        }
        Ok(key)
    }

    fn as_ptr(&self) -> *mut bssl_sys::EC_KEY {
        self.ptr.as_ptr()
    }
}

impl Drop for EcKey {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was allocated by `EC_KEY_new` and is uniquely owned.
        unsafe {
            bssl_sys::EC_KEY_free(self.ptr.as_ptr());
        }
    }
}

/// Validates that `(x, y)` is a valid non-infinity point on `group`.
pub fn ec_validate_point(group: EcGroup, x: &[u8], y: &[u8]) -> Result<(), BsslError> {
    let group_handle = group.handle()?;
    let _pt = EcPoint::from_affine_coords(&group_handle, x, y)?;
    Ok(())
}

/// Computes generator multiplication $R = d \cdot G$ on `group`.
pub fn ec_point_multiply_generator(
    group: EcGroup,
    scalar: &[u8],
    x_out: &mut [u8],
    y_out: &mut [u8],
) -> Result<(), BsslError> {
    let group_handle = group.handle()?;
    let d = group.validate_scalar(&group_handle, scalar)?;
    let r = EcPoint::new(&group_handle)?;
    // SAFETY: `EC_POINT_mul(group, r, d, NULL, NULL, NULL)` computes `r = d * G`.
    let ok = unsafe {
        bssl_sys::EC_POINT_mul(
            group_handle.as_ptr(),
            r.as_ptr(),
            d.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
        ) == 1
    };
    if !ok {
        return Err(BsslError::Internal);
    }
    r.to_affine_coords(&group_handle, group.coord_len(), x_out, y_out)
}

/// Computes arbitrary point multiplication $R = d \cdot Q$ on `group`.
pub fn ec_point_multiply(
    group: EcGroup,
    scalar: &[u8],
    x_in: &[u8],
    y_in: &[u8],
    x_out: &mut [u8],
    y_out: &mut [u8],
) -> Result<(), BsslError> {
    let group_handle = group.handle()?;
    let d = group.validate_scalar(&group_handle, scalar)?;
    let q = EcPoint::from_affine_coords(&group_handle, x_in, y_in)?;
    let r = EcPoint::new(&group_handle)?;
    // SAFETY: `EC_POINT_mul(group, r, NULL, q, d, NULL)` computes `r = d * q`.
    let ok = unsafe {
        bssl_sys::EC_POINT_mul(
            group_handle.as_ptr(),
            r.as_ptr(),
            ptr::null(),
            q.as_ptr(),
            d.as_ptr(),
            ptr::null_mut(),
        ) == 1
    };
    if !ok {
        return Err(BsslError::Internal);
    }
    r.to_affine_coords(&group_handle, group.coord_len(), x_out, y_out)
}

/// Signs a pre-hashed digest using ECDSA and outputs a fixed-width IEEE P1363 `(r || s)` signature.
pub fn ecdsa_sign(
    group: EcGroup,
    private_key: &[u8],
    digest: &[u8],
    signature_out: &mut [u8],
) -> Result<usize, BsslError> {
    let group_handle = group.handle()?;
    let sig_size = 2 * group.coord_len();
    if signature_out.len() < sig_size {
        return Err(BsslError::BufferTooSmall);
    }
    let key = EcKey::from_private_scalar(group, &group_handle, private_key)?;
    let mut out_len: usize = 0;
    // SAFETY:
    // - `digest.as_ptr()` is valid for `digest.len()` bytes.
    // - `signature_out.as_mut_ptr()` is valid for `signature_out.len() >= sig_size` bytes.
    // - `key.as_ptr()` is a valid private `EC_KEY`.
    let res = unsafe {
        bssl_sys::ECDSA_sign_p1363(
            digest.as_ptr(),
            digest.len(),
            signature_out.as_mut_ptr(),
            &mut out_len,
            signature_out.len(),
            key.as_ptr(),
        )
    };
    if res != 1 || out_len != sig_size {
        return Err(BsslError::Internal);
    }
    Ok(out_len)
}

/// Verifies a fixed-width IEEE P1363 `(r || s)` ECDSA signature against a pre-hashed digest.
pub fn ecdsa_verify(
    group: EcGroup,
    public_key_xy: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<(), BsslError> {
    let group_handle = group.handle()?;
    let coord_len = group.coord_len();
    if public_key_xy.len() != 2 * coord_len || signature.len() != 2 * coord_len {
        return Err(BsslError::InvalidData);
    }
    let x = &public_key_xy[..coord_len];
    let y = &public_key_xy[coord_len..];
    let key = EcKey::from_public_point(&group_handle, x, y)?;
    // SAFETY:
    // - `digest.as_ptr()` is valid for `digest.len()` bytes.
    // - `signature.as_ptr()` is valid for `signature.len()` bytes.
    // - `key.as_ptr()` is a valid public `EC_KEY`.
    let res = unsafe {
        bssl_sys::ECDSA_verify_p1363(
            digest.as_ptr(),
            digest.len(),
            signature.as_ptr(),
            signature.len(),
            key.as_ptr(),
        )
    };
    if res == 1 {
        Ok(())
    } else {
        Err(BsslError::InvalidData)
    }
}

/// Generates an ECC keypair on `group` using `rng` for candidate scalar generation.
pub fn ec_generate_key(
    group: EcGroup,
    rng: &mut impl rand_core::RngCore,
    public_key_out: &mut [u8],
    private_key_out: &mut [u8],
) -> Result<(usize, usize), BsslError> {
    let group_handle = group.handle()?;
    let coord_len = group.coord_len();
    if public_key_out.len() < 2 * coord_len || private_key_out.len() < coord_len {
        return Err(BsslError::BufferTooSmall);
    }

    let mut cand = [0u8; 66];
    for _ in 0..100 {
        rng.fill_bytes(&mut cand[..coord_len]);
        if group == EcGroup::P521 {
            // Mask top 7 bits so 66 bytes (528 bits) fits in 521 bits
            cand[0] &= 0x01;
        }
        if group
            .validate_scalar(&group_handle, &cand[..coord_len])
            .is_ok()
        {
            let (x_out, y_out) = public_key_out[..2 * coord_len].split_at_mut(coord_len);
            let res = ec_point_multiply_generator(group, &cand[..coord_len], x_out, y_out);
            private_key_out[..coord_len].copy_from_slice(&cand[..coord_len]);
            cleanse(&mut cand);
            res?;
            return Ok((2 * coord_len, coord_len));
        }
    }
    cleanse(&mut cand);
    Err(BsslError::Internal)
}

// ============================================================================
// ML-KEM-768/1024 and ML-DSA-44/65/87 Safe Bindings over `bssl-sys`
// ============================================================================

/// A BoringSSL key structure (`MLKEM*_private_key`, `MLDSA*_private_key`, ...)
/// initialized by a C function, cleansed with `OPENSSL_cleanse` on drop.
struct CleansedKey<T> {
    key: MaybeUninit<T>,
}

impl<T> CleansedKey<T> {
    /// Initializes the key with `init`, which returns BoringSSL's 1 on success.
    fn new(init: impl FnOnce(*mut T) -> c_int) -> Result<Self, BsslError> {
        let mut key = Self {
            key: MaybeUninit::uninit(),
        };
        if init(key.key.as_mut_ptr()) == 1 {
            Ok(key)
        } else {
            Err(BsslError::Internal)
        }
    }

    /// Returns a pointer to the key, which `new` initialized.
    fn as_ptr(&self) -> *const T {
        self.key.as_ptr()
    }
}

impl<T> Drop for CleansedKey<T> {
    fn drop(&mut self) {
        // SAFETY: `self.key` is valid for `size_of::<T>()` bytes.
        unsafe {
            bssl_sys::OPENSSL_cleanse(
                self.key.as_mut_ptr().cast::<c_void>(),
                core::mem::size_of::<T>(),
            );
        }
    }
}

/// Serializes into exactly `out.len()` bytes with a `marshal` function writing
/// to a fixed `CBB` over `out`.
fn marshal_fixed(
    out: &mut [u8],
    marshal: impl FnOnce(*mut bssl_sys::CBB) -> c_int,
) -> Result<(), BsslError> {
    let mut cbb = MaybeUninit::<bssl_sys::CBB>::uninit();
    // SAFETY: `CBB_init_fixed` initializes `cbb` to write to `out`, which is
    // valid for `out.len()` bytes and outlives `cbb`.
    if unsafe { bssl_sys::CBB_init_fixed(cbb.as_mut_ptr(), out.as_mut_ptr(), out.len()) } != 1 {
        return Err(BsslError::Internal);
    }
    let ok = marshal(cbb.as_mut_ptr()) == 1
        // SAFETY: `cbb` is initialized.
        && unsafe { bssl_sys::CBB_len(cbb.as_ptr()) } == out.len();
    // SAFETY: `cbb` is initialized; a fixed `CBB` does not own `out`.
    unsafe { bssl_sys::CBB_cleanup(cbb.as_mut_ptr()) };
    if ok { Ok(()) } else { Err(BsslError::Internal) }
}

impl EvpPkey {
    /// Parses the raw public key `key` of the algorithm `alg`
    /// (`EVP_PKEY_from_raw_public_key`), or [`BsslError::InvalidData`] if BoringSSL
    /// rejects it.
    fn from_raw_public_key(
        alg: *const bssl_sys::EVP_PKEY_ALG,
        key: &[u8],
    ) -> Result<Self, BsslError> {
        // SAFETY: `alg` is a static `EVP_PKEY_ALG` and `key` is valid for
        // `key.len()` bytes; the result is a new `EVP_PKEY` or NULL.
        let ptr = unsafe { bssl_sys::EVP_PKEY_from_raw_public_key(alg, key.as_ptr(), key.len()) };
        NonNull::new(ptr)
            .map(|ptr| Self { ptr })
            .ok_or(BsslError::InvalidData)
    }
}

/// Defines a module with the ML-KEM bindings of one parameter set.
macro_rules! mlkem_bindings {
    (
        $(#[$doc:meta])* $module:ident,
        $private:ident, $public:ident, $public_bytes:expr, $ciphertext_bytes:expr,
        $from_seed:ident, $public_from_private:ident, $marshal:ident, $decap:ident,
        $evp_pkey_alg:ident, $evp_kem:ident $(,)?
    ) => {
        $(#[$doc])*
        pub mod $module {
            use super::*;

            /// The size of an encapsulation key.
            pub const PUBLIC_KEY_BYTES: usize = $public_bytes;
            /// The size of a ciphertext.
            pub const CIPHERTEXT_BYTES: usize = $ciphertext_bytes;

            /// Expands the decapsulation key of the seed `d || z`.
            fn private_key(
                seed: &[u8; 64],
            ) -> Result<CleansedKey<bssl_sys::$private>, BsslError> {
                // SAFETY: `key` is valid for writing a private key and `seed` is
                // valid for `seed.len()` bytes.
                CleansedKey::new(|key| unsafe {
                    bssl_sys::$from_seed(key, seed.as_ptr(), seed.len())
                })
            }

            /// Writes the encapsulation key of the seed `d || z` to `out`
            /// (`ML-KEM.KeyGen_internal(d, z)`).
            pub fn public_key_from_seed(
                seed: &[u8; 64],
                out: &mut [u8; PUBLIC_KEY_BYTES],
            ) -> Result<(), BsslError> {
                let private = private_key(seed)?;
                let mut public = MaybeUninit::<bssl_sys::$public>::uninit();
                // SAFETY: `private` is initialized and `public` is valid for
                // writing a public key, which this initializes.
                let public = unsafe {
                    bssl_sys::$public_from_private(public.as_mut_ptr(), private.as_ptr());
                    public.assume_init()
                };
                // SAFETY: `cbb` is an initialized `CBB` and `public` an initialized
                // public key.
                marshal_fixed(out, |cbb| unsafe { bssl_sys::$marshal(cbb, &public) })
            }

            /// Checks the encapsulation key `public_key` with BoringSSL's parsing
            /// (`EVP_PKEY_from_raw_public_key`: the modulus check of FIPS 203,
            /// Section 7.2), or [`BsslError::InvalidData`] if it fails.
            pub fn check_public_key(public_key: &[u8; PUBLIC_KEY_BYTES]) -> Result<(), BsslError> {
                // SAFETY: `$evp_pkey_alg` returns a static `EVP_PKEY_ALG`.
                EvpPkey::from_raw_public_key(unsafe { bssl_sys::$evp_pkey_alg() }, public_key)
                    .map(|_| ())
            }

            /// Encapsulates to the encapsulation key `public_key` with the
            /// randomness `entropy` (`ML-KEM.Encaps_internal(ek, m)`), or
            /// [`BsslError::InvalidData`] if `public_key` fails BoringSSL's
            /// parsing (the modulus check of FIPS 203, Section 7.2).
            ///
            /// The randomness goes through
            /// `EVP_KEM_encap_external_entropy_for_testing`, BoringSSL's only
            /// public derandomized encapsulation; the TPM draws `entropy` from
            /// its DRBG (TPM 2.0 Part 1), as the TCG reference does.
            pub fn encapsulate(
                public_key: &[u8; PUBLIC_KEY_BYTES],
                entropy: &[u8; 32],
                ciphertext_out: &mut [u8; CIPHERTEXT_BYTES],
                shared_secret_out: &mut [u8; 32],
            ) -> Result<(), BsslError> {
                // SAFETY: `$evp_pkey_alg` returns a static `EVP_PKEY_ALG`.
                let pkey = EvpPkey::from_raw_public_key(
                    unsafe { bssl_sys::$evp_pkey_alg() },
                    public_key,
                )?;
                // SAFETY: `$evp_kem` returns a static `EVP_KEM`; the output buffers
                // and `entropy` are valid for their lengths, and `pkey` is a valid
                // public key of the KEM's type.
                let res = unsafe {
                    bssl_sys::EVP_KEM_encap_external_entropy_for_testing(
                        bssl_sys::$evp_kem(),
                        ciphertext_out.as_mut_ptr(),
                        ciphertext_out.len(),
                        shared_secret_out.as_mut_ptr(),
                        shared_secret_out.len(),
                        pkey.as_ptr(),
                        entropy.as_ptr(),
                        entropy.len(),
                    )
                };
                if res == 1 { Ok(()) } else { Err(BsslError::Internal) }
            }

            /// Decapsulates `ciphertext` with the key of the seed `d || z`
            /// (`ML-KEM.Decaps`, with implicit rejection).
            pub fn decapsulate(
                seed: &[u8; 64],
                ciphertext: &[u8; CIPHERTEXT_BYTES],
                shared_secret_out: &mut [u8; 32],
            ) -> Result<(), BsslError> {
                let private = private_key(seed)?;
                // SAFETY: the buffers are valid for their lengths and `private` is
                // an initialized private key.
                let res = unsafe {
                    bssl_sys::$decap(
                        shared_secret_out.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        ciphertext.len(),
                        private.as_ptr(),
                    )
                };
                if res == 1 { Ok(()) } else { Err(BsslError::Internal) }
            }
        }
    };
}

mlkem_bindings!(
    /// ML-KEM-768 (`MLKEM768_*`).
    mlkem768,
    MLKEM768_private_key,
    MLKEM768_public_key,
    1184,
    1088,
    MLKEM768_private_key_from_seed,
    MLKEM768_public_from_private,
    MLKEM768_marshal_public_key,
    MLKEM768_decap,
    EVP_pkey_ml_kem_768,
    EVP_kem_ml_kem_768,
);

mlkem_bindings!(
    /// ML-KEM-1024 (`MLKEM1024_*`).
    mlkem1024,
    MLKEM1024_private_key,
    MLKEM1024_public_key,
    1568,
    1568,
    MLKEM1024_private_key_from_seed,
    MLKEM1024_public_from_private,
    MLKEM1024_marshal_public_key,
    MLKEM1024_decap,
    EVP_pkey_ml_kem_1024,
    EVP_kem_ml_kem_1024,
);

/// Defines a module with the ML-DSA bindings of one parameter set.
macro_rules! mldsa_bindings {
    (
        $(#[$doc:meta])* $module:ident,
        $private:ident, $public:ident, $prehash:ident, $public_bytes:expr,
        $from_seed:ident, $public_from_private:ident, $marshal:ident, $parse:ident,
        $prehash_init:ident, $prehash_update:ident, $prehash_finalize:ident,
        $verify:ident $(,)?
    ) => {
        $(#[$doc])*
        pub mod $module {
            use super::*;

            /// The size of a verification key.
            pub const PUBLIC_KEY_BYTES: usize = $public_bytes;

            /// Writes the verification key of the seed `xi` to `out`
            /// (`ML-DSA.KeyGen_internal(xi)`).
            pub fn public_key_from_seed(
                seed: &[u8; 32],
                out: &mut [u8; PUBLIC_KEY_BYTES],
            ) -> Result<(), BsslError> {
                // SAFETY: `key` is valid for writing a private key and `seed` is
                // valid for `seed.len()` bytes.
                let private = CleansedKey::<bssl_sys::$private>::new(|key| unsafe {
                    bssl_sys::$from_seed(key, seed.as_ptr(), seed.len())
                })?;
                // SAFETY: `public` is valid for writing a public key and `private`
                // is an initialized private key.
                let public = CleansedKey::<bssl_sys::$public>::new(|public| unsafe {
                    bssl_sys::$public_from_private(public, private.as_ptr())
                })?;
                // SAFETY: `cbb` is an initialized `CBB` and `public` an initialized
                // public key.
                marshal_fixed(out, |cbb| unsafe { bssl_sys::$marshal(cbb, public.as_ptr()) })
            }

            /// Parses the encoded verification key `public_key`, or
            /// [`BsslError::InvalidData`] if it does not parse (or has trailing data).
            fn parse_public_key(
                public_key: &[u8],
            ) -> Result<CleansedKey<bssl_sys::$public>, BsslError> {
                let mut cbs = MaybeUninit::<bssl_sys::CBS>::uninit();
                // SAFETY: `CBS_init` initializes `cbs` over `public_key`, which is
                // valid for `public_key.len()` bytes and outlives `cbs`.
                unsafe { bssl_sys::CBS_init(cbs.as_mut_ptr(), public_key.as_ptr(), public_key.len()) };
                // SAFETY: `public` is valid for writing a public key and `cbs` is
                // initialized.
                let public = CleansedKey::<bssl_sys::$public>::new(|public| unsafe {
                    bssl_sys::$parse(public, cbs.as_mut_ptr())
                })
                .map_err(|_| BsslError::InvalidData)?;
                // SAFETY: `cbs` is initialized.
                if unsafe { bssl_sys::CBS_len(cbs.as_ptr()) } != 0 {
                    return Err(BsslError::InvalidData);
                }
                Ok(public)
            }

            /// Checks that the encoded verification key `public_key` parses, or
            /// [`BsslError::InvalidData`].
            pub fn check_public_key(public_key: &[u8; PUBLIC_KEY_BYTES]) -> Result<(), BsslError> {
                parse_public_key(public_key).map(|_| ())
            }

            /// Computes the message representative `mu` of the concatenation of the
            /// `msg` slices for pure ML-DSA with the context string `context`
            /// (`ML-DSA.Sign`/`ML-DSA.Verify` up to `mu`, BoringSSL's
            /// `*_prehash_init`/`_update`/`_finalize`) and the encoded verification
            /// key `public_key`, or [`BsslError::InvalidData`] if the key does not
            /// parse or `context` is longer than 255 bytes.
            pub fn mu(
                public_key: &[u8; PUBLIC_KEY_BYTES],
                context: &[u8],
                msg: &[&[u8]],
                out: &mut [u8; 64],
            ) -> Result<(), BsslError> {
                let public = parse_public_key(public_key)?;
                let mut state = MaybeUninit::<bssl_sys::$prehash>::uninit();
                // SAFETY: `state` is valid for writing a pre-hashing state, `public` is
                // an initialized public key, and `context` is valid for its length.
                if unsafe {
                    bssl_sys::$prehash_init(
                        state.as_mut_ptr(),
                        public.as_ptr(),
                        context.as_ptr(),
                        context.len(),
                    )
                } != 1
                {
                    return Err(BsslError::InvalidData);
                }
                for part in msg {
                    // SAFETY: `state` was initialized by `$prehash_init` and `part` is
                    // valid for its length.
                    unsafe { bssl_sys::$prehash_update(state.as_mut_ptr(), part.as_ptr(), part.len()) };
                }
                // SAFETY: `state` is initialized and `out` has `MLDSA_MU_BYTES` (64) bytes.
                unsafe { bssl_sys::$prehash_finalize(out.as_mut_ptr(), state.as_mut_ptr()) };
                Ok(())
            }

            /// Verifies `signature` over the message representative `mu` with the
            /// encoded verification key `public_key` (`ML-DSA.Verify_internal`
            /// from line 8 on), or [`BsslError::InvalidData`] if the key does not
            /// parse or the signature is invalid.
            pub fn verify_mu(
                public_key: &[u8],
                mu: &[u8; 64],
                signature: &[u8],
            ) -> Result<(), BsslError> {
                let public = parse_public_key(public_key)?;
                // SAFETY: `public` is an initialized public key, and `signature`
                // and `mu` are valid for their lengths.
                let res = unsafe {
                    bssl_sys::$verify(public.as_ptr(), signature.as_ptr(), signature.len(), mu.as_ptr())
                };
                if res == 1 { Ok(()) } else { Err(BsslError::InvalidData) }
            }
        }
    };
}

mldsa_bindings!(
    /// ML-DSA-44 (`MLDSA44_*`).
    mldsa44,
    MLDSA44_private_key,
    MLDSA44_public_key,
    MLDSA44_prehash,
    1312,
    MLDSA44_private_key_from_seed,
    MLDSA44_public_from_private,
    MLDSA44_marshal_public_key,
    MLDSA44_parse_public_key,
    MLDSA44_prehash_init,
    MLDSA44_prehash_update,
    MLDSA44_prehash_finalize,
    MLDSA44_verify_message_representative,
);

mldsa_bindings!(
    /// ML-DSA-65 (`MLDSA65_*`).
    mldsa65,
    MLDSA65_private_key,
    MLDSA65_public_key,
    MLDSA65_prehash,
    1952,
    MLDSA65_private_key_from_seed,
    MLDSA65_public_from_private,
    MLDSA65_marshal_public_key,
    MLDSA65_parse_public_key,
    MLDSA65_prehash_init,
    MLDSA65_prehash_update,
    MLDSA65_prehash_finalize,
    MLDSA65_verify_message_representative,
);

mldsa_bindings!(
    /// ML-DSA-87 (`MLDSA87_*`).
    mldsa87,
    MLDSA87_private_key,
    MLDSA87_public_key,
    MLDSA87_prehash,
    2592,
    MLDSA87_private_key_from_seed,
    MLDSA87_public_from_private,
    MLDSA87_marshal_public_key,
    MLDSA87_parse_public_key,
    MLDSA87_prehash_init,
    MLDSA87_prehash_update,
    MLDSA87_prehash_finalize,
    MLDSA87_verify_message_representative,
);
