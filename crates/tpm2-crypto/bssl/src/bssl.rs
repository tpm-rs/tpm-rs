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
// HMAC-SHA1 Safe Binding over `bssl-sys`
// ============================================================================

/// Safe wrapper around BoringSSL's `HMAC_CTX` configured for HMAC-SHA1.
pub struct HmacSha1 {
    ctx: bssl_sys::HMAC_CTX,
}

impl HmacSha1 {
    /// Creates a new HMAC-SHA1 context initialized with the provided `key`.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, BsslError> {
        let mut ctx = MaybeUninit::<bssl_sys::HMAC_CTX>::uninit();
        // SAFETY:
        // - `ctx.as_mut_ptr()` is a valid pointer to uninitialized `HMAC_CTX` stack memory.
        // - `EVP_sha1()` returns a static, valid `EVP_MD` pointer.
        // - `key.as_ptr()` is non-null (even for empty slices in Rust) and valid for `key.len()` bytes.
        let res = unsafe {
            bssl_sys::HMAC_CTX_init(ctx.as_mut_ptr());
            let md = bssl_sys::EVP_sha1();
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

    /// Updates the HMAC-SHA1 state with `data`.
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

    /// Finalizes the HMAC-SHA1 computation and writes the 20-byte tag into `out`.
    pub fn finalize(mut self, out: &mut [u8; 20]) -> Result<(), BsslError> {
        let mut len: c_uint = 0;
        // SAFETY: `self.ctx` is an initialized `HMAC_CTX`, `out` has space for 20 bytes (SHA-1 digest size),
        // and `len` is a valid mutable pointer.
        let res = unsafe { bssl_sys::HMAC_Final(&mut self.ctx, out.as_mut_ptr(), &mut len) };
        if res == 1 && len == 20 {
            Ok(())
        } else {
            Err(BsslError::Internal)
        }
    }
}

impl Clone for HmacSha1 {
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

impl Drop for HmacSha1 {
    fn drop(&mut self) {
        // SAFETY: `self.ctx` was initialized by `HMAC_CTX_init` in `new_from_slice` or `clone`.
        unsafe {
            bssl_sys::HMAC_CTX_cleanup(&mut self.ctx);
        }
    }
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

    fn finalize(self, out: &mut [u8; 16]) -> Result<(), BsslError> {
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
            pub fn finalize(self, out: &mut [u8; 16]) -> Result<(), BsslError> {
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
// AES-CFB Safe Bindings over `bssl-sys`
// ============================================================================

/// Internal streaming AES-CFB-128 state wrapping BoringSSL's `AES_KEY` and `AES_cfb128_encrypt`.
#[derive(Clone)]
struct AesCfb {
    key: bssl_sys::AES_KEY,
    ivec: [u8; 16],
    prev_iv: [u8; 16],
    num: c_int,
    enc: c_int,
}

impl AesCfb {
    fn new(key_bytes: &[u8], iv: &[u8; 16], enc: c_int) -> Result<Self, BsslError> {
        let bits = (key_bytes.len() * 8) as c_uint;
        let mut aes_key = MaybeUninit::<bssl_sys::AES_KEY>::uninit();
        // SAFETY:
        // - In CFB mode, the block cipher is always used in the encryption direction (`E_K(IV)`),
        //   so both encryption (`AES_ENCRYPT`) and decryption (`AES_DECRYPT`) require `AES_set_encrypt_key`.
        // - `key_bytes` is valid for `bits / 8` bytes, and `aes_key` is valid uninitialized memory.
        let res = unsafe {
            bssl_sys::AES_set_encrypt_key(key_bytes.as_ptr(), bits, aes_key.as_mut_ptr())
        };
        // Note: `AES_set_encrypt_key` returns 0 on success and negative on error.
        if res == 0 {
            // SAFETY: `AES_set_encrypt_key` returned 0, so `aes_key` is initialized.
            Ok(Self {
                key: unsafe { aes_key.assume_init() },
                ivec: *iv,
                prev_iv: *iv,
                num: 0,
                enc,
            })
        } else {
            Err(BsslError::InvalidData)
        }
    }

    fn update(&mut self, mut data: &mut [u8]) -> Result<(), BsslError> {
        while !data.is_empty() {
            // 1. If we are in the middle of a partial 16-byte block (`self.num != 0`),
            //    feed up to the remaining bytes of that block first so `self.num` wraps to 0.
            if self.num != 0 {
                let rem_in_block = (16 - self.num as usize).min(data.len());
                let (chunk, rest) = data.split_at_mut(rem_in_block);
                // SAFETY: `chunk` is non-empty and valid for in-place encryption/decryption (`in == out`);
                // `self.key` is initialized; `self.ivec` is 16 bytes; `self.num` is in `1..16`.
                unsafe {
                    bssl_sys::AES_cfb128_encrypt(
                        chunk.as_ptr(),
                        chunk.as_mut_ptr(),
                        chunk.len(),
                        &self.key,
                        self.ivec.as_mut_ptr(),
                        &mut self.num,
                        self.enc,
                    );
                }
                data = rest;
                continue;
            }

            // 2. `self.num` is now 0. Process all full 16-byte blocks in bulk.
            if data.len() >= 16 {
                let full_len = (data.len() / 16) * 16;
                let (chunk, rest) = data.split_at_mut(full_len);
                // SAFETY: `chunk` is a non-empty multiple of 16 bytes; `self.key` is initialized.
                unsafe {
                    bssl_sys::AES_cfb128_encrypt(
                        chunk.as_ptr(),
                        chunk.as_mut_ptr(),
                        chunk.len(),
                        &self.key,
                        self.ivec.as_mut_ptr(),
                        &mut self.num,
                        self.enc,
                    );
                }
                debug_assert_eq!(self.num, 0);
                data = rest;
                continue;
            }

            // 3. `self.num` is 0 and `1 <= data.len() < 16`.
            //    Record `self.ivec` into `self.prev_iv` before `AES_cfb128_encrypt` overwrites
            //    `self.ivec` with the encrypted keystream block, so `finalize` can reconstruct
            //    the exact TPM 2.0 output IV (`[ciphertext[0..num], prev_iv[num..16]]`).
            self.prev_iv = self.ivec;
            // SAFETY: `data` is non-empty (`< 16` bytes); `self.key` is initialized.
            unsafe {
                bssl_sys::AES_cfb128_encrypt(
                    data.as_ptr(),
                    data.as_mut_ptr(),
                    data.len(),
                    &self.key,
                    self.ivec.as_mut_ptr(),
                    &mut self.num,
                    self.enc,
                );
            }
            break;
        }
        Ok(())
    }

    fn finalize(self, iv_out: &mut [u8; 16]) -> Result<(), BsslError> {
        *iv_out = self.ivec;
        if self.num > 0 {
            let n = self.num as usize;
            iv_out[n..].copy_from_slice(&self.prev_iv[n..]);
        }
        Ok(())
    }
}

impl Drop for AesCfb {
    fn drop(&mut self) {
        // SAFETY: `self.key`, `self.ivec`, and `self.prev_iv` are valid stack-allocated fields.
        unsafe {
            bssl_sys::OPENSSL_cleanse(
                ptr::from_mut(&mut self.key).cast::<c_void>(),
                core::mem::size_of_val(&self.key),
            );
            bssl_sys::OPENSSL_cleanse(self.ivec.as_mut_ptr().cast::<c_void>(), self.ivec.len());
            bssl_sys::OPENSSL_cleanse(
                self.prev_iv.as_mut_ptr().cast::<c_void>(),
                self.prev_iv.len(),
            );
        }
    }
}

macro_rules! impl_bssl_aes_cfb {
    ($name:ident, $key_len:literal, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name(AesCfb);

        impl $name {
            /// Creates a new AES-CFB encryptor initialized with `key` and `iv`.
            pub fn new_encrypt(key: &[u8; $key_len], iv: &[u8; 16]) -> Result<Self, BsslError> {
                AesCfb::new(key, iv, bssl_sys::AES_ENCRYPT).map(Self)
            }

            /// Creates a new AES-CFB decryptor initialized with `key` and `iv`.
            pub fn new_decrypt(key: &[u8; $key_len], iv: &[u8; 16]) -> Result<Self, BsslError> {
                AesCfb::new(key, iv, bssl_sys::AES_DECRYPT).map(Self)
            }

            /// Encrypts or decrypts `data` in place.
            pub fn update(&mut self, data: &mut [u8]) -> Result<(), BsslError> {
                self.0.update(data)
            }

            /// Finalizes the cipher stream and writes the resulting feedback IV to `iv_out`.
            pub fn finalize(self, iv_out: &mut [u8; 16]) -> Result<(), BsslError> {
                self.0.finalize(iv_out)
            }
        }
    };
}

impl_bssl_aes_cfb!(
    Aes128Cfb,
    16,
    "Safe wrapper around BoringSSL's `AES_cfb128_encrypt` for 128-bit keys."
);

impl_bssl_aes_cfb!(
    Aes192Cfb,
    24,
    "Safe wrapper around BoringSSL's `AES_cfb128_encrypt` for 192-bit keys."
);

impl_bssl_aes_cfb!(
    Aes256Cfb,
    32,
    "Safe wrapper around BoringSSL's `AES_cfb128_encrypt` for 256-bit keys."
);

// ============================================================================
// Internal RAII Helpers for BoringSSL Memory, Bignum, RSA, EVP, and EC
// ============================================================================

/// Scoped heap buffer allocated via `OPENSSL_malloc` that is cleansed and freed on drop.
struct ScopedBsslBuffer {
    ptr: NonNull<u8>,
    len: usize,
}

impl ScopedBsslBuffer {
    fn new(len: usize) -> Result<Self, BsslError> {
        let alloc_len = len.max(1);
        // SAFETY: `OPENSSL_malloc` allocates `alloc_len` bytes on the heap or returns NULL.
        let raw = unsafe { bssl_sys::OPENSSL_malloc(alloc_len) } as *mut u8;
        let ptr = NonNull::new(raw).ok_or(BsslError::Internal)?;
        // SAFETY: `ptr` is valid for `alloc_len` bytes.
        unsafe {
            ptr::write_bytes(ptr.as_ptr(), 0, alloc_len);
        }
        Ok(Self { ptr, len })
    }

    fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: `self.ptr` is valid and initialized for `self.len` bytes.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for ScopedBsslBuffer {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was allocated with `OPENSSL_malloc` with at least `self.len` bytes.
        unsafe {
            bssl_sys::OPENSSL_cleanse(self.ptr.as_ptr() as *mut c_void, self.len);
            bssl_sys::OPENSSL_free(self.ptr.as_ptr() as *mut c_void);
        }
    }
}

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

    /// Creates an RSA public key from big-endian modulus `n_bytes` and fixed exponent 65537.
    fn from_public_key_be(n_bytes: &[u8]) -> Result<Self, BsslError> {
        let n = Bignum::from_bytes_be(n_bytes)?;
        let e = Bignum::from_u32(65537)?;
        // SAFETY: `n.as_ptr()` and `e.as_ptr()` are valid `BIGNUM`s. `RSA_new_public_key` copies/adopts them.
        let rsa_ptr = unsafe { bssl_sys::RSA_new_public_key(n.as_ptr(), e.as_ptr()) };
        let ptr = NonNull::new(rsa_ptr).ok_or(BsslError::InvalidData)?;
        Ok(Self { ptr })
    }

    /// Parses an RSA private key from PKCS#8 DER or PKCS#1 RSAPrivateKey DER bytes.
    fn from_private_key_der(der: &[u8]) -> Result<Self, BsslError> {
        // SAFETY: `EVP_pkey_rsa()` returns a static `EVP_PKEY_ALG` pointer.
        let alg = unsafe { bssl_sys::EVP_pkey_rsa() };
        // SAFETY: `der.as_ptr()` is valid for `der.len()` bytes.
        let pkey_ptr =
            unsafe { bssl_sys::EVP_PKEY_from_private_key_info(der.as_ptr(), der.len(), &alg, 1) };
        if let Some(pkey_nn) = NonNull::new(pkey_ptr) {
            let pkey = EvpPkey { ptr: pkey_nn };
            // SAFETY: `pkey.as_ptr()` is a valid `EVP_PKEY`. `EVP_PKEY_get1_RSA` increments the refcount.
            let rsa_ptr = unsafe { bssl_sys::EVP_PKEY_get1_RSA(pkey.as_ptr()) };
            if let Some(ptr) = NonNull::new(rsa_ptr) {
                return Ok(Self { ptr });
            }
        }

        // Fallback to PKCS#1 RSAPrivateKey DER
        // SAFETY: `der.as_ptr()` is valid for `der.len()` bytes.
        let rsa_ptr = unsafe { bssl_sys::RSA_private_key_from_bytes(der.as_ptr(), der.len()) };
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

    /// Serializes the RSA private key into RFC 5208 PKCS#8 `PrivateKeyInfo` DER format.
    fn to_pkcs8_der(&self, out: &mut [u8]) -> Result<usize, BsslError> {
        let pkey = EvpPkey::from_rsa(self)?;
        let mut cbb = MaybeUninit::<bssl_sys::CBB>::uninit();
        // SAFETY: `CBB_init` initializes `cbb` with an initial capacity of 512 bytes.
        if unsafe { bssl_sys::CBB_init(cbb.as_mut_ptr(), 512) } != 1 {
            return Err(BsslError::Internal);
        }
        // SAFETY: `cbb` is initialized and `pkey.as_ptr()` is valid.
        let marshal_res =
            unsafe { bssl_sys::EVP_marshal_private_key(cbb.as_mut_ptr(), pkey.as_ptr()) };
        if marshal_res != 1 {
            // SAFETY: `cbb` is initialized and must be cleaned up on error.
            unsafe { bssl_sys::CBB_cleanup(cbb.as_mut_ptr()) };
            return Err(BsslError::Internal);
        }
        let mut buf_ptr: *mut u8 = ptr::null_mut();
        let mut buf_len: usize = 0;
        // SAFETY: `cbb` is finalized, transferring ownership of `buf_ptr` (allocated via `OPENSSL_malloc`) to caller.
        if unsafe { bssl_sys::CBB_finish(cbb.as_mut_ptr(), &mut buf_ptr, &mut buf_len) } != 1 {
            unsafe { bssl_sys::CBB_cleanup(cbb.as_mut_ptr()) };
            return Err(BsslError::Internal);
        }
        let res = if out.len() < buf_len {
            Err(BsslError::BufferTooSmall)
        } else {
            // SAFETY: `buf_ptr` is valid for `buf_len` bytes.
            let slice = unsafe { core::slice::from_raw_parts(buf_ptr, buf_len) };
            out[..buf_len].copy_from_slice(slice);
            Ok(buf_len)
        };
        // SAFETY: `buf_ptr` was allocated by `CBB_finish` via `OPENSSL_malloc` and must be cleansed and freed.
        unsafe {
            bssl_sys::OPENSSL_cleanse(buf_ptr as *mut c_void, buf_len);
            bssl_sys::OPENSSL_free(buf_ptr as *mut c_void);
        }
        res
    }
}

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
        TpmiAlgHash::Sha512 => Ok(bssl_sys::NID_sha512 as c_int),
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
            TpmiAlgHash::Sha512 => Ok(bssl_sys::EVP_sha512()),
            _ => Err(BsslError::Unsupported),
        }
    }
}
// ============================================================================
// RSA Safe Bindings over `bssl-sys`
// ============================================================================

/// Signs a pre-hashed digest using RSASSA-PKCS1-v1_5 (`RSA_sign`).
pub fn rsa_sign_pkcs1v15(
    private_key_der: &[u8],
    hash_alg: TpmiAlgHash,
    digest: &[u8],
    signature_out: &mut [u8],
) -> Result<usize, BsslError> {
    let nid = hash_alg_to_nid(hash_alg)?;
    let rsa = RsaKey::from_private_key_der(private_key_der)?;
    let key_size = rsa.size();
    if signature_out.len() < key_size {
        return Err(BsslError::BufferTooSmall);
    }

    let mut sig_len: c_uint = 0;
    // SAFETY:
    // - `digest.as_ptr()` is valid for `digest.len()` bytes.
    // - `signature_out.as_mut_ptr()` is valid for `key_size` bytes.
    // - `rsa.as_ptr()` is a valid private `RSA` key.
    let res = unsafe {
        bssl_sys::RSA_sign(
            nid,
            digest.as_ptr(),
            digest.len(),
            signature_out.as_mut_ptr(),
            &mut sig_len,
            rsa.as_ptr(),
        )
    };
    // `RSA_sign` fails if the key is too small for the `DigestInfo` encoding of `digest`.
    if res != 1 {
        return Err(BsslError::InvalidData);
    }
    Ok(sig_len as usize)
}

/// Verifies a pre-hashed digest against an RSASSA-PKCS1-v1_5 signature (`RSA_verify`).
pub fn rsa_verify_pkcs1v15(
    public_key_be: &[u8],
    hash_alg: TpmiAlgHash,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), BsslError> {
    let nid = hash_alg_to_nid(hash_alg)?;
    let rsa = RsaKey::from_public_key_be(public_key_be)?;
    // SAFETY:
    // - `digest.as_ptr()` is valid for `digest.len()` bytes.
    // - `signature.as_ptr()` is valid for `signature.len()` bytes.
    // - `rsa.as_ptr()` is a valid public `RSA` key.
    let res = unsafe {
        bssl_sys::RSA_verify(
            nid,
            digest.as_ptr(),
            digest.len(),
            signature.as_ptr(),
            signature.len(),
            rsa.as_ptr(),
        )
    };
    if res == 1 {
        Ok(())
    } else {
        Err(BsslError::InvalidData)
    }
}

/// Signs a pre-hashed digest using RSASSA-PSS with salt length equal to digest length (`RSA_sign_pss_mgf1`).
pub fn rsa_sign_pss(
    private_key_der: &[u8],
    hash_alg: TpmiAlgHash,
    digest: &[u8],
    signature_out: &mut [u8],
) -> Result<usize, BsslError> {
    let md = hash_alg_to_evp_md(hash_alg)?;
    let rsa = RsaKey::from_private_key_der(private_key_der)?;
    let key_size = rsa.size();
    if signature_out.len() < key_size {
        return Err(BsslError::BufferTooSmall);
    }
    #[cfg(feature = "reproducible")]
    if crate::replay::is_active() {
        return replay_padding::rsa_sign_pss(&rsa, md, digest, signature_out);
    }

    let mut sig_len: usize = 0;
    // SAFETY:
    // - `signature_out` has at least `key_size` bytes.
    // - `digest.as_ptr()` is valid for `digest.len()` bytes.
    // - `md` is a valid `EVP_MD` pointer.
    let res = unsafe {
        bssl_sys::RSA_sign_pss_mgf1(
            rsa.as_ptr(),
            &mut sig_len,
            signature_out.as_mut_ptr(),
            signature_out.len(),
            digest.as_ptr(),
            digest.len(),
            md,
            md,
            bssl_sys::RSA_PSS_SALTLEN_DIGEST,
        )
    };
    // `RSA_sign_pss_mgf1` fails if the key is too small for the digest and salt.
    if res != 1 {
        return Err(BsslError::InvalidData);
    }
    Ok(sig_len)
}

/// Verifies a pre-hashed digest against an RSASSA-PSS signature (`RSA_verify_pss_mgf1`).
///
/// Tries `RSA_PSS_SALTLEN_DIGEST` first, falling back to `RSA_PSS_SALTLEN_AUTO` for TPM 2.0 compatibility
/// with signatures that use maximal salt length.
pub fn rsa_verify_pss(
    public_key_be: &[u8],
    hash_alg: TpmiAlgHash,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), BsslError> {
    let md = hash_alg_to_evp_md(hash_alg)?;
    let rsa = RsaKey::from_public_key_be(public_key_be)?;
    // SAFETY: `signature.as_ptr()` and `digest.as_ptr()` are valid for their respective lengths.
    let res_digest = unsafe {
        bssl_sys::RSA_verify_pss_mgf1(
            rsa.as_ptr(),
            digest.as_ptr(),
            digest.len(),
            md,
            md,
            bssl_sys::RSA_PSS_SALTLEN_DIGEST,
            signature.as_ptr(),
            signature.len(),
        )
    };
    if res_digest == 1 {
        return Ok(());
    }

    // Fallback to auto salt length detection (`RSA_PSS_SALTLEN_AUTO`)
    // SAFETY: Same valid pointers as above.
    let res_auto = unsafe {
        bssl_sys::RSA_verify_pss_mgf1(
            rsa.as_ptr(),
            digest.as_ptr(),
            digest.len(),
            md,
            md,
            bssl_sys::RSA_PSS_SALTLEN_AUTO,
            signature.as_ptr(),
            signature.len(),
        )
    };
    if res_auto == 1 {
        Ok(())
    } else {
        Err(BsslError::InvalidData)
    }
}

/// Encrypts `data` using RSAES-PKCS1-v1_5 (`RSA_encrypt` with `RSA_PKCS1_PADDING`).
pub fn rsa_encrypt_pkcs1v15(
    public_key_be: &[u8],
    data: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<usize, BsslError> {
    let rsa = RsaKey::from_public_key_be(public_key_be)?;
    let key_size = rsa.size();
    if ciphertext_out.len() < key_size {
        return Err(BsslError::BufferTooSmall);
    }
    #[cfg(feature = "reproducible")]
    if crate::replay::is_active() {
        let em = replay_padding::pkcs1v15_type2(key_size, data)?;
        return rsa_encrypt_null(public_key_be, &em, ciphertext_out);
    }

    let mut out_len: usize = 0;
    // SAFETY:
    // - `ciphertext_out` is valid for `ciphertext_out.len() >= key_size` bytes.
    // - `data` is valid for `data.len()` bytes.
    let res = unsafe {
        bssl_sys::RSA_encrypt(
            rsa.as_ptr(),
            &mut out_len,
            ciphertext_out.as_mut_ptr(),
            ciphertext_out.len(),
            data.as_ptr(),
            data.len(),
            bssl_sys::RSA_PKCS1_PADDING as c_int,
        )
    };
    // `RSA_encrypt` fails if `data` is too large for PKCS#1 v1.5 padding with this key.
    if res != 1 {
        return Err(BsslError::InvalidData);
    }
    Ok(out_len)
}

/// Decrypts `ciphertext` using RSAES-PKCS1-v1_5 (`RSA_decrypt` with `RSA_PKCS1_PADDING`).
pub fn rsa_decrypt_pkcs1v15(
    private_key_der: &[u8],
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
) -> Result<usize, BsslError> {
    let rsa = RsaKey::from_private_key_der(private_key_der)?;
    let key_size = rsa.size();
    let mut temp_buf = ScopedBsslBuffer::new(key_size)?;
    let mut out_len: usize = 0;

    // SAFETY:
    // - `temp_buf` is valid for `key_size` bytes (BoringSSL requires `max_out >= RSA_size`).
    // - `ciphertext` is valid for `ciphertext.len()` bytes.
    let res = unsafe {
        bssl_sys::RSA_decrypt(
            rsa.as_ptr(),
            &mut out_len,
            temp_buf.as_mut_ptr(),
            key_size,
            ciphertext.as_ptr(),
            ciphertext.len(),
            bssl_sys::RSA_PKCS1_PADDING as c_int,
        )
    };
    if res != 1 {
        return Err(BsslError::InvalidData);
    }
    if plaintext_out.len() < out_len {
        return Err(BsslError::BufferTooSmall);
    }
    plaintext_out[..out_len].copy_from_slice(&temp_buf.as_slice()[..out_len]);
    Ok(out_len)
}

/// Encrypts `data` using RSA-OAEP with the specified hash algorithm and label.
pub fn rsa_encrypt_oaep(
    hash_alg: TpmiAlgHash,
    public_key_be: &[u8],
    data: &[u8],
    label: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<usize, BsslError> {
    let _label_str = core::str::from_utf8(label).map_err(|_| BsslError::InvalidData)?;
    let md = hash_alg_to_evp_md(hash_alg)?;
    let rsa = RsaKey::from_public_key_be(public_key_be)?;
    let key_size = rsa.size();
    if ciphertext_out.len() < key_size {
        return Err(BsslError::BufferTooSmall);
    }
    #[cfg(feature = "reproducible")]
    if crate::replay::is_active() {
        let em = replay_padding::oaep(md, key_size, data, label)?;
        return rsa_encrypt_null(public_key_be, &em, ciphertext_out);
    }

    let pkey = EvpPkey::from_rsa(&rsa)?;
    let ctx = EvpPkeyCtx::new(&pkey)?;

    // SAFETY: `ctx.as_ptr()` is a valid `EVP_PKEY_CTX`.
    unsafe {
        if bssl_sys::EVP_PKEY_encrypt_init(ctx.as_ptr()) != 1
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
        unsafe {
            ptr::copy_nonoverlapping(label.as_ptr(), label_ptr, label.len());
            if bssl_sys::EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.as_ptr(), label_ptr, label.len()) != 1
            {
                bssl_sys::OPENSSL_free(label_ptr as *mut c_void);
                return Err(BsslError::Internal);
            }
        }
    }

    let mut out_len = ciphertext_out.len();
    // SAFETY: `ciphertext_out` is valid for `out_len` bytes and `data` is valid for `data.len()` bytes.
    let res = unsafe {
        bssl_sys::EVP_PKEY_encrypt(
            ctx.as_ptr(),
            ciphertext_out.as_mut_ptr(),
            &mut out_len,
            data.as_ptr(),
            data.len(),
        )
    };
    // `EVP_PKEY_encrypt` fails if `data` is too large for OAEP padding with this key.
    if res != 1 {
        return Err(BsslError::InvalidData);
    }
    Ok(out_len)
}

/// Decrypts `ciphertext` using RSA-OAEP with the specified hash algorithm and label.
pub fn rsa_decrypt_oaep(
    hash_alg: TpmiAlgHash,
    private_key_der: &[u8],
    ciphertext: &[u8],
    label: &[u8],
    plaintext_out: &mut [u8],
) -> Result<usize, BsslError> {
    let _label_str = core::str::from_utf8(label).map_err(|_| BsslError::InvalidData)?;
    let md = hash_alg_to_evp_md(hash_alg)?;
    let rsa = RsaKey::from_private_key_der(private_key_der)?;
    let key_size = rsa.size();
    let pkey = EvpPkey::from_rsa(&rsa)?;
    let ctx = EvpPkeyCtx::new(&pkey)?;

    // SAFETY: `ctx.as_ptr()` is a valid `EVP_PKEY_CTX`.
    unsafe {
        if bssl_sys::EVP_PKEY_decrypt_init(ctx.as_ptr()) != 1
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
        unsafe {
            ptr::copy_nonoverlapping(label.as_ptr(), label_ptr, label.len());
            if bssl_sys::EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.as_ptr(), label_ptr, label.len()) != 1
            {
                bssl_sys::OPENSSL_free(label_ptr as *mut c_void);
                return Err(BsslError::Internal);
            }
        }
    }

    let mut temp_buf = ScopedBsslBuffer::new(key_size)?;
    let mut out_len = key_size;
    // SAFETY: `temp_buf` is valid for `key_size` bytes and `ciphertext` is valid for `ciphertext.len()` bytes.
    let res = unsafe {
        bssl_sys::EVP_PKEY_decrypt(
            ctx.as_ptr(),
            temp_buf.as_mut_ptr(),
            &mut out_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        )
    };
    // `EVP_PKEY_decrypt` fails if the ciphertext, its padding, or the label is invalid.
    if res != 1 {
        return Err(BsslError::InvalidData);
    }
    if plaintext_out.len() < out_len {
        return Err(BsslError::BufferTooSmall);
    }
    plaintext_out[..out_len].copy_from_slice(&temp_buf.as_slice()[..out_len]);
    Ok(out_len)
}

/// Raw modular exponentiation $c = m^e \bmod n$ (`RSA_encrypt` with `RSA_NO_PADDING`).
pub fn rsa_encrypt_null(
    public_key_be: &[u8],
    data: &[u8],
    ciphertext_out: &mut [u8],
) -> Result<usize, BsslError> {
    let rsa = RsaKey::from_public_key_be(public_key_be)?;
    let mod_len = rsa.size();
    let m = Bignum::from_bytes_be(data)?;

    // Verify m < n
    // SAFETY: `rsa.as_ptr()` is a valid `RSA` struct and `m.as_ptr()` is a valid `BIGNUM`.
    let n_ptr = unsafe { bssl_sys::RSA_get0_n(rsa.as_ptr()) };
    if n_ptr.is_null() || unsafe { bssl_sys::BN_cmp(m.as_ptr(), n_ptr) } >= 0 {
        return Err(BsslError::InvalidData);
    }

    if ciphertext_out.len() < mod_len {
        return Err(BsslError::BufferTooSmall);
    }

    let mut padded_in = ScopedBsslBuffer::new(mod_len)?;
    // SAFETY: `padded_in` has `mod_len` bytes and `m < n`, so `m` fits in `mod_len` bytes.
    if unsafe { bssl_sys::BN_bn2bin_padded(padded_in.as_mut_ptr(), mod_len, m.as_ptr()) } != 1 {
        return Err(BsslError::InvalidData);
    }

    let mut out_len: usize = 0;
    // SAFETY: Both `padded_in` and `ciphertext_out` are valid for `mod_len` bytes.
    let res = unsafe {
        bssl_sys::RSA_encrypt(
            rsa.as_ptr(),
            &mut out_len,
            ciphertext_out.as_mut_ptr(),
            mod_len,
            padded_in.as_ptr(),
            mod_len,
            bssl_sys::RSA_NO_PADDING as c_int,
        )
    };
    if res != 1 || out_len != mod_len {
        return Err(BsslError::Internal);
    }
    Ok(mod_len)
}

/// Raw modular exponentiation $m = c^d \bmod n$ (`RSA_decrypt` with `RSA_NO_PADDING`).
pub fn rsa_decrypt_null(
    private_key_der: &[u8],
    ciphertext: &[u8],
    plaintext_out: &mut [u8],
) -> Result<usize, BsslError> {
    let rsa = RsaKey::from_private_key_der(private_key_der)?;
    let mod_len = rsa.size();
    let c = Bignum::from_bytes_be(ciphertext)?;

    // Verify c < n
    // SAFETY: `rsa.as_ptr()` is a valid `RSA` struct and `c.as_ptr()` is a valid `BIGNUM`.
    let n_ptr = unsafe { bssl_sys::RSA_get0_n(rsa.as_ptr()) };
    if n_ptr.is_null() || unsafe { bssl_sys::BN_cmp(c.as_ptr(), n_ptr) } >= 0 {
        return Err(BsslError::InvalidData);
    }

    if plaintext_out.len() < mod_len {
        return Err(BsslError::BufferTooSmall);
    }

    let mut padded_in = ScopedBsslBuffer::new(mod_len)?;
    // SAFETY: `padded_in` has `mod_len` bytes and `c < n`, so `c` fits in `mod_len` bytes.
    if unsafe { bssl_sys::BN_bn2bin_padded(padded_in.as_mut_ptr(), mod_len, c.as_ptr()) } != 1 {
        return Err(BsslError::InvalidData);
    }

    let mut out_len: usize = 0;
    // SAFETY: Both `padded_in` and `plaintext_out` are valid for `mod_len` bytes.
    let res = unsafe {
        bssl_sys::RSA_decrypt(
            rsa.as_ptr(),
            &mut out_len,
            plaintext_out.as_mut_ptr(),
            mod_len,
            padded_in.as_ptr(),
            mod_len,
            bssl_sys::RSA_NO_PADDING as c_int,
        )
    };
    if res != 1 || out_len != mod_len {
        return Err(BsslError::Internal);
    }
    Ok(mod_len)
}

/// Imports an RSA private key from big-endian `(modulus, prime_p, exponent)` and serializes it to PKCS#8 DER.
pub fn rsa_import_private_key(
    modulus: &[u8],
    prime_p: &[u8],
    exponent: u32,
    private_key_out: &mut [u8],
) -> Result<usize, BsslError> {
    if exponent < 3 || exponent.is_multiple_of(2) {
        return Err(BsslError::InvalidData);
    }

    let n = Bignum::from_bytes_be(modulus)?;
    let p = Bignum::from_bytes_be(prime_p)?;
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

    if !rem.is_zero() || !q.is_odd() || q.num_bits() <= 1 || p.num_bits().abs_diff(q.num_bits()) > 1
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

    rsa_construct_and_serialize_pkcs8(&n, &p, &q, &e, &ctx, private_key_out)
}

/// Derives CRT parameters `(d, dmp1, dmq1, iqmp)` from `(n, p, q, e)` and serializes the RSA key to PKCS#8 DER.
fn rsa_construct_and_serialize_pkcs8(
    n: &Bignum,
    p: &Bignum,
    q: &Bignum,
    e: &Bignum,
    ctx: &BnCtx,
    private_key_out: &mut [u8],
) -> Result<usize, BsslError> {
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

    // Construct RSA private key and serialize to PKCS#8 DER
    // SAFETY: All `BIGNUM` parameters are valid and non-null.
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
    let rsa = RsaKey {
        ptr: NonNull::new(rsa_ptr).ok_or(BsslError::InvalidData)?,
    };
    rsa.to_pkcs8_der(private_key_out)
}

/// Generates a random prime of `prime_bits` bits from `rng` using BoringSSL's `BN_primality_test`.
fn generate_deterministic_prime(
    rng: &mut rand_chacha::ChaCha20Rng,
    prime_bits: usize,
    ctx: &BnCtx,
) -> Result<Bignum, BsslError> {
    use rand_core::RngCore as _;
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

    loop {
        // Check gcd(cand - 1, 65537) == 1 (equivalent to cand % 65537 != 1 since 65537 is prime)
        // SAFETY: `cand.as_ptr()` is a valid non-null `BIGNUM`.
        let rem = unsafe { bssl_sys::BN_mod_word(cand.as_ptr(), 65537) };
        if rem != 1 && cand.is_prime(ctx)? {
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

/// Generates an RSA key pair of `bits` bits (e.g. 1024, 2048, 3072, 4096).
///
/// - When `seed` is `None`, uses BoringSSL's `RSA_generate_key_ex` directly.
/// - When `seed` is `Some(seed_bytes)`, derives a deterministic byte stream via SHA-256 + `ChaCha20Rng`
///   and generates prime factors using BoringSSL's `BIGNUM` and `BN_primality_test`.
pub fn rsa_generate_key(
    bits: usize,
    public_key_out: &mut [u8],
    private_key_out: &mut [u8],
    seed: Option<&[u8]>,
) -> Result<(usize, usize), BsslError> {
    if !(1024..=4096).contains(&bits) || !bits.is_multiple_of(128) {
        return Err(BsslError::Unsupported);
    }
    let mod_len = bits / 8;
    if public_key_out.len() < mod_len || private_key_out.len() < bits / 2 {
        return Err(BsslError::BufferTooSmall);
    }

    let e = Bignum::from_u32(65537)?;

    // Under replay, draw the key-generation seed from the replay stream so the
    // key is reproducible.
    #[cfg(feature = "reproducible")]
    let replay_seed;
    #[cfg(feature = "reproducible")]
    let seed = match seed {
        None if crate::replay::is_active() => {
            let mut s = [0u8; 32];
            crate::rand_bytes(&mut s);
            replay_seed = s;
            Some(&replay_seed[..])
        }
        other => other,
    };

    match seed {
        None => {
            let rsa = RsaKey::new()?;
            // SAFETY: `rsa.as_ptr()` and `e.as_ptr()` are valid non-null pointers.
            let res = unsafe {
                bssl_sys::RSA_generate_key_ex(
                    rsa.as_ptr(),
                    bits as c_int,
                    e.as_ptr(),
                    ptr::null_mut(),
                )
            };
            if res != 1 {
                return Err(BsslError::Internal);
            }
            // SAFETY: `rsa.as_ptr()` is a valid initialized `RSA` key.
            let n_ptr = unsafe { bssl_sys::RSA_get0_n(rsa.as_ptr()) };
            if n_ptr.is_null()
                || unsafe {
                    bssl_sys::BN_bn2bin_padded(public_key_out.as_mut_ptr(), mod_len, n_ptr)
                } != 1
            {
                return Err(BsslError::Internal);
            }
            let priv_len = rsa.to_pkcs8_der(private_key_out)?;
            Ok((mod_len, priv_len))
        }
        Some(seed_bytes) => {
            let seed_32 = bssl_crypto::digest::Sha256::hash(seed_bytes);
            use rand_chacha::rand_core::SeedableRng as _;
            let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed_32);
            let ctx = BnCtx::new()?;
            let prime_bits = bits / 2;

            for _ in 0..32 {
                let mut p = generate_deterministic_prime(&mut rng, prime_bits, &ctx)?;
                let mut q = generate_deterministic_prime(&mut rng, prime_bits, &ctx)?;
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
                if unsafe { bssl_sys::BN_mul(n.as_ptr(), p.as_ptr(), q.as_ptr(), ctx.as_ptr()) }
                    != 1
                {
                    return Err(BsslError::Internal);
                }
                if n.num_bits() != bits {
                    continue;
                }

                match rsa_construct_and_serialize_pkcs8(&n, &p, &q, &e, &ctx, private_key_out) {
                    Ok(priv_len) => {
                        // SAFETY: `public_key_out` has at least `mod_len` bytes, and `n` has `bits` bits.
                        if unsafe {
                            bssl_sys::BN_bn2bin_padded(
                                public_key_out.as_mut_ptr(),
                                mod_len,
                                n.as_ptr(),
                            )
                        } != 1
                        {
                            return Err(BsslError::Internal);
                        }
                        return Ok((mod_len, priv_len));
                    }
                    Err(BsslError::BufferTooSmall) => return Err(BsslError::BufferTooSmall),
                    Err(_) => continue,
                }
            }
            Err(BsslError::Internal)
        }
    }
}

/// Extracts the first prime factor `p` from a PKCS#8 DER RSA private key as big-endian bytes.
pub fn rsa_private_key_to_prime_p(
    private_key_der: &[u8],
    prime_p_out: &mut [u8],
) -> Result<usize, BsslError> {
    let rsa = RsaKey::from_private_key_der(private_key_der)?;
    // SAFETY: `rsa.as_ptr()` is a valid private `RSA` key.
    let p_ptr = unsafe { bssl_sys::RSA_get0_p(rsa.as_ptr()) };
    if p_ptr.is_null() {
        return Err(BsslError::InvalidData);
    }
    // SAFETY: `p_ptr` is a valid non-null `BIGNUM`.
    let p_len = unsafe { bssl_sys::BN_num_bytes(p_ptr) as usize };
    if prime_p_out.len() < p_len {
        return Err(BsslError::BufferTooSmall);
    }
    // SAFETY: `prime_p_out` is valid for `p_len` bytes.
    if unsafe { bssl_sys::BN_bn2bin_padded(prime_p_out.as_mut_ptr(), p_len, p_ptr) } != 1 {
        return Err(BsslError::Internal);
    }
    Ok(p_len)
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
    #[cfg(feature = "reproducible")]
    if crate::replay::is_active() {
        return ecdsa_sign_replay(group, &key, digest, &mut signature_out[..sig_size]);
    }
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

/// ECDSA signing with a nonce drawn from the thread's replay generator.
///
/// Uses BoringSSL's `ECDSA_sign_with_nonce_and_leak_private_key_for_testing`;
/// nonces that are zero or not below the group order are redrawn.
#[cfg(feature = "reproducible")]
fn ecdsa_sign_replay(
    group: EcGroup,
    key: &EcKey,
    digest: &[u8],
    signature_out: &mut [u8],
) -> Result<usize, BsslError> {
    let coord_len = group.coord_len();
    let mut nonce = [0u8; 66];
    for _ in 0..100 {
        crate::rand_bytes(&mut nonce[..coord_len]);
        if group == EcGroup::P521 {
            // The P-521 order has 521 bits; keep candidates within 66 bytes' top bit.
            nonce[0] &= 0x01;
        }
        // SAFETY:
        // - `digest` and `nonce[..coord_len]` are valid for their lengths.
        // - `key.as_ptr()` is a valid private `EC_KEY`.
        let sig = unsafe {
            bssl_sys::ECDSA_sign_with_nonce_and_leak_private_key_for_testing(
                digest.as_ptr(),
                digest.len(),
                key.as_ptr(),
                nonce.as_ptr(),
                coord_len,
            )
        };
        if sig.is_null() {
            continue;
        }
        let (r_out, s_out) = signature_out.split_at_mut(coord_len);
        // SAFETY: `sig` is a valid `ECDSA_SIG` owned here; `r`/`s` are borrowed from it and
        // fit in `coord_len` bytes (both are below the group order). `sig` is freed once.
        let ok = unsafe {
            let r = bssl_sys::ECDSA_SIG_get0_r(sig);
            let s = bssl_sys::ECDSA_SIG_get0_s(sig);
            let ok = bssl_sys::BN_bn2bin_padded(r_out.as_mut_ptr(), coord_len, r) == 1
                && bssl_sys::BN_bn2bin_padded(s_out.as_mut_ptr(), coord_len, s) == 1;
            bssl_sys::ECDSA_SIG_free(sig);
            ok
        };
        return if ok {
            Ok(2 * coord_len)
        } else {
            Err(BsslError::Internal)
        };
    }
    Err(BsslError::Internal)
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
            ec_point_multiply_generator(group, &cand[..coord_len], x_out, y_out)?;
            private_key_out[..coord_len].copy_from_slice(&cand[..coord_len]);
            return Ok((2 * coord_len, coord_len));
        }
    }
    Err(BsslError::Internal)
}

/// RSA encoding with randomness drawn from the thread's replay generator
/// (RFC 8017), used instead of BoringSSL's internal padding when a
/// `replay::ReplayRng` scope is active.
#[cfg(feature = "reproducible")]
mod replay_padding {
    use super::*;
    use std::vec::Vec;

    /// `Hash(parts[0] || parts[1] || ...)` with `md`.
    fn digest(md: *const bssl_sys::EVP_MD, parts: &[&[u8]]) -> Result<Vec<u8>, BsslError> {
        let input = parts.concat();
        let mut out = [0u8; 64];
        let mut len: c_uint = 0;
        // SAFETY: `input` is valid for its length, `out` holds the largest digest
        // (64 bytes) and `md` is a valid `EVP_MD`.
        let ok = unsafe {
            bssl_sys::EVP_Digest(
                input.as_ptr() as *const c_void,
                input.len(),
                out.as_mut_ptr(),
                &mut len,
                md,
                ptr::null_mut(),
            )
        };
        if ok != 1 {
            return Err(BsslError::Internal);
        }
        Ok(out[..len as usize].to_vec())
    }

    /// MGF1 (RFC 8017 B.2.1) mask of `len` bytes.
    fn mgf1(md: *const bssl_sys::EVP_MD, seed: &[u8], len: usize) -> Result<Vec<u8>, BsslError> {
        let mut mask = Vec::with_capacity(len + 64);
        let mut counter: u32 = 0;
        while mask.len() < len {
            mask.extend(digest(md, &[seed, &counter.to_be_bytes()])?);
            counter += 1;
        }
        mask.truncate(len);
        Ok(mask)
    }

    fn random(len: usize) -> Vec<u8> {
        let mut v = std::vec![0u8; len];
        crate::rand_bytes(&mut v);
        v
    }

    /// EME-OAEP encoding (RFC 8017 7.1.1) to `k` bytes; MGF1 uses the same hash.
    pub(super) fn oaep(
        md: *const bssl_sys::EVP_MD,
        k: usize,
        message: &[u8],
        label: &[u8],
    ) -> Result<Vec<u8>, BsslError> {
        let l_hash = digest(md, &[label])?;
        let h_len = l_hash.len();
        if k < 2 * h_len + 2 || message.len() > k - 2 * h_len - 2 {
            return Err(BsslError::InvalidData);
        }
        let mut db = l_hash;
        db.resize(k - message.len() - h_len - 2, 0);
        db.push(0x01);
        db.extend_from_slice(message);
        let seed = random(h_len);
        let db_mask = mgf1(md, &seed, db.len())?;
        let masked_db: Vec<u8> = db.iter().zip(&db_mask).map(|(a, b)| a ^ b).collect();
        let seed_mask = mgf1(md, &masked_db, h_len)?;
        let mut em = std::vec![0u8];
        em.extend(seed.iter().zip(&seed_mask).map(|(a, b)| a ^ b));
        em.extend(masked_db);
        Ok(em)
    }

    /// EME-PKCS1-v1_5 encoding (RFC 8017 7.2.1) to `k` bytes.
    pub(super) fn pkcs1v15_type2(k: usize, message: &[u8]) -> Result<Vec<u8>, BsslError> {
        if k < 11 || message.len() > k - 11 {
            return Err(BsslError::InvalidData);
        }
        let mut em = std::vec![0x00, 0x02];
        let mut byte = [0u8; 1];
        while em.len() < k - message.len() - 1 {
            crate::rand_bytes(&mut byte);
            if byte[0] != 0 {
                em.push(byte[0]);
            }
        }
        em.push(0x00);
        em.extend_from_slice(message);
        Ok(em)
    }

    /// RSASSA-PSS signature (RFC 8017 8.1.1) with salt length = digest length
    /// and MGF1 with the same hash, matching `RSA_PSS_SALTLEN_DIGEST`.
    pub(super) fn rsa_sign_pss(
        rsa: &RsaKey,
        md: *const bssl_sys::EVP_MD,
        m_hash: &[u8],
        signature_out: &mut [u8],
    ) -> Result<usize, BsslError> {
        let k = rsa.size();
        // SAFETY: `rsa` holds a valid key with a modulus.
        let mod_bits =
            unsafe { bssl_sys::BN_num_bits(bssl_sys::RSA_get0_n(rsa.as_ptr())) } as usize;
        let em_bits = mod_bits - 1;
        let em_len = em_bits.div_ceil(8);
        let h_len = m_hash.len();
        if em_len < 2 * h_len + 2 {
            return Err(BsslError::InvalidData);
        }
        let salt = random(h_len);
        let h = digest(md, &[&[0u8; 8], m_hash, &salt])?;
        let mut db = std::vec![0u8; em_len - 2 * h_len - 2];
        db.push(0x01);
        db.extend_from_slice(&salt);
        let db_mask = mgf1(md, &h, db.len())?;
        let mut masked_db: Vec<u8> = db.iter().zip(&db_mask).map(|(a, b)| a ^ b).collect();
        masked_db[0] &= 0xFF >> (8 * em_len - em_bits);
        // The private-key input is the k-byte big-endian encoding of EM.
        let mut input = std::vec![0u8; k - em_len];
        input.extend(masked_db);
        input.extend(h);
        input.push(0xBC);

        let mut out_len: usize = 0;
        // SAFETY: `signature_out` holds at least `k` bytes (checked by the caller) and
        // `input` is exactly `k` bytes, as `RSA_NO_PADDING` requires.
        let res = unsafe {
            bssl_sys::RSA_sign_raw(
                rsa.as_ptr(),
                &mut out_len,
                signature_out.as_mut_ptr(),
                signature_out.len(),
                input.as_ptr(),
                input.len(),
                bssl_sys::RSA_NO_PADDING as c_int,
            )
        };
        if res != 1 {
            return Err(BsslError::Internal);
        }
        Ok(out_len)
    }
}

#[cfg(all(test, feature = "reproducible"))]
mod replay_tests {
    use super::*;
    use crate::replay::ReplayRng;

    /// Runs `f` twice, each time in a fresh replay scope with the same seed.
    fn twice<T>(f: impl Fn() -> T) -> (T, T) {
        (ReplayRng::new(42).scope(&f), ReplayRng::new(42).scope(&f))
    }

    fn rsa_key() -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
        let (mut public, mut private) = ([0u8; 256], [0u8; 2048]);
        let (n, p) = rsa_generate_key(2048, &mut public, &mut private, None).unwrap();
        (public[..n].to_vec(), private[..p].to_vec())
    }

    #[test]
    fn rsa_keygen_is_reproducible() {
        let (a, b) = twice(rsa_key);
        assert_eq!(a, b);
    }

    #[test]
    fn rsa_padding_is_reproducible_and_valid() {
        let (public, private) = ReplayRng::new(1).scope(rsa_key);
        let digest = [0x5Au8; 32];
        let mut out = [0u8; 256];

        let (s1, s2) = twice(|| {
            let mut sig = [0u8; 256];
            let n = rsa_sign_pss(&private, TpmiAlgHash::Sha256, &digest, &mut sig).unwrap();
            sig[..n].to_vec()
        });
        assert_eq!(s1, s2);
        rsa_verify_pss(&public, TpmiAlgHash::Sha256, &digest, &s1).unwrap();

        let (c1, c2) = twice(|| {
            let mut ct = [0u8; 256];
            let n = rsa_encrypt_oaep(
                TpmiAlgHash::Sha256,
                &public,
                b"secret",
                b"IDENTITY\0",
                &mut ct,
            )
            .unwrap();
            ct[..n].to_vec()
        });
        assert_eq!(c1, c2);
        let n =
            rsa_decrypt_oaep(TpmiAlgHash::Sha256, &private, &c1, b"IDENTITY\0", &mut out).unwrap();
        assert_eq!(&out[..n], b"secret");

        let (c1, c2) = twice(|| {
            let mut ct = [0u8; 256];
            let n = rsa_encrypt_pkcs1v15(&public, b"secret", &mut ct).unwrap();
            ct[..n].to_vec()
        });
        assert_eq!(c1, c2);
        let n = rsa_decrypt_pkcs1v15(&private, &c1, &mut out).unwrap();
        assert_eq!(&out[..n], b"secret");
    }

    #[test]
    fn ecdsa_is_reproducible_and_valid() {
        for group in [EcGroup::P256, EcGroup::P384, EcGroup::P521] {
            let len = group.coord_len();
            let (key, _) = twice(|| {
                let (mut public, mut private) = ([0u8; 132], [0u8; 66]);
                ec_generate_key(group, &mut crate::BsslRng, &mut public, &mut private).unwrap();
                (public[..2 * len].to_vec(), private[..len].to_vec())
            });
            let digest = [0x11u8; 32];
            let (s1, s2) = twice(|| {
                let mut sig = [0u8; 132];
                let n = ecdsa_sign(group, &key.1, &digest, &mut sig).unwrap();
                sig[..n].to_vec()
            });
            assert_eq!(s1, s2);
            ecdsa_verify(group, &key.0, &digest, &s1).unwrap();
        }
    }
}
