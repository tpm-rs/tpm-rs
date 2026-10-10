//! Safe wrappers over `bssl-sys` FFI primitives.

#![allow(unsafe_code)]

use alloc::boxed::Box;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};
use rand_chacha::rand_core::RngCore;
use tpm2::TpmiAlgHash;
use tpm2::crypto::CryptoError;

const fn u32_to_usize(val: u32) -> usize {
    val as usize
}

/// Fills `dest` with cryptographically secure random bytes from BoringSSL's CSPRNG.
pub fn rand_bytes(dest: &mut [u8]) {
    bssl_crypto::rand_bytes(dest);
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
    pub fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
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
            Err(CryptoError::Internal)
        }
    }

    /// Updates the HMAC-SHA1 state with `data`.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if data.is_empty() {
            return Ok(());
        }
        // SAFETY: `self.ctx` is an initialized `HMAC_CTX`, and `data` is valid for `data.len()` bytes.
        let res = unsafe { bssl_sys::HMAC_Update(&mut self.ctx, data.as_ptr(), data.len()) };
        if res == 1 {
            Ok(())
        } else {
            Err(CryptoError::Internal)
        }
    }

    /// Finalizes the HMAC-SHA1 computation and writes the 20-byte tag into `out`.
    pub fn finalize(mut self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        let mut len: c_uint = 0;
        // SAFETY: `self.ctx` is an initialized `HMAC_CTX`, `out` has space for 20 bytes (SHA-1 digest size),
        // and `len` is a valid mutable pointer.
        let res = unsafe { bssl_sys::HMAC_Final(&mut self.ctx, out.as_mut_ptr(), &mut len) };
        if res == 1 && len == 20 {
            Ok(())
        } else {
            Err(CryptoError::Internal)
        }
    }
}

impl Clone for HmacSha1 {
    fn clone(&self) -> Self {
        let mut ctx = MaybeUninit::<bssl_sys::HMAC_CTX>::uninit();
        // SAFETY: `ctx` is initialized by `HMAC_CTX_init`, and `self.ctx` is a valid initialized `HMAC_CTX`.
        let res = unsafe {
            bssl_sys::HMAC_CTX_init(ctx.as_mut_ptr());
            bssl_sys::HMAC_CTX_copy_ex(ctx.as_mut_ptr(), &self.ctx)
        };
        assert_eq!(res, 1, "bssl_sys::HMAC_CTX_copy_ex failed");
        // SAFETY: `HMAC_CTX_copy_ex` succeeded.
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
    fn new(key: &[u8], cipher: *const bssl_sys::EVP_CIPHER) -> Result<Self, CryptoError> {
        // SAFETY: `CMAC_CTX_new` allocates a new `CMAC_CTX` on the heap or returns null on failure.
        let ptr = unsafe { bssl_sys::CMAC_CTX_new() };
        let non_null = NonNull::new(ptr).ok_or(CryptoError::Internal)?;
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
            Err(CryptoError::Internal)
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if data.is_empty() {
            return Ok(());
        }
        // SAFETY: `self.0` is an initialized `CMAC_CTX`, and `data` is valid for `data.len()` bytes.
        let res = unsafe { bssl_sys::CMAC_Update(self.0.as_ptr(), data.as_ptr(), data.len()) };
        if res == 1 {
            Ok(())
        } else {
            Err(CryptoError::Internal)
        }
    }

    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        let mut out_len: usize = 0;
        // SAFETY: `self.0` is an initialized `CMAC_CTX`, `out` is a valid 16-byte buffer,
        // and `out_len` is a valid mutable pointer.
        let res = unsafe { bssl_sys::CMAC_Final(self.0.as_ptr(), out.as_mut_ptr(), &mut out_len) };
        if res == 1 && out_len == 16 {
            Ok(())
        } else {
            Err(CryptoError::Internal)
        }
    }
}

impl Clone for CmacCtx {
    fn clone(&self) -> Self {
        // SAFETY: Allocates a new `CMAC_CTX` and copies state from `self.0`.
        let ptr = unsafe { bssl_sys::CMAC_CTX_new() };
        let non_null = NonNull::new(ptr).expect("bssl_sys::CMAC_CTX_new failed");
        // SAFETY: Both `non_null` and `self.0` are valid non-null `CMAC_CTX` pointers.
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
            pub fn new(key: &[u8; $key_len]) -> Result<Self, CryptoError> {
                // SAFETY: `$cipher_fn()` returns a static, valid `EVP_CIPHER` pointer.
                let cipher = unsafe { bssl_sys::$cipher_fn() };
                CmacCtx::new(key, cipher).map(Self)
            }

            /// Updates the CMAC computation with `data`.
            pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                self.0.update(data)
            }

            /// Finalizes the CMAC computation and writes the 16-byte tag into `out`.
            pub fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
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
// AES Block Cipher & CFB Safe Bindings over `bssl-sys`
// ============================================================================

/// Safe wrapper around BoringSSL's `AES_KEY` for single-block encryption and decryption.
pub struct AesCipher {
    enc_key: bssl_sys::AES_KEY,
    dec_key: bssl_sys::AES_KEY,
}

impl AesCipher {
    /// Initializes an AES key schedule for 128, 192, or 256-bit `key_bytes`.
    pub fn new(key_bytes: &[u8]) -> Result<Self, CryptoError> {
        let bits = c_uint::try_from(key_bytes.len() * 8).map_err(|_| CryptoError::Internal)?;
        let mut enc_key = MaybeUninit::<bssl_sys::AES_KEY>::uninit();
        let mut dec_key = MaybeUninit::<bssl_sys::AES_KEY>::uninit();
        // SAFETY: `key_bytes` is valid for `bits / 8` bytes, and `enc_key` / `dec_key` are valid uninitialized stack memory.
        let (enc_res, dec_res) = unsafe {
            (
                bssl_sys::AES_set_encrypt_key(key_bytes.as_ptr(), bits, enc_key.as_mut_ptr()),
                bssl_sys::AES_set_decrypt_key(key_bytes.as_ptr(), bits, dec_key.as_mut_ptr()),
            )
        };
        if enc_res == 0 && dec_res == 0 {
            // SAFETY: Both `AES_set_encrypt_key` and `AES_set_decrypt_key` returned 0.
            Ok(Self {
                enc_key: unsafe { enc_key.assume_init() },
                dec_key: unsafe { dec_key.assume_init() },
            })
        } else {
            Err(CryptoError::Internal)
        }
    }

    /// Encrypts a single 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let p = block.as_mut_ptr();
        // SAFETY: `p` is valid for 16 bytes (`AES_encrypt` supports `in == out`) and `self.enc_key` is initialized.
        unsafe {
            bssl_sys::AES_encrypt(p, p, &self.enc_key);
        }
    }

    /// Decrypts a single 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let p = block.as_mut_ptr();
        // SAFETY: `p` is valid for 16 bytes (`AES_decrypt` supports `in == out`) and `self.dec_key` is initialized.
        unsafe {
            bssl_sys::AES_decrypt(p, p, &self.dec_key);
        }
    }
}

impl Drop for AesCipher {
    fn drop(&mut self) {
        // SAFETY: `self.enc_key` and `self.dec_key` are valid stack-allocated fields.
        unsafe {
            bssl_sys::OPENSSL_cleanse(
                ptr::from_mut(&mut self.enc_key).cast::<c_void>(),
                core::mem::size_of_val(&self.enc_key),
            );
            bssl_sys::OPENSSL_cleanse(
                ptr::from_mut(&mut self.dec_key).cast::<c_void>(),
                core::mem::size_of_val(&self.dec_key),
            );
        }
    }
}

// ============================================================================
// Internal RAII Helpers for BoringSSL Memory, Bignum, RSA, EVP, and EC
// ============================================================================

/// Scoped heap buffer allocated via `OPENSSL_malloc` that is cleansed and freed on drop.
struct ScopedBsslBuffer {
    ptr: NonNull<u8>,
    len: usize,
}

impl ScopedBsslBuffer {
    fn new(len: usize) -> Result<Self, CryptoError> {
        let alloc_len = len.max(1);
        // SAFETY: `OPENSSL_malloc` allocates `alloc_len` bytes on the heap or returns NULL.
        let raw = unsafe { bssl_sys::OPENSSL_malloc(alloc_len) }.cast::<u8>();
        let ptr = NonNull::new(raw).ok_or(CryptoError::Internal)?;
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
            bssl_sys::OPENSSL_cleanse(self.ptr.as_ptr().cast::<c_void>(), self.len);
            bssl_sys::OPENSSL_free(self.ptr.as_ptr().cast::<c_void>());
        }
    }
}

/// Safe RAII wrapper around `*mut bssl_sys::BIGNUM`.
struct Bignum {
    ptr: NonNull<bssl_sys::BIGNUM>,
}

impl Bignum {
    fn new() -> Result<Self, CryptoError> {
        // SAFETY: `BN_new` allocates a new initialized `BIGNUM` or returns NULL.
        let ptr = NonNull::new(unsafe { bssl_sys::BN_new() }).ok_or(CryptoError::Internal)?;
        Ok(Self { ptr })
    }

    fn from_bytes_be(bytes: &[u8]) -> Result<Self, CryptoError> {
        // SAFETY: `bytes.as_ptr()` is valid for `bytes.len()` bytes. `BN_bin2bn` allocates a new `BIGNUM`.
        let ptr = NonNull::new(unsafe {
            bssl_sys::BN_bin2bn(bytes.as_ptr(), bytes.len(), ptr::null_mut())
        })
        .ok_or(CryptoError::Internal)?;
        Ok(Self { ptr })
    }

    fn from_u32(val: u32) -> Result<Self, CryptoError> {
        let bn = Self::new()?;
        // SAFETY: `bn.as_ptr()` is a valid `BIGNUM` pointer.
        let res = unsafe { bssl_sys::BN_set_word(bn.as_ptr(), val.into()) };
        if res != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(bn)
    }

    fn as_ptr(&self) -> *mut bssl_sys::BIGNUM {
        self.ptr.as_ptr()
    }

    fn num_bits(&self) -> usize {
        // SAFETY: `self.ptr` is a valid `BIGNUM` pointer.
        u32_to_usize(unsafe { bssl_sys::BN_num_bits(self.ptr.as_ptr()) })
    }

    fn is_odd(&self) -> bool {
        // SAFETY: `self.ptr` is a valid `BIGNUM` pointer.
        unsafe { bssl_sys::BN_is_odd(self.ptr.as_ptr()) == 1 }
    }

    fn is_zero(&self) -> bool {
        // SAFETY: `self.ptr` is a valid `BIGNUM` pointer.
        unsafe { bssl_sys::BN_is_zero(self.ptr.as_ptr()) == 1 }
    }

    fn is_one(&self) -> bool {
        // SAFETY: `self.ptr` is a valid `BIGNUM` pointer.
        unsafe { bssl_sys::BN_is_one(self.ptr.as_ptr()) == 1 }
    }

    fn is_prime(&self, ctx: &BnCtx) -> Result<bool, CryptoError> {
        let mut is_probably_prime: c_int = 0;
        // SAFETY:
        // - `is_probably_prime` is a valid mutable pointer to `c_int`.
        // - `self.as_ptr()` and `ctx.as_ptr()` are valid non-null pointers.
        let res = unsafe {
            bssl_sys::BN_primality_test(
                &mut is_probably_prime,
                self.as_ptr(),
                bssl_sys::BN_prime_checks_for_generation,
                ctx.as_ptr(),
                1,
                ptr::null_mut(),
            )
        };
        if res != 1 {
            return Err(CryptoError::Internal);
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
    fn new() -> Result<Self, CryptoError> {
        // SAFETY: `BN_CTX_new` allocates a new `BN_CTX` or returns NULL.
        let ptr = NonNull::new(unsafe { bssl_sys::BN_CTX_new() }).ok_or(CryptoError::Internal)?;
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
pub struct RsaKey {
    ptr: NonNull<bssl_sys::RSA>,
}

impl RsaKey {
    /// Creates an RSA public key from big-endian modulus `n_bytes` and `exponent`.
    fn from_public_key_be_with_exp(
        n_bytes: &[u8],
        exponent: u32,
    ) -> Result<Option<Self>, CryptoError> {
        if exponent < 3 || exponent.is_multiple_of(2) {
            return Ok(None);
        }
        let n = Bignum::from_bytes_be(n_bytes)?;
        let e = Bignum::from_u32(exponent)?;
        // SAFETY: `n` and `e` are valid `BIGNUM` pointers.
        if !n.is_odd() || unsafe { bssl_sys::BN_cmp(n.as_ptr(), e.as_ptr()) } <= 0 {
            return Ok(None);
        }
        // SAFETY: `n.as_ptr()` and `e.as_ptr()` are valid `BIGNUM`s. `RSA_new_public_key` copies them.
        let rsa_ptr = unsafe { bssl_sys::RSA_new_public_key(n.as_ptr(), e.as_ptr()) };
        Ok(NonNull::new(rsa_ptr).map(|ptr| Self { ptr }))
    }

    /// Validates and constructs an RSA public key for `bits`, `exponent`, and `modulus`.
    pub fn load_public(
        bits: u16,
        exponent: u32,
        modulus: &[u8],
    ) -> Result<Option<Self>, CryptoError> {
        let expected_len = usize::from(bits) / 8;
        if modulus.len() != expected_len {
            return Ok(None);
        }
        let n = Bignum::from_bytes_be(modulus)?;
        if n.num_bits() != usize::from(bits) {
            return Ok(None);
        }
        Self::from_public_key_be_with_exp(modulus, exponent)
    }

    /// Reconstructs an RSA private key from a validated `public` key, `exponent`, and `prime_p`.
    pub fn load_private(
        public: &Self,
        exponent: u32,
        prime_p: &[u8],
    ) -> Result<Option<Self>, CryptoError> {
        let mut mod_buf = [0u8; 512];
        let mod_len = public.size();
        let modulus = public.modulus(mod_len, &mut mod_buf)?;
        rsa_construct_from_p(modulus, prime_p, exponent)
    }

    /// Generates an RSA key pair deterministically from `rng` for `bits` and odd `exponent >= 3`.
    pub fn generate(
        rng: &mut rand_chacha::ChaCha20Rng,
        bits: u16,
        exponent: u32,
    ) -> Result<(Self, Self), CryptoError> {
        let bits_usize = usize::from(bits);
        let e = Bignum::from_u32(exponent)?;
        let ctx = BnCtx::new()?;
        let prime_bits = bits_usize / 2;

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
                return Err(CryptoError::Internal);
            }
            if n.num_bits() != bits_usize {
                continue;
            }

            if let Some(priv_key) = rsa_construct_private_key(&n, &p, &q, &e, &ctx)? {
                // SAFETY: `n` and `e` are valid `BIGNUM`s.
                let pub_ptr = unsafe { bssl_sys::RSA_new_public_key(n.as_ptr(), e.as_ptr()) };
                let pub_key = NonNull::new(pub_ptr)
                    .map(|ptr| Self { ptr })
                    .ok_or(CryptoError::Internal)?;
                return Ok((pub_key, priv_key));
            }
        }
        Err(CryptoError::Internal)
    }

    fn as_ptr(&self) -> *mut bssl_sys::RSA {
        self.ptr.as_ptr()
    }

    /// Returns the modulus size in bytes (`RSA_size`).
    pub fn size(&self) -> usize {
        // SAFETY: `self.ptr` is a valid `RSA` pointer.
        u32_to_usize(unsafe { bssl_sys::RSA_size(self.ptr.as_ptr()) })
    }

    /// Writes the big-endian modulus `n` padded to `len` bytes into `out`.
    pub fn modulus<'a>(&self, len: usize, out: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        let out = out.get_mut(..len).ok_or(CryptoError::Internal)?;
        // SAFETY: `self.as_ptr()` is a valid `RSA` pointer.
        let n_ptr = unsafe { bssl_sys::RSA_get0_n(self.as_ptr()) };
        if n_ptr.is_null()
            || unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), len, n_ptr) } != 1
        {
            return Err(CryptoError::Internal);
        }
        Ok(out)
    }

    /// Writes the first prime factor `p` (padded to at least `half_mod_len` bytes) into `out`.
    pub fn prime_p<'a>(
        &self,
        half_mod_len: usize,
        out: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        // SAFETY: `self.as_ptr()` is a valid private `RSA` key.
        let p_ptr = unsafe { bssl_sys::RSA_get0_p(self.as_ptr()) };
        if p_ptr.is_null() {
            return Err(CryptoError::Internal);
        }
        // SAFETY: `p_ptr` is a valid non-null `BIGNUM`.
        let p_len = u32_to_usize(unsafe { bssl_sys::BN_num_bytes(p_ptr) }).max(half_mod_len);
        let out = out.get_mut(..p_len).ok_or(CryptoError::Internal)?;
        // SAFETY: `out` is valid for `p_len` bytes.
        if unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), p_len, p_ptr) } != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(out)
    }

    /// Returns `true` if the big-endian integer `bytes` is strictly less than the modulus `n`.
    pub fn is_less_than_n(&self, bytes: &[u8]) -> Result<bool, CryptoError> {
        let val = Bignum::from_bytes_be(bytes)?;
        // SAFETY: `self.as_ptr()` is a valid `RSA` pointer.
        let n_ptr = unsafe { bssl_sys::RSA_get0_n(self.as_ptr()) };
        if n_ptr.is_null() {
            return Err(CryptoError::Internal);
        }
        // SAFETY: `val.as_ptr()` and `n_ptr` are valid `BIGNUM` pointers.
        Ok(unsafe { bssl_sys::BN_cmp(val.as_ptr(), n_ptr) } < 0)
    }

    /// Raw RSA encryption (`RSA_NO_PADDING`). Returns `Ok(None)` if `plaintext` is longer than
    /// the modulus or `>= n`.
    pub fn encrypt_raw(
        &self,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let mod_len = self.size();
        if plaintext.len() > mod_len || !self.is_less_than_n(plaintext)? {
            return Ok(None);
        }
        if out.len() < mod_len {
            return Err(CryptoError::Internal);
        }
        let m = Bignum::from_bytes_be(plaintext)?;
        let mut padded_in = ScopedBsslBuffer::new(mod_len)?;
        // SAFETY: `padded_in` has `mod_len` bytes and `m < n`, so `m` fits in `mod_len` bytes.
        if unsafe { bssl_sys::BN_bn2bin_padded(padded_in.as_mut_ptr(), mod_len, m.as_ptr()) } != 1 {
            return Err(CryptoError::Internal);
        }
        let mut out_len: usize = 0;
        // SAFETY: Both `padded_in` and `out` are valid for `mod_len` bytes.
        let res = unsafe {
            bssl_sys::RSA_encrypt(
                self.as_ptr(),
                &mut out_len,
                out.as_mut_ptr(),
                mod_len,
                padded_in.as_ptr(),
                mod_len,
                bssl_sys::RSA_NO_PADDING,
            )
        };
        if res != 1 || out_len != mod_len {
            return Err(CryptoError::Internal);
        }
        Ok(Some(mod_len))
    }

    /// Raw RSA decryption (`RSA_NO_PADDING`). Returns `Ok(None)` if `ciphertext` is not `mod_len`
    /// bytes or `>= n`.
    pub fn decrypt_raw(
        &self,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let mod_len = self.size();
        if ciphertext.len() != mod_len || !self.is_less_than_n(ciphertext)? {
            return Ok(None);
        }
        if out.len() < mod_len {
            return Err(CryptoError::Internal);
        }
        let mut out_len: usize = 0;
        // SAFETY: `ciphertext` and `out` are valid for `mod_len` bytes.
        let res = unsafe {
            bssl_sys::RSA_decrypt(
                self.as_ptr(),
                &mut out_len,
                out.as_mut_ptr(),
                mod_len,
                ciphertext.as_ptr(),
                mod_len,
                bssl_sys::RSA_NO_PADDING,
            )
        };
        if res != 1 || out_len != mod_len {
            return Err(CryptoError::Internal);
        }
        Ok(Some(mod_len))
    }

    /// RSAES-PKCS1-v1_5 encryption (`RSA_PKCS1_PADDING`). Returns `Ok(None)` if `plaintext` is too long.
    pub fn encrypt_pkcs1v15(
        &self,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let key_size = self.size();
        if plaintext.len().saturating_add(11) > key_size {
            return Ok(None);
        }
        if out.len() < key_size {
            return Err(CryptoError::Internal);
        }
        let mut out_len: usize = 0;
        // SAFETY: `out` has at least `key_size` bytes and `plaintext` is valid for `plaintext.len()` bytes.
        let res = unsafe {
            bssl_sys::RSA_encrypt(
                self.as_ptr(),
                &mut out_len,
                out.as_mut_ptr(),
                out.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                bssl_sys::RSA_PKCS1_PADDING,
            )
        };
        if res != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(Some(out_len))
    }

    /// RSAES-PKCS1-v1_5 decryption (`RSA_PKCS1_PADDING`). Returns `Ok(None)` if decryption fails.
    pub fn decrypt_pkcs1v15(
        &self,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let key_size = self.size();
        if ciphertext.len() != key_size {
            return Ok(None);
        }
        let mut temp_buf = ScopedBsslBuffer::new(key_size)?;
        let mut out_len: usize = 0;
        // SAFETY: `temp_buf` is valid for `key_size` bytes and `ciphertext` is valid for `ciphertext.len()` bytes.
        let res = unsafe {
            bssl_sys::RSA_decrypt(
                self.as_ptr(),
                &mut out_len,
                temp_buf.as_mut_ptr(),
                key_size,
                ciphertext.as_ptr(),
                ciphertext.len(),
                bssl_sys::RSA_PKCS1_PADDING,
            )
        };
        if res != 1 {
            return Ok(None);
        }
        let dest = out.get_mut(..out_len).ok_or(CryptoError::Internal)?;
        dest.copy_from_slice(&temp_buf.as_slice()[..out_len]);
        Ok(Some(out_len))
    }

    /// RSAES-OAEP encryption. Returns `Err(CryptoError::Unsupported)` if `hash_alg` is unsupported,
    /// or `Ok(None)` if `plaintext` is too long for the key and hash.
    pub fn encrypt_oaep(
        &self,
        hash_alg: TpmiAlgHash,
        label: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let md = hash_alg_to_evp_md(hash_alg)?;
        let key_size = self.size();
        if plaintext
            .len()
            .saturating_add(2 * hash_alg.digest_size() + 2)
            > key_size
        {
            return Ok(None);
        }
        if out.len() < key_size {
            return Err(CryptoError::Internal);
        }
        let pkey = EvpPkey::from_rsa(self)?;
        let ctx = EvpPkeyCtx::new(&pkey)?;
        // SAFETY: `ctx.as_ptr()` is a valid `EVP_PKEY_CTX` and `md` is a valid `EVP_MD`.
        unsafe {
            if bssl_sys::EVP_PKEY_encrypt_init(ctx.as_ptr()) != 1
                || bssl_sys::EVP_PKEY_CTX_set_rsa_padding(
                    ctx.as_ptr(),
                    bssl_sys::RSA_PKCS1_OAEP_PADDING,
                ) != 1
                || bssl_sys::EVP_PKEY_CTX_set_rsa_oaep_md(ctx.as_ptr(), md) != 1
                || bssl_sys::EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.as_ptr(), md) != 1
            {
                return Err(CryptoError::Internal);
            }
        }
        set_oaep_label(&ctx, label)?;
        let mut out_len = out.len();
        // SAFETY: `out` is valid for `out_len` bytes and `plaintext` is valid for `plaintext.len()` bytes.
        let res = unsafe {
            bssl_sys::EVP_PKEY_encrypt(
                ctx.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
                plaintext.as_ptr(),
                plaintext.len(),
            )
        };
        if res != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(Some(out_len))
    }

    /// RSAES-OAEP decryption. Returns `Err(CryptoError::Unsupported)` if `hash_alg` is unsupported,
    /// or `Ok(None)` if `ciphertext` is invalid.
    pub fn decrypt_oaep(
        &self,
        hash_alg: TpmiAlgHash,
        label: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let md = hash_alg_to_evp_md(hash_alg)?;
        let key_size = self.size();
        if ciphertext.len() != key_size {
            return Ok(None);
        }
        let pkey = EvpPkey::from_rsa(self)?;
        let ctx = EvpPkeyCtx::new(&pkey)?;
        // SAFETY: `ctx.as_ptr()` is a valid `EVP_PKEY_CTX` and `md` is a valid `EVP_MD`.
        unsafe {
            if bssl_sys::EVP_PKEY_decrypt_init(ctx.as_ptr()) != 1
                || bssl_sys::EVP_PKEY_CTX_set_rsa_padding(
                    ctx.as_ptr(),
                    bssl_sys::RSA_PKCS1_OAEP_PADDING,
                ) != 1
                || bssl_sys::EVP_PKEY_CTX_set_rsa_oaep_md(ctx.as_ptr(), md) != 1
                || bssl_sys::EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.as_ptr(), md) != 1
            {
                return Err(CryptoError::Internal);
            }
        }
        set_oaep_label(&ctx, label)?;
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
        if res != 1 {
            return Ok(None);
        }
        let dest = out.get_mut(..out_len).ok_or(CryptoError::Internal)?;
        dest.copy_from_slice(&temp_buf.as_slice()[..out_len]);
        Ok(Some(out_len))
    }

    /// Signs `digest` using RSASSA-PKCS1-v1_5 (`RSA_sign`).
    pub fn sign_pkcs1v15(
        &self,
        hash_alg: TpmiAlgHash,
        digest: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let nid = hash_alg_to_nid(hash_alg)?;
        let key_size = self.size();
        if out.len() < key_size {
            return Err(CryptoError::Internal);
        }
        let mut sig_len: c_uint = 0;
        // SAFETY: `digest` is valid for `digest.len()` bytes and `out` has at least `key_size` bytes.
        let res = unsafe {
            bssl_sys::RSA_sign(
                nid,
                digest.as_ptr(),
                digest.len(),
                out.as_mut_ptr(),
                &mut sig_len,
                self.as_ptr(),
            )
        };
        if res != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(u32_to_usize(sig_len))
    }

    /// Verifies an RSASSA-PKCS1-v1_5 `signature` over `digest` (`RSA_verify`).
    pub fn verify_pkcs1v15(
        &self,
        hash_alg: TpmiAlgHash,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let nid = hash_alg_to_nid(hash_alg)?;
        if signature.len() != self.size() || !self.is_less_than_n(signature)? {
            return Ok(false);
        }
        // SAFETY: `digest` and `signature` are valid for their lengths, and `self.as_ptr()` is valid.
        let res = unsafe {
            bssl_sys::RSA_verify(
                nid,
                digest.as_ptr(),
                digest.len(),
                signature.as_ptr(),
                signature.len(),
                self.as_ptr(),
            )
        };
        Ok(res == 1)
    }

    /// Signs `digest` using RSASSA-PSS (`RSA_sign_pss_mgf1`), using a salt equal to the digest
    /// length (or the maximum salt length allowed by the key if shorter).
    pub fn sign_pss(
        &self,
        hash_alg: TpmiAlgHash,
        digest: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let md = hash_alg_to_evp_md(hash_alg)?;
        let key_size = self.size();
        if out.len() < key_size {
            return Err(CryptoError::Internal);
        }
        let max_salt_len = key_size
            .checked_sub(digest.len() + 2)
            .ok_or(CryptoError::Unsupported)?;
        let salt_len =
            c_int::try_from(digest.len().min(max_salt_len)).map_err(|_| CryptoError::Internal)?;
        let mut sig_len: usize = 0;
        // SAFETY: `out` has at least `key_size` bytes, `digest` is valid, and `md` is valid.
        let res = unsafe {
            bssl_sys::RSA_sign_pss_mgf1(
                self.as_ptr(),
                &mut sig_len,
                out.as_mut_ptr(),
                out.len(),
                digest.as_ptr(),
                digest.len(),
                md,
                md,
                salt_len,
            )
        };
        if res != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(sig_len)
    }

    /// Verifies an RSASSA-PSS `signature` over `digest` (`RSA_verify_pss_mgf1`),
    /// accepting any salt length.
    pub fn verify_pss(
        &self,
        hash_alg: TpmiAlgHash,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let md = hash_alg_to_evp_md(hash_alg)?;
        let key_size = self.size();
        if key_size < digest.len() + 2 {
            return Err(CryptoError::Unsupported);
        }
        if signature.len() != key_size || !self.is_less_than_n(signature)? {
            return Ok(false);
        }
        // SAFETY: `digest` and `signature` are valid for their lengths, and `md` is valid.
        let res = unsafe {
            bssl_sys::RSA_verify_pss_mgf1(
                self.as_ptr(),
                digest.as_ptr(),
                digest.len(),
                md,
                md,
                bssl_sys::RSA_PSS_SALTLEN_AUTO,
                signature.as_ptr(),
                signature.len(),
            )
        };
        Ok(res == 1)
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
    fn from_rsa(rsa: &RsaKey) -> Result<Self, CryptoError> {
        // SAFETY: `EVP_PKEY_new` allocates a new empty `EVP_PKEY`.
        let pkey_ptr =
            NonNull::new(unsafe { bssl_sys::EVP_PKEY_new() }).ok_or(CryptoError::Internal)?;
        let pkey = Self { ptr: pkey_ptr };
        // SAFETY: `EVP_PKEY_set1_RSA` increments the refcount of `rsa.as_ptr()` and assigns it to `pkey`.
        if unsafe { bssl_sys::EVP_PKEY_set1_RSA(pkey.as_ptr(), rsa.as_ptr()) } != 1 {
            return Err(CryptoError::Internal);
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
    fn new(pkey: &EvpPkey) -> Result<Self, CryptoError> {
        // SAFETY: `EVP_PKEY_CTX_new` creates a context for `pkey`.
        let ptr =
            NonNull::new(unsafe { bssl_sys::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut()) })
                .ok_or(CryptoError::Internal)?;
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

fn set_oaep_label(ctx: &EvpPkeyCtx, label: &[u8]) -> Result<(), CryptoError> {
    if label.is_empty() {
        return Ok(());
    }
    // SAFETY: Allocate a buffer via `OPENSSL_malloc` for `EVP_PKEY_CTX_set0_rsa_oaep_label`, which
    // takes ownership of the pointer on success (1) and frees it when `ctx` is freed.
    let label_ptr = unsafe { bssl_sys::OPENSSL_malloc(label.len()) }.cast::<u8>();
    if label_ptr.is_null() {
        return Err(CryptoError::Internal);
    }
    // SAFETY: `label_ptr` is non-null and valid for `label.len()` bytes.
    unsafe {
        ptr::copy_nonoverlapping(label.as_ptr(), label_ptr, label.len());
        if bssl_sys::EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.as_ptr(), label_ptr, label.len()) != 1 {
            bssl_sys::OPENSSL_free(label_ptr.cast::<c_void>());
            return Err(CryptoError::Internal);
        }
    }
    Ok(())
}

fn hash_alg_to_nid(hash_alg: TpmiAlgHash) -> Result<c_int, CryptoError> {
    match hash_alg {
        TpmiAlgHash::Sha1 => Ok(bssl_sys::NID_sha1),
        TpmiAlgHash::Sha256 => Ok(bssl_sys::NID_sha256),
        TpmiAlgHash::Sha384 => Ok(bssl_sys::NID_sha384),
        TpmiAlgHash::Sha512 => Ok(bssl_sys::NID_sha512),
        _ => Err(CryptoError::Unsupported),
    }
}

fn hash_alg_to_evp_md(hash_alg: TpmiAlgHash) -> Result<*const bssl_sys::EVP_MD, CryptoError> {
    // SAFETY: Each `EVP_sha*` function returns a static, immutable pointer to `EVP_MD`.
    unsafe {
        match hash_alg {
            TpmiAlgHash::Sha1 => Ok(bssl_sys::EVP_sha1()),
            TpmiAlgHash::Sha256 => Ok(bssl_sys::EVP_sha256()),
            TpmiAlgHash::Sha384 => Ok(bssl_sys::EVP_sha384()),
            TpmiAlgHash::Sha512 => Ok(bssl_sys::EVP_sha512()),
            _ => Err(CryptoError::Unsupported),
        }
    }
}

// ============================================================================
// Standalone RSA Helper Functions over `bssl-sys`
// ============================================================================

/// Reconstructs an `RsaKey` from big-endian `(modulus, prime_p, exponent)`.
fn rsa_construct_from_p(
    modulus: &[u8],
    prime_p: &[u8],
    exponent: u32,
) -> Result<Option<RsaKey>, CryptoError> {
    if exponent < 3 || exponent.is_multiple_of(2) {
        return Ok(None);
    }

    let n = Bignum::from_bytes_be(modulus)?;
    let p = Bignum::from_bytes_be(prime_p)?;
    let e = Bignum::from_u32(exponent)?;

    if !n.is_odd() || !p.is_odd() || p.num_bits() <= 1 || n.num_bits() < 512 {
        return Ok(None);
    }

    let ctx = BnCtx::new()?;
    let q = Bignum::new()?;
    let rem = Bignum::new()?;

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
        return Ok(None);
    }

    if !rem.is_zero() || !q.is_odd() || q.num_bits() <= 1 || p.num_bits().abs_diff(q.num_bits()) > 1
    {
        return Ok(None);
    }

    let prod = Bignum::new()?;
    // SAFETY: All `BIGNUM` and `BN_CTX` pointers are valid.
    if unsafe { bssl_sys::BN_mul(prod.as_ptr(), p.as_ptr(), q.as_ptr(), ctx.as_ptr()) } != 1
        || unsafe { bssl_sys::BN_cmp(prod.as_ptr(), n.as_ptr()) } != 0
    {
        return Ok(None);
    }

    if !p.is_prime(&ctx)? || !q.is_prime(&ctx)? {
        return Ok(None);
    }

    rsa_construct_private_key(&n, &p, &q, &e, &ctx)
}

/// Derives CRT parameters `(d, dmp1, dmq1, iqmp)` from `(n, p, q, e)` and constructs an `RsaKey`.
fn rsa_construct_private_key(
    n: &Bignum,
    p: &Bignum,
    q: &Bignum,
    e: &Bignum,
    ctx: &BnCtx,
) -> Result<Option<RsaKey>, CryptoError> {
    // SAFETY: `p` and `q` are valid `BIGNUM` pointers.
    if unsafe { bssl_sys::BN_cmp(p.as_ptr(), q.as_ptr()) } == 0 {
        return Ok(None);
    }
    let one = Bignum::from_u32(1)?;
    let pm1 = Bignum::new()?;
    let qm1 = Bignum::new()?;
    // SAFETY: Valid `BIGNUM` pointers.
    if unsafe { bssl_sys::BN_sub(pm1.as_ptr(), p.as_ptr(), one.as_ptr()) } != 1
        || unsafe { bssl_sys::BN_sub(qm1.as_ptr(), q.as_ptr(), one.as_ptr()) } != 1
    {
        return Err(CryptoError::Internal);
    }

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
        return Err(CryptoError::Internal);
    }

    let d = Bignum::new()?;
    // SAFETY: `BN_mod_inverse` returns NULL if `e` and `lcm` are not coprime.
    if unsafe { bssl_sys::BN_mod_inverse(d.as_ptr(), e.as_ptr(), lcm.as_ptr(), ctx.as_ptr()) }
        .is_null()
    {
        return Ok(None);
    }

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
        return Ok(None);
    }

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
    Ok(NonNull::new(rsa_ptr).map(|ptr| RsaKey { ptr }))
}

/// Generates a random prime of `prime_bits` bits from `rng` coprime to `e`.
fn generate_deterministic_prime(
    rng: &mut rand_chacha::ChaCha20Rng,
    prime_bits: usize,
    e: &Bignum,
    ctx: &BnCtx,
) -> Result<Bignum, CryptoError> {
    let prime_bytes = prime_bits / 8;
    let mut buf = [0u8; 256];
    if prime_bytes == 0 || prime_bytes > buf.len() {
        return Err(CryptoError::Internal);
    }

    rng.fill_bytes(&mut buf[..prime_bytes]);
    buf[0] |= 0xC0;
    buf[prime_bytes - 1] |= 0x01;

    let cand = Bignum::from_bytes_be(&buf[..prime_bytes])?;
    let one = Bignum::from_u32(1)?;
    let pm1 = Bignum::new()?;
    let gcd = Bignum::new()?;

    loop {
        // Check gcd(cand - 1, e) == 1
        // SAFETY: `pm1`, `cand`, `one`, `gcd`, `e`, and `ctx` are valid non-null pointers.
        if unsafe { bssl_sys::BN_sub(pm1.as_ptr(), cand.as_ptr(), one.as_ptr()) } != 1
            || unsafe { bssl_sys::BN_gcd(gcd.as_ptr(), pm1.as_ptr(), e.as_ptr(), ctx.as_ptr()) }
                != 1
        {
            return Err(CryptoError::Internal);
        }
        if gcd.is_one() && cand.is_prime(ctx)? {
            return Ok(cand);
        }
        // SAFETY: `cand.as_ptr()` is a valid non-null `BIGNUM`.
        if unsafe { bssl_sys::BN_add_word(cand.as_ptr(), 2) } != 1 {
            return Err(CryptoError::Internal);
        }
        if cand.num_bits() > prime_bits {
            rng.fill_bytes(&mut buf[..prime_bytes]);
            buf[0] |= 0xC0;
            buf[prime_bytes - 1] |= 0x01;
            // SAFETY: `cand.as_ptr()` is a valid non-null `BIGNUM`.
            if unsafe { bssl_sys::BN_bin2bn(buf.as_ptr(), prime_bytes, cand.as_ptr()) }.is_null() {
                return Err(CryptoError::Internal);
            }
        }
    }
}

// ============================================================================
// Elliptic Curve Safe Bindings over `bssl-sys` (P-256, P-384, P-521)
// ============================================================================

/// Supported elliptic curves in `tpm2-boringssl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcGroup {
    /// NIST P-256 (`secp256r1`), 32-byte coordinates.
    P256,
    /// NIST P-384 (`secp384r1`), 48-byte coordinates.
    P384,
    /// NIST P-521 (`secp521r1`), 66-byte coordinates.
    P521,
}

/// A BoringSSL built-in `EC_GROUP`, which is static and never freed.
struct EcGroupHandle(*const bssl_sys::EC_GROUP);

impl EcGroupHandle {
    fn as_ptr(&self) -> *const bssl_sys::EC_GROUP {
        self.0
    }
}

impl EcGroup {
    /// Returns a scoped `EcGroupHandle` for this curve.
    fn handle(self) -> Result<EcGroupHandle, CryptoError> {
        // SAFETY: Each `EC_group_p*` function returns a static, immutable `EC_GROUP` pointer.
        let group = unsafe {
            match self {
                Self::P256 => bssl_sys::EC_group_p256(),
                Self::P384 => bssl_sys::EC_group_p384(),
                Self::P521 => bssl_sys::EC_group_p521(),
            }
        };
        Ok(EcGroupHandle(group))
    }

    /// Returns the coordinate byte length for this curve (32, 48, or 66).
    pub const fn coord_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    /// Validates that `scalar` represents an integer $d$ in the range $1 \le d < \text{order}$.
    fn validate_scalar(
        self,
        group_handle: &EcGroupHandle,
        scalar: &[u8],
    ) -> Result<Bignum, CryptoError> {
        let d = Bignum::from_bytes_be(scalar)?;
        if d.is_zero() {
            return Err(CryptoError::Internal);
        }
        // SAFETY: `group_handle.as_ptr()` is a valid `EC_GROUP`.
        let order = unsafe { bssl_sys::EC_GROUP_get0_order(group_handle.as_ptr()) };
        if order.is_null() || unsafe { bssl_sys::BN_cmp(d.as_ptr(), order) } >= 0 {
            return Err(CryptoError::Internal);
        }
        Ok(d)
    }
}

/// Safe RAII wrapper around `*mut bssl_sys::EC_POINT`.
struct EcPoint {
    ptr: NonNull<bssl_sys::EC_POINT>,
}

impl EcPoint {
    fn new(group: &EcGroupHandle) -> Result<Self, CryptoError> {
        // SAFETY: `EC_POINT_new` allocates a new point on `group`.
        let ptr = NonNull::new(unsafe { bssl_sys::EC_POINT_new(group.as_ptr()) })
            .ok_or(CryptoError::Internal)?;
        Ok(Self { ptr })
    }

    fn from_affine_coords(group: &EcGroupHandle, x: &[u8], y: &[u8]) -> Result<Self, CryptoError> {
        let pt = Self::new(group)?;
        let x_bn = Bignum::from_bytes_be(x)?;
        let y_bn = Bignum::from_bytes_be(y)?;
        // SAFETY:
        // - `group.as_ptr()` and `pt.as_ptr()` are valid.
        // - `EC_POINT_set_affine_coordinates_GFp` checks that `(x, y)` is on the curve and `< p`.
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
            return Err(CryptoError::Internal);
        }
        Ok(pt)
    }

    fn to_affine_coords(
        &self,
        group: &EcGroupHandle,
        coord_len: usize,
        x_out: &mut [u8],
        y_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if x_out.len() < coord_len || y_out.len() < coord_len {
            return Err(CryptoError::Internal);
        }
        // SAFETY: `group.as_ptr()` and `self.as_ptr()` are valid.
        if unsafe { bssl_sys::EC_POINT_is_at_infinity(group.as_ptr(), self.as_ptr()) } != 0 {
            return Err(CryptoError::Internal);
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
            return Err(CryptoError::Internal);
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
    fn new(group: &EcGroupHandle) -> Result<Self, CryptoError> {
        // SAFETY: `EC_KEY_new` allocates a new `EC_KEY`.
        let ptr = NonNull::new(unsafe { bssl_sys::EC_KEY_new() }).ok_or(CryptoError::Internal)?;
        let key = Self { ptr };
        // SAFETY: `key.as_ptr()` and `group.as_ptr()` are valid.
        if unsafe { bssl_sys::EC_KEY_set_group(key.as_ptr(), group.as_ptr()) } != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(key)
    }

    fn from_private_scalar(
        group: EcGroup,
        group_handle: &EcGroupHandle,
        scalar: &[u8],
    ) -> Result<Self, CryptoError> {
        let d = group.validate_scalar(group_handle, scalar)?;
        let key = Self::new(group_handle)?;
        // SAFETY: `key.as_ptr()` and `d.as_ptr()` are valid.
        if unsafe { bssl_sys::EC_KEY_set_private_key(key.as_ptr(), d.as_ptr()) } != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(key)
    }

    fn from_public_point(
        group_handle: &EcGroupHandle,
        x: &[u8],
        y: &[u8],
    ) -> Result<Self, CryptoError> {
        let pt = EcPoint::from_affine_coords(group_handle, x, y)?;
        let key = Self::new(group_handle)?;
        // SAFETY: `key.as_ptr()` and `pt.as_ptr()` are valid.
        if unsafe { bssl_sys::EC_KEY_set_public_key(key.as_ptr(), pt.as_ptr()) } != 1 {
            return Err(CryptoError::Internal);
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
pub fn ec_validate_point(group: EcGroup, x: &[u8], y: &[u8]) -> Result<(), CryptoError> {
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
) -> Result<(), CryptoError> {
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
        return Err(CryptoError::Internal);
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
) -> Result<(), CryptoError> {
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
        return Err(CryptoError::Internal);
    }
    r.to_affine_coords(&group_handle, group.coord_len(), x_out, y_out)
}

/// Signs a pre-hashed digest using ECDSA and outputs a fixed-width IEEE P1363 `(r || s)` signature.
pub fn ecdsa_sign(
    group: EcGroup,
    private_key: &[u8],
    digest: &[u8],
    signature_out: &mut [u8],
) -> Result<usize, CryptoError> {
    let group_handle = group.handle()?;
    let sig_size = 2 * group.coord_len();
    if signature_out.len() < sig_size {
        return Err(CryptoError::Internal);
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
        return Err(CryptoError::Internal);
    }
    Ok(out_len)
}

/// Verifies a fixed-width IEEE P1363 `(r || s)` ECDSA signature against a pre-hashed digest.
pub fn ecdsa_verify(
    group: EcGroup,
    public_key_xy: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let group_handle = group.handle()?;
    let coord_len = group.coord_len();
    if public_key_xy.len() != 2 * coord_len || signature.len() != 2 * coord_len {
        return Err(CryptoError::Internal);
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
        Err(CryptoError::Internal)
    }
}

/// Generates an ECC keypair on `group` using `rng` for candidate scalar generation.
pub fn ec_generate_key(
    group: EcGroup,
    rng: &mut impl RngCore,
    public_key_out: &mut [u8],
    private_key_out: &mut [u8],
) -> Result<(usize, usize), CryptoError> {
    let group_handle = group.handle()?;
    let coord_len = group.coord_len();
    if public_key_out.len() < 2 * coord_len || private_key_out.len() < coord_len {
        return Err(CryptoError::Internal);
    }

    let mut cand = [0u8; 66];
    for _ in 0..100 {
        rng.fill_bytes(&mut cand[..coord_len]);
        if group == EcGroup::P521 {
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
    Err(CryptoError::Internal)
}

// ============================================================================
// ML-KEM (768 and 1024) Safe Bindings over `bssl-sys`
// ============================================================================

macro_rules! impl_bssl_mlkem {
    (
        $pub_name:ident,
        $priv_name:ident,
        $sys_pub:ident,
        $sys_priv:ident,
        $parse_pub:ident,
        $marshal_pub:ident,
        $priv_from_seed:ident,
        $pub_from_priv:ident,
        $encap:ident,
        $decap:ident,
        $pub_bytes:expr,
        $ct_bytes:expr
    ) => {
        /// Safe boxed wrapper around BoringSSL's ML-KEM public key structure.
        pub struct $pub_name(Box<bssl_sys::$sys_pub>);

        /// Safe boxed wrapper around BoringSSL's ML-KEM private key structure.
        pub struct $priv_name(Box<bssl_sys::$sys_priv>);

        impl $pub_name {
            /// Parses and validates an encoded ML-KEM public key, returning `None` if invalid.
            pub fn parse(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != $pub_bytes {
                    return None;
                }
                // SAFETY: `bssl_sys::$sys_pub` is a plain C struct of byte arrays/words.
                let mut key =
                    Box::new(unsafe { MaybeUninit::<bssl_sys::$sys_pub>::zeroed().assume_init() });
                let mut cbs = MaybeUninit::<bssl_sys::CBS>::uninit();
                // SAFETY: `cbs` is initialized from `bytes` and `key` is valid mutable memory.
                let ok = unsafe {
                    bssl_sys::CBS_init(cbs.as_mut_ptr(), bytes.as_ptr(), bytes.len());
                    bssl_sys::$parse_pub(&mut *key, cbs.as_mut_ptr()) == 1
                        && bssl_sys::CBS_len(cbs.as_ptr()) == 0
                };
                if ok { Some(Self(key)) } else { None }
            }

            /// Marshals the ML-KEM public key into the prefix of `out`.
            pub fn marshal<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
                let out = out.get_mut(..$pub_bytes).ok_or(CryptoError::Internal)?;
                let mut cbb = MaybeUninit::<bssl_sys::CBB>::uninit();
                let mut out_len: usize = 0;
                // SAFETY: `CBB_init_fixed` writes bounded to `out`, and `self.0` is a valid public key.
                let ok = unsafe {
                    bssl_sys::CBB_init_fixed(cbb.as_mut_ptr(), out.as_mut_ptr(), out.len()) == 1
                        && bssl_sys::$marshal_pub(cbb.as_mut_ptr(), &*self.0) == 1
                        && bssl_sys::CBB_finish(cbb.as_mut_ptr(), ptr::null_mut(), &mut out_len)
                            == 1
                };
                if ok && out_len == $pub_bytes {
                    Ok(out)
                } else {
                    Err(CryptoError::Internal)
                }
            }

            /// Encapsulates a shared secret to this public key, writing the ciphertext into `out_ct`
            /// and the 32-byte shared secret into `out_ss`.
            pub fn encapsulate<'a>(
                &self,
                out_ct: &'a mut [u8],
                out_ss: &mut [u8; 32],
            ) -> Result<&'a [u8], CryptoError> {
                let ct = out_ct.get_mut(..$ct_bytes).ok_or(CryptoError::Internal)?;
                // SAFETY: `ct` has `$ct_bytes` bytes, `out_ss` has 32 bytes, and `self.0` is initialized.
                unsafe {
                    bssl_sys::$encap(ct.as_mut_ptr(), out_ss.as_mut_ptr(), &*self.0);
                }
                Ok(ct)
            }
        }

        impl $priv_name {
            /// Expands an ML-KEM keypair from a 64-byte `(d || z)` seed.
            pub fn from_seed(seed: &[u8; 64]) -> Result<($pub_name, Self), CryptoError> {
                // SAFETY: Both key structs are plain C structs of byte arrays/words.
                let mut priv_key =
                    Box::new(unsafe { MaybeUninit::<bssl_sys::$sys_priv>::zeroed().assume_init() });
                let mut pub_key =
                    Box::new(unsafe { MaybeUninit::<bssl_sys::$sys_pub>::zeroed().assume_init() });
                // SAFETY: `seed` is 64 bytes (`MLKEM_SEED_BYTES`), and `priv_key` / `pub_key` are valid.
                let ok = unsafe {
                    if bssl_sys::$priv_from_seed(&mut *priv_key, seed.as_ptr(), seed.len()) == 1 {
                        bssl_sys::$pub_from_priv(&mut *pub_key, &*priv_key);
                        true
                    } else {
                        false
                    }
                };
                if ok {
                    Ok(($pub_name(pub_key), Self(priv_key)))
                } else {
                    Err(CryptoError::Internal)
                }
            }

            /// Decapsulates `ciphertext` into `out_ss`, returning `false` if `ciphertext` has the wrong length.
            pub fn decapsulate(&self, ciphertext: &[u8], out_ss: &mut [u8; 32]) -> bool {
                if ciphertext.len() != $ct_bytes {
                    return false;
                }
                // SAFETY: `out_ss` is 32 bytes, `ciphertext` is valid for `ciphertext.len()` bytes,
                // and `self.0` is an initialized private key.
                unsafe {
                    bssl_sys::$decap(
                        out_ss.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        ciphertext.len(),
                        &*self.0,
                    ) == 1
                }
            }
        }

        impl Drop for $priv_name {
            fn drop(&mut self) {
                // SAFETY: `self.0` is uniquely owned heap memory.
                unsafe {
                    bssl_sys::OPENSSL_cleanse(
                        ptr::from_mut(&mut *self.0).cast::<c_void>(),
                        core::mem::size_of_val(&*self.0),
                    );
                }
            }
        }
    };
}

impl_bssl_mlkem!(
    Mlkem768PublicKey,
    Mlkem768PrivateKey,
    MLKEM768_public_key,
    MLKEM768_private_key,
    MLKEM768_parse_public_key,
    MLKEM768_marshal_public_key,
    MLKEM768_private_key_from_seed,
    MLKEM768_public_from_private,
    MLKEM768_encap,
    MLKEM768_decap,
    1184,
    1088
);

impl_bssl_mlkem!(
    Mlkem1024PublicKey,
    Mlkem1024PrivateKey,
    MLKEM1024_public_key,
    MLKEM1024_private_key,
    MLKEM1024_parse_public_key,
    MLKEM1024_marshal_public_key,
    MLKEM1024_private_key_from_seed,
    MLKEM1024_public_from_private,
    MLKEM1024_encap,
    MLKEM1024_decap,
    1568,
    1568
);

// ============================================================================
// ML-DSA (44, 65, and 87) Safe Bindings over `bssl-sys`
// ============================================================================

macro_rules! impl_bssl_mldsa {
    (
        $pub_name:ident,
        $priv_name:ident,
        $prehash_name:ident,
        $sys_pub:ident,
        $sys_priv:ident,
        $sys_prehash:ident,
        $parse_pub:ident,
        $marshal_pub:ident,
        $priv_from_seed:ident,
        $pub_from_priv:ident,
        $sign:ident,
        $verify:ident,
        $prehash_init:ident,
        $prehash_update:ident,
        $prehash_finalize:ident,
        $sign_mu:ident,
        $verify_mu:ident,
        $pub_bytes:expr,
        $sig_bytes:expr
    ) => {
        /// Safe boxed wrapper around BoringSSL's ML-DSA public key structure.
        pub struct $pub_name(Box<bssl_sys::$sys_pub>);

        /// Safe boxed wrapper around BoringSSL's ML-DSA private key structure.
        pub struct $priv_name(Box<bssl_sys::$sys_priv>);

        /// Safe wrapper around BoringSSL's ML-DSA prehash (`µ`) context.
        #[derive(Clone)]
        pub struct $prehash_name(bssl_sys::$sys_prehash);

        impl $pub_name {
            /// Parses and validates an encoded ML-DSA public key, returning `None` if invalid.
            pub fn parse(bytes: &[u8]) -> Option<Self> {
                if bytes.len() != $pub_bytes {
                    return None;
                }
                // SAFETY: `bssl_sys::$sys_pub` is a plain C struct of byte arrays/words.
                let mut key =
                    Box::new(unsafe { MaybeUninit::<bssl_sys::$sys_pub>::zeroed().assume_init() });
                let mut cbs = MaybeUninit::<bssl_sys::CBS>::uninit();
                // SAFETY: `cbs` is initialized from `bytes` and `key` is valid mutable memory.
                let ok = unsafe {
                    bssl_sys::CBS_init(cbs.as_mut_ptr(), bytes.as_ptr(), bytes.len());
                    bssl_sys::$parse_pub(&mut *key, cbs.as_mut_ptr()) == 1
                        && bssl_sys::CBS_len(cbs.as_ptr()) == 0
                };
                if ok { Some(Self(key)) } else { None }
            }

            /// Marshals the ML-DSA public key into the prefix of `out`.
            pub fn marshal<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
                let out = out.get_mut(..$pub_bytes).ok_or(CryptoError::Internal)?;
                let mut cbb = MaybeUninit::<bssl_sys::CBB>::uninit();
                let mut out_len: usize = 0;
                // SAFETY: `CBB_init_fixed` writes bounded to `out`, and `self.0` is a valid public key.
                let ok = unsafe {
                    bssl_sys::CBB_init_fixed(cbb.as_mut_ptr(), out.as_mut_ptr(), out.len()) == 1
                        && bssl_sys::$marshal_pub(cbb.as_mut_ptr(), &*self.0) == 1
                        && bssl_sys::CBB_finish(cbb.as_mut_ptr(), ptr::null_mut(), &mut out_len)
                            == 1
                };
                if ok && out_len == $pub_bytes {
                    Ok(out)
                } else {
                    Err(CryptoError::Internal)
                }
            }

            /// Initializes a streaming prehash (`µ`) context for this public key and `context`.
            pub fn prehash_init(&self, context: &[u8]) -> Result<$prehash_name, CryptoError> {
                let mut state = MaybeUninit::<bssl_sys::$sys_prehash>::uninit();
                // SAFETY: `state` is valid uninitialized memory, `self.0` is valid, and `context` is valid for `context.len()`.
                let ok = unsafe {
                    bssl_sys::$prehash_init(
                        state.as_mut_ptr(),
                        &*self.0,
                        context.as_ptr(),
                        context.len(),
                    ) == 1
                };
                if ok {
                    // SAFETY: `$prehash_init` returned 1, so `state` is initialized.
                    Ok($prehash_name(unsafe { state.assume_init() }))
                } else {
                    Err(CryptoError::Internal)
                }
            }

            /// Verifies a pure ML-DSA `signature` over `msg` and `context`.
            pub fn verify(&self, msg: &[u8], context: &[u8], signature: &[u8]) -> bool {
                if signature.len() != $sig_bytes {
                    return false;
                }
                // SAFETY: `self.0`, `signature`, `msg`, and `context` are valid for their lengths.
                unsafe {
                    bssl_sys::$verify(
                        &*self.0,
                        signature.as_ptr(),
                        signature.len(),
                        msg.as_ptr(),
                        msg.len(),
                        context.as_ptr(),
                        context.len(),
                    ) == 1
                }
            }

            /// Verifies an ML-DSA `signature` over a 64-byte external message representative `mu`.
            pub fn verify_mu(&self, mu: &[u8; 64], signature: &[u8]) -> bool {
                if signature.len() != $sig_bytes {
                    return false;
                }
                // SAFETY: `self.0`, `signature`, and `mu` (64 bytes) are valid.
                unsafe {
                    bssl_sys::$verify_mu(&*self.0, signature.as_ptr(), signature.len(), mu.as_ptr())
                        == 1
                }
            }
        }

        impl $prehash_name {
            /// Updates the streaming `µ` computation with `data`.
            pub fn update(&mut self, data: &[u8]) {
                if data.is_empty() {
                    return;
                }
                // SAFETY: `self.0` is initialized and `data` is valid for `data.len()` bytes.
                unsafe {
                    bssl_sys::$prehash_update(&mut self.0, data.as_ptr(), data.len());
                }
            }

            /// Finalizes the streaming `µ` computation and writes the 64-byte representative into `out`.
            pub fn finalize(mut self, out: &mut [u8; 64]) {
                // SAFETY: `self.0` is initialized and `out` has 64 bytes (`MLDSA_MU_BYTES`).
                unsafe {
                    bssl_sys::$prehash_finalize(out.as_mut_ptr(), &mut self.0);
                }
            }
        }

        impl $priv_name {
            /// Expands an ML-DSA keypair from a 32-byte `ξ` seed.
            pub fn from_seed(seed: &[u8; 32]) -> Result<($pub_name, Self), CryptoError> {
                // SAFETY: Both key structs are plain C structs of byte arrays/words.
                let mut priv_key =
                    Box::new(unsafe { MaybeUninit::<bssl_sys::$sys_priv>::zeroed().assume_init() });
                let mut pub_key =
                    Box::new(unsafe { MaybeUninit::<bssl_sys::$sys_pub>::zeroed().assume_init() });
                // SAFETY: `seed` is 32 bytes (`MLDSA_SEED_BYTES`), and `priv_key` / `pub_key` are valid.
                let ok = unsafe {
                    bssl_sys::$priv_from_seed(&mut *priv_key, seed.as_ptr(), seed.len()) == 1
                        && bssl_sys::$pub_from_priv(&mut *pub_key, &*priv_key) == 1
                };
                if ok {
                    Ok(($pub_name(pub_key), Self(priv_key)))
                } else {
                    Err(CryptoError::Internal)
                }
            }

            /// Signs `msg` and `context` using pure ML-DSA, writing the signature into `out`.
            pub fn sign<'a>(
                &self,
                msg: &[u8],
                context: &[u8],
                out: &'a mut [u8],
            ) -> Result<&'a [u8], CryptoError> {
                let sig = out.get_mut(..$sig_bytes).ok_or(CryptoError::Internal)?;
                // SAFETY: `sig` has `$sig_bytes` bytes, `self.0` is initialized, and `msg`/`context` are valid.
                let ok = unsafe {
                    bssl_sys::$sign(
                        sig.as_mut_ptr(),
                        &*self.0,
                        msg.as_ptr(),
                        msg.len(),
                        context.as_ptr(),
                        context.len(),
                    ) == 1
                };
                if ok {
                    Ok(sig)
                } else {
                    Err(CryptoError::Internal)
                }
            }

            /// Signs a 64-byte external message representative `mu`, writing the signature into `out`.
            pub fn sign_mu<'a>(
                &self,
                mu: &[u8; 64],
                out: &'a mut [u8],
            ) -> Result<&'a [u8], CryptoError> {
                let sig = out.get_mut(..$sig_bytes).ok_or(CryptoError::Internal)?;
                // SAFETY: `sig` has `$sig_bytes` bytes, `self.0` is initialized, and `mu` is 64 bytes.
                let ok =
                    unsafe { bssl_sys::$sign_mu(sig.as_mut_ptr(), &*self.0, mu.as_ptr()) == 1 };
                if ok {
                    Ok(sig)
                } else {
                    Err(CryptoError::Internal)
                }
            }
        }

        impl Drop for $priv_name {
            fn drop(&mut self) {
                // SAFETY: `self.0` is uniquely owned heap memory.
                unsafe {
                    bssl_sys::OPENSSL_cleanse(
                        ptr::from_mut(&mut *self.0).cast::<c_void>(),
                        core::mem::size_of_val(&*self.0),
                    );
                }
            }
        }
    };
}

impl_bssl_mldsa!(
    Mldsa44PublicKey,
    Mldsa44PrivateKey,
    Mldsa44Prehash,
    MLDSA44_public_key,
    MLDSA44_private_key,
    MLDSA44_prehash,
    MLDSA44_parse_public_key,
    MLDSA44_marshal_public_key,
    MLDSA44_private_key_from_seed,
    MLDSA44_public_from_private,
    MLDSA44_sign,
    MLDSA44_verify,
    MLDSA44_prehash_init,
    MLDSA44_prehash_update,
    MLDSA44_prehash_finalize,
    MLDSA44_sign_message_representative,
    MLDSA44_verify_message_representative,
    1312,
    2420
);

impl_bssl_mldsa!(
    Mldsa65PublicKey,
    Mldsa65PrivateKey,
    Mldsa65Prehash,
    MLDSA65_public_key,
    MLDSA65_private_key,
    MLDSA65_prehash,
    MLDSA65_parse_public_key,
    MLDSA65_marshal_public_key,
    MLDSA65_private_key_from_seed,
    MLDSA65_public_from_private,
    MLDSA65_sign,
    MLDSA65_verify,
    MLDSA65_prehash_init,
    MLDSA65_prehash_update,
    MLDSA65_prehash_finalize,
    MLDSA65_sign_message_representative,
    MLDSA65_verify_message_representative,
    1952,
    3309
);

impl_bssl_mldsa!(
    Mldsa87PublicKey,
    Mldsa87PrivateKey,
    Mldsa87Prehash,
    MLDSA87_public_key,
    MLDSA87_private_key,
    MLDSA87_prehash,
    MLDSA87_parse_public_key,
    MLDSA87_marshal_public_key,
    MLDSA87_private_key_from_seed,
    MLDSA87_public_from_private,
    MLDSA87_sign,
    MLDSA87_verify,
    MLDSA87_prehash_init,
    MLDSA87_prehash_update,
    MLDSA87_prehash_finalize,
    MLDSA87_sign_message_representative,
    MLDSA87_verify_message_representative,
    2592,
    4627
);
