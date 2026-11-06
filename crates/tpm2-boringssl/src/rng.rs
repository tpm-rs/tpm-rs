//! Random number generation: BoringSSL's system RNG (`RAND_bytes`), or a
//! deterministic AES-256-CTR DRBG (`CTR_DRBG_STATE`, NIST SP 800-90A).

use core::{
    mem::MaybeUninit,
    ptr::{self, NonNull},
};

use tpm2::crypto::{CryptoError, Random, Rng};

use crate::BoringSsl;

const ENTROPY_LEN: usize = bssl_sys::CTR_DRBG_ENTROPY_LEN as usize;
const MAX_GENERATE_LEN: usize = bssl_sys::CTR_DRBG_MAX_GENERATE_LENGTH as usize;

/// BoringSSL random number generator.
///
/// [`Random::from_entropy`] returns BoringSSL's system RNG (`RAND_bytes`),
/// which ignores [`Rng::stir_bytes`]. [`Random::from_seed`] returns a
/// deterministic `CTR_DRBG`, instantiated from `SHA-384(seed)` and reseeded
/// with `SHA-384(data)` by [`Rng::stir_bytes`].
pub struct BoringSslRng(Kind);

enum Kind {
    RandBytes,
    Drbg(NonNull<bssl_sys::CTR_DRBG_STATE>),
}

// SAFETY: `CTR_DRBG_STATE` is an owned heap allocation with no thread-local
// affinity, and is only accessed through `&mut self`.
unsafe impl Send for BoringSslRng {}
unsafe impl Sync for BoringSslRng {}

impl Drop for BoringSslRng {
    fn drop(&mut self) {
        if let Kind::Drbg(drbg) = self.0 {
            unsafe { bssl_sys::CTR_DRBG_free(drbg.as_ptr()) };
        }
    }
}

impl BoringSslRng {
    /// Checks that this is the system RNG, for operations which use BoringSSL's
    /// system RNG directly rather than drawing from `self`.
    ///
    /// Returns `Err(CryptoError::Internal)` for a seeded RNG, as the caller
    /// would otherwise silently get non-deterministic output.
    pub(crate) const fn check_system(&self) -> Result<(), CryptoError> {
        match self.0 {
            Kind::RandBytes => Ok(()),
            Kind::Drbg(_) => Err(CryptoError::Internal),
        }
    }
}

/// Returns `SHA-384(input)`, a `CTR_DRBG_ENTROPY_LEN`-byte entropy input.
fn sha384(input: &[u8]) -> [u8; ENTROPY_LEN] {
    // BoringSSL's one-shot `SHA384` is `static inline`, so it isn't exported.
    let mut out = [0u8; ENTROPY_LEN];
    let mut ctx = MaybeUninit::<bssl_sys::SHA512_CTX>::uninit();
    unsafe {
        bssl_sys::SHA384_Init(ctx.as_mut_ptr());
        bssl_sys::SHA384_Update(ctx.as_mut_ptr(), input.as_ptr().cast(), input.len());
        bssl_sys::SHA384_Final(out.as_mut_ptr(), ctx.as_mut_ptr());
    }
    out
}

impl Random for BoringSsl {
    type Rng = BoringSslRng;

    fn from_entropy() -> Result<BoringSslRng, CryptoError> {
        Ok(BoringSslRng(Kind::RandBytes))
    }

    fn from_seed(seed: &[u8]) -> Result<BoringSslRng, CryptoError> {
        let mut entropy = sha384(seed);
        let drbg = unsafe { bssl_sys::CTR_DRBG_new(entropy.as_ptr(), ptr::null(), 0) };
        unsafe { bssl_sys::OPENSSL_cleanse(entropy.as_mut_ptr().cast(), ENTROPY_LEN) };
        let drbg = NonNull::new(drbg).ok_or(CryptoError::Internal)?;
        Ok(BoringSslRng(Kind::Drbg(drbg)))
    }

    fn rand_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
        unsafe { bssl_sys::RAND_bytes(out.as_mut_ptr(), out.len()) };
        Ok(())
    }
}

impl Rng for BoringSslRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let Kind::Drbg(drbg) = self.0 else {
            return BoringSsl::rand_bytes(out);
        };
        for chunk in out.chunks_mut(MAX_GENERATE_LEN) {
            let ok = unsafe {
                bssl_sys::CTR_DRBG_generate(
                    drbg.as_ptr(),
                    chunk.as_mut_ptr(),
                    chunk.len(),
                    ptr::null(),
                    0,
                )
            };
            if ok != 1 {
                return Err(CryptoError::Internal);
            }
        }
        Ok(())
    }

    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let Kind::Drbg(drbg) = self.0 else {
            return Ok(());
        };
        let mut entropy = sha384(data);
        let ok =
            unsafe { bssl_sys::CTR_DRBG_reseed(drbg.as_ptr(), entropy.as_ptr(), ptr::null(), 0) };
        unsafe { bssl_sys::OPENSSL_cleanse(entropy.as_mut_ptr().cast(), ENTROPY_LEN) };
        if ok != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(())
    }
}
