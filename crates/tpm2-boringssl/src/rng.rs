//! Random number generator backed by BoringSSL's FIPS-module AES-256-CTR DRBG
//! (`CTR_DRBG_STATE`) and BCM entropy (`BCM_rand_bytes`).

use core::ptr::{self, NonNull};

use tpm2::crypto::{CryptoError, Random, Rng, backend::HashState};

use crate::{BoringSsl, bcm, bssl_sys, hash::BoringSslHashState};

const ENTROPY_LEN: usize = bssl_sys::CTR_DRBG_ENTROPY_LEN as usize;
const MAX_GENERATE_LEN: usize = bssl_sys::CTR_DRBG_MAX_GENERATE_LENGTH as usize;

/// Stateful deterministic random bit generator backed by BoringSSL's FIPS
/// `CTR_DRBG_STATE` (NIST SP 800-90A AES-256-CTR DRBG).
pub struct BoringSslRng {
    drbg: NonNull<bssl_sys::CTR_DRBG_STATE>,
}

// SAFETY: `CTR_DRBG_STATE` is an owned heap-allocated state with no thread-local affinity.
unsafe impl Send for BoringSslRng {}
unsafe impl Sync for BoringSslRng {}

impl Drop for BoringSslRng {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::CTR_DRBG_free(self.drbg.as_ptr());
        }
    }
}

/// Derives a 48-byte (`CTR_DRBG_ENTROPY_LEN`) entropy block from arbitrary-length
/// input material using `BCM_sha384`.
fn derive_entropy(input: &[u8], out: &mut [u8; ENTROPY_LEN]) -> Result<(), CryptoError> {
    BoringSslHashState::<48>::hash(&[input], out)
}

impl BoringSslRng {
    /// Instantiates a DRBG from `entropy`, then cleanses `entropy`.
    fn from_entropy_block(entropy: &mut [u8; ENTROPY_LEN]) -> Result<Self, CryptoError> {
        let ptr = unsafe { bssl_sys::CTR_DRBG_new(entropy.as_ptr(), ptr::null(), 0) };
        unsafe {
            bssl_sys::OPENSSL_cleanse(entropy.as_mut_ptr().cast(), entropy.len());
        }
        let drbg = NonNull::new(ptr).ok_or(CryptoError::Internal)?;
        Ok(Self { drbg })
    }
}

impl Random for BoringSsl {
    type Rng = BoringSslRng;

    /// Seeds a DRBG from BoringSSL's BCM entropy source (`BCM_rand_bytes`).
    fn from_entropy() -> Result<BoringSslRng, CryptoError> {
        let mut entropy = [0u8; ENTROPY_LEN];
        Self::rand_bytes(&mut entropy)?;
        BoringSslRng::from_entropy_block(&mut entropy)
    }

    /// Seeds a DRBG from `SHA-384(seed)`.
    fn from_seed(seed: &[u8]) -> Result<BoringSslRng, CryptoError> {
        let mut entropy = [0u8; ENTROPY_LEN];
        derive_entropy(seed, &mut entropy)?;
        BoringSslRng::from_entropy_block(&mut entropy)
    }

    /// Fills `out` directly from `BCM_rand_bytes`.
    fn rand_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
        if !out.is_empty() {
            unsafe {
                bcm::bssl_BCM_rand_bytes(out.as_mut_ptr(), out.len());
            }
        }
        Ok(())
    }
}

impl Rng for BoringSslRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        for chunk in out.chunks_mut(MAX_GENERATE_LEN) {
            let ok = unsafe {
                bssl_sys::CTR_DRBG_generate(
                    self.drbg.as_ptr(),
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
        let mut entropy = [0u8; ENTROPY_LEN];
        derive_entropy(data, &mut entropy)?;
        let ok = unsafe {
            bssl_sys::CTR_DRBG_reseed(self.drbg.as_ptr(), entropy.as_ptr(), ptr::null(), 0)
        };
        unsafe {
            bssl_sys::OPENSSL_cleanse(entropy.as_mut_ptr().cast(), entropy.len());
        }
        if ok != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(())
    }
}
