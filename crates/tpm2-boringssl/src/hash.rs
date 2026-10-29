//! SHA-1 and SHA-2 (`SHA-256`, `SHA-384`, `SHA-512`) hash implementations via
//! BoringSSL's BCM (`BCM_sha*`) entry points.

use core::mem::MaybeUninit;

use tpm2::crypto::{
    CryptoError,
    backend::{Hash, HashState},
};

use crate::{BoringSsl, bcm};

#[derive(Clone)]
enum HashCtx {
    Sha1(bcm::SHA_CTX),
    Sha256(bcm::SHA256_CTX),
    Sha384(bcm::SHA512_CTX),
    Sha512(bcm::SHA512_CTX),
}

/// Streaming hash state backed by BoringSSL `BCM_sha*` functions.
#[derive(Clone)]
pub struct BoringSslHashState<const DIGEST_SIZE: usize> {
    ctx: HashCtx,
}

impl HashState<20> for BoringSslHashState<20> {
    fn init() -> Result<Self, CryptoError> {
        let mut ctx = MaybeUninit::<bcm::SHA_CTX>::uninit();
        unsafe {
            bcm::bssl_BCM_sha1_init(ctx.as_mut_ptr());
            Ok(Self {
                ctx: HashCtx::Sha1(ctx.assume_init()),
            })
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let HashCtx::Sha1(ctx) = &mut self.ctx else {
            return Err(CryptoError::Internal);
        };
        if !data.is_empty() {
            unsafe {
                bcm::bssl_BCM_sha1_update(ctx, data.as_ptr().cast(), data.len());
            }
        }
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        let HashCtx::Sha1(ctx) = &mut self.ctx else {
            return Err(CryptoError::Internal);
        };
        unsafe {
            bcm::bssl_BCM_sha1_final(out.as_mut_ptr(), ctx);
        }
        Ok(())
    }
}

impl HashState<32> for BoringSslHashState<32> {
    fn init() -> Result<Self, CryptoError> {
        let mut ctx = MaybeUninit::<bcm::SHA256_CTX>::uninit();
        unsafe {
            bcm::bssl_BCM_sha256_init(ctx.as_mut_ptr());
            Ok(Self {
                ctx: HashCtx::Sha256(ctx.assume_init()),
            })
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let HashCtx::Sha256(ctx) = &mut self.ctx else {
            return Err(CryptoError::Internal);
        };
        if !data.is_empty() {
            unsafe {
                bcm::bssl_BCM_sha256_update(ctx, data.as_ptr().cast(), data.len());
            }
        }
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        let HashCtx::Sha256(ctx) = &mut self.ctx else {
            return Err(CryptoError::Internal);
        };
        unsafe {
            bcm::bssl_BCM_sha256_final(out.as_mut_ptr(), ctx);
        }
        Ok(())
    }
}

impl HashState<48> for BoringSslHashState<48> {
    fn init() -> Result<Self, CryptoError> {
        let mut ctx = MaybeUninit::<bcm::SHA512_CTX>::uninit();
        unsafe {
            bcm::bssl_BCM_sha384_init(ctx.as_mut_ptr());
            Ok(Self {
                ctx: HashCtx::Sha384(ctx.assume_init()),
            })
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let HashCtx::Sha384(ctx) = &mut self.ctx else {
            return Err(CryptoError::Internal);
        };
        if !data.is_empty() {
            unsafe {
                bcm::bssl_BCM_sha384_update(ctx, data.as_ptr().cast(), data.len());
            }
        }
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; 48]) -> Result<(), CryptoError> {
        let HashCtx::Sha384(ctx) = &mut self.ctx else {
            return Err(CryptoError::Internal);
        };
        unsafe {
            bcm::bssl_BCM_sha384_final(out.as_mut_ptr(), ctx);
        }
        Ok(())
    }
}

impl HashState<64> for BoringSslHashState<64> {
    fn init() -> Result<Self, CryptoError> {
        let mut ctx = MaybeUninit::<bcm::SHA512_CTX>::uninit();
        unsafe {
            bcm::bssl_BCM_sha512_init(ctx.as_mut_ptr());
            Ok(Self {
                ctx: HashCtx::Sha512(ctx.assume_init()),
            })
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let HashCtx::Sha512(ctx) = &mut self.ctx else {
            return Err(CryptoError::Internal);
        };
        if !data.is_empty() {
            unsafe {
                bcm::bssl_BCM_sha512_update(ctx, data.as_ptr().cast(), data.len());
            }
        }
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        let HashCtx::Sha512(ctx) = &mut self.ctx else {
            return Err(CryptoError::Internal);
        };
        unsafe {
            bcm::bssl_BCM_sha512_final(out.as_mut_ptr(), ctx);
        }
        Ok(())
    }
}

impl Hash for BoringSsl {
    type Sha1 = BoringSslHashState<20>;
    type Sha256 = BoringSslHashState<32>;
    type Sha384 = BoringSslHashState<48>;
    type Sha512 = BoringSslHashState<64>;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}
