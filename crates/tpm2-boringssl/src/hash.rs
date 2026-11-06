//! SHA-1 and SHA-2 (`SHA-256`, `SHA-384`, `SHA-512`) hash implementations via
//! BoringSSL's `SHA*_Init`, `SHA*_Update`, and `SHA*_Final`.

use core::mem::MaybeUninit;

use tpm2::crypto::{
    CryptoError,
    backend::{Hash, HashState},
};

use crate::BoringSsl;

#[derive(Clone)]
enum HashCtx {
    Sha1(bssl_sys::SHA_CTX),
    Sha256(bssl_sys::SHA256_CTX),
    Sha384(bssl_sys::SHA512_CTX),
    Sha512(bssl_sys::SHA512_CTX),
}

/// Streaming hash state backed by BoringSSL `SHA*` functions.
#[derive(Clone)]
pub struct BoringSslHashState<const DIGEST_SIZE: usize> {
    ctx: HashCtx,
}

macro_rules! impl_hash {
    ($size:literal, $variant:ident, $ctx:ident, $init:ident, $update:ident, $final:ident) => {
        impl HashState<$size> for BoringSslHashState<$size> {
            fn init() -> Result<Self, CryptoError> {
                let mut ctx = MaybeUninit::<bssl_sys::$ctx>::uninit();
                unsafe {
                    bssl_sys::$init(ctx.as_mut_ptr());
                    Ok(Self {
                        ctx: HashCtx::$variant(ctx.assume_init()),
                    })
                }
            }

            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                let HashCtx::$variant(ctx) = &mut self.ctx else {
                    return Err(CryptoError::Internal);
                };
                if !data.is_empty() {
                    unsafe {
                        bssl_sys::$update(ctx, data.as_ptr().cast(), data.len());
                    }
                }
                Ok(())
            }

            fn finalize(&mut self, out: &mut [u8; $size]) -> Result<(), CryptoError> {
                let HashCtx::$variant(ctx) = &mut self.ctx else {
                    return Err(CryptoError::Internal);
                };
                unsafe {
                    bssl_sys::$final(out.as_mut_ptr(), ctx);
                }
                Ok(())
            }
        }
    };
}

impl_hash!(20, Sha1, SHA_CTX, SHA1_Init, SHA1_Update, SHA1_Final);
impl_hash!(
    32,
    Sha256,
    SHA256_CTX,
    SHA256_Init,
    SHA256_Update,
    SHA256_Final
);
impl_hash!(
    48,
    Sha384,
    SHA512_CTX,
    SHA384_Init,
    SHA384_Update,
    SHA384_Final
);
impl_hash!(
    64,
    Sha512,
    SHA512_CTX,
    SHA512_Init,
    SHA512_Update,
    SHA512_Final
);

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
