use crate::errors::TpmResult;
use core::marker::PhantomData;

#[allow(non_camel_case_types)]
pub enum DigestType {
    SHA1,
    SHA2_256,
    SHA2_384,
    SHA2_512,
}

pub trait Crypto {
    /// Handle for hashes. Do not make Copy or Clone. Default should be an invalid handle
    type HashHandle: Default;

    fn hash_start(digest_type: DigestType) -> TpmResult<Self::HashHandle>;
    fn hash_update(handle: &mut Self::HashHandle, data: &[u8]) -> TpmResult<()>;
    fn hash_finish(handle: Self::HashHandle, out: &mut [u8]) -> TpmResult<usize>;
    fn hash_abort(handle: Self::HashHandle) -> TpmResult<()>;
}

pub struct CryptoEngine<C: Crypto> {
    phantom_data: PhantomData<C>,
}

impl<C: Crypto> CryptoEngine<C> {
    pub fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }

    pub fn start_hash(&self, digest_type: DigestType) -> TpmResult<HashOperation<C>> {
        HashOperation::new(digest_type)
    }
}

pub struct HashOperation<C: Crypto> {
    handle: C::HashHandle,
}

impl<C: Crypto> HashOperation<C> {
    pub fn new(digest_type: DigestType) -> TpmResult<Self> {
        let handle = C::hash_start(digest_type)?;
        Ok(Self { handle })
    }

    pub fn update(&mut self, data: &[u8]) -> TpmResult<()> {
        C::hash_update(&mut self.handle, data)?;
        Ok(())
    }

    pub fn finish(mut self, out: &mut [u8]) -> TpmResult<usize> {
        let handle = core::mem::take(&mut self.handle);
        // Since we are finishing the hash operation normally, we do not want the normal
        // drop glue to call abort
        core::mem::forget(self);
        C::hash_finish(handle, out)
    }
}

impl<C: Crypto> Drop for HashOperation<C> {
    fn drop(&mut self) {
        let handle = core::mem::take(&mut self.handle);
        // TODO report general failure somehow?
        let _ = C::hash_abort(handle);
    }
}

// TODO Put in separate unit test folder location
#[cfg(test)]
pub mod testing {
    pub use super::*;

    pub struct FakeCrypto;

    #[derive(Default)]
    pub struct FakeHashContext {
        buffer: [u8; 32],
    }

    impl Crypto for FakeCrypto {
        type HashHandle = FakeHashContext;

        fn hash_start(_digest_type: DigestType) -> TpmResult<Self::HashHandle> {
            Ok(Self::HashHandle::default())
        }

        fn hash_update(handle: &mut Self::HashHandle, data: &[u8]) -> TpmResult<()> {
            // TODO use an actual hash implementation instead of just XORing in tests
            for chunk in data.chunks(handle.buffer.len()) {
                for (hash, input) in handle.buffer.iter_mut().zip(chunk) {
                    *hash ^= *input;
                }
            }
            Ok(())
        }

        fn hash_finish(handle: Self::HashHandle, out: &mut [u8]) -> TpmResult<usize> {
            let size = out.len().min(handle.buffer.len());
            out[..size].copy_from_slice(&handle.buffer[..size]);
            Ok(size)
        }

        fn hash_abort(_handle: Self::HashHandle) -> TpmResult<()> {
            Ok(())
        }
    }
}
