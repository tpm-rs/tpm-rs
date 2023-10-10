use crate::{
    constants::{
        TPM2_SHA1_DIGEST_SIZE, TPM2_SHA256_DIGEST_SIZE, TPM2_SHA384_DIGEST_SIZE,
        TPM2_SHA512_DIGEST_SIZE, TPM2_SM3_256_DIGEST_SIZE,
    },
    errors::{TpmError, TpmResult},
};
use arrayvec::ArrayVec;

pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3_256,
    // NOTE: If a larger length is added, MUST update HashAlg::MAX_ALG_LEN
}

impl HashAlg {
    const MAX_ALG_LEN: Self = Self::Sha512;

    pub const fn size(self) -> usize {
        match self {
            HashAlg::Sha1 => TPM2_SHA1_DIGEST_SIZE,
            HashAlg::Sha256 => TPM2_SHA256_DIGEST_SIZE,
            HashAlg::Sha384 => TPM2_SHA384_DIGEST_SIZE,
            HashAlg::Sha512 => TPM2_SHA512_DIGEST_SIZE,
            HashAlg::Sm3_256 => TPM2_SM3_256_DIGEST_SIZE,
        }
    }
}

/// A common base struct that can be used for all digests, signatures, and keys.
#[derive(Debug, PartialEq, Eq)]
pub struct Digest(ArrayVec<u8, { Self::MAX_SIZE }>);

impl Digest {
    pub const MAX_SIZE: usize = HashAlg::MAX_ALG_LEN as usize;

    pub fn new(bytes: &[u8]) -> TpmResult<Digest> {
        let mut vec = ArrayVec::new();
        vec.try_extend_from_slice(bytes)
            .map_err(|_| TpmError::TPM2_RC_SIZE)?;
        Ok(Digest(vec))
    }

    pub fn default(algs: HashAlg) -> Digest {
        let mut vec = ArrayVec::new();
        for _ in 0..algs.size() {
            vec.push(0);
        }
        Digest(vec)
    }

    pub fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }
}

pub trait Hasher: Sized {
    /// Initializes a Hasher object.
    fn new() -> TpmResult<Self>;

    /// Adds a chunk to the running hash.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Value to add to hash.
    fn update(&mut self, bytes: &[u8]) -> TpmResult<()>;

    /// Finish a running hash operation and return the result.
    ///
    /// Once this function has been called, the object can no longer be used and
    /// a new one must be created to hash more data.
    fn finish(self) -> TpmResult<Digest>;
}
