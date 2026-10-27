//! Hashes, generic over the OpenSSL digest's NID.

use core::ffi::c_int;
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl_sys as ffi;
use tpm2::crypto::{
    CryptoError,
    backend::{Hash, HashState},
};

/// Returns the OpenSSL digest with NID `nid`.
pub(crate) fn digest(nid: c_int) -> Result<MessageDigest, CryptoError> {
    MessageDigest::from_nid(Nid::from_raw(nid)).ok_or(CryptoError::Unsupported)
}

/// Streaming hash state for the `SIZE`-byte OpenSSL digest with NID `NID`.
pub struct OpensslHash<const NID: c_int, const SIZE: usize>(Hasher);

impl<const NID: c_int, const SIZE: usize> HashState<SIZE> for OpensslHash<NID, SIZE> {
    fn init() -> Result<Self, CryptoError> {
        Hasher::new(digest(NID)?)
            .map(Self)
            .map_err(|_| CryptoError::Internal)
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data).map_err(|_| CryptoError::Internal)
    }
    fn finalize(&mut self, out: &mut [u8; SIZE]) -> Result<(), CryptoError> {
        let digest = self.0.finish().map_err(|_| CryptoError::Internal)?;
        out.copy_from_slice(&digest);
        Ok(())
    }
}

impl Hash for super::OpensslBackend {
    type Sha1 = OpensslHash<{ ffi::NID_sha1 }, 20>;
    type Sha256 = OpensslHash<{ ffi::NID_sha256 }, 32>;
    type Sha384 = OpensslHash<{ ffi::NID_sha384 }, 48>;
    type Sha512 = OpensslHash<{ ffi::NID_sha512 }, 64>;
    type Sm3_256 = OpensslHash<{ ffi::NID_sm3 }, 32>;
    type Sha3_256 = OpensslHash<{ ffi::NID_sha3_256 }, 32>;
    type Sha3_384 = OpensslHash<{ ffi::NID_sha3_384 }, 48>;
    type Sha3_512 = OpensslHash<{ ffi::NID_sha3_512 }, 64>;
}
