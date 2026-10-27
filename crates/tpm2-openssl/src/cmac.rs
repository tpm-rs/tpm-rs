//! CMAC, generic over the NID of the OpenSSL block cipher's CBC mode.

use core::ffi::c_int;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::Cipher;
use openssl_sys as ffi;
use tpm2::crypto::{
    CryptoError,
    backend::{Cmac, CmacState},
};

/// Streaming CMAC state for the block cipher with `KEY_SIZE`-byte keys whose
/// CBC mode has NID `CBC`.
pub struct OpensslCmac<const CBC: c_int, const KEY_SIZE: usize>(Signer<'static>);

impl<const CBC: c_int, const KEY_SIZE: usize> CmacState<KEY_SIZE> for OpensslCmac<CBC, KEY_SIZE> {
    fn init(key: &[u8; KEY_SIZE]) -> Result<Self, CryptoError> {
        let cipher = Cipher::from_nid(Nid::from_raw(CBC)).ok_or(CryptoError::Unsupported)?;
        let pkey = PKey::cmac(&cipher, key).map_err(|_| CryptoError::Internal)?;
        let signer = Signer::new_without_digest(&pkey).map_err(|_| CryptoError::Internal)?;
        Ok(Self(signer))
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data).map_err(|_| CryptoError::Internal)
    }
    fn finalize(&mut self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        let sig = self.0.sign_to_vec().map_err(|_| CryptoError::Internal)?;
        out.copy_from_slice(&sig);
        Ok(())
    }
}

impl Cmac for super::OpensslBackend {
    type Aes128 = OpensslCmac<{ ffi::NID_aes_128_cbc }, 16>;
    type Aes192 = OpensslCmac<{ ffi::NID_aes_192_cbc }, 24>;
    type Aes256 = OpensslCmac<{ ffi::NID_aes_256_cbc }, 32>;
    type Sm4_128 = OpensslCmac<{ ffi::NID_sm4_cbc }, 16>;
    type Camellia128 = OpensslCmac<{ ffi::NID_camellia_128_cbc }, 16>;
    type Camellia192 = OpensslCmac<{ ffi::NID_camellia_192_cbc }, 24>;
    type Camellia256 = OpensslCmac<{ ffi::NID_camellia_256_cbc }, 32>;
}
