use crate::BsslCryptoProvider;
use tpm2::TpmiAlgSymMode;
use tpm2::crypto::{CryptoError, Finalize, Symmetric, UpdateInPlace};

/// AES-128-CFB context wrapper for `BsslCryptoProvider`.
pub struct BsslAes128Cfb(crate::bssl::Aes128Cfb);

impl UpdateInPlace<CryptoError> for BsslAes128Cfb {
    fn update(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        self.0.update(data)
    }
}

impl Finalize<16, CryptoError> for BsslAes128Cfb {
    fn finalize(self, iv_out: &mut [u8; 16]) -> Result<(), CryptoError> {
        self.0.finalize(iv_out)
    }
}

/// AES-192-CFB context wrapper for `BsslCryptoProvider`.
pub struct BsslAes192Cfb(crate::bssl::Aes192Cfb);

impl UpdateInPlace<CryptoError> for BsslAes192Cfb {
    fn update(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        self.0.update(data)
    }
}

impl Finalize<16, CryptoError> for BsslAes192Cfb {
    fn finalize(self, iv_out: &mut [u8; 16]) -> Result<(), CryptoError> {
        self.0.finalize(iv_out)
    }
}

/// AES-256-CFB context wrapper for `BsslCryptoProvider`.
pub struct BsslAes256Cfb(crate::bssl::Aes256Cfb);

impl UpdateInPlace<CryptoError> for BsslAes256Cfb {
    fn update(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        self.0.update(data)
    }
}

impl Finalize<16, CryptoError> for BsslAes256Cfb {
    fn finalize(self, iv_out: &mut [u8; 16]) -> Result<(), CryptoError> {
        self.0.finalize(iv_out)
    }
}

impl Symmetric for BsslCryptoProvider {
    fn invalid_key(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn invalid_iv(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    type Aes128EncryptCtx = BsslAes128Cfb;
    fn aes128_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Aes128EncryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        crate::bssl::Aes128Cfb::new_encrypt(key, iv).map(BsslAes128Cfb)
    }

    type Aes128DecryptCtx = BsslAes128Cfb;
    fn aes128_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Aes128DecryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        crate::bssl::Aes128Cfb::new_decrypt(key, iv).map(BsslAes128Cfb)
    }

    type Aes192EncryptCtx = BsslAes192Cfb;
    fn aes192_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Aes192EncryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        crate::bssl::Aes192Cfb::new_encrypt(key, iv).map(BsslAes192Cfb)
    }

    type Aes192DecryptCtx = BsslAes192Cfb;
    fn aes192_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Aes192DecryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        crate::bssl::Aes192Cfb::new_decrypt(key, iv).map(BsslAes192Cfb)
    }

    type Aes256EncryptCtx = BsslAes256Cfb;
    fn aes256_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Aes256EncryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        crate::bssl::Aes256Cfb::new_encrypt(key, iv).map(BsslAes256Cfb)
    }

    type Aes256DecryptCtx = BsslAes256Cfb;
    fn aes256_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Aes256DecryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        crate::bssl::Aes256Cfb::new_decrypt(key, iv).map(BsslAes256Cfb)
    }

    type Sm4_128EncryptCtx = !;
    type Sm4_128DecryptCtx = !;
    type Camellia128EncryptCtx = !;
    type Camellia128DecryptCtx = !;
    type Camellia192EncryptCtx = !;
    type Camellia192DecryptCtx = !;
    type Camellia256EncryptCtx = !;
    type Camellia256DecryptCtx = !;
}
