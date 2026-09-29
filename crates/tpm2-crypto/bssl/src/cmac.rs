use crate::BsslCryptoProvider;
use tpm2::crypto::CryptoError;

/// AES-128-CMAC context wrapper for `BsslCryptoProvider`.
pub struct BsslCmacAes128(crate::bssl::CmacAes128);

impl tpm2::crypto::Update<CryptoError> for BsslCmacAes128 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data)
    }
}

impl tpm2::crypto::Finalize<16, CryptoError> for BsslCmacAes128 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        self.0.finalize(out)
    }
}

/// AES-192-CMAC context wrapper for `BsslCryptoProvider`.
pub struct BsslCmacAes192(crate::bssl::CmacAes192);

impl tpm2::crypto::Update<CryptoError> for BsslCmacAes192 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data)
    }
}

impl tpm2::crypto::Finalize<16, CryptoError> for BsslCmacAes192 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        self.0.finalize(out)
    }
}

/// AES-256-CMAC context wrapper for `BsslCryptoProvider`.
pub struct BsslCmacAes256(crate::bssl::CmacAes256);

impl tpm2::crypto::Update<CryptoError> for BsslCmacAes256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data)
    }
}

impl tpm2::crypto::Finalize<16, CryptoError> for BsslCmacAes256 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        self.0.finalize(out)
    }
}

impl tpm2::crypto::Cmac for BsslCryptoProvider {
    fn invalid_key(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    type Aes128Ctx = BsslCmacAes128;
    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Ctx, CryptoError> {
        crate::bssl::CmacAes128::new(key).map(BsslCmacAes128)
    }

    type Aes192Ctx = BsslCmacAes192;
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Ctx, CryptoError> {
        crate::bssl::CmacAes192::new(key).map(BsslCmacAes192)
    }

    type Aes256Ctx = BsslCmacAes256;
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Ctx, CryptoError> {
        crate::bssl::CmacAes256::new(key).map(BsslCmacAes256)
    }

    type Sm4_128Ctx = !;
    type Camellia128Ctx = !;
    type Camellia192Ctx = !;
    type Camellia256Ctx = !;
}
