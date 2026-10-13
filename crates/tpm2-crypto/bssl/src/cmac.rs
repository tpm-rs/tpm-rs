use crate::BsslCryptoProvider;
use tpm2::crypto::CryptoError;

/// AES-128-CMAC context wrapper for `BsslCryptoProvider`.
pub struct BsslCmacAes128(crate::bssl::CmacAes128);

impl tpm2::crypto::Update for BsslCmacAes128 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data).map_err(Into::into)
    }
}

impl tpm2::crypto::Finalize<16> for BsslCmacAes128 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        self.0.finalize(out).map_err(Into::into)
    }
}

/// AES-192-CMAC context wrapper for `BsslCryptoProvider`.
pub struct BsslCmacAes192(crate::bssl::CmacAes192);

impl tpm2::crypto::Update for BsslCmacAes192 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data).map_err(Into::into)
    }
}

impl tpm2::crypto::Finalize<16> for BsslCmacAes192 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        self.0.finalize(out).map_err(Into::into)
    }
}

/// AES-256-CMAC context wrapper for `BsslCryptoProvider`.
pub struct BsslCmacAes256(crate::bssl::CmacAes256);

impl tpm2::crypto::Update for BsslCmacAes256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data).map_err(Into::into)
    }
}

impl tpm2::crypto::Finalize<16> for BsslCmacAes256 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        self.0.finalize(out).map_err(Into::into)
    }
}

impl tpm2::crypto::Cmac for BsslCryptoProvider {
    type Aes128Context = BsslCmacAes128;
    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Context, CryptoError> {
        crate::bssl::CmacAes128::new(key)
            .map(BsslCmacAes128)
            .map_err(Into::into)
    }

    type Aes192Context = BsslCmacAes192;
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Context, CryptoError> {
        crate::bssl::CmacAes192::new(key)
            .map(BsslCmacAes192)
            .map_err(Into::into)
    }

    type Aes256Context = BsslCmacAes256;
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Context, CryptoError> {
        crate::bssl::CmacAes256::new(key)
            .map(BsslCmacAes256)
            .map_err(Into::into)
    }

    type Sm4_128Context = !;
    type Camellia128Context = !;
    type Camellia192Context = !;
    type Camellia256Context = !;
}
