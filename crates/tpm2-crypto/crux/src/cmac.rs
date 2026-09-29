use crate::CruxCryptoProvider;
use tpm2::crypto::CryptoError;

/// AES-128-CMAC context wrapper for `CruxCryptoProvider`.
pub struct CruxCmacAes128(cmac::Cmac<aes::Aes128>);

impl tpm2::crypto::Update<CryptoError> for CruxCmacAes128 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<16, CryptoError> for CruxCmacAes128 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// AES-192-CMAC context wrapper for `CruxCryptoProvider`.
pub struct CruxCmacAes192(cmac::Cmac<aes::Aes192>);

impl tpm2::crypto::Update<CryptoError> for CruxCmacAes192 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<16, CryptoError> for CruxCmacAes192 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// AES-256-CMAC context wrapper for `CruxCryptoProvider`.
pub struct CruxCmacAes256(cmac::Cmac<aes::Aes256>);

impl tpm2::crypto::Update<CryptoError> for CruxCmacAes256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<16, CryptoError> for CruxCmacAes256 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

impl tpm2::crypto::Cmac for CruxCryptoProvider {
    fn invalid_key(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    type Aes128Ctx = CruxCmacAes128;
    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Ctx, CryptoError> {
        use cmac::Mac as _;
        cmac::Cmac::<aes::Aes128>::new_from_slice(key)
            .map(CruxCmacAes128)
            .map_err(|_| CryptoError::InvalidData)
    }

    type Aes192Ctx = CruxCmacAes192;
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Ctx, CryptoError> {
        use cmac::Mac as _;
        cmac::Cmac::<aes::Aes192>::new_from_slice(key)
            .map(CruxCmacAes192)
            .map_err(|_| CryptoError::InvalidData)
    }

    type Aes256Ctx = CruxCmacAes256;
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Ctx, CryptoError> {
        use cmac::Mac as _;
        cmac::Cmac::<aes::Aes256>::new_from_slice(key)
            .map(CruxCmacAes256)
            .map_err(|_| CryptoError::InvalidData)
    }

    type Sm4_128Ctx = !;
    type Camellia128Ctx = !;
    type Camellia192Ctx = !;
    type Camellia256Ctx = !;
}
