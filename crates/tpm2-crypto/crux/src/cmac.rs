use crate::CruxCryptoProvider;
use tpm2::crypto::CryptoError;

/// AES-128-CMAC context wrapper for `CruxCryptoProvider`.
pub struct CruxCmacAes128(cmac::Cmac<aes::Aes128>);

impl tpm2::crypto::Update for CruxCmacAes128 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<16> for CruxCmacAes128 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// AES-192-CMAC context wrapper for `CruxCryptoProvider`.
pub struct CruxCmacAes192(cmac::Cmac<aes::Aes192>);

impl tpm2::crypto::Update for CruxCmacAes192 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<16> for CruxCmacAes192 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// AES-256-CMAC context wrapper for `CruxCryptoProvider`.
pub struct CruxCmacAes256(cmac::Cmac<aes::Aes256>);

impl tpm2::crypto::Update for CruxCmacAes256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<16> for CruxCmacAes256 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// The keys are fixed-size arrays of the cipher's key length, so the
/// constructors only fail ([`CryptoError::Internal`]) if the `cmac` crate
/// rejects a correctly sized key, which it never does.
impl tpm2::crypto::Cmac for CruxCryptoProvider {
    type Aes128Context = CruxCmacAes128;
    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Context, CryptoError> {
        use cmac::Mac as _;
        cmac::Cmac::<aes::Aes128>::new_from_slice(key)
            .map(CruxCmacAes128)
            .map_err(|_| CryptoError::Internal)
    }

    type Aes192Context = CruxCmacAes192;
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Context, CryptoError> {
        use cmac::Mac as _;
        cmac::Cmac::<aes::Aes192>::new_from_slice(key)
            .map(CruxCmacAes192)
            .map_err(|_| CryptoError::Internal)
    }

    type Aes256Context = CruxCmacAes256;
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Context, CryptoError> {
        use cmac::Mac as _;
        cmac::Cmac::<aes::Aes256>::new_from_slice(key)
            .map(CruxCmacAes256)
            .map_err(|_| CryptoError::Internal)
    }

    type Sm4_128Context = !;
    type Camellia128Context = !;
    type Camellia192Context = !;
    type Camellia256Context = !;
}
