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

/// Camellia-128-CMAC context wrapper for `BsslCryptoProvider`.
///
/// BoringSSL is built without Camellia (`OPENSSL_NO_CAMELLIA`), so this is a
/// fallback on the RustCrypto `cmac` and `camellia` crates.
pub struct BsslCmacCamellia128(cmac::Cmac<camellia::Camellia128>);

impl tpm2::crypto::Update for BsslCmacCamellia128 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<16> for BsslCmacCamellia128 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// Camellia-192-CMAC context wrapper for `BsslCryptoProvider`.
///
/// BoringSSL is built without Camellia (`OPENSSL_NO_CAMELLIA`), so this is a
/// fallback on the RustCrypto `cmac` and `camellia` crates.
pub struct BsslCmacCamellia192(cmac::Cmac<camellia::Camellia192>);

impl tpm2::crypto::Update for BsslCmacCamellia192 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<16> for BsslCmacCamellia192 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// Camellia-256-CMAC context wrapper for `BsslCryptoProvider`.
///
/// BoringSSL is built without Camellia (`OPENSSL_NO_CAMELLIA`), so this is a
/// fallback on the RustCrypto `cmac` and `camellia` crates.
pub struct BsslCmacCamellia256(cmac::Cmac<camellia::Camellia256>);

impl tpm2::crypto::Update for BsslCmacCamellia256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<16> for BsslCmacCamellia256 {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        use cmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
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

    type Camellia128Context = BsslCmacCamellia128;
    fn camellia128(&self, key: &[u8; 16]) -> Result<Self::Camellia128Context, CryptoError> {
        use cmac::Mac as _;
        // The key array always has the cipher's key length, so this cannot
        // fail; if it did, that would be an internal error.
        cmac::Cmac::<camellia::Camellia128>::new_from_slice(key)
            .map(BsslCmacCamellia128)
            .map_err(|_| CryptoError::Internal)
    }

    type Camellia192Context = BsslCmacCamellia192;
    fn camellia192(&self, key: &[u8; 24]) -> Result<Self::Camellia192Context, CryptoError> {
        use cmac::Mac as _;
        // The key array always has the cipher's key length, so this cannot
        // fail; if it did, that would be an internal error.
        cmac::Cmac::<camellia::Camellia192>::new_from_slice(key)
            .map(BsslCmacCamellia192)
            .map_err(|_| CryptoError::Internal)
    }

    type Camellia256Context = BsslCmacCamellia256;
    fn camellia256(&self, key: &[u8; 32]) -> Result<Self::Camellia256Context, CryptoError> {
        use cmac::Mac as _;
        // The key array always has the cipher's key length, so this cannot
        // fail; if it did, that would be an internal error.
        cmac::Cmac::<camellia::Camellia256>::new_from_slice(key)
            .map(BsslCmacCamellia256)
            .map_err(|_| CryptoError::Internal)
    }
}
