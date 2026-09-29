use crate::CruxCryptoProvider;
use aes::cipher::KeyInit as _;
use tpm2::TpmiAlgSymMode;
use tpm2::crypto::{CryptoError, Finalize, Symmetric, UpdateInPlace};

/// Generic CFB-128 streaming encryptor over a 128-bit block cipher.
pub struct CfbEncryptor<C> {
    cipher: C,
    iv: [u8; 16],
    keystream: [u8; 16],
    pos: usize,
}

impl<C: aes::cipher::BlockEncrypt> CfbEncryptor<C> {
    fn new(cipher: C, iv: &[u8; 16]) -> Self {
        Self {
            cipher,
            iv: *iv,
            keystream: [0u8; 16],
            pos: 16,
        }
    }
}

impl<C: aes::cipher::BlockEncrypt> UpdateInPlace<CryptoError> for CfbEncryptor<C> {
    fn update(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        for byte in data.iter_mut() {
            if self.pos == 16 {
                let mut block =
                    aes::cipher::generic_array::GenericArray::clone_from_slice(&self.iv);
                self.cipher.encrypt_block(&mut block);
                self.keystream.copy_from_slice(&block);
                self.pos = 0;
            }
            let c = *byte ^ self.keystream[self.pos];
            self.iv[self.pos] = c;
            *byte = c;
            self.pos += 1;
        }
        Ok(())
    }
}

impl<C> Finalize<16, CryptoError> for CfbEncryptor<C> {
    fn finalize(self, iv_out: &mut [u8; 16]) -> Result<(), CryptoError> {
        *iv_out = self.iv;
        Ok(())
    }
}

/// Generic CFB-128 streaming decryptor over a 128-bit block cipher.
pub struct CfbDecryptor<C> {
    cipher: C,
    iv: [u8; 16],
    keystream: [u8; 16],
    pos: usize,
}

impl<C: aes::cipher::BlockEncrypt> CfbDecryptor<C> {
    fn new(cipher: C, iv: &[u8; 16]) -> Self {
        Self {
            cipher,
            iv: *iv,
            keystream: [0u8; 16],
            pos: 16,
        }
    }
}

impl<C: aes::cipher::BlockEncrypt> UpdateInPlace<CryptoError> for CfbDecryptor<C> {
    fn update(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        for byte in data.iter_mut() {
            if self.pos == 16 {
                let mut block =
                    aes::cipher::generic_array::GenericArray::clone_from_slice(&self.iv);
                self.cipher.encrypt_block(&mut block);
                self.keystream.copy_from_slice(&block);
                self.pos = 0;
            }
            let c = *byte;
            let p = c ^ self.keystream[self.pos];
            self.iv[self.pos] = c;
            *byte = p;
            self.pos += 1;
        }
        Ok(())
    }
}

impl<C> Finalize<16, CryptoError> for CfbDecryptor<C> {
    fn finalize(self, iv_out: &mut [u8; 16]) -> Result<(), CryptoError> {
        *iv_out = self.iv;
        Ok(())
    }
}

impl Symmetric for CruxCryptoProvider {
    fn invalid_key(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn invalid_iv(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    type Aes128EncryptCtx = CfbEncryptor<aes::Aes128>;
    fn aes128_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Aes128EncryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        aes::Aes128::new_from_slice(key)
            .map(|c| CfbEncryptor::new(c, iv))
            .map_err(|_| CryptoError::InvalidData)
    }

    type Aes128DecryptCtx = CfbDecryptor<aes::Aes128>;
    fn aes128_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Aes128DecryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        aes::Aes128::new_from_slice(key)
            .map(|c| CfbDecryptor::new(c, iv))
            .map_err(|_| CryptoError::InvalidData)
    }

    type Aes192EncryptCtx = CfbEncryptor<aes::Aes192>;
    fn aes192_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Aes192EncryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        aes::Aes192::new_from_slice(key)
            .map(|c| CfbEncryptor::new(c, iv))
            .map_err(|_| CryptoError::InvalidData)
    }

    type Aes192DecryptCtx = CfbDecryptor<aes::Aes192>;
    fn aes192_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Aes192DecryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        aes::Aes192::new_from_slice(key)
            .map(|c| CfbDecryptor::new(c, iv))
            .map_err(|_| CryptoError::InvalidData)
    }

    type Aes256EncryptCtx = CfbEncryptor<aes::Aes256>;
    fn aes256_encrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Aes256EncryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        aes::Aes256::new_from_slice(key)
            .map(|c| CfbEncryptor::new(c, iv))
            .map_err(|_| CryptoError::InvalidData)
    }

    type Aes256DecryptCtx = CfbDecryptor<aes::Aes256>;
    fn aes256_decrypt(
        &self,
        mode: TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Aes256DecryptCtx, CryptoError> {
        if mode != TpmiAlgSymMode::CFB {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        aes::Aes256::new_from_slice(key)
            .map(|c| CfbDecryptor::new(c, iv))
            .map_err(|_| CryptoError::InvalidData)
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
