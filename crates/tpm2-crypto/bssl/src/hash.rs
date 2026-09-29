use crate::BsslCryptoProvider;
use tpm2::crypto::CryptoError;

pub struct BsslSha1(bssl_crypto::digest::InsecureSha1);

impl tpm2::crypto::Update<CryptoError> for BsslSha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<20, CryptoError> for BsslSha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct BsslSha256(bssl_crypto::digest::Sha256);

impl tpm2::crypto::Update<CryptoError> for BsslSha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<32, CryptoError> for BsslSha256 {
    fn finalize(self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct BsslSha384(bssl_crypto::digest::Sha384);

impl tpm2::crypto::Update<CryptoError> for BsslSha384 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<48, CryptoError> for BsslSha384 {
    fn finalize(self, out: &mut [u8; 48]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct BsslSha512(bssl_crypto::digest::Sha512);

impl tpm2::crypto::Update<CryptoError> for BsslSha512 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<64, CryptoError> for BsslSha512 {
    fn finalize(self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

impl tpm2::crypto::Hash for BsslCryptoProvider {
    type Sha1Ctx = BsslSha1;
    fn sha1(&self) -> Result<Self::Sha1Ctx, CryptoError> {
        Ok(BsslSha1(bssl_crypto::digest::InsecureSha1::new()))
    }

    type Sha256Ctx = BsslSha256;
    fn sha256(&self) -> Result<Self::Sha256Ctx, CryptoError> {
        Ok(BsslSha256(bssl_crypto::digest::Sha256::new()))
    }

    type Sha384Ctx = BsslSha384;
    fn sha384(&self) -> Result<Self::Sha384Ctx, CryptoError> {
        Ok(BsslSha384(bssl_crypto::digest::Sha384::new()))
    }

    type Sha512Ctx = BsslSha512;
    fn sha512(&self) -> Result<Self::Sha512Ctx, CryptoError> {
        Ok(BsslSha512(bssl_crypto::digest::Sha512::new()))
    }

    type Sm3_256Ctx = !;
    type Sha3_256Ctx = !;
    type Sha3_384Ctx = !;
    type Sha3_512Ctx = !;
}

pub struct BsslHmacSha1(crate::bssl::HmacSha1);

impl tpm2::crypto::Update<CryptoError> for BsslHmacSha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data)
    }
}

impl tpm2::crypto::Finalize<20, CryptoError> for BsslHmacSha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        self.0.finalize(out)
    }
}

pub struct BsslHmacSha256(bssl_crypto::hmac::HmacSha256);

impl tpm2::crypto::Update<CryptoError> for BsslHmacSha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<32, CryptoError> for BsslHmacSha256 {
    fn finalize(self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct BsslHmacSha384(bssl_crypto::hmac::HmacSha384);

impl tpm2::crypto::Update<CryptoError> for BsslHmacSha384 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<48, CryptoError> for BsslHmacSha384 {
    fn finalize(self, out: &mut [u8; 48]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct BsslHmacSha512(bssl_crypto::hmac::HmacSha512);

impl tpm2::crypto::Update<CryptoError> for BsslHmacSha512 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<64, CryptoError> for BsslHmacSha512 {
    fn finalize(self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

impl tpm2::crypto::Hmac for BsslCryptoProvider {
    type Sha1Ctx = BsslHmacSha1;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Ctx, CryptoError> {
        crate::bssl::HmacSha1::new_from_slice(key).map(BsslHmacSha1)
    }

    type Sha256Ctx = BsslHmacSha256;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Ctx, CryptoError> {
        Ok(BsslHmacSha256(
            bssl_crypto::hmac::HmacSha256::new_from_slice(key),
        ))
    }

    type Sha384Ctx = BsslHmacSha384;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Ctx, CryptoError> {
        Ok(BsslHmacSha384(
            bssl_crypto::hmac::HmacSha384::new_from_slice(key),
        ))
    }

    type Sha512Ctx = BsslHmacSha512;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Ctx, CryptoError> {
        Ok(BsslHmacSha512(
            bssl_crypto::hmac::HmacSha512::new_from_slice(key),
        ))
    }

    type Sm3_256Ctx = !;
    type Sha3_256Ctx = !;
    type Sha3_384Ctx = !;
    type Sha3_512Ctx = !;
}
