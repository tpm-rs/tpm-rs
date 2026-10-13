use crate::BsslCryptoProvider;
use tpm2::crypto::CryptoError;

pub struct BsslSha1(bssl_crypto::digest::InsecureSha1);

impl tpm2::crypto::Update for BsslSha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<20> for BsslSha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct BsslSha256(bssl_crypto::digest::Sha256);

impl tpm2::crypto::Update for BsslSha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<32> for BsslSha256 {
    fn finalize(self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct BsslSha384(bssl_crypto::digest::Sha384);

impl tpm2::crypto::Update for BsslSha384 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<48> for BsslSha384 {
    fn finalize(self, out: &mut [u8; 48]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct BsslSha512(bssl_crypto::digest::Sha512);

impl tpm2::crypto::Update for BsslSha512 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<64> for BsslSha512 {
    fn finalize(self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

impl tpm2::crypto::Hash for BsslCryptoProvider {
    type Sha1Context = BsslSha1;
    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        Ok(BsslSha1(bssl_crypto::digest::InsecureSha1::new()))
    }

    type Sha256Context = BsslSha256;
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        Ok(BsslSha256(bssl_crypto::digest::Sha256::new()))
    }

    type Sha384Context = BsslSha384;
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        Ok(BsslSha384(bssl_crypto::digest::Sha384::new()))
    }

    type Sha512Context = BsslSha512;
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        Ok(BsslSha512(bssl_crypto::digest::Sha512::new()))
    }

    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}

pub struct BsslHmacSha1(crate::bssl::HmacSha1);

impl tpm2::crypto::Update for BsslHmacSha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data).map_err(Into::into)
    }
}

impl tpm2::crypto::Finalize<20> for BsslHmacSha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        self.0.finalize(out).map_err(Into::into)
    }
}

pub struct BsslHmacSha256(bssl_crypto::hmac::HmacSha256);

impl tpm2::crypto::Update for BsslHmacSha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<32> for BsslHmacSha256 {
    fn finalize(self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct BsslHmacSha384(bssl_crypto::hmac::HmacSha384);

impl tpm2::crypto::Update for BsslHmacSha384 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<48> for BsslHmacSha384 {
    fn finalize(self, out: &mut [u8; 48]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct BsslHmacSha512(bssl_crypto::hmac::HmacSha512);

impl tpm2::crypto::Update for BsslHmacSha512 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<64> for BsslHmacSha512 {
    fn finalize(self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        let res = self.0.digest();
        out.copy_from_slice(&res);
        Ok(())
    }
}

impl tpm2::crypto::Hmac for BsslCryptoProvider {
    type Sha1Context = BsslHmacSha1;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        crate::bssl::HmacSha1::new_from_slice(key)
            .map(BsslHmacSha1)
            .map_err(Into::into)
    }

    type Sha256Context = BsslHmacSha256;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        Ok(BsslHmacSha256(
            bssl_crypto::hmac::HmacSha256::new_from_slice(key),
        ))
    }

    type Sha384Context = BsslHmacSha384;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        Ok(BsslHmacSha384(
            bssl_crypto::hmac::HmacSha384::new_from_slice(key),
        ))
    }

    type Sha512Context = BsslHmacSha512;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        Ok(BsslHmacSha512(
            bssl_crypto::hmac::HmacSha512::new_from_slice(key),
        ))
    }

    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}
