use crate::CruxCryptoProvider;
use libcrux_sha2::Digest as _;
use tpm2::crypto::CryptoError;

pub struct CruxSha1(sha1::Sha1);

impl tpm2::crypto::Update<CryptoError> for CruxSha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use sha1::Digest as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<20, CryptoError> for CruxSha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        use sha1::Digest as _;
        let res = self.0.finalize();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct CruxSha256(libcrux_sha2::Sha256);

impl tpm2::crypto::Update<CryptoError> for CruxSha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<32, CryptoError> for CruxSha256 {
    fn finalize(self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        self.0.finish(out);
        Ok(())
    }
}

pub struct CruxSha384(libcrux_sha2::Sha384);

impl tpm2::crypto::Update<CryptoError> for CruxSha384 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<48, CryptoError> for CruxSha384 {
    fn finalize(self, out: &mut [u8; 48]) -> Result<(), CryptoError> {
        self.0.finish(out);
        Ok(())
    }
}

pub struct CruxSha512(libcrux_sha2::Sha512);

impl tpm2::crypto::Update<CryptoError> for CruxSha512 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<64, CryptoError> for CruxSha512 {
    fn finalize(self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        self.0.finish(out);
        Ok(())
    }
}

impl tpm2::crypto::Hash for CruxCryptoProvider {
    type Sha1Ctx = CruxSha1;
    fn sha1(&self) -> Result<Self::Sha1Ctx, CryptoError> {
        use sha1::Digest as _;
        Ok(CruxSha1(sha1::Sha1::new()))
    }

    type Sha256Ctx = CruxSha256;
    fn sha256(&self) -> Result<Self::Sha256Ctx, CryptoError> {
        Ok(CruxSha256(libcrux_sha2::Sha256::new()))
    }

    type Sha384Ctx = CruxSha384;
    fn sha384(&self) -> Result<Self::Sha384Ctx, CryptoError> {
        Ok(CruxSha384(libcrux_sha2::Sha384::new()))
    }

    type Sha512Ctx = CruxSha512;
    fn sha512(&self) -> Result<Self::Sha512Ctx, CryptoError> {
        Ok(CruxSha512(libcrux_sha2::Sha512::new()))
    }

    type Sm3_256Ctx = !;
    type Sha3_256Ctx = !;
    type Sha3_384Ctx = !;
    type Sha3_512Ctx = !;
}

pub struct CruxHmacSha1(hmac::Hmac<sha1::Sha1>);

impl tpm2::crypto::Update<CryptoError> for CruxHmacSha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<20, CryptoError> for CruxHmacSha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct CruxHmacSha256(hmac::Hmac<sha2::Sha256>);

impl tpm2::crypto::Update<CryptoError> for CruxHmacSha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<32, CryptoError> for CruxHmacSha256 {
    fn finalize(self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct CruxHmacSha384(hmac::Hmac<sha2::Sha384>);

impl tpm2::crypto::Update<CryptoError> for CruxHmacSha384 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<48, CryptoError> for CruxHmacSha384 {
    fn finalize(self, out: &mut [u8; 48]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

pub struct CruxHmacSha512(hmac::Hmac<sha2::Sha512>);

impl tpm2::crypto::Update<CryptoError> for CruxHmacSha512 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<64, CryptoError> for CruxHmacSha512 {
    fn finalize(self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

impl tpm2::crypto::Hmac for CruxCryptoProvider {
    type Sha1Ctx = CruxHmacSha1;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Ctx, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha1::Sha1>::new_from_slice(key)
            .map(CruxHmacSha1)
            .map_err(|_| CryptoError::KeyTooSmall)
    }

    type Sha256Ctx = CruxHmacSha256;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Ctx, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
            .map(CruxHmacSha256)
            .map_err(|_| CryptoError::KeyTooSmall)
    }

    type Sha384Ctx = CruxHmacSha384;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Ctx, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha2::Sha384>::new_from_slice(key)
            .map(CruxHmacSha384)
            .map_err(|_| CryptoError::KeyTooSmall)
    }

    type Sha512Ctx = CruxHmacSha512;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Ctx, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha2::Sha512>::new_from_slice(key)
            .map(CruxHmacSha512)
            .map_err(|_| CryptoError::KeyTooSmall)
    }

    type Sm3_256Ctx = !;
    type Sha3_256Ctx = !;
    type Sha3_384Ctx = !;
    type Sha3_512Ctx = !;
}
