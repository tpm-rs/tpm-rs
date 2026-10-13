use crate::RustCryptoProvider;
use tpm2::crypto::CryptoError;

/// SHA-1 context wrapper for `RustCryptoProvider`.
pub struct RustCryptoSha1(sha1::Sha1);

impl tpm2::crypto::Update for RustCryptoSha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use sha1::Digest as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<20> for RustCryptoSha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        use sha1::Digest as _;
        let res = self.0.finalize();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// SHA-256 context wrapper for `RustCryptoProvider`.
pub struct RustCryptoSha256(sha2::Sha256);

impl tpm2::crypto::Update for RustCryptoSha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use sha2::Digest as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<32> for RustCryptoSha256 {
    fn finalize(self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        use sha2::Digest as _;
        let res = self.0.finalize();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// SHA-384 context wrapper for `RustCryptoProvider`.
pub struct RustCryptoSha384(sha2::Sha384);

impl tpm2::crypto::Update for RustCryptoSha384 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use sha2::Digest as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<48> for RustCryptoSha384 {
    fn finalize(self, out: &mut [u8; 48]) -> Result<(), CryptoError> {
        use sha2::Digest as _;
        let res = self.0.finalize();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// SHA-512 context wrapper for `RustCryptoProvider`.
pub struct RustCryptoSha512(sha2::Sha512);

impl tpm2::crypto::Update for RustCryptoSha512 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use sha2::Digest as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<64> for RustCryptoSha512 {
    fn finalize(self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        use sha2::Digest as _;
        let res = self.0.finalize();
        out.copy_from_slice(&res);
        Ok(())
    }
}

impl tpm2::crypto::Hash for RustCryptoProvider {
    type Sha1Context = RustCryptoSha1;
    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        use sha1::Digest as _;
        Ok(RustCryptoSha1(sha1::Sha1::new()))
    }

    type Sha256Context = RustCryptoSha256;
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        use sha2::Digest as _;
        Ok(RustCryptoSha256(sha2::Sha256::new()))
    }

    type Sha384Context = RustCryptoSha384;
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        use sha2::Digest as _;
        Ok(RustCryptoSha384(sha2::Sha384::new()))
    }

    type Sha512Context = RustCryptoSha512;
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        use sha2::Digest as _;
        Ok(RustCryptoSha512(sha2::Sha512::new()))
    }

    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}

/// HMAC-SHA-1 context wrapper for `RustCryptoProvider`.
pub struct RustCryptoHmacSha1(hmac::Hmac<sha1::Sha1>);

impl tpm2::crypto::Update for RustCryptoHmacSha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<20> for RustCryptoHmacSha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// HMAC-SHA-256 context wrapper for `RustCryptoProvider`.
pub struct RustCryptoHmacSha256(hmac::Hmac<sha2::Sha256>);

impl tpm2::crypto::Update for RustCryptoHmacSha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<32> for RustCryptoHmacSha256 {
    fn finalize(self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// HMAC-SHA-384 context wrapper for `RustCryptoProvider`.
pub struct RustCryptoHmacSha384(hmac::Hmac<sha2::Sha384>);

impl tpm2::crypto::Update for RustCryptoHmacSha384 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<48> for RustCryptoHmacSha384 {
    fn finalize(self, out: &mut [u8; 48]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// HMAC-SHA-512 context wrapper for `RustCryptoProvider`.
pub struct RustCryptoHmacSha512(hmac::Hmac<sha2::Sha512>);

impl tpm2::crypto::Update for RustCryptoHmacSha512 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<64> for RustCryptoHmacSha512 {
    fn finalize(self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

// HMAC accepts keys of any length, so `new_from_slice` cannot fail; if it did, that would be an
// internal error (`CryptoError::Internal`).
impl tpm2::crypto::Hmac for RustCryptoProvider {
    type Sha1Context = RustCryptoHmacSha1;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha1::Sha1>::new_from_slice(key)
            .map(RustCryptoHmacSha1)
            .map_err(|_| CryptoError::Internal)
    }

    type Sha256Context = RustCryptoHmacSha256;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
            .map(RustCryptoHmacSha256)
            .map_err(|_| CryptoError::Internal)
    }

    type Sha384Context = RustCryptoHmacSha384;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha2::Sha384>::new_from_slice(key)
            .map(RustCryptoHmacSha384)
            .map_err(|_| CryptoError::Internal)
    }

    type Sha512Context = RustCryptoHmacSha512;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha2::Sha512>::new_from_slice(key)
            .map(RustCryptoHmacSha512)
            .map_err(|_| CryptoError::Internal)
    }

    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}
