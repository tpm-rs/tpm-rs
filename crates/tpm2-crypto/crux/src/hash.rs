use crate::CruxCryptoProvider;
use libcrux_sha2::Digest as _;
use tpm2::crypto::CryptoError;

/// SHA-1 hash context for `CruxCryptoProvider` (RustCrypto `sha1`).
pub struct CruxSha1(sha1::Sha1);

impl tpm2::crypto::Update for CruxSha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use sha1::Digest as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<20> for CruxSha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        use sha1::Digest as _;
        let res = self.0.finalize();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// SHA-256 hash context for `CruxCryptoProvider` (`libcrux-sha2`).
pub struct CruxSha256(libcrux_sha2::Sha256);

impl tpm2::crypto::Update for CruxSha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<32> for CruxSha256 {
    fn finalize(self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        self.0.finish(out);
        Ok(())
    }
}

/// SHA-384 hash context for `CruxCryptoProvider` (`libcrux-sha2`).
pub struct CruxSha384(libcrux_sha2::Sha384);

impl tpm2::crypto::Update for CruxSha384 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<48> for CruxSha384 {
    fn finalize(self, out: &mut [u8; 48]) -> Result<(), CryptoError> {
        self.0.finish(out);
        Ok(())
    }
}

/// SHA-512 hash context for `CruxCryptoProvider` (`libcrux-sha2`).
pub struct CruxSha512(libcrux_sha2::Sha512);

impl tpm2::crypto::Update for CruxSha512 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<64> for CruxSha512 {
    fn finalize(self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        self.0.finish(out);
        Ok(())
    }
}

impl tpm2::crypto::Hash for CruxCryptoProvider {
    type Sha1Context = CruxSha1;
    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        use sha1::Digest as _;
        Ok(CruxSha1(sha1::Sha1::new()))
    }

    type Sha256Context = CruxSha256;
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        Ok(CruxSha256(libcrux_sha2::Sha256::new()))
    }

    type Sha384Context = CruxSha384;
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        Ok(CruxSha384(libcrux_sha2::Sha384::new()))
    }

    type Sha512Context = CruxSha512;
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        Ok(CruxSha512(libcrux_sha2::Sha512::new()))
    }

    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}

/// HMAC-SHA-1 context for `CruxCryptoProvider` (RustCrypto `hmac`).
pub struct CruxHmacSha1(hmac::Hmac<sha1::Sha1>);

impl tpm2::crypto::Update for CruxHmacSha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<20> for CruxHmacSha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// HMAC-SHA-256 context for `CruxCryptoProvider` (RustCrypto `hmac`).
pub struct CruxHmacSha256(hmac::Hmac<sha2::Sha256>);

impl tpm2::crypto::Update for CruxHmacSha256 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<32> for CruxHmacSha256 {
    fn finalize(self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// HMAC-SHA-384 context for `CruxCryptoProvider` (RustCrypto `hmac`).
pub struct CruxHmacSha384(hmac::Hmac<sha2::Sha384>);

impl tpm2::crypto::Update for CruxHmacSha384 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<48> for CruxHmacSha384 {
    fn finalize(self, out: &mut [u8; 48]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// HMAC-SHA-512 context for `CruxCryptoProvider` (RustCrypto `hmac`).
pub struct CruxHmacSha512(hmac::Hmac<sha2::Sha512>);

impl tpm2::crypto::Update for CruxHmacSha512 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        self.0.update(data);
        Ok(())
    }
}

impl tpm2::crypto::Finalize<64> for CruxHmacSha512 {
    fn finalize(self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        use hmac::Mac as _;
        let res = self.0.finalize().into_bytes();
        out.copy_from_slice(&res);
        Ok(())
    }
}

/// HMAC accepts keys of any length, so the constructors only fail
/// ([`CryptoError::Internal`]) if the `hmac` crate rejects the key, which it
/// never does.
impl tpm2::crypto::Hmac for CruxCryptoProvider {
    type Sha1Context = CruxHmacSha1;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha1::Sha1>::new_from_slice(key)
            .map(CruxHmacSha1)
            .map_err(|_| CryptoError::Internal)
    }

    type Sha256Context = CruxHmacSha256;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
            .map(CruxHmacSha256)
            .map_err(|_| CryptoError::Internal)
    }

    type Sha384Context = CruxHmacSha384;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha2::Sha384>::new_from_slice(key)
            .map(CruxHmacSha384)
            .map_err(|_| CryptoError::Internal)
    }

    type Sha512Context = CruxHmacSha512;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        use hmac::Mac as _;
        hmac::Hmac::<sha2::Sha512>::new_from_slice(key)
            .map(CruxHmacSha512)
            .map_err(|_| CryptoError::Internal)
    }

    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}
