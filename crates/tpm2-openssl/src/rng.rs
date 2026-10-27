use tpm2::crypto::{CryptoError, Random, Rng};

use crate::OpensslBackend;

// A simple deterministic RNG using OpenSSL AES-CTR.
use openssl::hash::{Hasher, MessageDigest};
use openssl::symm::{Cipher, Crypter, Mode};

pub struct OpensslRng {
    key: [u8; 32],
    iv: [u8; 16],
}

impl Random for OpensslBackend {
    type Rng = OpensslRng;

    fn from_entropy() -> Result<OpensslRng, CryptoError> {
        let mut rng = OpensslRng {
            key: [0u8; 32],
            iv: [0u8; 16],
        };
        openssl::rand::rand_bytes(&mut rng.key).map_err(|_| CryptoError::Internal)?;
        openssl::rand::rand_bytes(&mut rng.iv).map_err(|_| CryptoError::Internal)?;
        Ok(rng)
    }

    fn from_seed(seed: &[u8]) -> Result<OpensslRng, CryptoError> {
        let mut hasher = Hasher::new(MessageDigest::sha384()).map_err(|_| CryptoError::Internal)?;
        hasher.update(seed).map_err(|_| CryptoError::Internal)?;
        let digest = hasher.finish().map_err(|_| CryptoError::Internal)?;
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        key.copy_from_slice(&digest[0..32]);
        iv.copy_from_slice(&digest[32..48]);
        Ok(OpensslRng { key, iv })
    }

    fn rand_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
        openssl::rand::rand_bytes(out).map_err(|_| CryptoError::Internal)
    }
}

impl Rng for OpensslRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let mut c = Crypter::new(
            Cipher::aes_256_ctr(),
            Mode::Encrypt,
            &self.key,
            Some(&self.iv),
        )
        .map_err(|_| CryptoError::Internal)?;
        c.pad(false);
        let zeroes = vec![0u8; out.len()];
        let mut buf = vec![0u8; out.len() + 16];
        let count = c
            .update(&zeroes, &mut buf)
            .map_err(|_| CryptoError::Internal)?;
        let rest = c
            .finalize(&mut buf[count..])
            .map_err(|_| CryptoError::Internal)?;
        out.copy_from_slice(&buf[..count + rest]);
        // Update IV (just hash the current IV to get next IV)
        let mut hasher = Hasher::new(MessageDigest::sha256()).map_err(|_| CryptoError::Internal)?;
        hasher.update(&self.iv).map_err(|_| CryptoError::Internal)?;
        let digest = hasher.finish().map_err(|_| CryptoError::Internal)?;
        self.iv.copy_from_slice(&digest[0..16]);
        Ok(())
    }

    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let mut hasher = Hasher::new(MessageDigest::sha384()).map_err(|_| CryptoError::Internal)?;
        hasher
            .update(&self.key)
            .map_err(|_| CryptoError::Internal)?;
        hasher.update(&self.iv).map_err(|_| CryptoError::Internal)?;
        hasher.update(data).map_err(|_| CryptoError::Internal)?;
        let digest = hasher.finish().map_err(|_| CryptoError::Internal)?;
        self.key.copy_from_slice(&digest[0..32]);
        self.iv.copy_from_slice(&digest[32..48]);
        Ok(())
    }
}
