//! [`Rsa`] implementation using BoringSSL (`RSA` and `BIGNUM`).

use core::fmt;

use tpm2::crypto::{CryptoError, Rsa, RsaEncryptScheme};
use tpm2::{Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmiRsaKeyBits};

use crate::{BoringSsl, ChaChaRng, bssl};

/// The public exponent used when the TPM specifies an exponent of `0`.
const DEFAULT_EXPONENT: u32 = 65537;

/// RSA public key handle for [`Rsa::PublicKey`].
pub struct RsaPublicKey {
    bits: TpmiRsaKeyBits,
    exponent: u32,
    pub(crate) key: bssl::RsaKey,
}

/// RSA private key handle for [`Rsa::PrivateKey`].
pub struct RsaPrivateKey {
    public: RsaPublicKey,
    pub(crate) key: bssl::RsaKey,
}

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKey")
            .field("bits", &self.bits)
            .field("exponent", &self.exponent)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl RsaPublicKey {
    /// Returns the modulus size in bytes.
    pub(crate) fn len(&self) -> usize {
        usize::from(self.bits.as_u16()) / 8
    }
}

impl tpm2::crypto::RsaPublicKey for RsaPublicKey {
    fn bits(&self) -> TpmiRsaKeyBits {
        self.bits
    }

    fn exponent(&self) -> u32 {
        self.exponent
    }

    fn modulus<'a>(
        &self,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        let modulus = self.key.modulus(self.len(), out)?;
        Tpm2bPublicKeyRsa::new(modulus).ok_or(CryptoError::Internal)
    }
}

impl tpm2::crypto::RsaPrivateKey for RsaPrivateKey {
    type PublicKey = RsaPublicKey;

    fn public_key(&self) -> &RsaPublicKey {
        &self.public
    }

    fn prime_p<'a>(
        &self,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES],
    ) -> Result<Tpm2bPrivateKeyRsa<'a>, CryptoError> {
        let p = self.key.prime_p(self.public.len() / 2, out)?;
        Tpm2bPrivateKeyRsa::new(p).ok_or(CryptoError::Internal)
    }
}

impl Rsa for BoringSsl {
    type PublicKey = RsaPublicKey;
    type PrivateKey = RsaPrivateKey;

    fn load_public(
        &self,
        bits: TpmiRsaKeyBits,
        exponent: u32,
        modulus: Tpm2bPublicKeyRsa<'_>,
    ) -> Result<Option<RsaPublicKey>, CryptoError> {
        let exponent = if exponent == 0 {
            DEFAULT_EXPONENT
        } else {
            exponent
        };
        let Some(key) = bssl::RsaKey::load_public(bits.as_u16(), exponent, modulus.as_slice())?
        else {
            return Ok(None);
        };
        Ok(Some(RsaPublicKey {
            bits,
            exponent,
            key,
        }))
    }

    fn load_private(
        &self,
        public: RsaPublicKey,
        prime_p: Tpm2bPrivateKeyRsa<'_>,
    ) -> Result<Option<RsaPrivateKey>, CryptoError> {
        let Some(key) =
            bssl::RsaKey::load_private(&public.key, public.exponent, prime_p.as_slice())?
        else {
            return Ok(None);
        };
        Ok(Some(RsaPrivateKey { public, key }))
    }

    fn generate_key(
        &self,
        rng: &mut ChaChaRng,
        bits: TpmiRsaKeyBits,
        exponent: u32,
    ) -> Result<RsaPrivateKey, CryptoError> {
        let exponent = if exponent == 0 {
            DEFAULT_EXPONENT
        } else {
            exponent
        };
        if exponent < 3 || exponent.is_multiple_of(2) {
            return Err(CryptoError::Unsupported);
        }
        let (pub_key, priv_key) = bssl::RsaKey::generate(&mut rng.0, bits.as_u16(), exponent)?;
        Ok(RsaPrivateKey {
            public: RsaPublicKey {
                bits,
                exponent,
                key: pub_key,
            },
            key: priv_key,
        })
    }

    fn encrypt<'a>(
        &self,
        _rng: &mut ChaChaRng,
        key: &RsaPublicKey,
        scheme: RsaEncryptScheme<'_>,
        plaintext: &[u8],
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Option<Tpm2bPublicKeyRsa<'a>>, CryptoError> {
        let out_len = match scheme {
            RsaEncryptScheme::Raw => key.key.encrypt_raw(plaintext, out)?,
            RsaEncryptScheme::Rsaes => key.key.encrypt_pkcs1v15(plaintext, out)?,
            RsaEncryptScheme::Oaep { hash, label } => {
                key.key.encrypt_oaep(hash, label, plaintext, out)?
            }
        };
        let Some(len) = out_len else {
            return Ok(None);
        };
        Ok(Some(
            Tpm2bPublicKeyRsa::new(&out[..len]).ok_or(CryptoError::Internal)?,
        ))
    }

    fn decrypt<'a>(
        &self,
        key: &RsaPrivateKey,
        scheme: RsaEncryptScheme<'_>,
        ciphertext: &[u8],
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Option<Tpm2bPublicKeyRsa<'a>>, CryptoError> {
        let out_len = match scheme {
            RsaEncryptScheme::Raw => key.key.decrypt_raw(ciphertext, out)?,
            RsaEncryptScheme::Rsaes => key.key.decrypt_pkcs1v15(ciphertext, out)?,
            RsaEncryptScheme::Oaep { hash, label } => {
                key.key.decrypt_oaep(hash, label, ciphertext, out)?
            }
        };
        let Some(len) = out_len else {
            return Ok(None);
        };
        Ok(Some(
            Tpm2bPublicKeyRsa::new(&out[..len]).ok_or(CryptoError::Internal)?,
        ))
    }
}
