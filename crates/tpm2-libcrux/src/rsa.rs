//! [`Rsa`] implementation using the RustCrypto `rsa` crate.
//!
//! libcrux-rsa only supports RSA-PSS signatures with `e = 65537` over
//! messages it hashes itself, so it can't implement the TPM's digest-based
//! signatures or RSA encryption.

use ::rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use ::rsa::{BigUint, Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use tpm2::crypto::{CryptoError, Random as _, Rsa, RsaEncryptScheme};
use tpm2::{Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmiAlgHash, TpmiRsaKeyBits};

use crate::{ChaChaRng, Libcrux, write, write_be};

/// The public exponent used when the TPM specifies an exponent of `0`.
const DEFAULT_EXPONENT: u32 = 65537;

/// RSA public key handle for [`Rsa::PublicKey`].
pub struct RsaPublic {
    bits: TpmiRsaKeyBits,
    exponent: u32,
    pub(crate) key: RsaPublicKey,
}

/// RSA private key handle for [`Rsa::PrivateKey`].
pub struct RsaPrivate {
    public: RsaPublic,
    pub(crate) key: RsaPrivateKey,
}

impl RsaPublic {
    /// The modulus size in bytes.
    pub(crate) fn len(&self) -> usize {
        key_bytes(self.bits)
    }
}

impl tpm2::crypto::RsaPublicKey for RsaPublic {
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
        let modulus = write_be(&self.key.n().to_bytes_be(), self.len(), out)?;
        Tpm2bPublicKeyRsa::new(modulus).ok_or(CryptoError::Internal)
    }
}

impl tpm2::crypto::RsaPrivateKey for RsaPrivate {
    type PublicKey = RsaPublic;

    fn public_key(&self) -> &RsaPublic {
        &self.public
    }

    fn prime_p<'a>(
        &self,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES],
    ) -> Result<Tpm2bPrivateKeyRsa<'a>, CryptoError> {
        let p = self.key.primes().first().ok_or(CryptoError::Internal)?;
        let p = p.to_bytes_be();
        // Pad `p` to half the modulus size; a prime can be one byte longer.
        let len = p.len().max(self.public.len() / 2);
        Tpm2bPrivateKeyRsa::new(write_be(&p, len, out)?).ok_or(CryptoError::Internal)
    }
}

/// Returns the modulus size in bytes for `bits`.
fn key_bytes(bits: TpmiRsaKeyBits) -> usize {
    usize::from(bits.as_u16()) / 8
}

/// Creates the OAEP padding scheme for `hash` and `label`.
fn oaep(hash: TpmiAlgHash, label: &[u8]) -> Result<Oaep, CryptoError> {
    // The `rsa` crate only supports UTF-8 labels. TPM labels such as
    // "DUPLICATE\0" are ASCII (including the trailing NUL).
    let label = core::str::from_utf8(label).map_err(|_| CryptoError::Unsupported)?;
    Ok(match hash {
        TpmiAlgHash::Sha1 => Oaep::new_with_label::<sha1::Sha1, _>(label),
        TpmiAlgHash::Sha256 => Oaep::new_with_label::<sha2::Sha256, _>(label),
        TpmiAlgHash::Sha384 => Oaep::new_with_label::<sha2::Sha384, _>(label),
        TpmiAlgHash::Sha512 => Oaep::new_with_label::<sha2::Sha512, _>(label),
        _ => return Err(CryptoError::Unsupported),
    })
}

impl Rsa for Libcrux {
    type PublicKey = RsaPublic;
    type PrivateKey = RsaPrivate;

    fn load_public(
        &self,
        bits: TpmiRsaKeyBits,
        exponent: u32,
        modulus: Tpm2bPublicKeyRsa<'_>,
    ) -> Result<Option<RsaPublic>, CryptoError> {
        let exponent = if exponent == 0 {
            DEFAULT_EXPONENT
        } else {
            exponent
        };
        let modulus = modulus.as_slice();
        if modulus.len() != key_bytes(bits) {
            return Ok(None);
        }
        let n = BigUint::from_bytes_be(modulus);
        if n.bits() != usize::from(bits.as_u16()) {
            return Ok(None);
        }
        // Checks that `n` and `e` are odd and that `1 < e < n`.
        let Ok(key) = RsaPublicKey::new(n, BigUint::from(exponent)) else {
            return Ok(None);
        };
        Ok(Some(RsaPublic {
            bits,
            exponent,
            key,
        }))
    }

    fn load_private(
        &self,
        public: RsaPublic,
        prime_p: Tpm2bPrivateKeyRsa<'_>,
    ) -> Result<Option<RsaPrivate>, CryptoError> {
        let n = public.key.n();
        let p = BigUint::from_bytes_be(prime_p.as_slice());
        let one = BigUint::from(1u32);
        if p <= one {
            return Ok(None);
        }
        let q = n / &p;
        if q <= one || &(&p * &q) != n {
            return Ok(None);
        }
        // Like the TPM reference implementation, require balanced primes.
        if p.bits().abs_diff(q.bits()) > 1 {
            return Ok(None);
        }
        // Checks that `p` and `q` are distinct and that `e` is invertible.
        let Ok(key) = RsaPrivateKey::from_p_q(p, q, public.key.e().clone()) else {
            return Ok(None);
        };
        // Pairwise consistency check, as `from_p_q` doesn't check that `p` and `q` are prime:
        // with a composite `p`, every private-key operation would fail later.
        let m = BigUint::from(2u8);
        let c = ::rsa::hazmat::rsa_encrypt(&key, &m).map_err(|_| CryptoError::Internal)?;
        let mut rng = self.rng()?;
        if ::rsa::hazmat::rsa_decrypt_and_check(&key, Some(&mut rng.0), &c).ok() != Some(m) {
            return Ok(None);
        }
        Ok(Some(RsaPrivate { public, key }))
    }

    fn generate_key(
        &self,
        rng: &mut ChaChaRng,
        bits: TpmiRsaKeyBits,
        exponent: u32,
    ) -> Result<RsaPrivate, CryptoError> {
        let exponent = if exponent == 0 {
            DEFAULT_EXPONENT
        } else {
            exponent
        };
        // The `rsa` crate requires an odd exponent greater than 1.
        if exponent < 3 || exponent.is_multiple_of(2) {
            return Err(CryptoError::Unsupported);
        }
        let key = RsaPrivateKey::new_with_exp(
            &mut rng.0,
            usize::from(bits.as_u16()),
            &BigUint::from(exponent),
        )
        .map_err(|_| CryptoError::Internal)?;
        let public = RsaPublic {
            bits,
            exponent,
            key: key.to_public_key(),
        };
        Ok(RsaPrivate { public, key })
    }

    fn encrypt<'a>(
        &self,
        rng: &mut ChaChaRng,
        key: &RsaPublic,
        scheme: RsaEncryptScheme<'_>,
        plaintext: &[u8],
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Option<Tpm2bPublicKeyRsa<'a>>, CryptoError> {
        let result = match scheme {
            RsaEncryptScheme::Raw => {
                let m = BigUint::from_bytes_be(plaintext);
                if plaintext.len() > key.len() || &m >= key.key.n() {
                    return Ok(None);
                }
                ::rsa::hazmat::rsa_encrypt(&key.key, &m).map(|c| c.to_bytes_be())
            }
            RsaEncryptScheme::Rsaes => key.key.encrypt(&mut rng.0, Pkcs1v15Encrypt, plaintext),
            RsaEncryptScheme::Oaep { hash, label } => {
                key.key.encrypt(&mut rng.0, oaep(hash, label)?, plaintext)
            }
        };
        let ciphertext = match result {
            Ok(ciphertext) => ciphertext,
            Err(::rsa::Error::MessageTooLong) => return Ok(None),
            Err(_) => return Err(CryptoError::Internal),
        };
        let ciphertext = write_be(&ciphertext, key.len(), out)?;
        Ok(Some(
            Tpm2bPublicKeyRsa::new(ciphertext).ok_or(CryptoError::Internal)?,
        ))
    }

    fn decrypt<'a>(
        &self,
        key: &RsaPrivate,
        scheme: RsaEncryptScheme<'_>,
        ciphertext: &[u8],
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Option<Tpm2bPublicKeyRsa<'a>>, CryptoError> {
        let len = key.public.len();
        if ciphertext.len() != len {
            return Ok(None);
        }
        // Blind the private key operation with a fresh RNG.
        let mut rng = self.rng()?;
        let rng = &mut rng.0;
        let result = match scheme {
            RsaEncryptScheme::Raw => {
                let c = BigUint::from_bytes_be(ciphertext);
                if &c >= key.key.n() {
                    return Ok(None);
                }
                ::rsa::hazmat::rsa_decrypt_and_check(&key.key, Some(rng), &c)
                    .map(|m| m.to_bytes_be())
            }
            RsaEncryptScheme::Rsaes => key.key.decrypt_blinded(rng, Pkcs1v15Encrypt, ciphertext),
            RsaEncryptScheme::Oaep { hash, label } => {
                key.key.decrypt_blinded(rng, oaep(hash, label)?, ciphertext)
            }
        };
        let plaintext = match result {
            Ok(plaintext) => plaintext,
            Err(::rsa::Error::Decryption) => return Ok(None),
            Err(_) => return Err(CryptoError::Internal),
        };
        let plaintext = match scheme {
            // Raw decryption returns the whole modulus-sized block.
            RsaEncryptScheme::Raw => write_be(&plaintext, len, out)?,
            _ => write(&plaintext, out)?,
        };
        Ok(Some(
            Tpm2bPublicKeyRsa::new(plaintext).ok_or(CryptoError::Internal)?,
        ))
    }
}
