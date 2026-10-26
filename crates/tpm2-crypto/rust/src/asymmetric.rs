use crate::{BNP256, NistP224, RngWrapper, RustCryptoProvider};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use tpm2::crypto::{Asymmetric, AsymmetricSign, CryptoError, TpmiRsaKeyBits};
use tpm2::{TpmEccCurve, TpmiAlgHash, TpmtHa};

/// Returns the RSA public exponent `exponent` (`TPMS_RSA_PARMS.exponent`) as a big integer,
/// where `0` selects the default exponent $2^{16}+1$ (65537).
fn rsa_public_exponent(exponent: u32) -> rsa::BigUint {
    rsa::BigUint::from(if exponent == 0 { 65537 } else { exponent })
}

fn prepare_prehash(d: &[u8], target_len: usize, buf: &mut [u8]) -> usize {
    if d.len() >= target_len {
        buf[..target_len].copy_from_slice(&d[..target_len]);
    } else {
        let offset = target_len - d.len();
        buf[..offset].fill(0);
        buf[offset..target_len].copy_from_slice(d);
    }
    target_len
}

/// Signing follows the [`AsymmetricSign`] conventions: `Ok(None)` if `private_key` is invalid or
/// cannot sign the digest (for example, an RSA key too small for the digest and its padding),
/// `Err(CryptoError::Unsupported)` for an unsupported digest algorithm, and
/// `Err(CryptoError::Internal)` if `signature_out` is too small.
impl AsymmetricSign for RustCryptoProvider {
    fn rsassa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let Ok(priv_key) = rsa::RsaPrivateKey::from_pkcs8_der(private_key) else {
            return Ok(None);
        };

        let sig = match digest {
            TpmtHa::Sha1(d) => priv_key.sign(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha1::Sha1>(), d),
            TpmtHa::Sha256(d) => {
                priv_key.sign(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(), d)
            }
            TpmtHa::Sha384(d) => {
                priv_key.sign(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha384>(), d)
            }
            TpmtHa::Sha512(d) => {
                priv_key.sign(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha512>(), d)
            }
            _ => return Err(CryptoError::Unsupported),
        };
        let Ok(sig) = sig else {
            return Ok(None);
        };

        if signature_out.len() < sig.len() {
            return Err(CryptoError::Internal);
        }
        signature_out[..sig.len()].copy_from_slice(&sig);
        Ok(Some(sig.len()))
    }

    fn rsapss_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let Ok(priv_key) = rsa::RsaPrivateKey::from_pkcs8_der(private_key) else {
            return Ok(None);
        };

        let sig = match digest {
            TpmtHa::Sha1(d) => {
                priv_key.sign_with_rng(&mut rand_core::OsRng, rsa::pss::Pss::new::<sha1::Sha1>(), d)
            }
            TpmtHa::Sha256(d) => priv_key.sign_with_rng(
                &mut rand_core::OsRng,
                rsa::pss::Pss::new::<sha2::Sha256>(),
                d,
            ),
            TpmtHa::Sha384(d) => priv_key.sign_with_rng(
                &mut rand_core::OsRng,
                rsa::pss::Pss::new::<sha2::Sha384>(),
                d,
            ),
            TpmtHa::Sha512(d) => priv_key.sign_with_rng(
                &mut rand_core::OsRng,
                rsa::pss::Pss::new::<sha2::Sha512>(),
                d,
            ),
            _ => return Err(CryptoError::Unsupported),
        };
        let Ok(sig) = sig else {
            return Ok(None);
        };

        if signature_out.len() < sig.len() {
            return Err(CryptoError::Internal);
        }
        signature_out[..sig.len()].copy_from_slice(&sig);
        Ok(Some(sig.len()))
    }

    fn ecdsa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        if private_key.len() <= 32 && !private_key.is_empty() {
            let mut padded = [0u8; 32];
            padded[32 - private_key.len()..].copy_from_slice(private_key);
            let Ok(secret_key) = p256::SecretKey::from_slice(&padded) else {
                return Ok(None);
            };
            let signing_key = p256::ecdsa::SigningKey::from(secret_key);
            use p256::ecdsa::signature::hazmat::PrehashSigner as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 32, &mut d_buf);
            let sig: Result<p256::ecdsa::Signature, _> = signing_key.sign_prehash(&d_buf[..d_len]);
            let Ok(sig) = sig else {
                return Ok(None);
            };
            let sig_bytes = sig.to_bytes();
            if signature_out.len() < sig_bytes.len() {
                return Err(CryptoError::Internal);
            }
            signature_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
            Ok(Some(sig_bytes.len()))
        } else if private_key.len() <= 48 && private_key.len() > 32 {
            let mut padded = [0u8; 48];
            padded[48 - private_key.len()..].copy_from_slice(private_key);
            let Ok(secret_key) = p384::SecretKey::from_slice(&padded) else {
                return Ok(None);
            };
            let signing_key = p384::ecdsa::SigningKey::from(secret_key);
            use p384::ecdsa::signature::hazmat::PrehashSigner as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 48, &mut d_buf);
            let sig: Result<p384::ecdsa::Signature, _> = signing_key.sign_prehash(&d_buf[..d_len]);
            let Ok(sig) = sig else {
                return Ok(None);
            };
            let sig_bytes = sig.to_bytes();
            if signature_out.len() < sig_bytes.len() {
                return Err(CryptoError::Internal);
            }
            signature_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
            Ok(Some(sig_bytes.len()))
        } else if private_key.len() <= 66 && private_key.len() > 48 {
            let mut padded = [0u8; 66];
            padded[66 - private_key.len()..].copy_from_slice(private_key);
            let Ok(signing_key) = p521::ecdsa::SigningKey::from_slice(&padded) else {
                return Ok(None);
            };
            use p521::ecdsa::signature::hazmat::PrehashSigner as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 66, &mut d_buf);
            let sig: Result<p521::ecdsa::Signature, _> = signing_key.sign_prehash(&d_buf[..d_len]);
            let Ok(sig) = sig else {
                return Ok(None);
            };
            let sig_bytes = sig.to_bytes();
            if signature_out.len() < sig_bytes.len() {
                return Err(CryptoError::Internal);
            }
            signature_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
            Ok(Some(sig_bytes.len()))
        } else {
            Ok(None)
        }
    }
}

/// Verification returns `Ok(false)` for an invalid signature or an unusable public key.
/// Encryption, decryption and key import return `Ok(None)` for invalid inputs (an unusable key or
/// label, a message too large for the key, a bad ciphertext or padding, inconsistent key
/// components). Unsupported algorithms return `Err(CryptoError::Unsupported)`, and output buffers
/// that are too small return `Err(CryptoError::Internal)`.
impl Asymmetric for RustCryptoProvider {
    fn rsassa_verify(
        &self,
        public_key: &[u8],
        exponent: u32,
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let Ok(pub_key) = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa_public_exponent(exponent),
        ) else {
            return Ok(false);
        };

        let verified = match digest {
            TpmtHa::Sha1(d) => pub_key.verify(
                rsa::pkcs1v15::Pkcs1v15Sign::new::<sha1::Sha1>(),
                d,
                signature,
            ),
            TpmtHa::Sha256(d) => pub_key.verify(
                rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(),
                d,
                signature,
            ),
            TpmtHa::Sha384(d) => pub_key.verify(
                rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha384>(),
                d,
                signature,
            ),
            TpmtHa::Sha512(d) => pub_key.verify(
                rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha512>(),
                d,
                signature,
            ),
            _ => return Err(CryptoError::Unsupported),
        };
        Ok(verified.is_ok())
    }

    fn rsapss_verify(
        &self,
        public_key: &[u8],
        exponent: u32,
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let Ok(pub_key) = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa_public_exponent(exponent),
        ) else {
            return Ok(false);
        };

        let verified = match digest {
            TpmtHa::Sha1(d) => pub_key
                .verify(rsa::pss::Pss::new::<sha1::Sha1>(), d, signature)
                .or_else(|_| {
                    let max_salt = public_key.len().saturating_sub(20 + 2);
                    pub_key.verify(
                        rsa::pss::Pss::new_with_salt::<sha1::Sha1>(max_salt),
                        d,
                        signature,
                    )
                }),
            TpmtHa::Sha256(d) => pub_key
                .verify(rsa::pss::Pss::new::<sha2::Sha256>(), d, signature)
                .or_else(|_| {
                    let max_salt = public_key.len().saturating_sub(32 + 2);
                    pub_key.verify(
                        rsa::pss::Pss::new_with_salt::<sha2::Sha256>(max_salt),
                        d,
                        signature,
                    )
                }),
            TpmtHa::Sha384(d) => pub_key
                .verify(rsa::pss::Pss::new::<sha2::Sha384>(), d, signature)
                .or_else(|_| {
                    let max_salt = public_key.len().saturating_sub(48 + 2);
                    pub_key.verify(
                        rsa::pss::Pss::new_with_salt::<sha2::Sha384>(max_salt),
                        d,
                        signature,
                    )
                }),
            TpmtHa::Sha512(d) => pub_key
                .verify(rsa::pss::Pss::new::<sha2::Sha512>(), d, signature)
                .or_else(|_| {
                    let max_salt = public_key.len().saturating_sub(64 + 2);
                    pub_key.verify(
                        rsa::pss::Pss::new_with_salt::<sha2::Sha512>(max_salt),
                        d,
                        signature,
                    )
                }),
            _ => return Err(CryptoError::Unsupported),
        };
        Ok(verified.is_ok())
    }

    fn ecdsa_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        if public_key.len() <= 64 && !public_key.is_empty() {
            if signature.len() != 64 {
                return Ok(false);
            }
            let mut sec1 = [0u8; 65];
            sec1[0] = 0x04;
            sec1[65 - public_key.len()..].copy_from_slice(public_key);
            let Ok(public) = p256::PublicKey::from_sec1_bytes(&sec1) else {
                return Ok(false);
            };
            let verifying_key = p256::ecdsa::VerifyingKey::from(public);
            let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) else {
                return Ok(false);
            };
            use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 32, &mut d_buf);
            Ok(verifying_key.verify_prehash(&d_buf[..d_len], &sig).is_ok())
        } else if public_key.len() <= 96 && public_key.len() > 64 {
            if signature.len() != 96 {
                return Ok(false);
            }
            let mut sec1 = [0u8; 97];
            sec1[0] = 0x04;
            sec1[97 - public_key.len()..].copy_from_slice(public_key);
            let Ok(public) = p384::PublicKey::from_sec1_bytes(&sec1) else {
                return Ok(false);
            };
            let verifying_key = p384::ecdsa::VerifyingKey::from(public);
            let Ok(sig) = p384::ecdsa::Signature::from_slice(signature) else {
                return Ok(false);
            };
            use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 48, &mut d_buf);
            Ok(verifying_key.verify_prehash(&d_buf[..d_len], &sig).is_ok())
        } else if public_key.len() <= 132 && public_key.len() > 96 {
            if signature.len() != 132 {
                return Ok(false);
            }
            let mut sec1 = [0u8; 133];
            sec1[0] = 0x04;
            sec1[133 - public_key.len()..].copy_from_slice(public_key);
            let Ok(verifying_key) = p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else {
                return Ok(false);
            };
            let Ok(sig) = p521::ecdsa::Signature::from_slice(signature) else {
                return Ok(false);
            };
            use p521::ecdsa::signature::hazmat::PrehashVerifier as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 66, &mut d_buf);
            Ok(verifying_key.verify_prehash(&d_buf[..d_len], &sig).is_ok())
        } else {
            Ok(false)
        }
    }

    fn rsaes_encrypt(
        &self,
        public_key: &[u8],
        exponent: u32,
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let Ok(pub_key) = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa_public_exponent(exponent),
        ) else {
            return Ok(None);
        };

        // Fails if `data` is too large for the key.
        let Ok(encrypted) = pub_key.encrypt(&mut rand_core::OsRng, rsa::Pkcs1v15Encrypt, data)
        else {
            return Ok(None);
        };
        if ciphertext.len() < encrypted.len() {
            return Err(CryptoError::Internal);
        }
        ciphertext[..encrypted.len()].copy_from_slice(&encrypted);
        Ok(Some(encrypted.len()))
    }

    fn oaep_encrypt(
        &self,
        hash_alg: TpmiAlgHash,
        public_key: &[u8],
        exponent: u32,
        data: &[u8],
        label: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let Ok(pub_key) = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa_public_exponent(exponent),
        ) else {
            return Ok(None);
        };

        let Ok(label_str) = core::str::from_utf8(label) else {
            return Ok(None);
        };
        let encrypted = match hash_alg {
            TpmiAlgHash::Sha1 => pub_key.encrypt(
                &mut rand_core::OsRng,
                if label.is_empty() {
                    rsa::Oaep::new::<sha1::Sha1>()
                } else {
                    rsa::Oaep::new_with_label::<sha1::Sha1, _>(label_str)
                },
                data,
            ),
            TpmiAlgHash::Sha256 => pub_key.encrypt(
                &mut rand_core::OsRng,
                if label.is_empty() {
                    rsa::Oaep::new::<sha2::Sha256>()
                } else {
                    rsa::Oaep::new_with_label::<sha2::Sha256, _>(label_str)
                },
                data,
            ),
            TpmiAlgHash::Sha384 => pub_key.encrypt(
                &mut rand_core::OsRng,
                if label.is_empty() {
                    rsa::Oaep::new::<sha2::Sha384>()
                } else {
                    rsa::Oaep::new_with_label::<sha2::Sha384, _>(label_str)
                },
                data,
            ),
            TpmiAlgHash::Sha512 => pub_key.encrypt(
                &mut rand_core::OsRng,
                if label.is_empty() {
                    rsa::Oaep::new::<sha2::Sha512>()
                } else {
                    rsa::Oaep::new_with_label::<sha2::Sha512, _>(label_str)
                },
                data,
            ),
            _ => return Err(CryptoError::Unsupported),
        };
        // Fails if `data` (or `label`) is too large for the key.
        let Ok(encrypted) = encrypted else {
            return Ok(None);
        };

        if ciphertext.len() < encrypted.len() {
            return Err(CryptoError::Internal);
        }
        ciphertext[..encrypted.len()].copy_from_slice(&encrypted);
        Ok(Some(encrypted.len()))
    }

    fn rsa_null_encrypt(
        &self,
        public_key: &[u8],
        exponent: u32,
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let Ok(pub_key) = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa_public_exponent(exponent),
        ) else {
            return Ok(None);
        };

        let n = pub_key.n();
        let e = pub_key.e();
        let m = rsa::BigUint::from_bytes_be(data);
        if &m >= n {
            return Ok(None);
        }
        let c = m.modpow(e, n);
        let c_bytes = c.to_bytes_be();
        let mod_len = n.bits().div_ceil(8);
        if ciphertext.len() < mod_len {
            return Err(CryptoError::Internal);
        }
        ciphertext[..mod_len].fill(0);
        let start = mod_len - c_bytes.len();
        ciphertext[start..mod_len].copy_from_slice(&c_bytes);
        Ok(Some(mod_len))
    }

    fn rsaes_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let Ok(priv_key) = rsa::RsaPrivateKey::from_pkcs8_der(private_key) else {
            return Ok(None);
        };

        let Ok(decrypted) = priv_key.decrypt(rsa::Pkcs1v15Encrypt, ciphertext) else {
            return Ok(None);
        };
        if plaintext.len() < decrypted.len() {
            return Err(CryptoError::Internal);
        }
        plaintext[..decrypted.len()].copy_from_slice(&decrypted);
        Ok(Some(decrypted.len()))
    }

    fn oaep_decrypt(
        &self,
        hash_alg: TpmiAlgHash,
        private_key: &[u8],
        ciphertext: &[u8],
        label: &[u8],
        plaintext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let Ok(priv_key) = rsa::RsaPrivateKey::from_pkcs8_der(private_key) else {
            return Ok(None);
        };

        let Ok(label_str) = core::str::from_utf8(label) else {
            return Ok(None);
        };
        let decrypted = match hash_alg {
            TpmiAlgHash::Sha1 => priv_key.decrypt(
                if label.is_empty() {
                    rsa::Oaep::new::<sha1::Sha1>()
                } else {
                    rsa::Oaep::new_with_label::<sha1::Sha1, _>(label_str)
                },
                ciphertext,
            ),
            TpmiAlgHash::Sha256 => priv_key.decrypt(
                if label.is_empty() {
                    rsa::Oaep::new::<sha2::Sha256>()
                } else {
                    rsa::Oaep::new_with_label::<sha2::Sha256, _>(label_str)
                },
                ciphertext,
            ),
            TpmiAlgHash::Sha384 => priv_key.decrypt(
                if label.is_empty() {
                    rsa::Oaep::new::<sha2::Sha384>()
                } else {
                    rsa::Oaep::new_with_label::<sha2::Sha384, _>(label_str)
                },
                ciphertext,
            ),
            TpmiAlgHash::Sha512 => priv_key.decrypt(
                if label.is_empty() {
                    rsa::Oaep::new::<sha2::Sha512>()
                } else {
                    rsa::Oaep::new_with_label::<sha2::Sha512, _>(label_str)
                },
                ciphertext,
            ),
            _ => return Err(CryptoError::Unsupported),
        };
        // Fails if the ciphertext, its padding, or the label is invalid.
        let Ok(decrypted) = decrypted else {
            return Ok(None);
        };

        if plaintext.len() < decrypted.len() {
            return Err(CryptoError::Internal);
        }
        plaintext[..decrypted.len()].copy_from_slice(&decrypted);
        Ok(Some(decrypted.len()))
    }

    fn rsa_null_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let Ok(priv_key) = rsa::RsaPrivateKey::from_pkcs8_der(private_key) else {
            return Ok(None);
        };

        let n = priv_key.n();
        let d = priv_key.d();
        let c = rsa::BigUint::from_bytes_be(ciphertext);
        if &c >= n {
            return Ok(None);
        }
        let m = c.modpow(d, n);
        let m_bytes = m.to_bytes_be();
        let mod_len = n.bits().div_ceil(8);
        if plaintext.len() < mod_len {
            return Err(CryptoError::Internal);
        }
        plaintext[..mod_len].fill(0);
        let start = mod_len - m_bytes.len();
        plaintext[start..mod_len].copy_from_slice(&m_bytes);
        Ok(Some(mod_len))
    }

    fn rsa_generate_key(
        &self,
        key_bits: TpmiRsaKeyBits,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        let mut rng = match seed {
            Some(seed_bytes) => {
                use sha2::Digest as _;
                let mut hasher = sha2::Sha256::new();
                hasher.update(seed_bytes);
                let seed_32: [u8; 32] = hasher.finalize().into();
                use rand_chacha::rand_core::SeedableRng as _;
                RngWrapper::ChaCha(rand_chacha::ChaCha20Rng::from_seed(seed_32))
            }
            None => RngWrapper::Os(rand_core::OsRng),
        };

        let bit_size = u16::from(key_bits) as usize;
        let priv_key =
            rsa::RsaPrivateKey::new(&mut rng, bit_size).map_err(|_| CryptoError::Internal)?;
        let pub_key = rsa::RsaPublicKey::from(&priv_key);

        use rsa::pkcs8::EncodePrivateKey as _;
        let priv_der = priv_key.to_pkcs8_der().map_err(|_| CryptoError::Internal)?;
        let pub_bytes = pub_key.n().to_bytes_be();

        let priv_bytes = priv_der.as_bytes();

        if private_key.len() < priv_bytes.len() || public_key.len() < pub_bytes.len() {
            return Err(CryptoError::Internal);
        }

        private_key[..priv_bytes.len()].copy_from_slice(priv_bytes);
        public_key[..pub_bytes.len()].copy_from_slice(&pub_bytes);

        Ok((pub_bytes.len(), priv_bytes.len()))
    }

    fn ecc_generate_key(
        &self,
        curve: TpmEccCurve,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        let mut rng = match seed {
            Some(seed_bytes) => {
                use sha2::Digest as _;
                let mut hasher = sha2::Sha256::new();
                hasher.update(seed_bytes);
                let seed_32: [u8; 32] = hasher.finalize().into();
                use rand_chacha::rand_core::SeedableRng as _;
                RngWrapper::ChaCha(rand_chacha::ChaCha20Rng::from_seed(seed_32))
            }
            None => RngWrapper::Os(rand_core::OsRng),
        };

        match curve {
            TpmEccCurve::NistP224 => {
                let p224 = NistP224::new();
                let mut k_bytes = [0u8; 28];
                let k = loop {
                    use rand_core::RngCore as _;
                    rng.fill_bytes(&mut k_bytes);
                    let val = rsa::BigUint::from_bytes_be(&k_bytes);
                    if val >= rsa::BigUint::from(1u32) && val < p224.n {
                        break val;
                    }
                };
                let gx = rsa::BigUint::from_bytes_be(&hex_literal::hex!(
                    "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"
                ));
                let gy = rsa::BigUint::from_bytes_be(&hex_literal::hex!(
                    "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"
                ));
                let q = p224.multiply(&k, (gx, gy)).ok_or(CryptoError::Internal)?;
                let q_x = q.0.to_bytes_be();
                let q_y = q.1.to_bytes_be();

                let mut public_xy = [0u8; 56];
                if q_x.len() <= 28 {
                    public_xy[28 - q_x.len()..28].copy_from_slice(&q_x);
                }
                if q_y.len() <= 28 {
                    public_xy[56 - q_y.len()..56].copy_from_slice(&q_y);
                }

                let mut private_scalar = [0u8; 28];
                let k_bytes_be = k.to_bytes_be();
                if k_bytes_be.len() <= 28 {
                    private_scalar[28 - k_bytes_be.len()..].copy_from_slice(&k_bytes_be);
                }

                if public_key.len() < 56 || private_key.len() < 28 {
                    return Err(CryptoError::Internal);
                }
                public_key[..56].copy_from_slice(&public_xy);
                private_key[..28].copy_from_slice(&private_scalar);
                Ok((56, 28))
            }
            TpmEccCurve::NistP256 => {
                let secret_key = p256::SecretKey::random(&mut rng);
                let private_scalar = secret_key.to_bytes();
                let public_key_point = secret_key.public_key();
                let encoded_point = public_key_point.to_encoded_point(false);
                let public_sec1 = encoded_point.as_bytes();
                if public_sec1.len() != 65 || public_sec1[0] != 0x04 {
                    return Err(CryptoError::Internal);
                }
                let public_xy = &public_sec1[1..];
                if public_key.len() < public_xy.len() || private_key.len() < private_scalar.len() {
                    return Err(CryptoError::Internal);
                }
                public_key[..public_xy.len()].copy_from_slice(public_xy);
                private_key[..private_scalar.len()].copy_from_slice(&private_scalar);
                Ok((public_xy.len(), private_scalar.len()))
            }
            TpmEccCurve::NistP384 => {
                let secret_key = p384::SecretKey::random(&mut rng);
                let private_scalar = secret_key.to_bytes();
                let public_key_point = secret_key.public_key();
                let encoded_point = public_key_point.to_encoded_point(false);
                let public_sec1 = encoded_point.as_bytes();
                if public_sec1.len() != 97 || public_sec1[0] != 0x04 {
                    return Err(CryptoError::Internal);
                }
                let public_xy = &public_sec1[1..];
                if public_key.len() < public_xy.len() || private_key.len() < private_scalar.len() {
                    return Err(CryptoError::Internal);
                }
                public_key[..public_xy.len()].copy_from_slice(public_xy);
                private_key[..private_scalar.len()].copy_from_slice(&private_scalar);
                Ok((public_xy.len(), private_scalar.len()))
            }
            TpmEccCurve::NistP521 => {
                let secret_key = p521::SecretKey::random(&mut rng);
                let private_scalar = secret_key.to_bytes();
                let public_key_point = secret_key.public_key();
                let encoded_point = public_key_point.to_encoded_point(false);
                let public_sec1 = encoded_point.as_bytes();
                if public_sec1.len() != 133 || public_sec1[0] != 0x04 {
                    return Err(CryptoError::Internal);
                }
                let public_xy = &public_sec1[1..];
                if public_key.len() < public_xy.len() || private_key.len() < private_scalar.len() {
                    return Err(CryptoError::Internal);
                }
                public_key[..public_xy.len()].copy_from_slice(public_xy);
                private_key[..private_scalar.len()].copy_from_slice(&private_scalar);
                Ok((public_xy.len(), private_scalar.len()))
            }
            TpmEccCurve::BNP256 => {
                let bn = BNP256::new();
                let mut k_bytes = [0u8; 32];
                let k = loop {
                    use rand_core::RngCore as _;
                    rng.fill_bytes(&mut k_bytes);
                    let val = rsa::BigUint::from_bytes_be(&k_bytes);
                    if val >= rsa::BigUint::from(1u32) && val < bn.n {
                        break val;
                    }
                };
                let g = (rsa::BigUint::from(1u32), rsa::BigUint::from(2u32));
                let q = bn.multiply(&k, g).ok_or(CryptoError::Internal)?;
                let q_x = q.0.to_bytes_be();
                let q_y = q.1.to_bytes_be();

                let mut public_xy = [0u8; 64];
                if q_x.len() <= 32 {
                    public_xy[32 - q_x.len()..32].copy_from_slice(&q_x);
                }
                if q_y.len() <= 32 {
                    public_xy[64 - q_y.len()..64].copy_from_slice(&q_y);
                }

                let mut private_scalar = [0u8; 32];
                let k_bytes_be = k.to_bytes_be();
                if k_bytes_be.len() <= 32 {
                    private_scalar[32 - k_bytes_be.len()..].copy_from_slice(&k_bytes_be);
                }

                if public_key.len() < 64 || private_key.len() < 32 {
                    return Err(CryptoError::Internal);
                }
                public_key[..64].copy_from_slice(&public_xy);
                private_key[..32].copy_from_slice(&private_scalar);
                Ok((64, 32))
            }
            _ => Err(CryptoError::Unsupported),
        }
    }

    fn rsa_import_private_key(
        &self,
        modulus: &[u8],
        prime_p: &[u8],
        exponent: u32,
        private_key_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        if exponent == 0 {
            return Ok(None);
        }
        let n = rsa::BigUint::from_bytes_be(modulus);
        let p = rsa::BigUint::from_bytes_be(prime_p);
        let e = rsa::BigUint::from(exponent);

        let one = rsa::BigUint::from(1u32);
        if p <= one {
            return Ok(None);
        }
        let q = &n / &p;
        if q <= one {
            return Ok(None);
        }
        if p.bits().abs_diff(q.bits()) > 1 {
            return Ok(None);
        }
        let rem = &n % &p;
        if rem != rsa::BigUint::default() {
            return Ok(None);
        }
        if &p * &q != n {
            return Ok(None);
        }

        let Ok(priv_key) = rsa::RsaPrivateKey::from_p_q(p, q, e) else {
            return Ok(None);
        };

        use rsa::pkcs8::EncodePrivateKey as _;
        let priv_der = priv_key.to_pkcs8_der().map_err(|_| CryptoError::Internal)?;
        let priv_bytes = priv_der.as_bytes();
        if private_key_out.len() < priv_bytes.len() {
            return Err(CryptoError::Internal);
        }
        private_key_out[..priv_bytes.len()].copy_from_slice(priv_bytes);
        Ok(Some(priv_bytes.len()))
    }

    fn rsa_private_key_to_prime_p(
        &self,
        private_key: &[u8],
        prime_p_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let Ok(priv_key) = rsa::RsaPrivateKey::from_pkcs8_der(private_key) else {
            return Ok(None);
        };
        let primes = priv_key.primes();
        if primes.is_empty() {
            return Ok(None);
        }
        let prime_p_bytes = primes[0].to_bytes_be();
        if prime_p_out.len() < prime_p_bytes.len() {
            return Err(CryptoError::Internal);
        }
        prime_p_out[..prime_p_bytes.len()].copy_from_slice(&prime_p_bytes);
        Ok(Some(prime_p_bytes.len()))
    }
}
