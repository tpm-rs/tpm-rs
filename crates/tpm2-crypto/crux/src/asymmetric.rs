use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use tpm2::crypto::{Asymmetric, AsymmetricSign, CryptoError, TpmiRsaKeyBits, ecc::TpmEccCurve};
use tpm2::{TpmiAlgHash, TpmtHa};

use crate::{BNP256, CruxCryptoProvider, RngWrapper};

/// Signing follows the [`AsymmetricSign`] conventions: `Ok(None)` if `private_key` is invalid or
/// cannot sign the digest (e.g. an RSA key too small for the digest and its padding),
/// `Err(CryptoError::Unsupported)` for an unsupported digest algorithm (ECDSA requires SHA-256 on
/// P-256, SHA-384 on P-384 and SHA-512 on P-521), and `Err(CryptoError::Internal)` if
/// `signature_out` is too small or the operating system RNG fails.
impl AsymmetricSign for CruxCryptoProvider {
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
        // The key cannot sign the digest (e.g. too small for it and its padding).
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
        // The key cannot sign the digest (e.g. too small for it and its padding).
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
        let hash_alg = digest.hash_alg();
        let digest_bytes = digest.digest();
        if private_key.len() == 32 {
            if hash_alg != TpmiAlgHash::Sha256 {
                return Err(CryptoError::Unsupported);
            }

            use rand::TryRngCore as _;
            let mut nonce = [0u8; 32];
            let mut success = false;
            for _ in 0..100 {
                let _ = rand::rngs::OsRng.try_fill_bytes(&mut nonce);
                if libcrux_p256::validate_private_key(&nonce) {
                    success = true;
                    break;
                }
            }
            if !success {
                return Err(CryptoError::Internal);
            }

            let mut signature = [0u8; 64];
            if libcrux_p256::ecdsa_sign_p256_without_hash(
                &mut signature,
                digest_bytes.len() as u32,
                digest_bytes,
                private_key,
                &nonce,
            ) {
                if signature_out.len() < 64 {
                    return Err(CryptoError::Internal);
                }
                signature_out[..64].copy_from_slice(&signature);
                Ok(Some(64))
            } else {
                // `private_key` is not a valid P-256 scalar.
                Ok(None)
            }
        } else if private_key.len() == 48 {
            if hash_alg != TpmiAlgHash::Sha384 {
                return Err(CryptoError::Unsupported);
            }
            let Ok(secret_key) = p384::SecretKey::from_slice(private_key) else {
                return Ok(None);
            };
            let signing_key = p384::ecdsa::SigningKey::from(secret_key);
            use p384::ecdsa::signature::hazmat::PrehashSigner as _;
            let sig: Result<p384::ecdsa::Signature, _> = signing_key.sign_prehash(digest_bytes);
            let Ok(sig) = sig else {
                return Ok(None);
            };
            let sig_bytes = sig.to_bytes();
            if signature_out.len() < sig_bytes.len() {
                return Err(CryptoError::Internal);
            }
            signature_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
            Ok(Some(sig_bytes.len()))
        } else if private_key.len() == 66 {
            if hash_alg != TpmiAlgHash::Sha512 {
                return Err(CryptoError::Unsupported);
            }
            let Ok(signing_key) = p521::ecdsa::SigningKey::from_slice(private_key) else {
                return Ok(None);
            };
            use p521::ecdsa::signature::hazmat::PrehashSigner as _;
            let sig: Result<p521::ecdsa::Signature, _> = signing_key.sign_prehash(digest_bytes);
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
/// that are too small return `Err(CryptoError::Internal)`. RSA public keys use the exponent 65537
/// and private keys are PKCS#8 DER.
impl Asymmetric for CruxCryptoProvider {
    fn rsassa_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let Ok(pub_key) = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa::BigUint::from(65537u32),
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
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let Ok(pub_key) = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa::BigUint::from(65537u32),
        ) else {
            return Ok(false);
        };

        let verified = match digest {
            TpmtHa::Sha1(d) => pub_key.verify(rsa::pss::Pss::new::<sha1::Sha1>(), d, signature),
            TpmtHa::Sha256(d) => pub_key.verify(rsa::pss::Pss::new::<sha2::Sha256>(), d, signature),
            TpmtHa::Sha384(d) => pub_key.verify(rsa::pss::Pss::new::<sha2::Sha384>(), d, signature),
            TpmtHa::Sha512(d) => pub_key.verify(rsa::pss::Pss::new::<sha2::Sha512>(), d, signature),
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
        let hash_alg = digest.hash_alg();
        let digest_bytes = digest.digest();
        if public_key.len() == 64 {
            if hash_alg != TpmiAlgHash::Sha256 {
                return Err(CryptoError::Unsupported);
            }
            if signature.len() != 64 {
                return Ok(false);
            }
            let r = &signature[..32];
            let s = &signature[32..];
            Ok(libcrux_p256::ecdsa_verif_without_hash(
                digest_bytes.len() as u32,
                digest_bytes,
                public_key,
                r,
                s,
            ))
        } else if public_key.len() == 96 {
            if hash_alg != TpmiAlgHash::Sha384 {
                return Err(CryptoError::Unsupported);
            }
            if signature.len() != 96 {
                return Ok(false);
            }
            let mut sec1 = [0u8; 97];
            sec1[0] = 0x04;
            sec1[1..].copy_from_slice(public_key);
            let Ok(public) = p384::PublicKey::from_sec1_bytes(&sec1) else {
                return Ok(false);
            };
            let verifying_key = p384::ecdsa::VerifyingKey::from(public);
            let Ok(sig) = p384::ecdsa::Signature::from_slice(signature) else {
                return Ok(false);
            };
            use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
            Ok(verifying_key.verify_prehash(digest_bytes, &sig).is_ok())
        } else if public_key.len() == 132 {
            if hash_alg != TpmiAlgHash::Sha512 {
                return Err(CryptoError::Unsupported);
            }
            if signature.len() != 132 {
                return Ok(false);
            }
            let mut sec1 = [0u8; 133];
            sec1[0] = 0x04;
            sec1[1..].copy_from_slice(public_key);
            let Ok(verifying_key) = p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else {
                return Ok(false);
            };
            let Ok(sig) = p521::ecdsa::Signature::from_slice(signature) else {
                return Ok(false);
            };
            use p521::ecdsa::signature::hazmat::PrehashVerifier as _;
            Ok(verifying_key.verify_prehash(digest_bytes, &sig).is_ok())
        } else {
            Ok(false)
        }
    }

    fn oaep_encrypt(
        &self,
        hash_alg: TpmiAlgHash,
        public_key: &[u8],
        data: &[u8],
        label: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let Ok(pub_key) = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa::BigUint::from(65537u32),
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
        // `data` is too large for the key.
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
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let Ok(pub_key) = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa::BigUint::from(65537u32),
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

    /// Decrypts with RSAES-OAEP. A ciphertext that does not decrypt (bad
    /// padding, wrong label, wrong length) returns `Ok(None)`.
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

    /// Generates an RSA key pair of 1024, 2048, 3072, or 4096 bits (any other
    /// size returns [`CryptoError::Unsupported`]).
    ///
    /// With a `seed`, the key is derived deterministically from a ChaCha20 RNG
    /// seeded with SHA-256(`seed`); otherwise the operating system RNG is used.
    fn rsa_generate_key(
        &self,
        bits: TpmiRsaKeyBits,
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

        let bit_size = u16::from(bits) as usize;
        if ![1024, 2048, 3072, 4096].contains(&bit_size) {
            return Err(CryptoError::Unsupported);
        }
        let priv_key =
            rsa::RsaPrivateKey::new(&mut rng, bit_size).map_err(|_| CryptoError::Internal)?;
        let pub_key = rsa::RsaPublicKey::from(&priv_key);

        use rsa::pkcs8::EncodePrivateKey as _;
        let priv_der = priv_key.to_pkcs8_der().map_err(|_| CryptoError::Internal)?;
        let priv_bytes = priv_der.as_bytes();

        let n_bytes = pub_key.n().to_bytes_be();
        let mod_len = pub_key.n().bits().div_ceil(8);

        if public_key.len() < mod_len || private_key.len() < priv_bytes.len() {
            return Err(CryptoError::Internal);
        }

        public_key[..mod_len].fill(0);
        let start = mod_len - n_bytes.len();
        public_key[start..mod_len].copy_from_slice(&n_bytes);

        private_key[..priv_bytes.len()].copy_from_slice(priv_bytes);
        Ok((mod_len, priv_bytes.len()))
    }

    /// Generates an ECC key pair on NIST P-256, P-384, P-521, or BN P-256 (any
    /// other curve returns [`CryptoError::Unsupported`]).
    ///
    /// With a `seed`, the key is derived deterministically from a ChaCha20 RNG
    /// seeded with SHA-256(`seed`); otherwise the operating system RNG is used.
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
            TpmEccCurve::NistP224 => Err(CryptoError::Unsupported),
            TpmEccCurve::NistP256 => {
                use rand_core::RngCore as _;
                let mut scalar_32 = [0u8; 32];
                let mut success = false;
                for _ in 0..100 {
                    rng.fill_bytes(&mut scalar_32);
                    if libcrux_p256::validate_private_key(&scalar_32) {
                        success = true;
                        break;
                    }
                }
                if !success {
                    return Err(CryptoError::Internal);
                }

                let mut pub_64 = [0u8; 64];
                if !libcrux_p256::dh_initiator(&mut pub_64, &scalar_32) {
                    return Err(CryptoError::Internal);
                }

                if public_key.len() < 64 || private_key.len() < 32 {
                    return Err(CryptoError::Internal);
                }
                public_key[..64].copy_from_slice(&pub_64);
                private_key[..32].copy_from_slice(&scalar_32);
                Ok((64, 32))
            }
            TpmEccCurve::NistP384 => {
                let secret_key = p384::SecretKey::random(&mut rng);
                let pub_key = secret_key.public_key();
                let secret_bytes = secret_key.to_bytes();
                use p384::elliptic_curve::sec1::ToEncodedPoint as _;
                let encoded_point = pub_key.to_encoded_point(false);
                let public_sec1 = encoded_point.as_bytes();
                if public_sec1.len() != 97 || public_sec1[0] != 0x04 {
                    return Err(CryptoError::Internal);
                }
                let public_xy = &public_sec1[1..];
                if public_key.len() < public_xy.len() || private_key.len() < secret_bytes.len() {
                    return Err(CryptoError::Internal);
                }
                public_key[..public_xy.len()].copy_from_slice(public_xy);
                private_key[..secret_bytes.len()].copy_from_slice(&secret_bytes);
                Ok((public_xy.len(), secret_bytes.len()))
            }
            TpmEccCurve::NistP521 => {
                let secret_key = p521::SecretKey::random(&mut rng);
                let pub_key = secret_key.public_key();
                let secret_bytes = secret_key.to_bytes();
                use p521::elliptic_curve::sec1::ToEncodedPoint as _;
                let encoded_point = pub_key.to_encoded_point(false);
                let public_sec1 = encoded_point.as_bytes();
                if public_sec1.len() != 133 || public_sec1[0] != 0x04 {
                    return Err(CryptoError::Internal);
                }
                let public_xy = &public_sec1[1..];
                if public_key.len() < public_xy.len() || private_key.len() < secret_bytes.len() {
                    return Err(CryptoError::Internal);
                }
                public_key[..public_xy.len()].copy_from_slice(public_xy);
                private_key[..secret_bytes.len()].copy_from_slice(&secret_bytes);
                Ok((public_xy.len(), secret_bytes.len()))
            }
            TpmEccCurve::BNP256 => {
                use rand_core::RngCore as _;
                let bn = BNP256::new();
                let mut scalar_32 = [0u8; 32];
                let mut k;
                let zero = rsa::BigUint::from(0u32);
                loop {
                    rng.fill_bytes(&mut scalar_32);
                    k = rsa::BigUint::from_bytes_be(&scalar_32);
                    if k > zero && k < bn.n {
                        break;
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2::Alg;

    /// Generates a deterministic RSA-1024 key pair: `(modulus, pkcs8_der)`.
    fn rsa_1024_key(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let c = CruxCryptoProvider;
        let (mut public, mut private) = ([0u8; 512], [0u8; 2048]);
        let (pl, sl) = c
            .rsa_generate_key(TpmiRsaKeyBits(1024), &mut public, &mut private, Some(seed))
            .unwrap();
        assert_eq!(pl, 128);
        (public[..pl].to_vec(), private[..sl].to_vec())
    }

    #[test]
    fn rsa_seeded_key_generation_is_deterministic() {
        let c = CruxCryptoProvider;
        let (n, d) = rsa_1024_key(b"seed");
        assert_eq!((n.clone(), d.clone()), rsa_1024_key(b"seed"));
        assert_ne!(n, rsa_1024_key(b"other seed").0);

        let (mut public, mut private) = ([0u8; 512], [0u8; 2048]);
        assert_eq!(
            c.rsa_generate_key(
                TpmiRsaKeyBits(1536),
                &mut public,
                &mut private,
                Some(b"seed")
            ),
            Err(CryptoError::Unsupported)
        );
        assert_eq!(
            c.rsa_generate_key(
                TpmiRsaKeyBits(1024),
                &mut public[..127],
                &mut private,
                Some(b"seed")
            ),
            Err(CryptoError::Internal)
        );
    }

    #[test]
    fn rsa_operations_follow_the_result_conventions() {
        let c = CruxCryptoProvider;
        let (n, d) = rsa_1024_key(b"conventions");
        let digest = [0x42u8; 32];
        let sha256 = TpmtHa::Sha256(&digest);

        // RSASSA: sign/verify, corrupted signature, unusable keys.
        let mut sig = [0u8; 256];
        let len = c.rsassa_sign(&d, sha256, &mut sig).unwrap().unwrap();
        assert_eq!(len, 128);
        assert_eq!(c.rsassa_verify(&n, sha256, &sig[..len]), Ok(true));
        assert_eq!(
            c.verify_inner(Alg::RSASSA, &n, sha256, &sig[..len]),
            Ok(true)
        );
        sig[0] ^= 1;
        assert_eq!(c.rsassa_verify(&n, sha256, &sig[..len]), Ok(false));
        assert_eq!(c.rsassa_verify(&[], sha256, &sig[..len]), Ok(false));
        assert_eq!(c.rsassa_sign(b"not a key", sha256, &mut sig), Ok(None));
        assert_eq!(
            c.rsassa_sign(&d, sha256, &mut sig[..64]),
            Err(CryptoError::Internal)
        );
        assert_eq!(
            c.rsassa_sign(&d, TpmtHa::Sm3_256(&digest), &mut sig),
            Err(CryptoError::Unsupported)
        );

        // RSA-PSS: a 1024-bit key cannot sign SHA-512 with a 64-byte salt.
        let len = c.rsapss_sign(&d, sha256, &mut sig).unwrap().unwrap();
        assert_eq!(c.rsapss_verify(&n, sha256, &sig[..len]), Ok(true));
        assert_eq!(
            c.rsapss_sign(&d, TpmtHa::Sha512(&[7; 64]), &mut sig),
            Ok(None)
        );

        // OAEP: round trip, wrong label, corrupted ciphertext, oversized message.
        let mut ct = [0u8; 128];
        let len = c
            .oaep_encrypt(TpmiAlgHash::Sha256, &n, b"secret", b"label\0", &mut ct)
            .unwrap()
            .unwrap();
        let mut pt = [0u8; 128];
        assert_eq!(
            c.oaep_decrypt(TpmiAlgHash::Sha256, &d, &ct[..len], b"label\0", &mut pt),
            Ok(Some(6))
        );
        assert_eq!(&pt[..6], b"secret");
        assert_eq!(
            c.oaep_decrypt(TpmiAlgHash::Sha256, &d, &ct[..len], b"other\0", &mut pt),
            Ok(None)
        );
        ct[5] ^= 1;
        assert_eq!(
            c.oaep_decrypt(TpmiAlgHash::Sha256, &d, &ct[..len], b"label\0", &mut pt),
            Ok(None)
        );
        assert_eq!(
            c.oaep_encrypt(TpmiAlgHash::Sha256, &n, &[0; 63], b"", &mut ct),
            Ok(None)
        );
        assert_eq!(
            c.oaep_encrypt(TpmiAlgHash::Sha256, &n, b"m", &[0xff], &mut ct),
            Ok(None)
        );
        assert_eq!(
            c.oaep_encrypt(TpmiAlgHash::Sm3_256, &n, b"m", b"", &mut ct),
            Err(CryptoError::Unsupported)
        );

        // Raw RSA: round trip, and a message not smaller than the modulus.
        let mut m = [0u8; 128];
        m[127] = 9;
        assert_eq!(c.rsa_null_encrypt(&n, &m, &mut ct), Ok(Some(128)));
        assert_eq!(c.rsa_null_decrypt(&d, &ct, &mut pt), Ok(Some(128)));
        assert_eq!(pt, m);
        assert_eq!(c.rsa_null_encrypt(&n, &n, &mut ct), Ok(None));
        assert_eq!(c.rsa_null_decrypt(&d, &n, &mut pt), Ok(None));
        assert_eq!(
            c.rsa_null_encrypt(&n, &m, &mut ct[..127]),
            Err(CryptoError::Internal)
        );

        // Import from (n, p): the imported key decrypts what the original encrypted.
        let mut p = [0u8; 128];
        let p_len = c.rsa_private_key_to_prime_p(&d, &mut p).unwrap().unwrap();
        assert_eq!(c.rsa_private_key_to_prime_p(b"junk", &mut p), Ok(None));
        let mut imported = [0u8; 2048];
        let imported_len = c
            .rsa_import_private_key(&n, &p[..p_len], 65537, &mut imported)
            .unwrap()
            .unwrap();
        assert_eq!(
            c.rsa_null_decrypt(&imported[..imported_len], &ct, &mut pt),
            Ok(Some(128))
        );
        assert_eq!(pt, m);
        assert_eq!(
            c.rsa_import_private_key(&n, &p[..p_len], 0, &mut imported),
            Ok(None)
        );
        assert_eq!(
            c.rsa_import_private_key(&n, &n, 65537, &mut imported),
            Ok(None)
        );
        assert_eq!(
            c.rsa_import_private_key(&n, &[1], 65537, &mut imported),
            Ok(None)
        );
        assert_eq!(
            c.rsa_import_private_key(&n, &p[..p_len], 65537, &mut imported[..10]),
            Err(CryptoError::Internal)
        );

        // RSAES is not implemented by this backend.
        assert_eq!(
            c.encrypt(Alg::RSAES, Alg::NULL, &n, b"m", &mut ct, b""),
            Err(CryptoError::Unsupported)
        );
    }

    #[test]
    fn ecdsa_sign_and_verify_on_each_nist_curve() {
        let c = CruxCryptoProvider;
        let digests: [(TpmEccCurve, TpmtHa<'_>); 3] = [
            (TpmEccCurve::NistP256, TpmtHa::Sha256(&[1; 32])),
            (TpmEccCurve::NistP384, TpmtHa::Sha384(&[2; 48])),
            (TpmEccCurve::NistP521, TpmtHa::Sha512(&[3; 64])),
        ];
        for (curve, digest) in digests {
            let (mut public, mut private) = ([0u8; 132], [0u8; 66]);
            let (pl, sl) = c
                .ecc_generate_key(curve, &mut public, &mut private, Some(b"ecdsa"))
                .unwrap();
            let (public, private) = (&public[..pl], &private[..sl]);
            let mut sig = [0u8; 132];
            let len = c.ecdsa_sign(private, digest, &mut sig).unwrap().unwrap();
            assert_eq!(len, pl, "{curve:?}");
            assert_eq!(
                c.ecdsa_verify(public, digest, &sig[..len]),
                Ok(true),
                "{curve:?}"
            );
            assert_eq!(
                c.sign_inner(Alg::ECDSA, private, digest, &mut sig[..len]),
                Ok(Some(len)),
                "{curve:?}"
            );
            sig[len - 1] ^= 1;
            assert_eq!(
                c.ecdsa_verify(public, digest, &sig[..len]),
                Ok(false),
                "{curve:?}"
            );
            assert_eq!(
                c.ecdsa_verify(public, digest, &sig[1..len]),
                Ok(false),
                "{curve:?}"
            );
            // Invalid private scalars (zero) and the wrong digest for the curve.
            assert_eq!(
                c.ecdsa_sign(&vec![0; sl], digest, &mut sig),
                Ok(None),
                "{curve:?}"
            );
            assert_eq!(
                c.ecdsa_sign(private, TpmtHa::Sha1(&[0; 20]), &mut sig),
                Err(CryptoError::Unsupported),
                "{curve:?}"
            );
            assert_eq!(
                c.ecdsa_sign(private, digest, &mut sig[..len - 1]),
                Err(CryptoError::Internal),
                "{curve:?}"
            );
        }
        assert_eq!(
            c.ecdsa_sign(&[1; 20], TpmtHa::Sha256(&[1; 32]), &mut [0; 64]),
            Ok(None)
        );
        assert_eq!(
            c.ecdsa_verify(&[1; 20], TpmtHa::Sha256(&[1; 32]), &[0; 64]),
            Ok(false)
        );
    }

    #[test]
    fn ecc_seeded_key_generation_is_deterministic() {
        let c = CruxCryptoProvider;
        for (curve, pl, sl) in [
            (TpmEccCurve::NistP256, 64, 32),
            (TpmEccCurve::NistP384, 96, 48),
            (TpmEccCurve::NistP521, 132, 66),
            (TpmEccCurve::BNP256, 64, 32),
        ] {
            let gen_key = |seed: &[u8]| {
                let (mut public, mut private) = ([0u8; 132], [0u8; 66]);
                let lens = c
                    .ecc_generate_key(curve, &mut public, &mut private, Some(seed))
                    .unwrap();
                (lens, public, private)
            };
            let (lens, public, private) = gen_key(b"seed");
            assert_eq!(lens, (pl, sl), "{curve:?}");
            assert_eq!(gen_key(b"seed"), (lens, public, private), "{curve:?}");
            assert_ne!(gen_key(b"other").1, public, "{curve:?}");
            assert_eq!(
                tpm2::crypto::Ecc::validate_point(&c, curve, &public[..pl]),
                Ok(true),
                "{curve:?}"
            );
            let (mut small_pub, mut small_priv) = (vec![0u8; pl - 1], vec![0u8; sl]);
            assert_eq!(
                c.ecc_generate_key(curve, &mut small_pub, &mut small_priv, Some(b"seed")),
                Err(CryptoError::Internal),
                "{curve:?}"
            );
        }
        let (mut public, mut private) = ([0u8; 132], [0u8; 66]);
        assert_eq!(
            c.ecc_generate_key(TpmEccCurve::NistP224, &mut public, &mut private, None),
            Err(CryptoError::Unsupported)
        );
    }
}
