use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use tpm2::crypto::{Asymmetric, AsymmetricSign, CryptoError, TpmiRsaKeyBits, ecc::TpmEccCurve};
use tpm2::{TpmiAlgHash, TpmtHa};

use crate::{BNP256, CruxCryptoProvider, RngWrapper};

/// Returns the RSA public exponent `exponent` (`TPMS_RSA_PARMS.exponent`) as a big integer,
/// where `0` selects the default exponent $2^{16}+1$ (65537).
fn rsa_public_exponent(exponent: u32) -> rsa::BigUint {
    rsa::BigUint::from(if exponent == 0 { 65537 } else { exponent })
}

/// Normalizes an ECDSA `digest` to exactly `N` bytes, the byte length of the
/// curve order, as described by FIPS 186-5 section 6.4 (`bits2int`).
///
/// TPM 2.0 allows any hash algorithm to be combined with any ECDSA curve
/// (Part 1, section C.4 / `CryptEccSign`), so the digest length does not have
/// to match the curve size:
/// - A digest longer than the order is truncated to its leftmost `N` bytes.
///   For the byte-aligned orders used here (P-256 and P-384) this is exactly
///   the leftmost `bitlen(n)` bits.
/// - A shorter digest is left-padded with zeros, which preserves its integer
///   value.
///
/// This matches the BoringSSL and pure-Rust backends. It is also required to
/// avoid a panic in `libcrux_p256`, whose `*_without_hash` functions read
/// exactly 32 bytes from the message and index out of bounds on shorter input.
///
/// For P-521 (`N == 66`), every supported TPM digest (at most 64 bytes) is
/// shorter than the order, so only the zero-padding branch is ever taken.
fn ecdsa_prehash<const N: usize>(digest: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    if digest.len() >= N {
        out.copy_from_slice(&digest[..N]);
    } else {
        out[N - digest.len()..].copy_from_slice(digest);
    }
    out
}

/// Signing follows the [`AsymmetricSign`] conventions: `Ok(None)` if `private_key` is invalid or
/// cannot sign the digest (e.g. an RSA key too small for the digest and its padding),
/// `Err(CryptoError::Unsupported)` for an unsupported digest algorithm (ECDSA accepts any digest,
/// normalized with `ecdsa_prehash`), and `Err(CryptoError::Internal)` if
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
            #[cfg(feature = "sha512")]
            TpmtHa::Sha512(d) => {
                priv_key.sign(rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha512>(), d)
            }
            #[allow(unreachable_patterns)]
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
            #[cfg(feature = "sha512")]
            TpmtHa::Sha512(d) => priv_key.sign_with_rng(
                &mut rand_core::OsRng,
                rsa::pss::Pss::new::<sha2::Sha512>(),
                d,
            ),
            #[allow(unreachable_patterns)]
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
        // Any hash may be paired with any curve; the digest is normalized to the
        // curve order size (see `ecdsa_prehash`), like the other backends.
        let digest_bytes = digest.digest();
        if private_key.len() == 32 {
            let prehash = ecdsa_prehash::<32>(digest_bytes);

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
                prehash.len() as u32,
                &prehash,
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
            let prehash = ecdsa_prehash::<48>(digest_bytes);
            let Ok(secret_key) = p384::SecretKey::from_slice(private_key) else {
                return Ok(None);
            };
            let signing_key = p384::ecdsa::SigningKey::from(secret_key);
            use p384::ecdsa::signature::hazmat::PrehashSigner as _;
            let sig: Result<p384::ecdsa::Signature, _> = signing_key.sign_prehash(&prehash);
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
            let prehash = ecdsa_prehash::<66>(digest_bytes);
            let Ok(signing_key) = p521::ecdsa::SigningKey::from_slice(private_key) else {
                return Ok(None);
            };
            use p521::ecdsa::signature::hazmat::PrehashSigner as _;
            let sig: Result<p521::ecdsa::Signature, _> = signing_key.sign_prehash(&prehash);
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
/// that are too small return `Err(CryptoError::Internal)`. RSA public-key operations use the
/// key's public exponent (`0` for the default 65537), generated RSA keys use the exponent 65537,
/// and private keys are PKCS#8 DER.
impl Asymmetric for CruxCryptoProvider {
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
            #[cfg(feature = "sha512")]
            TpmtHa::Sha512(d) => pub_key.verify(
                rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha512>(),
                d,
                signature,
            ),
            #[allow(unreachable_patterns)]
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
            TpmtHa::Sha1(d) => pub_key.verify(rsa::pss::Pss::new::<sha1::Sha1>(), d, signature),
            TpmtHa::Sha256(d) => pub_key.verify(rsa::pss::Pss::new::<sha2::Sha256>(), d, signature),
            TpmtHa::Sha384(d) => pub_key.verify(rsa::pss::Pss::new::<sha2::Sha384>(), d, signature),
            #[cfg(feature = "sha512")]
            TpmtHa::Sha512(d) => pub_key.verify(rsa::pss::Pss::new::<sha2::Sha512>(), d, signature),
            #[allow(unreachable_patterns)]
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
        // Any hash may be paired with any curve; the digest is normalized to the
        // curve order size (see `ecdsa_prehash`), like the other backends. A
        // digest that does not match the signature is therefore reported as a
        // verification failure (`Ok(false)`), never as `Unsupported`.
        let digest_bytes = digest.digest();
        if public_key.len() == 64 {
            if signature.len() != 64 {
                return Ok(false);
            }
            let prehash = ecdsa_prehash::<32>(digest_bytes);
            let r = &signature[..32];
            let s = &signature[32..];
            Ok(libcrux_p256::ecdsa_verif_without_hash(
                prehash.len() as u32,
                &prehash,
                public_key,
                r,
                s,
            ))
        } else if public_key.len() == 96 {
            if signature.len() != 96 {
                return Ok(false);
            }
            let prehash = ecdsa_prehash::<48>(digest_bytes);
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
            Ok(verifying_key.verify_prehash(&prehash, &sig).is_ok())
        } else if public_key.len() == 132 {
            if signature.len() != 132 {
                return Ok(false);
            }
            let prehash = ecdsa_prehash::<66>(digest_bytes);
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
            Ok(verifying_key.verify_prehash(&prehash, &sig).is_ok())
        } else {
            Ok(false)
        }
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
            #[cfg(feature = "sha512")]
            TpmiAlgHash::Sha512 => pub_key.encrypt(
                &mut rand_core::OsRng,
                if label.is_empty() {
                    rsa::Oaep::new::<sha2::Sha512>()
                } else {
                    rsa::Oaep::new_with_label::<sha2::Sha512, _>(label_str)
                },
                data,
            ),
            #[allow(unreachable_patterns)]
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
            #[cfg(feature = "sha512")]
            TpmiAlgHash::Sha512 => priv_key.decrypt(
                if label.is_empty() {
                    rsa::Oaep::new::<sha2::Sha512>()
                } else {
                    rsa::Oaep::new_with_label::<sha2::Sha512, _>(label_str)
                },
                ciphertext,
            ),
            #[allow(unreachable_patterns)]
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

    fn rsa_private_key_to_crt(
        &self,
        private_key: &[u8],
        crt_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
        let Ok(priv_key) = rsa::RsaPrivateKey::from_pkcs8_der(private_key) else {
            return Ok(None);
        };
        let [first, second] = priv_key.primes() else {
            return Ok(None);
        };
        // The larger prime first, so that `qinv` is the inverse of the smaller one.
        let (p, q) = if first >= second {
            (first, second)
        } else {
            (second, first)
        };
        let Ok(key) = rsa::RsaPrivateKey::from_components(
            priv_key.n().clone(),
            priv_key.e().clone(),
            priv_key.d().clone(),
            alloc::vec![p.clone(), q.clone()],
        ) else {
            return Ok(None);
        };
        let (Some(dp), Some(dq), Some(qinv)) = (key.dp(), key.dq(), key.qinv()) else {
            return Ok(None);
        };
        let Some(qinv) = qinv.to_biguint() else {
            return Ok(None);
        };
        let size = p.to_bytes_be().len();
        if crt_out.len() < 5 * size {
            return Err(CryptoError::Internal);
        }
        for (value, out) in [p, q, dp, dq, &qinv]
            .into_iter()
            .zip(crt_out.chunks_exact_mut(size))
        {
            let bytes = value.to_bytes_be();
            if bytes.len() > size {
                return Err(CryptoError::Internal);
            }
            out[..size - bytes.len()].fill(0);
            out[size - bytes.len()..].copy_from_slice(&bytes);
        }
        Ok(Some(5 * size))
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
        assert_eq!(c.rsassa_verify(&n, 0, sha256, &sig[..len]), Ok(true));
        assert_eq!(
            c.verify_inner(Alg::RSASSA, &n, 0, sha256, &sig[..len]),
            Ok(true)
        );
        sig[0] ^= 1;
        assert_eq!(c.rsassa_verify(&n, 0, sha256, &sig[..len]), Ok(false));
        assert_eq!(c.rsassa_verify(&[], 0, sha256, &sig[..len]), Ok(false));
        assert_eq!(c.rsassa_sign(b"not a key", sha256, &mut sig), Ok(None));
        assert_eq!(
            c.rsassa_sign(&d, sha256, &mut sig[..64]),
            Err(CryptoError::Internal)
        );

        // RSA-PSS: a 1024-bit key cannot sign SHA-512 with a 64-byte salt.
        let len = c.rsapss_sign(&d, sha256, &mut sig).unwrap().unwrap();
        assert_eq!(c.rsapss_verify(&n, 0, sha256, &sig[..len]), Ok(true));
        #[cfg(feature = "sha512")]
        assert_eq!(
            c.rsapss_sign(&d, TpmtHa::Sha512(&[7; 64]), &mut sig),
            Ok(None)
        );

        // OAEP: round trip, wrong label, corrupted ciphertext, oversized message.
        let mut ct = [0u8; 128];
        let len = c
            .oaep_encrypt(TpmiAlgHash::Sha256, &n, 0, b"secret", b"label\0", &mut ct)
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
            c.oaep_encrypt(TpmiAlgHash::Sha256, &n, 0, &[0; 63], b"", &mut ct),
            Ok(None)
        );
        assert_eq!(
            c.oaep_encrypt(TpmiAlgHash::Sha256, &n, 0, b"m", &[0xff], &mut ct),
            Ok(None)
        );

        // Raw RSA: round trip, and a message not smaller than the modulus.
        let mut m = [0u8; 128];
        m[127] = 9;
        assert_eq!(c.rsa_null_encrypt(&n, 0, &m, &mut ct), Ok(Some(128)));
        assert_eq!(c.rsa_null_decrypt(&d, &ct, &mut pt), Ok(Some(128)));
        assert_eq!(pt, m);
        assert_eq!(c.rsa_null_encrypt(&n, 0, &n, &mut ct), Ok(None));
        assert_eq!(c.rsa_null_decrypt(&d, &n, &mut pt), Ok(None));
        assert_eq!(
            c.rsa_null_encrypt(&n, 0, &m, &mut ct[..127]),
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
            c.encrypt(Alg::RSAES, Alg::NULL, &n, 0, b"m", &mut ct, b""),
            Err(CryptoError::Unsupported)
        );
    }

    #[test]
    #[cfg(feature = "sha512")]
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
            // Invalid private scalars (zero). Any digest may be paired with any curve (see
            // `ecdsa_prehash` and the `ecdsa_tests` module below).
            assert_eq!(
                c.ecdsa_sign(&vec![0; sl], digest, &mut sig),
                Ok(None),
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

#[cfg(test)]
mod ecdsa_tests {
    use super::*;

    /// Generates a deterministic ECC key pair on `curve`, returning
    /// `(public_xy, private_scalar)`.
    fn ecc_key(curve: TpmEccCurve) -> (Vec<u8>, Vec<u8>) {
        let mut public = [0u8; 132];
        let mut private = [0u8; 66];
        let (pub_len, priv_len) = CruxCryptoProvider
            .ecc_generate_key(curve, &mut public, &mut private, Some(b"crux ecdsa test"))
            .unwrap();
        (public[..pub_len].to_vec(), private[..priv_len].to_vec())
    }

    fn sign(private: &[u8], digest: TpmtHa<'_>) -> Vec<u8> {
        let mut sig = [0u8; 132];
        let len = CruxCryptoProvider
            .ecdsa_sign(private, digest, &mut sig)
            .unwrap()
            .unwrap();
        sig[..len].to_vec()
    }

    fn verify(public: &[u8], digest: TpmtHa<'_>, sig: &[u8]) -> Result<bool, CryptoError> {
        CruxCryptoProvider.ecdsa_verify(public, digest, sig)
    }

    /// Returns `digest` left-padded with zeros to `N` bytes.
    fn left_pad<const N: usize>(digest: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        out[N - digest.len()..].copy_from_slice(digest);
        out
    }

    /// Longer digests are truncated to their leftmost bytes, shorter ones are
    /// zero-padded on the left, and equal-length digests are copied verbatim.
    #[test]
    fn ecdsa_prehash_truncates_and_pads() {
        let long: [u8; 48] = core::array::from_fn(|i| i as u8);
        assert_eq!(ecdsa_prehash::<32>(&long)[..], long[..32]);

        let short = [0xAAu8; 20];
        let padded = ecdsa_prehash::<32>(&short);
        assert_eq!(padded[..12], [0u8; 12]);
        assert_eq!(padded[12..], short);

        let exact = [0x55u8; 48];
        assert_eq!(ecdsa_prehash::<48>(&exact), exact);

        let sha512 = [0x77u8; 64];
        let p521 = ecdsa_prehash::<66>(&sha512);
        assert_eq!(p521[..2], [0u8; 2]);
        assert_eq!(p521[2..], sha512);
    }

    /// A P-256 key verifying a SHA-384 digest that does not match the
    /// signature reports a failed verification (`Ok(false)`, signature mismatch), not
    /// `Unsupported`. This is the regression for
    /// `adv_test_signature_verification_edge_cases`.
    #[test]
    fn ecdsa_p256_verify_mismatched_sha384_digest_fails_verification() {
        let (public, private) = ecc_key(TpmEccCurve::NistP256);
        let sig = sign(&private, TpmtHa::Sha256(&[0xDE; 32]));
        assert_eq!(
            verify(&public, TpmtHa::Sha384(&[0xBC; 48]), &sig),
            Ok(false)
        );
    }

    /// P-256 signs and verifies SHA-1/SHA-384/SHA-512 digests, and the result
    /// is equivalent to signing the FIPS 186 truncated/padded 32-byte value.
    #[test]
    fn ecdsa_p256_any_hash_round_trips_with_fips186_normalization() {
        let (public, private) = ecc_key(TpmEccCurve::NistP256);

        // SHA-384: truncated to the leftmost 32 bytes.
        let d384: [u8; 48] = core::array::from_fn(|i| (i * 7) as u8);
        let sig = sign(&private, TpmtHa::Sha384(&d384));
        assert_eq!(verify(&public, TpmtHa::Sha384(&d384), &sig), Ok(true));
        let truncated: [u8; 32] = d384[..32].try_into().unwrap();
        assert_eq!(verify(&public, TpmtHa::Sha256(&truncated), &sig), Ok(true));
        let mut tail_changed = d384;
        tail_changed[47] ^= 1; // Beyond the 256-bit order: ignored.
        assert_eq!(
            verify(&public, TpmtHa::Sha384(&tail_changed), &sig),
            Ok(true)
        );
        let mut head_changed = d384;
        head_changed[0] ^= 1;
        assert_eq!(
            verify(&public, TpmtHa::Sha384(&head_changed), &sig),
            Ok(false)
        );

        // SHA-512: truncated to the leftmost 32 bytes.
        #[cfg(feature = "sha512")]
        {
            let d512: [u8; 64] = core::array::from_fn(|i| (i * 3 + 1) as u8);
            let sig = sign(&private, TpmtHa::Sha512(&d512));
            assert_eq!(verify(&public, TpmtHa::Sha512(&d512), &sig), Ok(true));
            let truncated: [u8; 32] = d512[..32].try_into().unwrap();
            assert_eq!(verify(&public, TpmtHa::Sha256(&truncated), &sig), Ok(true));
        }

        // SHA-1: shorter than the order, zero-padded (no panic in libcrux).
        let d1 = [0x5Au8; 20];
        let sig = sign(&private, TpmtHa::Sha1(&d1));
        assert_eq!(verify(&public, TpmtHa::Sha1(&d1), &sig), Ok(true));
        assert_eq!(
            verify(&public, TpmtHa::Sha256(&left_pad::<32>(&d1)), &sig),
            Ok(true)
        );
        assert_eq!(verify(&public, TpmtHa::Sha1(&[0x5B; 20]), &sig), Ok(false));
    }

    /// P-384 accepts shorter (SHA-1/SHA-256) and longer (SHA-512) digests.
    /// Signatures over a SHA-512 digest are cross-checked with the `p384`
    /// crate's own FIPS 186 handling of the full, untruncated digest.
    #[test]
    fn ecdsa_p384_any_hash_round_trips() {
        let (public, private) = ecc_key(TpmEccCurve::NistP384);

        let d256 = [0x11u8; 32];
        let sig = sign(&private, TpmtHa::Sha256(&d256));
        assert_eq!(verify(&public, TpmtHa::Sha256(&d256), &sig), Ok(true));
        assert_eq!(
            verify(&public, TpmtHa::Sha384(&left_pad::<48>(&d256)), &sig),
            Ok(true)
        );
        assert_eq!(
            verify(&public, TpmtHa::Sha384(&[0x11; 48]), &sig),
            Ok(false)
        );

        let d1 = [0x22u8; 20];
        let sig = sign(&private, TpmtHa::Sha1(&d1));
        assert_eq!(verify(&public, TpmtHa::Sha1(&d1), &sig), Ok(true));

        #[cfg(feature = "sha512")]
        {
            let d512: [u8; 64] = core::array::from_fn(|i| (255 - i) as u8);
            let sig = sign(&private, TpmtHa::Sha512(&d512));
            assert_eq!(verify(&public, TpmtHa::Sha512(&d512), &sig), Ok(true));
            let truncated: [u8; 48] = d512[..48].try_into().unwrap();
            assert_eq!(verify(&public, TpmtHa::Sha384(&truncated), &sig), Ok(true));

            let mut sec1 = [0u8; 97];
            sec1[0] = 0x04;
            sec1[1..].copy_from_slice(&public);
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
            let reference = p384::ecdsa::Signature::from_slice(&sig).unwrap();
            use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
            vk.verify_prehash(&d512, &reference).unwrap();
        }
    }

    /// P-521 accepts digests shorter than its order (SHA-1/SHA-256/SHA-384).
    #[test]
    fn ecdsa_p521_any_hash_round_trips() {
        let (public, private) = ecc_key(TpmEccCurve::NistP521);

        let d256 = [0x33u8; 32];
        let sig = sign(&private, TpmtHa::Sha256(&d256));
        assert_eq!(verify(&public, TpmtHa::Sha256(&d256), &sig), Ok(true));
        assert_eq!(
            verify(&public, TpmtHa::Sha256(&[0x34; 32]), &sig),
            Ok(false)
        );

        let d384 = [0x44u8; 48];
        let sig = sign(&private, TpmtHa::Sha384(&d384));
        assert_eq!(verify(&public, TpmtHa::Sha384(&d384), &sig), Ok(true));

        let d1 = [0x55u8; 20];
        let sig = sign(&private, TpmtHa::Sha1(&d1));
        assert_eq!(verify(&public, TpmtHa::Sha1(&d1), &sig), Ok(true));
    }
}
