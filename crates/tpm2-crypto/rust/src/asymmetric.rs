use crate::{BNP256, NistP224, RngWrapper, RustCryptoProvider};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use tpm2::crypto::{Asymmetric, AsymmetricSign, CryptoError, TpmiRsaKeyBits};
use tpm2::{TpmEccCurve, TpmiAlgHash, TpmtHa};

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

impl AsymmetricSign for RustCryptoProvider {
    fn rsassa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(private_key)
            .map_err(|_| CryptoError::InvalidData)?;

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
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        }
        .map_err(|_| CryptoError::HardwareFailure)?;

        if signature_out.len() < sig.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        signature_out[..sig.len()].copy_from_slice(&sig);
        Ok(sig.len())
    }

    fn rsapss_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(private_key)
            .map_err(|_| CryptoError::InvalidData)?;

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
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        }
        .map_err(|_| CryptoError::HardwareFailure)?;

        if signature_out.len() < sig.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        signature_out[..sig.len()].copy_from_slice(&sig);
        Ok(sig.len())
    }

    fn ecdsa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if private_key.len() <= 32 && !private_key.is_empty() {
            let mut padded = [0u8; 32];
            padded[32 - private_key.len()..].copy_from_slice(private_key);
            let secret_key =
                p256::SecretKey::from_slice(&padded).map_err(|_| CryptoError::InvalidData)?;
            let signing_key = p256::ecdsa::SigningKey::from(secret_key);
            use p256::ecdsa::signature::hazmat::PrehashSigner as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 32, &mut d_buf);
            let sig: p256::ecdsa::Signature = signing_key
                .sign_prehash(&d_buf[..d_len])
                .map_err(|_| CryptoError::HardwareFailure)?;
            let sig_bytes = sig.to_bytes();
            if signature_out.len() < sig_bytes.len() {
                return Err(CryptoError::BufferTooSmall);
            }
            signature_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
            Ok(sig_bytes.len())
        } else if private_key.len() <= 48 && private_key.len() > 32 {
            let mut padded = [0u8; 48];
            padded[48 - private_key.len()..].copy_from_slice(private_key);
            let secret_key =
                p384::SecretKey::from_slice(&padded).map_err(|_| CryptoError::InvalidData)?;
            let signing_key = p384::ecdsa::SigningKey::from(secret_key);
            use p384::ecdsa::signature::hazmat::PrehashSigner as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 48, &mut d_buf);
            let sig: p384::ecdsa::Signature = signing_key
                .sign_prehash(&d_buf[..d_len])
                .map_err(|_| CryptoError::HardwareFailure)?;
            let sig_bytes = sig.to_bytes();
            if signature_out.len() < sig_bytes.len() {
                return Err(CryptoError::BufferTooSmall);
            }
            signature_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
            Ok(sig_bytes.len())
        } else if private_key.len() <= 66 && private_key.len() > 48 {
            let mut padded = [0u8; 66];
            padded[66 - private_key.len()..].copy_from_slice(private_key);
            let signing_key = p521::ecdsa::SigningKey::from_slice(&padded)
                .map_err(|_| CryptoError::InvalidData)?;
            use p521::ecdsa::signature::hazmat::PrehashSigner as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 66, &mut d_buf);
            let sig: p521::ecdsa::Signature = signing_key
                .sign_prehash(&d_buf[..d_len])
                .map_err(|_| CryptoError::HardwareFailure)?;
            let sig_bytes = sig.to_bytes();
            if signature_out.len() < sig_bytes.len() {
                return Err(CryptoError::BufferTooSmall);
            }
            signature_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
            Ok(sig_bytes.len())
        } else {
            Err(CryptoError::InvalidData)
        }
    }
}

impl Asymmetric for RustCryptoProvider {
    fn rsassa_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa::BigUint::from(65537u32),
        )
        .map_err(|_| CryptoError::InvalidData)?;

        match digest {
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
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        }
        .map_err(|_| CryptoError::InvalidData)
    }

    fn rsapss_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa::BigUint::from(65537u32),
        )
        .map_err(|_| CryptoError::InvalidData)?;

        match digest {
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
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        }
        .map_err(|_| CryptoError::InvalidData)
    }

    fn ecdsa_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if public_key.len() <= 64 && !public_key.is_empty() {
            if signature.len() != 64 {
                return Err(CryptoError::InvalidData);
            }
            let mut sec1 = [0u8; 65];
            sec1[0] = 0x04;
            sec1[65 - public_key.len()..].copy_from_slice(public_key);
            let public =
                p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidData)?;
            let verifying_key = p256::ecdsa::VerifyingKey::from(public);
            let sig = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| CryptoError::InvalidData)?;
            use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 32, &mut d_buf);
            verifying_key
                .verify_prehash(&d_buf[..d_len], &sig)
                .map_err(|_| CryptoError::InvalidData)?;
            Ok(())
        } else if public_key.len() <= 96 && public_key.len() > 64 {
            if signature.len() != 96 {
                return Err(CryptoError::InvalidData);
            }
            let mut sec1 = [0u8; 97];
            sec1[0] = 0x04;
            sec1[97 - public_key.len()..].copy_from_slice(public_key);
            let public =
                p384::PublicKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidData)?;
            let verifying_key = p384::ecdsa::VerifyingKey::from(public);
            let sig = p384::ecdsa::Signature::from_slice(signature)
                .map_err(|_| CryptoError::InvalidData)?;
            use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 48, &mut d_buf);
            verifying_key
                .verify_prehash(&d_buf[..d_len], &sig)
                .map_err(|_| CryptoError::InvalidData)?;
            Ok(())
        } else if public_key.len() <= 132 && public_key.len() > 96 {
            if signature.len() != 132 {
                return Err(CryptoError::InvalidData);
            }
            let mut sec1 = [0u8; 133];
            sec1[0] = 0x04;
            sec1[133 - public_key.len()..].copy_from_slice(public_key);
            let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| CryptoError::InvalidData)?;
            let sig = p521::ecdsa::Signature::from_slice(signature)
                .map_err(|_| CryptoError::InvalidData)?;
            use p521::ecdsa::signature::hazmat::PrehashVerifier as _;
            let mut d_buf = [0u8; 66];
            let d_len = prepare_prehash(digest.digest(), 66, &mut d_buf);
            verifying_key
                .verify_prehash(&d_buf[..d_len], &sig)
                .map_err(|_| CryptoError::InvalidData)?;
            Ok(())
        } else {
            Err(CryptoError::InvalidData)
        }
    }

    fn rsaes_encrypt(
        &self,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa::BigUint::from(65537u32),
        )
        .map_err(|_| CryptoError::InvalidData)?;

        let encrypted = pub_key
            .encrypt(&mut rand_core::OsRng, rsa::Pkcs1v15Encrypt, data)
            .map_err(|_| CryptoError::HardwareFailure)?;
        if ciphertext.len() < encrypted.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        ciphertext[..encrypted.len()].copy_from_slice(&encrypted);
        Ok(encrypted.len())
    }

    fn oaep_encrypt(
        &self,
        hash_alg: TpmiAlgHash,
        public_key: &[u8],
        data: &[u8],
        label: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa::BigUint::from(65537u32),
        )
        .map_err(|_| CryptoError::InvalidData)?;

        let label_str = core::str::from_utf8(label).map_err(|_| CryptoError::InvalidData)?;
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
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        }
        .map_err(|_| CryptoError::HardwareFailure)?;

        if ciphertext.len() < encrypted.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        ciphertext[..encrypted.len()].copy_from_slice(&encrypted);
        Ok(encrypted.len())
    }

    fn rsa_null_encrypt(
        &self,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let pub_key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(public_key),
            rsa::BigUint::from(65537u32),
        )
        .map_err(|_| CryptoError::InvalidData)?;

        let n = pub_key.n();
        let e = pub_key.e();
        let m = rsa::BigUint::from_bytes_be(data);
        if &m >= n {
            return Err(CryptoError::InvalidData);
        }
        let c = m.modpow(e, n);
        let c_bytes = c.to_bytes_be();
        let mod_len = n.bits().div_ceil(8);
        if ciphertext.len() < mod_len {
            return Err(CryptoError::BufferTooSmall);
        }
        ciphertext[..mod_len].fill(0);
        let start = mod_len - c_bytes.len();
        ciphertext[start..mod_len].copy_from_slice(&c_bytes);
        Ok(mod_len)
    }

    fn rsaes_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(private_key)
            .map_err(|_| CryptoError::InvalidData)?;

        let decrypted = priv_key
            .decrypt(rsa::Pkcs1v15Encrypt, ciphertext)
            .map_err(|_| CryptoError::InvalidData)?;
        if plaintext.len() < decrypted.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        plaintext[..decrypted.len()].copy_from_slice(&decrypted);
        Ok(decrypted.len())
    }

    fn oaep_decrypt(
        &self,
        hash_alg: TpmiAlgHash,
        private_key: &[u8],
        ciphertext: &[u8],
        label: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(private_key)
            .map_err(|_| CryptoError::InvalidData)?;

        let label_str = core::str::from_utf8(label).map_err(|_| CryptoError::InvalidData)?;
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
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        }
        .map_err(|_| CryptoError::HardwareFailure)?;

        if plaintext.len() < decrypted.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        plaintext[..decrypted.len()].copy_from_slice(&decrypted);
        Ok(decrypted.len())
    }

    fn rsa_null_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(private_key)
            .map_err(|_| CryptoError::InvalidData)?;

        let n = priv_key.n();
        let d = priv_key.d();
        let c = rsa::BigUint::from_bytes_be(ciphertext);
        if &c >= n {
            return Err(CryptoError::InvalidData);
        }
        let m = c.modpow(d, n);
        let m_bytes = m.to_bytes_be();
        let mod_len = n.bits().div_ceil(8);
        if plaintext.len() < mod_len {
            return Err(CryptoError::BufferTooSmall);
        }
        plaintext[..mod_len].fill(0);
        let start = mod_len - m_bytes.len();
        plaintext[start..mod_len].copy_from_slice(&m_bytes);
        Ok(mod_len)
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
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, bit_size)
            .map_err(|_| CryptoError::HardwareFailure)?;
        let pub_key = rsa::RsaPublicKey::from(&priv_key);

        use rsa::pkcs8::EncodePrivateKey as _;
        let priv_der = priv_key
            .to_pkcs8_der()
            .map_err(|_| CryptoError::HardwareFailure)?;
        let pub_bytes = pub_key.n().to_bytes_be();

        let priv_bytes = priv_der.as_bytes();

        if private_key.len() < priv_bytes.len() || public_key.len() < pub_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
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
                let q = p224
                    .multiply(&k, (gx, gy))
                    .ok_or(CryptoError::HardwareFailure)?;
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
                    return Err(CryptoError::BufferTooSmall);
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
                    return Err(CryptoError::HardwareFailure);
                }
                let public_xy = &public_sec1[1..];
                if public_key.len() < public_xy.len() || private_key.len() < private_scalar.len() {
                    return Err(CryptoError::BufferTooSmall);
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
                    return Err(CryptoError::HardwareFailure);
                }
                let public_xy = &public_sec1[1..];
                if public_key.len() < public_xy.len() || private_key.len() < private_scalar.len() {
                    return Err(CryptoError::BufferTooSmall);
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
                    return Err(CryptoError::HardwareFailure);
                }
                let public_xy = &public_sec1[1..];
                if public_key.len() < public_xy.len() || private_key.len() < private_scalar.len() {
                    return Err(CryptoError::BufferTooSmall);
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
                let q = bn.multiply(&k, g).ok_or(CryptoError::HardwareFailure)?;
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
                    return Err(CryptoError::BufferTooSmall);
                }
                public_key[..64].copy_from_slice(&public_xy);
                private_key[..32].copy_from_slice(&private_scalar);
                Ok((64, 32))
            }
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }

    fn rsa_import_private_key(
        &self,
        modulus: &[u8],
        prime_p: &[u8],
        exponent: u32,
        private_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if exponent == 0 {
            return Err(CryptoError::InvalidData);
        }
        let n = rsa::BigUint::from_bytes_be(modulus);
        let p = rsa::BigUint::from_bytes_be(prime_p);
        let e = rsa::BigUint::from(exponent);

        let one = rsa::BigUint::from(1u32);
        if p <= one {
            return Err(CryptoError::InvalidData);
        }
        let q = &n / &p;
        if q <= one {
            return Err(CryptoError::InvalidData);
        }
        if p.bits().abs_diff(q.bits()) > 1 {
            return Err(CryptoError::InvalidData);
        }
        let rem = &n % &p;
        if rem != rsa::BigUint::default() {
            return Err(CryptoError::InvalidData);
        }
        if &p * &q != n {
            return Err(CryptoError::InvalidData);
        }

        let priv_key =
            rsa::RsaPrivateKey::from_p_q(p, q, e).map_err(|_| CryptoError::InvalidData)?;

        use rsa::pkcs8::EncodePrivateKey as _;
        let priv_der = priv_key
            .to_pkcs8_der()
            .map_err(|_| CryptoError::HardwareFailure)?;
        let priv_bytes = priv_der.as_bytes();
        if private_key_out.len() < priv_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        private_key_out[..priv_bytes.len()].copy_from_slice(priv_bytes);
        Ok(priv_bytes.len())
    }

    fn rsa_private_key_to_prime_p(
        &self,
        private_key: &[u8],
        prime_p_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(private_key)
            .map_err(|_| CryptoError::InvalidData)?;
        let primes = priv_key.primes();
        if primes.is_empty() {
            return Err(CryptoError::InvalidData);
        }
        let prime_p_bytes = primes[0].to_bytes_be();
        if prime_p_out.len() < prime_p_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }
        prime_p_out[..prime_p_bytes.len()].copy_from_slice(&prime_p_bytes);
        Ok(prime_p_bytes.len())
    }
}
