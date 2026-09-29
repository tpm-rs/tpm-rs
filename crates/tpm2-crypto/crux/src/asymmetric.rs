use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use tpm2::crypto::{Asymmetric, AsymmetricSign, CryptoError, TpmiRsaKeyBits, ecc::TpmEccCurve};
use tpm2::{TpmiAlgHash, TpmtHa};

use crate::{BNP256, CruxCryptoProvider, RngWrapper};

impl AsymmetricSign for CruxCryptoProvider {
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
        let hash_alg = digest.hash_alg();
        let digest_bytes = digest.digest();
        if private_key.len() == 32 {
            if hash_alg != TpmiAlgHash::Sha256 {
                return Err(CryptoError::UnsupportedAlgorithm);
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
                return Err(CryptoError::HardwareFailure);
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
                    return Err(CryptoError::BufferTooSmall);
                }
                signature_out[..64].copy_from_slice(&signature);
                Ok(64)
            } else {
                Err(CryptoError::HardwareFailure)
            }
        } else if private_key.len() == 48 {
            if hash_alg != TpmiAlgHash::Sha384 {
                return Err(CryptoError::UnsupportedAlgorithm);
            }
            let secret_key =
                p384::SecretKey::from_slice(private_key).map_err(|_| CryptoError::InvalidData)?;
            let signing_key = p384::ecdsa::SigningKey::from(secret_key);
            use p384::ecdsa::signature::hazmat::PrehashSigner as _;
            let sig: p384::ecdsa::Signature = signing_key
                .sign_prehash(digest_bytes)
                .map_err(|_| CryptoError::HardwareFailure)?;
            let sig_bytes = sig.to_bytes();
            if signature_out.len() < sig_bytes.len() {
                return Err(CryptoError::BufferTooSmall);
            }
            signature_out[..sig_bytes.len()].copy_from_slice(&sig_bytes);
            Ok(sig_bytes.len())
        } else if private_key.len() == 66 {
            if hash_alg != TpmiAlgHash::Sha512 {
                return Err(CryptoError::UnsupportedAlgorithm);
            }
            let signing_key = p521::ecdsa::SigningKey::from_slice(private_key)
                .map_err(|_| CryptoError::InvalidData)?;
            use p521::ecdsa::signature::hazmat::PrehashSigner as _;
            let sig: p521::ecdsa::Signature = signing_key
                .sign_prehash(digest_bytes)
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

impl Asymmetric for CruxCryptoProvider {
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
            TpmtHa::Sha1(d) => pub_key.verify(rsa::pss::Pss::new::<sha1::Sha1>(), d, signature),
            TpmtHa::Sha256(d) => pub_key.verify(rsa::pss::Pss::new::<sha2::Sha256>(), d, signature),
            TpmtHa::Sha384(d) => pub_key.verify(rsa::pss::Pss::new::<sha2::Sha384>(), d, signature),
            TpmtHa::Sha512(d) => pub_key.verify(rsa::pss::Pss::new::<sha2::Sha512>(), d, signature),
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
        let hash_alg = digest.hash_alg();
        let digest_bytes = digest.digest();
        if public_key.len() == 64 {
            if hash_alg != TpmiAlgHash::Sha256 {
                return Err(CryptoError::UnsupportedAlgorithm);
            }
            if signature.len() != 64 {
                return Err(CryptoError::InvalidData);
            }
            let r = &signature[..32];
            let s = &signature[32..];
            if libcrux_p256::ecdsa_verif_without_hash(
                digest_bytes.len() as u32,
                digest_bytes,
                public_key,
                r,
                s,
            ) {
                Ok(())
            } else {
                Err(CryptoError::InvalidData)
            }
        } else if public_key.len() == 96 {
            if hash_alg != TpmiAlgHash::Sha384 {
                return Err(CryptoError::UnsupportedAlgorithm);
            }
            if signature.len() != 96 {
                return Err(CryptoError::InvalidData);
            }
            let mut sec1 = [0u8; 97];
            sec1[0] = 0x04;
            sec1[1..].copy_from_slice(public_key);
            let public =
                p384::PublicKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidData)?;
            let verifying_key = p384::ecdsa::VerifyingKey::from(public);
            let sig = p384::ecdsa::Signature::from_slice(signature)
                .map_err(|_| CryptoError::InvalidData)?;
            use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
            verifying_key
                .verify_prehash(digest_bytes, &sig)
                .map_err(|_| CryptoError::InvalidData)
        } else if public_key.len() == 132 {
            if hash_alg != TpmiAlgHash::Sha512 {
                return Err(CryptoError::UnsupportedAlgorithm);
            }
            if signature.len() != 132 {
                return Err(CryptoError::InvalidData);
            }
            let mut sec1 = [0u8; 133];
            sec1[0] = 0x04;
            sec1[1..].copy_from_slice(public_key);
            let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| CryptoError::InvalidData)?;
            let sig = p521::ecdsa::Signature::from_slice(signature)
                .map_err(|_| CryptoError::InvalidData)?;
            use p521::ecdsa::signature::hazmat::PrehashVerifier as _;
            verifying_key
                .verify_prehash(digest_bytes, &sig)
                .map_err(|_| CryptoError::InvalidData)
        } else {
            Err(CryptoError::InvalidData)
        }
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
            return Err(CryptoError::InvalidData);
        }
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, bit_size)
            .map_err(|_| CryptoError::HardwareFailure)?;
        let pub_key = rsa::RsaPublicKey::from(&priv_key);

        use rsa::pkcs8::EncodePrivateKey as _;
        let priv_der = priv_key
            .to_pkcs8_der()
            .map_err(|_| CryptoError::HardwareFailure)?;
        let priv_bytes = priv_der.as_bytes();

        let n_bytes = pub_key.n().to_bytes_be();
        let mod_len = pub_key.n().bits().div_ceil(8);

        if public_key.len() < mod_len || private_key.len() < priv_bytes.len() {
            return Err(CryptoError::BufferTooSmall);
        }

        public_key[..mod_len].fill(0);
        let start = mod_len - n_bytes.len();
        public_key[start..mod_len].copy_from_slice(&n_bytes);

        private_key[..priv_bytes.len()].copy_from_slice(priv_bytes);
        Ok((mod_len, priv_bytes.len()))
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
            TpmEccCurve::NistP224 => Err(CryptoError::UnsupportedAlgorithm),
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
                    return Err(CryptoError::HardwareFailure);
                }

                let mut pub_64 = [0u8; 64];
                if !libcrux_p256::dh_initiator(&mut pub_64, &scalar_32) {
                    return Err(CryptoError::HardwareFailure);
                }

                if public_key.len() < 64 || private_key.len() < 32 {
                    return Err(CryptoError::BufferTooSmall);
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
                    return Err(CryptoError::HardwareFailure);
                }
                let public_xy = &public_sec1[1..];
                if public_key.len() < public_xy.len() || private_key.len() < secret_bytes.len() {
                    return Err(CryptoError::BufferTooSmall);
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
                    return Err(CryptoError::HardwareFailure);
                }
                let public_xy = &public_sec1[1..];
                if public_key.len() < public_xy.len() || private_key.len() < secret_bytes.len() {
                    return Err(CryptoError::BufferTooSmall);
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
