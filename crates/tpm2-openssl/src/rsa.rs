use openssl::bn::{BigNum, BigNumContext};
use openssl::md::{Md, MdRef};
use openssl::pkey::{PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding, Rsa as OsRsa};
use openssl::sign::RsaPssSaltlen;
use tpm2::{
    TpmiAlgHash, TpmtHa,
    crypto::{
        CryptoError, Rng, RsaEncryptScheme,
        backend::{AsymmetricKey, Rsa, RsaKey, RsaSigScheme},
    },
};

pub struct RsaPriv {
    pub priv_key: OsRsa<Private>,
    pub pub_key: OsRsa<Public>,
}

/// `RSAES-PKCS1-v1_5` decryption padding mode which
/// reports invalid padding as an error, rather than OpenSSL's default implicit
/// rejection (returning a synthetic plaintext).
const RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING: libc::c_int = 8;

/// PSS salt length which recovers the salt length from the signature when
/// verifying.
const RSA_PSS_SALTLEN_AUTO: libc::c_int = -2;

/// Returns the OpenSSL digest for `alg`.
fn md(alg: TpmiAlgHash) -> &'static MdRef {
    match alg {
        TpmiAlgHash::Sha1 => Md::sha1(),
        TpmiAlgHash::Sha256 => Md::sha256(),
        TpmiAlgHash::Sha384 => Md::sha384(),
        TpmiAlgHash::Sha512 => Md::sha512(),
        TpmiAlgHash::Sm3_256 => Md::sm3(),
        TpmiAlgHash::Sha3_256 => Md::sha3_256(),
        TpmiAlgHash::Sha3_384 => Md::sha3_384(),
        TpmiAlgHash::Sha3_512 => Md::sha3_512(),
    }
}

macro_rules! impl_rsa {
    ($name:ident, $mod_size:expr, $prime_size:expr) => {
        pub struct $name;

        impl AsymmetricKey<$mod_size, $prime_size, u32> for $name {
            type Public = OsRsa<Public>;
            type Private = RsaPriv;

            fn load_public(
                exponent: u32,
                modulus: &[u8; $mod_size],
            ) -> Result<Option<Self::Public>, CryptoError> {
                // Per TPM 2.0 Part 1, the modulus has its top bit set and is odd.
                if modulus[0] & 0x80 == 0 || modulus[$mod_size - 1] & 1 == 0 {
                    return Ok(None);
                }
                let n = BigNum::from_slice(modulus).map_err(|_| CryptoError::Internal)?;
                let e = BigNum::from_u32(exponent).map_err(|_| CryptoError::Internal)?;
                Ok(OsRsa::from_public_components(n, e).ok())
            }

            fn store_public(
                public: &Self::Public,
                out: &mut [u8; $mod_size],
            ) -> Result<(), CryptoError> {
                let n_bytes = public.n().to_vec();
                if n_bytes.len() > $mod_size {
                    return Err(CryptoError::Internal);
                }
                out.fill(0);
                out[$mod_size - n_bytes.len()..].copy_from_slice(&n_bytes);
                Ok(())
            }

            fn load_private(
                public: Self::Public,
                prime_p: &[u8; $prime_size],
            ) -> Result<Option<Self::Private>, CryptoError> {
                let mut ctx = BigNumContext::new().map_err(|_| CryptoError::Internal)?;
                let p = BigNum::from_slice(prime_p).map_err(|_| CryptoError::Internal)?;
                let n = public.n().to_owned().map_err(|_| CryptoError::Internal)?;
                let e = public.e().to_owned().map_err(|_| CryptoError::Internal)?;

                let mut q = BigNum::new().map_err(|_| CryptoError::Internal)?;
                let mut rem = BigNum::new().map_err(|_| CryptoError::Internal)?;
                q.div_rem(&mut rem, &n, &p, &mut ctx)
                    .map_err(|_| CryptoError::Internal)?;
                if rem != BigNum::new().unwrap() {
                    return Ok(None);
                }

                let mut p1 = BigNum::new().map_err(|_| CryptoError::Internal)?;
                let mut q1 = BigNum::new().map_err(|_| CryptoError::Internal)?;
                let one = BigNum::from_u32(1).map_err(|_| CryptoError::Internal)?;
                p1.checked_sub(&p, &one)
                    .map_err(|_| CryptoError::Internal)?;
                q1.checked_sub(&q, &one)
                    .map_err(|_| CryptoError::Internal)?;

                let mut phi = BigNum::new().map_err(|_| CryptoError::Internal)?;
                phi.checked_mul(&p1, &q1, &mut ctx)
                    .map_err(|_| CryptoError::Internal)?;

                let mut d = BigNum::new().map_err(|_| CryptoError::Internal)?;
                if d.mod_inverse(&e, &phi, &mut ctx).is_err() {
                    return Ok(None); // e and phi are not coprime
                }

                let mut dmp1 = BigNum::new().map_err(|_| CryptoError::Internal)?;
                dmp1.nnmod(&d, &p1, &mut ctx)
                    .map_err(|_| CryptoError::Internal)?;

                let mut dmq1 = BigNum::new().map_err(|_| CryptoError::Internal)?;
                dmq1.nnmod(&d, &q1, &mut ctx)
                    .map_err(|_| CryptoError::Internal)?;

                let mut iqmp = BigNum::new().map_err(|_| CryptoError::Internal)?;
                if iqmp.mod_inverse(&q, &p, &mut ctx).is_err() {
                    return Ok(None);
                }

                let n_pub = n.to_owned().unwrap();
                let e_pub = e.to_owned().unwrap();
                let pub_key = OsRsa::from_public_components(n_pub, e_pub)
                    .map_err(|_| CryptoError::Internal)?;

                let priv_key = OsRsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp)
                    .map_err(|_| CryptoError::Internal)?;

                if priv_key.check_key().is_err() {
                    return Ok(None);
                }

                Ok(Some(RsaPriv { priv_key, pub_key }))
            }

            fn generate(_rng: &mut impl Rng, exponent: u32) -> Result<Self::Private, CryptoError> {
                let bn_e = BigNum::from_u32(exponent).map_err(|_| CryptoError::Internal)?;
                let priv_key = OsRsa::generate_with_e($mod_size as u32 * 8, &bn_e)
                    .map_err(|_| CryptoError::Internal)?;
                let pub_key = OsRsa::from_public_components(
                    priv_key.n().to_owned().unwrap(),
                    priv_key.e().to_owned().unwrap(),
                )
                .map_err(|_| CryptoError::Internal)?;
                Ok(RsaPriv { priv_key, pub_key })
            }

            fn as_public(private: &Self::Private) -> &Self::Public {
                &private.pub_key
            }

            fn store_private(
                private: &Self::Private,
                out: &mut [u8; $prime_size],
            ) -> Result<(), CryptoError> {
                let p_bytes = private.priv_key.p().unwrap().to_vec();
                if p_bytes.len() > $prime_size {
                    return Err(CryptoError::Internal);
                }
                out.fill(0);
                out[$prime_size - p_bytes.len()..].copy_from_slice(&p_bytes);
                Ok(())
            }
        }

        impl RsaKey<$mod_size, $prime_size> for $name {
            fn exponent(public: &Self::Public) -> u32 {
                let e_bytes = public.e().to_vec();
                let mut e = 0u32;
                for &b in &e_bytes {
                    e = (e << 8) | (b as u32);
                }
                e
            }

            fn encrypt(
                _rng: &mut impl Rng,
                public: &Self::Public,
                scheme: RsaEncryptScheme<'_>,
                plaintext: &[u8],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<()>, CryptoError> {
                let mut buf = vec![0u8; $mod_size];
                match scheme {
                    RsaEncryptScheme::Raw => {
                        // Per TPM 2.0 Part 3 / CryptRsaEncrypt: `plaintext` may have extra
                        // leading zero bytes beyond `MOD_SIZE`, or be shorter than `MOD_SIZE`.
                        let trimmed = match plaintext.iter().position(|&b| b != 0) {
                            Some(i) => &plaintext[i..],
                            None => &[],
                        };
                        if trimmed.len() > $mod_size {
                            return Ok(None);
                        }
                        let mut em = [0u8; $mod_size];
                        em[$mod_size - trimmed.len()..].copy_from_slice(trimmed);
                        match public.public_encrypt(&em, &mut buf, Padding::NONE) {
                            Ok(len) => {
                                if len != $mod_size {
                                    return Err(CryptoError::Internal);
                                }
                            }
                            // `em >= n`
                            Err(_) => return Ok(None),
                        }
                    }
                    RsaEncryptScheme::Rsaes => {
                        if plaintext.len() > $mod_size - 11 {
                            return Ok(None);
                        }
                        let len = public
                            .public_encrypt(plaintext, &mut buf, Padding::PKCS1)
                            .map_err(|_| CryptoError::Internal)?;
                        if len != $mod_size {
                            return Err(CryptoError::Internal);
                        }
                    }
                    RsaEncryptScheme::Oaep { hash, .. } => {
                        let md = md(hash);
                        if plaintext.len() + 2 * md.size() + 2 > $mod_size {
                            return Ok(None);
                        }
                        let pkey =
                            PKey::from_rsa(public.clone()).map_err(|_| CryptoError::Internal)?;
                        let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
                        pctx.encrypt_init().map_err(|_| CryptoError::Internal)?;
                        pctx.set_rsa_padding(Padding::PKCS1_OAEP)
                            .map_err(|_| CryptoError::Internal)?;
                        pctx.set_rsa_oaep_md(md)
                            .map_err(|_| CryptoError::Internal)?;
                        pctx.set_rsa_mgf1_md(md)
                            .map_err(|_| CryptoError::Internal)?;
                        let label = scheme.label_bytes();
                        if !label.is_empty() {
                            pctx.set_rsa_oaep_label(label)
                                .map_err(|_| CryptoError::Internal)?;
                        }
                        let len = pctx
                            .encrypt(plaintext, Some(&mut buf))
                            .map_err(|_| CryptoError::Internal)?;
                        if len != $mod_size {
                            return Err(CryptoError::Internal);
                        }
                    }
                }
                out.copy_from_slice(&buf);
                Ok(Some(()))
            }

            fn decrypt(
                _rng: &mut impl Rng,
                private: &Self::Private,
                scheme: RsaEncryptScheme<'_>,
                ciphertext: &[u8; $mod_size],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<usize>, CryptoError> {
                let mut buf = vec![0u8; $mod_size];
                // Errors are `ciphertext >= n` or invalid padding.
                let res = match scheme {
                    RsaEncryptScheme::Raw => {
                        match private
                            .priv_key
                            .private_decrypt(ciphertext, &mut buf, Padding::NONE)
                        {
                            Ok(len) => {
                                if len != $mod_size {
                                    return Err(CryptoError::Internal);
                                }
                                Ok(len)
                            }
                            Err(e) => Err(e),
                        }
                    }
                    RsaEncryptScheme::Rsaes => private.priv_key.private_decrypt(
                        ciphertext,
                        &mut buf,
                        Padding::from_raw(RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING),
                    ),
                    RsaEncryptScheme::Oaep { hash, .. } => {
                        let md = md(hash);
                        let pkey = PKey::from_rsa(private.priv_key.clone())
                            .map_err(|_| CryptoError::Internal)?;
                        let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
                        pctx.decrypt_init().map_err(|_| CryptoError::Internal)?;
                        pctx.set_rsa_padding(Padding::PKCS1_OAEP)
                            .map_err(|_| CryptoError::Internal)?;
                        pctx.set_rsa_oaep_md(md)
                            .map_err(|_| CryptoError::Internal)?;
                        pctx.set_rsa_mgf1_md(md)
                            .map_err(|_| CryptoError::Internal)?;
                        let label = scheme.label_bytes();
                        if !label.is_empty() {
                            pctx.set_rsa_oaep_label(label)
                                .map_err(|_| CryptoError::Internal)?;
                        }
                        pctx.decrypt(ciphertext, Some(&mut buf))
                    }
                };
                let res = match res {
                    Ok(len) if len <= $mod_size => {
                        out[..len].copy_from_slice(&buf[..len]);
                        Ok(Some(len))
                    }
                    Ok(_) => Err(CryptoError::Internal),
                    Err(_) => Ok(None),
                };
                buf.fill(0);
                res
            }

            fn sign(
                _rng: &mut impl Rng,
                private: &Self::Private,
                scheme: RsaSigScheme,
                digest: TpmtHa<'_>,
                out: &mut [u8; $mod_size],
            ) -> Result<(), CryptoError> {
                let md = md(digest.hash_alg());
                let pkey =
                    PKey::from_rsa(private.priv_key.clone()).map_err(|_| CryptoError::Internal)?;
                let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
                pctx.sign_init().map_err(|_| CryptoError::Internal)?;
                match scheme {
                    RsaSigScheme::Rsassa => {
                        pctx.set_rsa_padding(Padding::PKCS1)
                            .map_err(|_| CryptoError::Internal)?;
                    }
                    RsaSigScheme::Rsapss => {
                        // TPM 2.0 PssEncode: the largest salt up to the digest size.
                        let Some(max_salt) = ($mod_size as usize).checked_sub(md.size() + 2) else {
                            return Err(CryptoError::Unsupported);
                        };
                        let salt_len = max_salt.min(md.size());
                        pctx.set_rsa_padding(Padding::PKCS1_PSS)
                            .map_err(|_| CryptoError::Internal)?;
                        pctx.set_rsa_mgf1_md(md)
                            .map_err(|_| CryptoError::Internal)?;
                        pctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_len as i32))
                            .map_err(|_| CryptoError::Internal)?;
                    }
                }
                pctx.set_signature_md(md)
                    .map_err(|_| CryptoError::Internal)?;
                let len = pctx
                    .sign(digest.digest(), Some(out))
                    .map_err(|_| CryptoError::Internal)?;
                if len != $mod_size {
                    return Err(CryptoError::Internal);
                }
                Ok(())
            }

            fn verify(
                public: &Self::Public,
                scheme: RsaSigScheme,
                digest: TpmtHa<'_>,
                sig: &[u8; $mod_size],
            ) -> Result<bool, CryptoError> {
                let md = md(digest.hash_alg());
                let pkey = PKey::from_rsa(public.clone()).map_err(|_| CryptoError::Internal)?;
                let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
                pctx.verify_init().map_err(|_| CryptoError::Internal)?;
                match scheme {
                    RsaSigScheme::Rsassa => {
                        pctx.set_rsa_padding(Padding::PKCS1)
                            .map_err(|_| CryptoError::Internal)?;
                    }
                    RsaSigScheme::Rsapss => {
                        // TPM 2.0 PssDecode: accept any salt length.
                        pctx.set_rsa_padding(Padding::PKCS1_PSS)
                            .map_err(|_| CryptoError::Internal)?;
                        pctx.set_rsa_mgf1_md(md)
                            .map_err(|_| CryptoError::Internal)?;
                        pctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(RSA_PSS_SALTLEN_AUTO))
                            .map_err(|_| CryptoError::Internal)?;
                    }
                }
                pctx.set_signature_md(md)
                    .map_err(|_| CryptoError::Internal)?;
                // Invalid signatures (including `sig >= n`) are errors.
                Ok(pctx.verify(digest.digest(), sig).unwrap_or(false))
            }
        }
    };
}
impl_rsa!(Rsa1024, 128, 64);
impl_rsa!(Rsa2048, 256, 128);
impl_rsa!(Rsa3072, 384, 192);
impl_rsa!(Rsa4096, 512, 256);

impl Rsa for super::OpensslBackend {
    type Rsa1024 = Rsa1024;
    type Rsa2048 = Rsa2048;
    type Rsa3072 = Rsa3072;
    type Rsa4096 = Rsa4096;
}
