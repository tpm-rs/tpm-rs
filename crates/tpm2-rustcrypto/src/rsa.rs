use alloc::vec::Vec;

use rsa::{
    BoxedUint, Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey,
    hazmat::{rsa_decrypt_and_check, rsa_encrypt},
    traits::{PrivateKeyParts, PublicKeyParts},
};
use sha2::digest::Digest as _;
use tpm2::{
    TpmiAlgHash, TpmtHa,
    crypto::{
        CryptoError, Rng, RsaEncryptScheme,
        backend::{AsymmetricKey, RsaKey, RsaSigScheme},
    },
};

/// RSA key wrapper
pub struct RsaKeyWrapper<const MOD_SIZE: usize, const PRIME_SIZE: usize>;

macro_rules! with_digest {
    ($alg:expr, |$d:ident| $body:expr) => {
        match $alg {
            TpmiAlgHash::Sha1 => {
                type $d = sha1::Sha1;
                $body
            }
            TpmiAlgHash::Sha256 => {
                type $d = sha2::Sha256;
                $body
            }
            TpmiAlgHash::Sha384 => {
                type $d = sha2::Sha384;
                $body
            }
            TpmiAlgHash::Sha512 => {
                type $d = sha2::Sha512;
                $body
            }
            TpmiAlgHash::Sm3_256 => {
                type $d = sm3::Sm3;
                $body
            }
            TpmiAlgHash::Sha3_256 => {
                type $d = sha3::Sha3_256;
                $body
            }
            TpmiAlgHash::Sha3_384 => {
                type $d = sha3::Sha3_384;
                $body
            }
            TpmiAlgHash::Sha3_512 => {
                type $d = sha3::Sha3_512;
                $body
            }
        }
    };
}

/// DER `DigestInfo` prefix for `RSASSA-PKCS1-v1_5`, matching `MakeDerTag` in
/// the TPM 2.0 reference implementation.
fn digest_info_prefix(alg: TpmiAlgHash) -> &'static [u8] {
    match alg {
        TpmiAlgHash::Sha1 => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        TpmiAlgHash::Sha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        TpmiAlgHash::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        TpmiAlgHash::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        TpmiAlgHash::Sm3_256 => &[
            0x30, 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11,
            0x05, 0x00, 0x04, 0x20,
        ],
        TpmiAlgHash::Sha3_256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x08, 0x05, 0x00, 0x04, 0x20,
        ],
        TpmiAlgHash::Sha3_384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x09, 0x05, 0x00, 0x04, 0x30,
        ],
        TpmiAlgHash::Sha3_512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x0a, 0x05, 0x00, 0x04, 0x40,
        ],
    }
}

/// Builds the `rsa` crate's OAEP padding for `D` and the TPM label `L` (`label_bytes`).
fn oaep<D: sha2::digest::Digest + sha2::digest::FixedOutputReset>(label_bytes: &[u8]) -> Oaep<D> {
    if label_bytes.is_empty() {
        Oaep::<D>::new()
    } else {
        Oaep::<D>::new_with_label(label_bytes)
    }
}

/// Writes the big-endian `value` into `out`, left-padded with zeros.
fn write_be<const N: usize>(value: &BoxedUint, out: &mut [u8; N]) -> Result<(), CryptoError> {
    let bytes = value.to_be_bytes_trimmed_vartime();
    if bytes.len() > N {
        return Err(CryptoError::Internal);
    }
    out.fill(0);
    out[N - bytes.len()..].copy_from_slice(&bytes);
    Ok(())
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> AsymmetricKey<MOD_SIZE, PRIME_SIZE, u32>
    for RsaKeyWrapper<MOD_SIZE, PRIME_SIZE>
{
    type Public = RsaPublicKey;
    type Private = RsaPrivateKey;

    fn generate(rng: &mut impl Rng, exponent: u32) -> Result<Self::Private, CryptoError> {
        let mut wrapper = crate::RngWrapper(rng);
        RsaPrivateKey::new_with_exp(&mut wrapper, MOD_SIZE * 8, BoxedUint::from(exponent))
            .map_err(|_| CryptoError::Internal)
    }

    fn load_public(
        exponent: u32,
        modulus: &[u8; MOD_SIZE],
    ) -> Result<Option<Self::Public>, CryptoError> {
        let n = BoxedUint::from_be_slice_vartime(modulus);
        let e = BoxedUint::from(exponent);
        Ok(RsaPublicKey::new(n, e).ok())
    }

    fn store_public(public: &Self::Public, out: &mut [u8; MOD_SIZE]) -> Result<(), CryptoError> {
        write_be(public.n(), out)
    }

    fn load_private(
        public: Self::Public,
        prime_p: &[u8; PRIME_SIZE],
    ) -> Result<Option<Self::Private>, CryptoError> {
        let p = BoxedUint::from_be_slice_vartime(prime_p);
        if p <= BoxedUint::one() {
            return Ok(None);
        }
        let Some(q) = public.n().checked_div(&p).into_option() else {
            return Ok(None);
        };
        if q <= BoxedUint::one()
            || q.checked_mul(&p).into_option().as_ref() != Some(public.n().as_ref())
        {
            return Ok(None);
        }
        let e = public.e().clone();

        Ok(RsaPrivateKey::from_p_q(p, q, e).ok())
    }

    fn store_private(
        private: &Self::Private,
        out: &mut [u8; PRIME_SIZE],
    ) -> Result<(), CryptoError> {
        let primes = private.primes();
        if primes.is_empty() {
            return Err(CryptoError::Internal);
        }
        write_be(&primes[0], out)
    }

    fn as_public(private: &Self::Private) -> &Self::Public {
        let pub_key: &RsaPublicKey = private.as_ref();
        pub_key
    }
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> RsaKey<MOD_SIZE, PRIME_SIZE>
    for RsaKeyWrapper<MOD_SIZE, PRIME_SIZE>
{
    fn exponent(public: &Self::Public) -> u32 {
        let bytes = public.e().to_le_bytes();
        let mut arr = [0u8; 4];
        for (i, &b) in bytes.iter().take(4).enumerate() {
            arr[i] = b;
        }
        u32::from_le_bytes(arr)
    }

    fn encrypt(
        rng: &mut impl Rng,
        public: &Self::Public,
        scheme: RsaEncryptScheme<'_>,
        plaintext: &[u8],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let mut wrapper = crate::RngWrapper(rng);
        let ct = match scheme {
            RsaEncryptScheme::Raw => {
                let m = BoxedUint::from_be_slice_vartime(plaintext);
                if m >= public.n().as_ref() {
                    return Ok(None);
                }
                let c = rsa_encrypt(public, &m).map_err(|_| CryptoError::Internal)?;
                write_be(&c, out)?;
                return Ok(Some(()));
            }
            RsaEncryptScheme::Rsaes => public.encrypt(&mut wrapper, Pkcs1v15Encrypt, plaintext),
            RsaEncryptScheme::Oaep { hash, .. } => {
                let label_bytes = scheme.label_bytes();
                with_digest!(hash, |D| {
                    public.encrypt(&mut wrapper, oaep::<D>(label_bytes), plaintext)
                })
            }
        };
        match ct {
            Ok(ct) if ct.len() == MOD_SIZE => {
                out.copy_from_slice(&ct);
                Ok(Some(()))
            }
            Ok(_) => Err(CryptoError::Internal),
            Err(rsa::Error::MessageTooLong) => Ok(None),
            Err(_) => Err(CryptoError::Internal),
        }
    }

    fn decrypt(
        rng: &mut impl Rng,
        private: &Self::Private,
        scheme: RsaEncryptScheme<'_>,
        ciphertext: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        let mut wrapper = crate::RngWrapper(rng);
        let pt: Vec<u8> = match scheme {
            RsaEncryptScheme::Raw => {
                let Ok(c) = BoxedUint::from_be_slice(ciphertext, private.n_bits_precision()) else {
                    return Ok(None);
                };
                if c >= private.n().as_ref() {
                    return Ok(None);
                }
                let m = rsa_decrypt_and_check(private, Some(&mut wrapper), &c)
                    .map_err(|_| CryptoError::Internal)?;
                write_be(&m, out)?;
                return Ok(Some(MOD_SIZE));
            }
            RsaEncryptScheme::Rsaes => {
                match private.decrypt_blinded(&mut wrapper, Pkcs1v15Encrypt, ciphertext) {
                    Ok(pt) => pt,
                    Err(_) => return Ok(None),
                }
            }
            RsaEncryptScheme::Oaep { hash, .. } => {
                let label_bytes = scheme.label_bytes();
                let res = with_digest!(hash, |D| {
                    private.decrypt_blinded(&mut wrapper, oaep::<D>(label_bytes), ciphertext)
                });
                match res {
                    Ok(pt) => pt,
                    Err(_) => return Ok(None),
                }
            }
        };
        let dst = out.get_mut(..pt.len()).ok_or(CryptoError::Internal)?;
        dst.copy_from_slice(&pt);
        Ok(Some(pt.len()))
    }

    fn sign(
        rng: &mut impl Rng,
        private: &Self::Private,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError> {
        let mut wrapper = crate::RngWrapper(rng);
        let alg = digest.hash_alg();
        let hashed = digest.digest();
        let sig = match scheme {
            RsaSigScheme::Rsassa => {
                let padding = Pkcs1v15Sign {
                    hash_len: Some(hashed.len()),
                    prefix: digest_info_prefix(alg).into(),
                };
                private.sign_with_rng(&mut wrapper, padding, hashed)
            }
            RsaSigScheme::Rsapss => {
                // TPM 2.0 `PssEncode`: the largest salt up to the digest size.
                let em_len = (private.n().bits() as usize - 1).div_ceil(8);
                let max_salt = em_len.checked_sub(hashed.len() + 2);
                let salt_len = max_salt.ok_or(CryptoError::Unsupported)?.min(hashed.len());
                with_digest!(alg, |D| {
                    let padding = Pss::<D>::new_blinded_with_salt(salt_len);
                    private.sign_with_rng(&mut wrapper, padding, hashed)
                })
            }
        };
        let sig = sig.map_err(|_| CryptoError::Internal)?;
        if sig.len() != MOD_SIZE {
            return Err(CryptoError::Internal);
        }
        out.copy_from_slice(&sig);
        Ok(())
    }

    fn verify(
        public: &Self::Public,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError> {
        let alg = digest.hash_alg();
        let hashed = digest.digest();
        match scheme {
            RsaSigScheme::Rsassa => {
                let padding = Pkcs1v15Sign {
                    hash_len: Some(hashed.len()),
                    prefix: digest_info_prefix(alg).into(),
                };
                Ok(public.verify(padding, hashed, sig).is_ok())
            }
            RsaSigScheme::Rsapss => {
                if BoxedUint::from_be_slice_vartime(sig) >= public.n().as_ref() {
                    return Ok(false);
                }
                let res = with_digest!(alg, |D| {
                    let padding = Pss {
                        blinded: false,
                        digest: D::new(),
                        salt_len: None,
                    };
                    public.verify(padding, hashed, sig)
                });
                Ok(res.is_ok())
            }
        }
    }
}
