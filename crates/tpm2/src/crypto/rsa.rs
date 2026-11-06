//! RSA public/private keys and encryption/decryption operations.

use core::ffi::CStr;

use super::{
    CryptoError, SignatureBuffer,
    backend::{PrivateKey, Rsa, RsaKey},
    left_pad_be, match_rsa_bits,
};
use crate::{
    Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmiAlgHash, TpmiRsaKeyBits, TpmtRsaDecrypt,
    TpmtRsaScheme, TpmtSigScheme, TpmtSignature,
};

/// Encryption and decryption schemes for RSA operations (`TPM_ALG_NULL`,
/// `TPM_ALG_RSAES`, and `TPM_ALG_OAEP`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RsaEncryptScheme<'a> {
    /// Raw modular exponentiation (`TPM_ALG_NULL`).
    Raw,
    /// `RSAES-PKCS1-v1_5` (`TPM_ALG_RSAES`).
    Rsaes,
    /// `RSAES-OAEP` (`TPM_ALG_OAEP`) with digest algorithm `hash` and an
    /// optional `label`.
    ///
    /// `None` means no label (an empty `L`). `Some(c)` uses
    /// `c.to_bytes_with_nul()` as `L`: per TPM 2.0 Part 3 (`TPM2_RSA_Encrypt`),
    /// the terminating zero octet is part of the label. Labels with embedded
    /// zero bytes aren't supported: "Specifications before version 1.54 stated
    /// that label is truncated after the first zero octet. Applications should
    /// not include embedded zero bytes for compatibility."
    Oaep {
        hash: TpmiAlgHash,
        label: Option<&'a CStr>,
    },
}

impl<'a> RsaEncryptScheme<'a> {
    /// Returns the OAEP label `L`: `label.to_bytes_with_nul()`, or empty if
    /// there is no label (or `self` is not [`Oaep`](Self::Oaep)).
    pub const fn label_bytes(&self) -> &'a [u8] {
        match self {
            Self::Oaep {
                label: Some(label), ..
            } => label.to_bytes_with_nul(),
            _ => &[],
        }
    }
}

impl<'a> RsaEncryptScheme<'a> {
    /// Converts a [`TpmtRsaDecrypt`] scheme (from `TPM2_RSA_Encrypt` or
    /// `TPM2_RSA_Decrypt`) and label into an [`RsaEncryptScheme`].
    ///
    /// Per TPM 2.0 Part 3 (`CryptRsaEncrypt` / `CryptRsaDecrypt`), `label` is
    /// only used by `TPM_ALG_OAEP` and ignored by `TPM_ALG_NULL` and
    /// `TPM_ALG_RSAES`. Callers convert a `TPM2B_DATA` label as follows: empty
    /// is `None`, otherwise [`CStr::from_bytes_with_nul`] (a failure is
    /// `TPM_RC_VALUE`). See [`RsaEncryptScheme::Oaep`].
    pub const fn from_decrypt(scheme: Option<TpmtRsaDecrypt>, label: Option<&'a CStr>) -> Self {
        match scheme {
            None => Self::Raw,
            #[cfg(feature = "rsaes")]
            Some(TpmtRsaDecrypt::Rsaes) => Self::Rsaes,
            Some(TpmtRsaDecrypt::Oaep(hash)) => Self::Oaep { hash, label },
        }
    }

    /// Converts an object's [`TpmtRsaScheme`] and label into an
    /// [`RsaEncryptScheme`], returning `None` for signature-only schemes
    /// (`RSASSA`, `RSAPSS`).
    ///
    /// `label` is handled as in [`from_decrypt`](Self::from_decrypt).
    pub const fn from_tpm(scheme: Option<TpmtRsaScheme>, label: Option<&'a CStr>) -> Option<Self> {
        match scheme {
            None => Some(Self::Raw),
            #[cfg(feature = "rsaes")]
            Some(TpmtRsaScheme::Rsaes) => Some(Self::Rsaes),
            Some(TpmtRsaScheme::Oaep(hash)) => Some(Self::Oaep { hash, label }),
            #[cfg(feature = "rsassa")]
            Some(TpmtRsaScheme::Rsassa(_)) => None,
            #[cfg(feature = "rsapss")]
            Some(TpmtRsaScheme::Rsapss(_)) => None,
        }
    }
}

/// Scratch buffer large enough to hold the modulus, ciphertext, or
/// decrypted plaintext of any enabled RSA key size
/// ([`TpmiRsaKeyBits::MAX_PUB_KEY_BYTES`]).
pub type RsaModulusBuffer = [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];

/// Scratch buffer large enough to hold the secret prime factor `p` of any
/// enabled RSA key size ([`TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES`]).
pub type RsaPrimeBuffer = [u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];

/// Scratch buffer large enough to hold the CRT form (`p`, `q`, `dP`, `dQ`,
/// `qInv`) of any enabled RSA key size ([`RSA_PRIVATE_SIZE`](crate::limits::RSA_PRIVATE_SIZE)).
pub type RsaCrtBuffer = [u8; crate::limits::RSA_PRIVATE_SIZE];

/// Normalizes a TPM public exponent (`0` defaults to `65537`), returning
/// `None` if `< 3` or even.
const fn normalize_exponent(exponent: u32) -> Option<u32> {
    let e = if exponent == 0 { 65537 } else { exponent };
    if e >= 3 && e % 2 == 1 { Some(e) } else { None }
}

/// Converts a `TPM_ALG_NULL` plaintext (a big-endian integer, which may be
/// shorter than `N` bytes or have extra leading zero bytes, per TPM 2.0
/// Part 3 `CryptRsaEncrypt`) into an `N`-byte big-endian integer, returning
/// `None` if it doesn't fit.
fn raw_input<const N: usize>(plaintext: &[u8]) -> Option<[u8; N]> {
    let start = plaintext
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(plaintext.len());
    let m = &plaintext[start..];
    let mut out = [0u8; N];
    out.get_mut(N.checked_sub(m.len())?..)?.copy_from_slice(m);
    Some(out)
}

/// Returns `Err(`[`CryptoError::Unsupported`]`)` if `scheme`'s
/// [crate feature](crate#algorithm-feature-flags) is disabled.
const fn check_scheme(scheme: RsaEncryptScheme<'_>) -> Result<(), CryptoError> {
    match scheme {
        #[cfg(not(feature = "rsaes"))]
        RsaEncryptScheme::Rsaes => Err(CryptoError::Unsupported),
        _ => Ok(()),
    }
}

/// Validated RSA public key for a runtime-selected key size.
///
/// While an [`Rsa`] backend can implement whichever key sizes it wants, the
/// variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum RsaPublicKey<R: Rsa> {
    #[cfg(feature = "rsa1024")]
    Rsa1024(<R::Rsa1024 as PrivateKey<128, 64, R::Rng, u32>>::PublicKey),
    #[cfg(feature = "rsa2048")]
    Rsa2048(<R::Rsa2048 as PrivateKey<256, 128, R::Rng, u32>>::PublicKey),
    #[cfg(feature = "rsa3072")]
    Rsa3072(<R::Rsa3072 as PrivateKey<384, 192, R::Rng, u32>>::PublicKey),
    #[cfg(feature = "rsa4096")]
    Rsa4096(<R::Rsa4096 as PrivateKey<512, 256, R::Rng, u32>>::PublicKey),
}

impl<R: Rsa> RsaPublicKey<R> {
    /// Validates and loads an RSA public key (`exponent == 0` defaults to
    /// `65537`).
    ///
    /// Returns `Ok(None)` if `exponent` or `modulus` is invalid for `bits`,
    /// or `Err(`[`CryptoError::Unsupported`]`)` if `bits` (or `exponent`)
    /// is unsupported by the backend.
    pub fn load(
        bits: TpmiRsaKeyBits,
        exponent: u32,
        modulus: Tpm2bPublicKeyRsa<'_>,
    ) -> Result<Option<Self>, CryptoError> {
        let Some(exponent) = normalize_exponent(exponent) else {
            return Ok(None);
        };
        match_rsa_bits!(match bits {
            TpmiRsaKeyBits::$Alg => {
                let Some(m) = left_pad_be(modulus.as_slice()) else {
                    return Ok(None);
                };
                Ok(R::$Alg::load_public(exponent, &m)?.map(Self::$Alg))
            },
        })
    }

    /// Returns the modulus size in bits.
    pub const fn bits(&self) -> TpmiRsaKeyBits {
        match_rsa_bits!(match self {
            Self::$Alg(_) => { TpmiRsaKeyBits::$Alg },
        })
    }

    /// Returns the normalized public exponent `e` (`>= 3` and odd).
    pub fn exponent(&self) -> u32 {
        match_rsa_bits!(match self {
            Self::$Alg(k) => { R::$Alg::exponent(k) },
        })
    }

    /// Writes the big-endian public modulus `n` into `out` and returns it
    /// as a [`Tpm2bPublicKeyRsa`].
    ///
    /// `out` must be at least `self.bits().as_u16() / 8` bytes (e.g. an
    /// [`RsaModulusBuffer`]), or [`CryptoError::Internal`] is returned.
    pub fn modulus<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        match_rsa_bits!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                R::$Alg::store_public(k, buf)?;
                Tpm2bPublicKeyRsa::new(buf).ok_or(CryptoError::Internal)
            },
        })
    }

    /// Encrypts `plaintext` under this key using `scheme`
    /// (`TPM2_RSA_Encrypt`, `TPM2_MakeCredential`, `TPM2_Duplicate`),
    /// writing the ciphertext into `out`.
    ///
    /// `out` must be at least `self.bits().as_u16() / 8` bytes (e.g. an
    /// [`RsaModulusBuffer`]). Returns `Ok(None)` if `plaintext` is invalid
    /// for the key or `scheme` (e.g. too long, or `>= modulus` for
    /// [`RsaEncryptScheme::Raw`]), or `Err(`[`CryptoError::Unsupported`]`)`
    /// for [`RsaEncryptScheme::Rsaes`] if the `rsaes`
    /// [crate feature](crate#algorithm-feature-flags) is disabled or the
    /// backend doesn't support it.
    pub fn encrypt<'a>(
        &self,
        rng: &mut R::Rng,
        scheme: RsaEncryptScheme<'_>,
        plaintext: &[u8],
        out: &'a mut [u8],
    ) -> Result<Option<Tpm2bPublicKeyRsa<'a>>, CryptoError> {
        check_scheme(scheme)?;
        match_rsa_bits!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                let res = match scheme {
                    RsaEncryptScheme::Raw => {
                        let Some(m) = raw_input(plaintext) else {
                            return Ok(None);
                        };
                        R::$Alg::raw_encrypt(k, &m, buf)?
                    }
                    RsaEncryptScheme::Rsaes => R::$Alg::rsaes_encrypt(k, rng, plaintext, buf)?,
                    RsaEncryptScheme::Oaep { hash, .. } => {
                        let label = scheme.label_bytes();
                        R::$Alg::oaep_encrypt(k, rng, hash, label, plaintext, buf)?
                    }
                };
                match res {
                    Some(()) => {
                        Tpm2bPublicKeyRsa::new(buf).map(Some).ok_or(CryptoError::Internal)
                    }
                    None => Ok(None),
                }
            },
        })
    }
}

/// Validated RSA private key for a runtime-selected key size.
///
/// While an [`Rsa`] backend can implement whichever key sizes it wants, the
/// variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum RsaPrivateKey<R: Rsa> {
    #[cfg(feature = "rsa1024")]
    Rsa1024(R::Rsa1024),
    #[cfg(feature = "rsa2048")]
    Rsa2048(R::Rsa2048),
    #[cfg(feature = "rsa3072")]
    Rsa3072(R::Rsa3072),
    #[cfg(feature = "rsa4096")]
    Rsa4096(R::Rsa4096),
}

impl<R: Rsa> RsaPrivateKey<R> {
    /// Reconstructs and validates an RSA private key from `public` and its
    /// first secret prime factor `prime_p`.
    ///
    /// Returns `Ok(None)` if `prime_p` does not form a valid private key
    /// for `public`.
    pub fn load(
        public: RsaPublicKey<R>,
        prime_p: Tpm2bPrivateKeyRsa<'_>,
    ) -> Result<Option<Self>, CryptoError> {
        match_rsa_bits!(match public {
            RsaPublicKey::$Alg(pub_k) => {
                let Some(p) = left_pad_be(prime_p.as_slice()) else {
                    return Ok(None);
                };
                Ok(R::$Alg::load(pub_k, &p)?.map(Self::$Alg))
            },
        })
    }

    /// Generates a new RSA keypair from `rng` (`exponent == 0` defaults to
    /// `65537`).
    ///
    /// Returns `Err(`[`CryptoError::Unsupported`]`)` if `bits` or
    /// `exponent` is unsupported.
    pub fn generate(
        rng: &mut R::Rng,
        bits: TpmiRsaKeyBits,
        exponent: u32,
    ) -> Result<Self, CryptoError> {
        let Some(exponent) = normalize_exponent(exponent) else {
            return Err(CryptoError::Unsupported);
        };
        match_rsa_bits!(match bits {
            TpmiRsaKeyBits::$Alg => {
                Ok(Self::$Alg(R::$Alg::generate(rng, exponent)?))
            },
        })
    }

    /// Returns the modulus size in bits.
    pub const fn bits(&self) -> TpmiRsaKeyBits {
        match_rsa_bits!(match self {
            Self::$Alg(_) => { TpmiRsaKeyBits::$Alg },
        })
    }

    /// Returns the normalized public exponent `e` (`>= 3` and odd).
    pub fn exponent(&self) -> u32 {
        match_rsa_bits!(match self {
            Self::$Alg(k) => { R::$Alg::exponent(R::$Alg::as_public(k)) },
        })
    }

    /// Writes the big-endian public modulus `n` into `out` and returns it
    /// as a [`Tpm2bPublicKeyRsa`].
    pub fn modulus<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        match_rsa_bits!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                R::$Alg::store_public(R::$Alg::as_public(k), buf)?;
                Tpm2bPublicKeyRsa::new(buf).ok_or(CryptoError::Internal)
            },
        })
    }

    /// Writes the first secret prime factor `p` (big-endian) into `out` and
    /// returns it as a [`Tpm2bPrivateKeyRsa`].
    ///
    /// `out` must be at least `(self.bits().as_u16() / 8) / 2` bytes (e.g.
    /// an [`RsaPrimeBuffer`]), or [`CryptoError::Internal`] is returned.
    pub fn prime_p<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bPrivateKeyRsa<'a>, CryptoError> {
        match_rsa_bits!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                R::$Alg::store(k, buf)?;
                Tpm2bPrivateKeyRsa::new(buf).ok_or(CryptoError::Internal)
            },
        })
    }

    /// Writes the Chinese Remainder Theorem (CRT) form of this key
    /// ([`RsaKey::store_crt`]: `p`, `q`, `dP`, `dQ` and `qInv`, where `p` is the
    /// larger prime, each big-endian and left-padded to the prime size) into
    /// `out` and returns it as a [`Tpm2bPrivateKeyRsa`].
    ///
    /// This is a tpm-rs extension: the TPM stores this form as the sensitive
    /// value of RSA keys with *fixedTPM* parents (the TCG reference
    /// implementation's `CRT_FORMAT_RSA`). The first component is a prime
    /// factor, so [`RsaPrivateKey::load`] accepts the first
    /// `self.bits().as_u16() / 16` bytes of the result.
    ///
    /// `out` must be at least `5 * (self.bits().as_u16() / 16)` bytes (e.g. an
    /// [`RsaCrtBuffer`]), or [`CryptoError::Internal`] is returned.
    pub fn crt<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bPrivateKeyRsa<'a>, CryptoError> {
        match_rsa_bits!(match self {
            Self::$Alg(k) => {
                let mut crt = [[0u8; _]; 5];
                R::$Alg::store_crt(k, &mut crt)?;
                let len = crt.as_flattened().len();
                let Some(buf) = out.get_mut(..len) else {
                    return Err(CryptoError::Internal);
                };
                buf.copy_from_slice(crt.as_flattened());
                Tpm2bPrivateKeyRsa::new(buf).ok_or(CryptoError::Internal)
            },
        })
    }

    /// Decrypts `ciphertext` under this key using `scheme`
    /// (`TPM2_RSA_Decrypt`, `TPM2_ActivateCredential`, `TPM2_Import`),
    /// writing the recovered plaintext into `out`.
    ///
    /// `rng` is provided for side-channel blinding. `out` must be at least
    /// `self.bits().as_u16() / 8` bytes (e.g. an [`RsaModulusBuffer`]).
    /// Returns `Ok(None)` if `ciphertext.len()` does not match the modulus
    /// size, `ciphertext >= modulus`, or the padding is invalid, or
    /// `Err(`[`CryptoError::Unsupported`]`)` for [`RsaEncryptScheme::Rsaes`]
    /// if the `rsaes` [crate feature](crate#algorithm-feature-flags) is
    /// disabled or the backend doesn't support it.
    pub fn decrypt<'a>(
        &self,
        rng: &mut R::Rng,
        scheme: RsaEncryptScheme<'_>,
        ciphertext: &[u8],
        out: &'a mut [u8],
    ) -> Result<Option<Tpm2bPublicKeyRsa<'a>>, CryptoError> {
        check_scheme(scheme)?;
        match_rsa_bits!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                let Ok(ct) = ciphertext.try_into() else {
                    return Ok(None);
                };
                let res = match scheme {
                    RsaEncryptScheme::Raw => {
                        R::$Alg::raw_decrypt(k, rng, ct, buf)?.map(|()| buf.len())
                    }
                    RsaEncryptScheme::Rsaes => R::$Alg::rsaes_decrypt(k, rng, ct, buf)?,
                    RsaEncryptScheme::Oaep { hash, .. } => {
                        let label = scheme.label_bytes();
                        R::$Alg::oaep_decrypt(k, rng, hash, label, ct, buf)?
                    }
                };
                match res {
                    Some(len) => {
                        let msg = buf.get(..len).ok_or(CryptoError::Internal)?;
                        Tpm2bPublicKeyRsa::new(msg).map(Some).ok_or(CryptoError::Internal)
                    }
                    None => Ok(None),
                }
            },
        })
    }
}

impl<R: Rsa> RsaPrivateKey<R> {
    /// Signs `digest` with this key using `scheme` (`RSASSA` or `RSAPSS`;
    /// `TPM2_Sign`), writing the signature into `out` and returning it as a
    /// [`TpmtSignature`].
    ///
    /// Returns `Err(`[`CryptoError::Unsupported`]`)` for any other scheme, or
    /// `Err(`[`CryptoError::Internal`]`)` if `digest.len()` doesn't match
    /// `scheme`'s hash algorithm.
    pub fn sign<'a>(
        &self,
        rng: &mut R::Rng,
        scheme: TpmtSigScheme,
        digest: &[u8],
        out: &'a mut SignatureBuffer,
    ) -> Result<TpmtSignature<'a>, CryptoError> {
        match scheme {
            #[cfg(feature = "rsassa")]
            TpmtSigScheme::Rsassa(hash) => {
                let sig = self.sign_digest(rng, false, hash, digest, out)?;
                Ok(TpmtSignature::Rsassa(crate::TpmsSignatureRsa { hash, sig }))
            }
            #[cfg(feature = "rsapss")]
            TpmtSigScheme::Rsapss(hash) => {
                let sig = self.sign_digest(rng, true, hash, digest, out)?;
                Ok(TpmtSignature::Rsapss(crate::TpmsSignatureRsa { hash, sig }))
            }
            _ => {
                let _ = (rng, digest, out);
                Err(CryptoError::Unsupported)
            }
        }
    }

    #[cfg(any(feature = "rsassa", feature = "rsapss"))]
    fn sign_digest<'a>(
        &self,
        rng: &mut R::Rng,
        pss: bool,
        hash: TpmiAlgHash,
        digest: &[u8],
        out: &'a mut SignatureBuffer,
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        let digest = crate::TpmtHa::new(hash, digest).ok_or(CryptoError::Internal)?;
        match_rsa_bits!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                if pss {
                    R::$Alg::rsapss_sign(k, rng, digest, buf)?;
                } else {
                    R::$Alg::rsassa_sign(k, rng, digest, buf)?;
                }
                Tpm2bPublicKeyRsa::new(buf).ok_or(CryptoError::Internal)
            },
        })
    }
}

impl<R: Rsa> RsaPublicKey<R> {
    /// Verifies `signature` (`RSASSA` or `RSAPSS`) over `digest` with this key
    /// (`TPM2_VerifySignature`).
    ///
    /// Returns `Ok(false)` if `digest.len()` doesn't match the signature's hash
    /// algorithm, the signature size doesn't match the key, or verification
    /// fails, and `Err(`[`CryptoError::Unsupported`]`)` for any other scheme.
    pub fn verify(&self, digest: &[u8], signature: TpmtSignature<'_>) -> Result<bool, CryptoError> {
        match signature {
            #[cfg(feature = "rsassa")]
            TpmtSignature::Rsassa(s) => self.verify_digest(false, s, digest),
            #[cfg(feature = "rsapss")]
            TpmtSignature::Rsapss(s) => self.verify_digest(true, s, digest),
            _ => {
                let _ = digest;
                Err(CryptoError::Unsupported)
            }
        }
    }

    #[cfg(any(feature = "rsassa", feature = "rsapss"))]
    fn verify_digest(
        &self,
        pss: bool,
        signature: crate::TpmsSignatureRsa<'_>,
        digest: &[u8],
    ) -> Result<bool, CryptoError> {
        let Some(digest) = crate::TpmtHa::new(signature.hash, digest) else {
            return Ok(false);
        };
        match_rsa_bits!(match self {
            Self::$Alg(k) => {
                let Ok(sig) = signature.sig.as_slice().try_into() else {
                    return Ok(false);
                };
                if pss {
                    R::$Alg::rsapss_verify(k, digest, sig)
                } else {
                    R::$Alg::rsassa_verify(k, digest, sig)
                }
            },
        })
    }
}
