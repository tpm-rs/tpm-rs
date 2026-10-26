//! RSA public/private keys and encryption/decryption operations.

use core::ffi::CStr;

use crate::TpmiAlgHash;
#[cfg(feature = "rsa")]
use crate::{TpmtRsaDecrypt, TpmtRsaScheme};

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

#[cfg(feature = "rsa")]
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

#[cfg(feature = "rsa")]
mod keys {
    use super::{
        super::{
            CryptoError, Rng,
            backend::{AsymmetricKey, Rsa, RsaKey},
            left_pad_be, match_rsa_bits,
        },
        RsaEncryptScheme,
    };
    use crate::{Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmiRsaKeyBits};

    /// Scratch buffer large enough to hold the modulus, ciphertext, or
    /// decrypted plaintext of any enabled RSA key size
    /// ([`TpmiRsaKeyBits::MAX_PUB_KEY_BYTES`]).
    pub type RsaModulusBuffer = [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];

    /// Scratch buffer large enough to hold the secret prime factor `p` of any
    /// enabled RSA key size ([`TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES`]).
    pub type RsaPrimeBuffer = [u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];

    /// Normalizes a TPM public exponent (`0` defaults to `65537`), returning
    /// `None` if `< 3` or even.
    const fn normalize_exponent(exponent: u32) -> Option<u32> {
        let e = if exponent == 0 { 65537 } else { exponent };
        if e >= 3 && e % 2 == 1 { Some(e) } else { None }
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
        Rsa1024(<R::Rsa1024 as AsymmetricKey<128, 64, u32>>::Public),
        #[cfg(feature = "rsa2048")]
        Rsa2048(<R::Rsa2048 as AsymmetricKey<256, 128, u32>>::Public),
        #[cfg(feature = "rsa3072")]
        Rsa3072(<R::Rsa3072 as AsymmetricKey<384, 192, u32>>::Public),
        #[cfg(feature = "rsa4096")]
        Rsa4096(<R::Rsa4096 as AsymmetricKey<512, 256, u32>>::Public),
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
        /// for [`RsaEncryptScheme::Rsaes`] unless the `rsaes`
        /// [crate feature](crate#algorithm-feature-flags) is enabled.
        pub fn encrypt<'a>(
            &self,
            rng: &mut impl Rng,
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
                    match R::$Alg::encrypt(rng, k, scheme, plaintext, buf)? {
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
        Rsa1024(<R::Rsa1024 as AsymmetricKey<128, 64, u32>>::Private),
        #[cfg(feature = "rsa2048")]
        Rsa2048(<R::Rsa2048 as AsymmetricKey<256, 128, u32>>::Private),
        #[cfg(feature = "rsa3072")]
        Rsa3072(<R::Rsa3072 as AsymmetricKey<384, 192, u32>>::Private),
        #[cfg(feature = "rsa4096")]
        Rsa4096(<R::Rsa4096 as AsymmetricKey<512, 256, u32>>::Private),
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
                    Ok(R::$Alg::load_private(pub_k, &p)?.map(Self::$Alg))
                },
            })
        }

        /// Generates a new RSA keypair from `rng` (`exponent == 0` defaults to
        /// `65537`).
        ///
        /// Returns `Err(`[`CryptoError::Unsupported`]`)` if `bits` or
        /// `exponent` is unsupported.
        pub fn generate(
            rng: &mut impl Rng,
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
        pub fn prime_p<'a>(
            &self,
            out: &'a mut [u8],
        ) -> Result<Tpm2bPrivateKeyRsa<'a>, CryptoError> {
            match_rsa_bits!(match self {
                Self::$Alg(k) => {
                    let Some(buf) = out.first_chunk_mut() else {
                        return Err(CryptoError::Internal);
                    };
                    R::$Alg::store_private(k, buf)?;
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
        /// unless the `rsaes` [crate feature](crate#algorithm-feature-flags) is
        /// enabled.
        pub fn decrypt<'a>(
            &self,
            rng: &mut impl Rng,
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
                    match R::$Alg::decrypt(rng, k, scheme, ct, buf)? {
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
}

#[cfg(feature = "rsa")]
pub use keys::*;
