//! ML-DSA (FIPS 204) public and private keys.

use super::{
    CryptoError, SignatureBuffer,
    backend::{Mldsa, MldsaKey, PrivateKey},
    match_mldsa_parms,
};
use crate::{
    Tpm2b, Tpm2bPrivateKeyMldsa, Tpm2bPublicKeyMldsa, Tpm2bSignatureMldsa, TpmiMldsaParms,
    TpmtSignature,
};

/// Scratch buffer large enough to hold the encoded public key of any enabled
/// ML-DSA parameter set ([`TpmiMldsaParms::MAX_PUB_KEY_BYTES`]).
pub type MldsaPubKeyBuffer = [u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];

/// Scratch buffer holding a 32-byte ML-DSA private seed `ξ`.
pub type MldsaSeedBuffer = [u8; 32];

/// Validated ML-DSA public verification key for a runtime-selected parameter
/// set.
///
/// While an [`Mldsa`] backend can implement whichever parameter sets it wants,
/// the variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum MldsaPublicKey<M: Mldsa> {
    #[cfg(feature = "mldsa_44")]
    Mldsa44(<M::Mldsa44 as PrivateKey<1312, 32, M::Rng>>::PublicKey),
    #[cfg(feature = "mldsa_65")]
    Mldsa65(<M::Mldsa65 as PrivateKey<1952, 32, M::Rng>>::PublicKey),
    #[cfg(feature = "mldsa_87")]
    Mldsa87(<M::Mldsa87 as PrivateKey<2592, 32, M::Rng>>::PublicKey),
}

impl<M: Mldsa> MldsaPublicKey<M> {
    /// Validates and loads an ML-DSA public key for `parms`.
    ///
    /// Returns `Ok(None)` if `public.as_slice().len() != parms.pub_key_bytes()`
    /// or `public` is not a valid FIPS 204 public key encoding, and
    /// `Err(`[`CryptoError::Unsupported`]`)` if `parms` is unsupported by the
    /// backend.
    pub fn load(
        parms: TpmiMldsaParms,
        public: Tpm2bPublicKeyMldsa<'_>,
    ) -> Result<Option<Self>, CryptoError> {
        match_mldsa_parms!(match parms {
            TpmiMldsaParms::$Alg => {
                let Ok(pk) = public.as_slice().try_into() else {
                    return Ok(None);
                };
                Ok(M::$Alg::load_public((), pk)?.map(Self::$Alg))
            },
        })
    }

    /// Returns the ML-DSA parameter set identifier of this key.
    pub const fn parms(&self) -> TpmiMldsaParms {
        match_mldsa_parms!(match self {
            Self::$Alg(_) => { TpmiMldsaParms::$Alg },
        })
    }

    /// Writes the encoded FIPS 204 public key into `out` and returns it as a
    /// [`Tpm2bPublicKeyMldsa`].
    ///
    /// `out` must be at least `self.parms().pub_key_bytes()` bytes (e.g. an
    /// [`MldsaPubKeyBuffer`]), or [`CryptoError::Internal`] is returned.
    pub fn public<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bPublicKeyMldsa<'a>, CryptoError> {
        match_mldsa_parms!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                M::$Alg::store_public(k, buf)?;
                Tpm2bPublicKeyMldsa::new(buf).ok_or(CryptoError::Internal)
            },
        })
    }
}

/// Validated ML-DSA private signing key for a runtime-selected parameter set.
///
/// While an [`Mldsa`] backend can implement whichever parameter sets it wants,
/// the variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum MldsaPrivateKey<M: Mldsa> {
    #[cfg(feature = "mldsa_44")]
    Mldsa44(M::Mldsa44),
    #[cfg(feature = "mldsa_65")]
    Mldsa65(M::Mldsa65),
    #[cfg(feature = "mldsa_87")]
    Mldsa87(M::Mldsa87),
}

impl<M: Mldsa> MldsaPrivateKey<M> {
    /// Loads and validates an ML-DSA private key from `public` and 32-byte seed
    /// `seed`.
    ///
    /// Returns `Ok(None)` if `seed` does not expand to `public`.
    pub fn load(
        public: MldsaPublicKey<M>,
        seed: Tpm2bPrivateKeyMldsa<'_>,
    ) -> Result<Option<Self>, CryptoError> {
        match_mldsa_parms!(match public {
            MldsaPublicKey::$Alg(pub_k) => {
                Ok(M::$Alg::load(pub_k, seed.0)?.map(Self::$Alg))
            },
        })
    }

    /// Generates a new ML-DSA keypair for `parms` from `rng`.
    pub fn generate(rng: &mut M::Rng, parms: TpmiMldsaParms) -> Result<Self, CryptoError> {
        match_mldsa_parms!(match parms {
            TpmiMldsaParms::$Alg => {
                Ok(Self::$Alg(M::$Alg::generate(rng, ())?))
            },
        })
    }

    /// Returns the ML-DSA parameter set identifier of this key.
    pub const fn parms(&self) -> TpmiMldsaParms {
        match_mldsa_parms!(match self {
            Self::$Alg(_) => { TpmiMldsaParms::$Alg },
        })
    }

    /// Writes the encoded FIPS 204 public key into `out` and returns it as a
    /// [`Tpm2bPublicKeyMldsa`].
    pub fn public<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bPublicKeyMldsa<'a>, CryptoError> {
        match_mldsa_parms!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                M::$Alg::store_public(M::$Alg::as_public(k), buf)?;
                Tpm2bPublicKeyMldsa::new(buf).ok_or(CryptoError::Internal)
            },
        })
    }

    /// Writes the 32-byte FIPS 204 private seed `ξ` into `out` and returns it
    /// as a [`Tpm2bPrivateKeyMldsa`].
    ///
    /// `out` must be at least 32 bytes (e.g. an [`MldsaSeedBuffer`]), or
    /// [`CryptoError::Internal`] is returned.
    pub fn seed<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bPrivateKeyMldsa<'a>, CryptoError> {
        match_mldsa_parms!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                M::$Alg::store(k, buf)?;
                Ok(Tpm2b(buf))
            },
        })
    }
}

impl<M: Mldsa> MldsaPrivateKey<M> {
    /// Signs a 64-byte external message representative `mu`
    /// ([`TpmiMldsaParms::MU_BYTES`]) with this key (`TPM2_Sign` /
    /// `TPM2_SignDigest` with `TPM_ALG_MLDSA`), writing the signature into
    /// `out` and returning it as a [`TpmtSignature`].
    ///
    /// Returns `Err(`[`CryptoError::Internal`]`)` if `mu` isn't 64 bytes.
    pub fn sign_mu<'a>(
        &self,
        rng: &mut M::Rng,
        mu: &[u8],
        out: &'a mut SignatureBuffer,
    ) -> Result<TpmtSignature<'a>, CryptoError> {
        let Ok(mu) = mu.try_into() else {
            return Err(CryptoError::Internal);
        };
        match_mldsa_parms!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                M::$Alg::sign_mu(k, rng, mu, buf)?;
                Ok(TpmtSignature::Mldsa(
                    Tpm2bSignatureMldsa::new(buf).ok_or(CryptoError::Internal)?,
                ))
            },
        })
    }

    /// Signs prehashed `digest` with this key using `HashML-DSA` with `hash` and
    /// context string `context` (`TPM2_Sign` / `TPM2_SignDigest` with
    /// `TPM_ALG_HASH_MLDSA`), writing the signature into `out` and returning it
    /// as a [`TpmtSignature`].
    ///
    /// Returns `Err(`[`CryptoError::Internal`]`)` if `digest.len()` doesn't
    /// match `hash` or `context` is longer than 255 bytes
    /// ([`TpmtSignature::MAX_CTX_BYTES`]).
    #[cfg(feature = "hash_mldsa")]
    pub fn sign_prehash<'a>(
        &self,
        rng: &mut M::Rng,
        hash: crate::TpmiAlgHash,
        context: &[u8],
        digest: &[u8],
        out: &'a mut SignatureBuffer,
    ) -> Result<TpmtSignature<'a>, CryptoError> {
        if context.len() > TpmtSignature::MAX_CTX_BYTES {
            return Err(CryptoError::Internal);
        }
        let digest = crate::TpmtHa::new(hash, digest).ok_or(CryptoError::Internal)?;
        match_mldsa_parms!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                M::$Alg::sign_prehash(k, rng, context, digest, buf)?;
                let signature = Tpm2bSignatureMldsa::new(buf).ok_or(CryptoError::Internal)?;
                Ok(TpmtSignature::HashMldsa(crate::TpmsSignatureHashMldsa {
                    hash,
                    signature,
                }))
            },
        })
    }

    /// Signs the concatenation of `msg` slices with this key using pure
    /// `ML-DSA` with context string `context` (`TPM2_SignSequenceComplete`),
    /// writing the signature into `out` and returning it as a
    /// [`TpmtSignature`].
    ///
    /// Returns `Err(`[`CryptoError::Internal`]`)` if `context` is longer than
    /// 255 bytes ([`TpmtSignature::MAX_CTX_BYTES`]).
    pub fn sign_message<'a>(
        &self,
        rng: &mut M::Rng,
        context: &[u8],
        msg: &[&[u8]],
        out: &'a mut SignatureBuffer,
    ) -> Result<TpmtSignature<'a>, CryptoError> {
        if context.len() > TpmtSignature::MAX_CTX_BYTES {
            return Err(CryptoError::Internal);
        }
        match_mldsa_parms!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                M::$Alg::sign_message(k, rng, context, msg, buf)?;
                Ok(TpmtSignature::Mldsa(
                    Tpm2bSignatureMldsa::new(buf).ok_or(CryptoError::Internal)?,
                ))
            },
        })
    }
}

impl<M: Mldsa> MldsaPublicKey<M> {
    /// Verifies `signature` over `digest` with this key and context string
    /// `context` (`TPM2_VerifySignature` / `TPM2_VerifyDigestSignature`):
    /// - `ML-DSA`: `digest` is the 64-byte external `µ` and `context` must be
    ///   empty (see [`MldsaPrivateKey::sign_mu`]).
    /// - `HashML-DSA`: `digest` must match the signature's hash algorithm (see
    ///   [`MldsaPrivateKey::sign_prehash`]).
    ///
    /// Returns `Ok(false)` if `digest` or `context` doesn't meet these
    /// requirements, the signature size doesn't match the key, or verification
    /// fails, and `Err(`[`CryptoError::Unsupported`]`)` for any other scheme.
    pub fn verify(
        &self,
        context: &[u8],
        digest: &[u8],
        signature: TpmtSignature<'_>,
    ) -> Result<bool, CryptoError> {
        match signature {
            TpmtSignature::Mldsa(sig) => {
                let Ok(mu) = digest.try_into() else {
                    return Ok(false);
                };
                if !context.is_empty() {
                    return Ok(false);
                }
                match_mldsa_parms!(match self {
                    Self::$Alg(k) => {
                        let Ok(sig) = sig.as_slice().try_into() else {
                            return Ok(false);
                        };
                        M::$Alg::verify_mu(k, mu, sig)
                    },
                })
            }
            #[cfg(feature = "hash_mldsa")]
            TpmtSignature::HashMldsa(s) => {
                if context.len() > TpmtSignature::MAX_CTX_BYTES {
                    return Ok(false);
                }
                let Some(digest) = crate::TpmtHa::new(s.hash, digest) else {
                    return Ok(false);
                };
                match_mldsa_parms!(match self {
                    Self::$Alg(k) => {
                        let Ok(sig) = s.signature.as_slice().try_into() else {
                            return Ok(false);
                        };
                        M::$Alg::verify_prehash(k, context, digest, sig)
                    },
                })
            }
            _ => Err(CryptoError::Unsupported),
        }
    }

    /// Verifies pure `ML-DSA` `signature` over the concatenation of `msg`
    /// slices with this key and context string `context`
    /// (`TPM2_VerifySequenceComplete`).
    ///
    /// Returns `Ok(false)` if `context` is longer than 255 bytes
    /// ([`TpmtSignature::MAX_CTX_BYTES`]), the signature size doesn't match the
    /// key, or verification fails, and `Err(`[`CryptoError::Unsupported`]`)`
    /// for any other scheme.
    pub fn verify_message(
        &self,
        context: &[u8],
        msg: &[&[u8]],
        signature: TpmtSignature<'_>,
    ) -> Result<bool, CryptoError> {
        let TpmtSignature::Mldsa(sig) = signature else {
            return Err(CryptoError::Unsupported);
        };
        if context.len() > TpmtSignature::MAX_CTX_BYTES {
            return Ok(false);
        }
        match_mldsa_parms!(match self {
            Self::$Alg(k) => {
                let Ok(sig) = sig.as_slice().try_into() else {
                    return Ok(false);
                };
                M::$Alg::verify_message(k, context, msg, sig)
            },
        })
    }
}
