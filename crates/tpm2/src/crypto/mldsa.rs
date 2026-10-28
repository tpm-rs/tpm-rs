//! ML-DSA (FIPS 204) public and private keys.

use super::{
    CryptoError, Rng,
    backend::{AsymmetricKey, Mldsa},
    match_mldsa_parms,
};
use crate::{Tpm2b, Tpm2bPrivateKeyMldsa, Tpm2bPublicKeyMldsa, TpmiMldsaParms};

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
    Mldsa44(<M::Mldsa44 as AsymmetricKey<1312, 32>>::Public),
    #[cfg(feature = "mldsa_65")]
    Mldsa65(<M::Mldsa65 as AsymmetricKey<1952, 32>>::Public),
    #[cfg(feature = "mldsa_87")]
    Mldsa87(<M::Mldsa87 as AsymmetricKey<2592, 32>>::Public),
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
    Mldsa44(<M::Mldsa44 as AsymmetricKey<1312, 32>>::Private),
    #[cfg(feature = "mldsa_65")]
    Mldsa65(<M::Mldsa65 as AsymmetricKey<1952, 32>>::Private),
    #[cfg(feature = "mldsa_87")]
    Mldsa87(<M::Mldsa87 as AsymmetricKey<2592, 32>>::Private),
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
                Ok(M::$Alg::load_private(pub_k, seed.0)?.map(Self::$Alg))
            },
        })
    }

    /// Generates a new ML-DSA keypair for `parms` from `rng`.
    pub fn generate(rng: &mut impl Rng, parms: TpmiMldsaParms) -> Result<Self, CryptoError> {
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
                M::$Alg::store_private(k, buf)?;
                Ok(Tpm2b(buf))
            },
        })
    }
}
