//! ML-KEM (FIPS 203) public (encapsulation) and private (decapsulation) keys.

use super::{
    CryptoError, Rng,
    backend::{AsymmetricKey, Mlkem, MlkemKey},
    match_mlkem_parms,
};
use crate::{
    Tpm2b, Tpm2bKemCiphertext, Tpm2bPrivateKeyMlkem, Tpm2bPublicKeyMlkem, Tpm2bSharedSecret,
    TpmiMlkemParms,
};

/// Scratch buffer large enough to hold the encoded encapsulation (public) key
/// of any enabled ML-KEM parameter set ([`TpmiMlkemParms::MAX_PUB_KEY_BYTES`]).
pub type MlkemPubKeyBuffer = [u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];

/// Scratch buffer large enough to hold the ciphertext of any enabled ML-KEM
/// parameter set ([`TpmiMlkemParms::MAX_CT_BYTES`]).
pub type MlkemCiphertextBuffer = [u8; TpmiMlkemParms::MAX_CT_BYTES];

/// Scratch buffer holding a 64-byte ML-KEM `(d || z)` private seed.
pub type MlkemSeedBuffer = [u8; 64];

/// Scratch buffer holding a 32-byte ML-KEM shared secret
/// ([`TpmiMlkemParms::SHARED_SECRET_BYTES`]).
pub type MlkemSharedSecretBuffer = [u8; TpmiMlkemParms::SHARED_SECRET_BYTES];

/// Validated ML-KEM encapsulation (public) key for a runtime-selected parameter
/// set.
///
/// While an [`Mlkem`] backend can implement whichever parameter sets it wants,
/// the variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum MlkemPublicKey<K: Mlkem> {
    #[cfg(feature = "mlkem_512")]
    Mlkem512(<K::Mlkem512 as AsymmetricKey<800, 64>>::Public),
    #[cfg(feature = "mlkem_768")]
    Mlkem768(<K::Mlkem768 as AsymmetricKey<1184, 64>>::Public),
    #[cfg(feature = "mlkem_1024")]
    Mlkem1024(<K::Mlkem1024 as AsymmetricKey<1568, 64>>::Public),
}

impl<K: Mlkem> MlkemPublicKey<K> {
    /// Performs the FIPS 203 encapsulation key check and loads an ML-KEM public
    /// key for `parms`.
    ///
    /// Returns `Ok(None)` if `public.as_slice().len() != parms.pub_key_bytes()`
    /// or `public` fails the FIPS 203 modulus check, and
    /// `Err(`[`CryptoError::Unsupported`]`)` if `parms` is unsupported by the
    /// backend.
    pub fn load(
        parms: TpmiMlkemParms,
        public: Tpm2bPublicKeyMlkem<'_>,
    ) -> Result<Option<Self>, CryptoError> {
        match_mlkem_parms!(match parms {
            TpmiMlkemParms::$Alg => {
                let Ok(pk) = public.as_slice().try_into() else {
                    return Ok(None);
                };
                Ok(K::$Alg::load_public((), pk)?.map(Self::$Alg))
            },
        })
    }

    /// Returns the ML-KEM parameter set identifier of this key.
    pub const fn parms(&self) -> TpmiMlkemParms {
        match_mlkem_parms!(match self {
            Self::$Alg(_) => { TpmiMlkemParms::$Alg },
        })
    }

    /// Writes the encoded FIPS 203 encapsulation key into `out` and returns it
    /// as a [`Tpm2bPublicKeyMlkem`].
    ///
    /// `out` must be at least `self.parms().pub_key_bytes()` bytes (e.g. an
    /// [`MlkemPubKeyBuffer`]), or [`CryptoError::Internal`] is returned.
    pub fn public<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bPublicKeyMlkem<'a>, CryptoError> {
        match_mlkem_parms!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                K::$Alg::store_public(k, buf)?;
                Tpm2bPublicKeyMlkem::new(buf).ok_or(CryptoError::Internal)
            },
        })
    }

    /// Encapsulates a fresh 32-byte shared secret under this key using `rng`
    /// (`TPM2_Encapsulate`), writing the ciphertext into `out_ct` and the
    /// shared secret into `out_ss`.
    ///
    /// `out_ct` must be at least `self.parms().ct_bytes()` bytes (e.g. an
    /// [`MlkemCiphertextBuffer`]) and `out_ss` must be at least 32 bytes (e.g.
    /// an [`MlkemSharedSecretBuffer`]), or [`CryptoError::Internal`] is
    /// returned.
    pub fn encapsulate<'a>(
        &self,
        rng: &mut impl Rng,
        out_ct: &'a mut [u8],
        out_ss: &'a mut [u8],
    ) -> Result<(Tpm2bKemCiphertext<'a>, Tpm2bSharedSecret<'a>), CryptoError> {
        match_mlkem_parms!(match self {
            Self::$Alg(k) => {
                let (Some(ct_buf), Some(ss_buf)) =
                    (out_ct.first_chunk_mut(), out_ss.first_chunk_mut())
                else {
                    return Err(CryptoError::Internal);
                };
                K::$Alg::encapsulate(rng, k, ct_buf, ss_buf)?;
                Ok((
                    Tpm2bKemCiphertext::new(ct_buf).ok_or(CryptoError::Internal)?,
                    Tpm2bSharedSecret::new(ss_buf).ok_or(CryptoError::Internal)?,
                ))
            },
        })
    }
}

/// Validated ML-KEM decapsulation (private) key for a runtime-selected
/// parameter set.
///
/// While an [`Mlkem`] backend can implement whichever parameter sets it wants,
/// the variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum MlkemPrivateKey<K: Mlkem> {
    #[cfg(feature = "mlkem_512")]
    Mlkem512(<K::Mlkem512 as AsymmetricKey<800, 64>>::Private),
    #[cfg(feature = "mlkem_768")]
    Mlkem768(<K::Mlkem768 as AsymmetricKey<1184, 64>>::Private),
    #[cfg(feature = "mlkem_1024")]
    Mlkem1024(<K::Mlkem1024 as AsymmetricKey<1568, 64>>::Private),
}

impl<K: Mlkem> MlkemPrivateKey<K> {
    /// Loads and validates an ML-KEM decapsulation key from `public` and
    /// 64-byte `(d || z)` seed `seed`.
    ///
    /// Returns `Ok(None)` if `seed` does not expand to `public`.
    pub fn load(
        public: MlkemPublicKey<K>,
        seed: Tpm2bPrivateKeyMlkem<'_>,
    ) -> Result<Option<Self>, CryptoError> {
        match_mlkem_parms!(match public {
            MlkemPublicKey::$Alg(pub_k) => {
                Ok(K::$Alg::load_private(pub_k, seed.0)?.map(Self::$Alg))
            },
        })
    }

    /// Generates a new ML-KEM keypair for `parms` from `rng`.
    pub fn generate(rng: &mut impl Rng, parms: TpmiMlkemParms) -> Result<Self, CryptoError> {
        match_mlkem_parms!(match parms {
            TpmiMlkemParms::$Alg => {
                Ok(Self::$Alg(K::$Alg::generate(rng, ())?))
            },
        })
    }

    /// Returns the ML-KEM parameter set identifier of this key.
    pub const fn parms(&self) -> TpmiMlkemParms {
        match_mlkem_parms!(match self {
            Self::$Alg(_) => { TpmiMlkemParms::$Alg },
        })
    }

    /// Writes the encoded FIPS 203 encapsulation key into `out` and returns it
    /// as a [`Tpm2bPublicKeyMlkem`].
    pub fn public<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bPublicKeyMlkem<'a>, CryptoError> {
        match_mlkem_parms!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                K::$Alg::store_public(K::$Alg::as_public(k), buf)?;
                Tpm2bPublicKeyMlkem::new(buf).ok_or(CryptoError::Internal)
            },
        })
    }

    /// Writes the 64-byte FIPS 203 `(d || z)` private seed into `out` and
    /// returns it as a [`Tpm2bPrivateKeyMlkem`].
    ///
    /// `out` must be at least 64 bytes (e.g. an [`MlkemSeedBuffer`]), or
    /// [`CryptoError::Internal`] is returned.
    pub fn seed<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bPrivateKeyMlkem<'a>, CryptoError> {
        match_mlkem_parms!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                K::$Alg::store_private(k, buf)?;
                Ok(Tpm2b(buf))
            },
        })
    }

    /// Decapsulates `ciphertext` under this key (`TPM2_Decapsulate`), writing
    /// the 32-byte shared secret into `out_ss`.
    ///
    /// `out_ss` must be at least 32 bytes (e.g. an
    /// [`MlkemSharedSecretBuffer`]), or [`CryptoError::Internal`] is returned.
    /// Returns `Ok(None)` if `ciphertext.as_slice().len() != self.parms().ct_bytes()`.
    pub fn decapsulate<'a>(
        &self,
        ciphertext: Tpm2bKemCiphertext<'_>,
        out_ss: &'a mut [u8],
    ) -> Result<Option<Tpm2bSharedSecret<'a>>, CryptoError> {
        match_mlkem_parms!(match self {
            Self::$Alg(k) => {
                let Some(ss_buf) = out_ss.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                let Ok(ct) = ciphertext.as_slice().try_into() else {
                    return Ok(None);
                };
                K::$Alg::decapsulate(k, ct, ss_buf)?;
                Tpm2bSharedSecret::new(ss_buf).map(Some).ok_or(CryptoError::Internal)
            },
        })
    }
}
