use super::{CryptoError, Random};
use crate::{Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint};

/// Trait implemented by an opaque ECC public key handle.
pub trait EccPublicKey {
    /// Returns the elliptic curve identifier.
    fn curve(&self) -> TpmEccCurve;

    /// Writes the affine `(x, y)` coordinates into `out_x` and `out_y` and returns a [`TpmsEccPoint`].
    fn point<'a>(
        &self,
        out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<TpmsEccPoint<'a>, CryptoError>;
}

/// Trait implemented by an opaque ECC private key handle.
pub trait EccPrivateKey {
    type PublicKey: EccPublicKey;

    /// Returns a reference to the corresponding public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Writes the big-endian secret scalar `d` into `out` and returns it as a [`Tpm2bEccParameter`].
    fn scalar<'a>(
        &self,
        out: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<Tpm2bEccParameter<'a>, CryptoError>;
}

/// Trait implemented by a cryptographic backend to provide ECC key operations.
#[allow(unused_variables)]
pub trait Ecc: Random {
    type PublicKey: EccPublicKey;
    type PrivateKey: EccPrivateKey<PublicKey = Self::PublicKey>;

    /// Validates that `point` is on `curve` (and not infinity) and loads the public key.
    ///
    /// Returns `Ok(None)` if `point` is not a valid point on `curve`.
    fn load_public(
        &self,
        curve: TpmEccCurve,
        point: TpmsEccPoint<'_>,
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Loads an ECC private key from its public key and secret scalar `d`.
    ///
    /// Returns `Ok(None)` if `scalar` is out of range or does not match `public`.
    fn load_private(
        &self,
        public: Self::PublicKey,
        scalar: Tpm2bEccParameter<'_>,
    ) -> Result<Option<Self::PrivateKey>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Generates an ECC keypair on `curve` using `rng`.
    fn generate_key(
        &self,
        rng: &mut Self::Rng,
        curve: TpmEccCurve,
    ) -> Result<Self::PrivateKey, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Computes the shared secret point `Z = [h * d] * Q` (`TPM2_ECDH_ZGen` / `TPM2_ECDH_KeyGen`).
    ///
    /// Returns `Ok(None)` if the resulting point is the point at infinity (`TPM_RC_NO_RESULT`).
    fn ecdh<'a>(
        &self,
        private: &Self::PrivateKey,
        peer_public: &Self::PublicKey,
        out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<Option<TpmsEccPoint<'a>>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}
