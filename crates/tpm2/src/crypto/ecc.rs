//! Weierstrass ECC public/private keys and ECDH operations.

use super::{
    CryptoError, Rng,
    backend::{AsymmetricKey, Ecc, EccCurve},
    left_pad_be, match_ecc_curve,
};
use crate::{Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint};

/// Maximum coordinate / scalar size (in bytes) across enabled Weierstrass ECC
/// curve features.
pub const MAX_ECC_COORD_BYTES: usize = max!(
    0,
    #[cfg(feature = "nist_p192")]
    24,
    #[cfg(feature = "nist_p224")]
    28,
    #[cfg(feature = "nist_p256")]
    32,
    #[cfg(feature = "nist_p384")]
    48,
    #[cfg(feature = "nist_p521")]
    66,
    #[cfg(feature = "bn_p256")]
    32,
    #[cfg(feature = "bn_p638")]
    80,
    #[cfg(feature = "sm2_p256")]
    32,
    #[cfg(feature = "bp_p256_r1")]
    32,
    #[cfg(feature = "bp_p384_r1")]
    48,
    #[cfg(feature = "bp_p512_r1")]
    64,
);

/// Scratch buffer large enough to hold a coordinate or scalar of any enabled
/// Weierstrass ECC curve.
pub type EccCoordBuffer = [u8; MAX_ECC_COORD_BYTES];

/// Encodes a Weierstrass `point` as `x || y`, left-padding each big-endian
/// coordinate to `N / 2` bytes, returning `None` if either coordinate is empty
/// or longer than `N / 2`.
fn encode_point<const N: usize>(point: &TpmsEccPoint<'_>) -> Option<[u8; N]> {
    let (x, y) = (point.x.as_slice(), point.y.as_slice());
    let half = N / 2;
    if x.is_empty() || y.is_empty() || x.len() > half || y.len() > half {
        return None;
    }
    let mut out = [0u8; N];
    out[half - x.len()..half].copy_from_slice(x);
    out[N - y.len()..].copy_from_slice(y);
    Some(out)
}

/// Splits a Weierstrass `x || y` encoding into `out_x` and `out_y`, returning
/// [`CryptoError::Internal`] if either is too short.
fn decode_point<'a>(
    point: &[u8],
    out_x: &'a mut [u8],
    out_y: &'a mut [u8],
) -> Result<TpmsEccPoint<'a>, CryptoError> {
    let (x, y) = point.split_at(point.len() / 2);
    let (Some(bx), Some(by)) = (out_x.get_mut(..x.len()), out_y.get_mut(..y.len())) else {
        return Err(CryptoError::Internal);
    };
    bx.copy_from_slice(x);
    by.copy_from_slice(y);
    Ok(TpmsEccPoint {
        x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
        y: Tpm2bEccParameter::new(by).ok_or(CryptoError::Internal)?,
    })
}

/// Validated Weierstrass ECC public key for a runtime-selected curve.
///
/// While an [`Ecc`] backend can implement whichever curves it wants, the
/// variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum EccPublicKey<E: Ecc> {
    #[cfg(feature = "nist_p192")]
    NistP192(<E::NistP192 as AsymmetricKey<48, 24>>::Public),
    #[cfg(feature = "nist_p224")]
    NistP224(<E::NistP224 as AsymmetricKey<56, 28>>::Public),
    #[cfg(feature = "nist_p256")]
    NistP256(<E::NistP256 as AsymmetricKey<64, 32>>::Public),
    #[cfg(feature = "nist_p384")]
    NistP384(<E::NistP384 as AsymmetricKey<96, 48>>::Public),
    #[cfg(feature = "nist_p521")]
    NistP521(<E::NistP521 as AsymmetricKey<132, 66>>::Public),
    #[cfg(feature = "bn_p256")]
    BNP256(<E::BNP256 as AsymmetricKey<64, 32>>::Public),
    #[cfg(feature = "bn_p638")]
    BNP638(<E::BNP638 as AsymmetricKey<160, 80>>::Public),
    #[cfg(feature = "sm2_p256")]
    SM2P256(<E::SM2P256 as AsymmetricKey<64, 32>>::Public),
    #[cfg(feature = "bp_p256_r1")]
    BpP256R1(<E::BpP256R1 as AsymmetricKey<64, 32>>::Public),
    #[cfg(feature = "bp_p384_r1")]
    BpP384R1(<E::BpP384R1 as AsymmetricKey<96, 48>>::Public),
    #[cfg(feature = "bp_p512_r1")]
    BpP512R1(<E::BpP512R1 as AsymmetricKey<128, 64>>::Public),
}

impl<E: Ecc> EccPublicKey<E> {
    /// Validates that `point` lies on `curve` (and is not infinity) and loads
    /// the public key.
    ///
    /// Short big-endian coordinates in `point` are left-padded with zeros to
    /// `curve.key_bytes()`. Returns `Ok(None)` if either coordinate is empty,
    /// exceeds `curve.key_bytes()`, or `(x, y)` is not on `curve`. Returns
    /// `Err(`[`CryptoError::Unsupported`]`)` if `curve` is disabled,
    /// non-Weierstrass (`Curve25519`/`Curve448`), or unsupported by the
    /// backend.
    pub fn load(curve: TpmEccCurve, point: TpmsEccPoint<'_>) -> Result<Option<Self>, CryptoError> {
        match_ecc_curve!(match curve {
            TpmEccCurve::$Alg => {
                let Some(p) = encode_point(&point) else {
                    return Ok(None);
                };
                Ok(E::$Alg::load_public((), &p)?.map(Self::$Alg))
            },
            #[allow(unreachable_patterns)]
            _ => Err(CryptoError::Unsupported),
        })
    }

    /// Returns the elliptic curve identifier of this key.
    pub const fn curve(&self) -> TpmEccCurve {
        match_ecc_curve!(match self {
            Self::$Alg(_) => { TpmEccCurve::$Alg },
        })
    }

    /// Writes the canonical `curve.key_bytes()`-padded affine `(x, y)`
    /// coordinates into `out_x` and `out_y` and returns a [`TpmsEccPoint`].
    ///
    /// `out_x` and `out_y` must each be at least `self.curve().key_bytes()`
    /// bytes (e.g. [`EccCoordBuffer`]), or [`CryptoError::Internal`] is
    /// returned.
    pub fn point<'a>(
        &self,
        out_x: &'a mut [u8],
        out_y: &'a mut [u8],
    ) -> Result<TpmsEccPoint<'a>, CryptoError> {
        match_ecc_curve!(match self {
            Self::$Alg(k) => {
                let mut buf = [0u8; _];
                E::$Alg::store_public(k, &mut buf)?;
                decode_point(&buf, out_x, out_y)
            },
        })
    }
}

/// Validated Weierstrass ECC private key for a runtime-selected curve.
///
/// While an [`Ecc`] backend can implement whichever curves it wants, the
/// variants of this enum will only exist if the corresponding
/// [crate feature](crate#algorithm-feature-flags) is enabled.
pub enum EccPrivateKey<E: Ecc> {
    #[cfg(feature = "nist_p192")]
    NistP192(<E::NistP192 as AsymmetricKey<48, 24>>::Private),
    #[cfg(feature = "nist_p224")]
    NistP224(<E::NistP224 as AsymmetricKey<56, 28>>::Private),
    #[cfg(feature = "nist_p256")]
    NistP256(<E::NistP256 as AsymmetricKey<64, 32>>::Private),
    #[cfg(feature = "nist_p384")]
    NistP384(<E::NistP384 as AsymmetricKey<96, 48>>::Private),
    #[cfg(feature = "nist_p521")]
    NistP521(<E::NistP521 as AsymmetricKey<132, 66>>::Private),
    #[cfg(feature = "bn_p256")]
    BNP256(<E::BNP256 as AsymmetricKey<64, 32>>::Private),
    #[cfg(feature = "bn_p638")]
    BNP638(<E::BNP638 as AsymmetricKey<160, 80>>::Private),
    #[cfg(feature = "sm2_p256")]
    SM2P256(<E::SM2P256 as AsymmetricKey<64, 32>>::Private),
    #[cfg(feature = "bp_p256_r1")]
    BpP256R1(<E::BpP256R1 as AsymmetricKey<64, 32>>::Private),
    #[cfg(feature = "bp_p384_r1")]
    BpP384R1(<E::BpP384R1 as AsymmetricKey<96, 48>>::Private),
    #[cfg(feature = "bp_p512_r1")]
    BpP512R1(<E::BpP512R1 as AsymmetricKey<128, 64>>::Private),
}

impl<E: Ecc> EccPrivateKey<E> {
    /// Loads and validates an ECC private key from `public` and secret scalar
    /// `d`.
    ///
    /// Short big-endian scalars are left-padded with zeros to the curve size.
    /// Returns `Ok(None)` if `scalar` is empty, exceeds the curve size, is out
    /// of `[1, n - 1]`, or does not correspond to `public`.
    pub fn load(
        public: EccPublicKey<E>,
        scalar: Tpm2bEccParameter<'_>,
    ) -> Result<Option<Self>, CryptoError> {
        match_ecc_curve!(match public {
            EccPublicKey::$Alg(pub_k) => {
                let Some(d) = left_pad_be(scalar.as_slice()) else {
                    return Ok(None);
                };
                Ok(E::$Alg::load_private(pub_k, &d)?.map(Self::$Alg))
            },
        })
    }

    /// Generates a new ECC keypair on `curve` from `rng`.
    pub fn generate(rng: &mut impl Rng, curve: TpmEccCurve) -> Result<Self, CryptoError> {
        match_ecc_curve!(match curve {
            TpmEccCurve::$Alg => {
                Ok(Self::$Alg(E::$Alg::generate(rng, ())?))
            },
            #[allow(unreachable_patterns)]
            _ => Err(CryptoError::Unsupported),
        })
    }

    /// Returns the elliptic curve identifier of this key.
    pub const fn curve(&self) -> TpmEccCurve {
        match_ecc_curve!(match self {
            Self::$Alg(_) => { TpmEccCurve::$Alg },
        })
    }

    /// Writes the canonical `curve.key_bytes()`-padded affine `(x, y)`
    /// coordinates of `[d]G` into `out_x` and `out_y` and returns a
    /// [`TpmsEccPoint`].
    pub fn point<'a>(
        &self,
        out_x: &'a mut [u8],
        out_y: &'a mut [u8],
    ) -> Result<TpmsEccPoint<'a>, CryptoError> {
        match_ecc_curve!(match self {
            Self::$Alg(k) => {
                let mut buf = [0u8; _];
                E::$Alg::store_public(E::$Alg::as_public(k), &mut buf)?;
                decode_point(&buf, out_x, out_y)
            },
        })
    }

    /// Writes the canonical `curve.key_bytes()`-padded big-endian secret scalar
    /// `d` into `out` and returns it as a [`Tpm2bEccParameter`].
    pub fn scalar<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bEccParameter<'a>, CryptoError> {
        match_ecc_curve!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::$Alg::store_private(k, buf)?;
                Tpm2bEccParameter::new(buf).ok_or(CryptoError::Internal)
            },
        })
    }

    /// Computes the shared secret point `Z = [h * d] * peer_public`
    /// (`TPM2_ECDH_ZGen` / `TPM2_ECDH_KeyGen`), writing canonical
    /// `curve.key_bytes()`-padded `(x, y)` coordinates into `out_x` and
    /// `out_y`.
    ///
    /// Returns `Ok(None)` if the resulting point is the point at infinity
    /// (`TPM_RC_NO_RESULT`), or `Err(`[`CryptoError::Unsupported`]`)` if `self`
    /// and `peer_public` are on different curves.
    pub fn ecdh<'a>(
        &self,
        peer_public: &EccPublicKey<E>,
        out_x: &'a mut [u8],
        out_y: &'a mut [u8],
    ) -> Result<Option<TpmsEccPoint<'a>>, CryptoError> {
        match_ecc_curve!(match self {
            Self::$Alg(priv_k) => {
                #[allow(irrefutable_let_patterns)]
                let EccPublicKey::$Alg(pub_k) = peer_public else {
                    return Err(CryptoError::Unsupported);
                };
                let (Some(bx), Some(by)) = (out_x.first_chunk_mut(), out_y.first_chunk_mut()) else {
                    return Err(CryptoError::Internal);
                };
                match E::$Alg::ecdh(priv_k, pub_k, bx, by)? {
                    Some(()) => Ok(Some(TpmsEccPoint {
                        x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                        y: Tpm2bEccParameter::new(by).ok_or(CryptoError::Internal)?,
                    })),
                    None => Ok(None),
                }
            },
        })
    }
}
