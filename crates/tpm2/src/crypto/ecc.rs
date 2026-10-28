//! ECC public/private keys (Weierstrass, twisted Edwards, and Montgomery) and
//! ECDH operations.

#[allow(unused_imports)]
use super::{
    CryptoError, Rng,
    backend::{AsymmetricKey, Ecc, EccCurve, EdwardsCurve, MontgomeryCurve},
    left_pad_be, match_ecc_curve,
};
use crate::{Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint, TpmtEccScheme};

/// Maximum coordinate, compressed point, or scalar/secret size (in bytes)
/// across enabled ECC curve features.
pub const MAX_ECC_COORD_BYTES: usize = TpmEccCurve::MAX_ECC_KEY_BYTES;

/// Scratch buffer large enough to hold a coordinate, compressed point, or
/// scalar/secret of any enabled ECC curve.
pub type EccCoordBuffer = [u8; MAX_ECC_COORD_BYTES];

/// Key representation family selected by a `(TpmEccCurve, Option<TpmtEccScheme>)`
/// pair.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EccKeyKind {
    Weierstrass,
    #[cfg(feature = "eddsa")]
    Edwards,
    #[cfg(any(feature = "curve25519", feature = "curve448"))]
    Montgomery,
}

impl EccKeyKind {
    const fn select(
        curve: TpmEccCurve,
        scheme: Option<TpmtEccScheme>,
    ) -> Result<Self, CryptoError> {
        match curve {
            #[cfg(feature = "curve25519")]
            TpmEccCurve::Curve25519 => Self::select_edwards_or_montgomery(scheme),
            #[cfg(feature = "curve448")]
            TpmEccCurve::Curve448 => Self::select_edwards_or_montgomery(scheme),
            #[allow(unreachable_patterns)]
            _ => match scheme {
                #[cfg(feature = "eddsa")]
                Some(TpmtEccScheme::Eddsa) => Err(CryptoError::Unsupported),
                #[cfg(feature = "hash_eddsa")]
                Some(TpmtEccScheme::HashEddsa) => Err(CryptoError::Unsupported),
                _ => Ok(Self::Weierstrass),
            },
        }
    }

    #[cfg(any(feature = "curve25519", feature = "curve448"))]
    const fn select_edwards_or_montgomery(
        scheme: Option<TpmtEccScheme>,
    ) -> Result<Self, CryptoError> {
        match scheme {
            #[cfg(feature = "eddsa")]
            Some(TpmtEccScheme::Eddsa) => Ok(Self::Edwards),
            #[cfg(feature = "hash_eddsa")]
            Some(TpmtEccScheme::HashEddsa) => Ok(Self::Edwards),
            None => Ok(Self::Montgomery),
            Some(TpmtEccScheme::Ecdh(_)) => Ok(Self::Montgomery),
            #[allow(unreachable_patterns)]
            _ => Err(CryptoError::Unsupported),
        }
    }
}

/// Encodes a Weierstrass `point` as `x || y`, left-padding each big-endian
/// coordinate to `N / 2` bytes, returning `None` if either coordinate is empty
/// or longer than `N / 2`.
// Unused if no Weierstrass curve is enabled.
#[allow(dead_code)]
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
// Unused if no Weierstrass curve is enabled.
#[allow(dead_code)]
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

/// Validated ECC public key for a runtime-selected curve and key kind.
///
/// [`TpmEccCurve::Curve25519`] and [`TpmEccCurve::Curve448`] each map to two
/// distinct key representations selected by the key's [`TpmtEccScheme`]:
/// - **Twisted Edwards** (`Ed25519` / `Ed448`) when `scheme` is
///   [`TpmtEccScheme::Eddsa`] (`TPM_ALG_EDDSA`) or
///   [`TpmtEccScheme::HashEddsa`] (`TPM_ALG_HASH_EDDSA`). Public keys are RFC
///   8032 little-endian compressed points (32 or 57 bytes) in `point.x` with
///   `point.y` empty.
/// - **Montgomery** (`X25519` / `X448`) when `scheme` is `None`
///   (`TPM_ALG_NULL`) or [`TpmtEccScheme::Ecdh`]. Public keys are RFC 7748
///   little-endian `u`-coordinates (32 or 56 bytes) in `point.x` with `point.y`
///   empty.
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
    #[cfg(all(feature = "curve25519", feature = "eddsa"))]
    Ed25519(<E::Ed25519 as AsymmetricKey<32, 32>>::Public),
    #[cfg(all(feature = "curve448", feature = "eddsa"))]
    Ed448(<E::Ed448 as AsymmetricKey<57, 57>>::Public),
    #[cfg(feature = "curve25519")]
    X25519(<E::X25519 as AsymmetricKey<32, 32>>::Public),
    #[cfg(feature = "curve448")]
    X448(<E::X448 as AsymmetricKey<56, 56>>::Public),
}

impl<E: Ecc> EccPublicKey<E> {
    /// Validates that `point` is a valid public key for `(curve, scheme)` and
    /// loads the public key.
    ///
    /// - For **Weierstrass** curves, short big-endian coordinates in `point.x`
    ///   and `point.y` are left-padded with zeros to `curve.key_bytes()`.
    ///   Returns `Ok(None)` if either coordinate is empty, exceeds
    ///   `curve.key_bytes()`, or `(x, y)` is not on `curve`.
    /// - For **Edwards** (`Curve25519`/`Curve448` with `Eddsa`/`HashEddsa`) and
    ///   **Montgomery** (`Curve25519`/`Curve448` with `None`/`Ecdh`) keys,
    ///   `point.x` must be the exact key size (32B for Ed25519/X25519, 57B for
    ///   Ed448, 56B for X448) and `point.y` must be empty, or `Ok(None)` is
    ///   returned.
    /// - Returns `Err(`[`CryptoError::Unsupported`]`)` if `(curve, scheme)` is
    ///   an unsupported combination (e.g. `Eddsa` on a Weierstrass curve or
    ///   `Ecdsa` on `Curve25519`) or unsupported by the backend.
    pub fn load(
        curve: TpmEccCurve,
        scheme: Option<TpmtEccScheme>,
        point: TpmsEccPoint<'_>,
    ) -> Result<Option<Self>, CryptoError> {
        match EccKeyKind::select(curve, scheme)? {
            EccKeyKind::Weierstrass => {
                let _ = &point;
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
            #[cfg(feature = "eddsa")]
            EccKeyKind::Edwards => {
                if !point.y.as_slice().is_empty() {
                    return Ok(None);
                }
                match curve {
                    #[cfg(feature = "curve25519")]
                    TpmEccCurve::Curve25519 => {
                        let Ok(p) = point.x.as_slice().try_into() else {
                            return Ok(None);
                        };
                        Ok(E::Ed25519::load_public((), p)?.map(Self::Ed25519))
                    }
                    #[cfg(feature = "curve448")]
                    TpmEccCurve::Curve448 => {
                        let Ok(p) = point.x.as_slice().try_into() else {
                            return Ok(None);
                        };
                        Ok(E::Ed448::load_public((), p)?.map(Self::Ed448))
                    }
                    #[allow(unreachable_patterns)]
                    _ => Err(CryptoError::Unsupported),
                }
            }
            #[cfg(any(feature = "curve25519", feature = "curve448"))]
            EccKeyKind::Montgomery => {
                if !point.y.as_slice().is_empty() {
                    return Ok(None);
                }
                match curve {
                    #[cfg(feature = "curve25519")]
                    TpmEccCurve::Curve25519 => {
                        let Ok(u) = point.x.as_slice().try_into() else {
                            return Ok(None);
                        };
                        Ok(E::X25519::load_public((), u)?.map(Self::X25519))
                    }
                    #[cfg(feature = "curve448")]
                    TpmEccCurve::Curve448 => {
                        let Ok(u) = point.x.as_slice().try_into() else {
                            return Ok(None);
                        };
                        Ok(E::X448::load_public((), u)?.map(Self::X448))
                    }
                    #[allow(unreachable_patterns)]
                    _ => Err(CryptoError::Unsupported),
                }
            }
        }
    }

    /// Returns the elliptic curve identifier of this key.
    pub const fn curve(&self) -> TpmEccCurve {
        match_ecc_curve!(match self {
            Self::$Alg(_) => { TpmEccCurve::$Alg },
            #[cfg(all(feature = "curve25519", feature = "eddsa"))]
            Self::Ed25519(_) => TpmEccCurve::Curve25519,
            #[cfg(all(feature = "curve448", feature = "eddsa"))]
            Self::Ed448(_) => TpmEccCurve::Curve448,
            #[cfg(feature = "curve25519")]
            Self::X25519(_) => TpmEccCurve::Curve25519,
            #[cfg(feature = "curve448")]
            Self::X448(_) => TpmEccCurve::Curve448,
        })
    }

    /// Returns the canonical byte length of a coordinate, compressed point, or
    /// secret/scalar for this specific key variant.
    ///
    /// Note that for [`Self::Ed448`] this returns `57` (RFC 8032 compressed
    /// point / secret / signature half size), whereas [`Self::X448`] and
    /// `TpmEccCurve::Curve448.key_bytes()` return `56`.
    pub const fn key_bytes(&self) -> usize {
        match self {
            #[cfg(all(feature = "curve25519", feature = "eddsa"))]
            Self::Ed25519(_) => 32,
            #[cfg(all(feature = "curve448", feature = "eddsa"))]
            Self::Ed448(_) => 57,
            #[cfg(feature = "curve25519")]
            Self::X25519(_) => 32,
            #[cfg(feature = "curve448")]
            Self::X448(_) => 56,
            #[allow(unreachable_patterns)]
            _ => self.curve().key_bytes(),
        }
    }

    /// Writes the public point into `out_x` (and `out_y` for Weierstrass keys)
    /// and returns a [`TpmsEccPoint`].
    ///
    /// For Edwards and Montgomery keys, the little-endian encoded point is
    /// written into `out_x` and `point.y` is empty. `out_x` (and `out_y` for
    /// Weierstrass keys) must be at least [`self.key_bytes()`](Self::key_bytes)
    /// bytes (e.g. [`EccCoordBuffer`]), or [`CryptoError::Internal`] is
    /// returned.
    pub fn point<'a>(
        &self,
        out_x: &'a mut [u8],
        out_y: &'a mut [u8],
    ) -> Result<TpmsEccPoint<'a>, CryptoError> {
        let _ = &out_y;
        match_ecc_curve!(match self {
            Self::$Alg(k) => {
                let mut buf = [0u8; _];
                E::$Alg::store_public(k, &mut buf)?;
                decode_point(&buf, out_x, out_y)
            },
            #[cfg(all(feature = "curve25519", feature = "eddsa"))]
            Self::Ed25519(k) => {
                let Some(bx) = out_x.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::Ed25519::store_public(k, bx)?;
                Ok(TpmsEccPoint {
                    x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                    y: Tpm2bEccParameter::new(&[]).ok_or(CryptoError::Internal)?,
                })
            }
            #[cfg(all(feature = "curve448", feature = "eddsa"))]
            Self::Ed448(k) => {
                let Some(bx) = out_x.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::Ed448::store_public(k, bx)?;
                Ok(TpmsEccPoint {
                    x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                    y: Tpm2bEccParameter::new(&[]).ok_or(CryptoError::Internal)?,
                })
            }
            #[cfg(feature = "curve25519")]
            Self::X25519(k) => {
                let Some(bx) = out_x.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::X25519::store_public(k, bx)?;
                Ok(TpmsEccPoint {
                    x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                    y: Tpm2bEccParameter::new(&[]).ok_or(CryptoError::Internal)?,
                })
            }
            #[cfg(feature = "curve448")]
            Self::X448(k) => {
                let Some(bx) = out_x.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::X448::store_public(k, bx)?;
                Ok(TpmsEccPoint {
                    x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                    y: Tpm2bEccParameter::new(&[]).ok_or(CryptoError::Internal)?,
                })
            }
        })
    }
}

/// Validated ECC private key for a runtime-selected curve and key kind.
///
/// See [`EccPublicKey`] for how `(curve, scheme)` selects between Weierstrass,
/// twisted Edwards (`Ed25519` / `Ed448`), and Montgomery (`X25519` / `X448`)
/// representations.
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
    #[cfg(all(feature = "curve25519", feature = "eddsa"))]
    Ed25519(<E::Ed25519 as AsymmetricKey<32, 32>>::Private),
    #[cfg(all(feature = "curve448", feature = "eddsa"))]
    Ed448(<E::Ed448 as AsymmetricKey<57, 57>>::Private),
    #[cfg(feature = "curve25519")]
    X25519(<E::X25519 as AsymmetricKey<32, 32>>::Private),
    #[cfg(feature = "curve448")]
    X448(<E::X448 as AsymmetricKey<56, 56>>::Private),
}

impl<E: Ecc> EccPrivateKey<E> {
    /// Loads and validates an ECC private key from `public` and secret scalar
    /// or RFC 8032 secret seed `scalar`.
    ///
    /// - For **Weierstrass** keys, short big-endian scalars are left-padded
    ///   with zeros to the curve size.
    /// - For **Edwards** and **Montgomery** keys, `scalar` must have the exact
    ///   key size (`public.key_bytes()`).
    /// - Returns `Ok(None)` if `scalar` has an invalid length or value, or does
    ///   not correspond to `public`.
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
            #[cfg(all(feature = "curve25519", feature = "eddsa"))]
            EccPublicKey::Ed25519(pub_k) => {
                let Ok(s) = scalar.as_slice().try_into() else {
                    return Ok(None);
                };
                Ok(E::Ed25519::load_private(pub_k, s)?.map(Self::Ed25519))
            }
            #[cfg(all(feature = "curve448", feature = "eddsa"))]
            EccPublicKey::Ed448(pub_k) => {
                let Ok(s) = scalar.as_slice().try_into() else {
                    return Ok(None);
                };
                Ok(E::Ed448::load_private(pub_k, s)?.map(Self::Ed448))
            }
            #[cfg(feature = "curve25519")]
            EccPublicKey::X25519(pub_k) => {
                let Ok(s) = scalar.as_slice().try_into() else {
                    return Ok(None);
                };
                Ok(E::X25519::load_private(pub_k, s)?.map(Self::X25519))
            }
            #[cfg(feature = "curve448")]
            EccPublicKey::X448(pub_k) => {
                let Ok(s) = scalar.as_slice().try_into() else {
                    return Ok(None);
                };
                Ok(E::X448::load_private(pub_k, s)?.map(Self::X448))
            }
        })
    }

    /// Generates a new ECC keypair for `(curve, scheme)` from `rng`.
    pub fn generate(
        rng: &mut impl Rng,
        curve: TpmEccCurve,
        scheme: Option<TpmtEccScheme>,
    ) -> Result<Self, CryptoError> {
        match EccKeyKind::select(curve, scheme)? {
            EccKeyKind::Weierstrass => {
                let _ = &rng;
                match_ecc_curve!(match curve {
                    TpmEccCurve::$Alg => {
                        Ok(Self::$Alg(E::$Alg::generate(rng, ())?))
                    },
                    #[allow(unreachable_patterns)]
                    _ => Err(CryptoError::Unsupported),
                })
            }
            #[cfg(feature = "eddsa")]
            EccKeyKind::Edwards => match curve {
                #[cfg(feature = "curve25519")]
                TpmEccCurve::Curve25519 => Ok(Self::Ed25519(E::Ed25519::generate(rng, ())?)),
                #[cfg(feature = "curve448")]
                TpmEccCurve::Curve448 => Ok(Self::Ed448(E::Ed448::generate(rng, ())?)),
                #[allow(unreachable_patterns)]
                _ => Err(CryptoError::Unsupported),
            },
            #[cfg(any(feature = "curve25519", feature = "curve448"))]
            EccKeyKind::Montgomery => match curve {
                #[cfg(feature = "curve25519")]
                TpmEccCurve::Curve25519 => Ok(Self::X25519(E::X25519::generate(rng, ())?)),
                #[cfg(feature = "curve448")]
                TpmEccCurve::Curve448 => Ok(Self::X448(E::X448::generate(rng, ())?)),
                #[allow(unreachable_patterns)]
                _ => Err(CryptoError::Unsupported),
            },
        }
    }

    /// Returns the elliptic curve identifier of this key.
    pub const fn curve(&self) -> TpmEccCurve {
        match_ecc_curve!(match self {
            Self::$Alg(_) => { TpmEccCurve::$Alg },
            #[cfg(all(feature = "curve25519", feature = "eddsa"))]
            Self::Ed25519(_) => TpmEccCurve::Curve25519,
            #[cfg(all(feature = "curve448", feature = "eddsa"))]
            Self::Ed448(_) => TpmEccCurve::Curve448,
            #[cfg(feature = "curve25519")]
            Self::X25519(_) => TpmEccCurve::Curve25519,
            #[cfg(feature = "curve448")]
            Self::X448(_) => TpmEccCurve::Curve448,
        })
    }

    /// Returns the canonical byte length of a coordinate, compressed point, or
    /// secret/scalar for this specific key variant (`57` for [`Self::Ed448`],
    /// `56` for [`Self::X448`]).
    pub const fn key_bytes(&self) -> usize {
        match self {
            #[cfg(all(feature = "curve25519", feature = "eddsa"))]
            Self::Ed25519(_) => 32,
            #[cfg(all(feature = "curve448", feature = "eddsa"))]
            Self::Ed448(_) => 57,
            #[cfg(feature = "curve25519")]
            Self::X25519(_) => 32,
            #[cfg(feature = "curve448")]
            Self::X448(_) => 56,
            #[allow(unreachable_patterns)]
            _ => self.curve().key_bytes(),
        }
    }

    /// Writes the public point into `out_x` (and `out_y` for Weierstrass keys)
    /// and returns a [`TpmsEccPoint`].
    pub fn point<'a>(
        &self,
        out_x: &'a mut [u8],
        out_y: &'a mut [u8],
    ) -> Result<TpmsEccPoint<'a>, CryptoError> {
        let _ = &out_y;
        match_ecc_curve!(match self {
            Self::$Alg(k) => {
                let mut buf = [0u8; _];
                E::$Alg::store_public(E::$Alg::as_public(k), &mut buf)?;
                decode_point(&buf, out_x, out_y)
            },
            #[cfg(all(feature = "curve25519", feature = "eddsa"))]
            Self::Ed25519(k) => {
                let Some(bx) = out_x.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::Ed25519::store_public(E::Ed25519::as_public(k), bx)?;
                Ok(TpmsEccPoint {
                    x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                    y: Tpm2bEccParameter::new(&[]).ok_or(CryptoError::Internal)?,
                })
            }
            #[cfg(all(feature = "curve448", feature = "eddsa"))]
            Self::Ed448(k) => {
                let Some(bx) = out_x.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::Ed448::store_public(E::Ed448::as_public(k), bx)?;
                Ok(TpmsEccPoint {
                    x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                    y: Tpm2bEccParameter::new(&[]).ok_or(CryptoError::Internal)?,
                })
            }
            #[cfg(feature = "curve25519")]
            Self::X25519(k) => {
                let Some(bx) = out_x.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::X25519::store_public(E::X25519::as_public(k), bx)?;
                Ok(TpmsEccPoint {
                    x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                    y: Tpm2bEccParameter::new(&[]).ok_or(CryptoError::Internal)?,
                })
            }
            #[cfg(feature = "curve448")]
            Self::X448(k) => {
                let Some(bx) = out_x.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::X448::store_public(E::X448::as_public(k), bx)?;
                Ok(TpmsEccPoint {
                    x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                    y: Tpm2bEccParameter::new(&[]).ok_or(CryptoError::Internal)?,
                })
            }
        })
    }

    /// Writes the canonical `self.key_bytes()`-byte secret scalar or RFC 8032
    /// secret seed into `out` and returns it as a [`Tpm2bEccParameter`].
    pub fn scalar<'a>(&self, out: &'a mut [u8]) -> Result<Tpm2bEccParameter<'a>, CryptoError> {
        match_ecc_curve!(match self {
            Self::$Alg(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::$Alg::store_private(k, buf)?;
                Tpm2bEccParameter::new(buf).ok_or(CryptoError::Internal)
            },
            #[cfg(all(feature = "curve25519", feature = "eddsa"))]
            Self::Ed25519(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::Ed25519::store_private(k, buf)?;
                Tpm2bEccParameter::new(buf).ok_or(CryptoError::Internal)
            }
            #[cfg(all(feature = "curve448", feature = "eddsa"))]
            Self::Ed448(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::Ed448::store_private(k, buf)?;
                Tpm2bEccParameter::new(buf).ok_or(CryptoError::Internal)
            }
            #[cfg(feature = "curve25519")]
            Self::X25519(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::X25519::store_private(k, buf)?;
                Tpm2bEccParameter::new(buf).ok_or(CryptoError::Internal)
            }
            #[cfg(feature = "curve448")]
            Self::X448(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::X448::store_private(k, buf)?;
                Tpm2bEccParameter::new(buf).ok_or(CryptoError::Internal)
            }
        })
    }

    /// Computes the Diffie-Hellman shared secret (`TPM2_ECDH_ZGen` /
    /// `TPM2_ECDH_KeyGen`), writing `(x, y)` into `out_x` and `out_y` for
    /// Weierstrass keys or the little-endian `u`-coordinate into `out_x` (with
    /// `y` empty) for Montgomery (`X25519` / `X448`) keys.
    ///
    /// Returns `Ok(None)` if the result is the point at infinity or the all-zero
    /// low-order shared secret (`TPM_RC_NO_RESULT`), or
    /// `Err(`[`CryptoError::Unsupported`]`)` if either key is an Edwards signing
    /// key (`Ed25519` / `Ed448`) or the two keys do not have the same variant.
    pub fn ecdh<'a>(
        &self,
        peer_public: &EccPublicKey<E>,
        out_x: &'a mut [u8],
        out_y: &'a mut [u8],
    ) -> Result<Option<TpmsEccPoint<'a>>, CryptoError> {
        let _ = &out_y;
        match (self, peer_public) {
            #[cfg(feature = "curve25519")]
            (Self::X25519(priv_k), EccPublicKey::X25519(pub_k)) => {
                let Some(bx) = out_x.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                match E::X25519::ecdh(priv_k, pub_k, bx)? {
                    Some(()) => Ok(Some(TpmsEccPoint {
                        x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                        y: Tpm2bEccParameter::new(&[]).ok_or(CryptoError::Internal)?,
                    })),
                    None => Ok(None),
                }
            }
            #[cfg(feature = "curve448")]
            (Self::X448(priv_k), EccPublicKey::X448(pub_k)) => {
                let Some(bx) = out_x.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                match E::X448::ecdh(priv_k, pub_k, bx)? {
                    Some(()) => Ok(Some(TpmsEccPoint {
                        x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                        y: Tpm2bEccParameter::new(&[]).ok_or(CryptoError::Internal)?,
                    })),
                    None => Ok(None),
                }
            }
            #[allow(unreachable_patterns)]
            _ => match_ecc_curve!(match self {
                Self::$Alg(priv_k) => {
                    #[allow(irrefutable_let_patterns)]
                    let EccPublicKey::$Alg(pub_k) = peer_public else {
                        return Err(CryptoError::Unsupported);
                    };
                    let (Some(bx), Some(by)) =
                        (out_x.first_chunk_mut(), out_y.first_chunk_mut())
                    else {
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
                #[allow(unreachable_patterns)]
                _ => Err(CryptoError::Unsupported),
            }),
        }
    }
}
