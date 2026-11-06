//! ECC public/private keys (Weierstrass, twisted Edwards, and Montgomery) and
//! ECDH operations.

#[allow(unused_imports)]
use super::{
    CryptoError, Rng, SignatureBuffer,
    backend::{Ecc, EccCurve, EdwardsCurve, MontgomeryCurve, PrivateKey},
    left_pad_be, match_ecc_curve,
};
use crate::{
    Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint, TpmtEccScheme, TpmtSigScheme, TpmtSignature,
};

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
    NistP192(<E::NistP192 as PrivateKey<48, 24, E::Rng>>::PublicKey),
    #[cfg(feature = "nist_p224")]
    NistP224(<E::NistP224 as PrivateKey<56, 28, E::Rng>>::PublicKey),
    #[cfg(feature = "nist_p256")]
    NistP256(<E::NistP256 as PrivateKey<64, 32, E::Rng>>::PublicKey),
    #[cfg(feature = "nist_p384")]
    NistP384(<E::NistP384 as PrivateKey<96, 48, E::Rng>>::PublicKey),
    #[cfg(feature = "nist_p521")]
    NistP521(<E::NistP521 as PrivateKey<132, 66, E::Rng>>::PublicKey),
    #[cfg(feature = "bn_p256")]
    BNP256(<E::BNP256 as PrivateKey<64, 32, E::Rng>>::PublicKey),
    #[cfg(feature = "bn_p638")]
    BNP638(<E::BNP638 as PrivateKey<160, 80, E::Rng>>::PublicKey),
    #[cfg(feature = "sm2_p256")]
    SM2P256(<E::SM2P256 as PrivateKey<64, 32, E::Rng>>::PublicKey),
    #[cfg(feature = "bp_p256_r1")]
    BpP256R1(<E::BpP256R1 as PrivateKey<64, 32, E::Rng>>::PublicKey),
    #[cfg(feature = "bp_p384_r1")]
    BpP384R1(<E::BpP384R1 as PrivateKey<96, 48, E::Rng>>::PublicKey),
    #[cfg(feature = "bp_p512_r1")]
    BpP512R1(<E::BpP512R1 as PrivateKey<128, 64, E::Rng>>::PublicKey),
    #[cfg(all(feature = "curve25519", feature = "eddsa"))]
    Ed25519(<E::Ed25519 as PrivateKey<32, 32, E::Rng>>::PublicKey),
    #[cfg(all(feature = "curve448", feature = "eddsa"))]
    Ed448(<E::Ed448 as PrivateKey<57, 57, E::Rng>>::PublicKey),
    #[cfg(feature = "curve25519")]
    X25519(<E::X25519 as PrivateKey<32, 32, E::Rng>>::PublicKey),
    #[cfg(feature = "curve448")]
    X448(<E::X448 as PrivateKey<56, 56, E::Rng>>::PublicKey),
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
    NistP192(E::NistP192),
    #[cfg(feature = "nist_p224")]
    NistP224(E::NistP224),
    #[cfg(feature = "nist_p256")]
    NistP256(E::NistP256),
    #[cfg(feature = "nist_p384")]
    NistP384(E::NistP384),
    #[cfg(feature = "nist_p521")]
    NistP521(E::NistP521),
    #[cfg(feature = "bn_p256")]
    BNP256(E::BNP256),
    #[cfg(feature = "bn_p638")]
    BNP638(E::BNP638),
    #[cfg(feature = "sm2_p256")]
    SM2P256(E::SM2P256),
    #[cfg(feature = "bp_p256_r1")]
    BpP256R1(E::BpP256R1),
    #[cfg(feature = "bp_p384_r1")]
    BpP384R1(E::BpP384R1),
    #[cfg(feature = "bp_p512_r1")]
    BpP512R1(E::BpP512R1),
    #[cfg(all(feature = "curve25519", feature = "eddsa"))]
    Ed25519(E::Ed25519),
    #[cfg(all(feature = "curve448", feature = "eddsa"))]
    Ed448(E::Ed448),
    #[cfg(feature = "curve25519")]
    X25519(E::X25519),
    #[cfg(feature = "curve448")]
    X448(E::X448),
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
                Ok(E::$Alg::load(pub_k, &d)?.map(Self::$Alg))
            },
            #[cfg(all(feature = "curve25519", feature = "eddsa"))]
            EccPublicKey::Ed25519(pub_k) => {
                let Ok(s) = scalar.as_slice().try_into() else {
                    return Ok(None);
                };
                Ok(E::Ed25519::load(pub_k, s)?.map(Self::Ed25519))
            }
            #[cfg(all(feature = "curve448", feature = "eddsa"))]
            EccPublicKey::Ed448(pub_k) => {
                let Ok(s) = scalar.as_slice().try_into() else {
                    return Ok(None);
                };
                Ok(E::Ed448::load(pub_k, s)?.map(Self::Ed448))
            }
            #[cfg(feature = "curve25519")]
            EccPublicKey::X25519(pub_k) => {
                let Ok(s) = scalar.as_slice().try_into() else {
                    return Ok(None);
                };
                Ok(E::X25519::load(pub_k, s)?.map(Self::X25519))
            }
            #[cfg(feature = "curve448")]
            EccPublicKey::X448(pub_k) => {
                let Ok(s) = scalar.as_slice().try_into() else {
                    return Ok(None);
                };
                Ok(E::X448::load(pub_k, s)?.map(Self::X448))
            }
        })
    }

    /// Generates a new ECC keypair for `(curve, scheme)` from `rng`.
    pub fn generate(
        rng: &mut E::Rng,
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
                E::$Alg::store(k, buf)?;
                Tpm2bEccParameter::new(buf).ok_or(CryptoError::Internal)
            },
            #[cfg(all(feature = "curve25519", feature = "eddsa"))]
            Self::Ed25519(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::Ed25519::store(k, buf)?;
                Tpm2bEccParameter::new(buf).ok_or(CryptoError::Internal)
            }
            #[cfg(all(feature = "curve448", feature = "eddsa"))]
            Self::Ed448(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::Ed448::store(k, buf)?;
                Tpm2bEccParameter::new(buf).ok_or(CryptoError::Internal)
            }
            #[cfg(feature = "curve25519")]
            Self::X25519(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::X25519::store(k, buf)?;
                Tpm2bEccParameter::new(buf).ok_or(CryptoError::Internal)
            }
            #[cfg(feature = "curve448")]
            Self::X448(k) => {
                let Some(buf) = out.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                E::X448::store(k, buf)?;
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

impl<E: Ecc> EccPrivateKey<E> {
    /// Signs `digest` with this key using `scheme` (`TPM2_Sign` /
    /// `TPM2_SignDigest`), writing the signature into `out` and returning it as
    /// a [`TpmtSignature`].
    ///
    /// Supported schemes:
    /// - `ECDSA` and `SM2` (Weierstrass keys): `digest` must match `scheme`'s
    ///   hash algorithm. For `SM2`, `digest` is `H(Z_A || M)`, computed by the
    ///   caller.
    /// - `HashEdDSA` (`Ed25519` / `Ed448` keys): `digest` is the 64-byte prehash
    ///   (`SHA-512` for Ed25519ph, `SHAKE256-512` for Ed448ph).
    ///
    /// Pure `EdDSA` is message-only; see [`sign_message`](Self::sign_message).
    /// Returns `Err(`[`CryptoError::Unsupported`]`)` for any other scheme
    /// (including `ECDAA` and `ECSchnorr`) or key, or
    /// `Err(`[`CryptoError::Internal`]`)` if `digest.len()` doesn't match the
    /// scheme.
    pub fn sign<'a>(
        &self,
        rng: &mut E::Rng,
        scheme: TpmtSigScheme,
        digest: &[u8],
        out: &'a mut SignatureBuffer,
    ) -> Result<TpmtSignature<'a>, CryptoError> {
        match scheme {
            #[cfg(feature = "ecdsa")]
            TpmtSigScheme::Ecdsa(hash) => Ok(TpmtSignature::Ecdsa(
                self.sign_digest(rng, false, hash, digest, out)?,
            )),
            #[cfg(feature = "sm2")]
            TpmtSigScheme::Sm2(hash) => Ok(TpmtSignature::Sm2(
                self.sign_digest(rng, true, hash, digest, out)?,
            )),
            #[cfg(feature = "hash_eddsa")]
            TpmtSigScheme::HashEddsa => {
                let Ok(prehash) = digest.try_into() else {
                    return Err(CryptoError::Internal);
                };
                Ok(TpmtSignature::HashEddsa(
                    self.eddsa_sign_prehash(prehash, out)?,
                ))
            }
            // TODO: Add ECSchnorr support.
            _ => {
                let _ = (rng, digest, out);
                Err(CryptoError::Unsupported)
            }
        }
    }

    #[cfg(any(feature = "ecdsa", feature = "sm2"))]
    fn sign_digest<'a>(
        &self,
        rng: &mut E::Rng,
        sm2: bool,
        hash: crate::TpmiAlgHash,
        digest: &[u8],
        out: &'a mut SignatureBuffer,
    ) -> Result<crate::TpmsSignatureEcc<'a>, CryptoError> {
        if digest.len() != hash.digest_size() {
            return Err(CryptoError::Internal);
        }
        match_ecc_curve!(match self {
            Self::$Alg(k) => {
                let Some((out_r, rest)) = out.split_first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                let Some(out_s) = rest.first_chunk_mut() else {
                    return Err(CryptoError::Internal);
                };
                if sm2 {
                    E::$Alg::sm2_sign(k, rng, digest, out_r, out_s)?;
                } else {
                    E::$Alg::sign(k, rng, digest, out_r, out_s)?;
                }
                Ok(crate::TpmsSignatureEcc {
                    hash,
                    signature_r: Tpm2bEccParameter::new(out_r).ok_or(CryptoError::Internal)?,
                    signature_s: Tpm2bEccParameter::new(out_s).ok_or(CryptoError::Internal)?,
                })
            },
            #[allow(unreachable_patterns)]
            _ => Err(CryptoError::Unsupported),
        })
    }

    /// Signs the concatenation of `msg` slices with this key using pure `EdDSA`
    /// (`Ed25519` / `Ed448` with an empty context string;
    /// `TPM2_SignSequenceComplete`), writing the signature into `out` and
    /// returning it as a [`TpmtSignature`].
    ///
    /// Returns `Err(`[`CryptoError::Unsupported`]`)` if this isn't an Edwards
    /// key.
    #[cfg(feature = "eddsa")]
    pub fn sign_message<'a>(
        &self,
        msg: &[&[u8]],
        out: &'a mut SignatureBuffer,
    ) -> Result<TpmtSignature<'a>, CryptoError> {
        Ok(TpmtSignature::Eddsa(self.eddsa_sign_message(msg, out)?))
    }

    #[cfg(feature = "eddsa")]
    fn eddsa_sign_message<'a>(
        &self,
        msg: &[&[u8]],
        out: &'a mut SignatureBuffer,
    ) -> Result<crate::Tpm2bSignatureEddsa<'a>, CryptoError> {
        match self {
            #[cfg(feature = "curve25519")]
            Self::Ed25519(k) => {
                let Some(buf) = out.first_chunk_mut::<64>() else {
                    return Err(CryptoError::Internal);
                };
                let (out_r, out_s) = buf.split_first_chunk_mut::<32>().unwrap();
                let out_s: &mut [u8; 32] = out_s.try_into().unwrap();
                E::Ed25519::sign_message(k, msg, out_r, out_s)?;
                crate::Tpm2bSignatureEddsa::new(buf).ok_or(CryptoError::Internal)
            }
            #[cfg(feature = "curve448")]
            Self::Ed448(k) => {
                let Some(buf) = out.first_chunk_mut::<114>() else {
                    return Err(CryptoError::Internal);
                };
                let (out_r, out_s) = buf.split_first_chunk_mut::<57>().unwrap();
                let out_s: &mut [u8; 57] = out_s.try_into().unwrap();
                E::Ed448::sign_message(k, msg, out_r, out_s)?;
                crate::Tpm2bSignatureEddsa::new(buf).ok_or(CryptoError::Internal)
            }
            _ => Err(CryptoError::Unsupported),
        }
    }

    #[cfg(feature = "hash_eddsa")]
    fn eddsa_sign_prehash<'a>(
        &self,
        prehash: &[u8; 64],
        out: &'a mut SignatureBuffer,
    ) -> Result<crate::Tpm2bSignatureEddsa<'a>, CryptoError> {
        match self {
            #[cfg(feature = "curve25519")]
            Self::Ed25519(k) => {
                let Some(buf) = out.first_chunk_mut::<64>() else {
                    return Err(CryptoError::Internal);
                };
                let (out_r, out_s) = buf.split_first_chunk_mut::<32>().unwrap();
                let out_s: &mut [u8; 32] = out_s.try_into().unwrap();
                E::Ed25519::sign_prehash(k, prehash, out_r, out_s)?;
                crate::Tpm2bSignatureEddsa::new(buf).ok_or(CryptoError::Internal)
            }
            #[cfg(feature = "curve448")]
            Self::Ed448(k) => {
                let Some(buf) = out.first_chunk_mut::<114>() else {
                    return Err(CryptoError::Internal);
                };
                let (out_r, out_s) = buf.split_first_chunk_mut::<57>().unwrap();
                let out_s: &mut [u8; 57] = out_s.try_into().unwrap();
                E::Ed448::sign_prehash(k, prehash, out_r, out_s)?;
                crate::Tpm2bSignatureEddsa::new(buf).ok_or(CryptoError::Internal)
            }
            _ => Err(CryptoError::Unsupported),
        }
    }
}

impl<E: Ecc> EccPublicKey<E> {
    /// Verifies `signature` (`ECDSA`, `SM2`, or `HashEdDSA`) over `digest` with
    /// this key (`TPM2_VerifySignature` / `TPM2_VerifyDigestSignature`), with
    /// `digest` as in [`EccPrivateKey::sign`].
    ///
    /// Returns `Ok(false)` if `digest.len()` doesn't match the scheme, the
    /// signature doesn't fit the curve, or verification fails, and
    /// `Err(`[`CryptoError::Unsupported`]`)` for any other scheme (including
    /// `ECDAA`, `ECSchnorr`, and pure `EdDSA`; see
    /// [`verify_message`](Self::verify_message)) or key.
    pub fn verify(&self, digest: &[u8], signature: TpmtSignature<'_>) -> Result<bool, CryptoError> {
        match signature {
            #[cfg(feature = "ecdsa")]
            TpmtSignature::Ecdsa(s) => self.verify_digest(false, s, digest),
            #[cfg(feature = "sm2")]
            TpmtSignature::Sm2(s) => self.verify_digest(true, s, digest),
            #[cfg(feature = "hash_eddsa")]
            TpmtSignature::HashEddsa(sig) => {
                let Ok(prehash) = digest.try_into() else {
                    return Ok(false);
                };
                self.eddsa_verify_prehash(prehash, sig.as_slice())
            }
            // TODO: Add ECSchnorr support.
            _ => {
                let _ = digest;
                Err(CryptoError::Unsupported)
            }
        }
    }

    #[cfg(any(feature = "ecdsa", feature = "sm2"))]
    fn verify_digest(
        &self,
        sm2: bool,
        signature: crate::TpmsSignatureEcc<'_>,
        digest: &[u8],
    ) -> Result<bool, CryptoError> {
        if digest.len() != signature.hash.digest_size() {
            return Ok(false);
        }
        match_ecc_curve!(match self {
            Self::$Alg(k) => {
                let (Some(r), Some(s)) = (
                    left_pad_be(signature.signature_r.as_slice()),
                    left_pad_be(signature.signature_s.as_slice()),
                ) else {
                    return Ok(false);
                };
                if sm2 {
                    E::$Alg::sm2_verify(k, digest, &r, &s)
                } else {
                    E::$Alg::verify(k, digest, &r, &s)
                }
            },
            #[allow(unreachable_patterns)]
            _ => Err(CryptoError::Unsupported),
        })
    }

    /// Verifies pure `EdDSA` `signature` over the concatenation of `msg` slices
    /// with this key (`TPM2_VerifySequenceComplete`).
    ///
    /// Returns `Ok(false)` if the signature size doesn't match the key or
    /// verification fails, and `Err(`[`CryptoError::Unsupported`]`)` for any
    /// other scheme or key.
    #[cfg(feature = "eddsa")]
    pub fn verify_message(
        &self,
        msg: &[&[u8]],
        signature: TpmtSignature<'_>,
    ) -> Result<bool, CryptoError> {
        match signature {
            TpmtSignature::Eddsa(sig) => self.eddsa_verify_message(msg, sig.as_slice()),
            _ => Err(CryptoError::Unsupported),
        }
    }

    #[cfg(feature = "eddsa")]
    fn eddsa_verify_message(&self, msg: &[&[u8]], sig: &[u8]) -> Result<bool, CryptoError> {
        match self {
            #[cfg(feature = "curve25519")]
            Self::Ed25519(k) => {
                let Ok(buf): Result<&[u8; 64], _> = sig.try_into() else {
                    return Ok(false);
                };
                let (sig_r, sig_s) = buf.split_first_chunk::<32>().unwrap();
                let sig_s: &[u8; 32] = sig_s.try_into().unwrap();
                E::Ed25519::verify_message(k, msg, sig_r, sig_s)
            }
            #[cfg(feature = "curve448")]
            Self::Ed448(k) => {
                let Ok(buf): Result<&[u8; 114], _> = sig.try_into() else {
                    return Ok(false);
                };
                let (sig_r, sig_s) = buf.split_first_chunk::<57>().unwrap();
                let sig_s: &[u8; 57] = sig_s.try_into().unwrap();
                E::Ed448::verify_message(k, msg, sig_r, sig_s)
            }
            _ => Err(CryptoError::Unsupported),
        }
    }

    #[cfg(feature = "hash_eddsa")]
    fn eddsa_verify_prehash(&self, prehash: &[u8; 64], sig: &[u8]) -> Result<bool, CryptoError> {
        match self {
            #[cfg(feature = "curve25519")]
            Self::Ed25519(k) => {
                let Ok(buf): Result<&[u8; 64], _> = sig.try_into() else {
                    return Ok(false);
                };
                let (sig_r, sig_s) = buf.split_first_chunk::<32>().unwrap();
                let sig_s: &[u8; 32] = sig_s.try_into().unwrap();
                E::Ed25519::verify_prehash(k, prehash, sig_r, sig_s)
            }
            #[cfg(feature = "curve448")]
            Self::Ed448(k) => {
                let Ok(buf): Result<&[u8; 114], _> = sig.try_into() else {
                    return Ok(false);
                };
                let (sig_r, sig_s) = buf.split_first_chunk::<57>().unwrap();
                let sig_s: &[u8; 57] = sig_s.try_into().unwrap();
                E::Ed448::verify_prehash(k, prehash, sig_r, sig_s)
            }
            _ => Err(CryptoError::Unsupported),
        }
    }
}

// tpm-rs extensions: point arithmetic on the Weierstrass curves.

/// Multiplies the base point `G` of the Weierstrass curve `curve` by the
/// big-endian scalar `scalar` ([`EccCurve::mul_generator`]), writing `[k]G` into
/// `out_x` and `out_y`.
///
/// This is a tpm-rs extension. `scalar` may be shorter than the curve size (it
/// is left-padded with zeros). Returns `Ok(None)` if `scalar` is empty, longer
/// than `curve.key_bytes()`, or not in `[1, n - 1]`, and
/// `Err(`[`CryptoError::Unsupported`]`)` for curves other than the Weierstrass
/// curves (`Curve25519`, `Curve448`) or curves unsupported by the backend.
/// `out_x` and `out_y` must be at least `curve.key_bytes()` bytes (e.g.
/// [`EccCoordBuffer`]), or [`CryptoError::Internal`] is returned.
pub fn ecc_mul_generator<'a, E: Ecc>(
    curve: TpmEccCurve,
    scalar: &[u8],
    out_x: &'a mut [u8],
    out_y: &'a mut [u8],
) -> Result<Option<TpmsEccPoint<'a>>, CryptoError> {
    let _ = (&scalar, &out_x, &out_y);
    match_ecc_curve!(match curve {
        TpmEccCurve::$Alg => {
            let (Some(bx), Some(by)) = (out_x.first_chunk_mut(), out_y.first_chunk_mut()) else {
                return Err(CryptoError::Internal);
            };
            let Some(k) = left_pad_be(scalar) else {
                return Ok(None);
            };
            match E::$Alg::mul_generator(&k, bx, by)? {
                Some(()) => Ok(Some(TpmsEccPoint {
                    x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                    y: Tpm2bEccParameter::new(by).ok_or(CryptoError::Internal)?,
                })),
                None => Ok(None),
            }
        },
        #[allow(unreachable_patterns)]
        _ => Err(CryptoError::Unsupported),
    })
}

impl<E: Ecc> EccPublicKey<E> {
    /// Multiplies this Weierstrass public key (point) by the big-endian scalar
    /// `scalar` ([`EccCurve::mul_point`]), writing `[k]P` into `out_x` and
    /// `out_y`.
    ///
    /// This is a tpm-rs extension. Use [`EccPublicKey::load`] (with no scheme)
    /// to validate a point before multiplying it. `scalar` may be shorter than
    /// the curve size (it is left-padded with zeros). Returns `Ok(None)` if
    /// `scalar` is empty, longer than `self.key_bytes()`, or not in
    /// `[1, n - 1]`, or if the result is the point at infinity, and
    /// `Err(`[`CryptoError::Unsupported`]`)` for Edwards and Montgomery keys.
    /// `out_x` and `out_y` must be at least `self.key_bytes()` bytes, or
    /// [`CryptoError::Internal`] is returned.
    pub fn mul_point<'a>(
        &self,
        scalar: &[u8],
        out_x: &'a mut [u8],
        out_y: &'a mut [u8],
    ) -> Result<Option<TpmsEccPoint<'a>>, CryptoError> {
        let _ = (&scalar, &out_x, &out_y);
        match_ecc_curve!(match self {
            Self::$Alg(p) => {
                let (Some(bx), Some(by)) = (out_x.first_chunk_mut(), out_y.first_chunk_mut())
                else {
                    return Err(CryptoError::Internal);
                };
                let Some(k) = left_pad_be(scalar) else {
                    return Ok(None);
                };
                match E::$Alg::mul_point(p, &k, bx, by)? {
                    Some(()) => Ok(Some(TpmsEccPoint {
                        x: Tpm2bEccParameter::new(bx).ok_or(CryptoError::Internal)?,
                        y: Tpm2bEccParameter::new(by).ok_or(CryptoError::Internal)?,
                    })),
                    None => Ok(None),
                }
            },
            #[allow(unreachable_patterns)]
            _ => Err(CryptoError::Unsupported),
        })
    }
}

impl<E: Ecc> EccPrivateKey<E> {
    /// Loads the Weierstrass private key of `curve` with the big-endian secret
    /// scalar `scalar`, computing its public key `[d]G` with
    /// [`EccCurve::mul_generator`].
    ///
    /// This is a tpm-rs extension, for keys whose public point is not at hand
    /// (e.g. keys derived by the TPM, or the ephemeral keys of a scheme).
    /// `scalar` may be shorter than the curve size (it is left-padded with
    /// zeros). Returns `Ok(None)` if `scalar` is empty, longer than
    /// `curve.key_bytes()`, or not in `[1, n - 1]`, and
    /// `Err(`[`CryptoError::Unsupported`]`)` for `Curve25519`/`Curve448` and
    /// curves unsupported by the backend.
    pub fn from_scalar(curve: TpmEccCurve, scalar: &[u8]) -> Result<Option<Self>, CryptoError> {
        let _ = &scalar;
        match_ecc_curve!(match curve {
            TpmEccCurve::$Alg => {
                let Some(d) = left_pad_be(scalar) else {
                    return Ok(None);
                };
                let mut q = [0u8; _];
                let (qx, qy) = q.split_at_mut(d.len());
                let (Some(qx), Some(qy)) = (qx.first_chunk_mut(), qy.first_chunk_mut()) else {
                    return Err(CryptoError::Internal);
                };
                if E::$Alg::mul_generator(&d, qx, qy)?.is_none() {
                    return Ok(None);
                }
                let Some(public) = E::$Alg::load_public((), &q)? else {
                    return Err(CryptoError::Internal);
                };
                Ok(E::$Alg::load(public, &d)?.map(Self::$Alg))
            },
            #[allow(unreachable_patterns)]
            _ => Err(CryptoError::Unsupported),
        })
    }
}
