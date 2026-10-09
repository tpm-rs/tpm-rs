//! [`Ecc`] implementation: NIST P-256 using libcrux, and NIST P-384 and P-521
//! using RustCrypto (libcrux only implements P-256).

use rand_chacha::rand_core::RngCore;
use tpm2::crypto::{CryptoError, Ecc};
use tpm2::{Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint};

use crate::{ChaChaRng, Libcrux, left_pad, pad_into, write};

/// P-256 coordinate and scalar size in bytes.
pub(crate) const P256_BYTES: usize = TpmEccCurve::NistP256.key_bytes();
/// P-384 coordinate and scalar size in bytes.
pub(crate) const P384_BYTES: usize = TpmEccCurve::NistP384.key_bytes();
/// P-521 coordinate and scalar size in bytes.
pub(crate) const P521_BYTES: usize = TpmEccCurve::NistP521.key_bytes();

/// The number of candidates [`p256_random_scalar`] tries before giving up.
pub(crate) const MAX_ATTEMPTS: usize = 64;

/// ECC public key handle for [`Ecc::PublicKey`].
pub struct EccPublic(pub(crate) Public);

/// A validated public point (on the curve and not the point at infinity).
pub(crate) enum Public {
    /// The affine coordinates `x || y`.
    P256([u8; 2 * P256_BYTES]),
    P384(p384::PublicKey),
    P521(p521::PublicKey),
}

/// ECC private key handle for [`Ecc::PrivateKey`].
pub struct EccPrivate {
    public: EccPublic,
    pub(crate) secret: Secret,
}

/// A validated secret scalar in `[1, n - 1]`.
pub(crate) enum Secret {
    /// The big-endian scalar.
    P256([u8; P256_BYTES]),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

impl tpm2::crypto::EccPublicKey for EccPublic {
    fn curve(&self) -> TpmEccCurve {
        match self.0 {
            Public::P256(_) => TpmEccCurve::NistP256,
            Public::P384(_) => TpmEccCurve::NistP384,
            Public::P521(_) => TpmEccCurve::NistP521,
        }
    }

    fn point<'a>(
        &self,
        out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<TpmsEccPoint<'a>, CryptoError> {
        use p384::elliptic_curve::sec1::ToEncodedPoint as _;
        match &self.0 {
            Public::P256(xy) => {
                let (x, y) = xy.split_at(P256_BYTES);
                write_point(x, y, out_x, out_y)
            }
            Public::P384(public) => {
                let point = public.to_encoded_point(false);
                let (x, y) = point.x().zip(point.y()).ok_or(CryptoError::Internal)?;
                write_point(x, y, out_x, out_y)
            }
            Public::P521(public) => {
                let point = public.to_encoded_point(false);
                let (x, y) = point.x().zip(point.y()).ok_or(CryptoError::Internal)?;
                write_point(x, y, out_x, out_y)
            }
        }
    }
}

impl tpm2::crypto::EccPrivateKey for EccPrivate {
    type PublicKey = EccPublic;

    fn public_key(&self) -> &EccPublic {
        &self.public
    }

    fn scalar<'a>(
        &self,
        out: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<Tpm2bEccParameter<'a>, CryptoError> {
        match &self.secret {
            Secret::P256(d) => write_param(d, out),
            Secret::P384(d) => write_param(&d.to_bytes(), out),
            Secret::P521(d) => write_param(&d.to_bytes(), out),
        }
    }
}

/// Copies `value` into `out` and returns it as a [`Tpm2bEccParameter`].
pub(crate) fn write_param<'a>(
    value: &[u8],
    out: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
) -> Result<Tpm2bEccParameter<'a>, CryptoError> {
    Tpm2bEccParameter::new(write(value, out)?).ok_or(CryptoError::Internal)
}

/// Copies the coordinates `x` and `y` into `out_x` and `out_y` and returns
/// them as a [`TpmsEccPoint`].
fn write_point<'a>(
    x: &[u8],
    y: &[u8],
    out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
) -> Result<TpmsEccPoint<'a>, CryptoError> {
    Ok(TpmsEccPoint {
        x: write_param(x, out_x)?,
        y: write_param(y, out_y)?,
    })
}

/// Encodes `(x, y)` as an uncompressed SEC1 point `0x04 || x || y` with
/// `len`-byte coordinates.
///
/// Returns `None` if a coordinate is longer than `len` bytes.
fn sec1_point<'a>(
    x: &[u8],
    y: &[u8],
    len: usize,
    out: &'a mut [u8; 1 + 2 * P521_BYTES],
) -> Option<&'a [u8]> {
    let out = out.get_mut(..1 + 2 * len)?;
    let (tag, coordinates) = out.split_first_mut()?;
    *tag = 0x04;
    let (out_x, out_y) = coordinates.split_at_mut(len);
    pad_into(x, out_x)?;
    pad_into(y, out_y)?;
    Some(out)
}

/// Samples a uniformly random P-256 scalar in `[1, n - 1]` from `rng` by
/// rejection sampling.
pub(crate) fn p256_random_scalar(rng: &mut impl RngCore) -> Result<[u8; P256_BYTES], CryptoError> {
    // A random 256-bit value is in range with probability greater than
    // `1 - 2^-32`, so running out of attempts means the RNG is broken.
    for _ in 0..MAX_ATTEMPTS {
        let mut d = [0u8; P256_BYTES];
        rng.fill_bytes(&mut d);
        if libcrux_p256::validate_private_key(&d) {
            return Ok(d);
        }
    }
    Err(CryptoError::Internal)
}

impl Ecc for Libcrux {
    type PublicKey = EccPublic;
    type PrivateKey = EccPrivate;

    fn load_public(
        &self,
        curve: TpmEccCurve,
        point: TpmsEccPoint<'_>,
    ) -> Result<Option<EccPublic>, CryptoError> {
        let (x, y) = (point.x.as_slice(), point.y.as_slice());
        let mut sec1 = [0u8; 1 + 2 * P521_BYTES];
        let public = match curve {
            TpmEccCurve::NistP256 => {
                let mut xy = [0u8; 2 * P256_BYTES];
                let (out_x, out_y) = xy.split_at_mut(P256_BYTES);
                // Checks that the coordinates are less than `p` and that the
                // point is on the curve.
                if pad_into(x, out_x).is_none()
                    || pad_into(y, out_y).is_none()
                    || !libcrux_p256::validate_public_key(&xy)
                {
                    return Ok(None);
                }
                Public::P256(xy)
            }
            // `from_sec1_bytes` checks that the coordinates are less than `p`
            // and that the point is on the curve.
            TpmEccCurve::NistP384 => {
                let sec1 = sec1_point(x, y, P384_BYTES, &mut sec1);
                match sec1.map(p384::PublicKey::from_sec1_bytes) {
                    Some(Ok(public)) => Public::P384(public),
                    _ => return Ok(None),
                }
            }
            TpmEccCurve::NistP521 => {
                let sec1 = sec1_point(x, y, P521_BYTES, &mut sec1);
                match sec1.map(p521::PublicKey::from_sec1_bytes) {
                    Some(Ok(public)) => Public::P521(public),
                    _ => return Ok(None),
                }
            }
            _ => return Err(CryptoError::Unsupported),
        };
        Ok(Some(EccPublic(public)))
    }

    fn load_private(
        &self,
        public: EccPublic,
        scalar: Tpm2bEccParameter<'_>,
    ) -> Result<Option<EccPrivate>, CryptoError> {
        let scalar = scalar.as_slice();
        // Each arm checks that `d` is in `[1, n - 1]` and that `d * G` is the
        // public point.
        let secret = match &public.0 {
            Public::P256(q) => {
                let mut derived = [0u8; 2 * P256_BYTES];
                match left_pad::<P256_BYTES>(scalar) {
                    Some(d) if libcrux_p256::dh_initiator(&mut derived, &d) && derived == *q => {
                        Secret::P256(d)
                    }
                    _ => return Ok(None),
                }
            }
            Public::P384(q) => {
                let d = left_pad::<P384_BYTES>(scalar);
                match d.map(|d| p384::SecretKey::from_slice(&d)) {
                    Some(Ok(d)) if d.public_key() == *q => Secret::P384(d),
                    _ => return Ok(None),
                }
            }
            Public::P521(q) => {
                let d = left_pad::<P521_BYTES>(scalar);
                match d.map(|d| p521::SecretKey::from_slice(&d)) {
                    Some(Ok(d)) if d.public_key() == *q => Secret::P521(d),
                    _ => return Ok(None),
                }
            }
        };
        Ok(Some(EccPrivate { public, secret }))
    }

    fn generate_key(
        &self,
        rng: &mut ChaChaRng,
        curve: TpmEccCurve,
    ) -> Result<EccPrivate, CryptoError> {
        let (public, secret) = match curve {
            TpmEccCurve::NistP256 => {
                let d = p256_random_scalar(&mut rng.0)?;
                let mut q = [0u8; 2 * P256_BYTES];
                if !libcrux_p256::dh_initiator(&mut q, &d) {
                    return Err(CryptoError::Internal);
                }
                (Public::P256(q), Secret::P256(d))
            }
            TpmEccCurve::NistP384 => {
                let d = p384::SecretKey::random(&mut rng.0);
                (Public::P384(d.public_key()), Secret::P384(d))
            }
            TpmEccCurve::NistP521 => {
                let d = p521::SecretKey::random(&mut rng.0);
                (Public::P521(d.public_key()), Secret::P521(d))
            }
            _ => return Err(CryptoError::Unsupported),
        };
        Ok(EccPrivate {
            public: EccPublic(public),
            secret,
        })
    }

    fn ecdh<'a>(
        &self,
        private: &EccPrivate,
        peer_public: &EccPublic,
        out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<Option<TpmsEccPoint<'a>>, CryptoError> {
        use tpm2::crypto::EccPublicKey as _;
        let shared = match (&private.secret, &peer_public.0) {
            (Secret::P256(d), Public::P256(q)) => {
                let mut z = [0u8; 2 * P256_BYTES];
                // Both keys were validated when they were loaded and P-256 has
                // prime order, so this can't fail or produce the point at
                // infinity.
                if !libcrux_p256::dh_responder(&mut z, q, d) {
                    return Err(CryptoError::Internal);
                }
                Public::P256(z)
            }
            (Secret::P384(d), Public::P384(q)) => {
                let z = p384::ProjectivePoint::from(*q.as_affine()) * *d.to_nonzero_scalar();
                // `from_affine` rejects the point at infinity.
                match p384::PublicKey::from_affine(z.to_affine()) {
                    Ok(z) => Public::P384(z),
                    Err(_) => return Ok(None),
                }
            }
            (Secret::P521(d), Public::P521(q)) => {
                let z = p521::ProjectivePoint::from(*q.as_affine()) * *d.to_nonzero_scalar();
                match p521::PublicKey::from_affine(z.to_affine()) {
                    Ok(z) => Public::P521(z),
                    Err(_) => return Ok(None),
                }
            }
            // The keys are on different curves.
            _ => return Err(CryptoError::Unsupported),
        };
        EccPublic(shared).point(out_x, out_y).map(Some)
    }
}
