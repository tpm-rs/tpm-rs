//! [`Ecc`] keys and ECDH.

use core::fmt;

use elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytes, NonZeroScalar, PrimeCurve, PublicKey,
    group::Curve as _,
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use sm2::Sm2;
use tpm2::{
    Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint,
    crypto::{CryptoError, Ecc},
};

use crate::{ChaChaRng, RustCrypto};

/// An elliptic curve supported by this backend.
pub(crate) trait EcCurve:
    PrimeCurve
    + CurveArithmetic<AffinePoint: FromEncodedPoint<Self> + ToEncodedPoint<Self>>
    + elliptic_curve::Curve<FieldBytesSize: ModulusSize>
{
    fn wrap_point(point: PublicKey<Self>) -> EccPoint;
    fn wrap_scalar(scalar: NonZeroScalar<Self>) -> EccScalar;
}

macro_rules! impl_ec_curve {
    ($curve:ty, $variant:ident) => {
        impl EcCurve for $curve {
            fn wrap_point(point: PublicKey<Self>) -> EccPoint {
                EccPoint::$variant(point)
            }
            fn wrap_scalar(scalar: NonZeroScalar<Self>) -> EccScalar {
                EccScalar::$variant(scalar)
            }
        }
    };
}
impl_ec_curve!(NistP256, P256);
impl_ec_curve!(NistP384, P384);
impl_ec_curve!(NistP521, P521);
impl_ec_curve!(Sm2, Sm2);

/// Evaluates `$body` with `$var` bound to the curve-specific value inside an
/// [`EccPoint`] or [`EccScalar`].
macro_rules! dispatch {
    ($enum:ident, $value:expr, $var:ident => $body:expr) => {
        match $value {
            $enum::P256($var) => $body,
            $enum::P384($var) => $body,
            $enum::P521($var) => $body,
            $enum::Sm2($var) => $body,
        }
    };
}
pub(crate) use dispatch;

/// ECC public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EccPublicKey(pub(crate) EccPoint);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EccPoint {
    P256(PublicKey<NistP256>),
    P384(PublicKey<NistP384>),
    P521(PublicKey<NistP521>),
    Sm2(PublicKey<Sm2>),
}

/// ECC private key.
#[derive(Clone)]
pub struct EccPrivateKey {
    public: EccPublicKey,
    pub(crate) secret: EccScalar,
}

#[derive(Clone)]
pub(crate) enum EccScalar {
    P256(NonZeroScalar<NistP256>),
    P384(NonZeroScalar<NistP384>),
    P521(NonZeroScalar<NistP521>),
    Sm2(NonZeroScalar<Sm2>),
}

impl fmt::Debug for EccPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EccPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl tpm2::crypto::EccPublicKey for EccPublicKey {
    fn curve(&self) -> TpmEccCurve {
        match self.0 {
            EccPoint::P256(_) => TpmEccCurve::NistP256,
            EccPoint::P384(_) => TpmEccCurve::NistP384,
            EccPoint::P521(_) => TpmEccCurve::NistP521,
            EccPoint::Sm2(_) => TpmEccCurve::SM2P256,
        }
    }

    fn point<'a>(
        &self,
        out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<TpmsEccPoint<'a>, CryptoError> {
        dispatch!(EccPoint, &self.0, q => write_public(q, out_x, out_y))
    }
}

impl tpm2::crypto::EccPrivateKey for EccPrivateKey {
    type PublicKey = EccPublicKey;

    fn public_key(&self) -> &EccPublicKey {
        &self.public
    }

    fn scalar<'a>(
        &self,
        out: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<Tpm2bEccParameter<'a>, CryptoError> {
        dispatch!(EccScalar, &self.secret, d => write_scalar(d, out))
    }
}

impl Ecc for RustCrypto {
    type PublicKey = EccPublicKey;
    type PrivateKey = EccPrivateKey;

    fn load_public(
        &self,
        curve: TpmEccCurve,
        point: TpmsEccPoint<'_>,
    ) -> Result<Option<EccPublicKey>, CryptoError> {
        let (x, y) = (point.x.as_slice(), point.y.as_slice());
        Ok(match curve {
            TpmEccCurve::NistP256 => load_point::<NistP256>(x, y),
            TpmEccCurve::NistP384 => load_point::<NistP384>(x, y),
            TpmEccCurve::NistP521 => load_point::<NistP521>(x, y),
            TpmEccCurve::SM2P256 => load_point::<Sm2>(x, y),
            _ => return Err(CryptoError::Unsupported),
        })
    }

    fn load_private(
        &self,
        public: EccPublicKey,
        scalar: Tpm2bEccParameter<'_>,
    ) -> Result<Option<EccPrivateKey>, CryptoError> {
        let secret = dispatch!(EccPoint, &public.0, q => load_scalar(q, scalar.as_slice()));
        Ok(secret.map(|secret| EccPrivateKey { public, secret }))
    }

    fn generate_key(
        &self,
        rng: &mut ChaChaRng,
        curve: TpmEccCurve,
    ) -> Result<EccPrivateKey, CryptoError> {
        Ok(match curve {
            TpmEccCurve::NistP256 => generate::<NistP256>(rng),
            TpmEccCurve::NistP384 => generate::<NistP384>(rng),
            TpmEccCurve::NistP521 => generate::<NistP521>(rng),
            TpmEccCurve::SM2P256 => generate::<Sm2>(rng),
            _ => return Err(CryptoError::Unsupported),
        })
    }

    fn ecdh<'a>(
        &self,
        private: &EccPrivateKey,
        peer_public: &EccPublicKey,
        out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<Option<TpmsEccPoint<'a>>, CryptoError> {
        match (&private.secret, &peer_public.0) {
            (EccScalar::P256(d), EccPoint::P256(q)) => ecdh(d, q, out_x, out_y),
            (EccScalar::P384(d), EccPoint::P384(q)) => ecdh(d, q, out_x, out_y),
            (EccScalar::P521(d), EccPoint::P521(q)) => ecdh(d, q, out_x, out_y),
            (EccScalar::Sm2(d), EccPoint::Sm2(q)) => ecdh(d, q, out_x, out_y),
            // The keys are on different curves.
            _ => Err(CryptoError::Unsupported),
        }
    }
}

/// Converts a big-endian integer (of any length, ignoring leading zeros) into
/// [`FieldBytes`], returning `None` if it is too large to fit.
pub(crate) fn int_to_field<C: EcCurve>(bytes: &[u8]) -> Option<FieldBytes<C>> {
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let bytes = bytes.get(skip..)?;
    let mut out = FieldBytes::<C>::default();
    let pad = out.len().checked_sub(bytes.len())?;
    out.get_mut(pad..)?.copy_from_slice(bytes);
    Some(out)
}

/// Parses a big-endian integer in `[1, n - 1]` (where `n` is the order of `C`).
pub(crate) fn parse_scalar<C: EcCurve>(bytes: &[u8]) -> Option<NonZeroScalar<C>> {
    NonZeroScalar::from_repr(int_to_field::<C>(bytes)?).into()
}

/// Writes `bytes` into `out`, returning them as a [`Tpm2bEccParameter`].
pub(crate) fn write_param<'a>(
    bytes: &[u8],
    out: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
) -> Result<Tpm2bEccParameter<'a>, CryptoError> {
    let out = out.get_mut(..bytes.len()).ok_or(CryptoError::Internal)?;
    out.copy_from_slice(bytes);
    Tpm2bEccParameter::new(out).ok_or(CryptoError::Internal)
}

/// Writes the affine coordinates of `point`, returning `Ok(None)` for the
/// point at infinity.
fn write_point<'a, C: EcCurve>(
    point: &AffinePoint<C>,
    out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
) -> Result<Option<TpmsEccPoint<'a>>, CryptoError> {
    let encoded = point.to_encoded_point(false);
    let (Some(x), Some(y)) = (encoded.x(), encoded.y()) else {
        return Ok(None);
    };
    Ok(Some(TpmsEccPoint {
        x: write_param(x, out_x)?,
        y: write_param(y, out_y)?,
    }))
}

/// Writes the affine coordinates of the public key `q`.
fn write_public<'a, C: EcCurve>(
    q: &PublicKey<C>,
    out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
) -> Result<TpmsEccPoint<'a>, CryptoError> {
    // A public key is never the point at infinity.
    write_point::<C>(q.as_affine(), out_x, out_y)?.ok_or(CryptoError::Internal)
}

/// Writes the secret scalar `d` as a big-endian integer the size of the field.
fn write_scalar<'a, C: EcCurve>(
    d: &NonZeroScalar<C>,
    out: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
) -> Result<Tpm2bEccParameter<'a>, CryptoError> {
    write_param(&FieldBytes::<C>::from(d), out)
}

/// Loads the public key `(x, y)`, returning `None` if it isn't a point on
/// `C` (other than the point at infinity).
fn load_point<C: EcCurve>(x: &[u8], y: &[u8]) -> Option<EccPublicKey> {
    let (x, y) = (int_to_field::<C>(x)?, int_to_field::<C>(y)?);
    let encoded = EncodedPoint::<C>::from_affine_coordinates(&x, &y, false);
    let point = Option::from(AffinePoint::<C>::from_encoded_point(&encoded))?;
    let public = PublicKey::from_affine(point).ok()?;
    Some(EccPublicKey(C::wrap_point(public)))
}

/// Loads the secret scalar `d` of `public`, returning `None` if it is out of
/// range or doesn't match `public`.
fn load_scalar<C: EcCurve>(public: &PublicKey<C>, d: &[u8]) -> Option<EccScalar> {
    let d = parse_scalar::<C>(d)?;
    (PublicKey::from_secret_scalar(&d) == *public).then(|| C::wrap_scalar(d))
}

fn generate<C: EcCurve>(rng: &mut ChaChaRng) -> EccPrivateKey {
    let d = NonZeroScalar::<C>::random(&mut rng.0);
    let public = EccPublicKey(C::wrap_point(PublicKey::from_secret_scalar(&d)));
    EccPrivateKey {
        public,
        secret: C::wrap_scalar(d),
    }
}

fn ecdh<'a, C: EcCurve>(
    d: &NonZeroScalar<C>,
    q: &PublicKey<C>,
    out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
) -> Result<Option<TpmsEccPoint<'a>>, CryptoError> {
    // All supported curves have a cofactor of 1, so `Z = [d]Q`.
    let z = (q.to_projective() * **d).to_affine();
    write_point::<C>(&z, out_x, out_y)
}
