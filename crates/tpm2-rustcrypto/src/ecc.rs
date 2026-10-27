//! Weierstrass curve keys (`ECDH` and `ECDSA`), generic over the curve.

use core::ops::Mul;

use ecdsa::{EcdsaCurve, Signature, hazmat};
use elliptic_curve::{
    CurveArithmetic, FieldBytes, FieldBytesSize, Generate, NonZeroScalar, PublicKey, SecretKey,
    array::{ArraySize, typenum::U2},
    group::Curve as _,
    sec1::{FromSec1Point, ModulusSize, Sec1Point, ToSec1Point},
};
use tpm2::crypto::{
    CryptoError,
    backend::{EccCurve, PrivateKey},
};

use crate::{ChaChaRng, RngWrapper};

/// Weierstrass curve private key, storing both the private scalar and the
/// public point.
pub struct EccKeyPair<C: CurveArithmetic> {
    private: SecretKey<C>,
    public: PublicKey<C>,
}

/// Selects a curve's `ECDSA` implementation: SM2 has none, and
/// `ecdsa::EcdsaCurve` (which SM2 doesn't implement) can't be used to exclude
/// it from a generic impl.
pub trait Ecdsa: CurveArithmetic {
    /// [`EcdsaSupported`] or [`EcdsaUnsupported`].
    type Impl: EcdsaImpl<Self>;
}

/// `ECDSA` signing (with the nonce `k`) and verification of a digest `z`.
pub trait EcdsaImpl<C: CurveArithmetic> {
    /// Returns the signature `(r, s)`.
    fn sign(
        d: &NonZeroScalar<C>,
        k: &NonZeroScalar<C>,
        z: &[u8],
    ) -> Result<(FieldBytes<C>, FieldBytes<C>), CryptoError>;

    /// Returns whether `(r, s)` is a valid signature.
    fn verify(
        q: &PublicKey<C>,
        z: &[u8],
        r: FieldBytes<C>,
        s: FieldBytes<C>,
    ) -> Result<bool, CryptoError>;
}

/// `ECDSA` via `ecdsa::hazmat`.
pub struct EcdsaSupported;

impl<C: EcdsaCurve + CurveArithmetic> EcdsaImpl<C> for EcdsaSupported {
    fn sign(
        d: &NonZeroScalar<C>,
        k: &NonZeroScalar<C>,
        z: &[u8],
    ) -> Result<(FieldBytes<C>, FieldBytes<C>), CryptoError> {
        let (sig, _) = hazmat::sign_prehashed::<C>(d, k, z).map_err(|_| CryptoError::Internal)?;
        Ok(sig.split_bytes())
    }

    fn verify(
        q: &PublicKey<C>,
        z: &[u8],
        r: FieldBytes<C>,
        s: FieldBytes<C>,
    ) -> Result<bool, CryptoError> {
        Ok(Signature::<C>::from_scalars(r, s)
            .is_ok_and(|sig| hazmat::verify_prehashed(&q.to_projective(), z, &sig).is_ok()))
    }
}

/// No `ECDSA`: returns [`CryptoError::Unsupported`].
pub struct EcdsaUnsupported;

impl<C: CurveArithmetic> EcdsaImpl<C> for EcdsaUnsupported {
    fn sign(
        _: &NonZeroScalar<C>,
        _: &NonZeroScalar<C>,
        _: &[u8],
    ) -> Result<(FieldBytes<C>, FieldBytes<C>), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    fn verify(
        _: &PublicKey<C>,
        _: &[u8],
        _: FieldBytes<C>,
        _: FieldBytes<C>,
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

impl Ecdsa for p192::NistP192 {
    type Impl = EcdsaSupported;
}
impl Ecdsa for p224::NistP224 {
    type Impl = EcdsaSupported;
}
impl Ecdsa for p256::NistP256 {
    type Impl = EcdsaSupported;
}
impl Ecdsa for p384::NistP384 {
    type Impl = EcdsaSupported;
}
impl Ecdsa for p521::NistP521 {
    type Impl = EcdsaSupported;
}
impl Ecdsa for sm2::Sm2 {
    type Impl = EcdsaUnsupported;
}

/// Writes the affine coordinates of `point` to `out_x` and `out_y`.
fn write_point<C>(
    point: &PublicKey<C>,
    out_x: &mut [u8],
    out_y: &mut [u8],
) -> Result<(), CryptoError>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let pt = point.to_sec1_point(false);
    let (Some(x), Some(y)) = (pt.x(), pt.y()) else {
        return Err(CryptoError::Internal);
    };
    out_x.copy_from_slice(x);
    out_y.copy_from_slice(y);
    Ok(())
}

impl<C, const SIZE: usize, const POINT_SIZE: usize> PrivateKey<POINT_SIZE, SIZE, ChaChaRng>
    for EccKeyPair<C>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize
        + ArraySize<ArrayType<u8> = [u8; SIZE]>
        + Mul<U2, Output: ArraySize<ArrayType<u8> = [u8; POINT_SIZE]>>,
{
    type PublicKey = PublicKey<C>;

    fn generate(rng: &mut ChaChaRng, _: ()) -> Result<Self, CryptoError> {
        let private = SecretKey::<C>::generate_from_rng(&mut RngWrapper(rng));
        let public = private.public_key();
        Ok(EccKeyPair { private, public })
    }

    fn load_public(
        _: (),
        public: &[u8; POINT_SIZE],
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        let (x, y) = public.split_at(SIZE);
        let (x, y) = (x.try_into(), y.try_into());
        let (Ok(x), Ok(y)) = (x, y) else {
            return Err(CryptoError::Internal);
        };
        let pt = Sec1Point::<C>::from_affine_coordinates(&x, &y, false);
        Ok(PublicKey::<C>::from_sec1_point(&pt).into_option())
    }

    fn store_public(
        public: &Self::PublicKey,
        out: &mut [u8; POINT_SIZE],
    ) -> Result<(), CryptoError> {
        let (out_x, out_y) = out.split_at_mut(SIZE);
        write_point(public, out_x, out_y)
    }

    fn load(public: Self::PublicKey, scalar: &[u8; SIZE]) -> Result<Option<Self>, CryptoError> {
        let Ok(private) = SecretKey::<C>::from_slice(scalar) else {
            return Ok(None);
        };
        // Both points are public.
        if private.public_key() != public {
            return Ok(None);
        }
        Ok(Some(EccKeyPair { private, public }))
    }

    fn store(&self, out: &mut [u8; SIZE]) -> Result<(), CryptoError> {
        out.copy_from_slice(&self.private.to_bytes());
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }
}

impl<C, const SIZE: usize, const POINT_SIZE: usize> EccCurve<SIZE, POINT_SIZE, ChaChaRng>
    for EccKeyPair<C>
where
    C: Ecdsa,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize
        + ArraySize<ArrayType<u8> = [u8; SIZE]>
        + Mul<U2, Output: ArraySize<ArrayType<u8> = [u8; POINT_SIZE]>>,
{
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_x: &mut [u8; SIZE],
        out_y: &mut [u8; SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let shared = peer_public.to_projective() * *self.private.to_nonzero_scalar();
        // Fails for the point at infinity.
        let Ok(shared) = PublicKey::<C>::from_affine(shared.to_affine()) else {
            return Ok(None);
        };
        write_point(&shared, out_x, out_y).map(Some)
    }

    fn sign(
        &self,
        rng: &mut ChaChaRng,
        digest: &[u8],
        out_r: &mut [u8; SIZE],
        out_s: &mut [u8; SIZE],
    ) -> Result<(), CryptoError> {
        let k = NonZeroScalar::<C>::generate_from_rng(&mut RngWrapper(rng));
        let (r, s) = C::Impl::sign(&self.private.to_nonzero_scalar(), &k, digest)?;
        out_r.copy_from_slice(&r);
        out_s.copy_from_slice(&s);
        Ok(())
    }

    fn verify(
        public: &Self::PublicKey,
        digest: &[u8],
        sig_r: &[u8; SIZE],
        sig_s: &[u8; SIZE],
    ) -> Result<bool, CryptoError> {
        C::Impl::verify(public, digest, (*sig_r).into(), (*sig_s).into())
    }
}
