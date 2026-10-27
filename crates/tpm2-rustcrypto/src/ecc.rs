#![allow(unused_imports)]
//! ECC trait implementations
use elliptic_curve::{
    Generate, PublicKey, SecretKey,
    array::Array,
    sec1::{FromSec1Point, Sec1Point, ToSec1Point},
};
use tpm2::crypto::{
    CryptoError,
    backend::{EccCurve, PrivateKey},
};

use crate::{ChaChaRng, RngWrapper};

/// Weierstrass curve private key, storing both the private scalar and the
/// public point.
pub struct EccKeyPair<C: elliptic_curve::CurveArithmetic> {
    /// Private scalar
    pub private: SecretKey<C>,
    /// Public key
    pub public: PublicKey<C>,
}

pub trait CurveSignature<const SIZE: usize> {
    type Public;

    fn sign_ecdsa(
        &self,
        _rng: &mut ChaChaRng,
        _digest: &[u8],
        _out_r: &mut [u8; SIZE],
        _out_s: &mut [u8; SIZE],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    fn verify_ecdsa(
        _public: &Self::Public,
        _digest: &[u8],
        _sig_r: &[u8; SIZE],
        _sig_s: &[u8; SIZE],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

macro_rules! impl_ecc {
    ($curve:path, $size:expr, $point_size:expr) => {
        impl PrivateKey<$point_size, $size, ChaChaRng> for EccKeyPair<$curve> {
            type PublicKey = PublicKey<$curve>;

            fn generate(rng: &mut ChaChaRng, _: ()) -> Result<Self, CryptoError> {
                let mut wrapper = RngWrapper(rng);
                let private = SecretKey::<$curve>::generate_from_rng(&mut wrapper);
                let public = private.public_key();
                Ok(EccKeyPair { private, public })
            }

            fn load_public(
                _: (),
                public: &[u8; $point_size],
            ) -> Result<Option<Self::PublicKey>, CryptoError> {
                let (x, y) = public.split_at($size);
                let x_arr = Array::try_from(x).map_err(|_| CryptoError::Internal)?;
                let y_arr = Array::try_from(y).map_err(|_| CryptoError::Internal)?;
                let pt = Sec1Point::<$curve>::from_affine_coordinates(&x_arr, &y_arr, false);
                Ok(PublicKey::<$curve>::from_sec1_point(&pt).into_option())
            }

            fn store_public(
                public: &Self::PublicKey,
                out: &mut [u8; $point_size],
            ) -> Result<(), CryptoError> {
                let pt = public.to_sec1_point(false);
                if let (Some(x), Some(y)) = (pt.x(), pt.y()) {
                    let (out_x, out_y) = out.split_at_mut($size);
                    out_x.copy_from_slice(x);
                    out_y.copy_from_slice(y);
                    Ok(())
                } else {
                    Err(CryptoError::Internal)
                }
            }

            fn load(
                public: Self::PublicKey,
                scalar: &[u8; $size],
            ) -> Result<Option<Self>, CryptoError> {
                let Ok(private) = SecretKey::<$curve>::from_slice(scalar) else {
                    return Ok(None);
                };
                // Both points are public.
                if private.public_key() != public {
                    return Ok(None);
                }
                Ok(Some(EccKeyPair { private, public }))
            }

            fn store(&self, out: &mut [u8; $size]) -> Result<(), CryptoError> {
                let bytes = self.private.to_bytes();
                out.copy_from_slice(bytes.as_slice());
                Ok(())
            }

            fn as_public(&self) -> &Self::PublicKey {
                &self.public
            }
        }

        impl EccCurve<$size, $point_size, ChaChaRng> for EccKeyPair<$curve> {
            fn ecdh(
                &self,
                peer_public: &Self::PublicKey,
                out_x: &mut [u8; $size],
                out_y: &mut [u8; $size],
            ) -> Result<Option<()>, CryptoError> {
                use core::ops::Mul;

                let scalar = self.private.to_nonzero_scalar();
                let proj = peer_public.to_projective();
                let shared_proj = proj.mul(*scalar);

                use elliptic_curve::group::Curve;
                let shared_affine = shared_proj.to_affine();

                let pt = PublicKey::<$curve>::from_affine(shared_affine)
                    .map_err(|_| CryptoError::Internal)?
                    .to_sec1_point(false);

                if let (Some(x), Some(y)) = (pt.x(), pt.y()) {
                    out_x.copy_from_slice(x);
                    out_y.copy_from_slice(y);
                    Ok(Some(()))
                } else {
                    Ok(None)
                }
            }

            fn sign(
                &self,
                rng: &mut ChaChaRng,
                digest: &[u8],
                out_r: &mut [u8; $size],
                out_s: &mut [u8; $size],
            ) -> Result<(), CryptoError> {
                self.sign_ecdsa(rng, digest, out_r, out_s)
            }

            fn verify(
                public: &Self::PublicKey,
                digest: &[u8],
                sig_r: &[u8; $size],
                sig_s: &[u8; $size],
            ) -> Result<bool, CryptoError> {
                Self::verify_ecdsa(public, digest, sig_r, sig_s)
            }
        }
    };
}

macro_rules! impl_ecdsa {
    ($curve:path, $size:expr) => {
        impl CurveSignature<$size> for EccKeyPair<$curve> {
            type Public = PublicKey<$curve>;

            fn sign_ecdsa(
                &self,
                _rng: &mut ChaChaRng,
                digest: &[u8],
                out_r: &mut [u8; $size],
                out_s: &mut [u8; $size],
            ) -> Result<(), CryptoError> {
                use signature::hazmat::PrehashSigner;
                let signer = ecdsa::SigningKey::<$curve>::from(&self.private);
                let sig: ecdsa::Signature<$curve> = signer
                    .sign_prehash(digest)
                    .map_err(|_| CryptoError::Internal)?;
                let (r, s) = sig.split_bytes();
                out_r.copy_from_slice(&r);
                out_s.copy_from_slice(&s);
                Ok(())
            }

            fn verify_ecdsa(
                public: &Self::Public,
                digest: &[u8],
                sig_r: &[u8; $size],
                sig_s: &[u8; $size],
            ) -> Result<bool, CryptoError> {
                use signature::hazmat::PrehashVerifier;
                let verifier = ecdsa::VerifyingKey::<$curve>::from(public);
                if let Ok(sig) = ecdsa::Signature::<$curve>::from_scalars(*sig_r, *sig_s) {
                    Ok(verifier.verify_prehash(digest, &sig).is_ok())
                } else {
                    Ok(false)
                }
            }
        }
    };
}

macro_rules! impl_ecdsa_hazmat {
    ($curve:path, $size:expr) => {
        impl CurveSignature<$size> for EccKeyPair<$curve> {
            type Public = PublicKey<$curve>;

            fn sign_ecdsa(
                &self,
                _rng: &mut ChaChaRng,
                digest: &[u8],
                out_r: &mut [u8; $size],
                out_s: &mut [u8; $size],
            ) -> Result<(), CryptoError> {
                let scalar_d = self.private.to_nonzero_scalar();
                let mut wrapper = RngWrapper(_rng);
                let k = elliptic_curve::NonZeroScalar::<$curve>::generate_from_rng(&mut wrapper);
                let (sig, _) = ecdsa::hazmat::sign_prehashed::<$curve>(&scalar_d, &k, digest)
                    .map_err(|_| CryptoError::Internal)?;

                let (r, s) = sig.split_bytes();
                out_r.copy_from_slice(&r);
                out_s.copy_from_slice(&s);
                Ok(())
            }

            fn verify_ecdsa(
                public: &Self::Public,
                digest: &[u8],
                sig_r: &[u8; $size],
                sig_s: &[u8; $size],
            ) -> Result<bool, CryptoError> {
                if let Ok(sig) = ecdsa::Signature::<$curve>::from_scalars(*sig_r, *sig_s) {
                    let proj = public.to_projective();
                    Ok(ecdsa::hazmat::verify_prehashed(&proj, digest, &sig).is_ok())
                } else {
                    Ok(false)
                }
            }
        }
    };
}

impl_ecc!(p192::NistP192, 24, 48);
impl_ecdsa_hazmat!(p192::NistP192, 24);

impl_ecc!(p224::NistP224, 28, 56);
impl_ecdsa!(p224::NistP224, 28);

impl_ecc!(p256::NistP256, 32, 64);
impl_ecdsa!(p256::NistP256, 32);

impl_ecc!(p384::NistP384, 48, 96);
impl_ecdsa!(p384::NistP384, 48);

impl_ecc!(p521::NistP521, 66, 132);
impl_ecdsa!(p521::NistP521, 66);

impl CurveSignature<32> for EccKeyPair<sm2::Sm2> {
    type Public = PublicKey<sm2::Sm2>;
}
impl_ecc!(sm2::Sm2, 32, 64);
