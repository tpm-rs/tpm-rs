//! [`Ecc`] implementation for NIST P-256, P-384, and P-521 using BoringSSL (`EC_GROUP` / `EC_POINT`).

use core::fmt;

use tpm2::crypto::{CryptoError, Ecc};
use tpm2::{Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint};

use crate::{BoringSsl, ChaChaRng, bssl, pad_into, write};

/// ECC public key handle for [`Ecc::PublicKey`].
#[derive(Clone, PartialEq, Eq)]
pub struct EccPublicKey {
    pub(crate) curve: TpmEccCurve,
    pub(crate) group: bssl::EcGroup,
    pub(crate) x: [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    pub(crate) y: [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
}

/// ECC private key handle for [`Ecc::PrivateKey`].
#[derive(Clone)]
pub struct EccPrivateKey {
    pub(crate) public: EccPublicKey,
    pub(crate) scalar: [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
}

impl fmt::Debug for EccPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EccPublicKey")
            .field("curve", &self.curve)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for EccPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EccPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Maps a [`TpmEccCurve`] to a supported BoringSSL [`bssl::EcGroup`].
fn curve_to_group(curve: TpmEccCurve) -> Result<bssl::EcGroup, CryptoError> {
    match curve {
        TpmEccCurve::NistP256 => Ok(bssl::EcGroup::P256),
        TpmEccCurve::NistP384 => Ok(bssl::EcGroup::P384),
        TpmEccCurve::NistP521 => Ok(bssl::EcGroup::P521),
        _ => Err(CryptoError::Unsupported),
    }
}

/// Copies `value` into `out` and returns it as a [`Tpm2bEccParameter`].
pub(crate) fn write_param<'a>(
    value: &[u8],
    out: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
) -> Result<Tpm2bEccParameter<'a>, CryptoError> {
    Tpm2bEccParameter::new(write(value, out)?).ok_or(CryptoError::Internal)
}

impl tpm2::crypto::EccPublicKey for EccPublicKey {
    fn curve(&self) -> TpmEccCurve {
        self.curve
    }

    fn point<'a>(
        &self,
        out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<TpmsEccPoint<'a>, CryptoError> {
        let len = self.group.coord_len();
        Ok(TpmsEccPoint {
            x: write_param(&self.x[..len], out_x)?,
            y: write_param(&self.y[..len], out_y)?,
        })
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
        let len = self.public.group.coord_len();
        write_param(&self.scalar[..len], out)
    }
}

impl Ecc for BoringSsl {
    type PublicKey = EccPublicKey;
    type PrivateKey = EccPrivateKey;

    fn load_public(
        &self,
        curve: TpmEccCurve,
        point: TpmsEccPoint<'_>,
    ) -> Result<Option<EccPublicKey>, CryptoError> {
        let group = curve_to_group(curve)?;
        let len = group.coord_len();
        let mut x = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut y = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        if pad_into(point.x.as_slice(), &mut x[..len]).is_none()
            || pad_into(point.y.as_slice(), &mut y[..len]).is_none()
            || bssl::ec_validate_point(group, &x[..len], &y[..len]).is_err()
        {
            return Ok(None);
        }
        Ok(Some(EccPublicKey { curve, group, x, y }))
    }

    fn load_private(
        &self,
        public: EccPublicKey,
        d: Tpm2bEccParameter<'_>,
    ) -> Result<Option<EccPrivateKey>, CryptoError> {
        let len = public.group.coord_len();
        let mut scalar = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut gx = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut gy = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        if pad_into(d.as_slice(), &mut scalar[..len]).is_none()
            || bssl::ec_point_multiply_generator(
                public.group,
                &scalar[..len],
                &mut gx[..len],
                &mut gy[..len],
            )
            .is_err()
            || gx[..len] != public.x[..len]
            || gy[..len] != public.y[..len]
        {
            return Ok(None);
        }
        Ok(Some(EccPrivateKey { public, scalar }))
    }

    fn generate_key(
        &self,
        rng: &mut ChaChaRng,
        curve: TpmEccCurve,
    ) -> Result<EccPrivateKey, CryptoError> {
        let group = curve_to_group(curve)?;
        let len = group.coord_len();
        let mut pub_xy = [0u8; 2 * TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut scalar = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        bssl::ec_generate_key(
            group,
            &mut rng.0,
            &mut pub_xy[..2 * len],
            &mut scalar[..len],
        )?;
        let mut x = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut y = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        x[..len].copy_from_slice(&pub_xy[..len]);
        y[..len].copy_from_slice(&pub_xy[len..2 * len]);
        Ok(EccPrivateKey {
            public: EccPublicKey { curve, group, x, y },
            scalar,
        })
    }

    fn ecdh<'a>(
        &self,
        private: &EccPrivateKey,
        peer_public: &EccPublicKey,
        out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<Option<TpmsEccPoint<'a>>, CryptoError> {
        if private.public.curve != peer_public.curve {
            return Err(CryptoError::Unsupported);
        }
        let group = private.public.group;
        let len = group.coord_len();
        if bssl::ec_point_multiply(
            group,
            &private.scalar[..len],
            &peer_public.x[..len],
            &peer_public.y[..len],
            &mut out_x[..len],
            &mut out_y[..len],
        )
        .is_err()
        {
            return Ok(None);
        }
        Ok(Some(TpmsEccPoint {
            x: Tpm2bEccParameter::new(&out_x[..len]).ok_or(CryptoError::Internal)?,
            y: Tpm2bEccParameter::new(&out_y[..len]).ok_or(CryptoError::Internal)?,
        }))
    }
}
