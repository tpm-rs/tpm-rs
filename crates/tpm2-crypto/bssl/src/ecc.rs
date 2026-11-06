//! Elliptic-curve cryptography: NIST P-224, P-256, P-384, P-521 and BN P-256 with BoringSSL
//! (`EC_GROUP`, `EC_POINT`, `ECDSA_*`), and NIST P-192, BN P-638 and SM2 P-256 with the generic
//! arithmetic of `tpm2-crypto-weierstrass`.

use core::marker::PhantomData;

use crate::bssl::{
    BsslError, EcGroup, cleanse, ec_generate_key, ec_point_multiply, ec_point_multiply_generator,
    ec_validate_point, ecdsa_sign, ecdsa_verify,
};
use crate::{BsslCryptoProvider, BsslRng, output, verified};
use tpm2::crypto::CryptoError;
use tpm2::crypto::backend::{Ecc, EccCurve, PrivateKey};

/// A curve of BoringSSL ([`EcGroup`]), selecting the curve of [`BsslEcc`] and
/// [`BsslEccPublicKey`].
pub trait BsslCurve: 'static {
    /// The BoringSSL group of the curve.
    const GROUP: EcGroup;
}

macro_rules! bssl_curves {
    ($($(#[$m:meta])* $name:ident => $group:ident;)*) => {
        $(
            $(#[$m])*
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub struct $name;

            impl BsslCurve for $name {
                const GROUP: EcGroup = EcGroup::$group;
            }
        )*
    };
}

bssl_curves! {
    /// NIST P-224 (`EC_group_p224`).
    NistP224Group => P224;
    /// NIST P-256 (`EC_group_p256`).
    NistP256Group => P256;
    /// NIST P-384 (`EC_group_p384`).
    NistP384Group => P384;
    /// NIST P-521 (`EC_group_p521`).
    NistP521Group => P521;
    /// BN P-256 (a custom `EC_GROUP`).
    BnP256Group => BnP256;
}

/// A validated public key (a point of the curve other than the point at infinity) of the
/// BoringSSL curve `G`, as the affine point `x || y` of `POINT` bytes.
pub struct BsslEccPublicKey<G, const POINT: usize> {
    point: [u8; POINT],
    curve: PhantomData<fn() -> G>,
}

impl<G, const POINT: usize> BsslEccPublicKey<G, POINT> {
    /// Returns the coordinates `(x, y)`.
    fn coords(&self) -> (&[u8], &[u8]) {
        self.point.split_at(POINT / 2)
    }
}

/// A validated private key of the BoringSSL curve `G` with `COORD`-byte scalars and coordinates
/// (`POINT = 2 * COORD`), for `BsslCryptoProvider`. The secret scalar is cleansed on drop.
pub struct BsslEcc<G, const COORD: usize, const POINT: usize> {
    d: [u8; COORD],
    public: BsslEccPublicKey<G, POINT>,
}

impl<G, const COORD: usize, const POINT: usize> Drop for BsslEcc<G, COORD, POINT> {
    fn drop(&mut self) {
        cleanse(&mut self.d);
    }
}

impl<G: BsslCurve, const COORD: usize, const POINT: usize> BsslEcc<G, COORD, POINT> {
    /// Computes `[k]G` as an encoded point, or `Ok(None)` if `k` is not in `[1, n - 1]`.
    fn mul_base(k: &[u8; COORD]) -> Result<Option<[u8; POINT]>, CryptoError> {
        let mut point = [0u8; POINT];
        let (x, y) = point.split_at_mut(COORD);
        Ok(output(ec_point_multiply_generator(G::GROUP, k, x, y))?.map(|()| point))
    }
}

impl<G: BsslCurve, const COORD: usize, const POINT: usize> PrivateKey<POINT, COORD, BsslRng>
    for BsslEcc<G, COORD, POINT>
{
    type PublicKey = BsslEccPublicKey<G, POINT>;

    /// Draws the secret scalar from `rng` (by rejection sampling), so that the key is
    /// deterministic for the RNG of `from_seed`.
    fn generate(rng: &mut BsslRng, _: ()) -> Result<Self, CryptoError> {
        let mut key = Self {
            d: [0u8; COORD],
            public: BsslEccPublicKey {
                point: [0u8; POINT],
                curve: PhantomData,
            },
        };
        ec_generate_key(G::GROUP, rng, &mut key.public.point, &mut key.d)?;
        Ok(key)
    }

    fn load(public: Self::PublicKey, private: &[u8; COORD]) -> Result<Option<Self>, CryptoError> {
        match Self::mul_base(private)? {
            Some(point) if point == public.point => Ok(Some(Self {
                d: *private,
                public,
            })),
            _ => Ok(None),
        }
    }

    fn store(&self, out: &mut [u8; COORD]) -> Result<(), CryptoError> {
        *out = self.d;
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }

    fn load_public(_: (), public: &[u8; POINT]) -> Result<Option<Self::PublicKey>, CryptoError> {
        let (x, y) = public.split_at(COORD);
        if !verified(ec_validate_point(G::GROUP, x, y))? {
            return Ok(None);
        }
        Ok(Some(BsslEccPublicKey {
            point: *public,
            curve: PhantomData,
        }))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; POINT]) -> Result<(), CryptoError> {
        *out = public.point;
        Ok(())
    }
}

/// ECDSA, ECDH and point multiplications with BoringSSL. SM2 signatures are not supported
/// (the defaults, `Err(CryptoError::Unsupported)`). The ECDSA nonce comes from BoringSSL's RNG
/// (the `rng` argument is unused).
impl<G: BsslCurve, const COORD: usize, const POINT: usize> EccCurve<COORD, POINT, BsslRng>
    for BsslEcc<G, COORD, POINT>
{
    /// The cofactor of every BoringSSL curve is 1, so `Z = [d]Q`.
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_x: &mut [u8; COORD],
        out_y: &mut [u8; COORD],
    ) -> Result<Option<()>, CryptoError> {
        let (x, y) = peer_public.coords();
        output(ec_point_multiply(G::GROUP, &self.d, x, y, out_x, out_y))
    }

    fn sign(
        &self,
        _rng: &mut BsslRng,
        digest: &[u8],
        out_r: &mut [u8; COORD],
        out_s: &mut [u8; COORD],
    ) -> Result<(), CryptoError> {
        let mut signature = [0u8; POINT];
        ecdsa_sign(G::GROUP, &self.d, digest, &mut signature).map_err(|err| match err {
            // The scalar of a loaded key is valid.
            BsslError::InvalidData => CryptoError::Internal,
            err => err.into(),
        })?;
        let (r, s) = signature.split_at(COORD);
        out_r.copy_from_slice(r);
        out_s.copy_from_slice(s);
        Ok(())
    }

    fn verify(
        public: &Self::PublicKey,
        digest: &[u8],
        sig_r: &[u8; COORD],
        sig_s: &[u8; COORD],
    ) -> Result<bool, CryptoError> {
        let mut signature = [0u8; POINT];
        signature[..COORD].copy_from_slice(sig_r);
        signature[COORD..].copy_from_slice(sig_s);
        verified(ecdsa_verify(G::GROUP, &public.point, digest, &signature))
    }

    fn mul_generator(
        k: &[u8; COORD],
        out_x: &mut [u8; COORD],
        out_y: &mut [u8; COORD],
    ) -> Result<Option<()>, CryptoError> {
        output(ec_point_multiply_generator(G::GROUP, k, out_x, out_y))
    }

    fn mul_point(
        point: &Self::PublicKey,
        k: &[u8; COORD],
        out_x: &mut [u8; COORD],
        out_y: &mut [u8; COORD],
    ) -> Result<Option<()>, CryptoError> {
        let (x, y) = point.coords();
        output(ec_point_multiply(G::GROUP, k, x, y, out_x, out_y))
    }
}

/// NIST P-224 keys for `BsslCryptoProvider`.
pub type BsslEccNistP224 = BsslEcc<NistP224Group, 28, 56>;
/// NIST P-256 keys for `BsslCryptoProvider`.
pub type BsslEccNistP256 = BsslEcc<NistP256Group, 32, 64>;
/// NIST P-384 keys for `BsslCryptoProvider`.
pub type BsslEccNistP384 = BsslEcc<NistP384Group, 48, 96>;
/// NIST P-521 keys for `BsslCryptoProvider`.
pub type BsslEccNistP521 = BsslEcc<NistP521Group, 66, 132>;
/// BN P-256 keys for `BsslCryptoProvider`.
pub type BsslEccBnP256 = BsslEcc<BnP256Group, 32, 64>;

impl Ecc for BsslCryptoProvider {
    type NistP224 = BsslEccNistP224;
    type NistP256 = BsslEccNistP256;
    type NistP384 = BsslEccNistP384;
    type NistP521 = BsslEccNistP521;
    type BNP256 = BsslEccBnP256;
    // NIST P-192, BN P-638 and SM2 P-256: the generic constant-time short-Weierstrass
    // arithmetic of `tpm2-crypto-weierstrass` (which also implements SM2 signatures).
    type NistP192 = tpm2_crypto_weierstrass::NistP192;
    type BNP638 = tpm2_crypto_weierstrass::BnP638;
    type SM2P256 = tpm2_crypto_weierstrass::Sm2P256;
    type BpP256R1 = !;
    type BpP384R1 = !;
    type BpP512R1 = !;
    type Ed25519 = !;
    type Ed448 = !;
    type X25519 = !;
    type X448 = !;
}
