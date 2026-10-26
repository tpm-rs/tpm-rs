//! [`Ecc`] and [`EccCurve`].

use super::{AsymmetricKey, Hash};
use crate::{
    TpmtHa,
    crypto::{CryptoError, Rng},
};

/// Weierstrass ECC signature schemes (`ECDSA`, `SM2`, and `ECSchnorr`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EccSigScheme {
    Ecdsa,
    Sm2,
    Ecschnorr,
}

/// Weierstrass elliptic-curve cryptography, with one associated type per curve.
///
/// Each associated type implements [`EccCurve`] parameterized by its coordinate
/// (and scalar) size `ceil(key_bits / 8)` and point size `2 * COORD_SIZE` in
/// bytes.
///
/// Edwards and Montgomery curves ([`TpmEccCurve::Curve25519`](crate::TpmEccCurve::Curve25519)
/// and [`TpmEccCurve::Curve448`](crate::TpmEccCurve::Curve448)) use little-endian
/// single-coordinate encodings and message-level signing (`EdDSA`), so they are
/// not modeled by this trait.
///
/// See the [module documentation](super) for how to implement this trait.
pub trait Ecc {
    type NistP192: EccCurve<24, 48>;
    type NistP224: EccCurve<28, 56>;
    type NistP256: EccCurve<32, 64>;
    type NistP384: EccCurve<48, 96>;
    type NistP521: EccCurve<66, 132>;
    type BNP256: EccCurve<32, 64>;
    type BNP638: EccCurve<80, 160>;
    type SM2P256: EccCurve<32, 64>;
    type BpP256R1: EccCurve<32, 64>;
    type BpP384R1: EccCurve<48, 96>;
    type BpP512R1: EccCurve<64, 128>;
}

/// Elliptic-curve operations for a single Weierstrass curve, with coordinates
/// and scalars of `COORD_SIZE` bytes (big-endian, zero-padded on the left).
///
/// [`AsymmetricKey`] encodings:
/// - Public: the affine point `x || y` (`POINT_SIZE = 2 * COORD_SIZE` bytes),
///   which must be on the curve and not the point at infinity.
/// - Private: the secret scalar `d` (`0 < d < n`), which must satisfy
///   `[d]G == public`.
pub trait EccCurve<const COORD_SIZE: usize, const POINT_SIZE: usize>:
    AsymmetricKey<POINT_SIZE, COORD_SIZE>
{
    /// Computes the Diffie-Hellman shared point `Z = [h * d] * peer_public`
    /// (`TPM2_ECDH_ZGen` / `TPM2_ECDH_KeyGen`), writing big-endian `(x, y)`
    /// into `out_x` and `out_y`.
    ///
    /// Returns `Ok(None)` if the resulting point is the point at infinity
    /// (`TPM_RC_NO_RESULT`).
    fn ecdh(
        private: &Self::Private,
        peer_public: &Self::Public,
        out_x: &mut [u8; COORD_SIZE],
        out_y: &mut [u8; COORD_SIZE],
    ) -> Result<Option<()>, CryptoError>;

    /// Signs `digest` using `private` and `scheme`, writing big-endian `(r, s)`
    /// into `out_r` and `out_s`.
    fn sign<H: Hash>(
        rng: &mut impl Rng,
        private: &Self::Private,
        scheme: EccSigScheme,
        digest: TpmtHa<'_>,
        out_r: &mut [u8; COORD_SIZE],
        out_s: &mut [u8; COORD_SIZE],
    ) -> Result<(), CryptoError>;

    /// Verifies big-endian `(sig_r, sig_s)` over `digest` under `public` and
    /// `scheme`.
    ///
    /// Returns `Ok(true)` if valid, or `Ok(false)` if invalid (including `r` or
    /// `s` outside `[1, n - 1]`).
    fn verify<H: Hash>(
        public: &Self::Public,
        scheme: EccSigScheme,
        digest: TpmtHa<'_>,
        sig_r: &[u8; COORD_SIZE],
        sig_s: &[u8; COORD_SIZE],
    ) -> Result<bool, CryptoError>;
}

impl<const COORD_SIZE: usize, const POINT_SIZE: usize> EccCurve<COORD_SIZE, POINT_SIZE> for ! {
    fn ecdh(
        private: &Self::Private,
        _: &Self::Public,
        _: &mut [u8; COORD_SIZE],
        _: &mut [u8; COORD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        match *private {}
    }
    fn sign<H: Hash>(
        _: &mut impl Rng,
        private: &Self::Private,
        _: EccSigScheme,
        _: TpmtHa<'_>,
        _: &mut [u8; COORD_SIZE],
        _: &mut [u8; COORD_SIZE],
    ) -> Result<(), CryptoError> {
        match *private {}
    }
    fn verify<H: Hash>(
        public: &Self::Public,
        _: EccSigScheme,
        _: TpmtHa<'_>,
        _: &[u8; COORD_SIZE],
        _: &[u8; COORD_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
}
