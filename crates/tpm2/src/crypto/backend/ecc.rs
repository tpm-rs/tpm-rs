//! [`Ecc`], [`EccCurve`], [`EdwardsCurve`], and [`MontgomeryCurve`].

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

/// Elliptic-curve cryptography, with one associated type per curve (and key
/// kind for [`Curve25519`](crate::TpmEccCurve::Curve25519) /
/// [`Curve448`](crate::TpmEccCurve::Curve448)).
///
/// Weierstrass curves implement [`EccCurve`] parameterized by coordinate (and
/// scalar) size `ceil(key_bits / 8)` and point size `2 * COORD_SIZE` in bytes.
/// Twisted Edwards signing keys (`Ed25519`, `Ed448`) implement
/// [`EdwardsCurve`] and Montgomery Diffie-Hellman keys (`X25519`, `X448`)
/// implement [`MontgomeryCurve`].
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
    type Ed25519: EdwardsCurve<32>;
    type Ed448: EdwardsCurve<57>;
    type X25519: MontgomeryCurve<32>;
    type X448: MontgomeryCurve<56>;
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

/// Twisted Edwards curve operations for `EdDSA` (`TPM_ALG_EDDSA`) and
/// `HashEdDSA` (`TPM_ALG_HASH_EDDSA`, RFC 8032), with compressed points, secret
/// keys, and signature halves `(R, S)` of `KEY_SIZE` bytes (32 for Ed25519, 57
/// for Ed448).
///
/// Per TPM 2.0 Part 1 (EdDSA and ECC Parameter Encoding), public keys are
/// encoded in `TPMS_ECC_POINT.x` with `y` empty, and context strings are always
/// empty (`""`).
///
/// [`AsymmetricKey`] encodings:
/// - Public: the canonical RFC 8032 little-endian compressed point, which must
///   be on the curve.
/// - Private: the RFC 8032 secret seed, which must derive `public`.
pub trait EdwardsCurve<const KEY_SIZE: usize>: AsymmetricKey<KEY_SIZE, KEY_SIZE> {
    /// Signs the concatenation of `msg` slices using pure `EdDSA` (`Ed25519` or
    /// `Ed448` with an empty context string), writing the RFC 8032 signature
    /// halves `(R, S)` into `out_r` and `out_s`.
    fn sign_message(
        private: &Self::Private,
        msg: &[&[u8]],
        out_r: &mut [u8; KEY_SIZE],
        out_s: &mut [u8; KEY_SIZE],
    ) -> Result<(), CryptoError>;

    /// Signs a 64-byte prehash digest (`SHA-512(M)` for `Ed25519ph` or
    /// `SHAKE256(M, 512)` for `Ed448ph`, with an empty context string) using
    /// `HashEdDSA`, writing `(R, S)` into `out_r` and `out_s`.
    fn sign_prehash(
        private: &Self::Private,
        prehash: &[u8; 64],
        out_r: &mut [u8; KEY_SIZE],
        out_s: &mut [u8; KEY_SIZE],
    ) -> Result<(), CryptoError>;

    /// Verifies pure `EdDSA` signature `(sig_r, sig_s)` over the concatenation
    /// of `msg` slices under `public` (with an empty context string).
    fn verify_message(
        public: &Self::Public,
        msg: &[&[u8]],
        sig_r: &[u8; KEY_SIZE],
        sig_s: &[u8; KEY_SIZE],
    ) -> Result<bool, CryptoError>;

    /// Verifies `HashEdDSA` (`Ed25519ph` / `Ed448ph`) signature `(sig_r, sig_s)`
    /// over the 64-byte `prehash` under `public` (with an empty context string).
    fn verify_prehash(
        public: &Self::Public,
        prehash: &[u8; 64],
        sig_r: &[u8; KEY_SIZE],
        sig_s: &[u8; KEY_SIZE],
    ) -> Result<bool, CryptoError>;
}

impl<const KEY_SIZE: usize> EdwardsCurve<KEY_SIZE> for ! {
    fn sign_message(
        private: &Self::Private,
        _: &[&[u8]],
        _: &mut [u8; KEY_SIZE],
        _: &mut [u8; KEY_SIZE],
    ) -> Result<(), CryptoError> {
        match *private {}
    }
    fn sign_prehash(
        private: &Self::Private,
        _: &[u8; 64],
        _: &mut [u8; KEY_SIZE],
        _: &mut [u8; KEY_SIZE],
    ) -> Result<(), CryptoError> {
        match *private {}
    }
    fn verify_message(
        public: &Self::Public,
        _: &[&[u8]],
        _: &[u8; KEY_SIZE],
        _: &[u8; KEY_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
    fn verify_prehash(
        public: &Self::Public,
        _: &[u8; 64],
        _: &[u8; KEY_SIZE],
        _: &[u8; KEY_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
}

/// Montgomery curve operations for `X25519` and `X448` Diffie-Hellman (RFC 7748),
/// with little-endian `u`-coordinates and scalars of `KEY_SIZE` bytes (32 for
/// X25519, 56 for X448).
///
/// Per TPM 2.0 Part 1 (ECC Parameter Encoding), public keys and ECDH shared
/// secrets are encoded in `TPMS_ECC_POINT.x` with `y` empty.
///
/// [`AsymmetricKey`] encodings:
/// - Public: the RFC 7748 little-endian `u`-coordinate.
/// - Private: the RFC 7748 scalar, which must derive `public`.
pub trait MontgomeryCurve<const KEY_SIZE: usize>: AsymmetricKey<KEY_SIZE, KEY_SIZE> {
    /// Computes the RFC 7748 shared secret `X25519(private, peer_public)` or
    /// `X448(private, peer_public)` into `out_u`.
    ///
    /// Returns `Ok(None)` if the shared secret is the all-zero low-order point
    /// result (`TPM_RC_NO_RESULT`).
    fn ecdh(
        private: &Self::Private,
        peer_public: &Self::Public,
        out_u: &mut [u8; KEY_SIZE],
    ) -> Result<Option<()>, CryptoError>;
}

impl<const KEY_SIZE: usize> MontgomeryCurve<KEY_SIZE> for ! {
    fn ecdh(
        private: &Self::Private,
        _: &Self::Public,
        _: &mut [u8; KEY_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        match *private {}
    }
}
