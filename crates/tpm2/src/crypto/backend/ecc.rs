//! [`Ecc`], [`EccCurve`], [`EdwardsCurve`], and [`MontgomeryCurve`].

use super::PrivateKey;
use crate::crypto::{CryptoError, Random, Rng};

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
pub trait Ecc: Random {
    type NistP192: EccCurve<24, 48, Self::Rng>;
    type NistP224: EccCurve<28, 56, Self::Rng>;
    type NistP256: EccCurve<32, 64, Self::Rng>;
    type NistP384: EccCurve<48, 96, Self::Rng>;
    type NistP521: EccCurve<66, 132, Self::Rng>;
    type BNP256: EccCurve<32, 64, Self::Rng>;
    type BNP638: EccCurve<80, 160, Self::Rng>;
    type SM2P256: EccCurve<32, 64, Self::Rng>;
    type BpP256R1: EccCurve<32, 64, Self::Rng>;
    type BpP384R1: EccCurve<48, 96, Self::Rng>;
    type BpP512R1: EccCurve<64, 128, Self::Rng>;
    type Ed25519: EdwardsCurve<32, Self::Rng>;
    type Ed448: EdwardsCurve<57, Self::Rng>;
    type X25519: MontgomeryCurve<32, Self::Rng>;
    type X448: MontgomeryCurve<56, Self::Rng>;
}

/// Elliptic-curve private key operations for a single Weierstrass curve, with
/// coordinates and scalars of `COORD_SIZE` bytes (big-endian, zero-padded on
/// the left), using RNG `R`.
///
/// Private key operations take `&self`, and public key operations take a
/// [`PublicKey`](PrivateKey::PublicKey).
///
/// [`PrivateKey`] encodings:
/// - Public: the affine point `x || y` (`POINT_SIZE = 2 * COORD_SIZE` bytes),
///   which must be on the curve and not the point at infinity.
/// - Private: the secret scalar `d` (`0 < d < n`), which must satisfy
///   `[d]G == public`.
pub trait EccCurve<const COORD_SIZE: usize, const POINT_SIZE: usize, R: Rng>:
    PrivateKey<POINT_SIZE, COORD_SIZE, R>
{
    /// Computes the Diffie-Hellman shared point `Z = [h * d] * peer_public`
    /// (`TPM2_ECDH_ZGen` / `TPM2_ECDH_KeyGen`), where `d` is this key's secret
    /// scalar, writing big-endian `(x, y)` into `out_x` and `out_y`.
    ///
    /// Returns `Ok(None)` if the resulting point is the point at infinity
    /// (`TPM_RC_NO_RESULT`).
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_x: &mut [u8; COORD_SIZE],
        out_y: &mut [u8; COORD_SIZE],
    ) -> Result<Option<()>, CryptoError>;

    /// Signs `digest` using `ECDSA` (`TPM_ALG_ECDSA`, FIPS 186-5), writing
    /// big-endian `(r, s)` into `out_r` and `out_s`.
    ///
    /// `digest` may be from any hash algorithm. Per FIPS 186-5, only its
    /// leftmost `bitlen(n)` bits are used.
    fn sign(
        &self,
        rng: &mut R,
        digest: &[u8],
        out_r: &mut [u8; COORD_SIZE],
        out_s: &mut [u8; COORD_SIZE],
    ) -> Result<(), CryptoError>;

    /// Verifies big-endian `ECDSA` signature `(sig_r, sig_s)` over `digest`
    /// under `public`.
    ///
    /// Returns `Ok(true)` if valid, or `Ok(false)` if invalid (including `r` or
    /// `s` outside `[1, n - 1]`).
    fn verify(
        public: &Self::PublicKey,
        digest: &[u8],
        sig_r: &[u8; COORD_SIZE],
        sig_s: &[u8; COORD_SIZE],
    ) -> Result<bool, CryptoError>;

    /// Signs digest `e` using `SM2` (`TPM_ALG_SM2`, GB/T 32918.2), writing
    /// big-endian `(r, s)` into `out_r` and `out_s`.
    ///
    /// `e` is the `SM2` message digest `H(Z_A || M)`, computed by the caller.
    /// Per TPM 2.0 Part 1 ("SM2 Digital Signature Algorithm"), `SM2` may be
    /// used with any curve.
    ///
    /// Defaults to `Err(`[`CryptoError::Unsupported`]`)`.
    fn sm2_sign(
        &self,
        rng: &mut R,
        e: &[u8],
        out_r: &mut [u8; COORD_SIZE],
        out_s: &mut [u8; COORD_SIZE],
    ) -> Result<(), CryptoError> {
        let _ = (rng, e, out_r, out_s);
        Err(CryptoError::Unsupported)
    }

    /// Verifies big-endian `SM2` signature `(sig_r, sig_s)` over digest `e`
    /// (as in [`sm2_sign`](Self::sm2_sign)) under `public`.
    ///
    /// Returns `Ok(true)` if valid, or `Ok(false)` if invalid (including `r` or
    /// `s` outside `[1, n - 1]`). Defaults to
    /// `Err(`[`CryptoError::Unsupported`]`)`.
    fn sm2_verify(
        public: &Self::PublicKey,
        e: &[u8],
        sig_r: &[u8; COORD_SIZE],
        sig_s: &[u8; COORD_SIZE],
    ) -> Result<bool, CryptoError> {
        let _ = (public, e, sig_r, sig_s);
        Err(CryptoError::Unsupported)
    }
}

impl<const COORD_SIZE: usize, const POINT_SIZE: usize, R: Rng> EccCurve<COORD_SIZE, POINT_SIZE, R> for ! {
    fn ecdh(
        &self,
        _: &Self::PublicKey,
        _: &mut [u8; COORD_SIZE],
        _: &mut [u8; COORD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        match *self {}
    }
    fn sign(
        &self,
        _: &mut R,
        _: &[u8],
        _: &mut [u8; COORD_SIZE],
        _: &mut [u8; COORD_SIZE],
    ) -> Result<(), CryptoError> {
        match *self {}
    }
    fn verify(
        public: &Self::PublicKey,
        _: &[u8],
        _: &[u8; COORD_SIZE],
        _: &[u8; COORD_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
}

/// Twisted Edwards curve private key operations for `EdDSA` (`TPM_ALG_EDDSA`)
/// and `HashEdDSA` (`TPM_ALG_HASH_EDDSA`, RFC 8032), with compressed points,
/// secret keys, and signature halves `(R, S)` of `KEY_SIZE` bytes (32 for
/// Ed25519, 57 for Ed448), using RNG `R` (for key generation).
///
/// Per TPM 2.0 Part 1 (EdDSA and ECC Parameter Encoding), public keys are
/// encoded in `TPMS_ECC_POINT.x` with `y` empty, and context strings are always
/// empty (`""`).
///
/// Private key operations take `&self`, and public key operations take a
/// [`PublicKey`](PrivateKey::PublicKey).
///
/// [`PrivateKey`] encodings:
/// - Public: the canonical RFC 8032 little-endian compressed point, which must
///   be on the curve.
/// - Private: the RFC 8032 secret seed, which must derive `public`.
pub trait EdwardsCurve<const KEY_SIZE: usize, R: Rng>: PrivateKey<KEY_SIZE, KEY_SIZE, R> {
    /// Signs the concatenation of `msg` slices using pure `EdDSA` (`Ed25519` or
    /// `Ed448` with an empty context string), writing the RFC 8032 signature
    /// halves `(R, S)` into `out_r` and `out_s`.
    fn sign_message(
        &self,
        msg: &[&[u8]],
        out_r: &mut [u8; KEY_SIZE],
        out_s: &mut [u8; KEY_SIZE],
    ) -> Result<(), CryptoError>;

    /// Signs a 64-byte prehash digest (`SHA-512(M)` for `Ed25519ph` or
    /// `SHAKE256(M, 512)` for `Ed448ph`, with an empty context string) using
    /// `HashEdDSA`, writing `(R, S)` into `out_r` and `out_s`.
    fn sign_prehash(
        &self,
        prehash: &[u8; 64],
        out_r: &mut [u8; KEY_SIZE],
        out_s: &mut [u8; KEY_SIZE],
    ) -> Result<(), CryptoError>;

    /// Verifies pure `EdDSA` signature `(sig_r, sig_s)` over the concatenation
    /// of `msg` slices under `public` (with an empty context string).
    fn verify_message(
        public: &Self::PublicKey,
        msg: &[&[u8]],
        sig_r: &[u8; KEY_SIZE],
        sig_s: &[u8; KEY_SIZE],
    ) -> Result<bool, CryptoError>;

    /// Verifies `HashEdDSA` (`Ed25519ph` / `Ed448ph`) signature `(sig_r, sig_s)`
    /// over the 64-byte `prehash` under `public` (with an empty context string).
    fn verify_prehash(
        public: &Self::PublicKey,
        prehash: &[u8; 64],
        sig_r: &[u8; KEY_SIZE],
        sig_s: &[u8; KEY_SIZE],
    ) -> Result<bool, CryptoError>;
}

impl<const KEY_SIZE: usize, R: Rng> EdwardsCurve<KEY_SIZE, R> for ! {
    fn sign_message(
        &self,
        _: &[&[u8]],
        _: &mut [u8; KEY_SIZE],
        _: &mut [u8; KEY_SIZE],
    ) -> Result<(), CryptoError> {
        match *self {}
    }
    fn sign_prehash(
        &self,
        _: &[u8; 64],
        _: &mut [u8; KEY_SIZE],
        _: &mut [u8; KEY_SIZE],
    ) -> Result<(), CryptoError> {
        match *self {}
    }
    fn verify_message(
        public: &Self::PublicKey,
        _: &[&[u8]],
        _: &[u8; KEY_SIZE],
        _: &[u8; KEY_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
    fn verify_prehash(
        public: &Self::PublicKey,
        _: &[u8; 64],
        _: &[u8; KEY_SIZE],
        _: &[u8; KEY_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
}

/// Montgomery curve private key operations for `X25519` and `X448`
/// Diffie-Hellman (RFC 7748), with little-endian `u`-coordinates and scalars of
/// `KEY_SIZE` bytes (32 for X25519, 56 for X448), using RNG `R` (for key
/// generation).
///
/// Per TPM 2.0 Part 1 (ECC Parameter Encoding), public keys and ECDH shared
/// secrets are encoded in `TPMS_ECC_POINT.x` with `y` empty.
///
/// [`PrivateKey`] encodings:
/// - Public: the RFC 7748 little-endian `u`-coordinate.
/// - Private: the RFC 7748 scalar, which must derive `public`.
pub trait MontgomeryCurve<const KEY_SIZE: usize, R: Rng>:
    PrivateKey<KEY_SIZE, KEY_SIZE, R>
{
    /// Computes the RFC 7748 shared secret `X25519(k, peer_public)` or
    /// `X448(k, peer_public)` (where `k` is this key's scalar) into `out_u`.
    ///
    /// Returns `Ok(None)` if the shared secret is the all-zero low-order point
    /// result (`TPM_RC_NO_RESULT`).
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_u: &mut [u8; KEY_SIZE],
    ) -> Result<Option<()>, CryptoError>;
}

impl<const KEY_SIZE: usize, R: Rng> MontgomeryCurve<KEY_SIZE, R> for ! {
    fn ecdh(&self, _: &Self::PublicKey, _: &mut [u8; KEY_SIZE]) -> Result<Option<()>, CryptoError> {
        match *self {}
    }
}
