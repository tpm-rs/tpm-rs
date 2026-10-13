//! TPM 2.0 Elliptic Curve Cryptography (ECC) Abstractions
//!
//! This module defines the cryptographic traits required for Elliptic Curve operations in TPM 2.0,
//! covering curve point validation, generator scalar multiplication, ECDH key agreement, and ECDAA signing protocols.
//!
//! Supported curves define a concrete `*Context` type implementing [`EccCurve<N>`]
//! (where `N` is the coordinate and scalar size in bytes) and implement the corresponding
//! curve method on [`Ecc`] (e.g., [`Ecc::nist_p256()`]).
//!
//! Unimplemented curves bind their context type to [`!`] and omit the method, keeping the default
//! body of `Err(`[`CryptoError::Unsupported`]`)`.
//!
//! ### Error Handling
//!
//! Following the conventions of [`crypto`](super), [`CryptoError`] is only returned for
//! unsupported curves or operations ([`CryptoError::Unsupported`]) and for internal failures
//! ([`CryptoError::Internal`], which puts the TPM into failure mode). Semantic failures caused by
//! the inputs are reported in the `Ok` value:
//!   - Point validation returns `Ok(false)` if the point is not on the curve.
//!   - Point multiplication and ECDAA signing return `Ok(None)` if there is no valid result: the
//!     product is the point at infinity (`TPM_RC_NO_RESULT`), or a scalar or point input is
//!     invalid for the curve.
//!
//! An output buffer too small for the result is a programming error of the caller, reported as
//! [`CryptoError::Internal`].

// Without any `ecc_curve_*` feature, `EccContext` only has its uninhabited
// variant: its methods ignore their parameters and the helpers are unused.
#![cfg_attr(
    not(any(
        feature = "ecc_curve_nist_p192",
        feature = "ecc_curve_nist_p224",
        feature = "ecc_curve_nist_p256",
        feature = "ecc_curve_nist_p384",
        feature = "ecc_curve_nist_p521",
        feature = "ecc_curve_bn_p256",
        feature = "ecc_curve_bn_p638",
        feature = "ecc_curve_sm2_p256",
        feature = "ecc_curve_bp_p256_r1",
        feature = "ecc_curve_bp_p384_r1",
        feature = "ecc_curve_bp_p512_r1",
        feature = "ecc_curve_curve25519",
        feature = "ecc_curve_curve448",
    )),
    allow(dead_code, unused_variables)
)]

use super::CryptoError;

pub use crate::constants::TpmEccCurve;

/// Elliptic curve operations over a curve with coordinate/scalar size `N` bytes.
///
/// Points are given as affine coordinates `(x, y)` and scalars as big-endian
/// integers, each exactly `N` bytes long (zero-padded on the left).
pub trait EccCurve<const N: usize> {
    /// Validates that the affine point `(x, y)` lies on the curve.
    ///
    /// Returns `Ok(true)` if it does, and `Ok(false)` otherwise (including
    /// coordinates that are not smaller than the field prime).
    fn validate_point(&self, x: &[u8; N], y: &[u8; N]) -> Result<bool, CryptoError>;

    /// Multiplies the curve's base generator point `G` by `scalar`: `(x_out, y_out) = scalar * G`.
    ///
    /// Returns `Ok(Some(()))` on success, and `Ok(None)` if `scalar` is invalid
    /// for the curve (e.g. zero or not smaller than the group order), so that
    /// there is no valid result.
    fn point_multiply_generator(
        &self,
        scalar: &[u8; N],
        x_out: &mut [u8; N],
        y_out: &mut [u8; N],
    ) -> Result<Option<()>, CryptoError>;

    /// Multiplies the affine point `(x_in, y_in)` by `scalar`: `(x_out, y_out) = scalar * (x_in, y_in)`.
    ///
    /// Returns `Ok(Some(()))` on success, and `Ok(None)` if the product is the
    /// point at infinity, or if `(x_in, y_in)` or `scalar` is invalid for the
    /// curve.
    fn point_multiply(
        &self,
        scalar: &[u8; N],
        x_in: &[u8; N],
        y_in: &[u8; N],
        x_out: &mut [u8; N],
        y_out: &mut [u8; N],
    ) -> Result<Option<()>, CryptoError>;

    /// Signs a digest using the ECDAA protocol.
    ///
    /// Returns `Ok(Some(()))` after writing the nonce `k` to `nonce_k_out` and
    /// the signature value `s` to `s_out`, and `Ok(None)` if `commit_r` or
    /// `private_key_d` is invalid for the curve.
    #[allow(clippy::too_many_arguments)]
    fn ecdaa_sign(
        &self,
        commit_r: &[u8; N],
        commit_x: &[u8],
        commit_p1: &[u8],
        private_key_d: &[u8; N],
        digest: &[u8],
        nonce_k_out: &mut [u8; N],
        s_out: &mut [u8; N],
    ) -> Result<Option<()>, CryptoError>;
}

impl<const N: usize> EccCurve<N> for ! {
    fn validate_point(&self, _: &[u8; N], _: &[u8; N]) -> Result<bool, CryptoError> {
        match *self {}
    }
    fn point_multiply_generator(
        &self,
        _: &[u8; N],
        _: &mut [u8; N],
        _: &mut [u8; N],
    ) -> Result<Option<()>, CryptoError> {
        match *self {}
    }
    fn point_multiply(
        &self,
        _: &[u8; N],
        _: &[u8; N],
        _: &[u8; N],
        _: &mut [u8; N],
        _: &mut [u8; N],
    ) -> Result<Option<()>, CryptoError> {
        match *self {}
    }
    fn ecdaa_sign(
        &self,
        _: &[u8; N],
        _: &[u8],
        _: &[u8],
        _: &[u8; N],
        _: &[u8],
        _: &mut [u8; N],
        _: &mut [u8; N],
    ) -> Result<Option<()>, CryptoError> {
        match *self {}
    }
}

/// Cryptographic ECC interfaces for TPM implementations and clients.
///
/// Supported curves define a concrete `*Context` type and implement:
///   - A method creating/initializing the curve context (e.g. [`Ecc::nist_p256()`])
///   - [`EccCurve<N>`] for `*Context` (where `N` is the coordinate/scalar size in bytes)
///
/// Unimplemented curves bind their context type to [`!`] and
/// omit the method, keeping the default body of
/// `Err(`[`CryptoError::Unsupported`]`)`.
///
/// The provided methods ([`Ecc::validate_point`], [`Ecc::point_multiply_generator`],
/// [`Ecc::point_multiply`], and [`Ecc::ecdaa_sign`]) select the curve context
/// with [`EccContext`] and work on variable-length, big-endian byte strings.
///
/// # Example
///
/// ```
/// # use tpm2::crypto::{CryptoError, Ecc, EccCurve};
/// # struct MyBackend;
/// # struct MyNistP256;
/// impl Ecc for MyBackend {
///     type NistP256Context = MyNistP256;
///     fn nist_p256(&self) -> Result<MyNistP256, CryptoError> { Ok(MyNistP256) }
///
///     // Unsupported curves use `!` and default methods:
///     type NistP192Context = !;
///     type NistP224Context = !;
///     type NistP384Context = !;
///     type NistP521Context = !;
///     type BnP256Context = !;
///     type BnP638Context = !;
///     type Sm2P256Context = !;
///     type BpP256R1Context = !;
///     type BpP384R1Context = !;
///     type BpP512R1Context = !;
///     type Curve25519Context = !;
///     type Curve448Context = !;
/// }
///
/// impl EccCurve<32> for MyNistP256 {
///     fn validate_point(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<bool, CryptoError> {
///         todo!()
///     }
///     fn point_multiply_generator(
///         &self,
///         scalar: &[u8; 32],
///         x_out: &mut [u8; 32],
///         y_out: &mut [u8; 32],
///     ) -> Result<Option<()>, CryptoError> { todo!() }
///     fn point_multiply(
///         &self,
///         scalar: &[u8; 32],
///         x_in: &[u8; 32],
///         y_in: &[u8; 32],
///         x_out: &mut [u8; 32],
///         y_out: &mut [u8; 32],
///     ) -> Result<Option<()>, CryptoError> { todo!() }
///     fn ecdaa_sign(
///         &self,
///         commit_r: &[u8; 32],
///         commit_x: &[u8],
///         commit_p1: &[u8],
///         private_key_d: &[u8; 32],
///         digest: &[u8],
///         nonce_k_out: &mut [u8; 32],
///         s_out: &mut [u8; 32],
///     ) -> Result<Option<()>, CryptoError> {
///         // ECDAA is not supported on this curve.
///         Err(CryptoError::Unsupported)
///     }
/// }
/// ```
pub trait Ecc {
    type NistP192Context: EccCurve<24>;
    fn nist_p192(&self) -> Result<Self::NistP192Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type NistP224Context: EccCurve<28>;
    fn nist_p224(&self) -> Result<Self::NistP224Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type NistP256Context: EccCurve<32>;
    fn nist_p256(&self) -> Result<Self::NistP256Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type NistP384Context: EccCurve<48>;
    fn nist_p384(&self) -> Result<Self::NistP384Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type NistP521Context: EccCurve<66>;
    fn nist_p521(&self) -> Result<Self::NistP521Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type BnP256Context: EccCurve<32>;
    fn bn_p256(&self) -> Result<Self::BnP256Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type BnP638Context: EccCurve<80>;
    fn bn_p638(&self) -> Result<Self::BnP638Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Sm2P256Context: EccCurve<32>;
    fn sm2_p256(&self) -> Result<Self::Sm2P256Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type BpP256R1Context: EccCurve<32>;
    fn bp_p256_r1(&self) -> Result<Self::BpP256R1Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type BpP384R1Context: EccCurve<48>;
    fn bp_p384_r1(&self) -> Result<Self::BpP384R1Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type BpP512R1Context: EccCurve<64>;
    fn bp_p512_r1(&self) -> Result<Self::BpP512R1Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Curve25519Context: EccCurve<32>;
    fn curve25519(&self) -> Result<Self::Curve25519Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    type Curve448Context: EccCurve<56>;
    fn curve448(&self) -> Result<Self::Curve448Context, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Validates that `public_key` (`x || y`) is a valid affine point on `curve`.
    ///
    /// See [`EccContext::validate_point`].
    fn validate_point(&self, curve: TpmEccCurve, public_key: &[u8]) -> Result<bool, CryptoError>
    where
        Self: Sized,
    {
        validate_point(self, curve, public_key)
    }

    /// Multiplies the base generator point `G` of `curve` by `scalar` and writes `x || y` into `public_key_out`.
    ///
    /// See [`EccContext::point_multiply_generator`].
    fn point_multiply_generator(
        &self,
        curve: TpmEccCurve,
        scalar: &[u8],
        public_key_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError>
    where
        Self: Sized,
    {
        point_multiply_generator(self, curve, scalar, public_key_out)
    }

    /// Multiplies `public_point` (`x || y`) on `curve` by `scalar` and writes `x || y` into `derived_point_out`.
    ///
    /// See [`EccContext::point_multiply`].
    fn point_multiply(
        &self,
        curve: TpmEccCurve,
        scalar: &[u8],
        public_point: &[u8],
        derived_point_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError>
    where
        Self: Sized,
    {
        point_multiply(self, curve, scalar, public_point, derived_point_out)
    }

    /// Signs `digest` using the ECDAA protocol on `curve`.
    ///
    /// See [`EccContext::ecdaa_sign`].
    #[allow(clippy::too_many_arguments)]
    fn ecdaa_sign(
        &self,
        curve: TpmEccCurve,
        commit_r: &[u8],
        commit_x: &[u8],
        commit_p1: &[u8],
        private_key_d: &[u8],
        digest: &[u8],
        nonce_k_out: &mut [u8],
        s_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError>
    where
        Self: Sized,
    {
        ecdaa_sign(
            self,
            curve,
            commit_r,
            commit_x,
            commit_p1,
            private_key_d,
            digest,
            nonce_k_out,
            s_out,
        )
    }
}

/// Dynamic ECC context wrapping the curve-specific `*Context` types of an [`Ecc`] backend.
///
/// While an [`Ecc`] implementation can implement whichever curves it wants, the
/// variants of this enum will only exist if the corresponding `ecc_curve_*`
/// [crate feature](crate#algorithm-feature-flags) is enabled.
///
/// The methods of this type take variable-length, big-endian byte strings:
///   - Points are `x || y`, each coordinate exactly `N` bytes long.
///   - Input scalars may be shorter than `N` bytes (they are zero-padded on
///     the left), but not longer.
pub enum EccContext<E: Ecc> {
    #[cfg(feature = "ecc_curve_nist_p192")]
    NistP192(E::NistP192Context),
    #[cfg(feature = "ecc_curve_nist_p224")]
    NistP224(E::NistP224Context),
    #[cfg(feature = "ecc_curve_nist_p256")]
    NistP256(E::NistP256Context),
    #[cfg(feature = "ecc_curve_nist_p384")]
    NistP384(E::NistP384Context),
    #[cfg(feature = "ecc_curve_nist_p521")]
    NistP521(E::NistP521Context),
    #[cfg(feature = "ecc_curve_bn_p256")]
    BnP256(E::BnP256Context),
    #[cfg(feature = "ecc_curve_bn_p638")]
    BnP638(E::BnP638Context),
    #[cfg(feature = "ecc_curve_sm2_p256")]
    Sm2P256(E::Sm2P256Context),
    #[cfg(feature = "ecc_curve_bp_p256_r1")]
    BpP256R1(E::BpP256R1Context),
    #[cfg(feature = "ecc_curve_bp_p384_r1")]
    BpP384R1(E::BpP384R1Context),
    #[cfg(feature = "ecc_curve_bp_p512_r1")]
    BpP512R1(E::BpP512R1Context),
    #[cfg(feature = "ecc_curve_curve25519")]
    Curve25519(E::Curve25519Context),
    #[cfg(feature = "ecc_curve_curve448")]
    Curve448(E::Curve448Context),
    /// Uninhabited variant that keeps `E` used and the enum non-empty whatever
    /// curve features are enabled (including none of them).
    #[doc(hidden)]
    _Uninhabited(core::marker::PhantomData<E>, core::convert::Infallible),
}

/// Splits `point` (`x || y`) into its two `N`-byte coordinates, or returns
/// `None` if `point` is not exactly `2 * N` bytes long.
fn split_point<const N: usize>(point: &[u8]) -> Option<(&[u8; N], &[u8; N])> {
    let (x, y) = point.split_first_chunk::<N>()?;
    Some((x, y.try_into().ok()?))
}

/// Splits the first `2 * N` bytes of `out` into two `N`-byte coordinate
/// buffers (`x || y`), or returns `None` if `out` is shorter than `2 * N` bytes.
fn split_point_mut<const N: usize>(out: &mut [u8]) -> Option<(&mut [u8; N], &mut [u8; N])> {
    let (x, rest) = out.split_first_chunk_mut::<N>()?;
    let (y, _) = rest.split_first_chunk_mut::<N>()?;
    Some((x, y))
}

/// Left-pads the big-endian `scalar` with zeros to `N` bytes, or returns `None`
/// if `scalar` is longer than `N` bytes.
fn pad_scalar<const N: usize>(scalar: &[u8]) -> Option<[u8; N]> {
    let mut padded = [0u8; N];
    let offset = N.checked_sub(scalar.len())?;
    padded[offset..].copy_from_slice(scalar);
    Some(padded)
}

impl<E: Ecc> EccContext<E> {
    /// Initializes an ECC context for `curve` using backend `e`.
    ///
    /// Returns `Err(`[`CryptoError::Unsupported`]`)` for [`TpmEccCurve::None`]
    /// and for curves the backend does not implement.
    pub fn new(e: &E, curve: TpmEccCurve) -> Result<Self, CryptoError> {
        match curve {
            TpmEccCurve::None => Err(CryptoError::Unsupported),
            #[cfg(feature = "ecc_curve_nist_p192")]
            TpmEccCurve::NistP192 => e.nist_p192().map(EccContext::NistP192),
            #[cfg(feature = "ecc_curve_nist_p224")]
            TpmEccCurve::NistP224 => e.nist_p224().map(EccContext::NistP224),
            #[cfg(feature = "ecc_curve_nist_p256")]
            TpmEccCurve::NistP256 => e.nist_p256().map(EccContext::NistP256),
            #[cfg(feature = "ecc_curve_nist_p384")]
            TpmEccCurve::NistP384 => e.nist_p384().map(EccContext::NistP384),
            #[cfg(feature = "ecc_curve_nist_p521")]
            TpmEccCurve::NistP521 => e.nist_p521().map(EccContext::NistP521),
            #[cfg(feature = "ecc_curve_bn_p256")]
            TpmEccCurve::BNP256 => e.bn_p256().map(EccContext::BnP256),
            #[cfg(feature = "ecc_curve_bn_p638")]
            TpmEccCurve::BNP638 => e.bn_p638().map(EccContext::BnP638),
            #[cfg(feature = "ecc_curve_sm2_p256")]
            TpmEccCurve::SM2P256 => e.sm2_p256().map(EccContext::Sm2P256),
            #[cfg(feature = "ecc_curve_bp_p256_r1")]
            TpmEccCurve::BpP256R1 => e.bp_p256_r1().map(EccContext::BpP256R1),
            #[cfg(feature = "ecc_curve_bp_p384_r1")]
            TpmEccCurve::BpP384R1 => e.bp_p384_r1().map(EccContext::BpP384R1),
            #[cfg(feature = "ecc_curve_bp_p512_r1")]
            TpmEccCurve::BpP512R1 => e.bp_p512_r1().map(EccContext::BpP512R1),
            #[cfg(feature = "ecc_curve_curve25519")]
            TpmEccCurve::Curve25519 => e.curve25519().map(EccContext::Curve25519),
            #[cfg(feature = "ecc_curve_curve448")]
            TpmEccCurve::Curve448 => e.curve448().map(EccContext::Curve448),
        }
    }

    /// Validates that `public_key` (`x || y`) lies on the curve.
    ///
    /// Returns `Ok(false)` if `public_key` is not exactly `2 * N` bytes long or
    /// is not a point on the curve.
    pub fn validate_point(&self, public_key: &[u8]) -> Result<bool, CryptoError> {
        fn helper<const N: usize>(
            ctx: &impl EccCurve<N>,
            public_key: &[u8],
        ) -> Result<bool, CryptoError> {
            let Some((x, y)) = split_point::<N>(public_key) else {
                return Ok(false);
            };
            ctx.validate_point(x, y)
        }

        match self {
            #[cfg(feature = "ecc_curve_nist_p192")]
            EccContext::NistP192(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_nist_p224")]
            EccContext::NistP224(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_nist_p256")]
            EccContext::NistP256(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_nist_p384")]
            EccContext::NistP384(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_nist_p521")]
            EccContext::NistP521(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_bn_p256")]
            EccContext::BnP256(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_bn_p638")]
            EccContext::BnP638(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_sm2_p256")]
            EccContext::Sm2P256(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_bp_p256_r1")]
            EccContext::BpP256R1(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_bp_p384_r1")]
            EccContext::BpP384R1(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_bp_p512_r1")]
            EccContext::BpP512R1(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_curve25519")]
            EccContext::Curve25519(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_curve448")]
            EccContext::Curve448(ctx) => helper(ctx, public_key),
            EccContext::_Uninhabited(_, never) => match *never {},
        }
    }

    /// Multiplies the base generator point `G` by `scalar` and writes `x || y` into `public_key_out`.
    ///
    /// Returns `Ok(Some(2 * N))` (the number of bytes written) on success, and
    /// `Ok(None)` if `scalar` is longer than `N` bytes or is invalid for the
    /// curve. Returns `Err(`[`CryptoError::Internal`]`)` if `public_key_out` is
    /// shorter than `2 * N` bytes.
    pub fn point_multiply_generator(
        &self,
        scalar: &[u8],
        public_key_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        fn helper<const N: usize>(
            ctx: &impl EccCurve<N>,
            scalar: &[u8],
            public_key_out: &mut [u8],
        ) -> Result<Option<usize>, CryptoError> {
            let Some(scalar) = pad_scalar::<N>(scalar) else {
                return Ok(None);
            };
            let mut x_out = [0u8; N];
            let mut y_out = [0u8; N];
            if ctx
                .point_multiply_generator(&scalar, &mut x_out, &mut y_out)?
                .is_none()
            {
                return Ok(None);
            }
            let Some((x, y)) = split_point_mut::<N>(public_key_out) else {
                return Err(CryptoError::Internal);
            };
            *x = x_out;
            *y = y_out;
            Ok(Some(2 * N))
        }

        match self {
            #[cfg(feature = "ecc_curve_nist_p192")]
            EccContext::NistP192(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_nist_p224")]
            EccContext::NistP224(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_nist_p256")]
            EccContext::NistP256(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_nist_p384")]
            EccContext::NistP384(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_nist_p521")]
            EccContext::NistP521(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_bn_p256")]
            EccContext::BnP256(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_bn_p638")]
            EccContext::BnP638(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_sm2_p256")]
            EccContext::Sm2P256(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_bp_p256_r1")]
            EccContext::BpP256R1(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_bp_p384_r1")]
            EccContext::BpP384R1(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_bp_p512_r1")]
            EccContext::BpP512R1(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_curve25519")]
            EccContext::Curve25519(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_curve448")]
            EccContext::Curve448(ctx) => helper(ctx, scalar, public_key_out),
            EccContext::_Uninhabited(_, never) => match *never {},
        }
    }

    /// Multiplies `public_point` (`x || y`) by `scalar` and writes `x || y` into `derived_point_out`.
    ///
    /// Returns `Ok(Some(2 * N))` (the number of bytes written) on success, and
    /// `Ok(None)` if the product is the point at infinity, if `public_point` is
    /// not exactly `2 * N` bytes long or not a valid point, or if `scalar` is
    /// longer than `N` bytes or is invalid for the curve. Returns
    /// `Err(`[`CryptoError::Internal`]`)` if `derived_point_out` is shorter
    /// than `2 * N` bytes (checked first).
    pub fn point_multiply(
        &self,
        scalar: &[u8],
        public_point: &[u8],
        derived_point_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        fn helper<const N: usize>(
            ctx: &impl EccCurve<N>,
            scalar: &[u8],
            public_point: &[u8],
            derived_point_out: &mut [u8],
        ) -> Result<Option<usize>, CryptoError> {
            let Some((x_out, y_out)) = split_point_mut::<N>(derived_point_out) else {
                return Err(CryptoError::Internal);
            };
            let (Some((x_in, y_in)), Some(scalar)) =
                (split_point::<N>(public_point), pad_scalar::<N>(scalar))
            else {
                return Ok(None);
            };
            Ok(ctx
                .point_multiply(&scalar, x_in, y_in, x_out, y_out)?
                .map(|()| 2 * N))
        }

        match self {
            #[cfg(feature = "ecc_curve_nist_p192")]
            EccContext::NistP192(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_nist_p224")]
            EccContext::NistP224(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_nist_p256")]
            EccContext::NistP256(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_nist_p384")]
            EccContext::NistP384(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_nist_p521")]
            EccContext::NistP521(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_bn_p256")]
            EccContext::BnP256(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_bn_p638")]
            EccContext::BnP638(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_sm2_p256")]
            EccContext::Sm2P256(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_bp_p256_r1")]
            EccContext::BpP256R1(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_bp_p384_r1")]
            EccContext::BpP384R1(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_bp_p512_r1")]
            EccContext::BpP512R1(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_curve25519")]
            EccContext::Curve25519(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_curve448")]
            EccContext::Curve448(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            EccContext::_Uninhabited(_, never) => match *never {},
        }
    }

    /// Signs a digest using the ECDAA protocol.
    ///
    /// Writes the nonce `k` to the first `N` bytes of `nonce_k_out` and the
    /// signature value `s` to the first `N` bytes of `s_out`, and returns
    /// `Ok(Some(N))`. Returns `Ok(None)` if `commit_r` or `private_key_d` is
    /// longer than `N` bytes or is invalid for the curve, and
    /// `Err(`[`CryptoError::Internal`]`)` if `nonce_k_out` or `s_out` is
    /// shorter than `N` bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn ecdaa_sign(
        &self,
        commit_r: &[u8],
        commit_x: &[u8],
        commit_p1: &[u8],
        private_key_d: &[u8],
        digest: &[u8],
        nonce_k_out: &mut [u8],
        s_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        #[allow(clippy::too_many_arguments)]
        fn helper<const N: usize>(
            ctx: &impl EccCurve<N>,
            commit_r: &[u8],
            commit_x: &[u8],
            commit_p1: &[u8],
            private_key_d: &[u8],
            digest: &[u8],
            nonce_k_out: &mut [u8],
            s_out: &mut [u8],
        ) -> Result<Option<usize>, CryptoError> {
            let (Some(r), Some(d)) = (pad_scalar::<N>(commit_r), pad_scalar::<N>(private_key_d))
            else {
                return Ok(None);
            };
            let (Some(k_out), Some(s_out)) = (
                nonce_k_out.first_chunk_mut::<N>(),
                s_out.first_chunk_mut::<N>(),
            ) else {
                return Err(CryptoError::Internal);
            };
            Ok(ctx
                .ecdaa_sign(&r, commit_x, commit_p1, &d, digest, k_out, s_out)?
                .map(|()| N))
        }

        match self {
            #[cfg(feature = "ecc_curve_nist_p192")]
            EccContext::NistP192(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_nist_p224")]
            EccContext::NistP224(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_nist_p256")]
            EccContext::NistP256(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_nist_p384")]
            EccContext::NistP384(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_nist_p521")]
            EccContext::NistP521(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_bn_p256")]
            EccContext::BnP256(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_bn_p638")]
            EccContext::BnP638(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_sm2_p256")]
            EccContext::Sm2P256(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_bp_p256_r1")]
            EccContext::BpP256R1(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_bp_p384_r1")]
            EccContext::BpP384R1(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_bp_p512_r1")]
            EccContext::BpP512R1(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_curve25519")]
            EccContext::Curve25519(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(feature = "ecc_curve_curve448")]
            EccContext::Curve448(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            EccContext::_Uninhabited(_, never) => match *never {},
        }
    }
}

/// Validates that `public_key` (`x || y`) lies on `curve` using [`EccContext`].
///
/// See [`EccContext::validate_point`].
pub fn validate_point<E: Ecc>(
    e: &E,
    curve: TpmEccCurve,
    public_key: &[u8],
) -> Result<bool, CryptoError> {
    let ctx = EccContext::new(e, curve)?;
    ctx.validate_point(public_key)
}

/// Multiplies the base generator point `G` of `curve` by `scalar` using [`EccContext`].
///
/// See [`EccContext::point_multiply_generator`].
pub fn point_multiply_generator<E: Ecc>(
    e: &E,
    curve: TpmEccCurve,
    scalar: &[u8],
    public_key_out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let ctx = EccContext::new(e, curve)?;
    ctx.point_multiply_generator(scalar, public_key_out)
}

/// Multiplies `public_point` (`x || y`) on `curve` by `scalar` using [`EccContext`].
///
/// See [`EccContext::point_multiply`].
pub fn point_multiply<E: Ecc>(
    e: &E,
    curve: TpmEccCurve,
    scalar: &[u8],
    public_point: &[u8],
    derived_point_out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let ctx = EccContext::new(e, curve)?;
    ctx.point_multiply(scalar, public_point, derived_point_out)
}

/// Signs `digest` using the ECDAA protocol on `curve` using [`EccContext`].
///
/// See [`EccContext::ecdaa_sign`].
#[allow(clippy::too_many_arguments)]
pub fn ecdaa_sign<E: Ecc>(
    e: &E,
    curve: TpmEccCurve,
    commit_r: &[u8],
    commit_x: &[u8],
    commit_p1: &[u8],
    private_key_d: &[u8],
    digest: &[u8],
    nonce_k_out: &mut [u8],
    s_out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let ctx = EccContext::new(e, curve)?;
    ctx.ecdaa_sign(
        commit_r,
        commit_x,
        commit_p1,
        private_key_d,
        digest,
        nonce_k_out,
        s_out,
    )
}
