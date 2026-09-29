//! TPM 2.0 Elliptic Curve Cryptography (ECC) Abstractions
//!
//! This module defines the cryptographic traits required for Elliptic Curve operations in TPM 2.0,
//! covering curve point validation, generator scalar multiplication, ECDH key agreement, and ECDAA signing protocols.
//!
//! Supported curves define a concrete `*Ctx` type implementing [`EccCurve<N, Error>`]
//! (where `N` is the coordinate and scalar size in bytes) and implement the corresponding
//! curve method on [`Ecc`] (e.g., [`Ecc::nist_p256()`]).
//!
//! Unimplemented curves bind their context type to [`!`] and omit the method, keeping the default
//! body of [`Err(self.unimplemented(Alg::ECC))`](Base::unimplemented).

use crate::{Alg, crypto::Base};

pub use crate::constants::TpmEccCurve;

/// Elliptic curve operations over a curve with coordinate/scalar size `N` bytes.
pub trait EccCurve<const N: usize, Error> {
    /// Returns the error value for invalid point or scalar data.
    fn invalid_data(&self) -> Error;

    /// Returns the error value when the output buffer is too small.
    fn buffer_too_small(&self) -> Error;

    /// Validates that the affine point `(x, y)` lies on the curve.
    fn validate_point(&self, x: &[u8; N], y: &[u8; N]) -> Result<(), Error>;

    /// Multiplies the curve's base generator point `G` by `scalar`: `(x_out, y_out) = scalar * G`.
    fn point_multiply_generator(
        &self,
        scalar: &[u8; N],
        x_out: &mut [u8; N],
        y_out: &mut [u8; N],
    ) -> Result<(), Error>;

    /// Multiplies the affine point `(x_in, y_in)` by `scalar`: `(x_out, y_out) = scalar * (x_in, y_in)`.
    fn point_multiply(
        &self,
        scalar: &[u8; N],
        x_in: &[u8; N],
        y_in: &[u8; N],
        x_out: &mut [u8; N],
        y_out: &mut [u8; N],
    ) -> Result<(), Error>;

    /// Signs a digest using the ECDAA protocol.
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
    ) -> Result<(), Error>;
}

impl<const N: usize, Error> EccCurve<N, Error> for ! {
    fn invalid_data(&self) -> Error {
        match *self {}
    }
    fn buffer_too_small(&self) -> Error {
        match *self {}
    }
    fn validate_point(&self, _: &[u8; N], _: &[u8; N]) -> Result<(), Error> {
        match *self {}
    }
    fn point_multiply_generator(
        &self,
        _: &[u8; N],
        _: &mut [u8; N],
        _: &mut [u8; N],
    ) -> Result<(), Error> {
        match *self {}
    }
    fn point_multiply(
        &self,
        _: &[u8; N],
        _: &[u8; N],
        _: &[u8; N],
        _: &mut [u8; N],
        _: &mut [u8; N],
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
        match *self {}
    }
}

/// Cryptographic ECC interfaces for TPM implementations and clients.
///
/// Supported curves define a concrete `*Ctx` type and implement:
///   - A method creating/initializing the curve context (e.g. [`Ecc::nist_p256()`])
///   - [`EccCurve<N, Error>`] for `*Ctx` (where `N` is the coordinate/scalar size in bytes)
///
/// Unimplemented curves bind their context type to [`!`] and
/// omit the method, keeping the default body of
/// [`Err(self.unimplemented(Alg::ECC))`](Base::unimplemented).
///
/// # Example
///
/// ```
/// # use tpm2::{crypto::{Base, Ecc, EccCurve}, Alg};
/// # struct MyBackend;
/// # #[derive(Debug, PartialEq, Eq)]
/// # struct MyError;
/// # impl Base for MyBackend {
/// #   type Error = MyError;
/// #   fn unimplemented(&self, _: Alg) -> MyError { MyError }
/// # }
/// # struct MyNistP256;
/// impl Ecc for MyBackend {
///     type NistP256Ctx = MyNistP256;
///     fn nist_p256(&self) -> Result<MyNistP256, MyError> { Ok(MyNistP256) }
///
///     // Unsupported curves use `!` and default methods:
///     type NistP192Ctx = !;
///     type NistP224Ctx = !;
///     type NistP384Ctx = !;
///     type NistP521Ctx = !;
///     type BnP256Ctx = !;
///     type BnP638Ctx = !;
///     type Sm2P256Ctx = !;
///     type BpP256R1Ctx = !;
///     type BpP384R1Ctx = !;
///     type BpP512R1Ctx = !;
///     type Curve25519Ctx = !;
///     type Curve448Ctx = !;
/// }
///
/// impl EccCurve<32, MyError> for MyNistP256 {
///     fn invalid_data(&self) -> MyError { MyError }
///     fn buffer_too_small(&self) -> MyError { MyError }
///     fn validate_point(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<(), MyError> { todo!() }
///     fn point_multiply_generator(
///         &self,
///         scalar: &[u8; 32],
///         x_out: &mut [u8; 32],
///         y_out: &mut [u8; 32],
///     ) -> Result<(), MyError> { todo!() }
///     fn point_multiply(
///         &self,
///         scalar: &[u8; 32],
///         x_in: &[u8; 32],
///         y_in: &[u8; 32],
///         x_out: &mut [u8; 32],
///         y_out: &mut [u8; 32],
///     ) -> Result<(), MyError> { todo!() }
///     fn ecdaa_sign(
///         &self,
///         commit_r: &[u8; 32],
///         commit_x: &[u8],
///         commit_p1: &[u8],
///         private_key_d: &[u8; 32],
///         digest: &[u8],
///         nonce_k_out: &mut [u8; 32],
///         s_out: &mut [u8; 32],
///     ) -> Result<(), MyError> { todo!() }
/// }
/// ```
pub trait Ecc: Base {
    type NistP192Ctx: EccCurve<24, Self::Error>;
    fn nist_p192(&self) -> Result<Self::NistP192Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type NistP224Ctx: EccCurve<28, Self::Error>;
    fn nist_p224(&self) -> Result<Self::NistP224Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type NistP256Ctx: EccCurve<32, Self::Error>;
    fn nist_p256(&self) -> Result<Self::NistP256Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type NistP384Ctx: EccCurve<48, Self::Error>;
    fn nist_p384(&self) -> Result<Self::NistP384Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type NistP521Ctx: EccCurve<66, Self::Error>;
    fn nist_p521(&self) -> Result<Self::NistP521Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type BnP256Ctx: EccCurve<32, Self::Error>;
    fn bn_p256(&self) -> Result<Self::BnP256Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type BnP638Ctx: EccCurve<80, Self::Error>;
    fn bn_p638(&self) -> Result<Self::BnP638Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type Sm2P256Ctx: EccCurve<32, Self::Error>;
    fn sm2_p256(&self) -> Result<Self::Sm2P256Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type BpP256R1Ctx: EccCurve<32, Self::Error>;
    fn bp_p256_r1(&self) -> Result<Self::BpP256R1Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type BpP384R1Ctx: EccCurve<48, Self::Error>;
    fn bp_p384_r1(&self) -> Result<Self::BpP384R1Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type BpP512R1Ctx: EccCurve<64, Self::Error>;
    fn bp_p512_r1(&self) -> Result<Self::BpP512R1Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type Curve25519Ctx: EccCurve<32, Self::Error>;
    fn curve25519(&self) -> Result<Self::Curve25519Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    type Curve448Ctx: EccCurve<56, Self::Error>;
    fn curve448(&self) -> Result<Self::Curve448Ctx, Self::Error> {
        Err(self.unimplemented(Alg::ECC))
    }

    /// Validates that `public_key` (`x || y`) is a valid affine point on `curve`.
    fn validate_point(&self, curve: TpmEccCurve, public_key: &[u8]) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        validate_point(self, curve, public_key)
    }

    /// Multiplies the base generator point `G` of `curve` by `scalar` and writes `x || y` into `public_key_out`.
    fn point_multiply_generator(
        &self,
        curve: TpmEccCurve,
        scalar: &[u8],
        public_key_out: &mut [u8],
    ) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        point_multiply_generator(self, curve, scalar, public_key_out)
    }

    /// Multiplies `public_point` (`x || y`) on `curve` by `scalar` and writes `x || y` into `derived_point_out`.
    fn point_multiply(
        &self,
        curve: TpmEccCurve,
        scalar: &[u8],
        public_point: &[u8],
        derived_point_out: &mut [u8],
    ) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        point_multiply(self, curve, scalar, public_point, derived_point_out)
    }

    /// Signs `digest` using the ECDAA protocol on `curve`.
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
    ) -> Result<(), Self::Error>
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

/// Dynamic ECC context wrapping curve-specific implementations.
pub enum EccCtx<E: Ecc> {
    #[cfg(feature = "ecc_curve_nist_p192")]
    NistP192(E::NistP192Ctx),
    #[cfg(feature = "ecc_curve_nist_p224")]
    NistP224(E::NistP224Ctx),
    #[cfg(feature = "ecc_curve_nist_p256")]
    NistP256(E::NistP256Ctx),
    #[cfg(feature = "ecc_curve_nist_p384")]
    NistP384(E::NistP384Ctx),
    #[cfg(feature = "ecc_curve_nist_p521")]
    NistP521(E::NistP521Ctx),
    #[cfg(feature = "ecc_curve_bn_p256")]
    BnP256(E::BnP256Ctx),
    #[cfg(feature = "ecc_curve_bn_p638")]
    BnP638(E::BnP638Ctx),
    #[cfg(feature = "ecc_curve_sm2_p256")]
    Sm2P256(E::Sm2P256Ctx),
    #[cfg(feature = "ecc_curve_bp_p256_r1")]
    BpP256R1(E::BpP256R1Ctx),
    #[cfg(feature = "ecc_curve_bp_p384_r1")]
    BpP384R1(E::BpP384R1Ctx),
    #[cfg(feature = "ecc_curve_bp_p512_r1")]
    BpP512R1(E::BpP512R1Ctx),
    #[cfg(feature = "ecc_curve_curve25519")]
    Curve25519(E::Curve25519Ctx),
    #[cfg(feature = "ecc_curve_curve448")]
    Curve448(E::Curve448Ctx),
    #[cfg(not(feature = "ecc"))]
    #[doc(hidden)]
    _Uninhabited(core::marker::PhantomData<E>, core::convert::Infallible),
}

impl<E: Ecc> EccCtx<E> {
    /// Initializes an ECC context for `curve` using backend `e`.
    pub fn new(e: &E, curve: TpmEccCurve) -> Result<Self, E::Error> {
        match curve {
            TpmEccCurve::None => Err(e.unimplemented(Alg::ECC)),
            #[cfg(feature = "ecc_curve_nist_p192")]
            TpmEccCurve::NistP192 => e.nist_p192().map(EccCtx::NistP192),
            #[cfg(feature = "ecc_curve_nist_p224")]
            TpmEccCurve::NistP224 => e.nist_p224().map(EccCtx::NistP224),
            #[cfg(feature = "ecc_curve_nist_p256")]
            TpmEccCurve::NistP256 => e.nist_p256().map(EccCtx::NistP256),
            #[cfg(feature = "ecc_curve_nist_p384")]
            TpmEccCurve::NistP384 => e.nist_p384().map(EccCtx::NistP384),
            #[cfg(feature = "ecc_curve_nist_p521")]
            TpmEccCurve::NistP521 => e.nist_p521().map(EccCtx::NistP521),
            #[cfg(feature = "ecc_curve_bn_p256")]
            TpmEccCurve::BNP256 => e.bn_p256().map(EccCtx::BnP256),
            #[cfg(feature = "ecc_curve_bn_p638")]
            TpmEccCurve::BNP638 => e.bn_p638().map(EccCtx::BnP638),
            #[cfg(feature = "ecc_curve_sm2_p256")]
            TpmEccCurve::SM2P256 => e.sm2_p256().map(EccCtx::Sm2P256),
            #[cfg(feature = "ecc_curve_bp_p256_r1")]
            TpmEccCurve::BpP256R1 => e.bp_p256_r1().map(EccCtx::BpP256R1),
            #[cfg(feature = "ecc_curve_bp_p384_r1")]
            TpmEccCurve::BpP384R1 => e.bp_p384_r1().map(EccCtx::BpP384R1),
            #[cfg(feature = "ecc_curve_bp_p512_r1")]
            TpmEccCurve::BpP512R1 => e.bp_p512_r1().map(EccCtx::BpP512R1),
            #[cfg(feature = "ecc_curve_curve25519")]
            TpmEccCurve::Curve25519 => e.curve25519().map(EccCtx::Curve25519),
            #[cfg(feature = "ecc_curve_curve448")]
            TpmEccCurve::Curve448 => e.curve448().map(EccCtx::Curve448),
        }
    }

    /// Validates that `public_key` (`x || y`) lies on the curve.
    pub fn validate_point(&self, public_key: &[u8]) -> Result<(), E::Error> {
        fn helper<const N: usize, Error>(
            ctx: &impl EccCurve<N, Error>,
            public_key: &[u8],
        ) -> Result<(), Error> {
            if public_key.len() != 2 * N {
                return Err(ctx.invalid_data());
            }
            let (x, y) = public_key.split_at(N);
            let x: &[u8; N] = x.try_into().unwrap();
            let y: &[u8; N] = y.try_into().unwrap();
            ctx.validate_point(x, y)
        }

        match self {
            #[cfg(feature = "ecc_curve_nist_p192")]
            EccCtx::NistP192(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_nist_p224")]
            EccCtx::NistP224(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_nist_p256")]
            EccCtx::NistP256(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_nist_p384")]
            EccCtx::NistP384(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_nist_p521")]
            EccCtx::NistP521(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_bn_p256")]
            EccCtx::BnP256(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_bn_p638")]
            EccCtx::BnP638(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_sm2_p256")]
            EccCtx::Sm2P256(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_bp_p256_r1")]
            EccCtx::BpP256R1(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_bp_p384_r1")]
            EccCtx::BpP384R1(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_bp_p512_r1")]
            EccCtx::BpP512R1(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_curve25519")]
            EccCtx::Curve25519(ctx) => helper(ctx, public_key),
            #[cfg(feature = "ecc_curve_curve448")]
            EccCtx::Curve448(ctx) => helper(ctx, public_key),
            #[cfg(not(feature = "ecc"))]
            EccCtx::_Uninhabited(_, never) => match *never {},
        }
    }

    /// Multiplies the base generator point `G` by `scalar` and writes `x || y` into `public_key_out`.
    pub fn point_multiply_generator(
        &self,
        scalar: &[u8],
        public_key_out: &mut [u8],
    ) -> Result<(), E::Error> {
        fn helper<const N: usize, Error>(
            ctx: &impl EccCurve<N, Error>,
            scalar: &[u8],
            public_key_out: &mut [u8],
        ) -> Result<(), Error> {
            if scalar.len() > N {
                return Err(ctx.invalid_data());
            }
            let mut scalar_buf = [0u8; N];
            scalar_buf[N - scalar.len()..].copy_from_slice(scalar);
            let mut x_out = [0u8; N];
            let mut y_out = [0u8; N];
            ctx.point_multiply_generator(&scalar_buf, &mut x_out, &mut y_out)?;
            if public_key_out.len() < 2 * N {
                return Err(ctx.buffer_too_small());
            }
            public_key_out[..N].copy_from_slice(&x_out);
            public_key_out[N..2 * N].copy_from_slice(&y_out);
            Ok(())
        }

        match self {
            #[cfg(feature = "ecc_curve_nist_p192")]
            EccCtx::NistP192(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_nist_p224")]
            EccCtx::NistP224(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_nist_p256")]
            EccCtx::NistP256(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_nist_p384")]
            EccCtx::NistP384(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_nist_p521")]
            EccCtx::NistP521(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_bn_p256")]
            EccCtx::BnP256(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_bn_p638")]
            EccCtx::BnP638(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_sm2_p256")]
            EccCtx::Sm2P256(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_bp_p256_r1")]
            EccCtx::BpP256R1(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_bp_p384_r1")]
            EccCtx::BpP384R1(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_bp_p512_r1")]
            EccCtx::BpP512R1(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_curve25519")]
            EccCtx::Curve25519(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(feature = "ecc_curve_curve448")]
            EccCtx::Curve448(ctx) => helper(ctx, scalar, public_key_out),
            #[cfg(not(feature = "ecc"))]
            EccCtx::_Uninhabited(_, never) => match *never {},
        }
    }

    /// Multiplies `public_point` (`x || y`) by `scalar` and writes `x || y` into `derived_point_out`.
    pub fn point_multiply(
        &self,
        scalar: &[u8],
        public_point: &[u8],
        derived_point_out: &mut [u8],
    ) -> Result<(), E::Error> {
        fn helper<const N: usize, Error>(
            ctx: &impl EccCurve<N, Error>,
            scalar: &[u8],
            public_point: &[u8],
            derived_point_out: &mut [u8],
        ) -> Result<(), Error> {
            if derived_point_out.len() < 2 * N {
                return Err(ctx.buffer_too_small());
            }
            if public_point.len() != 2 * N || scalar.len() > N {
                return Err(ctx.invalid_data());
            }
            let mut scalar_buf = [0u8; N];
            scalar_buf[N - scalar.len()..].copy_from_slice(scalar);
            let (x_in, y_in) = public_point.split_at(N);
            let x_in: &[u8; N] = x_in.try_into().unwrap();
            let y_in: &[u8; N] = y_in.try_into().unwrap();
            let (x_out, rest) = derived_point_out.split_at_mut(N);
            let (y_out, _) = rest.split_at_mut(N);
            let x_out: &mut [u8; N] = x_out.try_into().unwrap();
            let y_out: &mut [u8; N] = y_out.try_into().unwrap();
            ctx.point_multiply(&scalar_buf, x_in, y_in, x_out, y_out)
        }

        match self {
            #[cfg(feature = "ecc_curve_nist_p192")]
            EccCtx::NistP192(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_nist_p224")]
            EccCtx::NistP224(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_nist_p256")]
            EccCtx::NistP256(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_nist_p384")]
            EccCtx::NistP384(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_nist_p521")]
            EccCtx::NistP521(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_bn_p256")]
            EccCtx::BnP256(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_bn_p638")]
            EccCtx::BnP638(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_sm2_p256")]
            EccCtx::Sm2P256(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_bp_p256_r1")]
            EccCtx::BpP256R1(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_bp_p384_r1")]
            EccCtx::BpP384R1(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_bp_p512_r1")]
            EccCtx::BpP512R1(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_curve25519")]
            EccCtx::Curve25519(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(feature = "ecc_curve_curve448")]
            EccCtx::Curve448(ctx) => helper(ctx, scalar, public_point, derived_point_out),
            #[cfg(not(feature = "ecc"))]
            EccCtx::_Uninhabited(_, never) => match *never {},
        }
    }

    /// Signs a digest using the ECDAA protocol.
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
    ) -> Result<(), E::Error> {
        #[allow(clippy::too_many_arguments)]
        fn helper<const N: usize, Error>(
            ctx: &impl EccCurve<N, Error>,
            commit_r: &[u8],
            commit_x: &[u8],
            commit_p1: &[u8],
            private_key_d: &[u8],
            digest: &[u8],
            nonce_k_out: &mut [u8],
            s_out: &mut [u8],
        ) -> Result<(), Error> {
            if commit_r.len() > N
                || private_key_d.len() > N
                || nonce_k_out.len() < N
                || s_out.len() < N
            {
                return Err(ctx.invalid_data());
            }
            let mut r_buf = [0u8; N];
            r_buf[N - commit_r.len()..].copy_from_slice(commit_r);
            let mut d_buf = [0u8; N];
            d_buf[N - private_key_d.len()..].copy_from_slice(private_key_d);
            let k_out: &mut [u8; N] = nonce_k_out.first_chunk_mut().unwrap();
            let s_out: &mut [u8; N] = s_out.first_chunk_mut().unwrap();
            ctx.ecdaa_sign(&r_buf, commit_x, commit_p1, &d_buf, digest, k_out, s_out)
        }

        match self {
            #[cfg(feature = "ecc_curve_nist_p192")]
            EccCtx::NistP192(ctx) => helper(
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
            EccCtx::NistP224(ctx) => helper(
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
            EccCtx::NistP256(ctx) => helper(
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
            EccCtx::NistP384(ctx) => helper(
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
            EccCtx::NistP521(ctx) => helper(
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
            EccCtx::BnP256(ctx) => helper(
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
            EccCtx::BnP638(ctx) => helper(
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
            EccCtx::Sm2P256(ctx) => helper(
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
            EccCtx::BpP256R1(ctx) => helper(
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
            EccCtx::BpP384R1(ctx) => helper(
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
            EccCtx::BpP512R1(ctx) => helper(
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
            EccCtx::Curve25519(ctx) => helper(
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
            EccCtx::Curve448(ctx) => helper(
                ctx,
                commit_r,
                commit_x,
                commit_p1,
                private_key_d,
                digest,
                nonce_k_out,
                s_out,
            ),
            #[cfg(not(feature = "ecc"))]
            EccCtx::_Uninhabited(_, never) => match *never {},
        }
    }
}

/// Validates that `public_key` (`x || y`) lies on `curve` using [`EccCtx`].
pub fn validate_point<E: Ecc>(
    e: &E,
    curve: TpmEccCurve,
    public_key: &[u8],
) -> Result<(), E::Error> {
    let ctx = EccCtx::new(e, curve)?;
    ctx.validate_point(public_key)
}

/// Multiplies the base generator point `G` of `curve` by `scalar` using [`EccCtx`].
pub fn point_multiply_generator<E: Ecc>(
    e: &E,
    curve: TpmEccCurve,
    scalar: &[u8],
    public_key_out: &mut [u8],
) -> Result<(), E::Error> {
    let ctx = EccCtx::new(e, curve)?;
    ctx.point_multiply_generator(scalar, public_key_out)
}

/// Multiplies `public_point` (`x || y`) on `curve` by `scalar` using [`EccCtx`].
pub fn point_multiply<E: Ecc>(
    e: &E,
    curve: TpmEccCurve,
    scalar: &[u8],
    public_point: &[u8],
    derived_point_out: &mut [u8],
) -> Result<(), E::Error> {
    let ctx = EccCtx::new(e, curve)?;
    ctx.point_multiply(scalar, public_point, derived_point_out)
}

/// Signs `digest` using the ECDAA protocol on `curve` using [`EccCtx`].
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
) -> Result<(), E::Error> {
    let ctx = EccCtx::new(e, curve)?;
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
