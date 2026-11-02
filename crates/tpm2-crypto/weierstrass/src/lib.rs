//! Generic, constant-time arithmetic on short Weierstrass curves `y^2 = x^3 + a*x + b` over
//! prime fields, for the TPM 2.0 curves that the cryptographic libraries of the backends do not
//! offer.
//!
//! [`Curve`] implements point validation, scalar multiplication and key generation for any
//! [`EccCurveParams`] of prime order (cofactor 1) whose coordinate size is exactly the size of
//! the `LIMBS`-limb integers it is instantiated with. The field arithmetic is the Montgomery
//! arithmetic of [`crypto_bigint`] with a modulus set at runtime ([`DynResidue`]). Scalar
//! multiplication is a Montgomery ladder over all bits of the group order with constant-time
//! conditional swaps, using the complete projective addition formulas of Renes, Costello and
//! Batina ("Complete addition formulas for prime order elliptic curves", EUROCRYPT 2016,
//! algorithm 1, for a general `a`), which are valid for all pairs of points of an odd-order
//! curve, including doublings and the point at infinity: the sequence of field operations does
//! not depend on the secret scalar.
//!
//! The curves used by the `tpm2-crypto-*` backends are NIST P-192 ([`NistP192`]), BN P-638
//! ([`BnP638`]) and SM2 P-256 ([`Sm2P256`]); their contexts implement
//! [`EccCurve`] with the conventions of `tpm2::crypto::ecc`
//! (`Ok(false)` / `Ok(None)` for invalid points, invalid scalars and the point at infinity;
//! ECDAA signing is [`CryptoError::Unsupported`], as `tpm2-engine` computes it from the
//! generic primitives), and [`generate_key`] implements
//! [`Asymmetric::ecc_generate_key`](tpm2::crypto::Asymmetric::ecc_generate_key) for them.
//!
//! The curve parameters are the always-present statics of [`tpm2::crypto::ecc_params`], so
//! that this crate does not enable any `ecc_curve_*` feature of `tpm2` (which would widen the
//! TPM built with it).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use crypto_bigint::{Limb, U192, U256, U640, Uint, Word};
use tpm2::crypto::ecc_params::{BN_P638, EccCurveParams, NIST_P192, SM2_P256};
use tpm2::crypto::{CryptoError, EccCurve};

/// A field element in Montgomery form.
type Fe<const LIMBS: usize> = DynResidue<LIMBS>;

/// A point in homogeneous projective coordinates `(X : Y : Z)`, representing the affine point
/// `(X/Z, Y/Z)`; `Z = 0` is the point at infinity.
#[derive(Clone, Copy, Debug)]
struct Point<const LIMBS: usize> {
    x: Fe<LIMBS>,
    y: Fe<LIMBS>,
    z: Fe<LIMBS>,
}

impl<const LIMBS: usize> ConditionallySelectable for Point<LIMBS> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: Fe::conditional_select(&a.x, &b.x, choice),
            y: Fe::conditional_select(&a.y, &b.y, choice),
            z: Fe::conditional_select(&a.z, &b.z, choice),
        }
    }
}

/// Decodes the big-endian integer `bytes` (at most `LIMBS` limbs long).
fn decode<const LIMBS: usize>(bytes: &[u8]) -> Option<Uint<LIMBS>> {
    if bytes.len() > LIMBS * Limb::BYTES {
        return None;
    }
    let mut words = [0 as Word; LIMBS];
    for (i, &byte) in bytes.iter().rev().enumerate() {
        words[i / Limb::BYTES] |= Word::from(byte) << (8 * (i % Limb::BYTES));
    }
    Some(Uint::from_words(words))
}

/// Encodes `value` big-endian into `out`, which is exactly `LIMBS` limbs long.
fn encode<const LIMBS: usize>(value: &Uint<LIMBS>, out: &mut [u8]) -> Result<(), CryptoError> {
    if out.len() != LIMBS * Limb::BYTES {
        return Err(CryptoError::Internal);
    }
    for (chunk, word) in out.rchunks_exact_mut(Limb::BYTES).zip(value.as_words()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    Ok(())
}

/// A short Weierstrass curve of prime order whose coordinates and scalars are `LIMBS` limbs
/// (`Curve::<LIMBS>::BYTES` bytes) long.
#[derive(Clone, Debug)]
pub struct Curve<const LIMBS: usize> {
    params: &'static EccCurveParams,
    p: Uint<LIMBS>,
    n: Uint<LIMBS>,
    n_bits: usize,
    a: Fe<LIMBS>,
    b: Fe<LIMBS>,
    b3: Fe<LIMBS>,
    g: Point<LIMBS>,
}

impl<const LIMBS: usize> Curve<LIMBS> {
    /// The size of a coordinate and of a scalar in bytes.
    pub const BYTES: usize = LIMBS * Limb::BYTES;

    /// Creates the context of the curve `params`.
    ///
    /// Returns [`CryptoError::Internal`] if the curve does not fit this instantiation: its
    /// coordinate size is not [`Self::BYTES`], its order is longer, its prime is even, a
    /// coefficient or generator coordinate is not reduced, or its cofactor is not 1.
    pub fn new(params: &'static EccCurveParams) -> Result<Self, CryptoError> {
        let p: Uint<LIMBS> = decode(params.p).ok_or(CryptoError::Internal)?;
        let n: Uint<LIMBS> = decode(params.n).ok_or(CryptoError::Internal)?;
        if params.coordinate_size() != Self::BYTES
            || p.as_words()[0] & 1 == 0
            || params.h != [1]
            || n == Uint::ZERO
        {
            return Err(CryptoError::Internal);
        }
        let field = DynResidueParams::new(&p);
        let element = |bytes: &[u8]| -> Result<Fe<LIMBS>, CryptoError> {
            let value = decode(bytes).ok_or(CryptoError::Internal)?;
            if value >= p {
                return Err(CryptoError::Internal);
            }
            Ok(Fe::new(&value, field))
        };
        let a = element(params.a)?;
        let b = element(params.b)?;
        let g = Point {
            x: element(params.gx)?,
            y: element(params.gy)?,
            z: Fe::one(field),
        };
        Ok(Self {
            params,
            p,
            n,
            n_bits: n.bits_vartime(),
            a,
            b,
            b3: b + b + b,
            g,
        })
    }

    /// The domain parameters of the curve.
    pub fn params(&self) -> &'static EccCurveParams {
        self.params
    }

    /// Decodes a coordinate: `None` if it is not smaller than the field prime.
    fn coordinate(&self, bytes: &[u8]) -> Option<Fe<LIMBS>> {
        let value = decode(bytes)?;
        if value >= self.p {
            return None;
        }
        Some(Fe::new(&value, *self.a.params()))
    }

    /// Whether the affine point `(x, y)` satisfies the curve equation.
    fn on_curve(&self, x: &Fe<LIMBS>, y: &Fe<LIMBS>) -> bool {
        let rhs = x.square() * x + self.a * x + self.b;
        y.square().ct_eq(&rhs).into()
    }

    /// Decodes a scalar: `None` unless it is in `[1, n - 1]`.
    fn scalar(&self, bytes: &[u8]) -> Option<Uint<LIMBS>> {
        let k: Uint<LIMBS> = decode(bytes)?;
        let valid = !k.ct_eq(&Uint::ZERO) & k.ct_lt(&self.n);
        bool::from(valid).then_some(k)
    }

    /// The point at infinity `(0 : 1 : 0)`.
    fn identity(&self) -> Point<LIMBS> {
        let field = *self.a.params();
        Point {
            x: Fe::zero(field),
            y: Fe::one(field),
            z: Fe::zero(field),
        }
    }

    /// `p + q` with the complete addition formulas of Renes-Costello-Batina 2016, algorithm 1
    /// (also valid for `p == q` and for the point at infinity).
    fn add(&self, p: &Point<LIMBS>, q: &Point<LIMBS>) -> Point<LIMBS> {
        let (a, b3) = (self.a, self.b3);
        let (x1, y1, z1) = (p.x, p.y, p.z);
        let (x2, y2, z2) = (q.x, q.y, q.z);
        let mut t0 = x1 * x2;
        let mut t1 = y1 * y2;
        let mut t2 = z1 * z2;
        let mut t3 = x1 + y1;
        let mut t4 = x2 + y2;
        t3 *= t4;
        t4 = t0 + t1;
        t3 -= t4;
        t4 = x1 + z1;
        let mut t5 = x2 + z2;
        t4 *= t5;
        t5 = t0 + t2;
        t4 -= t5;
        t5 = y1 + z1;
        let mut x3 = y2 + z2;
        t5 *= x3;
        x3 = t1 + t2;
        t5 -= x3;
        let mut z3 = a * t4;
        x3 = b3 * t2;
        z3 = x3 + z3;
        x3 = t1 - z3;
        z3 = t1 + z3;
        let mut y3 = x3 * z3;
        t1 = t0 + t0;
        t1 += t0;
        t2 = a * t2;
        t4 = b3 * t4;
        t1 += t2;
        t2 = t0 - t2;
        t2 = a * t2;
        t4 += t2;
        t0 = t1 * t4;
        y3 += t0;
        t0 = t5 * t4;
        x3 = t3 * x3;
        x3 -= t0;
        t0 = t3 * t1;
        z3 = t5 * z3;
        z3 += t0;
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `k * p` by a Montgomery ladder over the bits of the group order, with constant-time
    /// conditional swaps.
    fn multiply(&self, k: &Uint<LIMBS>, p: &Point<LIMBS>) -> Point<LIMBS> {
        let mut r0 = self.identity();
        let mut r1 = *p;
        let mut swapped = Choice::from(0);
        for i in (0..self.n_bits).rev() {
            let bit = Choice::from(k.bit(i));
            Point::conditional_swap(&mut r0, &mut r1, swapped ^ bit);
            swapped = bit;
            r1 = self.add(&r0, &r1);
            r0 = self.add(&r0, &r0);
        }
        Point::conditional_swap(&mut r0, &mut r1, swapped);
        r0
    }

    /// Writes the affine coordinates of `p`, or returns `Ok(None)` for the point at infinity.
    fn write_affine(
        &self,
        p: &Point<LIMBS>,
        x_out: &mut [u8],
        y_out: &mut [u8],
    ) -> Result<Option<()>, CryptoError> {
        let (z_inv, invertible) = p.z.invert();
        if !bool::from(invertible) {
            return Ok(None);
        }
        encode(&(p.x * z_inv).retrieve(), x_out)?;
        encode(&(p.y * z_inv).retrieve(), y_out)?;
        Ok(Some(()))
    }

    /// Validates that the affine point `(x, y)` lies on the curve: `Ok(false)` if it does not
    /// (including coordinates that are not smaller than the field prime).
    ///
    /// Both coordinates must be [`Self::BYTES`] long ([`CryptoError::Internal`] otherwise).
    pub fn validate_point(&self, x: &[u8], y: &[u8]) -> Result<bool, CryptoError> {
        if x.len() != Self::BYTES || y.len() != Self::BYTES {
            return Err(CryptoError::Internal);
        }
        Ok(match (self.coordinate(x), self.coordinate(y)) {
            (Some(x), Some(y)) => self.on_curve(&x, &y),
            _ => false,
        })
    }

    /// `(x_out, y_out) = scalar * G`: `Ok(None)` if `scalar` is not in `[1, n - 1]`.
    ///
    /// All buffers must be [`Self::BYTES`] long ([`CryptoError::Internal`] otherwise).
    pub fn point_multiply_generator(
        &self,
        scalar: &[u8],
        x_out: &mut [u8],
        y_out: &mut [u8],
    ) -> Result<Option<()>, CryptoError> {
        if scalar.len() != Self::BYTES {
            return Err(CryptoError::Internal);
        }
        let Some(k) = self.scalar(scalar) else {
            return Ok(None);
        };
        self.write_affine(&self.multiply(&k, &self.g), x_out, y_out)
    }

    /// `(x_out, y_out) = scalar * (x_in, y_in)`: `Ok(None)` if `(x_in, y_in)` is not a point
    /// of the curve, if `scalar` is not in `[1, n - 1]`, or if the product is the point at
    /// infinity.
    ///
    /// All buffers must be [`Self::BYTES`] long ([`CryptoError::Internal`] otherwise).
    pub fn point_multiply(
        &self,
        scalar: &[u8],
        x_in: &[u8],
        y_in: &[u8],
        x_out: &mut [u8],
        y_out: &mut [u8],
    ) -> Result<Option<()>, CryptoError> {
        if scalar.len() != Self::BYTES || x_in.len() != Self::BYTES || y_in.len() != Self::BYTES {
            return Err(CryptoError::Internal);
        }
        let (Some(x), Some(y)) = (self.coordinate(x_in), self.coordinate(y_in)) else {
            return Ok(None);
        };
        if !self.on_curve(&x, &y) {
            return Ok(None);
        }
        let Some(k) = self.scalar(scalar) else {
            return Ok(None);
        };
        let p = Point {
            x,
            y,
            z: Fe::one(*self.a.params()),
        };
        self.write_affine(&self.multiply(&k, &p), x_out, y_out)
    }

    /// Generates a key pair: draws the private scalar `d` uniformly from `[1, n - 1]` by
    /// rejection sampling of [`Self::BYTES`]-byte strings from `fill` (masked to the bit length
    /// of `n`), writes `d` ([`Self::BYTES`] bytes) to `private_key` and `d * G` (`x || y`, each
    /// [`Self::BYTES`] bytes) to `public_key`, and returns `(public_len, private_len)`.
    ///
    /// The result depends only on the bytes drawn from `fill` (so a seeded `fill` gives a
    /// deterministic key). Returns [`CryptoError::Internal`] if an output buffer is too small,
    /// or if no valid scalar was drawn in 128 attempts (each succeeds with probability above
    /// 1/2).
    pub fn generate_key(
        &self,
        fill: &mut dyn FnMut(&mut [u8]) -> Result<(), CryptoError>,
        public_key: &mut [u8],
        private_key: &mut [u8],
    ) -> Result<(usize, usize), CryptoError> {
        const MAX_BYTES: usize = 128;
        let size = Self::BYTES;
        if size > MAX_BYTES || public_key.len() < 2 * size || private_key.len() < size {
            return Err(CryptoError::Internal);
        }
        let mask = Uint::<LIMBS>::MAX.shr_vartime(LIMBS * Limb::BITS - self.n_bits);
        let mut buffer = [0u8; MAX_BYTES];
        for _ in 0..128 {
            fill(&mut buffer[..size])?;
            let candidate = decode::<LIMBS>(&buffer[..size]).ok_or(CryptoError::Internal)?;
            let k = candidate.bitand(&mask);
            buffer.fill(0);
            if !bool::from(!k.ct_eq(&Uint::ZERO) & k.ct_lt(&self.n)) {
                continue;
            }
            let (x_out, rest) = public_key.split_at_mut(size);
            if self
                .write_affine(&self.multiply(&k, &self.g), x_out, &mut rest[..size])?
                .is_none()
            {
                return Err(CryptoError::Internal);
            }
            encode(&k, &mut private_key[..size])?;
            return Ok((2 * size, size));
        }
        Err(CryptoError::Internal)
    }
}

/// NIST P-192 ([`NIST_P192`]).
pub type NistP192 = Curve<{ U192::LIMBS }>;
/// SM2 P-256 ([`SM2_P256`]).
pub type Sm2P256 = Curve<{ U256::LIMBS }>;
/// BN P-638 ([`BN_P638`]).
pub type BnP638 = Curve<{ U640::LIMBS }>;

/// The context of NIST P-192.
pub fn nist_p192() -> Result<NistP192, CryptoError> {
    Curve::new(&NIST_P192)
}

/// The context of SM2 P-256.
pub fn sm2_p256() -> Result<Sm2P256, CryptoError> {
    Curve::new(&SM2_P256)
}

/// The context of BN P-638.
pub fn bn_p638() -> Result<BnP638, CryptoError> {
    Curve::new(&BN_P638)
}

/// Implements [`EccCurve`] for a curve context by delegating to its inherent methods.
macro_rules! impl_ecc_curve {
    ($curve:ty, $n:literal) => {
        impl EccCurve<$n> for $curve {
            fn validate_point(&self, x: &[u8; $n], y: &[u8; $n]) -> Result<bool, CryptoError> {
                Curve::validate_point(self, x, y)
            }

            fn point_multiply_generator(
                &self,
                scalar: &[u8; $n],
                x_out: &mut [u8; $n],
                y_out: &mut [u8; $n],
            ) -> Result<Option<()>, CryptoError> {
                Curve::point_multiply_generator(self, scalar, x_out, y_out)
            }

            fn point_multiply(
                &self,
                scalar: &[u8; $n],
                x_in: &[u8; $n],
                y_in: &[u8; $n],
                x_out: &mut [u8; $n],
                y_out: &mut [u8; $n],
            ) -> Result<Option<()>, CryptoError> {
                Curve::point_multiply(self, scalar, x_in, y_in, x_out, y_out)
            }

            /// Not provided: `tpm2-engine` computes ECDAA signatures (TPM 2.0 Part 1, "ECDAA
            /// Sign Operation") from the generic primitives, as for the other curves.
            fn ecdaa_sign(
                &self,
                _commit_r: &[u8; $n],
                _commit_x: &[u8],
                _commit_p1: &[u8],
                _private_key_d: &[u8; $n],
                _digest: &[u8],
                _nonce_k_out: &mut [u8; $n],
                _s_out: &mut [u8; $n],
            ) -> Result<Option<()>, CryptoError> {
                Err(CryptoError::Unsupported)
            }
        }
    };
}

impl_ecc_curve!(NistP192, 24);
impl_ecc_curve!(Sm2P256, 32);
impl_ecc_curve!(BnP638, 80);

/// Generates a key pair on the curve with the `TPM_ECC_CURVE` identifier `curve_id`, if it is
/// one of the curves of this crate (see [`Curve::generate_key`]); `None` for any other curve.
///
/// `fill` supplies the random bytes (from a seeded generator for a deterministic key).
pub fn generate_key(
    curve_id: u16,
    fill: &mut dyn FnMut(&mut [u8]) -> Result<(), CryptoError>,
    public_key: &mut [u8],
    private_key: &mut [u8],
) -> Option<Result<(usize, usize), CryptoError>> {
    Some(match curve_id {
        id if id == NIST_P192.curve_id => {
            nist_p192().and_then(|c| c.generate_key(fill, public_key, private_key))
        }
        id if id == SM2_P256.curve_id => {
            sm2_p256().and_then(|c| c.generate_key(fill, public_key, private_key))
        }
        id if id == BN_P638.curve_id => {
            bn_p638().and_then(|c| c.generate_key(fill, public_key, private_key))
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests;
