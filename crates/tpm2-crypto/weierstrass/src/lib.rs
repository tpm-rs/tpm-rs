//! Generic, constant-time arithmetic on short Weierstrass curves `y^2 = x^3 + a*x + b` over
//! prime fields, for the TPM 2.0 curves that the cryptographic libraries of the backends do not
//! offer.
//!
//! [`Curve`] implements point validation, scalar multiplication, key generation, ECDSA and SM2
//! for any [`EccCurveParams`] of prime order (cofactor 1) whose coordinate size is at most the
//! size of the `LIMBS`-limb integers it is instantiated with. The field arithmetic (and the
//! arithmetic modulo the group order) is the Montgomery arithmetic of [`crypto_bigint`] with a
//! modulus set at runtime ([`DynResidue`]). Scalar multiplication is a Montgomery ladder over all
//! bits of the group order with constant-time conditional swaps, using the complete projective
//! addition formulas of Renes, Costello and Batina ("Complete addition formulas for prime order
//! elliptic curves", EUROCRYPT 2016, algorithm 1, for a general `a`), which are valid for all
//! pairs of points of an odd-order curve, including doublings and the point at infinity: the
//! sequence of field operations does not depend on the secret scalar.
//!
//! The key types [`EcPrivateKey`] and [`EcPublicKey`] implement the backend traits [`EccCurve`]
//! and [`PrivateKey`] of `tpm2::crypto::backend` (including the tpm-rs extensions
//! [`EccCurve::mul_generator`] and [`EccCurve::mul_point`], and `SM2`) for any random number
//! generator, so that every backend can bind its associated curve types to them.
//! The curves of this crate are NIST P-192 ([`NistP192`]), NIST P-224 ([`NistP224`]), BN P-256
//! ([`BnP256`]), BN P-638 ([`BnP638`]) and SM2 P-256 ([`Sm2P256`]).
//!
//! The curve parameters are the always-present statics of [`tpm2::crypto::ecc_params`], so
//! that this crate does not enable any curve feature of `tpm2` (which would widen the TPM built
//! with it).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::marker::PhantomData;

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use crypto_bigint::{Limb, U192, U256, U640, Uint, Word};
use tpm2::crypto::backend::{EccCurve, PrivateKey};
use tpm2::crypto::ecc_params::{BN_P256, BN_P638, EccCurveParams, NIST_P192, NIST_P224, SM2_P256};
use tpm2::crypto::{CryptoError, Rng};
use zeroize::Zeroize;

/// A field element (or an integer modulo the group order) in Montgomery form.
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

/// Encodes `value` big-endian into `out` (at most `LIMBS` limbs long), which must be long enough
/// to hold `value` ([`CryptoError::Internal`] otherwise).
fn encode<const LIMBS: usize>(value: &Uint<LIMBS>, out: &mut [u8]) -> Result<(), CryptoError> {
    if out.len() > LIMBS * Limb::BYTES {
        return Err(CryptoError::Internal);
    }
    let words = value.as_words();
    let byte = |i: usize| (words[i / Limb::BYTES] >> (8 * (i % Limb::BYTES))) as u8;
    // The bytes of `value` that do not fit into `out` must be zero.
    let mut overflow = 0u8;
    for i in out.len()..LIMBS * Limb::BYTES {
        overflow |= byte(i);
    }
    if overflow != 0 {
        return Err(CryptoError::Internal);
    }
    let len = out.len();
    for (i, b) in out.iter_mut().enumerate() {
        *b = byte(len - 1 - i);
    }
    Ok(())
}

/// The largest coordinate size supported by [`Curve::generate_key`] (and the key types).
const MAX_BYTES: usize = 128;

/// A short Weierstrass curve of prime order whose coordinates and scalars fit into `LIMBS` limbs
/// (`Curve::<LIMBS>::BYTES` bytes).
///
/// Coordinates and scalars are big-endian byte strings of exactly the coordinate size of the
/// curve ([`Self::size`], which may be smaller than [`Self::BYTES`], e.g. 28 bytes for NIST P-224
/// with 4 limbs of 64 bits).
#[derive(Clone, Debug)]
pub struct Curve<const LIMBS: usize> {
    params: &'static EccCurveParams,
    size: usize,
    p: Uint<LIMBS>,
    n: Uint<LIMBS>,
    n_bits: usize,
    /// The parameters of the arithmetic modulo `n`.
    scalars: DynResidueParams<LIMBS>,
    a: Fe<LIMBS>,
    b: Fe<LIMBS>,
    b3: Fe<LIMBS>,
    g: Point<LIMBS>,
}

impl<const LIMBS: usize> Curve<LIMBS> {
    /// The size of the integers of this instantiation in bytes (an upper bound of the coordinate
    /// size of the curve).
    pub const BYTES: usize = LIMBS * Limb::BYTES;

    /// Creates the context of the curve `params`.
    ///
    /// Returns [`CryptoError::Internal`] if the curve does not fit this instantiation: its
    /// coordinate size exceeds [`Self::BYTES`] (or 128 bytes), its order is longer than its
    /// coordinates, its prime or order is even, a coefficient or generator coordinate is not
    /// reduced, or its cofactor is not 1.
    pub fn new(params: &'static EccCurveParams) -> Result<Self, CryptoError> {
        let size = params.coordinate_size();
        let p: Uint<LIMBS> = decode(params.p).ok_or(CryptoError::Internal)?;
        let n: Uint<LIMBS> = decode(params.n).ok_or(CryptoError::Internal)?;
        if size > Self::BYTES
            || size > MAX_BYTES
            || params.scalar_size() > size
            || p.as_words()[0] & 1 == 0
            || n.as_words()[0] & 1 == 0
            || params.h != [1]
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
            size,
            p,
            n,
            n_bits: n.bits_vartime(),
            scalars: DynResidueParams::new(&n),
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

    /// The coordinate (and scalar) size of the curve in bytes.
    pub fn size(&self) -> usize {
        self.size
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

    /// Decodes and validates the affine point `(x, y)`: `None` if a coordinate is not smaller
    /// than the field prime or the point is not on the curve.
    fn point(&self, x: &[u8], y: &[u8]) -> Option<Point<LIMBS>> {
        let (x, y) = (self.coordinate(x)?, self.coordinate(y)?);
        self.on_curve(&x, &y).then(|| Point {
            x,
            y,
            z: Fe::one(*self.a.params()),
        })
    }

    /// Whether `k` is in `[1, n - 1]`.
    fn valid_scalar(&self, k: &Uint<LIMBS>) -> Choice {
        !k.ct_eq(&Uint::ZERO) & k.ct_lt(&self.n)
    }

    /// Decodes a scalar: `None` unless it is in `[1, n - 1]`.
    fn scalar(&self, bytes: &[u8]) -> Option<Uint<LIMBS>> {
        let k: Uint<LIMBS> = decode(bytes)?;
        bool::from(self.valid_scalar(&k)).then_some(k)
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
    /// conditional swaps (`k < 2^bits(n)`; `k = 0` gives the point at infinity).
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

    /// The affine coordinates of `p` as integers, or `None` for the point at infinity.
    fn affine(&self, p: &Point<LIMBS>) -> Option<(Uint<LIMBS>, Uint<LIMBS>)> {
        let (z_inv, invertible) = p.z.invert();
        bool::from(invertible).then(|| ((p.x * z_inv).retrieve(), (p.y * z_inv).retrieve()))
    }

    /// Writes the affine coordinates of `p`, or returns `Ok(None)` for the point at infinity.
    fn write_affine(
        &self,
        p: &Point<LIMBS>,
        x_out: &mut [u8],
        y_out: &mut [u8],
    ) -> Result<Option<()>, CryptoError> {
        if x_out.len() != self.size || y_out.len() != self.size {
            return Err(CryptoError::Internal);
        }
        let Some((x, y)) = self.affine(p) else {
            return Ok(None);
        };
        encode(&x, x_out)?;
        encode(&y, y_out)?;
        Ok(Some(()))
    }

    /// Checks that every buffer is [`Self::size`] bytes long.
    fn check_sizes(&self, lens: &[usize]) -> Result<(), CryptoError> {
        if lens.iter().all(|&len| len == self.size) {
            Ok(())
        } else {
            Err(CryptoError::Internal)
        }
    }

    /// Validates that the affine point `(x, y)` lies on the curve: `Ok(false)` if it does not
    /// (including coordinates that are not smaller than the field prime).
    ///
    /// Both coordinates must be [`Self::size`] bytes long ([`CryptoError::Internal`] otherwise).
    pub fn validate_point(&self, x: &[u8], y: &[u8]) -> Result<bool, CryptoError> {
        self.check_sizes(&[x.len(), y.len()])?;
        Ok(self.point(x, y).is_some())
    }

    /// `(x_out, y_out) = scalar * G`: `Ok(None)` if `scalar` is not in `[1, n - 1]`.
    ///
    /// All buffers must be [`Self::size`] bytes long ([`CryptoError::Internal`] otherwise).
    pub fn point_multiply_generator(
        &self,
        scalar: &[u8],
        x_out: &mut [u8],
        y_out: &mut [u8],
    ) -> Result<Option<()>, CryptoError> {
        self.check_sizes(&[scalar.len(), x_out.len(), y_out.len()])?;
        let Some(k) = self.scalar(scalar) else {
            return Ok(None);
        };
        self.write_affine(&self.multiply(&k, &self.g), x_out, y_out)
    }

    /// `(x_out, y_out) = scalar * (x_in, y_in)`: `Ok(None)` if `(x_in, y_in)` is not a point
    /// of the curve, if `scalar` is not in `[1, n - 1]`, or if the product is the point at
    /// infinity.
    ///
    /// All buffers must be [`Self::size`] bytes long ([`CryptoError::Internal`] otherwise).
    pub fn point_multiply(
        &self,
        scalar: &[u8],
        x_in: &[u8],
        y_in: &[u8],
        x_out: &mut [u8],
        y_out: &mut [u8],
    ) -> Result<Option<()>, CryptoError> {
        self.check_sizes(&[
            scalar.len(),
            x_in.len(),
            y_in.len(),
            x_out.len(),
            y_out.len(),
        ])?;
        let Some(p) = self.point(x_in, y_in) else {
            return Ok(None);
        };
        let Some(k) = self.scalar(scalar) else {
            return Ok(None);
        };
        self.write_affine(&self.multiply(&k, &p), x_out, y_out)
    }

    /// Draws a scalar uniformly from `[1, n - 1]` by rejection sampling of [`Self::size`]-byte
    /// strings from `fill` (masked to the bit length of `n`).
    ///
    /// Returns [`CryptoError::Internal`] if no valid scalar was drawn in 128 attempts (each
    /// succeeds with probability above 1/2).
    fn random_scalar(
        &self,
        fill: &mut dyn FnMut(&mut [u8]) -> Result<(), CryptoError>,
    ) -> Result<Uint<LIMBS>, CryptoError> {
        let size = self.size;
        let mask = Uint::<LIMBS>::MAX.shr_vartime(LIMBS * Limb::BITS - self.n_bits);
        let mut buffer = [0u8; MAX_BYTES];
        for _ in 0..128 {
            fill(&mut buffer[..size])?;
            let candidate = decode::<LIMBS>(&buffer[..size]).ok_or(CryptoError::Internal)?;
            let k = candidate.bitand(&mask);
            buffer.zeroize();
            if bool::from(self.valid_scalar(&k)) {
                return Ok(k);
            }
        }
        Err(CryptoError::Internal)
    }

    /// Generates a key pair: draws the private scalar `d` uniformly from `[1, n - 1]` by
    /// rejection sampling of [`Self::size`]-byte strings from `fill` (masked to the bit length
    /// of `n`), writes `d` ([`Self::size`] bytes) to `private_key` and `d * G` (`x || y`, each
    /// [`Self::size`] bytes) to `public_key`, and returns `(public_len, private_len)`.
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
        let size = self.size;
        if public_key.len() < 2 * size || private_key.len() < size {
            return Err(CryptoError::Internal);
        }
        let k = self.random_scalar(fill)?;
        let (x_out, rest) = public_key.split_at_mut(size);
        if self
            .write_affine(&self.multiply(&k, &self.g), x_out, &mut rest[..size])?
            .is_none()
        {
            return Err(CryptoError::Internal);
        }
        encode(&k, &mut private_key[..size])?;
        Ok((2 * size, size))
    }

    /// The integer `v` (any `LIMBS`-limb integer) modulo `n`.
    fn mod_n(&self, v: &Uint<LIMBS>) -> Fe<LIMBS> {
        Fe::new(v, self.scalars)
    }

    /// The ECDSA integer of `digest` modulo `n`: its leftmost `bits(n)` bits as a big-endian
    /// integer (FIPS 186-5, 6.4.1 step 3, `bits2int`), reduced modulo `n`.
    fn ecdsa_digest(&self, digest: &[u8]) -> Fe<LIMBS> {
        let n_bytes = self.n_bits.div_ceil(8);
        let digest = &digest[..digest.len().min(n_bytes)];
        // `digest` is at most `n_bytes <= Self::BYTES` long.
        let mut e = decode::<LIMBS>(digest).unwrap_or(Uint::ZERO);
        if digest.len() * 8 > self.n_bits {
            e = e.shr_vartime(digest.len() * 8 - self.n_bits);
        }
        self.mod_n(&e)
    }

    /// The big-endian integer `bytes` (of any length) modulo `n`, by Horner's rule.
    fn bytes_mod_n(&self, bytes: &[u8]) -> Fe<LIMBS> {
        let radix = self.mod_n(&Uint::from_u64(256));
        bytes.iter().fold(Fe::zero(self.scalars), |acc, &byte| {
            acc * radix + self.mod_n(&Uint::from_u64(u64::from(byte)))
        })
    }

    /// Decodes the components `(r, s)` of a signature: `None` unless both are in `[1, n - 1]`.
    fn signature(&self, r: &[u8], s: &[u8]) -> Option<(Fe<LIMBS>, Fe<LIMBS>)> {
        let (r, s) = (self.scalar(r)?, self.scalar(s)?);
        Some((self.mod_n(&r), self.mod_n(&s)))
    }

    /// Writes the integers modulo `n` `r` and `s` into `r_out` and `s_out`.
    fn write_signature(
        r: &Fe<LIMBS>,
        s: &Fe<LIMBS>,
        r_out: &mut [u8],
        s_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        encode(&r.retrieve(), r_out)?;
        encode(&s.retrieve(), s_out)
    }

    /// Signs `digest` with `ECDSA` (FIPS 186-5, 6.4.1) under the private scalar `d`, drawing
    /// the per-message secret from `fill` (see [`Self::generate_key`]), and writes `(r, s)` into
    /// `r_out` and `s_out`.
    ///
    /// Only the leftmost `bits(n)` bits of `digest` are used. Returns
    /// [`CryptoError::Internal`] if `d` is not in `[1, n - 1]`, a buffer is not [`Self::size`]
    /// bytes long, or no signature was found in 128 attempts.
    pub fn ecdsa_sign(
        &self,
        d: &[u8],
        digest: &[u8],
        fill: &mut dyn FnMut(&mut [u8]) -> Result<(), CryptoError>,
        r_out: &mut [u8],
        s_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.check_sizes(&[d.len(), r_out.len(), s_out.len()])?;
        let d = self.mod_n(&self.scalar(d).ok_or(CryptoError::Internal)?);
        let e = self.ecdsa_digest(digest);
        for _ in 0..128 {
            let k = self.random_scalar(fill)?;
            let (x, _) = self
                .affine(&self.multiply(&k, &self.g))
                .ok_or(CryptoError::Internal)?;
            let r = self.mod_n(&x);
            let (k_inv, _) = self.mod_n(&k).invert();
            let s = k_inv * (e + r * d);
            if bool::from(r.retrieve().ct_eq(&Uint::ZERO) | s.retrieve().ct_eq(&Uint::ZERO)) {
                continue;
            }
            return Self::write_signature(&r, &s, r_out, s_out);
        }
        Err(CryptoError::Internal)
    }

    /// Verifies the `ECDSA` signature `(r, s)` over `digest` (FIPS 186-5, 6.4.2) under the
    /// public point `(x, y)`: `Ok(false)` if it is invalid, including `r` or `s` outside
    /// `[1, n - 1]` and an invalid public point.
    ///
    /// All buffers but `digest` must be [`Self::size`] bytes long ([`CryptoError::Internal`]
    /// otherwise).
    pub fn ecdsa_verify(
        &self,
        x: &[u8],
        y: &[u8],
        digest: &[u8],
        r: &[u8],
        s: &[u8],
    ) -> Result<bool, CryptoError> {
        self.check_sizes(&[x.len(), y.len(), r.len(), s.len()])?;
        let (Some(q), Some((r, s))) = (self.point(x, y), self.signature(r, s)) else {
            return Ok(false);
        };
        let e = self.ecdsa_digest(digest);
        let (w, _) = s.invert();
        let (u1, u2) = ((e * w).retrieve(), (r * w).retrieve());
        let sum = self.add(&self.multiply(&u1, &self.g), &self.multiply(&u2, &q));
        let Some((x1, _)) = self.affine(&sum) else {
            return Ok(false);
        };
        Ok(self.mod_n(&x1).retrieve() == r.retrieve())
    }

    /// Signs the message digest `e` with `SM2` (GB/T 32918.2-2016, 6.1, steps A3 to A7) under
    /// the private scalar `d`, drawing the per-message secret from `fill` (see
    /// [`Self::generate_key`]), and writes `(r, s)` into `r_out` and `s_out`.
    ///
    /// `e` (of any length) is used as a big-endian integer modulo `n`. Returns
    /// [`CryptoError::Internal`] if `d` is not in `[1, n - 2]`, a buffer is not [`Self::size`]
    /// bytes long, or no signature was found in 128 attempts.
    pub fn sm2_sign(
        &self,
        d: &[u8],
        e: &[u8],
        fill: &mut dyn FnMut(&mut [u8]) -> Result<(), CryptoError>,
        r_out: &mut [u8],
        s_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.check_sizes(&[d.len(), r_out.len(), s_out.len()])?;
        let d = self.mod_n(&self.scalar(d).ok_or(CryptoError::Internal)?);
        let (d1_inv, invertible) = (d + Fe::one(self.scalars)).invert();
        if !bool::from(invertible) {
            return Err(CryptoError::Internal);
        }
        let e = self.bytes_mod_n(e);
        for _ in 0..128 {
            let k = self.random_scalar(fill)?;
            let (x1, _) = self
                .affine(&self.multiply(&k, &self.g))
                .ok_or(CryptoError::Internal)?;
            let r = e + self.mod_n(&x1);
            let k = self.mod_n(&k);
            let s = d1_inv * (k - r * d);
            let zero = |v: Fe<LIMBS>| v.retrieve().ct_eq(&Uint::ZERO);
            if bool::from(zero(r) | zero(r + k) | zero(s)) {
                continue;
            }
            return Self::write_signature(&r, &s, r_out, s_out);
        }
        Err(CryptoError::Internal)
    }

    /// Verifies the `SM2` signature `(r, s)` over the message digest `e` (GB/T 32918.2-2016,
    /// 7.1, steps B3 to B7) under the public point `(x, y)`: `Ok(false)` if it is invalid,
    /// including `r` or `s` outside `[1, n - 1]` and an invalid public point.
    ///
    /// All buffers but `e` must be [`Self::size`] bytes long ([`CryptoError::Internal`]
    /// otherwise).
    pub fn sm2_verify(
        &self,
        x: &[u8],
        y: &[u8],
        e: &[u8],
        r: &[u8],
        s: &[u8],
    ) -> Result<bool, CryptoError> {
        self.check_sizes(&[x.len(), y.len(), r.len(), s.len()])?;
        let (Some(q), Some((r, s))) = (self.point(x, y), self.signature(r, s)) else {
            return Ok(false);
        };
        let t = r + s;
        if t.retrieve() == Uint::ZERO {
            return Ok(false);
        }
        let sum = self.add(
            &self.multiply(&s.retrieve(), &self.g),
            &self.multiply(&t.retrieve(), &q),
        );
        let Some((x1, _)) = self.affine(&sum) else {
            return Ok(false);
        };
        Ok((self.bytes_mod_n(e) + self.mod_n(&x1)).retrieve() == r.retrieve())
    }
}

/// The domain parameters of a curve of this crate, selecting the curve of [`EcPrivateKey`] and
/// [`EcPublicKey`].
pub trait CurveId: 'static {
    /// The domain parameters of the curve.
    fn params() -> &'static EccCurveParams;
}

macro_rules! curve_ids {
    ($($(#[$m:meta])* $name:ident => $params:ident;)*) => {
        $(
            $(#[$m])*
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub struct $name;

            impl CurveId for $name {
                fn params() -> &'static EccCurveParams {
                    &$params
                }
            }
        )*
    };
}

curve_ids! {
    /// NIST P-192 ([`NIST_P192`]).
    NistP192Id => NIST_P192;
    /// NIST P-224 ([`NIST_P224`]).
    NistP224Id => NIST_P224;
    /// BN P-256 ([`BN_P256`]).
    BnP256Id => BN_P256;
    /// BN P-638 ([`BN_P638`]).
    BnP638Id => BN_P638;
    /// SM2 P-256 ([`SM2_P256`]).
    Sm2P256Id => SM2_P256;
}

/// A validated public key (a point of the curve other than the point at infinity) of the curve
/// `C`, with `COORD`-byte coordinates and arithmetic on `LIMBS`-limb integers.
pub struct EcPublicKey<C, const LIMBS: usize, const COORD: usize> {
    x: [u8; COORD],
    y: [u8; COORD],
    curve: PhantomData<fn() -> C>,
}

impl<C, const LIMBS: usize, const COORD: usize> Clone for EcPublicKey<C, LIMBS, COORD> {
    fn clone(&self) -> Self {
        Self {
            x: self.x,
            y: self.y,
            curve: PhantomData,
        }
    }
}

impl<C, const LIMBS: usize, const COORD: usize> PartialEq for EcPublicKey<C, LIMBS, COORD> {
    fn eq(&self, other: &Self) -> bool {
        self.x == other.x && self.y == other.y
    }
}

impl<C, const LIMBS: usize, const COORD: usize> Eq for EcPublicKey<C, LIMBS, COORD> {}

impl<C, const LIMBS: usize, const COORD: usize> core::fmt::Debug for EcPublicKey<C, LIMBS, COORD> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcPublicKey")
            .field("x", &self.x)
            .field("y", &self.y)
            .finish()
    }
}

impl<C, const LIMBS: usize, const COORD: usize> EcPublicKey<C, LIMBS, COORD> {
    /// The big-endian `x` coordinate.
    pub fn x(&self) -> &[u8; COORD] {
        &self.x
    }

    /// The big-endian `y` coordinate.
    pub fn y(&self) -> &[u8; COORD] {
        &self.y
    }
}

/// A validated private key (a secret scalar `d` in `[1, n - 1]` and its public key `[d]G`) of the
/// curve `C`, with `COORD`-byte coordinates and scalars, and arithmetic on `LIMBS`-limb integers.
///
/// It implements [`EccCurve`] and [`PrivateKey`] for any random number generator `R`. The secret
/// scalar is zeroized on drop.
pub struct EcPrivateKey<C, const LIMBS: usize, const COORD: usize> {
    d: [u8; COORD],
    public: EcPublicKey<C, LIMBS, COORD>,
}

impl<C, const LIMBS: usize, const COORD: usize> Drop for EcPrivateKey<C, LIMBS, COORD> {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}

impl<C, const LIMBS: usize, const COORD: usize> core::fmt::Debug for EcPrivateKey<C, LIMBS, COORD> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl<C: CurveId, const LIMBS: usize, const COORD: usize> EcPrivateKey<C, LIMBS, COORD> {
    /// The context of the curve.
    fn curve() -> Result<Curve<LIMBS>, CryptoError> {
        let curve = Curve::new(C::params())?;
        if curve.size() != COORD {
            return Err(CryptoError::Internal);
        }
        Ok(curve)
    }

    /// The key of the secret scalar `d`, with the public key `[d]G`: `Ok(None)` if `d` is not in
    /// `[1, n - 1]`.
    pub fn from_scalar(d: &[u8; COORD]) -> Result<Option<Self>, CryptoError> {
        let curve = Self::curve()?;
        let (mut x, mut y) = ([0u8; COORD], [0u8; COORD]);
        if curve.point_multiply_generator(d, &mut x, &mut y)?.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            d: *d,
            public: EcPublicKey {
                x,
                y,
                curve: PhantomData,
            },
        }))
    }
}

/// Fills `buf` from `rng`.
fn filler<R: Rng>(rng: &mut R) -> impl FnMut(&mut [u8]) -> Result<(), CryptoError> + '_ {
    |buf: &mut [u8]| rng.fill_bytes(buf)
}

/// Splits the encoded point `x || y` into its coordinates.
fn split_point<const COORD: usize>(point: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    if point.len() != 2 * COORD {
        return Err(CryptoError::Internal);
    }
    Ok(point.split_at(COORD))
}

impl<C: CurveId, const LIMBS: usize, const COORD: usize, const POINT: usize, R: Rng>
    PrivateKey<POINT, COORD, R> for EcPrivateKey<C, LIMBS, COORD>
{
    type PublicKey = EcPublicKey<C, LIMBS, COORD>;

    fn generate(rng: &mut R, _: ()) -> Result<Self, CryptoError> {
        let curve = Self::curve()?;
        let mut d = [0u8; COORD];
        let mut point = [0u8; MAX_BYTES * 2];
        curve.generate_key(&mut filler(rng), &mut point[..2 * COORD], &mut d)?;
        let (x, y) = split_point::<COORD>(&point[..2 * COORD])?;
        let key = Self {
            d,
            public: EcPublicKey {
                x: x.try_into().map_err(|_| CryptoError::Internal)?,
                y: y.try_into().map_err(|_| CryptoError::Internal)?,
                curve: PhantomData,
            },
        };
        d.zeroize();
        Ok(key)
    }

    fn load(public: Self::PublicKey, private: &[u8; COORD]) -> Result<Option<Self>, CryptoError> {
        let Some(key) = Self::from_scalar(private)? else {
            return Ok(None);
        };
        let matches = key.public.x[..].ct_eq(&public.x[..]) & key.public.y[..].ct_eq(&public.y[..]);
        Ok(bool::from(matches).then_some(key))
    }

    fn store(&self, out: &mut [u8; COORD]) -> Result<(), CryptoError> {
        *out = self.d;
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }

    fn load_public(_: (), public: &[u8; POINT]) -> Result<Option<Self::PublicKey>, CryptoError> {
        let (x, y) = split_point::<COORD>(public)?;
        if !Self::curve()?.validate_point(x, y)? {
            return Ok(None);
        }
        Ok(Some(EcPublicKey {
            x: x.try_into().map_err(|_| CryptoError::Internal)?,
            y: y.try_into().map_err(|_| CryptoError::Internal)?,
            curve: PhantomData,
        }))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; POINT]) -> Result<(), CryptoError> {
        if POINT != 2 * COORD {
            return Err(CryptoError::Internal);
        }
        out[..COORD].copy_from_slice(&public.x);
        out[COORD..].copy_from_slice(&public.y);
        Ok(())
    }
}

impl<C: CurveId, const LIMBS: usize, const COORD: usize, const POINT: usize, R: Rng>
    EccCurve<COORD, POINT, R> for EcPrivateKey<C, LIMBS, COORD>
{
    /// The cofactor of the curves of this crate is 1, so this is `[d]Q`.
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_x: &mut [u8; COORD],
        out_y: &mut [u8; COORD],
    ) -> Result<Option<()>, CryptoError> {
        Self::curve()?.point_multiply(&self.d, &peer_public.x, &peer_public.y, out_x, out_y)
    }

    fn sign(
        &self,
        rng: &mut R,
        digest: &[u8],
        out_r: &mut [u8; COORD],
        out_s: &mut [u8; COORD],
    ) -> Result<(), CryptoError> {
        Self::curve()?.ecdsa_sign(&self.d, digest, &mut filler(rng), out_r, out_s)
    }

    fn verify(
        public: &Self::PublicKey,
        digest: &[u8],
        sig_r: &[u8; COORD],
        sig_s: &[u8; COORD],
    ) -> Result<bool, CryptoError> {
        Self::curve()?.ecdsa_verify(&public.x, &public.y, digest, sig_r, sig_s)
    }

    fn sm2_sign(
        &self,
        rng: &mut R,
        e: &[u8],
        out_r: &mut [u8; COORD],
        out_s: &mut [u8; COORD],
    ) -> Result<(), CryptoError> {
        Self::curve()?.sm2_sign(&self.d, e, &mut filler(rng), out_r, out_s)
    }

    fn sm2_verify(
        public: &Self::PublicKey,
        e: &[u8],
        sig_r: &[u8; COORD],
        sig_s: &[u8; COORD],
    ) -> Result<bool, CryptoError> {
        Self::curve()?.sm2_verify(&public.x, &public.y, e, sig_r, sig_s)
    }

    fn mul_generator(
        k: &[u8; COORD],
        out_x: &mut [u8; COORD],
        out_y: &mut [u8; COORD],
    ) -> Result<Option<()>, CryptoError> {
        Self::curve()?.point_multiply_generator(k, out_x, out_y)
    }

    fn mul_point(
        point: &Self::PublicKey,
        k: &[u8; COORD],
        out_x: &mut [u8; COORD],
        out_y: &mut [u8; COORD],
    ) -> Result<Option<()>, CryptoError> {
        Self::curve()?.point_multiply(k, &point.x, &point.y, out_x, out_y)
    }
}

/// NIST P-192 keys ([`NIST_P192`]).
pub type NistP192 = EcPrivateKey<NistP192Id, { U192::LIMBS }, 24>;
/// NIST P-224 keys ([`NIST_P224`]).
pub type NistP224 = EcPrivateKey<NistP224Id, { U256::LIMBS }, 28>;
/// BN P-256 keys ([`BN_P256`]).
pub type BnP256 = EcPrivateKey<BnP256Id, { U256::LIMBS }, 32>;
/// BN P-638 keys ([`BN_P638`]).
pub type BnP638 = EcPrivateKey<BnP638Id, { U640::LIMBS }, 80>;
/// SM2 P-256 keys ([`SM2_P256`]).
pub type Sm2P256 = EcPrivateKey<Sm2P256Id, { U256::LIMBS }, 32>;

#[cfg(test)]
mod tests;
