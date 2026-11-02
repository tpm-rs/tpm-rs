//! ECC curve domain parameters and the affine point arithmetic the crypto provider does not
//! offer.
//!
//! The crypto provider ([`tpm2::crypto::Ecc`]) multiplies points by scalars and validates them;
//! the TPM's split-signing schemes (SM2, EC-Schnorr verification) and key-exchange schemes
//! (ECMQV, SM2) also need point addition, which is implemented here on top of the field
//! arithmetic of [`crate::modular`] and the curve table of [`tpm2::crypto::ecc_params`].
//!
//! Points are `x || y`, each coordinate big-endian and padded to the coordinate size of the curve
//! ([`CurveParams::coordinate_size`]). The point at infinity has no encoding: functions return
//! `None` when it is the result. The functions are not constant time; they are only applied to
//! public points (signature verification, public keys of a key exchange) or to points derived
//! from per-operation random values, like the reference implementation's `TpmEcc_PointAdd()`.

// Not every build uses every helper (they serve the optional SM2, EC-Schnorr and ECMQV schemes).
#![allow(dead_code)]

use crate::modular::{add_mod, inv_mod, is_zero, mul_mod, sub_mod};

#[allow(unused_imports)]
pub(crate) use tpm2::crypto::{EccCurveParams as CurveParams, ecc_curve_params as curve_params};

/// Returns the coordinate (and scalar) size in bytes of `curve`, or `None` if the curve is not
/// implemented.
pub(crate) fn param_size(curve: tpm2::TpmEccCurve) -> Option<usize> {
    curve_params(curve).map(CurveParams::coordinate_size)
}

/// Largest coordinate size of the registered curves (BN P-638).
const MAX_COORD: usize = 80;

/// Writes `-p = (x, p - y)` of the point `p` (`x || y`) on curve `c` into `out` and returns the
/// number of bytes written (`2 * c.coordinate_size()`), or `None` if `p` is not exactly that long
/// or `out` is too small.
pub(crate) fn point_negate(c: &CurveParams, p: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = c.coordinate_size();
    if p.len() != 2 * n || out.len() < 2 * n {
        return None;
    }
    let (x, y) = p.split_at(n);
    out[..n].copy_from_slice(x);
    if is_zero(y) {
        out[n..2 * n].fill(0);
    } else {
        let zero = [0u8; MAX_COORD];
        sub_mod(&zero[..n], y, c.p, &mut out[n..2 * n]);
    }
    Some(2 * n)
}

/// Writes the sum `p + q` of the affine points `p` and `q` (`x || y`) on curve `c` into `out`
/// and returns the number of bytes written (`2 * c.coordinate_size()`).
///
/// Returns `None` if the sum is the point at infinity (`q == -p`), if `p` or `q` is not exactly
/// `2 * c.coordinate_size()` bytes long or has a coordinate not below the field prime, or if
/// `out` is too small. The points are not checked to lie on the curve; callers pass validated
/// points. Equal points are doubled.
pub(crate) fn point_add(c: &CurveParams, p: &[u8], q: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = c.coordinate_size();
    if p.len() != 2 * n || q.len() != 2 * n || out.len() < 2 * n {
        return None;
    }
    let (x1, y1) = p.split_at(n);
    let (x2, y2) = q.split_at(n);
    if [x1, y1, x2, y2].iter().any(|v| *v >= c.p) {
        return None;
    }
    let m = c.p;
    let mut lambda = [0u8; MAX_COORD];
    let mut num = [0u8; MAX_COORD];
    let mut den = [0u8; MAX_COORD];
    let mut inv = [0u8; MAX_COORD];
    if x1 == x2 {
        if y1 != y2 || is_zero(y1) {
            // q == -p (including the doubling of a point of order 2).
            return None;
        }
        // Doubling: lambda = (3 * x1^2 + a) / (2 * y1).
        let mut x1_sq = [0u8; MAX_COORD];
        mul_mod(x1, x1, m, &mut x1_sq[..n]);
        let mut t = [0u8; MAX_COORD];
        add_mod(&x1_sq[..n], &x1_sq[..n], m, &mut t[..n]);
        add_mod(&t[..n], &x1_sq[..n], m, &mut num[..n]);
        t[..n].copy_from_slice(&num[..n]);
        add_mod(&t[..n], c.a, m, &mut num[..n]);
        add_mod(y1, y1, m, &mut den[..n]);
    } else {
        // Addition: lambda = (y2 - y1) / (x2 - x1).
        sub_mod(y2, y1, m, &mut num[..n]);
        sub_mod(x2, x1, m, &mut den[..n]);
    }
    if !inv_mod(&den[..n], m, &mut inv[..n]) {
        return None;
    }
    mul_mod(&num[..n], &inv[..n], m, &mut lambda[..n]);
    // x3 = lambda^2 - x1 - x2
    let mut x3 = [0u8; MAX_COORD];
    let mut t = [0u8; MAX_COORD];
    mul_mod(&lambda[..n], &lambda[..n], m, &mut t[..n]);
    sub_mod(&t[..n], x1, m, &mut x3[..n]);
    t[..n].copy_from_slice(&x3[..n]);
    sub_mod(&t[..n], x2, m, &mut x3[..n]);
    // y3 = lambda * (x1 - x3) - y1
    let mut y3 = [0u8; MAX_COORD];
    sub_mod(x1, &x3[..n], m, &mut t[..n]);
    mul_mod(&lambda[..n], &t[..n], m, &mut y3[..n]);
    t[..n].copy_from_slice(&y3[..n]);
    sub_mod(&t[..n], y1, m, &mut y3[..n]);
    out[..n].copy_from_slice(&x3[..n]);
    out[n..2 * n].copy_from_slice(&y3[..n]);
    Some(2 * n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2::TpmEccCurve;

    /// The base point `G` of `c` as `x || y`.
    fn generator(c: &CurveParams) -> ([u8; 2 * MAX_COORD], usize) {
        let n = c.coordinate_size();
        let mut g = [0u8; 2 * MAX_COORD];
        g[..n].copy_from_slice(c.gx);
        g[n..2 * n].copy_from_slice(c.gy);
        (g, 2 * n)
    }

    /// `y^2 == x^3 + a*x + b (mod p)` for the point `x || y`.
    fn on_curve(c: &CurveParams, point: &[u8]) -> bool {
        let n = c.coordinate_size();
        let (x, y) = point.split_at(n);
        let [mut lhs, mut x2, mut x3, mut ax, mut s, mut rhs] = [[0u8; MAX_COORD]; 6];
        mul_mod(y, y, c.p, &mut lhs[..n]);
        mul_mod(x, x, c.p, &mut x2[..n]);
        mul_mod(&x2[..n], x, c.p, &mut x3[..n]);
        mul_mod(c.a, x, c.p, &mut ax[..n]);
        add_mod(&x3[..n], &ax[..n], c.p, &mut s[..n]);
        add_mod(&s[..n], c.b, c.p, &mut rhs[..n]);
        lhs[..n] == rhs[..n]
    }

    /// For every curve of the build: 2G = G + G is on the curve, 3G = 2G + G is on the curve,
    /// 2G + 3G == 3G + 2G, G + (-G) is the point at infinity, and (2G + G) + G == 2G + 2G.
    #[test]
    fn group_law_on_every_curve() {
        for curve in [
            #[cfg(feature = "ecc_curve_nist_p192")]
            TpmEccCurve::NistP192,
            TpmEccCurve::NistP224,
            TpmEccCurve::NistP256,
            TpmEccCurve::NistP384,
            TpmEccCurve::NistP521,
            TpmEccCurve::BNP256,
            #[cfg(feature = "ecc_curve_bn_p638")]
            TpmEccCurve::BNP638,
            #[cfg(feature = "ecc_curve_sm2_p256")]
            TpmEccCurve::SM2P256,
        ] {
            let c = curve_params(curve).unwrap();
            let (g, len) = generator(c);
            let g = &g[..len];
            assert!(on_curve(c, g), "{curve:?}");
            let mut g2 = [0u8; 2 * MAX_COORD];
            let mut g3 = [0u8; 2 * MAX_COORD];
            let mut g4a = [0u8; 2 * MAX_COORD];
            let mut g4b = [0u8; 2 * MAX_COORD];
            let mut g5a = [0u8; 2 * MAX_COORD];
            let mut g5b = [0u8; 2 * MAX_COORD];
            assert_eq!(point_add(c, g, g, &mut g2), Some(len));
            assert!(on_curve(c, &g2[..len]), "{curve:?}: 2G");
            assert_eq!(point_add(c, &g2[..len], g, &mut g3), Some(len));
            assert!(on_curve(c, &g3[..len]), "{curve:?}: 3G");
            assert_eq!(point_add(c, &g3[..len], g, &mut g4a), Some(len));
            assert_eq!(point_add(c, &g2[..len], &g2[..len], &mut g4b), Some(len));
            assert_eq!(g4a[..len], g4b[..len], "{curve:?}: 4G");
            assert_eq!(point_add(c, &g2[..len], &g3[..len], &mut g5a), Some(len));
            assert_eq!(point_add(c, &g3[..len], &g2[..len], &mut g5b), Some(len));
            assert_eq!(g5a[..len], g5b[..len], "{curve:?}: 5G");
            let mut neg = [0u8; 2 * MAX_COORD];
            assert_eq!(point_negate(c, g, &mut neg), Some(len));
            assert!(on_curve(c, &neg[..len]), "{curve:?}: -G");
            assert_eq!(point_add(c, g, &neg[..len], &mut g2), None);
            // Malformed inputs.
            assert_eq!(point_add(c, &g[..len - 1], g, &mut g2), None);
            assert_eq!(point_add(c, g, g, &mut g2[..len - 1]), None);
        }
    }
}
