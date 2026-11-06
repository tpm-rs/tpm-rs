//! Small fixed-size big-endian modular arithmetic for values up to the largest registered curve
//! prime/order (BN P-638, 80 bytes), used where the crypto backend offers no primitive: deriving
//! ECC private scalars with the "extra random bits" method, computing ECDAA, SM2 and EC-Schnorr
//! signatures, and the affine point arithmetic of [`crate::ecc_curves`].
//!
//! All numbers are unsigned big-endian byte strings. [`reduce`], [`add_mod`], [`sub_mod`],
//! [`mul_mod`] and [`inv_mod_prime`] run in time independent of the values of their operands (only
//! of their lengths and of the modulus), so they may be applied to secrets (private keys, nonces);
//! [`inv_mod`] (binary extended Euclid) is faster but not constant time and is only applied to
//! public values (point coordinates).

/// Size of the scratch buffers: one more byte than the largest supported modulus.
/// (BN P-638: 80-byte prime and order.)
const MAX: usize = 80 + 1;

/// Returns `true` if `a >= b` for equal-length big-endian numbers.
fn ge(a: &[u8], b: &[u8]) -> bool {
    a >= b
}

/// `a -= b` (modulo `256^len`) for equal-length big-endian numbers, without branches on the
/// values; returns the borrow out (1 if `a < b`).
fn sub_ct(a: &mut [u8], b: &[u8]) -> u8 {
    let mut borrow = 0u16;
    for i in (0..a.len()).rev() {
        let t = u16::from(a[i]) + 0x100 - u16::from(b[i]) - borrow;
        a[i] = t as u8;
        borrow = 1 - (t >> 8);
    }
    borrow as u8
}

/// `a -= b` for equal-length big-endian numbers (requires `a >= b`).
fn sub_in_place(a: &mut [u8], b: &[u8]) {
    sub_ct(a, b);
}

/// Copies `src` into `dst` if `choice` is 1 and leaves `dst` unchanged if it is 0, without
/// branches on `choice`.
fn select(dst: &mut [u8], src: &[u8], choice: u8) {
    let mask = 0u8.wrapping_sub(choice & 1);
    for (d, s) in dst.iter_mut().zip(src) {
        *d = (*d & !mask) | (*s & mask);
    }
}

/// `a += b` for equal-length big-endian numbers; returns the carry out.
fn add_in_place(a: &mut [u8], b: &[u8]) -> bool {
    let mut carry = 0u16;
    for i in (0..a.len()).rev() {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        a[i] = sum as u8;
        carry = sum >> 8;
    }
    carry != 0
}

/// Writes `x mod m` into `out` (`out.len() == m.len()`, `1 <= m.len() < MAX`, `m != 0`).
/// `x` may be of any length.
pub(crate) fn reduce(x: &[u8], m: &[u8], out: &mut [u8]) {
    let len = m.len();
    // Bitwise long division with one guard byte: rem = (rem << 1 | bit) mod m.
    let mut m_ext = [0u8; MAX];
    m_ext[1..=len].copy_from_slice(m);
    let m_ext = &m_ext[..=len];
    let mut rem = [0u8; MAX];
    let r = &mut rem[..=len];
    for &byte in x {
        for bit in (0..8).rev() {
            let mut carry = (byte >> bit) & 1;
            for b in r.iter_mut().rev() {
                let next = *b >> 7;
                *b = (*b << 1) | carry;
                carry = next;
            }
            // r < 2m, so one conditional subtraction (r - m if it does not borrow) suffices.
            let mut t = [0u8; MAX];
            t[..=len].copy_from_slice(r);
            let borrow = sub_ct(&mut t[..=len], m_ext);
            select(r, &t[..=len], 1 - borrow);
        }
    }
    out.copy_from_slice(&r[1..]);
}

/// Writes `(a + b) mod m` into `out`, for `a, b < m` of length `m.len()`.
pub(crate) fn add_mod(a: &[u8], b: &[u8], m: &[u8], out: &mut [u8]) {
    let len = m.len();
    let mut sum = [0u8; MAX];
    sum[1..=len].copy_from_slice(a);
    let mut b_ext = [0u8; MAX];
    b_ext[1..=len].copy_from_slice(b);
    add_in_place(&mut sum[..=len], &b_ext[..=len]);
    let mut m_ext = [0u8; MAX];
    m_ext[1..=len].copy_from_slice(m);
    let mut t = sum;
    let borrow = sub_ct(&mut t[..=len], &m_ext[..=len]);
    select(&mut sum[..=len], &t[..=len], 1 - borrow);
    out.copy_from_slice(&sum[1..=len]);
}

/// Writes `(a - b) mod m` into `out`, for `a, b < m` of length `m.len()`.
pub(crate) fn sub_mod(a: &[u8], b: &[u8], m: &[u8], out: &mut [u8]) {
    let len = m.len();
    let mut diff = [0u8; MAX];
    diff[..len].copy_from_slice(a);
    let borrow = sub_ct(&mut diff[..len], b);
    // If a < b, a - b + 256^len wrapped; adding m (again modulo 256^len) gives a - b + m.
    let mut t = diff;
    add_in_place(&mut t[..len], m);
    select(&mut diff[..len], &t[..len], borrow);
    out.copy_from_slice(&diff[..len]);
}

/// Halves `x` modulo the odd modulus `m` in place: `x / 2` if `x` is even, `(x + m) / 2`
/// otherwise. `x` and `m` are `len + 1` bytes long with a zero guard byte in front, and `x < m`.
fn half_mod(x: &mut [u8], m: &[u8]) {
    if x[x.len() - 1] & 1 == 1 {
        add_in_place(x, m);
    }
    shr1(x);
}

/// Shifts the big-endian number `x` right by one bit in place.
fn shr1(x: &mut [u8]) {
    let mut carry = 0u8;
    for b in x.iter_mut() {
        let next = *b & 1;
        *b = (*b >> 1) | (carry << 7);
        carry = next;
    }
}

/// Writes the modular inverse `a^-1 mod m` into `out` for an odd modulus `m` (such as a curve
/// prime or a prime group order) and `a < m`, all of length `m.len()`, using the binary extended
/// Euclidean algorithm.
///
/// Returns `false` (leaving `out` unspecified) if `a` has no inverse, i.e. `a` is zero or shares
/// a factor with `m`.
pub(crate) fn inv_mod(a: &[u8], m: &[u8], out: &mut [u8]) -> bool {
    let len = m.len();
    debug_assert!(m[len - 1] & 1 == 1, "inv_mod needs an odd modulus");
    // Invariants: x1 * a == u (mod m) and x2 * a == v (mod m); every buffer has a guard byte.
    let mut u = [0u8; MAX];
    let mut v = [0u8; MAX];
    let mut x1 = [0u8; MAX];
    let mut x2 = [0u8; MAX];
    let mut m_ext = [0u8; MAX];
    u[1..=len].copy_from_slice(a);
    v[1..=len].copy_from_slice(m);
    x1[len] = 1;
    m_ext[1..=len].copy_from_slice(m);
    let (u, v, x1, x2, m_ext) = (
        &mut u[..=len],
        &mut v[..=len],
        &mut x1[..=len],
        &mut x2[..=len],
        &m_ext[..=len],
    );
    let is_one = |x: &[u8]| x[x.len() - 1] == 1 && is_zero(&x[..x.len() - 1]);
    loop {
        if is_zero(u) || is_zero(v) {
            return false;
        }
        if is_one(u) {
            out.copy_from_slice(&x1[1..]);
            return true;
        }
        if is_one(v) {
            out.copy_from_slice(&x2[1..]);
            return true;
        }
        while u[len] & 1 == 0 {
            shr1(u);
            half_mod(x1, m_ext);
        }
        while v[len] & 1 == 0 {
            shr1(v);
            half_mod(x2, m_ext);
        }
        if ge(u, v) {
            sub_in_place(u, v);
            let mut t = [0u8; MAX];
            sub_mod(&x1[1..], &x2[1..], m, &mut t[..len]);
            x1[1..].copy_from_slice(&t[..len]);
        } else {
            sub_in_place(v, u);
            let mut t = [0u8; MAX];
            sub_mod(&x2[1..], &x1[1..], m, &mut t[..len]);
            x2[1..].copy_from_slice(&t[..len]);
        }
    }
}

/// Writes `(a * b) mod m` into `out`, for `a, b < m` of length `m.len()` (double-and-add over
/// the bits of `a`, always computing the addition and selecting it without branches).
pub(crate) fn mul_mod(a: &[u8], b: &[u8], m: &[u8], out: &mut [u8]) {
    let len = m.len();
    let mut acc = [0u8; MAX];
    let mut tmp = [0u8; MAX];
    let mut sum = [0u8; MAX];
    for &byte in a {
        for bit in (0..8).rev() {
            tmp[..len].copy_from_slice(&acc[..len]);
            add_mod(&tmp[..len], &tmp[..len], m, &mut acc[..len]);
            add_mod(&acc[..len], b, m, &mut sum[..len]);
            select(&mut acc[..len], &sum[..len], (byte >> bit) & 1);
        }
    }
    out.copy_from_slice(&acc[..len]);
}

/// Writes the inverse `a^-1 mod p` into `out` for a prime modulus `p` (a curve's group order)
/// and `0 < a < p`, all of length `p.len()`, as `a^(p - 2) mod p` (Fermat) with [`mul_mod`]: the
/// running time depends only on `p`, so `a` may be secret. Returns `false` if `a` is zero.
#[cfg(any(test, not(feature = "reference-rng")))]
pub(crate) fn inv_mod_prime(a: &[u8], p: &[u8], out: &mut [u8]) -> bool {
    let len = p.len();
    if is_zero(a) {
        return false;
    }
    // e = p - 2 (public).
    let mut e = [0u8; MAX];
    e[..len].copy_from_slice(p);
    let mut two = [0u8; MAX];
    two[len - 1] = 2;
    sub_in_place(&mut e[..len], &two[..len]);
    let mut acc = [0u8; MAX];
    acc[len - 1] = 1;
    let mut tmp = [0u8; MAX];
    for &byte in &e[..len] {
        for bit in (0..8).rev() {
            tmp[..len].copy_from_slice(&acc[..len]);
            mul_mod(&tmp[..len], &tmp[..len], p, &mut acc[..len]);
            // Branching on the bits of the public exponent is fine.
            if (byte >> bit) & 1 == 1 {
                tmp[..len].copy_from_slice(&acc[..len]);
                mul_mod(&tmp[..len], a, p, &mut acc[..len]);
            }
        }
    }
    out.copy_from_slice(&acc[..len]);
    true
}

/// Computes the ECC private scalar `d = (c mod (n - 1)) + 1` of FIPS 186-5 A.2.1 ("Key Pair
/// Generation Using Extra Random Bits", C `TpmEcc_GenPrivateScalar`), where `c` and `n` are
/// big-endian and `d` has the length of `n`. `n` must be at least 2.
pub(crate) fn ecc_scalar_from_extra_bits(c: &[u8], n: &[u8], d: &mut [u8]) {
    let len = n.len();
    let mut n_minus_1 = [0u8; MAX];
    n_minus_1[..len].copy_from_slice(n);
    for byte in n_minus_1[..len].iter_mut().rev() {
        if *byte == 0 {
            *byte = 0xFF;
        } else {
            *byte -= 1;
            break;
        }
    }
    reduce(c, &n_minus_1[..len], d);
    // d = rem + 1 (rem < n - 1, so no overflow beyond `len` bytes).
    for byte in d.iter_mut().rev() {
        let (v, overflow) = byte.overflowing_add(1);
        *byte = v;
        if !overflow {
            break;
        }
    }
}

/// Returns `true` if every byte of `x` is zero.
pub(crate) fn is_zero(x: &[u8]) -> bool {
    x.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce_small_and_multibyte() {
        let mut out = [0u8; 1];
        reduce(&[0x01, 0x23], &[10], &mut out); // 291 mod 10
        assert_eq!(out, [1]);
        let mut out2 = [0u8; 2];
        reduce(&[0xFF, 0xFF, 0xFF], &[0x01, 0x00], &mut out2); // 2^24-1 mod 256
        assert_eq!(out2, [0x00, 0xFF]);
        reduce(&[], &[0x01, 0x00], &mut out2);
        assert_eq!(out2, [0, 0]);
    }

    #[test]
    fn add_and_mul_mod() {
        let m = [0x00, 0x65]; // 101
        let mut out = [0u8; 2];
        add_mod(&[0x00, 0x60], &[0x00, 0x10], &m, &mut out); // 96 + 16 = 112 -> 11
        assert_eq!(out, [0x00, 0x0B]);
        mul_mod(&[0x00, 0x60], &[0x00, 0x10], &m, &mut out); // 96 * 16 = 1536 -> 21
        assert_eq!(out, [0x00, 21]);
        mul_mod(&[0x00, 0x00], &[0x00, 0x10], &m, &mut out);
        assert_eq!(out, [0, 0]);
    }

    #[test]
    fn sub_and_inv_mod() {
        let m = [0x00, 0x65]; // 101
        let mut out = [0u8; 2];
        sub_mod(&[0x00, 0x60], &[0x00, 0x10], &m, &mut out);
        assert_eq!(out, [0x00, 0x50]);
        sub_mod(&[0x00, 0x10], &[0x00, 0x60], &m, &mut out); // 16 - 96 = -80 -> 21
        assert_eq!(out, [0x00, 21]);
        for a in 1u8..101 {
            assert!(inv_mod(&[0, a], &m, &mut out));
            let mut prod = [0u8; 2];
            mul_mod(&[0, a], &out, &m, &mut prod);
            assert_eq!(prod, [0, 1], "inverse of {a}");
        }
        assert!(!inv_mod(&[0, 0], &m, &mut out));
        for a in 1u8..101 {
            let mut inv = [0u8; 2];
            assert!(inv_mod_prime(&[0, a], &m, &mut inv));
            assert!(inv_mod(&[0, a], &m, &mut out));
            assert_eq!(inv, out, "Fermat inverse of {a}");
        }
        assert!(!inv_mod_prime(&[0, 0], &m, &mut out));
        // 15 = 3 * 5 has no inverse modulo 21.
        assert!(!inv_mod(&[15], &[21], &mut [0u8]));
        // Large moduli: the inverses of p - 2 and of 2 modulo every curve prime of the build.
        for curve in [
            tpm2::TpmEccCurve::NistP521,
            #[cfg(feature = "bn_p638")]
            tpm2::TpmEccCurve::BNP638,
        ] {
            let p = tpm2::crypto::ecc_curve_params(curve).unwrap().p;
            let len = p.len();
            let mut a = [0u8; MAX];
            a[..len].copy_from_slice(p);
            a[len - 1] -= 2;
            let mut two = [0u8; MAX];
            two[len - 1] = 2;
            let mut one = [0u8; MAX];
            one[len - 1] = 1;
            for x in [&a[..len], &two[..len]] {
                let mut inv = [0u8; MAX];
                let mut prod = [0u8; MAX];
                let mut fermat = [0u8; MAX];
                assert!(inv_mod(x, p, &mut inv[..len]));
                assert!(inv_mod_prime(x, p, &mut fermat[..len]));
                assert_eq!(inv[..len], fermat[..len], "{curve:?}");
                mul_mod(x, &inv[..len], p, &mut prod[..len]);
                assert_eq!(prod[..len], one[..len], "{curve:?}");
            }
        }
    }

    #[test]
    fn extra_bits_reduction() {
        // n = 11 -> n - 1 = 10; c = 0x0123 = 291 -> 291 mod 10 = 1 -> d = 2.
        let mut d = [0u8; 1];
        ecc_scalar_from_extra_bits(&[0x01, 0x23], &[11], &mut d);
        assert_eq!(d, [2]);
        // c = 9 -> d = 10 (= n - 1, the largest scalar).
        ecc_scalar_from_extra_bits(&[0x00, 0x09], &[11], &mut d);
        assert_eq!(d, [10]);
        // n = 0x0101 (257) -> n - 1 = 256; c = 0xFFFFFF -> 255 -> d = 256.
        let mut d2 = [0u8; 2];
        ecc_scalar_from_extra_bits(&[0xFF, 0xFF, 0xFF], &[0x01, 0x01], &mut d2);
        assert_eq!(d2, [0x01, 0x00]);
    }
}
