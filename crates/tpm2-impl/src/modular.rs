//! Small fixed-size big-endian modular arithmetic for values up to the largest supported curve
//! order (NIST P-521, 66 bytes), used where the crypto provider offers no primitive: deriving
//! ECC private scalars with the "extra random bits" method and computing ECDAA signatures.
//!
//! All numbers are unsigned big-endian byte strings. The functions are not constant time; they
//! are only applied to values that are either public or freshly generated per operation in the
//! same way as the reference implementation's `ExtMath_*` big-number helpers.

/// Size of the scratch buffers: one more byte than the largest supported modulus.
/// (NIST P-521: 66-byte order.)
const MAX: usize = 66 + 1;

/// Returns `true` if `a >= b` for equal-length big-endian numbers.
fn ge(a: &[u8], b: &[u8]) -> bool {
    a >= b
}

/// `a -= b` for equal-length big-endian numbers (requires `a >= b`).
fn sub_in_place(a: &mut [u8], b: &[u8]) {
    let mut borrow = 0u16;
    for i in (0..a.len()).rev() {
        let sub = u16::from(b[i]) + borrow;
        let cur = u16::from(a[i]);
        if cur >= sub {
            a[i] = (cur - sub) as u8;
            borrow = 0;
        } else {
            a[i] = (cur + 256 - sub) as u8;
            borrow = 1;
        }
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
            if ge(r, m_ext) {
                sub_in_place(r, m_ext);
            }
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
    if ge(&sum[..=len], &m_ext[..=len]) {
        sub_in_place(&mut sum[..=len], &m_ext[..=len]);
    }
    out.copy_from_slice(&sum[1..=len]);
}

/// Writes `(a * b) mod m` into `out`, for `a, b < m` of length `m.len()` (double-and-add over
/// the bits of `a`).
pub(crate) fn mul_mod(a: &[u8], b: &[u8], m: &[u8], out: &mut [u8]) {
    let len = m.len();
    let mut acc = [0u8; MAX];
    let mut tmp = [0u8; MAX];
    for &byte in a {
        for bit in (0..8).rev() {
            tmp[..len].copy_from_slice(&acc[..len]);
            add_mod(&tmp[..len], &tmp[..len], m, &mut acc[..len]);
            if (byte >> bit) & 1 == 1 {
                tmp[..len].copy_from_slice(&acc[..len]);
                add_mod(&tmp[..len], b, m, &mut acc[..len]);
            }
        }
    }
    out.copy_from_slice(&acc[..len]);
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
