//! Fixed-capacity unsigned big integers for the RSA prime search of [`crate::rsa_keygen`]:
//! numbers of up to the largest RSA prime of the profile ([`MAX_LIMBS`] 64-bit limbs, e.g. 1024
//! bits for RSA-2048 and 2048 bits for RSA-4096), the few operations the C reference's
//! `CryptRsaGenerateKey()` uses on them (comparisons, small additions and subtractions,
//! remainders by 32-bit words, shifts, a binary GCD, the product of two primes) and Montgomery
//! multiplication for the modular exponentiations of Miller-Rabin ([`Monty`]).
//!
//! Everything lives on the stack (no `alloc`). Numbers are little-endian arrays of limbs with a
//! runtime length (`len` limbs are significant, the rest are zero); the exponentiation
//! ([`Monty::pow`]) runs in time independent of the values of the base and the exponent (a fixed
//! 4-bit window over the whole width and a table lookup that reads every entry), as the
//! candidates of a prime search are secret; the other operations are only applied where their
//! timing reveals no more than the reference's does (the sieve, the comparisons of the
//! Miller-Rabin rounds).

use core::cmp::Ordering;

/// The largest number of limbs: one RSA prime of the largest key size of the profile.
pub(crate) const MAX_LIMBS: usize = tpm2::TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES / 8;

/// An unsigned integer of `len` little-endian 64-bit limbs (at most [`MAX_LIMBS`]).
#[derive(Clone, Copy)]
pub(crate) struct Uint {
    limbs: [u64; MAX_LIMBS],
    len: usize,
}

impl Uint {
    /// Zero with `len` limbs.
    pub(crate) const fn zero(len: usize) -> Self {
        Self {
            limbs: [0; MAX_LIMBS],
            len,
        }
    }

    /// The small value `value` with `len` limbs (`len >= 1`).
    pub(crate) fn from_u64(value: u64, len: usize) -> Self {
        let mut n = Self::zero(len);
        n.limbs[0] = value;
        n
    }

    /// The big-endian `bytes` (a multiple of 8 octets, at most `8 * MAX_LIMBS`), with
    /// `bytes.len() / 8` limbs, or `None` if `bytes` does not fit.
    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        if !bytes.len().is_multiple_of(8) || bytes.len() > 8 * MAX_LIMBS {
            return None;
        }
        let mut n = Self::zero(bytes.len() / 8);
        for (limb, chunk) in n.limbs.iter_mut().zip(bytes.rchunks_exact(8)) {
            *limb = u64::from_be_bytes(chunk.try_into().ok()?);
        }
        Some(n)
    }

    /// Writes the value big-endian to `out` (exactly `8 * len` octets).
    pub(crate) fn write_be_bytes(&self, out: &mut [u8]) {
        for (chunk, limb) in out.rchunks_exact_mut(8).zip(self.limbs()) {
            chunk.copy_from_slice(&limb.to_be_bytes());
        }
    }

    /// The significant limbs.
    pub(crate) fn limbs(&self) -> &[u64] {
        &self.limbs[..self.len]
    }

    /// The number of significant limbs.
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Whether the value is zero.
    pub(crate) fn is_zero(&self) -> bool {
        self.limbs().iter().all(|&l| l == 0)
    }

    /// Whether the value is the word `w`.
    pub(crate) fn eq_word(&self, w: u64) -> bool {
        self.limbs.first() == Some(&w) && self.limbs[1..self.len].iter().all(|&l| l == 0)
    }

    /// The least significant 32 bits (`ExtMath_GetLeastSignificant32bits()`).
    pub(crate) const fn low_u32(&self) -> u32 {
        self.limbs[0] as u32
    }

    /// The number of bits needed to hold the value (`ExtMath_SizeInBits()`; 0 for zero).
    pub(crate) fn bit_len(&self) -> usize {
        match self.limbs().iter().rposition(|&l| l != 0) {
            Some(i) => 64 * i + 64 - self.limbs[i].leading_zeros() as usize,
            None => 0,
        }
    }

    /// Bit `i` of the value.
    pub(crate) fn bit(&self, i: usize) -> bool {
        self.limbs
            .get(i / 64)
            .is_some_and(|l| (l >> (i % 64)) & 1 == 1)
    }

    /// Compares the values of `self` and `other` (of any lengths).
    pub(crate) fn cmp_value(&self, other: &Self) -> Ordering {
        let len = self.len.max(other.len);
        (0..len)
            .rev()
            .map(|i| self.limbs[i].cmp(&other.limbs[i]))
            .find(|o| o.is_ne())
            .unwrap_or(Ordering::Equal)
    }

    /// `self + w` (the carry out of the `len` limbs is dropped).
    pub(crate) fn add_word(&self, w: u64) -> Self {
        let mut out = *self;
        let mut carry = w;
        for limb in out.limbs[..out.len].iter_mut() {
            let (sum, overflow) = limb.overflowing_add(carry);
            *limb = sum;
            carry = u64::from(overflow);
        }
        out
    }

    /// `self - w`, for `self >= w`.
    pub(crate) fn sub_word(&self, w: u64) -> Self {
        let mut out = *self;
        let mut borrow = w;
        for limb in out.limbs[..out.len].iter_mut() {
            let (diff, underflow) = limb.overflowing_sub(borrow);
            *limb = diff;
            borrow = u64::from(underflow);
        }
        out
    }

    /// `self - other` with `self.len` limbs, for `self >= other`.
    pub(crate) fn sub(&self, other: &Self) -> Self {
        let mut out = *self;
        sub_in_place(&mut out.limbs[..self.len], &other.limbs[..self.len]);
        out
    }

    /// `|self - other|`.
    pub(crate) fn abs_diff(&self, other: &Self) -> Self {
        match self.cmp_value(other) {
            Ordering::Less => other.sub(self),
            _ => self.sub(other),
        }
    }

    /// `self >> shift` (`ExtMath_ShiftRight()`).
    pub(crate) fn shr(&self, shift: usize) -> Self {
        let mut out = Self::zero(self.len);
        let (limbs, bits) = (shift / 64, shift % 64);
        for i in 0..self.len.saturating_sub(limbs) {
            let low = self.limbs[i + limbs] >> bits;
            let high = match (bits, self.limbs.get(i + limbs + 1)) {
                (0, _) | (_, None) => 0,
                (_, Some(&next)) => next << (64 - bits),
            };
            out.limbs[i] = low | high;
        }
        out
    }

    /// The remainder of the value divided by the word `m` (`ExtMath_ModWord()`; `m != 0`).
    pub(crate) fn rem_u32(&self, m: u32) -> u32 {
        let m = u128::from(m);
        let rem = self
            .limbs()
            .iter()
            .rev()
            .fold(0u128, |rem, &limb| ((rem << 64) | u128::from(limb)) % m);
        rem as u32
    }

    /// Whether `gcd(self, other) == 1` (a binary GCD; `ExtMath_ModInverse()` of the reference
    /// succeeds exactly then). The values are public in the prime search's use (a pair of
    /// distinct primes) except in a probability-zero case.
    pub(crate) fn coprime(&self, other: &Self) -> bool {
        let (mut a, mut b) = (*self, *other);
        let len = a.len.max(b.len);
        (a.len, b.len) = (len, len);
        if a.is_zero() || b.is_zero() {
            return a.eq_word(1) || b.eq_word(1);
        }
        // A common factor of 2 means they are not coprime.
        if !a.bit(0) && !b.bit(0) {
            return false;
        }
        while !a.bit(0) {
            a = a.shr(1);
        }
        loop {
            while !b.bit(0) {
                b = b.shr(1);
            }
            if a.cmp_value(&b) == Ordering::Greater {
                core::mem::swap(&mut a, &mut b);
            }
            b = b.sub(&a);
            if b.is_zero() {
                return a.eq_word(1);
            }
        }
    }
}

/// `a -= b` for limb slices of equal length; returns the borrow out.
fn sub_in_place(a: &mut [u64], b: &[u64]) -> u64 {
    let mut borrow = 0u64;
    for (x, &y) in a.iter_mut().zip(b) {
        let (d1, o1) = x.overflowing_sub(y);
        let (d2, o2) = d1.overflowing_sub(borrow);
        *x = d2;
        borrow = u64::from(o1 | o2);
    }
    borrow
}

/// Writes the big-endian product `a * b` (`2 * len` limbs, for operands of `len` limbs) to `out`
/// (exactly `16 * len` octets).
pub(crate) fn mul_to_be_bytes(a: &Uint, b: &Uint, out: &mut [u8]) {
    let len = a.len;
    let mut product = [0u64; 2 * MAX_LIMBS];
    for i in 0..len {
        let mut carry = 0u128;
        for j in 0..len {
            let t = u128::from(a.limbs[i]) * u128::from(b.limbs[j])
                + u128::from(product[i + j])
                + carry;
            product[i + j] = t as u64;
            carry = t >> 64;
        }
        product[i + len] = carry as u64;
    }
    for (chunk, limb) in out.rchunks_exact_mut(8).zip(&product[..2 * len]) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    product.fill(0);
}

/// Montgomery arithmetic modulo an odd `m` (`R = 2^(64 * len)`): numbers in the Montgomery form
/// `x * R mod m` are multiplied with [`Monty::mul`].
pub(crate) struct Monty {
    /// The odd modulus.
    m: Uint,
    /// `-m^-1 mod 2^64`.
    m0_inv: u64,
    /// `R^2 mod m`, to convert into the Montgomery form.
    r2: Uint,
}

impl Monty {
    /// The arithmetic modulo the odd `m` (`m > 1`).
    pub(crate) fn new(m: &Uint) -> Self {
        // m0^-1 mod 2^64 by Newton's iteration (each step doubles the correct low bits).
        let m0 = m.limbs[0];
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        }
        // R^2 mod m by doubling 1 2 * 64 * len times modulo m.
        let mut r2 = Uint::from_u64(1, m.len);
        for _ in 0..2 * 64 * m.len {
            r2 = double_mod(&r2, m);
        }
        Self {
            m: *m,
            m0_inv: inv.wrapping_neg(),
            r2,
        }
    }

    /// The Montgomery product `a * b * R^-1 mod m`, for `a, b < m` (CIOS, with the final
    /// subtraction selected without branches).
    pub(crate) fn mul(&self, a: &Uint, b: &Uint) -> Uint {
        let len = self.m.len;
        let m = &self.m.limbs;
        let mut t = [0u64; MAX_LIMBS + 2];
        for &bi in &b.limbs[..len] {
            let mut carry = 0u128;
            for j in 0..len {
                let s = u128::from(t[j]) + u128::from(a.limbs[j]) * u128::from(bi) + carry;
                t[j] = s as u64;
                carry = s >> 64;
            }
            let s = u128::from(t[len]) + carry;
            t[len] = s as u64;
            t[len + 1] = (s >> 64) as u64;
            let u = t[0].wrapping_mul(self.m0_inv);
            let s = u128::from(t[0]) + u128::from(u) * u128::from(m[0]);
            let mut carry = s >> 64;
            for j in 1..len {
                let s = u128::from(t[j]) + u128::from(u) * u128::from(m[j]) + carry;
                t[j - 1] = s as u64;
                carry = s >> 64;
            }
            let s = u128::from(t[len]) + carry;
            t[len - 1] = s as u64;
            t[len] = t[len + 1] + (s >> 64) as u64;
        }
        // t < 2m: subtract m once if t >= m (t[len] is the extra limb).
        let mut out = Uint::zero(len);
        out.limbs[..len].copy_from_slice(&t[..len]);
        let mut reduced = out;
        let borrow = sub_in_place(&mut reduced.limbs[..len], &m[..len]);
        // Keep the subtraction unless it borrowed out of a value without the extra limb.
        let keep = u64::from(t[len] != 0) | (1 ^ borrow);
        select(&mut out, &reduced, keep);
        t.fill(0);
        out
    }

    /// `a` (`a < m`) in the Montgomery form.
    pub(crate) fn to_monty(&self, a: &Uint) -> Uint {
        self.mul(a, &self.r2)
    }

    /// `a` (in the Montgomery form) in the normal form.
    pub(crate) fn to_normal(&self, a: &Uint) -> Uint {
        self.mul(a, &Uint::from_u64(1, self.m.len))
    }

    /// `base^exp mod m` (`base < m`, both in the normal form), in time independent of `base`
    /// and `exp` (`ExtMath_ModExp()`): a fixed 4-bit window over all `64 * len` bits of `exp`.
    pub(crate) fn pow(&self, base: &Uint, exp: &Uint) -> Uint {
        let len = self.m.len;
        let mut table = [Uint::zero(len); 16];
        table[0] = self.to_monty(&Uint::from_u64(1, len));
        table[1] = self.to_monty(base);
        for i in 2..16 {
            table[i] = self.mul(&table[i - 1], &table[1]);
        }
        let mut acc = table[0];
        for window in (0..16 * len).rev() {
            for _ in 0..4 {
                acc = self.mul(&acc, &acc);
            }
            let digit = (exp.limbs[window / 16] >> (4 * (window % 16))) & 0xf;
            let mut factor = Uint::zero(len);
            for (i, entry) in table.iter().enumerate() {
                select(&mut factor, entry, u64::from(i as u64 == digit));
            }
            acc = self.mul(&acc, &factor);
        }
        for entry in table.iter_mut() {
            entry.limbs.fill(0);
        }
        self.to_normal(&acc)
    }
}

/// `2a mod m`, for `a < m`.
fn double_mod(a: &Uint, m: &Uint) -> Uint {
    let len = m.len;
    let mut out = Uint::zero(len);
    let mut carry = 0u64;
    for i in 0..len {
        out.limbs[i] = (a.limbs[i] << 1) | carry;
        carry = a.limbs[i] >> 63;
    }
    let mut reduced = out;
    let borrow = sub_in_place(&mut reduced.limbs[..len], &m.limbs[..len]);
    select(&mut out, &reduced, carry | (1 ^ borrow));
    out
}

/// Copies `src` into `dst` if `choice` is 1 and leaves `dst` unchanged if it is 0, without
/// branches on `choice`.
fn select(dst: &mut Uint, src: &Uint, choice: u64) {
    let mask = 0u64.wrapping_sub(choice & 1);
    for (d, s) in dst.limbs.iter_mut().zip(&src.limbs) {
        *d = (*d & !mask) | (*s & mask);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    /// A deterministic pseudo-random number of `len` limbs (odd if `odd`).
    fn number(seed: u64, len: usize, odd: bool) -> Uint {
        let mut n = Uint::zero(len);
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        for limb in n.limbs[..len].iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *limb = x;
        }
        n.limbs[len - 1] |= 1 << 63;
        if odd {
            n.limbs[0] |= 1;
        }
        n
    }

    fn big(n: &Uint) -> BigUint {
        let mut bytes = alloc::vec![0u8; 8 * n.len()];
        n.write_be_bytes(&mut bytes);
        BigUint::from_bytes_be(&bytes)
    }

    fn uint(b: &BigUint, len: usize) -> Uint {
        let bytes = b.to_bytes_be();
        let mut padded = alloc::vec![0u8; 8 * len];
        padded[8 * len - bytes.len()..].copy_from_slice(&bytes);
        Uint::from_be_bytes(&padded).unwrap()
    }

    /// Byte conversions round-trip and reject sizes that are not limbs or do not fit.
    #[test]
    fn bytes_round_trip() {
        let bytes: alloc::vec::Vec<u8> = (0u8..64).collect();
        let n = Uint::from_be_bytes(&bytes).unwrap();
        assert_eq!(n.len(), 8);
        assert_eq!(n.low_u32(), 0x3c3d_3e3f);
        let mut out = [0u8; 64];
        n.write_be_bytes(&mut out);
        assert_eq!(out[..], bytes[..]);
        assert!(Uint::from_be_bytes(&[0; 7]).is_none());
        assert!(Uint::from_be_bytes(&alloc::vec![0; 8 * MAX_LIMBS + 8]).is_none());
    }

    /// The small operations agree with `num-bigint`.
    #[test]
    fn small_operations_match_num_bigint() {
        for seed in 1..20 {
            let len = 1 + (seed as usize % MAX_LIMBS);
            let (a, b) = (number(seed, len, false), number(seed + 100, len, true));
            let (ba, bb) = (big(&a), big(&b));
            assert_eq!(a.bit_len() as u64, ba.bits());
            assert_eq!(
                big(&a.add_word(u64::MAX)),
                (&ba + u64::MAX) % (BigUint::from(1u8) << (64 * len))
            );
            assert_eq!(big(&a.sub_word(12345)), &ba - 12345u32);
            assert_eq!(
                big(&a.abs_diff(&b)),
                if ba > bb { &ba - &bb } else { &bb - &ba }
            );
            for shift in [0, 1, 63, 64, 65, 130] {
                assert_eq!(big(&a.shr(shift)), &ba >> shift, "{shift}");
            }
            for m in [3u32, 105, 65537, 0xffff_fffb, 955_049_953] {
                assert_eq!(BigUint::from(a.rem_u32(m)), &ba % m);
            }
            assert_eq!(a.cmp_value(&b), ba.cmp(&bb));
            assert_eq!(a.bit(5), ba.bit(5));
            let mut product = alloc::vec![0u8; 16 * len];
            mul_to_be_bytes(&a, &b, &mut product);
            assert_eq!(BigUint::from_bytes_be(&product), &ba * &bb);
        }
        assert!(Uint::from_u64(1, 3).eq_word(1));
        assert!(!Uint::from_u64(2, 3).eq_word(1));
        assert!(Uint::zero(2).is_zero() && Uint::zero(2).bit_len() == 0);
    }

    /// `coprime` is `gcd == 1`.
    #[test]
    fn coprime_is_gcd_one() {
        let n = |v: u64| Uint::from_u64(v, 2);
        assert!(n(35).coprime(&n(64)));
        assert!(!n(35).coprime(&n(21)));
        assert!(!n(12).coprime(&n(18)));
        assert!(n(1).coprime(&n(0)));
        assert!(!n(0).coprime(&n(5)));
        let (a, b) = (number(7, 4, true), number(8, 4, true));
        let gcd = {
            let (mut x, mut y) = (big(&a), big(&b));
            while y != BigUint::from(0u8) {
                (x, y) = (y.clone(), x % y);
            }
            x
        };
        assert_eq!(a.coprime(&b), gcd == BigUint::from(1u8));
        assert!(!a.coprime(&a));
    }

    /// Montgomery multiplication and exponentiation agree with `num-bigint`.
    #[test]
    fn montgomery_matches_num_bigint() {
        for seed in 1..12 {
            let len = 1 + (seed as usize * 5 % MAX_LIMBS);
            let m = number(seed, len, true);
            let bm = big(&m);
            let monty = Monty::new(&m);
            let a = uint(&(big(&number(seed + 1, len, false)) % &bm), len);
            let b = uint(&(big(&number(seed + 2, len, false)) % &bm), len);
            let product = monty.to_normal(&monty.mul(&monty.to_monty(&a), &monty.to_monty(&b)));
            assert_eq!(big(&product), big(&a) * big(&b) % &bm, "{len} limbs");
            let exp = number(seed + 3, len, false);
            assert_eq!(big(&monty.pow(&a, &exp)), big(&a).modpow(&big(&exp), &bm));
            assert_eq!(
                big(&monty.pow(&a, &Uint::zero(len))),
                BigUint::from(1u8) % &bm
            );
        }
        // m - 1 squared is 1.
        let m = number(3, 4, true);
        let monty = Monty::new(&m);
        let minus_one = m.sub_word(1);
        assert!(monty.pow(&minus_one, &Uint::from_u64(2, 4)).eq_word(1));
    }
}
