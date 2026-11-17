//! RSA key generation with the C reference TPMs' prime search (`CryptRsaGenerateKey()` of
//! `CryptRsa.c`, `TpmRsa_GeneratePrimeForRSA()` and `MillerRabin()` of `CryptPrime.c`, and
//! `PrimeSelectWithSieve()`/`PrimeSieve()` of `CryptPrimeSieve.c`), drawing every random value
//! from an [`Rng`] with [`Rng::fill_bytes`]: the prime candidates, the Miller-Rabin bases and the
//! value of the pairwise consistency test of a signing key, in the reference's order and sizes
//! and with its retries. A TPM whose RNG draws the reference's DRBG output therefore generates the
//! reference's RSA keys.
//!
//! The search for one prime of `bits = keyBits / 2` bits:
//!
//! 1. Draw `bits / 8` octets and reverse their order (`TpmMath_GetRandomBits()`), set the lowest
//!    bit and replace the most significant 32 bits `msw` with `0xB505_0000 + (msw * 0x4AFB) >>
//!    16` (`RsaAdjustPrimeCandidate()`), so that the product of two primes has exactly `keyBits`
//!    bits.
//! 2. Sieve a field of 16384 odd numbers starting at the candidate rounded down to an odd
//!    multiple of 105 with the small primes up to a limit that depends on `bits`
//!    (`PrimeSieve()`), starting from a pattern without the multiples of 3, 5 and 7.
//! 3. Take the remaining numbers in an order derived from the candidate's low 32 bits; the first
//!    one that is not 0 or 1 modulo the public exponent and passes Miller-Rabin (with bases drawn
//!    from the RNG) is the prime. If none does, draw a new candidate.
//!
//! The key is the first pair of primes whose difference has more than 100 bits (each new prime is
//! paired with the previous one); a signing key must also pass the pairwise test (a random value
//! in `[1, n)` encrypted and decrypted with the backend's raw RSA). The key is then built by the
//! backend from the modulus and the prime that the reference's sensitive area holds first (the
//! prime generated into the first of its two prime slots, which may be the larger or the smaller
//! prime), so that the TPM stores the reference's prime-only and CRT forms.
//!
//! The big-number arithmetic is [`crate::bignum`] (fixed-size, on the stack).

use core::cmp::Ordering;

use tpm2::crypto::{Crypto, CryptoError, Rng, RsaEncryptScheme, RsaPrivateKey, RsaPublicKey};
use tpm2::{Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmiRsaKeyBits};

use crate::bignum::{MAX_LIMBS, Monty, Uint, mul_to_be_bytes};

/// `RSA_DEFAULT_PUBLIC_EXPONENT`: the public exponent used for the exponent 0.
const DEFAULT_EXPONENT: u32 = 65537;

/// The iterations of the key loop of `CryptRsaGenerateKey()` (`i` from 1 to 99), each of which
/// generates one prime.
const KEY_ITERATIONS: usize = 99;

/// A bound on the prime candidates of `TpmRsa_GeneratePrimeForRSA()` and on the draws of a
/// Miller-Rabin base, which the reference repeats until they succeed (a field without a prime,
/// or a base out of range, has a small probability), so that a broken RNG cannot hang the TPM.
const MAX_ATTEMPTS: usize = 1000;

/// The size of the sieve field in octets (`MAX_FIELD_SIZE`): 16384 odd numbers.
const FIELD_SIZE: usize = 2048;

/// The largest number of the reference's table of small primes (`s_LastPrimeInTable`).
const LAST_PRIME_IN_TABLE: u32 = 65537;

/// The number of primes in the reference's table (`s_PrimesInTable`, the odd primes up to
/// [`LAST_PRIME_IN_TABLE`]).
const PRIMES_IN_TABLE: u32 = 6542;

/// The sieve limits of the reference (`s_PrimeMarkers`): the 1024th, 2048th, ... prime.
const PRIME_MARKERS: [u32; 6] = [8167, 17881, 28183, 38891, 49871, 60961];

/// The reference's grouping of the sieve primes (`sieveMarks`): primes below `prime` are taken
/// `count` at a time, so that the product of a group fits in 32 bits.
const SIEVE_MARKS: [(u32, usize); 6] = [
    (31, 7),
    (73, 5),
    (241, 4),
    (1621, 3),
    (u16::MAX as u32, 2),
    (u32::MAX, 1),
];

/// The odd primes up to [`LAST_PRIME_IN_TABLE`] as a bit map (`s_PrimeTable`): bit `i` (bit
/// `i % 8` of octet `i / 8`) is set if `2i + 1` is prime.
static PRIME_TABLE: [u8; 4097] = prime_table();

/// The initial sieve field pattern (`seedValues`, 105 octets): bit `j` is set unless
/// `105 + 2j` is a multiple of 3, 5 or 7, i.e. the field of an odd multiple of 105 after
/// sieving with 3, 5 and 7.
static SEED_VALUES: [u8; 105] = seed_values();

/// Computes [`PRIME_TABLE`] with the sieve of Eratosthenes.
const fn prime_table() -> [u8; 4097] {
    const LIMIT: usize = LAST_PRIME_IN_TABLE as usize;
    let mut composite = [false; LIMIT + 1];
    let mut table = [0u8; 4097];
    let mut n = 3;
    while n <= LIMIT {
        if !composite[n] {
            let i = n / 2;
            table[i / 8] |= 1 << (i % 8);
            let mut multiple = n * n;
            while multiple <= LIMIT {
                composite[multiple] = true;
                multiple += 2 * n;
            }
        }
        n += 2;
    }
    table
}

/// Computes [`SEED_VALUES`].
const fn seed_values() -> [u8; 105] {
    let mut field = [0u8; 105];
    let mut j = 0;
    while j < 8 * 105 {
        let n = 105 + 2 * j;
        if n % 3 != 0 && n % 5 != 0 && n % 7 != 0 {
            field[j / 8] |= 1 << (j % 8);
        }
        j += 1;
    }
    field
}

/// Generates an RSA key of `bits` bits with the public exponent `exponent` (0 for 65537;
/// otherwise a prime of at least 65537) as the reference's `CryptRsaGenerateKey()` does, drawing
/// from `rng` (see the [module documentation](self)); `sign` is the *sign* attribute of the key's
/// object, which adds the pairwise consistency test. The backend builds the key from the modulus
/// and the prime the reference stores first ([`RsaPrivateKey::prime_p`]).
///
/// Returns [`CryptoError::Unsupported`] for another exponent (the caller reports
/// `TPM_RC_RANGE` first) or a key the backend cannot build (e.g. its exponent), and
/// [`CryptoError::Internal`] if drawing fails or no key is found within the reference's
/// iterations.
pub(crate) fn generate_key<C: Crypto>(
    rng: &mut C::Rng,
    bits: TpmiRsaKeyBits,
    exponent: u32,
    sign: bool,
) -> Result<RsaPrivateKey<C>, CryptoError> {
    let e = match exponent {
        0 => DEFAULT_EXPONENT,
        e if e >= DEFAULT_EXPONENT && is_prime_u32(e) => e,
        _ => return Err(CryptoError::Unsupported),
    };
    let key_bytes = usize::from(bits.as_u16()) / 8;
    let prime_bits = 4 * key_bytes;
    if prime_bits > 64 * MAX_LIMBS || !prime_bits.is_multiple_of(64) {
        return Err(CryptoError::Unsupported);
    }
    let prime_bytes = key_bytes / 2;
    // The reference's two prime slots (the storage of `Z->P` and `Z->Q` of its
    // `privateExponent`) and which slot `Z->P` points to: `MakePgreaterThanQ()` swaps the
    // pointers, not the values, and the first slot's prime is the one the sensitive area holds
    // first (the prime-only form), whether it is the larger or the smaller prime.
    let zero = Uint::zero(prime_bits / 64);
    let mut slots = [zero; 2];
    let (mut pi, mut qi) = (0, 1);
    for _ in 0..KEY_ITERATIONS {
        slots[pi] = generate_prime(rng, prime_bits, e)?;
        if slots[qi].is_zero() {
            slots[qi] = slots[pi];
            continue;
        }
        // The primes must differ in more than their low 100 bits (`MostSigBitNum(|p - q|) <
        // 100`: the bit number of the most significant bit, one less than the bit length).
        if slots[pi].abs_diff(&slots[qi]).bit_len() <= 100 {
            continue;
        }
        let mut modulus = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let modulus = &mut modulus[..key_bytes];
        mul_to_be_bytes(&slots[pi], &slots[qi], modulus);
        if modulus[0] & 0x80 == 0 {
            // `FAIL(FATAL_ERROR_INTERNAL)` in the reference: impossible with adjusted candidates.
            return Err(CryptoError::Internal);
        }
        // `ComputePrivateExponent()`: `Z->P` becomes the larger prime; e must be invertible
        // modulo p - 1 and q - 1 (e is prime, so it must not divide them), and q modulo p.
        if slots[pi].cmp_value(&slots[qi]) == Ordering::Less {
            core::mem::swap(&mut pi, &mut qi);
        }
        let mut p_ok = slots[pi].sub_word(1).rem_u32(e) != 0;
        let mut q_ok = slots[qi].sub_word(1).rem_u32(e) != 0;
        if p_ok && q_ok {
            let inverse = slots[qi].coprime(&slots[pi]);
            (p_ok, q_ok) = (inverse, inverse);
        }
        if !(p_ok && q_ok) {
            if !p_ok {
                slots[pi] = zero;
            }
            if !q_ok {
                slots[qi] = zero;
            }
            if slots[qi].is_zero() {
                slots[qi] = slots[pi];
            }
            continue;
        }
        let mut prime = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
        let prime = &mut prime[..prime_bytes];
        slots[0].write_be_bytes(prime);
        let key = build_key::<C>(bits, e, modulus, prime);
        prime.fill(0);
        let key = key?;
        if sign && !pairwise_test::<C>(rng, &key, modulus)? {
            // A failed test discards the smaller prime (and so, at the next prime, both).
            slots[qi] = zero;
            continue;
        }
        return Ok(key);
    }
    Err(CryptoError::Internal)
}

/// The key of the modulus `modulus` and the prime `prime` with the public exponent `e`, built by
/// the backend.
fn build_key<C: Crypto>(
    bits: TpmiRsaKeyBits,
    e: u32,
    modulus: &[u8],
    prime: &[u8],
) -> Result<RsaPrivateKey<C>, CryptoError> {
    let n = Tpm2bPublicKeyRsa::new(modulus).ok_or(CryptoError::Internal)?;
    let p = Tpm2bPrivateKeyRsa::new(prime).ok_or(CryptoError::Internal)?;
    let public = RsaPublicKey::<C>::load(bits, e, n)?.ok_or(CryptoError::Internal)?;
    RsaPrivateKey::load(public, p)?.ok_or(CryptoError::Internal)
}

/// The pairwise consistency test of a signing key (`CryptRsaGenerateKey()`): a value
/// `1 <= m < n` drawn from `rng` (`TpmMath_GetRandomInRange()`) must decrypt to itself after
/// encryption with the backend's raw RSA. Returns whether it does.
fn pairwise_test<C: Crypto>(
    rng: &mut C::Rng,
    key: &RsaPrivateKey<C>,
    modulus: &[u8],
) -> Result<bool, CryptoError> {
    let mut m = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let m = &mut m[..modulus.len()];
    random_below(rng, modulus, m)?;
    let n = Tpm2bPublicKeyRsa::new(modulus).ok_or(CryptoError::Internal)?;
    let public =
        RsaPublicKey::<C>::load(key.bits(), key.exponent(), n)?.ok_or(CryptoError::Internal)?;
    let mut c = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let Some(c) = public.encrypt(rng, RsaEncryptScheme::Raw, m, &mut c)? else {
        return Ok(false);
    };
    let mut back = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let Some(back) = key.decrypt(rng, RsaEncryptScheme::Raw, c.as_slice(), &mut back)? else {
        return Ok(false);
    };
    Ok(back.as_slice() == &m[..])
}

/// `TpmMath_GetRandomInRange()` for the big-endian `limit` whose most significant bit is set
/// (an RSA modulus): `limit.len()` octets drawn from `rng` into `out`, drawn again while the
/// value is zero or not below `limit`.
fn random_below(rng: &mut impl Rng, limit: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    for _ in 0..MAX_ATTEMPTS {
        rng.fill_bytes(out)?;
        if out.iter().any(|&b| b != 0) && &out[..] < limit {
            return Ok(());
        }
    }
    Err(CryptoError::Internal)
}

/// `IsPrimeInt()`: whether `n` is prime (trial division).
fn is_prime_u32(n: u32) -> bool {
    if n < 4 {
        return n >= 2;
    }
    if n.is_multiple_of(2) {
        return false;
    }
    let n = u64::from(n);
    (3u64..)
        .step_by(2)
        .take_while(|d| d * d <= n)
        .all(|d| n % d != 0)
}

/// `TpmRsa_GeneratePrimeForRSA()`: a prime of `bits` bits (a multiple of 64) for the public
/// exponent `e`, from candidates drawn from `rng` (see the [module documentation](self)).
fn generate_prime(rng: &mut impl Rng, bits: usize, e: u32) -> Result<Uint, CryptoError> {
    let mut large = [0u8; 8 * MAX_LIMBS];
    let large = &mut large[..bits / 8];
    for _ in 0..MAX_ATTEMPTS {
        // `TpmMath_GetRandomBits()`: the drawn octets in reverse order (for compatibility with
        // the reference's older known-answer tests); `bits` is a multiple of 8, so no bits are
        // masked.
        rng.fill_bytes(large)?;
        large.reverse();
        adjust_prime_candidate(large);
        let candidate = Uint::from_be_bytes(large).ok_or(CryptoError::Internal)?;
        if let Some(prime) = prime_select_with_sieve(rng, candidate, e)? {
            large.fill(0);
            return Ok(prime);
        }
    }
    large.fill(0);
    Err(CryptoError::Internal)
}

/// `RsaAdjustPrimeCandidate()`: makes the big-endian candidate odd and maps its most significant
/// 32 bits `msw` linearly onto `[0xB505_0000, 0xFFFF_FFFF]` (`0xB505_0000 + msw * 0x4AFB / 2^16`,
/// computed in two 16-bit halves), so that the product of two such primes has its top bit set.
fn adjust_prime_candidate(candidate: &mut [u8]) {
    if let Some(last) = candidate.last_mut() {
        *last |= 1;
    }
    let Some(top) = candidate.first_chunk_mut::<4>() else {
        return;
    };
    let msw = u32::from_be_bytes(*top);
    let adjusted = (msw >> 16)
        .wrapping_mul(0x4AFB)
        .wrapping_add(((msw & 0xFFFF).wrapping_mul(0x4AFB)) >> 16)
        .wrapping_add(0xB505_0000);
    *top = adjusted.to_be_bytes();
}

/// `RsaAdjustPrimeLimit()`: the sieve limit (as the index `p / 2` of the largest sieve prime in
/// [`PRIME_TABLE`]) for the first `requested` primes of the table (0: all).
fn prime_limit(requested: u32) -> u32 {
    let requested = if requested == 0 || requested > PRIMES_IN_TABLE {
        PRIMES_IN_TABLE
    } else {
        requested
    };
    let marker = ((requested - 1) / 1024) as usize;
    PRIME_MARKERS
        .get(marker)
        .copied()
        .unwrap_or(LAST_PRIME_IN_TABLE)
        >> 1
}

/// `RsaNextPrime()`: the next odd prime of [`PRIME_TABLE`] after `last` up to the limit `limit`
/// ([`prime_limit`]), or 0 if there is none (or `last` is 0).
fn next_prime(last: u32, limit: u32) -> u32 {
    if last == 0 {
        return 0;
    }
    ((last >> 1) + 1..=limit)
        .find(|&i| (PRIME_TABLE[(i >> 3) as usize] >> (i & 7)) & 1 == 1)
        .map_or(0, |i| (i << 1) + 1)
}

/// Clears bit `bit` of `field`.
fn clear_bit(field: &mut [u8; FIELD_SIZE], bit: usize) {
    field[bit >> 3] &= !(1 << (bit & 7));
}

/// `FindNthSetBit()`: the number of the `n`-th (from 1) set bit of `field`, counting the bits of
/// each octet from the least significant, or `None` if fewer bits are set.
fn find_nth_set_bit(field: &[u8; FIELD_SIZE], n: u32) -> Option<usize> {
    let mut seen = 0u32;
    for (i, &octet) in field.iter().enumerate() {
        let ones = octet.count_ones();
        if seen + ones >= n {
            let mut remaining = n - seen;
            for bit in 0..8 {
                if (octet >> bit) & 1 == 1 {
                    remaining -= 1;
                    if remaining == 0 {
                        return Some(8 * i + bit);
                    }
                }
            }
        }
        seen += ones;
    }
    None
}

/// `PrimeSieve()`: rounds `base` down to an odd multiple of 105 and returns the sieve field of
/// the 16384 odd numbers `base + 2j` (bit `j` set unless a sieve prime up to the limit `limit`
/// divides `base + 2j`) and the number of set bits.
fn prime_sieve(base: &mut Uint, limit: u32) -> Result<([u8; FIELD_SIZE], u32), CryptoError> {
    let mut adjust = base.rem_u32(105);
    if adjust & 1 == 1 {
        adjust += 105;
    }
    *base = base.sub_word(u64::from(adjust));
    let mut field = [0u8; FIELD_SIZE];
    for (octet, seed) in field.iter_mut().zip(SEED_VALUES.iter().cycle()) {
        *octet = *seed;
    }
    let field_bits = 8 * FIELD_SIZE as u32;
    let (mut mark, mut iter) = (0, 7u32);
    let (mut stop, mut count) = SIEVE_MARKS[0];
    let mut primes = [0u32; 8];
    'sieve: loop {
        // A group of `count` primes (`primes[count]` down to `primes[1]`) and their product.
        iter = next_prime(iter, limit);
        if iter == 0 {
            break;
        }
        let mut composite = iter;
        primes[count] = iter;
        for i in (1..count).rev() {
            iter = next_prime(iter, limit);
            primes[i] = iter;
            if iter != 0 {
                composite = composite.wrapping_mul(iter);
            }
        }
        let remainder = base.rem_u32(composite);
        let mut next = 0;
        for &prime in primes[1..=count].iter().rev() {
            next = prime;
            if prime == 0 {
                break 'sieve;
            }
            // The first j with base + 2j = 0 (mod prime).
            let r = remainder % prime;
            let mut j = if r & 1 == 1 {
                (prime - r) / 2
            } else if r == 0 {
                0
            } else {
                prime - r / 2
            };
            while j < field_bits {
                clear_bit(&mut field, j as usize);
                j += prime;
            }
        }
        if next >= stop {
            mark += 1;
            // `FAIL(FATAL_ERROR_INTERNAL)` in the reference.
            (stop, count) = *SIEVE_MARKS.get(mark).ok_or(CryptoError::Internal)?;
        }
    }
    let ones = field.iter().map(|o| o.count_ones()).sum();
    Ok((field, ones))
}

/// `PrimeSelectWithSieve()`: the prime of the sieve field of `candidate` (see the
/// [module documentation](self)), or `Ok(None)` if the field has none.
fn prime_select_with_sieve(
    rng: &mut impl Rng,
    mut candidate: Uint,
    e: u32,
) -> Result<Option<Uint>, CryptoError> {
    // The first 1024 primes for primes of up to 512 bits, 4096 up to 1024 bits, else all.
    let prime_size = candidate.bit_len();
    let limit = if prime_size <= 512 {
        prime_limit(1024)
    } else if prime_size <= 1024 {
        prime_limit(4096)
    } else {
        prime_limit(0)
    };
    let first = candidate.low_u32() | 0x8000_0000;
    let (mut field, mut ones) = prime_sieve(&mut candidate, limit)?;
    while ones > 0 {
        let chosen = find_nth_set_bit(&field, first % ones + 1).ok_or(CryptoError::Internal)?;
        let test = candidate.add_word(2 * chosen as u64);
        let mod_e = test.rem_u32(e);
        if mod_e != 0 && mod_e != 1 && miller_rabin(rng, &test)? {
            return Ok(Some(test));
        }
        clear_bit(&mut field, chosen);
        ones -= 1;
    }
    Ok(None)
}

/// `MillerRabinRounds()`: the Miller-Rabin rounds for a prime of `bits` bits.
fn miller_rabin_rounds(bits: usize) -> usize {
    if bits < 511 {
        8
    } else if bits < 1536 {
        5
    } else {
        4
    }
}

/// `MillerRabin()`: whether the odd `w` is probably prime, with each round's base `b` drawn from
/// `rng` as `TpmMath_GetRandomInteger(b, bitlen(w))` (the octet size of `bitlen(w)`, with the
/// reference's mask, [`crate::modular::reference_mask_bits`]), again while `b <= 1` or
/// `b >= w - 1`.
fn miller_rabin(rng: &mut impl Rng, w: &Uint) -> Result<bool, CryptoError> {
    let w_minus_1 = w.sub_word(1);
    // w - 1 = 2^a * m with m odd (`a` counts from bit 1, as `w - 1` is even).
    let a = (1..64 * w.len())
        .find(|&bit| w_minus_1.bit(bit))
        .unwrap_or(64 * w.len());
    let m = w_minus_1.shr(a);
    let w_bits = w.bit_len();
    let monty = Monty::new(w);
    let one_m = monty.to_monty(&Uint::from_u64(1, w.len()));
    let minus_one_m = monty.to_monty(&w_minus_1);
    let mut bytes = [0u8; 8 * MAX_LIMBS];
    let bytes = &mut bytes[..8 * w.len()];
    let start = bytes.len() - w_bits.div_ceil(8);
    'rounds: for _ in 0..miller_rabin_rounds(w_bits) {
        let mut attempts = 0;
        let b = loop {
            attempts += 1;
            if attempts > MAX_ATTEMPTS {
                return Err(CryptoError::Internal);
            }
            rng.fill_bytes(&mut bytes[start..])?;
            crate::modular::reference_mask_bits(&mut bytes[start..], w_bits);
            let b = Uint::from_be_bytes(bytes).ok_or(CryptoError::Internal)?;
            if b.cmp_value(&Uint::from_u64(1, w.len())) == Ordering::Greater
                && b.cmp_value(&w_minus_1) == Ordering::Less
            {
                break b;
            }
        };
        let z = monty.pow(&b, &m);
        if z.eq_word(1) || z.cmp_value(&w_minus_1) == Ordering::Equal {
            continue;
        }
        let mut z = monty.to_monty(&z);
        for _ in 1..a {
            z = monty.mul(&z, &z);
            if z.cmp_value(&minus_one_m) == Ordering::Equal {
                continue 'rounds;
            }
            if z.cmp_value(&one_m) == Ordering::Equal {
                return Ok(false);
            }
        }
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    /// The tables match the reference's `s_PrimeTable` (`PrimeData.c`) and `seedValues`
    /// (`CryptPrimeSieve.c`).
    #[test]
    fn tables_match_the_reference() {
        assert_eq!(
            PRIME_TABLE[..13],
            [
                0x6e, 0xcb, 0xb4, 0x64, 0x9a, 0x12, 0x6d, 0x81, 0x32, 0x4c, 0x4a, 0x86, 0x0d
            ]
        );
        // The odd primes up to 65537 (the reference's last octet holds only 65537).
        assert_eq!(
            PRIME_TABLE.iter().map(|o| o.count_ones()).sum::<u32>(),
            PRIMES_IN_TABLE
        );
        assert_eq!(PRIME_TABLE[4096], 0x01);
        assert_eq!(
            SEED_VALUES[..12],
            [
                0x16, 0x29, 0xcb, 0xa4, 0x65, 0xda, 0x30, 0x6c, 0x99, 0x96, 0x4c, 0x53
            ]
        );
        assert_eq!(SEED_VALUES[100..], [0x4c, 0x4b, 0xa6, 0x29, 0xd1]);
    }

    /// The prime limits and the prime iteration of the sieve.
    #[test]
    fn prime_limits_and_iteration() {
        assert_eq!(prime_limit(1024), 8167 >> 1);
        assert_eq!(prime_limit(4096), 38891 >> 1);
        assert_eq!(prime_limit(0), 65537 >> 1);
        assert_eq!(prime_limit(7000), 65537 >> 1);
        assert_eq!(next_prime(7, prime_limit(0)), 11);
        assert_eq!(next_prime(0, prime_limit(0)), 0);
        assert_eq!(next_prime(8161, prime_limit(1024)), 8167);
        assert_eq!(next_prime(8167, prime_limit(1024)), 0);
        assert_eq!(next_prime(65521, prime_limit(0)), 65537);
        assert_eq!(next_prime(65537, prime_limit(0)), 0);
    }

    /// `RsaAdjustPrimeCandidate()` maps the top word onto `[0xB5050000, 0xFFFFFFFF]` and makes
    /// the candidate odd.
    #[test]
    fn candidates_are_adjusted() {
        let mut c = [0u8; 8];
        adjust_prime_candidate(&mut c);
        assert_eq!(c, [0xb5, 0x05, 0, 0, 0, 0, 0, 1]);
        let mut c = [0xff; 8];
        adjust_prime_candidate(&mut c);
        assert_eq!(c[..4], 0xffff_ffffu32.to_be_bytes());
        let mut c = [0x80, 0, 0, 0, 0, 0, 0, 0];
        adjust_prime_candidate(&mut c);
        assert_eq!(c[..4], (0xB505_0000u32 + 0x4AFB * 0x8000).to_be_bytes());
    }

    /// `FindNthSetBit()` counts from the least significant bit of each octet.
    #[test]
    fn nth_set_bit() {
        let mut field = [0u8; FIELD_SIZE];
        field[0] = 0b1010_0000;
        field[3] = 0b0000_0001;
        assert_eq!(find_nth_set_bit(&field, 1), Some(5));
        assert_eq!(find_nth_set_bit(&field, 2), Some(7));
        assert_eq!(find_nth_set_bit(&field, 3), Some(24));
        assert_eq!(find_nth_set_bit(&field, 4), None);
    }

    /// The sieve leaves exactly the numbers of its field that no sieve prime divides.
    #[test]
    fn sieve_keeps_the_numbers_without_small_factors() {
        let mut bytes = [0x5au8; 64];
        bytes[63] |= 1;
        let mut base = Uint::from_be_bytes(&bytes).unwrap();
        let original = BigUint::from_bytes_be(&bytes);
        let limit = prime_limit(1024);
        let (field, ones) = prime_sieve(&mut base, limit).unwrap();
        let mut b = [0u8; 64];
        base.write_be_bytes(&mut b);
        let base = BigUint::from_bytes_be(&b);
        assert!(base <= original && &original - &base < BigUint::from(210u32));
        assert_eq!(&base % 105u32, BigUint::from(0u32));
        assert_eq!(&base % 2u32, BigUint::from(1u32));
        let small: alloc::vec::Vec<u32> = (3..=8167).filter(|&p| is_prime_u32(p)).collect();
        let mut count = 0;
        for j in 0..8 * FIELD_SIZE {
            let n = &base + 2u32 * j as u32;
            let expected = small.iter().all(|&p| &n % p != BigUint::from(0u32));
            let set = (field[j / 8] >> (j % 8)) & 1 == 1;
            assert_eq!(set, expected, "bit {j}");
            count += u32::from(set);
        }
        assert_eq!(count, ones);
    }

    /// Miller-Rabin accepts primes and rejects composites, including Carmichael numbers.
    #[test]
    fn miller_rabin_separates_primes_and_composites() {
        use tpm2::crypto::Random;
        let mut rng = tpm2_crypto_rust::RustCryptoProvider::from_seed(b"miller-rabin").unwrap();
        // 2^127 - 1 and 2^61 - 1 are prime; (2^61 - 1)^2 and 561 * 1105 * ... are not.
        let n = |v: u128| {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&v.to_be_bytes());
            Uint::from_be_bytes(&bytes).unwrap()
        };
        assert!(miller_rabin(&mut rng, &n((1 << 127) - 1)).unwrap());
        assert!(miller_rabin(&mut rng, &n((1 << 61) - 1)).unwrap());
        assert!(!miller_rabin(&mut rng, &n(((1u128 << 61) - 1) * ((1 << 61) - 1))).unwrap());
        // The Carmichael number 6763 * 10627 * 29947 (a strong pseudoprime to the bases 2, 3, 5,
        // 7 and 11), and a product of it with another prime.
        let carmichael = 6763u128 * 10627 * 29947;
        assert!(!miller_rabin(&mut rng, &n(carmichael)).unwrap());
        assert!(!miller_rabin(&mut rng, &n(carmichael * 1_000_003)).unwrap());
    }
}
