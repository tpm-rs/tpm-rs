//! The ECC signature schemes computed by the TPM itself on top of the crypto backend's point
//! multiplications ([`tpm2::crypto::ecc_mul_generator`], [`EccPublicKey::mul_point`]) and
//! [`crate::ecc_curves`]: SM2 (`TPM_ALG_SM2`, TPM 2.0 Part 1, "SM2 Digital Signature
//! Algorithm"), EC-Schnorr (`TPM_ALG_ECSCHNORR`, Part 1, "EC Schnorr") and ECDSA on any curve
//! (the engine uses it on the curves the backend's ECDSA does not cover).
//!
//! The dispatch API ([`tpm2::crypto::EccPrivateKey::sign`]) does not implement EC-Schnorr and
//! implements SM2 only where the backend does, so these schemes are computed here. All values
//! are big-endian; signatures are `(r, s)` with both components padded to the size of the curve
//! order. Semantic failures (an invalid signature or key) are `Ok(false)`/`Ok(None)`;
//! [`CryptoError`] is returned only by the backend.
//!
//! The point multiplications are the backend's, without the ECDH self test (as the old
//! multiplications of the old provider interface were); the EC-Schnorr hashes test their hash algorithm
//! ([`Tested`]).
//!
//! The random parts are the C reference TPMs' (`CryptEccMain.c`, `TpmEcc_Signature_*.c`): every
//! random value is drawn from an [`Rng`] with [`Rng::fill_bytes`], with the reference's sizes,
//! order and retries: private scalars and the ECDSA and EC-Schnorr nonces with
//! `TpmEcc_GenPrivateScalar()` ([`private_scalar`]), the SM2 nonce with
//! `TpmMath_GetRandomInRange()` ([`random_in_range`]), and the retry loops of
//! `TpmEcc_SignEcdsa()`, `TpmEcc_SignEcSm2()` and `TpmEcc_SignEcSchnorr()`. A TPM whose RNG draws
//! the reference's DRBG output therefore produces the reference's keys and signatures (the
//! point multiplications and the modular arithmetic are deterministic).

use tpm2::TpmEccCurve;
use tpm2::TpmiAlgHash;
use tpm2::crypto::{Crypto, CryptoError, EccPrivateKey, EccPublicKey, Rng};

use crate::self_test::Tested;

use crate::ecc_curves::{CurveParams, curve_params, point_add};
use crate::modular::{add_mod, inv_mod, is_zero, mul_mod, reduce, sub_mod};
use crate::modular::{ecc_scalar_from_extra_bits, inv_mod_prime, reference_mask_bits};

/// Largest coordinate/scalar size of the registered curves (BN P-638).
const MAX: usize = 80;
/// Largest digest size.
const MAX_DIGEST: usize = TpmiAlgHash::MAX_DIGEST_BYTES;
/// The nonce tries of `TpmEcc_SignEcdsa()` (`tries`): a nonce whose `[k]G` fails, whose `r` is
/// zero or that has no inverse uses up a try; the tries are shared by the retries for `s = 0`.
const ECDSA_TRIES: usize = 10;
/// A bound on the loops that the reference repeats until they succeed (`TpmEcc_SignEcSm2()`,
/// `TpmEcc_SignEcSchnorr()`, `TpmMath_GetRandomInRange()` and the `s = 0` retries of
/// `TpmEcc_SignEcdsa()`), so that a broken RNG cannot hang the TPM: each retry has a negligible
/// probability with any RNG that is not stuck, so the draws are the reference's.
const MAX_ATTEMPTS: usize = 100;
/// The bound of the draws of [`random_in_range`] (the reference draws until a value is in range;
/// for NIST P-521 only one in 128 is, see [`random_in_range`]).
const MAX_RANGE_ATTEMPTS: usize = 100_000;

/// A big-endian scalar or coordinate of at most [`MAX`] bytes.
#[derive(Clone, Copy)]
pub(crate) struct Num {
    buf: [u8; MAX],
    len: usize,
}

impl Num {
    /// A zero of `len` bytes.
    fn zero(len: usize) -> Self {
        Self { buf: [0; MAX], len }
    }

    /// `value` (big-endian, any number of leading zero bytes) reduced modulo `m`, `m.len()` bytes.
    fn reduced(value: &[u8], m: &[u8]) -> Self {
        let mut n = Self::zero(m.len());
        reduce(value, m, n.as_mut());
        n
    }

    /// `value` left-padded to `len` bytes, or `None` if its significant bytes do not fit.
    fn padded(value: &[u8], len: usize) -> Option<Self> {
        let skip = value.iter().take_while(|&&b| b == 0).count();
        let value = &value[skip..];
        if value.len() > len {
            return None;
        }
        let mut n = Self::zero(len);
        n.buf[len - value.len()..len].copy_from_slice(value);
        Some(n)
    }

    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// The big-endian value (of its full length).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }

    fn is_zero(&self) -> bool {
        is_zero(self.as_ref())
    }
}

/// `(a + b) mod m`.
fn add(a: &Num, b: &Num, m: &[u8]) -> Num {
    let mut out = Num::zero(m.len());
    add_mod(a.as_ref(), b.as_ref(), m, out.as_mut());
    out
}

/// `(a - b) mod m`.
fn sub(a: &Num, b: &Num, m: &[u8]) -> Num {
    let mut out = Num::zero(m.len());
    sub_mod(a.as_ref(), b.as_ref(), m, out.as_mut());
    out
}

/// `(a * b) mod m`.
fn mul(a: &Num, b: &Num, m: &[u8]) -> Num {
    let mut out = Num::zero(m.len());
    mul_mod(a.as_ref(), b.as_ref(), m, out.as_mut());
    out
}

/// `a^-1 mod n` for a public `a` (fast, not constant time), or `None` if `a` is zero.
fn inv_public(a: &Num, n: &[u8]) -> Option<Num> {
    let mut out = Num::zero(n.len());
    inv_mod(a.as_ref(), n, out.as_mut()).then_some(out)
}

/// `a^-1 mod n` for a secret `a` and the prime group order `n` (constant time), or `None` if `a`
/// is zero.
fn inv_secret(a: &Num, n: &[u8]) -> Option<Num> {
    let mut out = Num::zero(n.len());
    inv_mod_prime(a.as_ref(), n, out.as_mut()).then_some(out)
}

/// The domain parameters of `curve`, or `Err(Unsupported)` for a curve this build does not
/// implement.
fn params(curve: TpmEccCurve) -> Result<&'static CurveParams, CryptoError> {
    curve_params(curve).ok_or(CryptoError::Unsupported)
}

/// Splits the signature `r || s` buffer `out` into its halves of `n_len` bytes, or fails with
/// `Internal` (a programming error) if it is too small.
fn split_out(out: &mut [u8], n_len: usize) -> Result<(&mut [u8], &mut [u8]), CryptoError> {
    let out = out.get_mut(..2 * n_len).ok_or(CryptoError::Internal)?;
    Ok(out.split_at_mut(n_len))
}

/// `[u1]G + [u2]Q` on curve `c` (`q` is `x || y`), skipping a term whose scalar is zero. The
/// scalars are reduced modulo `n`. Returns `x || y` in `out` (`2 * c.coordinate_size()` bytes),
/// or `Ok(None)` for the point at infinity or an invalid `q`.
fn mul_add<C: Crypto>(
    curve: TpmEccCurve,
    c: &CurveParams,
    u1: &Num,
    u2: &Num,
    q: &[u8],
    out: &mut [u8; 2 * MAX],
) -> Result<Option<usize>, CryptoError> {
    let len = 2 * c.coordinate_size();
    let mut p1 = [0u8; 2 * MAX];
    let mut p2 = [0u8; 2 * MAX];
    let first = if u1.is_zero() {
        None
    } else {
        mul_generator::<C>(curve, u1.as_ref(), &mut p1)?
    };
    let second = if u2.is_zero() {
        None
    } else {
        match mul_point::<C>(curve, u2.as_ref(), q, &mut p2)? {
            Some(n) => Some(n),
            // An invalid public point (the product with a valid scalar is never infinity on a
            // prime-order curve).
            None => return Ok(None),
        }
    };
    match (first, second) {
        (Some(_), Some(_)) => Ok(point_add(c, &p1[..len], &p2[..len], out)),
        (Some(_), None) => {
            out[..len].copy_from_slice(&p1[..len]);
            Ok(Some(len))
        }
        (None, Some(_)) => {
            out[..len].copy_from_slice(&p2[..len]);
            Ok(Some(len))
        }
        (None, None) => Ok(None),
    }
}

/// `[k]G` on `curve` as `x || y` (each coordinate the curve size) in `out` (untested: no ECDH
/// self test). Returns the length, or `Ok(None)` if `k` is not in `[1, n - 1]`.
fn mul_generator<C: Crypto>(
    curve: TpmEccCurve,
    k: &[u8],
    out: &mut [u8; 2 * MAX],
) -> Result<Option<usize>, CryptoError> {
    let size = curve.key_bytes();
    let (x, y) = out.split_at_mut(size);
    Ok(tpm2::crypto::ecc_mul_generator::<C>(curve, k, x, &mut y[..size])?.map(|_| 2 * size))
}

/// `[k]P` on `curve` for the point `point` (`x || y`) as `x || y` in `out` (untested: no ECDH
/// self test). Returns the length, or `Ok(None)` if `point` is not a point of `curve`, `k` is not
/// in `[1, n - 1]` or the product is the point at infinity.
fn mul_point<C: Crypto>(
    curve: TpmEccCurve,
    k: &[u8],
    point: &[u8],
    out: &mut [u8; 2 * MAX],
) -> Result<Option<usize>, CryptoError> {
    let Some(public) = crate::ecc_curves::load_point::<C>(curve, point)? else {
        return Ok(None);
    };
    let size = curve.key_bytes();
    let (x, y) = out.split_at_mut(size);
    Ok(EccPublicKey::mul_point(&public, k, x, &mut y[..size])?.map(|_| 2 * size))
}

/// `TpmEcc_GenPrivateScalar()`: a private scalar `1 <= d < n` for the curve order `n`, with
/// the "extra random bits" method (FIPS 186-5, A.2.1): the octet size of `bitlen(n)` plus 8
/// octets drawn from `rng` (`TpmMath_GetRandomInteger()`, whose mask, [`reference_mask_bits`],
/// clears nothing of them for the registered curves), reduced modulo `n - 1`, plus 1. Used for
/// the private keys and ephemeral keys of every curve and for the ECDSA and EC-Schnorr nonces.
pub(crate) fn private_scalar(rng: &mut impl Rng, n: &[u8]) -> Result<Num, CryptoError> {
    let order_bytes = bit_len(n).div_ceil(8);
    let mut c = [0u8; MAX + 8];
    let c = &mut c[..order_bytes + 8];
    let drawn = rng.fill_bytes(c);
    reference_mask_bits(c, 8 * order_bytes + 64);
    let mut d = Num::zero(n.len());
    if drawn.is_ok() {
        ecc_scalar_from_extra_bits(c, n, d.as_mut());
    }
    c.fill(0);
    drawn.map(|()| d)
}

/// `TpmMath_GetRandomInRange()`: a value `1 <= k < n` drawn from `rng` as the octet size of
/// `bitlen(n)` with the reference's mask ([`reference_mask_bits`]: in the top 64-bit word only
/// the low `64 - bitlen(n) % 64` bits are kept), drawn again while it is zero or not below `n`.
/// Used for the SM2 nonce. As the mask clears nothing for NIST P-521, a 528-bit value is drawn
/// about 128 times on average until one is below `n`, as in the reference.
/// [`CryptoError::Internal`] for `n < 2`, or if [`MAX_RANGE_ATTEMPTS`] draws are out of range.
pub(crate) fn random_in_range(rng: &mut impl Rng, n: &[u8]) -> Result<Num, CryptoError> {
    let bits = bit_len(n);
    if bits < 2 {
        return Err(CryptoError::Internal);
    }
    let len = bits.div_ceil(8);
    let mut k = Num::zero(n.len());
    for _ in 0..MAX_RANGE_ATTEMPTS {
        let value = &mut k.buf[n.len() - len..n.len()];
        rng.fill_bytes(value)?;
        reference_mask_bits(value, bits);
        if !k.is_zero() && k.as_ref() < n {
            return Ok(k);
        }
    }
    Err(CryptoError::Internal)
}

/// `TpmEcc_GenerateKeyPair()` (the key of `CryptEccGenerateKey()` without its pairwise test, and
/// of `CryptEccNewKeyPair()`): a key pair on `curve` whose private scalar is
/// [`private_scalar`] (drawn from `rng`) and whose public point is computed by the backend.
/// [`CryptoError::Unsupported`] for a curve that this build or the backend does not implement.
pub(crate) fn generate_key<C: Crypto>(
    rng: &mut impl Rng,
    curve: TpmEccCurve,
) -> Result<EccPrivateKey<C>, CryptoError> {
    let d = private_scalar(rng, params(curve)?.n)?;
    let mut scalar = Num::zero(curve.key_bytes());
    let key = match Num::padded(d.as_ref(), scalar.len) {
        Some(padded) => {
            scalar = padded;
            EccPrivateKey::<C>::from_scalar(curve, scalar.as_ref())
        }
        None => Err(CryptoError::Internal),
    };
    scalar.as_mut().fill(0);
    // A scalar in `[1, n - 1]` always has a public point (`TPM_RC_NO_RESULT` in the reference).
    key?.ok_or(CryptoError::Internal)
}

/// The bit length of the big-endian `n`.
fn bit_len(n: &[u8]) -> usize {
    let skip = n.iter().take_while(|&&b| b == 0).count();
    match n.get(skip) {
        Some(&b) => (n.len() - skip) * 8 - b.leading_zeros() as usize,
        None => 0,
    }
}

/// The ECDSA integer `e` of `digest` for the order `n`, as the reference's
/// `TpmEcc_AdjustEcdsaDigest()` computes it: the first `min(digest.len(), ceil(bitlen(n) / 8))`
/// octets as an integer, shifted right by the bits it has beyond `bitlen(n)`, then reduced modulo
/// `n`. This is SEC 1's leftmost `bitlen(n)` bits (4.1.3 step 5) whenever the digest is longer
/// than the order or the order's size is a multiple of 8 bits (every case of the registered
/// curves and hashes); otherwise the shift depends on the leading zero bits of the value.
fn ecdsa_e(digest: &[u8], n: &[u8]) -> Num {
    let n_bits = bit_len(n);
    let mut value = Num::zero(MAX);
    let take = digest.len().min(n_bits.div_ceil(8));
    value.buf[MAX - take..].copy_from_slice(&digest[..take]);
    let shift = bit_len(&value.buf).saturating_sub(n_bits);
    for _ in 0..shift {
        let mut carry = 0u8;
        for b in value.buf.iter_mut() {
            let next = *b & 1;
            *b = (*b >> 1) | (carry << 7);
            carry = next;
        }
    }
    Num::reduced(&value.buf, n)
}

/// The x coordinate of `point` (`x || y` of curve `c`) reduced modulo the order `n`.
fn x_mod_n(c: &CurveParams, point: &[u8]) -> Num {
    Num::reduced(&point[..c.coordinate_size()], c.n)
}

/// Parses the signature components `r` and `s`, requiring `0 < r, s < n` (as every ECC scheme
/// of C `CryptEccValidateSignature()` does).
fn parse_rs(r: &[u8], s: &[u8], n: &[u8]) -> Option<(Num, Num)> {
    let r = Num::padded(r, n.len())?;
    let s = Num::padded(s, n.len())?;
    let in_range = |v: &Num| !v.is_zero() && v.as_ref() < n;
    (in_range(&r) && in_range(&s)).then_some((r, s))
}

/// Pads the public point `q` (`x || y` of the curve's coordinate size) or returns `None` if it
/// has the wrong size.
fn check_point<'q>(c: &CurveParams, q: &'q [u8]) -> Option<&'q [u8]> {
    (q.len() == 2 * c.coordinate_size()).then_some(q)
}

/// Signs `digest` with ECDSA (SEC 1, 4.1.3) on `curve` with the private scalar `d`, with the
/// nonces drawn from `rng` as `TpmEcc_SignEcdsa()` draws them: a nonce ([`private_scalar`]) whose
/// `[k]G` fails, whose `r` is zero or that has no inverse is replaced, at most [`ECDSA_TRIES`]
/// times in total, and a signature with `s = 0` starts over with the remaining tries. Writes
/// `r || s` to `out` and returns its length (twice the order size), or `Ok(None)` if `d` is not a
/// valid private key; [`CryptoError::Internal`] if the tries are used up.
pub(crate) fn ecdsa_sign<C: Crypto>(
    curve: TpmEccCurve,
    d: &[u8],
    digest: &[u8],
    rng: &mut impl Rng,
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let c = params(curve)?;
    let n = c.n;
    let n_len = n.len();
    let Some(d) = Num::padded(d, n_len).filter(|d| !d.is_zero() && d.as_ref() < n) else {
        return Ok(None);
    };
    let e_num = ecdsa_e(digest, n);
    let mut tries = ECDSA_TRIES;
    for _ in 0..MAX_ATTEMPTS {
        // Steps 1-3: a nonce k with r = x([k]G) mod n != 0 and an inverse of k.
        let mut nonce = None;
        while tries > 0 {
            let k = private_scalar(rng, n)?;
            let mut kg = [0u8; 2 * MAX];
            if mul_generator::<C>(curve, k.as_ref(), &mut kg)?.is_some() {
                let r = x_mod_n(c, &kg);
                if !r.is_zero()
                    && let Some(k_inv) = inv_secret(&k, n)
                {
                    nonce = Some((r, k_inv));
                    break;
                }
            }
            tries -= 1;
        }
        let Some((r, k_inv)) = nonce else {
            return Err(CryptoError::Internal);
        };
        // Step 6: s = k^-1 (e + r d) mod n, starting over if it is zero.
        let s = mul(&k_inv, &add(&e_num, &mul(&r, &d, n), n), n);
        if s.is_zero() {
            continue;
        }
        let (r_out, s_out) = split_out(out, n_len)?;
        r_out.copy_from_slice(r.as_ref());
        s_out.copy_from_slice(s.as_ref());
        return Ok(Some(2 * n_len));
    }
    Err(CryptoError::Internal)
}

/// Verifies the ECDSA signature `(r, s)` over `digest` with the public point `q` (`x || y`) on
/// `curve` (SEC 1, 4.1.4).
pub(crate) fn ecdsa_verify<C: Crypto>(
    curve: TpmEccCurve,
    q: &[u8],
    digest: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<bool, CryptoError> {
    let c = params(curve)?;
    let n = c.n;
    let (Some(q), Some((r, s))) = (check_point(c, q), parse_rs(r, s, n)) else {
        return Ok(false);
    };
    let Some(w) = inv_public(&s, n) else {
        return Ok(false);
    };
    let u1 = mul(&ecdsa_e(digest, n), &w, n);
    let u2 = mul(&r, &w, n);
    let mut x = [0u8; 2 * MAX];
    Ok(match mul_add::<C>(curve, c, &u1, &u2, q, &mut x)? {
        Some(_) => x_mod_n(c, &x).as_ref() == r.as_ref(),
        None => false,
    })
}

/// Signs the digest `e` with SM2 (TPM 2.0 Part 1, "SM2 Sign", steps 1-7; `e` is the hash of
/// `Z_A || M`, computed by the caller) on `curve` with the private scalar `d`, with the nonce
/// drawn from `rng` as `TpmEcc_SignEcSm2()` draws it ([`random_in_range`], drawn again when
/// `[k]G` fails, `r = 0` or `s = 0`). Writes `r || s` to `out` and returns its length, or
/// `Ok(None)` if `d` is not a valid private key (including `d = n - 1`, for which `1 + d` has no
/// inverse; the reference would retry forever).
///
/// Step 4 also retries when `r + k = n` (the specification's condition, which would make the
/// signature invalid). The reference's check compares `r + k` with a variable that is never set
/// to `n` and so never retries; the draws differ only in that case (probability about `1 / n`).
pub(crate) fn sm2_sign<C: Crypto>(
    curve: TpmEccCurve,
    d: &[u8],
    digest: &[u8],
    rng: &mut impl Rng,
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let c = params(curve)?;
    let n = c.n;
    let n_len = n.len();
    let Some(d) = Num::padded(d, n_len).filter(|d| !d.is_zero() && d.as_ref() < n) else {
        return Ok(None);
    };
    let mut one = Num::zero(n_len);
    one.buf[n_len - 1] = 1;
    let Some(t) = inv_secret(&add(&one, &d, n), n) else {
        return Ok(None);
    };
    let e_num = Num::reduced(digest, n);
    for _ in 0..MAX_ATTEMPTS {
        // 1. 1 <= k <= n - 1; 2. (x1, y1) := [k]G
        let k = random_in_range(rng, n)?;
        let mut kg = [0u8; 2 * MAX];
        if mul_generator::<C>(curve, k.as_ref(), &mut kg)?.is_none() {
            continue;
        }
        // 3. r := e + x1 (mod n); 4. retry if r = 0 or r + k = n
        let r = add(&e_num, &x_mod_n(c, &kg), n);
        if r.is_zero() || add(&r, &k, n).is_zero() {
            continue;
        }
        // 5. s := (1 + d)^-1 * (k - r * d) (mod n); 6. retry if s = 0
        let s = mul(&t, &sub(&k, &mul(&r, &d, n), n), n);
        if s.is_zero() {
            continue;
        }
        let (r_out, s_out) = split_out(out, n_len)?;
        r_out.copy_from_slice(r.as_ref());
        s_out.copy_from_slice(s.as_ref());
        return Ok(Some(2 * n_len));
    }
    Err(CryptoError::Internal)
}

/// Verifies the SM2 signature `(r, s)` over the digest `e` with the public point `q` on `curve`
/// (TPM 2.0 Part 1, "SM2 Signature Verification", steps 1-6).
pub(crate) fn sm2_verify<C: Crypto>(
    curve: TpmEccCurve,
    q: &[u8],
    digest: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<bool, CryptoError> {
    let c = params(curve)?;
    let n = c.n;
    // 1. r and s in [1, n - 1]
    let (Some(q), Some((r, s))) = (check_point(c, q), parse_rs(r, s, n)) else {
        return Ok(false);
    };
    // 2. t := (r + s) mod n; 3. t > 0
    let t = add(&r, &s, n);
    if t.is_zero() {
        return Ok(false);
    }
    // 4. (x, y) := [s]G + [t]Q
    let mut x = [0u8; 2 * MAX];
    if mul_add::<C>(curve, c, &s, &t, q, &mut x)?.is_none() {
        return Ok(false);
    }
    // 5. r' := (e + x) mod n; 6. r' = r
    let r_prime = add(&Num::reduced(digest, n), &x_mod_n(c, &x), n);
    Ok(r_prime.as_ref() == r.as_ref())
}

/// `TRUNC(H_hash(FE2BS(xE) || P), n)` of EC-Schnorr (TPM 2.0 Part 1, "EC Schnorr Sign" step 4):
/// the digest of the x coordinate of `point` (as many octets as the order `n`) and the digest
/// `p`, truncated from its less significant end to the octet size of `n`.
fn schnorr_r<C: Crypto>(
    h: &Tested<'_, C>,
    hash: TpmiAlgHash,
    c: &CurveParams,
    point: &[u8],
    p: &[u8],
) -> Result<Num, CryptoError> {
    let n_len = c.n.len();
    let coord = c.coordinate_size();
    // FE2BS: the field element with the octet size of n (equal to the coordinate size for every
    // registered curve; a wider field element keeps its least significant octets).
    let x = &point[..coord];
    let fe = if coord >= n_len {
        &x[coord - n_len..]
    } else {
        return Err(CryptoError::Internal);
    };
    let mut stream = h.hash_stream(hash)?;
    stream.update(fe)?;
    stream.update(p)?;
    let mut buf = [0u8; MAX_DIGEST];
    let digest = stream.finalize(&mut buf)?;
    let digest = digest.digest();
    let take = digest.len().min(n_len);
    let mut r = Num::zero(n_len);
    r.buf[n_len - take..n_len].copy_from_slice(&digest[..take]);
    Ok(r)
}

/// Signs the digest `p` with EC-Schnorr (TPM 2.0 Part 1, "EC Schnorr Sign") with the scheme hash
/// `hash` on `curve` with the private scalar `d`, with the nonce drawn from `rng` as
/// `TpmEcc_SignEcSchnorr()` draws it ([`private_scalar`], drawn again while `r mod n = 0` or
/// `s = 0`). Writes `r || s` to `out` (`r` is the truncated hash, padded to the order size) and
/// returns its length, or `Ok(None)` if `d` is not a valid private key.
pub(crate) fn schnorr_sign<C: Crypto>(
    h: &Tested<'_, C>,
    curve: TpmEccCurve,
    hash: TpmiAlgHash,
    d: &[u8],
    p: &[u8],
    rng: &mut impl Rng,
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let c = params(curve)?;
    let n = c.n;
    let n_len = n.len();
    let Some(d) = Num::padded(d, n_len).filter(|d| !d.is_zero() && d.as_ref() < n) else {
        return Ok(None);
    };
    for _ in 0..MAX_ATTEMPTS {
        // 1. 0 < k < n; 2. E := [k]G (3. never infinity for 0 < k < n; the reference gives up
        // with `TPM_RC_NO_RESULT` if the multiplication fails)
        let k = private_scalar(rng, n)?;
        let mut kg = [0u8; 2 * MAX];
        if mul_generator::<C>(curve, k.as_ref(), &mut kg)?.is_none() {
            return Err(CryptoError::Internal);
        }
        // 4. r := TRUNC(H(FE2BS(xE) || P), n)
        let r = schnorr_r(h, hash, c, &kg, p)?;
        let r_mod_n = Num::reduced(r.as_ref(), n);
        // 6. s = k (that is, r = 0 mod n) or s = 0: retry
        if r_mod_n.is_zero() {
            continue;
        }
        // 5. s := (k + r * d) (mod n)
        let s = add(&k, &mul(&r_mod_n, &d, n), n);
        if s.is_zero() {
            continue;
        }
        let (r_out, s_out) = split_out(out, n_len)?;
        r_out.copy_from_slice(r.as_ref());
        s_out.copy_from_slice(s.as_ref());
        return Ok(Some(2 * n_len));
    }
    Err(CryptoError::Internal)
}

/// Verifies the EC-Schnorr signature `(r, s)` over the digest `p` with the scheme hash `hash`
/// and the public point `q` on `curve` (TPM 2.0 Part 1, "EC Schnorr Signature Validate").
pub(crate) fn schnorr_verify<C: Crypto>(
    h: &Tested<'_, C>,
    curve: TpmEccCurve,
    hash: TpmiAlgHash,
    q: &[u8],
    p: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<bool, CryptoError> {
    let c = params(curve)?;
    let n = c.n;
    // 1. 0 < s < n (and 0 < r < n, as for every ECC scheme of the TPM)
    let (Some(q), Some((r, s))) = (check_point(c, q), parse_rs(r, s, n)) else {
        return Ok(false);
    };
    // 2. E := [s]G + [-r]Q
    let neg_r = sub(&Num::zero(n.len()), &r, n);
    let mut point = [0u8; 2 * MAX];
    if mul_add::<C>(curve, c, &s, &neg_r, q, &mut point)?.is_none() {
        return Ok(false);
    }
    // 3. r' := TRUNC(H(FE2BS(xE) || P), n); 4. r' = r (as numbers)
    let r_prime = schnorr_r(h, hash, c, &point, p)?;
    Ok(r_prime.as_ref() == r.as_ref())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::self_test::SelfTestState;
    use tpm2::crypto::{EccPrivateKey, Random as _, SignatureBuffer};
    use tpm2::{Alg, Tpm2bEccParameter, TpmsSignatureEcc, TpmtSigScheme, TpmtSignature};
    #[cfg(feature = "dev_crypto_bssl")]
    type Crypto = tpm2_crypto_bssl::BsslCryptoProvider;
    #[cfg(feature = "dev_crypto_crux")]
    use tpm2_crypto_crux::CruxCryptoProvider as Crypto;
    #[cfg(feature = "dev_crypto_rust")]
    use tpm2_crypto_rust::RustCryptoProvider as Crypto;

    /// The NIST P-256 key pair (`d`, `x || y`) of [`REFERENCE_SIGNATURES`].
    const REFERENCE_KEY: ([u8; 32], [u8; 64]) = (
        hex_literal::hex!("7409f4f9d086181e57e83eef7db68c7afe2cae4306df4d3a7cc2c3df5a913711"),
        hex_literal::hex!(
            "29bd3e4bbd95ba9ed516c859979bd6ae813d21804abb72f3782bbc989eb8cf81"
            "df3259ea1ebd7e6a928f07c7d4e9d535e51b667ccded46cb858385d53c1ba59b"
        ),
    );

    /// SM2 and EC-Schnorr signatures (`scheme`, `hash`, `r`, `s`) of the digest `[0x42; 64]`
    /// with [`REFERENCE_KEY`], made by the C reference's `CryptEccSign()`
    /// (`tpm2_platform_linux`'s `reference_rng::ecc` tests, `SIGNATURES`, which pin the C
    /// outputs).
    const REFERENCE_SIGNATURES: &[(Alg, TpmiAlgHash, [u8; 32], [u8; 32])] = &[
        (
            Alg::SM2,
            TpmiAlgHash::Sha1,
            hex_literal::hex!("b2c94d386bae95d62ff012c60bb53fa2650690c822d6f19597994b8d15e9aae6"),
            hex_literal::hex!("ae214303b08df066b1ce7dd5f3507e05b3131a6ae1df6d79527e2fa7062206e1"),
        ),
        (
            Alg::ECSCHNORR,
            TpmiAlgHash::Sha1,
            hex_literal::hex!("00000000000000000000000098beba31e5ba04b06a1ba541a09ee0c390c03ec7"),
            hex_literal::hex!("601dbeb2cbc7d2986c2a555b7335ea477614ccb85b3719117f5723c8e52e511e"),
        ),
        (
            Alg::SM2,
            TpmiAlgHash::Sha256,
            hex_literal::hex!("9642bded8063262d15f80250158991982f4b5c4d0c7f4fe2cc8050e68bb463cd"),
            hex_literal::hex!("4f54f067f499ec0383bbc777238c619526381465c31244696cde5a1207ec0b74"),
        ),
        (
            Alg::ECSCHNORR,
            TpmiAlgHash::Sha256,
            hex_literal::hex!("32a2750b3aaac1413aef03586fd10d10faeb6497bdcec3172099133d6b6bc4d1"),
            hex_literal::hex!("62e2f2026ba486f5711abc8ed04e57eff4cfef274e0d9f613a31f08a9e221f6c"),
        ),
        (
            Alg::SM2,
            TpmiAlgHash::Sha384,
            hex_literal::hex!("25b5683b68a37b8f593877c781053446277cf9f3a99859053c4edbedfd6af7da"),
            hex_literal::hex!("894879cd1e8acf76bedcca274b2b8cc15ddd190b27d4047d9dd18eb5fee1ee58"),
        ),
        (
            Alg::ECSCHNORR,
            TpmiAlgHash::Sha384,
            hex_literal::hex!("909f41eb10bc83a75db25a10bef36eab9ced75cdec2520db540e69420249e3a4"),
            hex_literal::hex!("6d17a47a8f4251c5b44cd95f251ba73c882ba90f53ce486f7b300b1572c97251"),
        ),
        #[cfg(feature = "sha512")]
        (
            Alg::SM2,
            TpmiAlgHash::Sha512,
            hex_literal::hex!("bbfbbbff69f919fc98a1dd0e0e37563bdb07adae6f69e86ed925e8bcaae6c9b6"),
            hex_literal::hex!("dcc7d5b0b9d337414b9bf08c4d32004a908f152d27cff2488071d3fa3974ad71"),
        ),
        #[cfg(feature = "sha512")]
        (
            Alg::ECSCHNORR,
            TpmiAlgHash::Sha512,
            hex_literal::hex!("4a54c215d3c75be6bf9bf960c75eb8dc9e8f1a135c72d6e27261ee6b9da7cb82"),
            hex_literal::hex!("36244a8c64aaec6944035e94b6eaa4a96ed5404663cdcd12e7213933f816ef8f"),
        ),
    ];

    /// SM2 and EC-Schnorr signatures of the C reference's `CryptEccSign()` verify with the
    /// engine's own verification, for every implemented hash.
    #[test]
    fn reference_sm2_and_schnorr_signatures_verify() {
        let state = SelfTestState::default();
        let tested = Tested::<Crypto>::new(&state);
        let (_, q) = REFERENCE_KEY;
        let digest = [0x42u8; 64];
        for &(scheme, hash, r, s) in REFERENCE_SIGNATURES {
            let verified = if scheme == Alg::SM2 {
                sm2_verify::<Crypto>(TpmEccCurve::NistP256, &q, &digest, &r, &s)
            } else {
                schnorr_verify(&tested, TpmEccCurve::NistP256, hash, &q, &digest, &r, &s)
            };
            assert_eq!(verified, Ok(true), "{scheme:?} {hash:?}");
        }
    }

    /// Every curve of the build.
    const CURVES: &[TpmEccCurve] = &[
        #[cfg(feature = "nist_p192")]
        TpmEccCurve::NistP192,
        TpmEccCurve::NistP224,
        TpmEccCurve::NistP256,
        TpmEccCurve::NistP384,
        TpmEccCurve::NistP521,
        TpmEccCurve::BNP256,
        #[cfg(feature = "bn_p638")]
        TpmEccCurve::BNP638,
        #[cfg(feature = "sm2_p256")]
        TpmEccCurve::SM2P256,
    ];

    /// A key pair on `curve`: `(d, q, len)` with `d` the coordinate size and `q` twice that, or
    /// `None` if the backend cannot generate keys on `curve` (e.g. Crux without NIST P-224).
    fn key_pair(curve: TpmEccCurve) -> Option<([u8; MAX], [u8; 2 * MAX], usize)> {
        let mut rng = Crypto::from_entropy().unwrap();
        let key = match EccPrivateKey::<Crypto>::generate(&mut rng, curve, None) {
            Ok(key) => key,
            Err(CryptoError::Unsupported) => return None,
            Err(e) => panic!("{curve:?}: key generation: {e:?}"),
        };
        let len = curve.key_bytes();
        let (mut d, mut q) = ([0u8; MAX], [0u8; 2 * MAX]);
        assert_eq!(key.scalar(&mut d).unwrap().as_slice().len(), len);
        let (x, y) = q.split_at_mut(len);
        let point = key.point(x, &mut y[..len]).unwrap();
        assert_eq!(
            (point.x.as_slice().len(), point.y.as_slice().len()),
            (len, len)
        );
        Some((d, q, len))
    }

    /// A nonce source: a new random number generator of the backend.
    fn nonce() -> <Crypto as tpm2::crypto::Random>::Rng {
        Crypto::from_entropy().unwrap()
    }

    /// A [`Tested`] backend that runs no self test.
    fn tested(state: &SelfTestState) -> Tested<'_, Crypto> {
        Tested::new(state)
    }

    /// Signs and verifies with every scheme on every curve, and rejects a different digest, a
    /// modified signature, out-of-range components and another key.
    #[test]
    fn sign_and_verify_on_every_curve() {
        let state = SelfTestState::default();
        let t = tested(&state);
        let hash = TpmiAlgHash::Sha256;
        let digest = [0x5a; 32];
        let other = [0xa5; 32];
        for &curve in CURVES {
            let Some((d, q, len)) = key_pair(curve) else {
                continue;
            };
            let (d, q) = (&d[..len], &q[..2 * len]);
            let (_, q2, _) = key_pair(curve).unwrap();
            let q2 = &q2[..2 * len];
            let n = curve_params(curve).unwrap().n;
            for scheme in ["ecdsa", "sm2", "schnorr"] {
                let mut sig = [0u8; 2 * MAX];
                let signed = match scheme {
                    "ecdsa" => ecdsa_sign::<Crypto>(curve, d, &digest, &mut nonce(), &mut sig),
                    "sm2" => sm2_sign::<Crypto>(curve, d, &digest, &mut nonce(), &mut sig),
                    _ => schnorr_sign(&t, curve, hash, d, &digest, &mut nonce(), &mut sig),
                };
                assert_eq!(signed, Ok(Some(2 * len)), "{curve:?} {scheme}");
                let verify = |q: &[u8], digest: &[u8], r: &[u8], s: &[u8]| {
                    match scheme {
                        "ecdsa" => ecdsa_verify::<Crypto>(curve, q, digest, r, s),
                        "sm2" => sm2_verify::<Crypto>(curve, q, digest, r, s),
                        _ => schnorr_verify(&t, curve, hash, q, digest, r, s),
                    }
                    .unwrap()
                };
                let (r, s) = sig[..2 * len].split_at(len);
                assert!(verify(q, &digest, r, s), "{curve:?} {scheme}");
                assert!(!verify(q, &other, r, s), "{curve:?} {scheme}: other digest");
                assert!(!verify(q2, &digest, r, s), "{curve:?} {scheme}: other key");
                let mut bad_s = [0u8; MAX];
                bad_s[..len].copy_from_slice(s);
                bad_s[len - 1] ^= 1;
                assert!(
                    !verify(q, &digest, r, &bad_s[..len]),
                    "{curve:?} {scheme}: bad s"
                );
                assert!(!verify(q, &digest, r, &[0]), "{curve:?} {scheme}: s = 0");
                assert!(!verify(q, &digest, n, s), "{curve:?} {scheme}: r = n");
                assert!(
                    !verify(&q[1..], &digest, r, s),
                    "{curve:?} {scheme}: short point"
                );
            }
        }
    }

    /// The generic ECDSA agrees with the backend's on the NIST curves (in both directions).
    #[test]
    fn ecdsa_matches_the_backend() {
        let digest = [0x11; 48];
        let mut rng = Crypto::from_entropy().unwrap();
        for curve in [
            TpmEccCurve::NistP224,
            TpmEccCurve::NistP256,
            TpmEccCurve::NistP384,
            TpmEccCurve::NistP521,
        ] {
            let Some((d, q, len)) = key_pair(curve) else {
                continue;
            };
            let (d, q) = (&d[..len], &q[..2 * len]);
            let Some(public) = crate::ecc_curves::load_point::<Crypto>(curve, q).unwrap() else {
                panic!("{curve:?}: generated point rejected");
            };
            let private = EccPrivateKey::load(public, Tpm2bEccParameter::new(d).unwrap()).unwrap();
            let private = private.unwrap_or_else(|| panic!("{curve:?}: generated key rejected"));
            let scheme = TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha384);
            let mut buf = [0u8; core::mem::size_of::<SignatureBuffer>()];
            let (r, s) = match private.sign(&mut rng, scheme, &digest, &mut buf) {
                Ok(TpmtSignature::Ecdsa(TpmsSignatureEcc {
                    signature_r,
                    signature_s,
                    ..
                })) => (signature_r, signature_s),
                // A backend without ECDSA on this curve.
                Err(CryptoError::Unsupported) => continue,
                other => panic!("{curve:?}: {other:?}"),
            };
            assert!(
                ecdsa_verify::<Crypto>(curve, q, &digest, r.as_slice(), s.as_slice()).unwrap(),
                "{curve:?}"
            );
            let mut sig = [0u8; 2 * MAX];
            ecdsa_sign::<Crypto>(curve, d, &digest, &mut nonce(), &mut sig).unwrap();
            let (r, s) = sig[..2 * len].split_at(len);
            let signature = TpmtSignature::Ecdsa(TpmsSignatureEcc {
                hash: TpmiAlgHash::Sha384,
                signature_r: Tpm2bEccParameter::new(r).unwrap(),
                signature_s: Tpm2bEccParameter::new(s).unwrap(),
            });
            let public = crate::ecc_curves::load_point::<Crypto>(curve, q)
                .unwrap()
                .unwrap();
            assert!(public.verify(&digest, signature).unwrap(), "{curve:?}");
        }
    }

    /// The reference's EC-Schnorr known-answer signatures (`c_TestEcSchnorr_r`/`_s` of
    /// `EccTestData.h`, NIST P-256 test key, the 64-byte test value as the digest) verify.
    #[test]
    fn schnorr_known_answer_signatures_verify() {
        use crate::self_test::vectors::*;
        let state = SelfTestState::default();
        let t = tested(&state);
        let mut q = [0u8; 64];
        q[..32].copy_from_slice(&EC_TEST_KEY_QS_X);
        q[32..].copy_from_slice(&EC_TEST_KEY_QS_Y);
        let r384 =
            hex_literal::hex!("1eb8e1bfa19e391e58a2e659d01a6a036a1f1c4f3619c1ec30a4851be9743566");
        let s384 =
            hex_literal::hex!("b9e6e37ecbb9eaf1ccf448444adac8d787b4ba40fe5b681114cfa00e85469901");
        let r512 =
            hex_literal::hex!("cc07ad6591dda01023ae53ecdff150901696f44509739c84b55c5f0851cb6001");
        let s512 =
            hex_literal::hex!("55202154e249074771f4991554f3ab14db8eda79b6020ee35e6f2cb605bd1410");
        let curve = TpmEccCurve::NistP256;
        let verify = |hash, r: &[u8], s: &[u8]| {
            schnorr_verify(&t, curve, hash, &q, &EC_TEST_VALUE, r, s).unwrap()
        };
        assert!(verify(TpmiAlgHash::Sha384, &r384, &s384));
        assert!(!verify(TpmiAlgHash::Sha256, &r384, &s384));
        if let Some(sha512) = crate::handler::capability::sha512() {
            assert!(verify(sha512, &r512, &s512));
        }
    }

    /// The leftmost-bits truncation of ECDSA: a digest longer than the order keeps its leftmost
    /// `bitlen(n)` bits.
    #[test]
    fn ecdsa_truncates_long_digests() {
        // n = 0x0101 (9 bits): the 16-bit digest 0xFFFF becomes 0x1FF mod 0x101 = 0xFE.
        assert_eq!(
            ecdsa_e(&[0xff, 0xff], &[0x01, 0x01]).as_ref(),
            &[0x00, 0xfe]
        );
        // 0x0105 has only 9 significant bits, so the reference keeps it whole (0x105 mod 0x101):
        // its shift depends on the value's bit length, not on the digest's size.
        assert_eq!(
            ecdsa_e(&[0x01, 0x05], &[0x01, 0x01]).as_ref(),
            &[0x00, 0x04]
        );
        // A digest longer than the order's octet size keeps its first octets.
        assert_eq!(
            ecdsa_e(&[0x00, 0x05, 0xff], &[0x01, 0x01]).as_ref(),
            &[0x00, 0x05]
        );
        // A digest with no more bits than the order is only reduced.
        assert_eq!(ecdsa_e(&[0xff], &[0x01, 0x01]).as_ref(), &[0x00, 0xff]);
        assert_eq!(bit_len(&[0x00, 0x01, 0x00]), 9);
        assert_eq!(bit_len(&[0x00]), 0);
    }

    /// Invalid private keys (zero, not below n) are `Ok(None)`.
    #[test]
    fn invalid_private_keys_are_rejected() {
        let state = SelfTestState::default();
        let t = tested(&state);
        let curve = TpmEccCurve::NistP256;
        let n = curve_params(curve).unwrap().n;
        let mut sig = [0u8; 2 * MAX];
        for d in [&[0u8; 32][..], n] {
            assert_eq!(
                ecdsa_sign::<Crypto>(curve, d, &[1; 32], &mut nonce(), &mut sig),
                Ok(None)
            );
            assert_eq!(
                sm2_sign::<Crypto>(curve, d, &[1; 32], &mut nonce(), &mut sig),
                Ok(None)
            );
            assert_eq!(
                schnorr_sign(
                    &t,
                    curve,
                    TpmiAlgHash::Sha256,
                    d,
                    &[1; 32],
                    &mut nonce(),
                    &mut sig
                ),
                Ok(None)
            );
        }
        // SM2 also rejects d = n - 1 (1 + d has no inverse modulo n).
        let mut d = [0u8; 32];
        d.copy_from_slice(n);
        d[31] -= 1;
        assert_eq!(
            sm2_sign::<Crypto>(curve, &d, &[1; 32], &mut nonce(), &mut sig),
            Ok(None)
        );
    }
}
