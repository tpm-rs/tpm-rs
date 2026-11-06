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
//! The signing functions take the random nonce source as a closure (`nonce`) that fills its
//! argument with random bytes, so that the TPM can draw from its DRBG.

use tpm2::TpmEccCurve;
use tpm2::TpmiAlgHash;
use tpm2::crypto::{Crypto, CryptoError, EccPublicKey};

use crate::self_test::Tested;

use crate::ecc_curves::{CurveParams, curve_params, point_add};
use crate::modular::{add_mod, inv_mod, is_zero, mul_mod, reduce, sub_mod};
#[cfg(any(test, not(feature = "reference-rng")))]
use crate::modular::{ecc_scalar_from_extra_bits, inv_mod_prime};

/// Largest coordinate/scalar size of the registered curves (BN P-638).
const MAX: usize = 80;
/// Largest digest size.
const MAX_DIGEST: usize = TpmiAlgHash::MAX_DIGEST_BYTES;
/// Retries of a signing loop before giving up (each retry has a negligible probability).
#[cfg(any(test, not(feature = "reference-rng")))]
const MAX_ATTEMPTS: usize = 100;

/// A big-endian scalar or coordinate of at most [`MAX`] bytes.
#[derive(Clone, Copy)]
struct Num {
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
#[cfg(any(test, not(feature = "reference-rng")))]
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
#[cfg(any(test, not(feature = "reference-rng")))]
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

/// Draws a scalar `1 <= k < n` with the "extra random bits" method (FIPS 186-5 A.2.1, C
/// `TpmEcc_GenPrivateScalar()`) from `nonce`.
#[cfg(any(test, not(feature = "reference-rng")))]
fn random_scalar(
    n: &[u8],
    nonce: &mut impl FnMut(&mut [u8]) -> Result<(), CryptoError>,
) -> Result<Num, CryptoError> {
    let mut c = [0u8; MAX + 8];
    nonce(&mut c[..n.len() + 8])?;
    let mut k = Num::zero(n.len());
    ecc_scalar_from_extra_bits(&c[..n.len() + 8], n, k.as_mut());
    Ok(k)
}

/// The bit length of the big-endian `n`.
fn bit_len(n: &[u8]) -> usize {
    let skip = n.iter().take_while(|&&b| b == 0).count();
    match n.get(skip) {
        Some(&b) => (n.len() - skip) * 8 - b.leading_zeros() as usize,
        None => 0,
    }
}

/// The ECDSA integer `e` of `digest` for the order `n` (SEC 1, 4.1.3 step 5): the leftmost
/// `bitlen(n)` bits of the digest, reduced modulo `n`.
fn ecdsa_e(digest: &[u8], n: &[u8]) -> Num {
    let n_bits = bit_len(n);
    let mut buf = [0u8; MAX_DIGEST];
    let digest = &digest[..digest.len().min(MAX_DIGEST)];
    let mut len = digest.len();
    buf[..len].copy_from_slice(digest);
    if len * 8 > n_bits {
        len = n_bits.div_ceil(8);
        let shift = len * 8 - n_bits;
        if shift > 0 {
            // Shift the first `len` bytes right by `shift` bits.
            for i in (0..len).rev() {
                let hi = if i > 0 { buf[i - 1] } else { 0 };
                buf[i] = (buf[i] >> shift) | (hi << (8 - shift));
            }
        }
    }
    Num::reduced(&buf[..len], n)
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

/// Signs `digest` with ECDSA (SEC 1, 4.1.3) on `curve` with the private scalar `d`. Writes
/// `r || s` to `out` and returns its length (twice the order size), or `Ok(None)` if `d` is not
/// a valid private key.
#[cfg(any(test, not(feature = "reference-rng")))]
pub(crate) fn ecdsa_sign<C: Crypto>(
    curve: TpmEccCurve,
    d: &[u8],
    digest: &[u8],
    mut nonce: impl FnMut(&mut [u8]) -> Result<(), CryptoError>,
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let c = params(curve)?;
    let n = c.n;
    let n_len = n.len();
    let Some(d) = Num::padded(d, n_len).filter(|d| !d.is_zero() && d.as_ref() < n) else {
        return Ok(None);
    };
    let e_num = ecdsa_e(digest, n);
    for _ in 0..MAX_ATTEMPTS {
        let k = random_scalar(n, &mut nonce)?;
        let mut kg = [0u8; 2 * MAX];
        if mul_generator::<C>(curve, k.as_ref(), &mut kg)?.is_none() {
            continue;
        }
        let r = x_mod_n(c, &kg);
        if r.is_zero() {
            continue;
        }
        let Some(k_inv) = inv_secret(&k, n) else {
            continue;
        };
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
/// `Z_A || M`, computed by the caller) on `curve` with the private scalar `d`. Writes `r || s`
/// to `out` and returns its length, or `Ok(None)` if `d` is not a valid private key (including
/// `d = n - 1`, for which `1 + d` has no inverse).
#[cfg(any(test, not(feature = "reference-rng")))]
pub(crate) fn sm2_sign<C: Crypto>(
    curve: TpmEccCurve,
    d: &[u8],
    digest: &[u8],
    mut nonce: impl FnMut(&mut [u8]) -> Result<(), CryptoError>,
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
        let k = random_scalar(n, &mut nonce)?;
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
/// `hash` on `curve` with the private scalar `d`. Writes `r || s` to `out` (`r` is the truncated
/// hash, padded to the order size) and returns its length, or `Ok(None)` if `d` is not a valid
/// private key.
#[cfg(any(test, not(feature = "reference-rng")))]
pub(crate) fn schnorr_sign<C: Crypto>(
    h: &Tested<'_, C>,
    curve: TpmEccCurve,
    hash: TpmiAlgHash,
    d: &[u8],
    p: &[u8],
    mut nonce: impl FnMut(&mut [u8]) -> Result<(), CryptoError>,
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let c = params(curve)?;
    let n = c.n;
    let n_len = n.len();
    let Some(d) = Num::padded(d, n_len).filter(|d| !d.is_zero() && d.as_ref() < n) else {
        return Ok(None);
    };
    for _ in 0..MAX_ATTEMPTS {
        // 1. 0 < k < n; 2. E := [k]G (3. never infinity for 0 < k < n)
        let k = random_scalar(n, &mut nonce)?;
        let mut kg = [0u8; 2 * MAX];
        if mul_generator::<C>(curve, k.as_ref(), &mut kg)?.is_none() {
            continue;
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
    use tpm2::crypto::{EccPrivateKey, Random as _, Rng as _, SignatureBuffer};
    use tpm2::{Tpm2bEccParameter, TpmsSignatureEcc, TpmtSigScheme, TpmtSignature};
    #[cfg(feature = "dev_crypto_bssl")]
    use tpm2_crypto_bssl::BsslCryptoProvider as Crypto;
    #[cfg(feature = "dev_crypto_crux")]
    use tpm2_crypto_crux::CruxCryptoProvider as Crypto;
    #[cfg(feature = "dev_crypto_rust")]
    use tpm2_crypto_rust::RustCryptoProvider as Crypto;

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

    /// A nonce source from the backend's random number generator.
    fn nonce() -> impl FnMut(&mut [u8]) -> Result<(), CryptoError> {
        let mut rng = Crypto::from_entropy().unwrap();
        move |buf| rng.fill_bytes(buf)
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
                    "ecdsa" => ecdsa_sign::<Crypto>(curve, d, &digest, nonce(), &mut sig),
                    "sm2" => sm2_sign::<Crypto>(curve, d, &digest, nonce(), &mut sig),
                    _ => schnorr_sign(&t, curve, hash, d, &digest, nonce(), &mut sig),
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
            ecdsa_sign::<Crypto>(curve, d, &digest, nonce(), &mut sig).unwrap();
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
        // 0x0105 keeps its leftmost 9 bits: 0x002.
        assert_eq!(
            ecdsa_e(&[0x01, 0x05], &[0x01, 0x01]).as_ref(),
            &[0x00, 0x02]
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
                ecdsa_sign::<Crypto>(curve, d, &[1; 32], nonce(), &mut sig),
                Ok(None)
            );
            assert_eq!(
                sm2_sign::<Crypto>(curve, d, &[1; 32], nonce(), &mut sig),
                Ok(None)
            );
            assert_eq!(
                schnorr_sign(
                    &t,
                    curve,
                    TpmiAlgHash::Sha256,
                    d,
                    &[1; 32],
                    nonce(),
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
            sm2_sign::<Crypto>(curve, &d, &[1; 32], nonce(), &mut sig),
            Ok(None)
        );
    }
}
