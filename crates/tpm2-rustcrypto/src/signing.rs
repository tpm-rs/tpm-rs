//! [`Signing`] with RSA and ECC keys.

use ::rsa::{BigUint, Pkcs1v15Sign, hazmat::rsa_encrypt, traits::PublicKeyParts};
use ecdsa::{
    Signature, SignatureSize,
    hazmat::{sign_prehashed, verify_prehashed},
};
use elliptic_curve::{
    FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar,
    ff::Field as _,
    generic_array::ArrayLength,
    group::{Curve as _, Group as _},
    ops::{LinearCombination as _, MulByGenerator as _, Reduce},
    point::AffineCoordinates as _,
};
use tpm2::{
    Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmEccCurve, TpmiAlgHash, TpmiRsaKeyBits, TpmtHa,
    crypto::{CryptoError, EccSigScheme, Rng, RsaSigScheme, Signing, pre_hash_oid},
};

use crate::{
    ChaChaRng, EccPrivateKey, EccPublicKey, RsaPrivateKey, RsaPublicKey, RustCrypto,
    ecc::{EcCurve, EccPoint, EccScalar, dispatch, int_to_field, parse_scalar, write_param},
    hash::hash_concat,
    rsa::{mgf1_xor, prefix, private_op, to_tpm2b, write_be},
};

/// The maximum number of nonces to try when generating an ECC signature.
///
/// Each attempt only fails with negligible probability, so reaching this
/// limit indicates a broken RNG.
const MAX_SIGN_ATTEMPTS: usize = 32;

/// An ECC signature `(r, s)`, as big-endian integers the size of the field.
type RawSignature<C> = (FieldBytes<C>, FieldBytes<C>);

impl Signing for RustCrypto {
    fn rsa_sign<'a>(
        &self,
        rng: &mut ChaChaRng,
        key: &RsaPrivateKey,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        let sig = prefix(out, key.public.size())?;
        match scheme {
            RsaSigScheme::Rsassa => {
                let scheme = pkcs1v15_sign(digest.hash_alg())?;
                let s = key
                    .key
                    .sign_with_rng(&mut rng.0, scheme, digest.digest())
                    .map_err(|_| CryptoError::Internal)?;
                if s.len() != sig.len() {
                    return Err(CryptoError::Internal);
                }
                sig.copy_from_slice(&s);
            }
            RsaSigScheme::Rsapss => {
                pss_encode(rng, digest, sig)?;
                let s = private_op(&key.key, rng, &BigUint::from_bytes_be(sig))?;
                write_be(&s, sig)?;
            }
        }
        to_tpm2b(sig)
    }

    fn rsa_verify(
        &self,
        key: &RsaPublicKey,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        sig: &[u8],
    ) -> Result<bool, CryptoError> {
        // The signature must be the size of the modulus.
        if sig.len() != key.size() {
            return Ok(false);
        }
        match scheme {
            RsaSigScheme::Rsassa => {
                let scheme = pkcs1v15_sign(digest.hash_alg())?;
                match key.key.verify(scheme, digest.digest(), sig) {
                    Ok(()) => Ok(true),
                    Err(::rsa::Error::Verification) => Ok(false),
                    Err(_) => Err(CryptoError::Internal),
                }
            }
            RsaSigScheme::Rsapss => {
                // RSAVP1: the signature representative must be less than the modulus.
                let s = BigUint::from_bytes_be(sig);
                if &s >= key.key.n() {
                    return Ok(false);
                }
                let m = rsa_encrypt(&key.key, &s).map_err(|_| CryptoError::Internal)?;
                let mut em = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
                let em = prefix(&mut em, sig.len())?;
                write_be(&m, em)?;
                pss_verify(digest, em)
            }
        }
    }

    fn ecc_sign<'a>(
        &self,
        rng: &mut ChaChaRng,
        key: &EccPrivateKey,
        scheme: EccSigScheme,
        digest: TpmtHa<'_>,
        out_r: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_s: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<(Tpm2bEccParameter<'a>, Tpm2bEccParameter<'a>), CryptoError> {
        let scheme = Scheme::new(scheme)?;
        dispatch!(EccScalar, &key.secret, d => ecc_sign_impl(rng, d, scheme, digest, out_r, out_s))
    }

    fn ecc_verify(
        &self,
        key: &EccPublicKey,
        scheme: EccSigScheme,
        digest: TpmtHa<'_>,
        sig_r: &[u8],
        sig_s: &[u8],
    ) -> Result<bool, CryptoError> {
        let scheme = Scheme::new(scheme)?;
        dispatch!(EccPoint, &key.0, q => ecc_verify_impl(q, scheme, digest, sig_r, sig_s))
    }
}

/// Returns the RSASSA-PKCS1-v1_5 scheme for `hash`, with the DER encoding of
/// its `DigestInfo` prefix (RFC 8017, Section 9.2).
fn pkcs1v15_sign(hash: TpmiAlgHash) -> Result<Pkcs1v15Sign, CryptoError> {
    // All lengths are less than 0x80, so they use the short form.
    let len = |n: usize| {
        u8::try_from(n)
            .ok()
            .filter(|&n| n < 0x80)
            .ok_or(CryptoError::Internal)
    };
    let oid = pre_hash_oid(hash);
    let h = hash.digest_size();
    // DigestInfo ::= SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING }
    let prefix = [
        &[0x30, len(oid.len() + h + 6)?, 0x30, len(oid.len() + 2)?][..],
        oid,
        &[0x05, 0x00, 0x04, len(h)?],
    ]
    .concat();
    Ok(Pkcs1v15Sign {
        hash_len: Some(h),
        prefix: prefix.into_boxed_slice(),
    })
}

/// EMSA-PSS encoding (RFC 8017, Section 9.1.1) into all of `em`, as in the
/// TPM reference implementation (`PssEncode`).
fn pss_encode(rng: &mut ChaChaRng, digest: TpmtHa<'_>, em: &mut [u8]) -> Result<(), CryptoError> {
    let hash = digest.hash_alg();
    let h = hash.digest_size();
    // EM = maskedDB || H || 0xbc
    let m_len = em.len().checked_sub(h + 1).ok_or(CryptoError::Internal)?;
    let (db, rest) = em.split_at_mut(m_len);
    let (h_out, trailer) = rest.split_at_mut(h);

    // Use the maximum salt size allowed by FIPS 186-4 (the digest size), as
    // long as it fits in the mask.
    let salt_len = m_len.checked_sub(1).ok_or(CryptoError::Internal)?.min(h);
    let mut salt = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let salt = prefix(&mut salt, salt_len)?;
    rng.fill_bytes(salt)?;

    // H = Hash(0x00 * 8 || mHash || salt)
    let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    h_out.copy_from_slice(hash_concat(
        hash,
        &[&[0; 8], digest.digest(), salt],
        &mut buf,
    )?);
    trailer.fill(0xbc);

    // DB = PS || 0x01 || salt
    let (ps_one, db_salt) = db.split_at_mut(m_len - salt_len);
    let (one, ps) = ps_one.split_last_mut().ok_or(CryptoError::Internal)?;
    ps.fill(0);
    *one = 0x01;
    db_salt.copy_from_slice(salt);
    mgf1_xor(hash, h_out, db)?;

    // Since all supported key sizes are multiples of 8 bits, clearing the
    // most significant bit makes EM less than the modulus.
    if let Some(first) = db.first_mut() {
        *first &= 0x7f;
    }
    Ok(())
}

/// EMSA-PSS verification (RFC 8017, Section 9.1.2) of `em`, as in the TPM
/// reference implementation (`PssDecode`), which accepts any salt length.
fn pss_verify(digest: TpmtHa<'_>, em: &mut [u8]) -> Result<bool, CryptoError> {
    let hash = digest.hash_alg();
    let h = hash.digest_size();
    // EM = maskedDB || H || 0xbc, where the most significant bit is zero.
    let Some(m_len) = em.len().checked_sub(h + 1) else {
        return Ok(false);
    };
    let (db, rest) = em.split_at_mut(m_len);
    let (h_in, trailer) = rest.split_at(h);
    if trailer != [0xbc] || db.first().is_none_or(|&b| b & 0x80 != 0) {
        return Ok(false);
    }
    mgf1_xor(hash, h_in, db)?;
    // Clear the most significant bit, as was done during encoding.
    if let Some(first) = db.first_mut() {
        *first &= 0x7f;
    }

    // DB = PS || 0x01 || salt
    let Some(sep) = db.iter().position(|&b| b != 0) else {
        return Ok(false);
    };
    let Some((0x01, salt)) = db.split_at(sep).1.split_first() else {
        return Ok(false);
    };
    let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let expected = hash_concat(hash, &[&[0; 8], digest.digest(), salt], &mut buf)?;
    Ok(expected == h_in)
}

/// An ECC signature scheme supported by this backend.
#[derive(Clone, Copy)]
enum Scheme {
    Ecdsa,
    Sm2,
    Ecschnorr,
}

impl Scheme {
    fn new(scheme: EccSigScheme) -> Result<Self, CryptoError> {
        match scheme {
            EccSigScheme::Ecdsa => Ok(Self::Ecdsa),
            EccSigScheme::Sm2 => Ok(Self::Sm2),
            EccSigScheme::Ecschnorr => Ok(Self::Ecschnorr),
            // ECDAA signing requires the `TPM2_Commit` protocol.
            EccSigScheme::Ecdaa(_) => Err(CryptoError::Unsupported),
        }
    }
}

fn ecc_sign_impl<'a, C: EcCurve>(
    rng: &mut ChaChaRng,
    d: &NonZeroScalar<C>,
    scheme: Scheme,
    digest: TpmtHa<'_>,
    out_r: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    out_s: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
) -> Result<(Tpm2bEccParameter<'a>, Tpm2bEccParameter<'a>), CryptoError>
where
    SignatureSize<C>: ArrayLength<u8>,
{
    for _ in 0..MAX_SIGN_ATTEMPTS {
        let k = NonZeroScalar::<C>::random(&mut rng.0);
        let signature = match scheme {
            Scheme::Ecdsa => ecdsa_sign(d, &k, digest),
            Scheme::Sm2 => sm2_sign(d, &k, digest)?,
            Scheme::Ecschnorr => schnorr_sign(d, &k, digest)?,
        };
        if let Some((r, s)) = signature {
            return Ok((write_param(&r, out_r)?, write_param(&s, out_s)?));
        }
    }
    Err(CryptoError::Internal)
}

fn ecc_verify_impl<C: EcCurve>(
    q: &PublicKey<C>,
    scheme: Scheme,
    digest: TpmtHa<'_>,
    sig_r: &[u8],
    sig_s: &[u8],
) -> Result<bool, CryptoError>
where
    SignatureSize<C>: ArrayLength<u8>,
{
    // Both signature values must be in [1, n - 1].
    let (Some(r), Some(s)) = (parse_scalar::<C>(sig_r), parse_scalar::<C>(sig_s)) else {
        return Ok(false);
    };
    match scheme {
        Scheme::Ecdsa => Ok(ecdsa_verify(q, digest, &r, &s)),
        Scheme::Sm2 => Ok(sm2_verify(q, digest, &r, &s)),
        Scheme::Ecschnorr => schnorr_verify(q, digest, &r, &s),
    }
}

/// Converts `digest` into the ECDSA integer `z`: its leftmost bytes, up to the
/// size of the curve order (as in the TPM reference implementation).
fn ecdsa_z<C: EcCurve>(digest: TpmtHa<'_>) -> FieldBytes<C> {
    let mut z = FieldBytes::<C>::default();
    let len = digest.digest().len().min(z.len());
    let pad = z.len() - len;
    let (digest, _) = digest.digest().split_at(len);
    z[pad..].copy_from_slice(digest);
    z
}

/// ECDSA signature with nonce `k`, or `None` if `k` must be retried.
fn ecdsa_sign<C: EcCurve>(
    d: &NonZeroScalar<C>,
    k: &NonZeroScalar<C>,
    digest: TpmtHa<'_>,
) -> Option<RawSignature<C>>
where
    SignatureSize<C>: ArrayLength<u8>,
{
    // This only fails if `r` or `s` is zero.
    let (signature, _) = sign_prehashed::<C, Scalar<C>>(d, **k, &ecdsa_z::<C>(digest)).ok()?;
    Some(signature.split_bytes())
}

fn ecdsa_verify<C: EcCurve>(
    q: &PublicKey<C>,
    digest: TpmtHa<'_>,
    r: &NonZeroScalar<C>,
    s: &NonZeroScalar<C>,
) -> bool
where
    SignatureSize<C>: ArrayLength<u8>,
{
    let Ok(signature) = Signature::<C>::from_scalars(r, s) else {
        return false;
    };
    verify_prehashed::<C>(&q.to_projective(), &ecdsa_z::<C>(digest), &signature).is_ok()
}

/// Interprets `digest` as a big-endian integer modulo the curve order.
fn digest_to_scalar<C: EcCurve>(digest: TpmtHa<'_>) -> Scalar<C> {
    let base = Scalar::<C>::from(256u64);
    digest.digest().iter().fold(Scalar::<C>::ZERO, |e, &b| {
        e * base + Scalar::<C>::from(u64::from(b))
    })
}

/// Returns the x-coordinate of `point` modulo the curve order.
fn x_mod_n<C: EcCurve>(point: &ProjectivePoint<C>) -> Scalar<C> {
    <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(&point.to_affine().x())
}

/// SM2 signature (GB/T 32918.2-2016, Section 6.1) with nonce `k`, or
/// `Ok(None)` if `k` must be retried.
///
/// As in the TPM reference implementation, `e` is the signed digest itself.
fn sm2_sign<C: EcCurve>(
    d: &NonZeroScalar<C>,
    k: &NonZeroScalar<C>,
    digest: TpmtHa<'_>,
) -> Result<Option<RawSignature<C>>, CryptoError> {
    // A4: (x1, y1) = [k]G
    // A5: r = (e + x1) mod n; if r = 0 or r + k = n, return to A3
    let r =
        digest_to_scalar::<C>(digest) + x_mod_n::<C>(&ProjectivePoint::<C>::mul_by_generator(k));
    if bool::from(r.is_zero() | (r + **k).is_zero()) {
        return Ok(None);
    }
    // A6: s = ((1 + d)^-1 * (k - r * d)) mod n; if s = 0, return to A3
    // (1 + d) is only zero for d = n - 1, which isn't a valid SM2 private key.
    let inv: Option<Scalar<C>> = (Scalar::<C>::ONE + **d).invert().into();
    let s = inv.ok_or(CryptoError::Unsupported)? * (**k - r * **d);
    if bool::from(s.is_zero()) {
        return Ok(None);
    }
    Ok(Some((r.into(), s.into())))
}

/// SM2 verification (GB/T 32918.2-2016, Section 7.1).
fn sm2_verify<C: EcCurve>(
    q: &PublicKey<C>,
    digest: TpmtHa<'_>,
    r: &NonZeroScalar<C>,
    s: &NonZeroScalar<C>,
) -> bool {
    // B5: t = (r + s) mod n; fail if t = 0
    let t = **r + **s;
    if bool::from(t.is_zero()) {
        return false;
    }
    // B6: (x1, y1) = [s]G + [t]Q
    let g = ProjectivePoint::<C>::generator();
    let point = ProjectivePoint::<C>::lincomb(&g, s, &q.to_projective(), &t);
    if bool::from(point.is_identity()) {
        return false;
    }
    // B7: R = (e + x1) mod n; succeed if R = r
    digest_to_scalar::<C>(digest) + x_mod_n::<C>(&point) == **r
}

/// Returns `Hash(x || digest)`, truncated to the size of the curve order (as
/// in the TPM reference implementation's `SchnorrReduce`).
fn schnorr_hash<C: EcCurve>(
    digest: TpmtHa<'_>,
    x: &FieldBytes<C>,
) -> Result<FieldBytes<C>, CryptoError> {
    let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let hash = hash_concat(digest.hash_alg(), &[x, digest.digest()], &mut buf)?;
    let (hash, _) = hash.split_at(hash.len().min(x.len()));
    int_to_field::<C>(hash).ok_or(CryptoError::Internal)
}

/// EC-Schnorr signature with nonce `k` (as in the TPM reference
/// implementation's `BnSignEcSchnorr`), or `Ok(None)` if `k` must be retried.
fn schnorr_sign<C: EcCurve>(
    d: &NonZeroScalar<C>,
    k: &NonZeroScalar<C>,
    digest: TpmtHa<'_>,
) -> Result<Option<RawSignature<C>>, CryptoError> {
    // r = Hash(x(kG) || digest)
    let x = ProjectivePoint::<C>::mul_by_generator(k).to_affine().x();
    let r_bytes = schnorr_hash::<C>(digest, &x)?;
    // Verification requires r to be in [1, n - 1]. The reference
    // implementation only retries if r = 0 (mod n), so it can produce
    // signatures with r >= n that its own verification rejects.
    let Some(r) = Option::<NonZeroScalar<C>>::from(NonZeroScalar::from_repr(r_bytes)) else {
        return Ok(None);
    };
    // s = (k + r * d) mod n
    let s = **k + *r * **d;
    if bool::from(s.is_zero()) {
        return Ok(None);
    }
    Ok(Some((r.into(), s.into())))
}

/// EC-Schnorr verification (as in the TPM reference implementation's
/// `BnValidateSignatureEcSchnorr`).
fn schnorr_verify<C: EcCurve>(
    q: &PublicKey<C>,
    digest: TpmtHa<'_>,
    r: &NonZeroScalar<C>,
    s: &NonZeroScalar<C>,
) -> Result<bool, CryptoError> {
    // E = [s]G - [r]Q
    let g = ProjectivePoint::<C>::generator();
    let point = ProjectivePoint::<C>::lincomb(&g, s, &q.to_projective(), &-**r);
    if bool::from(point.is_identity()) {
        return Ok(false);
    }
    // Succeed if r = Hash(x(E) || digest)
    Ok(schnorr_hash::<C>(digest, &point.to_affine().x())? == FieldBytes::<C>::from(r))
}
