//! The TPM's random asymmetric algorithms with the C reference TPMs' draws: key generation and
//! the randomized ECC signatures, computed by the engine on [`Rng::fill_bytes`] alone (an RNG
//! implements no algorithm), with the reference's sizes, order and retries:
//!
//! - [`rsa_generate_key`]: `CryptRsaGenerateKey()` (prime candidates, sieve, Miller-Rabin bases,
//!   the pairwise consistency test of signing keys; `src/rsa_keygen.rs`);
//! - [`ecc_private_scalar`] (`TpmEcc_GenPrivateScalar()`), [`ecc_random_in_range`]
//!   (`TpmMath_GetRandomInRange()`) and [`ecc_generate_key`] (`TpmEcc_GenerateKeyPair()`: the key
//!   of `CryptEccGenerateKey()` and `CryptEccNewKeyPair()`);
//! - [`ecdsa_sign`], [`sm2_sign`] and [`ecschnorr_sign`] (`CryptEccSign()`).
//!
//! A TPM whose RNG draws the reference's DRBG output therefore produces the reference's keys and
//! signatures. The point multiplications and the raw RSA operations are the crypto backend's.
//!
//! The engine uses these for every RNG except the backend's system RNG
//! ([`Rng::is_system_rng`]), for which it keeps the backend's own algorithms where the backend
//! implements them (RSA and ECC key generation, ECDSA on the curves of the backend's ECDSA):
//! `generate_rsa_key`, `generate_ecc_key` and `sign_ecdsa` below select the implementation.
//! SM2, EC-Schnorr, ECDSA on the other curves and the pairwise consistency test of ECC signing
//! keys always use these algorithms. The functions are public so that other implementations can
//! be checked against them (e.g. `tpm2-platform-linux` checks them against the C reference's
//! functions on the same DRBG).

use tpm2::crypto::{Crypto, CryptoError, EccPrivateKey, MAX_SIGNATURE_BYTES, Rng, RsaPrivateKey};
use tpm2::{TpmEccCurve, TpmiAlgHash, TpmiRsaKeyBits, TpmtHa, TpmtSigScheme, TpmtSignature};

use crate::ecc_curves::curve_params;
use crate::self_test::{SelfTestState, Tested};

/// Writes the big-endian `value` to the front of `out` and returns its length.
fn write_front(value: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
    out.get_mut(..value.len())
        .ok_or(CryptoError::Internal)?
        .copy_from_slice(value);
    Ok(value.len())
}

/// The order of `curve` ([`CryptoError::Unsupported`] for a curve of another build).
fn order(curve: TpmEccCurve) -> Result<&'static [u8], CryptoError> {
    Ok(curve_params(curve).ok_or(CryptoError::Unsupported)?.n)
}

/// `TpmEcc_GenPrivateScalar()`: a private scalar `1 <= d < n` for the order `n` of `curve`, from
/// the octet size of `n` plus 8 octets drawn from `rng`, reduced modulo `n - 1`, plus 1 (FIPS
/// 186-5, A.2.1). Writes it (the size of `n`) to the front of `out` and returns its length.
pub fn ecc_private_scalar(
    rng: &mut impl Rng,
    curve: TpmEccCurve,
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let d = crate::ecc_schemes::private_scalar(rng, order(curve)?)?;
    write_front(d.as_bytes(), out)
}

/// `TpmMath_GetRandomInRange()` for the order `n` of `curve` (the SM2 nonce): `1 <= k < n`,
/// drawn from `rng` as `bitlen(n)` bits until it is in range. Writes it (the size of `n`) to the
/// front of `out` and returns its length.
pub fn ecc_random_in_range(
    rng: &mut impl Rng,
    curve: TpmEccCurve,
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    let k = crate::ecc_schemes::random_in_range(rng, order(curve)?)?;
    write_front(k.as_bytes(), out)
}

/// `TpmEcc_GenerateKeyPair()`: an ECC key pair on `curve` with the private scalar
/// [`ecc_private_scalar`] drawn from `rng` and the public point computed by the backend (the key
/// of `CryptEccGenerateKey()`, without its pairwise test, and of `CryptEccNewKeyPair()`).
pub fn ecc_generate_key<C: Crypto>(
    rng: &mut impl Rng,
    curve: TpmEccCurve,
) -> Result<EccPrivateKey<C>, CryptoError> {
    crate::ecc_schemes::generate_key::<C>(rng, curve)
}

/// `TpmEcc_SignEcdsa()`: signs `digest` (of any length) with the private scalar `d` on `curve`
/// with ECDSA, with the nonces drawn from `rng`. Writes `r || s` (each the size of the order) to
/// `out` and returns its length, or `Ok(None)` if `d` is not a valid private key.
pub fn ecdsa_sign<C: Crypto>(
    rng: &mut impl Rng,
    curve: TpmEccCurve,
    d: &[u8],
    digest: &[u8],
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    crate::ecc_schemes::ecdsa_sign::<C>(curve, d, digest, rng, out)
}

/// `TpmEcc_SignEcSm2()`: signs the digest `digest` (`e`) with the private scalar `d` on `curve`
/// with SM2, with the nonce drawn from `rng`. Writes `r || s` to `out` as [`ecdsa_sign`] does.
pub fn sm2_sign<C: Crypto>(
    rng: &mut impl Rng,
    curve: TpmEccCurve,
    d: &[u8],
    digest: &[u8],
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    crate::ecc_schemes::sm2_sign::<C>(curve, d, digest, rng, out)
}

/// `TpmEcc_SignEcSchnorr()`: signs the digest `digest` with the private scalar `d` on `curve`
/// with EC-Schnorr and the scheme hash `hash`, with the nonce drawn from `rng`. Writes `r || s`
/// to `out` as [`ecdsa_sign`] does. The hashes run without the TPM's self tests.
pub fn ecschnorr_sign<C: Crypto>(
    rng: &mut impl Rng,
    curve: TpmEccCurve,
    hash: TpmiAlgHash,
    d: &[u8],
    digest: &[u8],
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let state = SelfTestState::nothing_to_test();
    let crypto = Tested::<C>::new(&state);
    crate::ecc_schemes::schnorr_sign(&crypto, curve, hash, d, digest, rng, out)
}

/// `CryptRsaGenerateKey()`: an RSA key of `bits` bits with the public exponent `exponent` (0 for
/// 65537, otherwise a prime of at least 65537; [`CryptoError::Unsupported`] for others) whose
/// primes are drawn from `rng`, including the pairwise consistency test of a key whose object
/// has the *sign* attribute (`sign`). See `src/rsa_keygen.rs`.
pub fn rsa_generate_key<C: Crypto>(
    rng: &mut C::Rng,
    bits: TpmiRsaKeyBits,
    exponent: u32,
    sign: bool,
) -> Result<RsaPrivateKey<C>, CryptoError> {
    crate::rsa_keygen::generate_key::<C>(rng, bits, exponent, sign)
}

/// The key of a new RSA object: the backend's key generation for the backend's system RNG
/// ([`Rng::is_system_rng`], e.g. BoringSSL's `RSA_generate_key_ex`), [`rsa_generate_key`]
/// otherwise.
pub(crate) fn generate_rsa_key<C: Crypto>(
    rng: &mut C::Rng,
    bits: TpmiRsaKeyBits,
    exponent: u32,
    sign: bool,
) -> Result<RsaPrivateKey<C>, CryptoError> {
    if rng.is_system_rng() {
        RsaPrivateKey::generate(rng, bits, exponent)
    } else {
        rsa_generate_key::<C>(rng, bits, exponent, sign)
    }
}

/// The key of a new ECC object or an ephemeral key: the backend's key generation for the
/// backend's system RNG ([`Rng::is_system_rng`]), [`ecc_generate_key`] otherwise.
pub(crate) fn generate_ecc_key<C: Crypto>(
    rng: &mut C::Rng,
    curve: TpmEccCurve,
) -> Result<EccPrivateKey<C>, CryptoError> {
    if rng.is_system_rng() {
        EccPrivateKey::generate(rng, curve, None)
    } else {
        ecc_generate_key::<C>(rng, curve)
    }
}

/// An ECDSA signature of `digest` with the private scalar `d` on `curve` (`CryptEccSign()`):
/// the backend's ECDSA (e.g. BoringSSL's hedged ECDSA) for the backend's system RNG
/// ([`Rng::is_system_rng`]) on the curves of the backend's ECDSA
/// ([`provider_ecdsa_curve`](crate::handler::crypt_ops::provider_ecdsa_curve)), [`ecdsa_sign`]
/// otherwise. Writes `r || s` (each the size of the order) to `out` and returns its length, or
/// `Ok(None)` if `d` is not a valid private key.
pub(crate) fn sign_ecdsa<C: Crypto>(
    rng: &mut C::Rng,
    curve: TpmEccCurve,
    d: &[u8],
    digest: TpmtHa<'_>,
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    if !(rng.is_system_rng() && crate::handler::crypt_ops::provider_ecdsa_curve(curve)) {
        return ecdsa_sign::<C>(rng, curve, d, digest.digest(), out);
    }
    let Some(key) = EccPrivateKey::<C>::from_scalar(curve, d)? else {
        return Ok(None);
    };
    let mut buf = [0u8; MAX_SIGNATURE_BYTES];
    let scheme = TpmtSigScheme::Ecdsa(digest.hash_alg());
    let TpmtSignature::Ecdsa(sig) = key.sign(rng, scheme, digest.digest(), &mut buf)? else {
        return Err(CryptoError::Internal);
    };
    let size = order(curve)?.len();
    let out = out.get_mut(..2 * size).ok_or(CryptoError::Internal)?;
    out.fill(0);
    for (half, component) in out
        .chunks_mut(size)
        .zip([sig.signature_r.as_slice(), sig.signature_s.as_slice()])
    {
        let offset = size
            .checked_sub(component.len())
            .ok_or(CryptoError::Internal)?;
        half[offset..].copy_from_slice(component);
    }
    Ok(Some(2 * size))
}
