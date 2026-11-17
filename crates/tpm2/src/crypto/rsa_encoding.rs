//! The randomized RSA encodings of the TPM (tpm-rs extensions): EME-OAEP
//! ([`rsa_oaep_encode`]), RSAES-PKCS1-v1_5 ([`rsa_pkcs1v15_encode`]) and
//! EMSA-PSS ([`rsa_pss_encode`]) of RFC 8017, with every random value drawn
//! from an [`Rng`] exactly as the C reference TPMs draw it (`OaepEncode()`,
//! `RSAES_PKCS1v1_5Encode()` and `PssEncode()` of `CryptRsa.c`).
//!
//! The dispatch functions ([`RsaPublicKey::encrypt`] and
//! [`RsaPrivateKey::sign`]) encode with these functions for every RNG and then
//! apply the backend's raw RSA operation, so that a TPM draws the same seeds,
//! padding strings and salts as the references from the same RNG output. The
//! references differ from generic implementations in two ways that matter
//! here: RSAES-PKCS1-v1_5 replaces each zero octet of the drawn padding string
//! with `0x55` (instead of drawing again), and PSS uses the largest salt that
//! fits, at most the digest size ([`rsa_pss_salt_size`]).
//!
//! [`RsaPublicKey::encrypt`]: super::RsaPublicKey::encrypt
//! [`RsaPrivateKey::sign`]: super::RsaPrivateKey::sign

use super::{CryptoError, Rng, backend::Hash, hash};
use crate::TpmiAlgHash;

/// The largest digest of the enabled hash algorithms.
const MAX_DIGEST: usize = TpmiAlgHash::MAX_DIGEST_BYTES;

/// XORs `MGF1(seed, mask.len())` with the hash `alg` (RFC 8017, B.2.1; the
/// reference's `CryptMGF_KDF()`) into `mask`.
fn mgf1_xor<H: Hash>(alg: TpmiAlgHash, seed: &[u8], mask: &mut [u8]) -> Result<(), CryptoError> {
    let mut digest = [0u8; MAX_DIGEST];
    for (counter, chunk) in (0u32..).zip(mask.chunks_mut(alg.digest_size())) {
        let d = hash::<H>(alg, &[seed, &counter.to_be_bytes()], &mut digest)?;
        for (m, d) in chunk.iter_mut().zip(d.digest()) {
            *m ^= d;
        }
    }
    Ok(())
}

/// The EME-OAEP encoding (RFC 8017, 7.1.1 step 2) of `message` with the hash
/// `alg` and the label `label` (all of its octets, e.g. including the
/// terminating zero octet of a TPM label) into `padded`, whose length is that
/// of the modulus: `0x00 || maskedSeed || maskedDB` with
/// `DB = lHash || PS || 0x01 || message`. The seed (one digest) is drawn from
/// `rng` after `DB` is assembled, as the reference's `OaepEncode()` draws it.
///
/// Returns `Ok(None)`, drawing nothing, if `padded` cannot hold two digests
/// and two octets (the reference's `TPM_RC_HASH`) or `message` is longer than
/// `padded.len() - 2 * hLen - 2` octets (`TPM_RC_VALUE`).
pub fn rsa_oaep_encode<H: Hash>(
    rng: &mut impl Rng,
    alg: TpmiAlgHash,
    label: &[u8],
    message: &[u8],
    padded: &mut [u8],
) -> Result<Option<()>, CryptoError> {
    let h_len = alg.digest_size();
    let k = padded.len();
    let Some(max_message) = k.checked_sub(2 * h_len + 2) else {
        return Ok(None);
    };
    if message.len() > max_message {
        return Ok(None);
    }
    let (first, rest) = padded.split_at_mut(1);
    let (seed, db) = rest.split_at_mut(h_len);
    // DB = lHash || PS || 0x01 || M.
    let mut l_hash = [0u8; MAX_DIGEST];
    let l_hash = hash::<H>(alg, &[label], &mut l_hash)?;
    db[..h_len].copy_from_slice(l_hash.digest());
    let one = db.len() - message.len() - 1;
    db[h_len..one].fill(0);
    db[one] = 0x01;
    db[one + 1..].copy_from_slice(message);
    // The seed, then maskedDB = DB ^ MGF1(seed) and maskedSeed = seed ^ MGF1(maskedDB).
    rng.fill_bytes(seed)?;
    mgf1_xor::<H>(alg, seed, db)?;
    mgf1_xor::<H>(alg, db, seed)?;
    first[0] = 0x00;
    Ok(Some(()))
}

/// The RSAES-PKCS1-v1_5 encoding (RFC 8017, 7.2.1 step 2) of `message` into
/// `padded`, whose length is that of the modulus: `0x00 || 0x02 || PS || 0x00
/// || message`, with the padding string `PS` (`padded.len() - message.len() -
/// 3` octets) drawn from `rng` and each of its zero octets replaced with
/// `0x55`, as the reference's `RSAES_PKCS1v1_5Encode()` does.
///
/// Returns `Ok(None)`, drawing nothing, if `message` is longer than
/// `padded.len() - 11` octets (the reference's `TPM_RC_VALUE`).
pub fn rsa_pkcs1v15_encode(
    rng: &mut impl Rng,
    message: &[u8],
    padded: &mut [u8],
) -> Result<Option<()>, CryptoError> {
    let k = padded.len();
    if k < 11 || message.len() > k - 11 {
        return Ok(None);
    }
    let ps = k - message.len() - 3;
    padded[0] = 0x00;
    padded[1] = 0x02;
    let padding = &mut padded[2..2 + ps];
    rng.fill_bytes(padding)?;
    for octet in padding.iter_mut().filter(|octet| **octet == 0) {
        *octet = 0x55;
    }
    padded[2 + ps] = 0x00;
    padded[3 + ps..].copy_from_slice(message);
    Ok(Some(()))
}

/// The salt length of the TPM's RSASSA-PSS signatures with a digest of
/// `hash_size` octets and a modulus of `out_size` octets: the largest that
/// fits (`out_size - hash_size - 2`), at most the digest size (FIPS 186-4),
/// and 0 if nothing fits (the reference's `CryptRsaPssSaltSize()`).
pub const fn rsa_pss_salt_size(hash_size: usize, out_size: usize) -> usize {
    let fits = out_size.saturating_sub(hash_size + 2);
    if fits > hash_size { hash_size } else { fits }
}

/// The EMSA-PSS encoding (RFC 8017, 9.1.1) of the message digest `digest`
/// with the hash `alg` into `out`, whose length is that of the modulus (a
/// multiple of 8 bits, so `emLen` is `out.len()` and one leading bit is
/// cleared), with a salt of [`rsa_pss_salt_size`] octets drawn from `rng`, as
/// the reference's `PssEncode()` draws it: `maskedDB || H || 0xbc` with
/// `H = Hash(0x00 * 8 || digest || salt)` and `DB = PS || 0x01 || salt`.
///
/// Returns [`CryptoError::Internal`], drawing nothing, if `out` cannot hold a
/// digest and two octets (a fatal error in the reference).
pub fn rsa_pss_encode<H: Hash>(
    rng: &mut impl Rng,
    alg: TpmiAlgHash,
    digest: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let h_len = alg.digest_size();
    let k = out.len();
    if k < h_len + 2 {
        return Err(CryptoError::Internal);
    }
    let m_len = k - h_len - 1;
    let salt_size = rsa_pss_salt_size(h_len, k);
    let mut salt = [0u8; MAX_DIGEST];
    let salt = &mut salt[..salt_size];
    rng.fill_bytes(salt)?;
    let (db, rest) = out.split_at_mut(m_len);
    let (h, trailer) = rest.split_at_mut(h_len);
    let mut buf = [0u8; MAX_DIGEST];
    let h_value = hash::<H>(alg, &[&[0u8; 8], digest, salt], &mut buf)?;
    h.copy_from_slice(h_value.digest());
    // maskedDB = MGF1(H) ^ (PS || 0x01 || salt), with the leftmost bit cleared.
    db.fill(0);
    mgf1_xor::<H>(alg, h, db)?;
    db[0] &= 0x7f;
    trailer[0] = 0xbc;
    let one = m_len - salt_size - 1;
    db[one] ^= 0x01;
    for (d, s) in db[one + 1..].iter_mut().zip(salt.iter()) {
        *d ^= s;
    }
    Ok(())
}
