//! [`Signing`] implementation: RSASSA-PKCS1-v1_5 and RSASSA-PSS using the
//! RustCrypto `rsa` crate, and ECDSA using libcrux (P-256) and RustCrypto
//! (P-384 and P-521).

use ::rsa::traits::PublicKeyParts as _;
use ::rsa::{BigUint, Pkcs1v15Sign, Pss};
use p384::ecdsa::signature::hazmat::{PrehashVerifier as _, RandomizedPrehashSigner as _};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};
use sha2::digest::{Digest, DynDigest};
use tpm2::crypto::{
    CryptoError, EccPublicKey as _, EccSigScheme, RsaPrivateKey as _, RsaSigScheme, Signing,
};
use tpm2::{
    Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmEccCurve, TpmiAlgHash, TpmiRsaKeyBits, TpmtHa,
};

use crate::ecc::{
    MAX_ATTEMPTS, P256_BYTES, P384_BYTES, P521_BYTES, Public, Secret, p256_random_scalar,
    write_param,
};
use crate::hash::sha256;
use crate::{ChaChaRng, EccPrivate, EccPublic, Libcrux, RsaPrivate, RsaPublic, pad_into, write_be};

/// The digest length passed to libcrux's P-256 ECDSA functions, which take
/// exactly [`P256_BYTES`] bytes.
const P256_MSG_LEN: u32 = 32;

/// Creates the RSASSA-PKCS1-v1_5 scheme for `hash`.
fn pkcs1v15(hash: TpmiAlgHash) -> Result<Pkcs1v15Sign, CryptoError> {
    Ok(match hash {
        TpmiAlgHash::Sha1 => Pkcs1v15Sign::new::<sha1::Sha1>(),
        TpmiAlgHash::Sha256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
        TpmiAlgHash::Sha384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
        TpmiAlgHash::Sha512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
        _ => return Err(CryptoError::Unsupported),
    })
}

/// Creates the RSASSA-PSS scheme for `hash` and a `len`-byte modulus.
fn pss(hash: TpmiAlgHash, len: usize) -> Result<Pss, CryptoError> {
    match hash {
        TpmiAlgHash::Sha1 => pss_with::<sha1::Sha1>(len),
        TpmiAlgHash::Sha256 => pss_with::<sha2::Sha256>(len),
        TpmiAlgHash::Sha384 => pss_with::<sha2::Sha384>(len),
        TpmiAlgHash::Sha512 => pss_with::<sha2::Sha512>(len),
        _ => Err(CryptoError::Unsupported),
    }
}

fn pss_with<D: 'static + Digest + DynDigest + Send + Sync>(len: usize) -> Result<Pss, CryptoError> {
    let digest_len = <D as Digest>::output_size();
    // Like the TPM reference implementation, use a salt as long as the
    // digest, or as long as the key allows if that is shorter (the encoded
    // message needs `digest_len + salt_len + 2` bytes).
    let max_salt_len = len
        .checked_sub(digest_len + 2)
        .ok_or(CryptoError::Unsupported)?;
    // A "blinded" scheme blinds the private key operation with the RNG. It
    // doesn't change the signature, and verification ignores it.
    Ok(Pss::new_blinded_with_salt::<D>(
        digest_len.min(max_salt_len),
    ))
}

/// Returns the `N`-byte big-endian ECDSA input for `digest`: its leftmost `N`
/// bytes, or the whole digest left-padded with zeros.
///
/// libcrux requires exactly 32 bytes, and RustCrypto rejects digests shorter
/// than half the field size.
fn digest_to_field<const N: usize>(digest: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let len = digest.len().min(N);
    out[N - len..].copy_from_slice(&digest[..len]);
    out
}

/// Concatenates `r || s` into `out`, each left-padded to `len` bytes.
///
/// Leading zeros are ignored, like in the TPM reference implementation.
/// Returns `None` if `r` or `s` is still longer than `len` bytes.
fn concat_rs<'a>(
    r: &[u8],
    s: &[u8],
    len: usize,
    out: &'a mut [u8; 2 * P521_BYTES],
) -> Option<&'a [u8]> {
    let out = out.get_mut(..2 * len)?;
    let (out_r, out_s) = out.split_at_mut(len);
    pad_into(trim_zeros(r), out_r)?;
    pad_into(trim_zeros(s), out_s)?;
    Some(out)
}

/// Returns the big-endian `value` without its leading zeros.
///
/// This isn't constant time, so only use it on public values.
fn trim_zeros(value: &[u8]) -> &[u8] {
    let zeros = value.iter().take_while(|&&byte| byte == 0).count();
    value.get(zeros..).unwrap_or_default()
}

/// Signs the P-256 ECDSA input `z` with the scalar `d`, returning `r || s`.
fn p256_sign(
    rng: &mut ChaCha20Rng,
    d: &[u8; P256_BYTES],
    z: &[u8; P256_BYTES],
) -> Result<[u8; 2 * P256_BYTES], CryptoError> {
    // Hedge the nonce by drawing it from a DRBG keyed with the RNG output, the
    // key and the digest (like BoringSSL), so that a repeated RNG output can't
    // reuse a nonce for a different digest.
    let mut entropy = [0u8; 32];
    rng.fill_bytes(&mut entropy);
    let mut nonces = ChaCha20Rng::from_seed(sha256(&[&entropy, d, z]));
    let mut signature = [0u8; 2 * P256_BYTES];
    for _ in 0..MAX_ATTEMPTS {
        let nonce = p256_random_scalar(&mut nonces)?;
        // Fails if `r` or `s` is zero, so retry with another nonce.
        if libcrux_p256::ecdsa_sign_p256_without_hash(&mut signature, P256_MSG_LEN, z, d, &nonce) {
            return Ok(signature);
        }
    }
    Err(CryptoError::Internal)
}

impl Signing for Libcrux {
    fn rsa_sign<'a>(
        &self,
        rng: &mut ChaChaRng,
        key: &RsaPrivate,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        let len = key.public_key().len();
        let hash = digest.hash_alg();
        let rng = &mut rng.0;
        let result = match scheme {
            RsaSigScheme::Rsassa => key.key.sign_with_rng(rng, pkcs1v15(hash)?, digest.digest()),
            RsaSigScheme::Rsapss => key.key.sign_with_rng(rng, pss(hash, len)?, digest.digest()),
        };
        let signature = match result {
            Ok(signature) => signature,
            // The key is too small for the digest.
            Err(::rsa::Error::MessageTooLong) => return Err(CryptoError::Unsupported),
            Err(_) => return Err(CryptoError::Internal),
        };
        Tpm2bPublicKeyRsa::new(write_be(&signature, len, out)?).ok_or(CryptoError::Internal)
    }

    fn rsa_verify(
        &self,
        key: &RsaPublic,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        sig: &[u8],
    ) -> Result<bool, CryptoError> {
        let hash = digest.hash_alg();
        let digest = digest.digest();
        // The `rsa` crate's PSS verification doesn't check that `sig < n`.
        let in_range = sig.len() == key.len() && BigUint::from_bytes_be(sig) < *key.key.n();
        Ok(match scheme {
            RsaSigScheme::Rsassa => {
                let scheme = pkcs1v15(hash)?;
                in_range && key.key.verify(scheme, digest, sig).is_ok()
            }
            RsaSigScheme::Rsapss => {
                // Unsupported hashes, and keys too small for the digest, fail like signing.
                pss(hash, key.len())?;
                if !in_range {
                    return Ok(false);
                }
                let m = ::rsa::hazmat::rsa_encrypt(&key.key, &BigUint::from_bytes_be(sig))
                    .map_err(|_| CryptoError::Internal)?;
                let mut em = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
                let em = em.get_mut(..key.len()).ok_or(CryptoError::Internal)?;
                pad_into(&m.to_bytes_be(), em).ok_or(CryptoError::Internal)?;
                pss_verify(hash, digest, em)?
            }
        })
    }

    fn ecc_sign<'a>(
        &self,
        rng: &mut ChaChaRng,
        key: &EccPrivate,
        scheme: EccSigScheme,
        digest: TpmtHa<'_>,
        out_r: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_s: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<(Tpm2bEccParameter<'a>, Tpm2bEccParameter<'a>), CryptoError> {
        if scheme != EccSigScheme::Ecdsa {
            return Err(CryptoError::Unsupported);
        }
        let digest = digest.digest();
        let rng = &mut rng.0;
        match &key.secret {
            Secret::P256(d) => {
                let signature = p256_sign(rng, d, &digest_to_field(digest))?;
                let (r, s) = signature.split_at(P256_BYTES);
                Ok((write_param(r, out_r)?, write_param(s, out_s)?))
            }
            Secret::P384(d) => {
                let z = digest_to_field::<P384_BYTES>(digest);
                let signature: p384::ecdsa::Signature = p384::ecdsa::SigningKey::from(d)
                    .sign_prehash_with_rng(rng, &z)
                    .map_err(|_| CryptoError::Internal)?;
                let (r, s) = signature.split_bytes();
                Ok((write_param(&r, out_r)?, write_param(&s, out_s)?))
            }
            Secret::P521(d) => {
                let z = digest_to_field::<P521_BYTES>(digest);
                let signature: p521::ecdsa::Signature =
                    p521::ecdsa::SigningKey::from_bytes(&d.to_bytes())
                        .and_then(|key| key.sign_prehash_with_rng(rng, &z))
                        .map_err(|_| CryptoError::Internal)?;
                let (r, s) = signature.split_bytes();
                Ok((write_param(&r, out_r)?, write_param(&s, out_s)?))
            }
        }
    }

    fn ecc_verify(
        &self,
        key: &EccPublic,
        scheme: EccSigScheme,
        digest: TpmtHa<'_>,
        sig_r: &[u8],
        sig_s: &[u8],
    ) -> Result<bool, CryptoError> {
        if scheme != EccSigScheme::Ecdsa {
            return Err(CryptoError::Unsupported);
        }
        let digest = digest.digest();
        let mut rs = [0u8; 2 * P521_BYTES];
        let Some(rs) = concat_rs(sig_r, sig_s, key.curve().key_bytes(), &mut rs) else {
            return Ok(false);
        };
        // Each arm checks that `r` and `s` are in `[1, n - 1]`.
        Ok(match &key.0 {
            Public::P256(q) => {
                let (r, s) = rs.split_at(P256_BYTES);
                let z = digest_to_field::<P256_BYTES>(digest);
                libcrux_p256::ecdsa_verif_without_hash(P256_MSG_LEN, &z, q, r, s)
            }
            Public::P384(q) => {
                let z = digest_to_field::<P384_BYTES>(digest);
                let key = p384::ecdsa::VerifyingKey::from(q);
                p384::ecdsa::Signature::from_slice(rs)
                    .is_ok_and(|signature| key.verify_prehash(&z, &signature).is_ok())
            }
            Public::P521(q) => {
                let z = digest_to_field::<P521_BYTES>(digest);
                let key = p521::ecdsa::VerifyingKey::from_affine(*q.as_affine())
                    .map_err(|_| CryptoError::Internal)?;
                p521::ecdsa::Signature::from_slice(rs)
                    .is_ok_and(|signature| key.verify_prehash(&z, &signature).is_ok())
            }
        })
    }
}

/// Checks the EMSA-PSS encoding `em` of `digest`, accepting any salt length (RFC 8017, section
/// 9.1.2), like `PssDecode` in the TPM reference implementation. The `rsa` crate only verifies one
/// salt length.
fn pss_verify(hash: TpmiAlgHash, digest: &[u8], em: &mut [u8]) -> Result<bool, CryptoError> {
    let h_len = hash.digest_size();
    // EM = maskedDB || H || 0xbc, where the most significant bit is zero.
    let Some(db_len) = em.len().checked_sub(h_len + 1) else {
        return Ok(false);
    };
    let (db, rest) = em.split_at_mut(db_len);
    let (h, trailer) = rest.split_at(h_len);
    if trailer != [0xbc] || db.first().is_none_or(|&b| b & 0x80 != 0) {
        return Ok(false);
    }
    // DB = maskedDB XOR MGF1(H), with the most significant bit cleared.
    let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    for (counter, chunk) in (0u32..).zip(db.chunks_mut(h_len)) {
        let mask = hash_parts(hash, &[h, &counter.to_be_bytes()], &mut buf)?;
        chunk.iter_mut().zip(mask).for_each(|(b, m)| *b ^= m);
    }
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
    let expected = hash_parts(hash, &[&[0; 8], digest, salt], &mut buf)?;
    Ok(expected == h)
}

/// Returns the `hash` digest of the concatenation of `parts`, written to `out`.
fn hash_parts<'a>(
    hash: TpmiAlgHash,
    parts: &[&[u8]],
    out: &'a mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
) -> Result<&'a [u8], CryptoError> {
    fn run<D: Digest>(parts: &[&[u8]], out: &mut [u8]) -> Result<usize, CryptoError> {
        let mut hasher = D::new();
        parts
            .iter()
            .for_each(|part| Digest::update(&mut hasher, part));
        let digest = hasher.finalize();
        out.get_mut(..digest.len())
            .ok_or(CryptoError::Internal)?
            .copy_from_slice(&digest);
        Ok(digest.len())
    }
    let len = match hash {
        TpmiAlgHash::Sha1 => run::<sha1::Sha1>(parts, out)?,
        TpmiAlgHash::Sha256 => run::<sha2::Sha256>(parts, out)?,
        TpmiAlgHash::Sha384 => run::<sha2::Sha384>(parts, out)?,
        TpmiAlgHash::Sha512 => run::<sha2::Sha512>(parts, out)?,
        _ => return Err(CryptoError::Unsupported),
    };
    out.get(..len).ok_or(CryptoError::Internal)
}
