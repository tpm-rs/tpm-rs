//! RSA encryption and decryption with the schemes of the TPM (`TPM_ALG_NULL`, `TPM_ALG_RSAES`
//! and `TPM_ALG_OAEP`) and a raw OAEP label: [`rsa_encrypt`] and [`rsa_decrypt`].
//!
//! The crypto backend's OAEP ([`RsaEncryptScheme::Oaep`]) takes the label as a C string, i.e.
//! the TPM's zero-terminated label without embedded zero octets. The TPM checks only the
//! terminating zero (TPM 2.0 Part 3, `TPM2_RSA_Encrypt`: "If label is present, the label must
//! be terminated by a zero octet"), and the reference's `OaepEncode()`/`OaepDecode()` hash the
//! whole label buffer. A label that is not a C string (with an embedded zero octet) is therefore
//! handled here with the EME-OAEP encoding of RFC 8017 (7.1) over the backend's raw RSA
//! (`RSAEP`/`RSADP`, [`RsaEncryptScheme::Raw`]) and its hashes, as the reference does.

use core::ffi::CStr;

use tpm2::crypto::{Crypto, CryptoError, Rng, RsaEncryptScheme, RsaPrivateKey, RsaPublicKey};
use tpm2::{Alg, TpmiAlgHash};

/// The largest modulus of the profile.
const MAX_MODULUS: usize = tpm2::TpmiRsaKeyBits::MAX_PUB_KEY_BYTES;
/// The largest digest of the profile.
const MAX_DIGEST: usize = TpmiAlgHash::MAX_DIGEST_BYTES;

/// The encryption scheme `scheme` (`TPM_ALG_NULL`, `TPM_ALG_RSAES` or `TPM_ALG_OAEP` with the
/// hash `hash`) of the backend for the label `label`, or `Ok(None)` for an OAEP label that is not
/// a C string (which [`oaep_encrypt`]/[`oaep_decrypt`] handle).
fn backend_scheme(
    scheme: Alg,
    hash: Alg,
    label: &[u8],
) -> Result<Option<RsaEncryptScheme<'_>>, CryptoError> {
    match scheme {
        Alg::NULL => Ok(Some(RsaEncryptScheme::Raw)),
        Alg::RSAES => Ok(Some(RsaEncryptScheme::Rsaes)),
        Alg::OAEP => {
            let hash = TpmiAlgHash::try_from(hash).map_err(|_| CryptoError::Unsupported)?;
            if label.is_empty() {
                return Ok(Some(RsaEncryptScheme::Oaep { hash, label: None }));
            }
            Ok(CStr::from_bytes_with_nul(label)
                .ok()
                .map(|label| RsaEncryptScheme::Oaep {
                    hash,
                    label: Some(label),
                }))
        }
        _ => Err(CryptoError::Unsupported),
    }
}

/// Encrypts `message` with the public key `key` and the scheme `scheme` (`TPM_ALG_NULL`,
/// `TPM_ALG_RSAES`, or `TPM_ALG_OAEP` with the hash `hash` and the label `label`, which includes
/// its terminating zero octet), writing the ciphertext (the size of the modulus) to `out`.
///
/// Returns the ciphertext length, `Ok(None)` if `message` cannot be encrypted with the key and
/// scheme (too long, or not below the modulus for `TPM_ALG_NULL`), or
/// [`CryptoError::Unsupported`] for another scheme or hash.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rsa_encrypt<C: Crypto>(
    rng: &mut C::Rng,
    key: &RsaPublicKey<C>,
    scheme: Alg,
    hash: Alg,
    label: &[u8],
    message: &[u8],
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    match backend_scheme(scheme, hash, label)? {
        Some(scheme) => Ok(key
            .encrypt(rng, scheme, message, out)?
            .map(|c| c.as_slice().len())),
        None => {
            let hash = TpmiAlgHash::try_from(hash).map_err(|_| CryptoError::Unsupported)?;
            oaep_encrypt(rng, key, hash, label, message, out)
        }
    }
}

/// Decrypts `ciphertext` with the private key `key` and the scheme `scheme` (see
/// [`rsa_encrypt`]), writing the message to `out`. A `TPM_ALG_NULL` message is the size of the
/// modulus.
///
/// Returns the message length, `Ok(None)` if `ciphertext` is not the size of the modulus, not
/// below the modulus or not correctly padded, or [`CryptoError::Unsupported`] for another scheme
/// or hash.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rsa_decrypt<C: Crypto>(
    rng: &mut C::Rng,
    key: &RsaPrivateKey<C>,
    scheme: Alg,
    hash: Alg,
    label: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    match backend_scheme(scheme, hash, label)? {
        Some(scheme) => {
            let Some(message) = key.decrypt(rng, scheme, ciphertext, out)? else {
                return Ok(None);
            };
            Ok(Some(message.as_slice().len()))
        }
        None => {
            let hash = TpmiAlgHash::try_from(hash).map_err(|_| CryptoError::Unsupported)?;
            oaep_decrypt(rng, key, hash, label, ciphertext, out)
        }
    }
}

/// `MGF1(seed, mask.len())` with `hash` (RFC 8017, B.2.1), XORed into `mask`.
fn mgf1_xor<C: Crypto>(hash: TpmiAlgHash, seed: &[u8], mask: &mut [u8]) -> Result<(), CryptoError> {
    let mut digest = [0u8; MAX_DIGEST];
    for (counter, chunk) in (0u32..).zip(mask.chunks_mut(hash.digest_size())) {
        let d = tpm2::crypto::hash::<C>(hash, &[seed, &counter.to_be_bytes()], &mut digest)?;
        for (m, d) in chunk.iter_mut().zip(d.digest()) {
            *m ^= d;
        }
    }
    Ok(())
}

/// RSAES-OAEP-ENCRYPT (RFC 8017, 7.1.1) with the raw label `label`, on the backend's `RSAEP`.
fn oaep_encrypt<C: Crypto>(
    rng: &mut C::Rng,
    key: &RsaPublicKey<C>,
    hash: TpmiAlgHash,
    label: &[u8],
    message: &[u8],
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let k = usize::from(key.bits().as_u16()) / 8;
    let h_len = hash.digest_size();
    if k < 2 * h_len + 2 || message.len() > k - 2 * h_len - 2 {
        return Ok(None);
    }
    // EM = 0x00 || maskedSeed || maskedDB, DB = lHash || PS || 0x01 || M.
    let mut em = [0u8; MAX_MODULUS];
    let em = &mut em[..k];
    let (seed, db) = em[1..].split_at_mut(h_len);
    let mut l_hash = [0u8; MAX_DIGEST];
    let l_hash = tpm2::crypto::hash::<C>(hash, &[label], &mut l_hash)?;
    db[..h_len].copy_from_slice(l_hash.digest());
    let one = db.len() - message.len() - 1;
    db[one] = 0x01;
    db[one + 1..].copy_from_slice(message);
    rng.fill_bytes(seed)?;
    mgf1_xor::<C>(hash, seed, db)?;
    mgf1_xor::<C>(hash, db, seed)?;
    Ok(key
        .encrypt(rng, RsaEncryptScheme::Raw, em, out)?
        .map(|c| c.as_slice().len()))
}

/// RSAES-OAEP-DECRYPT (RFC 8017, 7.1.2) with the raw label `label`, on the backend's `RSADP`.
fn oaep_decrypt<C: Crypto>(
    rng: &mut C::Rng,
    key: &RsaPrivateKey<C>,
    hash: TpmiAlgHash,
    label: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let k = usize::from(key.bits().as_u16()) / 8;
    let h_len = hash.digest_size();
    if k < 2 * h_len + 2 {
        return Ok(None);
    }
    let mut em = [0u8; MAX_MODULUS];
    let Some(decrypted) = key.decrypt(rng, RsaEncryptScheme::Raw, ciphertext, &mut em)? else {
        return Ok(None);
    };
    if decrypted.as_slice().len() != k {
        return Err(CryptoError::Internal);
    }
    let em = &mut em[..k];
    let y = em[0];
    let (seed, db) = em[1..].split_at_mut(h_len);
    mgf1_xor::<C>(hash, db, seed)?;
    mgf1_xor::<C>(hash, seed, db)?;
    let mut l_hash = [0u8; MAX_DIGEST];
    let l_hash = tpm2::crypto::hash::<C>(hash, &[label], &mut l_hash)?;
    let (l_hash_db, rest) = db.split_at(h_len);
    let start = rest.iter().position(|&b| b != 0);
    let valid = y == 0 && C::ct_eq(l_hash_db, l_hash.digest());
    match start {
        Some(i) if valid && rest[i] == 0x01 => {
            let message = &rest[i + 1..];
            out.get_mut(..message.len())
                .ok_or(CryptoError::Internal)?
                .copy_from_slice(message);
            Ok(Some(message.len()))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2::TpmiRsaKeyBits;
    use tpm2::crypto::Random;
    #[cfg(feature = "dev_crypto_bssl")]
    use tpm2_crypto_bssl::BsslCryptoProvider as Dev;
    #[cfg(feature = "dev_crypto_crux")]
    use tpm2_crypto_crux::CruxCryptoProvider as Dev;
    #[cfg(feature = "dev_crypto_rust")]
    use tpm2_crypto_rust::RustCryptoProvider as Dev;

    fn key() -> (RsaPrivateKey<Dev>, RsaPublicKey<Dev>) {
        let mut rng = Dev::from_seed(b"engine OAEP test key").unwrap();
        let private = RsaPrivateKey::<Dev>::generate(&mut rng, TpmiRsaKeyBits::Rsa2048, 0).unwrap();
        let mut n = [0u8; MAX_MODULUS];
        let n = private.modulus(&mut n).unwrap();
        let public = RsaPublicKey::<Dev>::load(TpmiRsaKeyBits::Rsa2048, 0, n)
            .unwrap()
            .unwrap();
        (private, public)
    }

    /// The engine's OAEP and the backend's agree for a C-string label, in both directions.
    #[test]
    fn engine_oaep_matches_the_backend() {
        let (private, public) = key();
        let mut rng = Dev::from_entropy().unwrap();
        let label = b"DUPLICATE\0";
        let message = [0x5au8; 32];
        for hash in [TpmiAlgHash::Sha1, TpmiAlgHash::Sha256] {
            let (mut ct, mut pt) = ([0u8; MAX_MODULUS], [0u8; MAX_MODULUS]);
            let len = oaep_encrypt(&mut rng, &public, hash, label, &message, &mut ct)
                .unwrap()
                .unwrap();
            let out = rsa_decrypt(
                &mut rng,
                &private,
                Alg::OAEP,
                hash.into(),
                label,
                &ct[..len],
                &mut pt,
            )
            .unwrap()
            .unwrap();
            assert_eq!(pt[..out], message);

            let len = rsa_encrypt(
                &mut rng,
                &public,
                Alg::OAEP,
                hash.into(),
                label,
                &message,
                &mut ct,
            )
            .unwrap()
            .unwrap();
            let out = oaep_decrypt(&mut rng, &private, hash, label, &ct[..len], &mut pt)
                .unwrap()
                .unwrap();
            assert_eq!(pt[..out], message);
            // A different label does not decrypt.
            assert_eq!(
                oaep_decrypt(
                    &mut rng,
                    &private,
                    hash,
                    b"DUPLICATE\0\0",
                    &ct[..len],
                    &mut pt
                ),
                Ok(None)
            );
        }
    }

    /// A label with an embedded zero octet round-trips through the engine's OAEP.
    #[test]
    fn labels_with_embedded_zeros_round_trip() {
        let (private, public) = key();
        let mut rng = Dev::from_entropy().unwrap();
        let label = b"A\0B\0";
        let (mut ct, mut pt) = ([0u8; MAX_MODULUS], [0u8; MAX_MODULUS]);
        let hash = Alg::SHA256;
        let len = rsa_encrypt(
            &mut rng,
            &public,
            Alg::OAEP,
            hash,
            label,
            b"secret",
            &mut ct,
        )
        .unwrap()
        .unwrap();
        let out = rsa_decrypt(
            &mut rng,
            &private,
            Alg::OAEP,
            hash,
            label,
            &ct[..len],
            &mut pt,
        )
        .unwrap()
        .unwrap();
        assert_eq!(&pt[..out], b"secret");
        assert_eq!(
            rsa_decrypt(
                &mut rng,
                &private,
                Alg::OAEP,
                hash,
                b"A\0",
                &ct[..len],
                &mut pt
            ),
            Ok(None)
        );
    }
}
