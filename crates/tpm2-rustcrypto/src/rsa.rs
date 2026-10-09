//! [`Rsa`] keys and encryption.

use core::fmt;

use ::rsa::{
    BigUint, Pkcs1v15Encrypt,
    hazmat::{rsa_decrypt_and_check, rsa_encrypt},
    traits::{PrivateKeyParts, PublicKeyParts},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use tpm2::{
    Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmiAlgHash, TpmiRsaKeyBits,
    crypto::{CryptoError, Random, Rng, Rsa, RsaEncryptScheme},
};

use crate::{ChaChaRng, RustCrypto, hash::hash_concat, xor};

/// The public exponent used when a TPM key specifies an exponent of `0`.
const DEFAULT_EXPONENT: u32 = 65537;

/// RSA public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPublicKey {
    bits: TpmiRsaKeyBits,
    exponent: u32,
    pub(crate) key: ::rsa::RsaPublicKey,
}

impl RsaPublicKey {
    /// Returns the size of the modulus in bytes (`k` in RFC 8017).
    pub(crate) fn size(&self) -> usize {
        usize::from(u16::from(self.bits)) / 8
    }
}

impl tpm2::crypto::RsaPublicKey for RsaPublicKey {
    fn bits(&self) -> TpmiRsaKeyBits {
        self.bits
    }

    fn exponent(&self) -> u32 {
        self.exponent
    }

    fn modulus<'a>(
        &self,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        let out = prefix(out, self.size())?;
        write_be(self.key.n(), out)?;
        to_tpm2b(out)
    }
}

/// RSA private key.
#[derive(Clone)]
pub struct RsaPrivateKey {
    pub(crate) public: RsaPublicKey,
    pub(crate) key: ::rsa::RsaPrivateKey,
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl tpm2::crypto::RsaPrivateKey for RsaPrivateKey {
    type PublicKey = RsaPublicKey;

    fn public_key(&self) -> &RsaPublicKey {
        &self.public
    }

    fn prime_p<'a>(
        &self,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES],
    ) -> Result<Tpm2bPrivateKeyRsa<'a>, CryptoError> {
        let p = self.key.primes().first().ok_or(CryptoError::Internal)?;
        let out = prefix(out, self.public.size() / 2)?;
        write_be(p, out)?;
        Tpm2bPrivateKeyRsa::new(out).ok_or(CryptoError::Internal)
    }
}

impl Rsa for RustCrypto {
    type PublicKey = RsaPublicKey;
    type PrivateKey = RsaPrivateKey;

    fn load_public(
        &self,
        bits: TpmiRsaKeyBits,
        exponent: u32,
        modulus: Tpm2bPublicKeyRsa<'_>,
    ) -> Result<Option<RsaPublicKey>, CryptoError> {
        let exponent = effective_exponent(exponent);
        let modulus = modulus.as_slice();
        let n = BigUint::from_bytes_be(modulus);
        // The modulus must be exactly `bits` long (with its top bit set).
        let bits_usize = usize::from(u16::from(bits));
        if modulus.len() != bits_usize / 8 || n.bits() != bits_usize {
            return Ok(None);
        }
        // This rejects even moduli, and exponents that are even, less than
        // `3`, or not less than the modulus.
        let key = ::rsa::RsaPublicKey::new(n, BigUint::from(exponent)).ok();
        Ok(key.map(|key| RsaPublicKey {
            bits,
            exponent,
            key,
        }))
    }

    fn load_private(
        &self,
        public: RsaPublicKey,
        prime_p: Tpm2bPrivateKeyRsa<'_>,
    ) -> Result<Option<RsaPrivateKey>, CryptoError> {
        let p = BigUint::from_bytes_be(prime_p.as_slice());
        let n = public.key.n();
        // `p` must be a factor of `n` greater than `1`, and no longer than
        // half of the modulus (which makes `q` greater than `1` too).
        let half_bits = usize::from(u16::from(public.bits)) / 2;
        if p <= BigUint::from(1u8) || p.bits() > half_bits || n % &p != BigUint::default() {
            return Ok(None);
        }
        let q = n / &p;
        let Ok(key) = ::rsa::RsaPrivateKey::from_p_q(p, q, public.key.e().clone()) else {
            return Ok(None);
        };
        // Pairwise consistency check, as `from_p_q` doesn't check that `p`
        // and `q` are prime.
        let m = BigUint::from(2u8);
        let c = rsa_encrypt(&key, &m).map_err(|_| CryptoError::Internal)?;
        let mut rng = self.rng()?;
        if rsa_decrypt_and_check(&key, Some(&mut rng.0), &c).ok() != Some(m) {
            return Ok(None);
        }
        Ok(Some(RsaPrivateKey { public, key }))
    }

    fn generate_key(
        &self,
        rng: &mut ChaChaRng,
        bits: TpmiRsaKeyBits,
        exponent: u32,
    ) -> Result<RsaPrivateKey, CryptoError> {
        let exponent = effective_exponent(exponent);
        // The exponent must be odd and at least `3` (key generation would
        // never terminate with an even exponent).
        if exponent < 3 || exponent.is_multiple_of(2) {
            return Err(CryptoError::Unsupported);
        }
        let key = ::rsa::RsaPrivateKey::new_with_exp(
            &mut rng.0,
            usize::from(u16::from(bits)),
            &BigUint::from(exponent),
        )
        .map_err(|_| CryptoError::Internal)?;
        let public = RsaPublicKey {
            bits,
            exponent,
            key: key.to_public_key(),
        };
        Ok(RsaPrivateKey { public, key })
    }

    fn encrypt<'a>(
        &self,
        rng: &mut ChaChaRng,
        key: &RsaPublicKey,
        scheme: RsaEncryptScheme<'_>,
        plaintext: &[u8],
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Option<Tpm2bPublicKeyRsa<'a>>, CryptoError> {
        let em = prefix(out, key.size())?;
        match scheme {
            RsaEncryptScheme::Raw => {
                // `plaintext` can have more bytes than the modulus as long as
                // the extra (most significant) bytes are zero.
                let skip = plaintext.iter().take_while(|&&b| b == 0).count();
                let value = plaintext.get(skip..).unwrap_or_default();
                let Some(pad) = em.len().checked_sub(value.len()) else {
                    return Ok(None);
                };
                let (zeros, rest) = em.split_at_mut(pad);
                zeros.fill(0);
                rest.copy_from_slice(value);
            }
            RsaEncryptScheme::Rsaes => {
                // The rsa crate does both the padding and RSAEP.
                return match key.key.encrypt(&mut rng.0, Pkcs1v15Encrypt, plaintext) {
                    Ok(ciphertext) if ciphertext.len() == em.len() => {
                        em.copy_from_slice(&ciphertext);
                        to_tpm2b(em).map(Some)
                    }
                    Err(::rsa::Error::MessageTooLong) => Ok(None),
                    _ => Err(CryptoError::Internal),
                };
            }
            RsaEncryptScheme::Oaep { hash, label } => {
                if !oaep_encode(rng, hash, label, plaintext, em)? {
                    return Ok(None);
                }
            }
        }
        // RSAEP: the message representative must be less than the modulus.
        let m = BigUint::from_bytes_be(em);
        if &m >= key.key.n() {
            return Ok(None);
        }
        let c = rsa_encrypt(&key.key, &m).map_err(|_| CryptoError::Internal)?;
        write_be(&c, em)?;
        to_tpm2b(em).map(Some)
    }

    fn decrypt<'a>(
        &self,
        key: &RsaPrivateKey,
        scheme: RsaEncryptScheme<'_>,
        ciphertext: &[u8],
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Option<Tpm2bPublicKeyRsa<'a>>, CryptoError> {
        let k = key.public.size();
        // The ciphertext must be the size of the modulus, and less than it.
        let c = BigUint::from_bytes_be(ciphertext);
        if ciphertext.len() != k || &c >= key.key.n() {
            return Ok(None);
        }
        // Blind the private key operation with a fresh RNG.
        let mut rng = self.rng()?;
        match scheme {
            RsaEncryptScheme::Raw => {
                let m = private_op(&key.key, &mut rng, &c)?;
                let out = prefix(out, k)?;
                write_be(&m, out)?;
                to_tpm2b(out).map(Some)
            }
            RsaEncryptScheme::Rsaes => {
                match key
                    .key
                    .decrypt_blinded(&mut rng.0, Pkcs1v15Encrypt, ciphertext)
                {
                    Ok(message) => {
                        let out = prefix(out, message.len())?;
                        out.copy_from_slice(&message);
                        to_tpm2b(out).map(Some)
                    }
                    Err(::rsa::Error::Decryption) => Ok(None),
                    Err(_) => Err(CryptoError::Internal),
                }
            }
            RsaEncryptScheme::Oaep { hash, label } => {
                let m = private_op(&key.key, &mut rng, &c)?;
                let mut em = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
                let em = prefix(&mut em, k)?;
                write_be(&m, em)?;
                oaep_decode(hash, label, em, out)
            }
        }
    }
}

/// Returns the public exponent the TPM uses for `exponent`.
fn effective_exponent(exponent: u32) -> u32 {
    if exponent == 0 {
        DEFAULT_EXPONENT
    } else {
        exponent
    }
}

/// Returns the first `len` bytes of `out`.
pub(crate) fn prefix(out: &mut [u8], len: usize) -> Result<&mut [u8], CryptoError> {
    out.get_mut(..len).ok_or(CryptoError::Internal)
}

/// Writes `value` into all of `out` as a big-endian integer, left-padded
/// with zeros.
pub(crate) fn write_be(value: &BigUint, out: &mut [u8]) -> Result<(), CryptoError> {
    let bytes = value.to_bytes_be();
    let pad = out
        .len()
        .checked_sub(bytes.len())
        .ok_or(CryptoError::Internal)?;
    let (zeros, rest) = out.split_at_mut(pad);
    zeros.fill(0);
    rest.copy_from_slice(&bytes);
    Ok(())
}

pub(crate) fn to_tpm2b(buf: &[u8]) -> Result<Tpm2bPublicKeyRsa<'_>, CryptoError> {
    Tpm2bPublicKeyRsa::new(buf).ok_or(CryptoError::Internal)
}

/// Computes the RSA private key operation `c^d mod n` (RSADP), blinded with
/// `rng` and checked by re-encrypting the result.
pub(crate) fn private_op(
    key: &::rsa::RsaPrivateKey,
    rng: &mut ChaChaRng,
    c: &BigUint,
) -> Result<BigUint, CryptoError> {
    rsa_decrypt_and_check(key, Some(&mut rng.0), c).map_err(|_| CryptoError::Internal)
}

/// XORs `MGF1(seed)` into `out` (RFC 8017, Appendix B.2.1).
pub(crate) fn mgf1_xor(hash: TpmiAlgHash, seed: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    for (counter, chunk) in (0u32..).zip(out.chunks_mut(hash.digest_size())) {
        let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mask = hash_concat(hash, &[seed, &counter.to_be_bytes()], &mut buf)?;
        xor(chunk, mask);
    }
    Ok(())
}

/// EME-OAEP encoding (RFC 8017, Section 7.1.1, step 2) of `message` into all
/// of `em`.
///
/// Returns `false` if `message` is too long.
fn oaep_encode(
    rng: &mut ChaChaRng,
    hash: TpmiAlgHash,
    label: &[u8],
    message: &[u8],
    em: &mut [u8],
) -> Result<bool, CryptoError> {
    let h = hash.digest_size();
    // The message must fit: mLen <= k - 2 * hLen - 2
    let Some(max_len) = em.len().checked_sub(2 * h + 2) else {
        return Ok(false);
    };
    if message.len() > max_len {
        return Ok(false);
    }
    // EM = 0x00 || maskedSeed || maskedDB
    let (zero, rest) = em.split_first_mut().ok_or(CryptoError::Internal)?;
    *zero = 0;
    let (seed, db) = rest.split_at_mut(h);
    // DB = lHash || PS || 0x01 || M
    let mut lhash = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let lhash = hash_concat(hash, &[label], &mut lhash)?;
    let (db_lhash, ps_m) = db.split_at_mut(h);
    db_lhash.copy_from_slice(lhash);
    let (ps_one, m) = ps_m.split_at_mut(ps_m.len() - message.len());
    let (one, ps) = ps_one.split_last_mut().ok_or(CryptoError::Internal)?;
    ps.fill(0);
    *one = 0x01;
    m.copy_from_slice(message);

    rng.fill_bytes(seed)?;
    mgf1_xor(hash, seed, db)?;
    mgf1_xor(hash, db, seed)?;
    Ok(true)
}

/// EME-OAEP decoding (RFC 8017, Section 7.1.2, step 3) of `em` into `out`.
///
/// Returns `Ok(None)` if the padding is invalid. The padding is checked in
/// constant time.
fn oaep_decode<'a>(
    hash: TpmiAlgHash,
    label: &[u8],
    em: &mut [u8],
    out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
) -> Result<Option<Tpm2bPublicKeyRsa<'a>>, CryptoError> {
    let h = hash.digest_size();
    // Anything smaller can't be an OAEP-padded block.
    if em.len() < 2 * h + 2 {
        return Ok(None);
    }
    // EM = Y || maskedSeed || maskedDB
    let (y, rest) = em.split_first_mut().ok_or(CryptoError::Internal)?;
    let (seed, db) = rest.split_at_mut(h);
    mgf1_xor(hash, db, seed)?;
    mgf1_xor(hash, seed, db)?;

    // DB = lHash' || PS || 0x01 || M
    let mut lhash = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let lhash = hash_concat(hash, &[label], &mut lhash)?;
    let (db_lhash, ps_m) = db.split_at(h);
    let mut valid = y.ct_eq(&0) & db_lhash.ct_eq(lhash);
    // Find the 0x01 byte after PS (a run of zeros).
    let mut searching = Choice::from(1);
    let mut separator = 0u16;
    for (i, b) in (0u16..).zip(ps_m) {
        let is_zero = b.ct_eq(&0);
        let is_one = b.ct_eq(&1);
        separator.conditional_assign(&i, searching & is_one);
        valid &= !searching | is_zero | is_one;
        searching &= !is_one;
    }
    valid &= !searching;
    if !bool::from(valid) {
        return Ok(None);
    }

    let message = ps_m
        .get(usize::from(separator) + 1..)
        .ok_or(CryptoError::Internal)?;
    let out = prefix(out, message.len())?;
    out.copy_from_slice(message);
    to_tpm2b(out).map(Some)
}
