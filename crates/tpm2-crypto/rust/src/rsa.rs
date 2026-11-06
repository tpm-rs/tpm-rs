//! RSA (`rsa`): key generation and loading, raw (`TPM_ALG_NULL`), `RSAES-OAEP`,
//! `RSAES-PKCS1-v1_5`, `RSASSA-PKCS1-v1_5` and `RSASSA-PSS`, for RSA-1024/2048/3072/4096.
//!
//! `RSAES-OAEP` (any label bytes) and `RSASSA-PSS` verification (any salt length, TPM 2.0
//! `PssDecode`) are implemented here on the raw RSA primitives of the `rsa` crate, which supports
//! neither (its OAEP labels are strings and its PSS verification takes a fixed salt length).

use crate::{RngAdapter, RustCryptoProvider};
use rsa::BigUint;
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use sha2::Digest;
use subtle::{Choice, ConditionallySelectable as _, ConstantTimeEq as _};
use tpm2::crypto::backend::{PrivateKey, Rsa, RsaKey};
use tpm2::crypto::{CryptoError, Rng};
use tpm2::{TpmiAlgHash, TpmtHa};

/// Runs `$body` with `$D` bound to the RustCrypto digest type of the hash algorithm `$hash`,
/// returning `Err(CryptoError::Unsupported)` for other hash algorithms.
macro_rules! with_digest {
    ($hash:expr, $D:ident => $body:expr) => {
        match $hash {
            TpmiAlgHash::Sha1 => {
                type $D = sha1::Sha1;
                $body
            }
            TpmiAlgHash::Sha256 => {
                type $D = sha2::Sha256;
                $body
            }
            TpmiAlgHash::Sha384 => {
                type $D = sha2::Sha384;
                $body
            }
            #[cfg(feature = "sha512")]
            TpmiAlgHash::Sha512 => {
                type $D = sha2::Sha512;
                $body
            }
            #[allow(unreachable_patterns)]
            _ => return Err(CryptoError::Unsupported),
        }
    };
}

/// Writes `value` big-endian into `out`, left-padded with zeros ([`CryptoError::Internal`] if
/// it does not fit).
fn write_be(value: &BigUint, out: &mut [u8]) -> Result<(), CryptoError> {
    let bytes = value.to_bytes_be();
    if bytes.len() > out.len() {
        return Err(CryptoError::Internal);
    }
    let (zeros, rest) = out.split_at_mut(out.len() - bytes.len());
    zeros.fill(0);
    rest.copy_from_slice(&bytes);
    Ok(())
}

/// XORs `MGF1(seed, mask.len())` with the hash function `D` (RFC 8017, B.2.1) into `mask`.
fn mgf1_xor<D: Digest>(seed: &[u8], mask: &mut [u8]) {
    for (counter, chunk) in mask.chunks_mut(<D as Digest>::output_size()).enumerate() {
        let block = D::new()
            .chain_update(seed)
            .chain_update((counter as u32).to_be_bytes())
            .finalize();
        for (byte, m) in chunk.iter_mut().zip(block.iter()) {
            *byte ^= m;
        }
    }
}

/// `EME-OAEP` encoding (RFC 8017, 7.1.1 step 2) of `m` with the label `label` and the hash
/// function `D` into `em`, with the random seed from `rng`: `None` if `m` is too long.
fn oaep_encode<D: Digest, R: Rng>(
    rng: &mut R,
    label: &[u8],
    m: &[u8],
    em: &mut [u8],
) -> Result<Option<()>, CryptoError> {
    let h_len = <D as Digest>::output_size();
    let k = em.len();
    if k < 2 * h_len + 2 || m.len() > k - 2 * h_len - 2 {
        return Ok(None);
    }
    em.fill(0);
    let (seed, db) = em[1..].split_at_mut(h_len);
    db[..h_len].copy_from_slice(&D::digest(label));
    let db_len = db.len();
    db[db_len - m.len() - 1] = 0x01;
    db[db_len - m.len()..].copy_from_slice(m);
    rng.fill_bytes(seed)?;
    mgf1_xor::<D>(seed, db);
    mgf1_xor::<D>(db, seed);
    Ok(Some(()))
}

/// `EME-OAEP` decoding (RFC 8017, 7.1.2 step 3) of `em` with the label `label` and the hash
/// function `D`, in constant time until the validity of the padding is known: the message is
/// `em[offset..]` for the returned `Some(offset)`, or `None` if the padding is invalid.
fn oaep_decode<D: Digest>(label: &[u8], em: &mut [u8]) -> Option<usize> {
    let h_len = <D as Digest>::output_size();
    let k = em.len();
    if k < 2 * h_len + 2 {
        return None;
    }
    let (y, rest) = em.split_at_mut(1);
    let (seed, db) = rest.split_at_mut(h_len);
    mgf1_xor::<D>(db, seed);
    mgf1_xor::<D>(seed, db);
    let mut good = y[0].ct_eq(&0) & db[..h_len].ct_eq(&D::digest(label)[..]);
    // The first nonzero byte after `lHash'` must be the 0x01 separator.
    let mut looking = Choice::from(1);
    let mut index = 0u32;
    let mut invalid = Choice::from(0);
    for (i, &byte) in db[h_len..].iter().enumerate() {
        let is_one = byte.ct_eq(&1);
        let is_zero = byte.ct_eq(&0);
        index.conditional_assign(&(i as u32), looking & is_one);
        invalid |= looking & !is_one & !is_zero;
        looking &= !is_one;
    }
    good &= !invalid & !looking;
    bool::from(good).then_some(1 + 2 * h_len + index as usize + 1)
}

/// `EMSA-PSS` verification (RFC 8017, 9.1.2) of the encoded message `em` (`8 * em.len() - 1`
/// bits) for `m_hash` with the hash function `D`, accepting any salt length (TPM 2.0
/// `PssDecode`).
fn pss_verify<D: Digest>(m_hash: &[u8], em: &mut [u8]) -> bool {
    let h_len = <D as Digest>::output_size();
    let em_len = em.len();
    if m_hash.len() != h_len || em_len < h_len + 2 || em[em_len - 1] != 0xbc || em[0] & 0x80 != 0 {
        return false;
    }
    let (db, rest) = em.split_at_mut(em_len - h_len - 1);
    let h = &rest[..h_len];
    mgf1_xor::<D>(h, db);
    db[0] &= 0x7f;
    let Some(separator) = db.iter().position(|&b| b != 0) else {
        return false;
    };
    if db[separator] != 0x01 {
        return false;
    }
    let salt = &db[separator + 1..];
    let h2 = D::new()
        .chain_update([0u8; 8])
        .chain_update(m_hash)
        .chain_update(salt)
        .finalize();
    h2[..] == *h
}

/// A validated RSA public key with a `MOD`-byte modulus, for `RustCryptoProvider`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCryptoRsaPublic<const MOD: usize> {
    key: rsa::RsaPublicKey,
    exponent: u32,
}

impl<const MOD: usize> RustCryptoRsaPublic<MOD> {
    /// The public key of the `rsa` crate.
    pub fn key(&self) -> &rsa::RsaPublicKey {
        &self.key
    }

    /// Decodes `value` (`MOD` bytes): `None` unless it is smaller than the modulus.
    fn below_modulus(&self, value: &[u8; MOD]) -> Option<BigUint> {
        let value = BigUint::from_bytes_be(value);
        (value < *self.key.n()).then_some(value)
    }

    /// `m^e mod n` (`RSAEP`, `RSAVP1`) of `m < n`, written into `out`.
    fn public_op(&self, m: &BigUint, out: &mut [u8; MOD]) -> Result<(), CryptoError> {
        let c = rsa::hazmat::rsa_encrypt(&self.key, m).map_err(|_| CryptoError::Internal)?;
        write_be(&c, out)
    }
}

/// An RSA private key with a `MOD`-byte modulus and `PRIME`-byte prime factors, for
/// `RustCryptoProvider` (any random number generator).
#[derive(Clone, Debug)]
pub struct RustCryptoRsa<const MOD: usize, const PRIME: usize> {
    key: rsa::RsaPrivateKey,
    public: RustCryptoRsaPublic<MOD>,
}

impl<const MOD: usize, const PRIME: usize> RustCryptoRsa<MOD, PRIME> {
    /// The private key of the `rsa` crate.
    pub fn key(&self) -> &rsa::RsaPrivateKey {
        &self.key
    }

    /// Wraps the private key `key` with the public exponent `exponent`.
    fn new(mut key: rsa::RsaPrivateKey, exponent: u32) -> Result<Self, CryptoError> {
        key.precompute().map_err(|_| CryptoError::Internal)?;
        let public = RustCryptoRsaPublic {
            key: key.to_public_key(),
            exponent,
        };
        Ok(Self { key, public })
    }

    /// `c^d mod n` (`RSADP`, `RSASP1`) of `c < n` with blinding from `rng`, written into `out`.
    fn private_op<R: Rng>(
        &self,
        rng: &mut R,
        c: &BigUint,
        out: &mut [u8; MOD],
    ) -> Result<(), CryptoError> {
        let mut rng = RngAdapter::new(rng);
        let m = rsa::hazmat::rsa_decrypt_and_check(&self.key, Some(&mut rng), c)
            .map_err(|_| CryptoError::Internal)?;
        let m = rng.finish(m)?;
        write_be(&m, out)
    }

    /// Copies the `rsa` crate's output `bytes` (`MOD` bytes) into `out`.
    fn output(bytes: &[u8], out: &mut [u8; MOD]) -> Result<(), CryptoError> {
        if bytes.len() != MOD {
            return Err(CryptoError::Internal);
        }
        out.copy_from_slice(bytes);
        Ok(())
    }
}

impl<const MOD: usize, const PRIME: usize, R: Rng> PrivateKey<MOD, PRIME, R, u32>
    for RustCryptoRsa<MOD, PRIME>
{
    type PublicKey = RustCryptoRsaPublic<MOD>;

    /// Generates a key whose modulus has exactly `8 * MOD` bits (and whose primes have
    /// `4 * MOD` bits); `Unsupported` for exponents that the `rsa` crate rejects.
    fn generate(rng: &mut R, exponent: u32) -> Result<Self, CryptoError> {
        let mut rng = RngAdapter::new(rng);
        let key = rsa::RsaPrivateKey::new_with_exp(&mut rng, 8 * MOD, &BigUint::from(exponent));
        let key = rng.finish(key)?.map_err(|_| CryptoError::Unsupported)?;
        if key.n().bits() != 8 * MOD || key.primes().iter().any(|p| p.bits() > 8 * PRIME) {
            return Err(CryptoError::Internal);
        }
        Self::new(key, exponent)
    }

    /// Loads the key of either prime factor: `None` unless `private` divides the modulus into
    /// two factors of (almost) the same size that form a valid key with the exponent.
    fn load(public: Self::PublicKey, private: &[u8; PRIME]) -> Result<Option<Self>, CryptoError> {
        let n = public.key.n();
        let p = BigUint::from_bytes_be(private);
        let one = BigUint::from(1u32);
        if p <= one || (n % &p) != BigUint::default() {
            return Ok(None);
        }
        let q = n / &p;
        if q <= one || p.bits().abs_diff(q.bits()) > 1 {
            return Ok(None);
        }
        let Ok(key) = rsa::RsaPrivateKey::from_p_q(p, q, public.key.e().clone()) else {
            return Ok(None);
        };
        if key.n() != n {
            return Ok(None);
        }
        Self::new(key, public.exponent).map(Some)
    }

    /// Writes the first prime factor of the key (the one it was loaded with).
    fn store(&self, out: &mut [u8; PRIME]) -> Result<(), CryptoError> {
        let p = self.key.primes().first().ok_or(CryptoError::Internal)?;
        write_be(p, out)
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }

    /// `None` unless the modulus has its most significant bit set and is odd (TPM 2.0 Part 1),
    /// and the `rsa` crate accepts the key.
    fn load_public(
        exponent: u32,
        public: &[u8; MOD],
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        if MOD == 0 || public[0] & 0x80 == 0 || public[MOD - 1] & 1 == 0 {
            return Ok(None);
        }
        let n = BigUint::from_bytes_be(public);
        Ok(rsa::RsaPublicKey::new(n, BigUint::from(exponent))
            .ok()
            .map(|key| RustCryptoRsaPublic { key, exponent }))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; MOD]) -> Result<(), CryptoError> {
        write_be(public.key.n(), out)
    }
}

impl<const MOD: usize, const PRIME: usize, R: Rng> RsaKey<MOD, PRIME, R>
    for RustCryptoRsa<MOD, PRIME>
{
    fn exponent(public: &Self::PublicKey) -> u32 {
        public.exponent
    }

    fn raw_encrypt(
        public: &Self::PublicKey,
        m: &[u8; MOD],
        out: &mut [u8; MOD],
    ) -> Result<Option<()>, CryptoError> {
        let Some(m) = public.below_modulus(m) else {
            return Ok(None);
        };
        public.public_op(&m, out).map(Some)
    }

    fn raw_decrypt(
        &self,
        rng: &mut R,
        c: &[u8; MOD],
        out: &mut [u8; MOD],
    ) -> Result<Option<()>, CryptoError> {
        let Some(c) = self.public.below_modulus(c) else {
            return Ok(None);
        };
        self.private_op(rng, &c, out).map(Some)
    }

    fn oaep_encrypt(
        public: &Self::PublicKey,
        rng: &mut R,
        hash: TpmiAlgHash,
        label: &[u8],
        m: &[u8],
        out: &mut [u8; MOD],
    ) -> Result<Option<()>, CryptoError> {
        let mut em = [0u8; MOD];
        with_digest!(hash, D => {
            if oaep_encode::<D, R>(rng, label, m, &mut em)?.is_none() {
                return Ok(None);
            }
        });
        // `em` starts with a zero byte, so it is smaller than the modulus.
        public
            .public_op(&BigUint::from_bytes_be(&em), out)
            .map(Some)
    }

    fn oaep_decrypt(
        &self,
        rng: &mut R,
        hash: TpmiAlgHash,
        label: &[u8],
        c: &[u8; MOD],
        out: &mut [u8; MOD],
    ) -> Result<Option<usize>, CryptoError> {
        let Some(c) = self.public.below_modulus(c) else {
            return Ok(None);
        };
        let mut em = [0u8; MOD];
        self.private_op(rng, &c, &mut em)?;
        let offset = with_digest!(hash, D => oaep_decode::<D>(label, &mut em));
        let result = offset.map(|offset| {
            let len = MOD - offset;
            out[..len].copy_from_slice(&em[offset..]);
            len
        });
        em.fill(0);
        Ok(result)
    }

    fn rsaes_encrypt(
        public: &Self::PublicKey,
        rng: &mut R,
        m: &[u8],
        out: &mut [u8; MOD],
    ) -> Result<Option<()>, CryptoError> {
        if m.len() + 11 > MOD {
            return Ok(None);
        }
        let mut rng = RngAdapter::new(rng);
        let c = public.key.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, m);
        let c = rng.finish(c)?.map_err(|_| CryptoError::Internal)?;
        Self::output(&c, out).map(Some)
    }

    fn rsaes_decrypt(
        &self,
        rng: &mut R,
        c: &[u8; MOD],
        out: &mut [u8; MOD],
    ) -> Result<Option<usize>, CryptoError> {
        if self.public.below_modulus(c).is_none() {
            return Ok(None);
        }
        let mut rng = RngAdapter::new(rng);
        let m = self.key.decrypt_blinded(&mut rng, rsa::Pkcs1v15Encrypt, c);
        let Ok(m) = rng.finish(m)? else {
            return Ok(None);
        };
        out[..m.len()].copy_from_slice(&m);
        Ok(Some(m.len()))
    }

    fn rsassa_sign(
        &self,
        rng: &mut R,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD],
    ) -> Result<(), CryptoError> {
        let mut rng = RngAdapter::new(rng);
        let sig = with_digest!(digest.hash_alg(), D => self.key.sign_with_rng(
            &mut rng,
            rsa::Pkcs1v15Sign::new::<D>(),
            digest.digest(),
        ));
        let sig = rng.finish(sig)?.map_err(|_| CryptoError::Internal)?;
        Self::output(&sig, out)
    }

    fn rsassa_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD],
    ) -> Result<bool, CryptoError> {
        let verified = with_digest!(digest.hash_alg(), D => public.key.verify(
            rsa::Pkcs1v15Sign::new::<D>(),
            digest.digest(),
            sig,
        ));
        Ok(verified.is_ok())
    }

    /// Uses the largest salt length up to the digest size (`min(hLen, MOD - hLen - 2)`, as the
    /// modulus has exactly `8 * MOD` bits).
    fn rsapss_sign(
        &self,
        rng: &mut R,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD],
    ) -> Result<(), CryptoError> {
        let h_len = digest.digest().len();
        let salt_len = h_len.min(MOD.checked_sub(h_len + 2).ok_or(CryptoError::Internal)?);
        let mut rng = RngAdapter::new(rng);
        let sig = with_digest!(digest.hash_alg(), D => self.key.sign_with_rng(
            &mut rng,
            rsa::Pss::new_with_salt::<D>(salt_len),
            digest.digest(),
        ));
        let sig = rng.finish(sig)?.map_err(|_| CryptoError::Internal)?;
        Self::output(&sig, out)
    }

    fn rsapss_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD],
    ) -> Result<bool, CryptoError> {
        let Some(s) = public.below_modulus(sig) else {
            return Ok(false);
        };
        let mut em = [0u8; MOD];
        public.public_op(&s, &mut em)?;
        Ok(with_digest!(digest.hash_alg(), D => pss_verify::<D>(digest.digest(), &mut em)))
    }

    fn store_crt(&self, out: &mut [[u8; PRIME]; 5]) -> Result<(), CryptoError> {
        let [first, second] = self.key.primes() else {
            return Err(CryptoError::Internal);
        };
        // The larger prime first, so that `qInv` is the inverse of the smaller one.
        let (p, q) = if first >= second {
            (first, second)
        } else {
            (second, first)
        };
        let key = rsa::RsaPrivateKey::from_components(
            self.key.n().clone(),
            self.key.e().clone(),
            self.key.d().clone(),
            alloc::vec![p.clone(), q.clone()],
        )
        .map_err(|_| CryptoError::Internal)?;
        let (Some(dp), Some(dq), Some(qinv)) = (key.dp(), key.dq(), key.qinv()) else {
            return Err(CryptoError::Internal);
        };
        let qinv = qinv.to_biguint().ok_or(CryptoError::Internal)?;
        for (value, out) in [p, q, dp, dq, &qinv].into_iter().zip(out.iter_mut()) {
            write_be(value, out)?;
        }
        Ok(())
    }
}

/// RSA-1024 keys for `RustCryptoProvider`.
pub type RustCryptoRsa1024 = RustCryptoRsa<128, 64>;
/// RSA-2048 keys for `RustCryptoProvider`.
pub type RustCryptoRsa2048 = RustCryptoRsa<256, 128>;
/// RSA-3072 keys for `RustCryptoProvider`.
pub type RustCryptoRsa3072 = RustCryptoRsa<384, 192>;
/// RSA-4096 keys for `RustCryptoProvider`.
pub type RustCryptoRsa4096 = RustCryptoRsa<512, 256>;

/// RSA-1024/2048/3072/4096 with SHA-1/256/384/512 for OAEP and the signature schemes (other
/// hash algorithms are `Unsupported`).
impl Rsa for RustCryptoProvider {
    type Rsa1024 = RustCryptoRsa1024;
    type Rsa2048 = RustCryptoRsa2048;
    type Rsa3072 = RustCryptoRsa3072;
    type Rsa4096 = RustCryptoRsa4096;
}
