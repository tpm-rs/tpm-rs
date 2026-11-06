//! [`Rsa`] for [`CruxCryptoProvider`]: RSA-1024/2048/3072/4096 keys with the
//! RustCrypto `rsa` crate.
//!
//! `libcrux-rsa` only signs and verifies with RSA-PSS on fixed key sizes, so
//! every RSA operation uses RustCrypto `rsa`. Private key operations
//! (decryption, signing) are blinded with the [`CruxRng`] passed to them.
//!
//! RSA-PSS signing uses the salt length of TPM 2.0 `PssEncode`
//! (`min(hLen, MOD_SIZE - hLen - 2)`), and RSA-PSS verification accepts any salt
//! length (TPM 2.0 `PssDecode`), as [`RsaKey`] requires. RSAES-OAEP labels
//! must be valid UTF-8 (a limitation of `rsa` 0.9, whose labels are
//! `String`s): an OAEP operation with any other label returns `Ok(None)`.

use alloc::vec;
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use tpm2::crypto::CryptoError;
use tpm2::crypto::backend::{PrivateKey, Rsa, RsaKey};
use tpm2::{TpmiAlgHash, TpmtHa};

use crate::{CruxCryptoProvider, CruxRng};

impl Rsa for CruxCryptoProvider {
    type Rsa1024 = CruxRsaKey<128, 64>;
    type Rsa2048 = CruxRsaKey<256, 128>;
    type Rsa3072 = CruxRsaKey<384, 192>;
    type Rsa4096 = CruxRsaKey<512, 256>;
}

/// A validated RSA public key with a modulus of `MOD_SIZE` bytes.
#[derive(Clone, Debug)]
pub struct CruxRsaPublicKey<const MOD_SIZE: usize> {
    key: RsaPublicKey,
    exponent: u32,
}

/// A validated RSA private key with a modulus of `MOD_SIZE` bytes and primes
/// of `PRIME_SIZE` bytes, including its public key.
#[derive(Clone, Debug)]
pub struct CruxRsaKey<const MOD_SIZE: usize, const PRIME_SIZE: usize> {
    key: RsaPrivateKey,
    public: CruxRsaPublicKey<MOD_SIZE>,
}

/// Writes `value` big-endian into `out`, left-padded with zeros, or returns
/// [`CryptoError::Internal`] if it does not fit.
fn write_be(value: &BigUint, out: &mut [u8]) -> Result<(), CryptoError> {
    let bytes = value.to_bytes_be();
    let start = out
        .len()
        .checked_sub(bytes.len())
        .ok_or(CryptoError::Internal)?;
    out[..start].fill(0);
    out[start..].copy_from_slice(&bytes);
    Ok(())
}

/// Copies the `MOD_SIZE`-byte output of the `rsa` crate into `out`.
fn copy_exact(bytes: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    if bytes.len() != out.len() {
        return Err(CryptoError::Internal);
    }
    out.copy_from_slice(bytes);
    Ok(())
}

/// Copies a recovered message into the start of `out`, returning its length.
fn copy_message(bytes: &[u8], out: &mut [u8]) -> Result<Option<usize>, CryptoError> {
    let dest = out.get_mut(..bytes.len()).ok_or(CryptoError::Internal)?;
    dest.copy_from_slice(bytes);
    Ok(Some(bytes.len()))
}

/// Maps the result of an `rsa` encryption: a message that is too long for the
/// key is `Ok(None)`, any other failure [`CryptoError::Internal`].
fn encrypted(
    result: rsa::Result<alloc::vec::Vec<u8>>,
    out: &mut [u8],
) -> Result<Option<()>, CryptoError> {
    match result {
        Ok(ciphertext) => copy_exact(&ciphertext, out).map(Some),
        Err(rsa::Error::MessageTooLong) => Ok(None),
        Err(_) => Err(CryptoError::Internal),
    }
}

/// Runs `$body` with the type alias `$D` bound to the RustCrypto digest of the
/// tagged digest `$digest` (whose bytes are bound to `$d`), returning
/// [`CryptoError::Unsupported`] for other hash algorithms.
macro_rules! with_digest {
    ($digest:expr, |$d:ident: $D:ident| $body:expr) => {
        match $digest {
            TpmtHa::Sha1($d) => {
                type $D = sha1::Sha1;
                $body
            }
            TpmtHa::Sha256($d) => {
                type $D = sha2::Sha256;
                $body
            }
            TpmtHa::Sha384($d) => {
                type $D = sha2::Sha384;
                $body
            }
            #[cfg(feature = "sha512")]
            TpmtHa::Sha512($d) => {
                type $D = sha2::Sha512;
                $body
            }
            #[allow(unreachable_patterns)]
            _ => return Err(CryptoError::Unsupported),
        }
    };
}

/// Runs `$body` with the type alias `$D` bound to the RustCrypto digest of the
/// hash algorithm `$hash`, returning [`CryptoError::Unsupported`] for other
/// hash algorithms.
macro_rules! with_hash_alg {
    ($hash:expr, |$D:ident| $body:expr) => {
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

/// The RSAES-OAEP padding scheme with `D` for the label hash and MGF1, or
/// `None` if `label` is not valid UTF-8 (see the [module documentation](self)).
fn oaep<D>(label: &[u8]) -> Option<rsa::Oaep>
where
    D: 'static + rsa::sha2::Digest + rsa::sha2::digest::DynDigest + Send + Sync,
{
    if label.is_empty() {
        return Some(rsa::Oaep::new::<D>());
    }
    let label = core::str::from_utf8(label).ok()?;
    Some(rsa::Oaep::new_with_label::<D, _>(label))
}

/// XORs `MGF1(seed)` (RFC 8017, B.2.1) with the hash `D` into `out`.
fn mgf1_xor<D: sha2::Digest>(seed: &[u8], out: &mut [u8]) {
    for (counter, chunk) in (0u32..).zip(out.chunks_mut(<D as sha2::Digest>::output_size())) {
        let mut hasher = D::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let mask = hasher.finalize();
        for (byte, m) in chunk.iter_mut().zip(mask.iter()) {
            *byte ^= m;
        }
    }
}

/// `EMSA-PSS-VERIFY` (RFC 8017, 9.1.2) of the encoded message `em` (with
/// `emBits = 8 * em.len() - 1`) for the message hash `m_hash` with the hash
/// `D`, accepting any salt length (TPM 2.0 `PssDecode`).
///
/// This is a public key operation: it need not run in constant time.
fn emsa_pss_verify<D: sha2::Digest>(em: &mut [u8], m_hash: &[u8]) -> bool {
    let h_len = <D as sha2::Digest>::output_size();
    let em_len = em.len();
    if m_hash.len() != h_len || em_len < h_len + 2 || em[em_len - 1] != 0xbc {
        return false;
    }
    let (masked_db, rest) = em.split_at_mut(em_len - h_len - 1);
    let h = &rest[..h_len];
    // The leftmost `8 * emLen - emBits` (one) bit of the encoding must be zero.
    if masked_db[0] & 0x80 != 0 {
        return false;
    }
    mgf1_xor::<D>(h, masked_db);
    masked_db[0] &= 0x7f;
    let Some(separator) = masked_db.iter().position(|&b| b != 0) else {
        return false;
    };
    if masked_db[separator] != 0x01 {
        return false;
    }
    let salt = &masked_db[separator + 1..];
    let mut hasher = D::new();
    hasher.update([0u8; 8]);
    hasher.update(m_hash);
    hasher.update(salt);
    hasher.finalize()[..] == *h
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> PrivateKey<MOD_SIZE, PRIME_SIZE, CruxRng, u32>
    for CruxRsaKey<MOD_SIZE, PRIME_SIZE>
{
    type PublicKey = CruxRsaPublicKey<MOD_SIZE>;

    /// Generates a key of `8 * MOD_SIZE` bits with the public exponent
    /// `exponent` from `rng`.
    fn generate(rng: &mut CruxRng, exponent: u32) -> Result<Self, CryptoError> {
        let key = RsaPrivateKey::new_with_exp(rng, 8 * MOD_SIZE, &BigUint::from(exponent))
            .map_err(|_| CryptoError::Internal)?;
        let public = CruxRsaPublicKey {
            key: key.to_public_key(),
            exponent,
        };
        Ok(Self { key, public })
    }

    /// Loads the key with the prime factor `private` (either of the two) of
    /// the modulus of `public`: `Ok(None)` if it does not divide the modulus
    /// into two primes of (almost) the same length that fit `PRIME_SIZE`.
    fn load(
        public: Self::PublicKey,
        private: &[u8; PRIME_SIZE],
    ) -> Result<Option<Self>, CryptoError> {
        let n = public.key.n();
        let p = BigUint::from_bytes_be(private);
        let one = BigUint::from(1u32);
        if p <= one {
            return Ok(None);
        }
        if (n % &p) != BigUint::default() {
            return Ok(None);
        }
        let q = n / &p;
        if q <= one || q.bits() > 8 * PRIME_SIZE || p.bits().abs_diff(q.bits()) > 1 {
            return Ok(None);
        }
        let Ok(key) = RsaPrivateKey::from_p_q(p, q, public.key.e().clone()) else {
            return Ok(None);
        };
        if key.n() != n {
            return Ok(None);
        }
        Ok(Some(Self { key, public }))
    }

    /// Writes the first prime factor of the key (the one it was loaded with).
    fn store(&self, out: &mut [u8; PRIME_SIZE]) -> Result<(), CryptoError> {
        let prime = self.key.primes().first().ok_or(CryptoError::Internal)?;
        write_be(prime, out)
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }

    /// Loads the modulus `public` with the public exponent `exponent`:
    /// `Ok(None)` unless its most significant bit is set and it is odd, or if
    /// the `rsa` crate rejects it.
    fn load_public(
        exponent: u32,
        public: &[u8; MOD_SIZE],
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        if public[0] & 0x80 == 0 || public[MOD_SIZE - 1] & 1 == 0 {
            return Ok(None);
        }
        let Ok(key) = RsaPublicKey::new(BigUint::from_bytes_be(public), BigUint::from(exponent))
        else {
            return Ok(None);
        };
        Ok(Some(CruxRsaPublicKey { key, exponent }))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; MOD_SIZE]) -> Result<(), CryptoError> {
        write_be(public.key.n(), out)
    }
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> RsaKey<MOD_SIZE, PRIME_SIZE, CruxRng>
    for CruxRsaKey<MOD_SIZE, PRIME_SIZE>
{
    fn exponent(public: &Self::PublicKey) -> u32 {
        public.exponent
    }

    fn raw_encrypt(
        public: &Self::PublicKey,
        m: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let m = BigUint::from_bytes_be(m);
        if &m >= public.key.n() {
            return Ok(None);
        }
        let c = rsa::hazmat::rsa_encrypt(&public.key, &m).map_err(|_| CryptoError::Internal)?;
        write_be(&c, out).map(Some)
    }

    fn raw_decrypt(
        &self,
        rng: &mut CruxRng,
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let c = BigUint::from_bytes_be(c);
        if &c >= self.key.n() {
            return Ok(None);
        }
        let m = rsa::hazmat::rsa_decrypt_and_check(&self.key, Some(rng), &c)
            .map_err(|_| CryptoError::Internal)?;
        write_be(&m, out).map(Some)
    }

    fn oaep_encrypt(
        public: &Self::PublicKey,
        rng: &mut CruxRng,
        hash: TpmiAlgHash,
        label: &[u8],
        m: &[u8],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let Some(padding) = with_hash_alg!(hash, |D| oaep::<D>(label)) else {
            return Ok(None);
        };
        encrypted(public.key.encrypt(rng, padding, m), out)
    }

    fn oaep_decrypt(
        &self,
        rng: &mut CruxRng,
        hash: TpmiAlgHash,
        label: &[u8],
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        let Some(padding) = with_hash_alg!(hash, |D| oaep::<D>(label)) else {
            return Ok(None);
        };
        match self.key.decrypt_blinded(rng, padding, c) {
            Ok(m) => copy_message(&m, out),
            Err(_) => Ok(None),
        }
    }

    fn rsaes_encrypt(
        public: &Self::PublicKey,
        rng: &mut CruxRng,
        m: &[u8],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        encrypted(public.key.encrypt(rng, rsa::Pkcs1v15Encrypt, m), out)
    }

    fn rsaes_decrypt(
        &self,
        rng: &mut CruxRng,
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        match self.key.decrypt_blinded(rng, rsa::Pkcs1v15Encrypt, c) {
            Ok(m) => copy_message(&m, out),
            Err(_) => Ok(None),
        }
    }

    fn rsassa_sign(
        &self,
        rng: &mut CruxRng,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError> {
        let signature = with_digest!(digest, |d: D| self.key.sign_with_rng(
            rng,
            rsa::Pkcs1v15Sign::new::<D>(),
            d
        ))
        .map_err(|_| CryptoError::Internal)?;
        copy_exact(&signature, out)
    }

    fn rsassa_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError> {
        let verified = with_digest!(digest, |d: D| public.key.verify(
            rsa::Pkcs1v15Sign::new::<D>(),
            d,
            sig
        ));
        Ok(verified.is_ok())
    }

    fn rsapss_sign(
        &self,
        rng: &mut CruxRng,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError> {
        // TPM 2.0 `PssEncode`: the largest salt up to the digest size.
        let h_len = digest.digest().len();
        let salt_len = h_len.min(
            MOD_SIZE
                .checked_sub(h_len + 2)
                .ok_or(CryptoError::Internal)?,
        );
        let signature = with_digest!(digest, |d: D| self.key.sign_with_rng(
            rng,
            rsa::Pss::new_with_salt::<D>(salt_len),
            d
        ))
        .map_err(|_| CryptoError::Internal)?;
        copy_exact(&signature, out)
    }

    fn rsapss_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError> {
        let s = BigUint::from_bytes_be(sig);
        if &s >= public.key.n() {
            return Ok(false);
        }
        let m = rsa::hazmat::rsa_encrypt(&public.key, &s).map_err(|_| CryptoError::Internal)?;
        let mut em = [0u8; MOD_SIZE];
        write_be(&m, &mut em)?;
        Ok(with_digest!(digest, |d: D| emsa_pss_verify::<D>(
            &mut em, d
        )))
    }

    fn store_crt(&self, out: &mut [[u8; PRIME_SIZE]; 5]) -> Result<(), CryptoError> {
        let [first, second] = self.key.primes() else {
            return Err(CryptoError::Internal);
        };
        // The larger prime first, so that `qInv` is the inverse of the smaller one.
        let (p, q) = if first >= second {
            (first, second)
        } else {
            (second, first)
        };
        let key = RsaPrivateKey::from_components(
            self.key.n().clone(),
            self.key.e().clone(),
            self.key.d().clone(),
            vec![p.clone(), q.clone()],
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

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2::crypto::Random as _;

    type Rsa1024 = CruxRsaKey<128, 64>;

    /// A deterministic RNG seeded with `seed`.
    fn test_rng(seed: &[u8]) -> CruxRng {
        CruxCryptoProvider::from_seed(seed).unwrap()
    }

    fn key(seed: &[u8]) -> Rsa1024 {
        Rsa1024::generate(&mut test_rng(seed), 65537).unwrap()
    }

    #[test]
    fn seeded_key_generation_is_deterministic() {
        let modulus = |k: &Rsa1024| {
            let mut n = [0u8; 128];
            Rsa1024::store_public(k.as_public(), &mut n).unwrap();
            n
        };
        let k = key(b"seed");
        assert_eq!(modulus(&k), modulus(&key(b"seed")));
        assert_ne!(modulus(&k), modulus(&key(b"other seed")));
        assert_eq!(modulus(&k)[0] & 0x80, 0x80);
        assert_eq!(Rsa1024::exponent(k.as_public()), 65537);
        let k3 = Rsa1024::generate(&mut test_rng(b"seed"), 3).unwrap();
        assert_eq!(Rsa1024::exponent(k3.as_public()), 3);
    }

    #[test]
    fn load_and_store_round_trip_with_either_prime() {
        let k = key(b"load");
        let (mut n, mut p) = ([0u8; 128], [0u8; 64]);
        Rsa1024::store_public(k.as_public(), &mut n).unwrap();
        k.store(&mut p).unwrap();
        let public = || Rsa1024::load_public(65537, &n).unwrap().unwrap();

        let mut crt = [[0u8; 64]; 5];
        k.store_crt(&mut crt).unwrap();
        assert!(crt[0] > crt[1], "p is the larger prime");
        for prime in [p, crt[0], crt[1]] {
            let loaded = Rsa1024::load(public(), &prime).unwrap().unwrap();
            let mut again = [[0u8; 64]; 5];
            loaded.store_crt(&mut again).unwrap();
            assert_eq!(again, crt);
            let mut stored = [0u8; 64];
            loaded.store(&mut stored).unwrap();
            assert_eq!(stored, prime);
        }
        // Not a factor, 1, and 0.
        let mut bad = p;
        bad[63] ^= 2;
        assert!(Rsa1024::load(public(), &bad).unwrap().is_none());
        let mut one = [0u8; 64];
        one[63] = 1;
        assert!(Rsa1024::load(public(), &one).unwrap().is_none());
        assert!(Rsa1024::load(public(), &[0; 64]).unwrap().is_none());

        // An even modulus and one without its most significant bit.
        let mut even = n;
        even[127] &= !1;
        assert!(Rsa1024::load_public(65537, &even).unwrap().is_none());
        let mut short = n;
        short[0] &= 0x7f;
        assert!(Rsa1024::load_public(65537, &short).unwrap().is_none());
    }

    #[test]
    fn signatures() {
        let k = key(b"sign");
        let mut rng = CruxCryptoProvider::from_entropy().unwrap();
        let digest = [0x42u8; 32];
        let sha256 = TpmtHa::Sha256(&digest);
        let mut sig = [0u8; 128];

        k.rsassa_sign(&mut rng, sha256, &mut sig).unwrap();
        assert_eq!(
            Rsa1024::rsassa_verify(k.as_public(), sha256, &sig),
            Ok(true)
        );
        assert_eq!(
            Rsa1024::rsassa_verify(k.as_public(), TpmtHa::Sha256(&[0x43; 32]), &sig),
            Ok(false)
        );
        sig[0] ^= 1;
        assert_eq!(
            Rsa1024::rsassa_verify(k.as_public(), sha256, &sig),
            Ok(false)
        );

        k.rsapss_sign(&mut rng, sha256, &mut sig).unwrap();
        assert_eq!(
            Rsa1024::rsapss_verify(k.as_public(), sha256, &sig),
            Ok(true)
        );
        assert_eq!(
            Rsa1024::rsassa_verify(k.as_public(), sha256, &sig),
            Ok(false)
        );
        sig[5] ^= 1;
        assert_eq!(
            Rsa1024::rsapss_verify(k.as_public(), sha256, &sig),
            Ok(false)
        );
        assert_eq!(
            Rsa1024::rsapss_verify(k.as_public(), sha256, &[0xff; 128]),
            Ok(false)
        );

        // A 1024-bit key signs SHA-512 with RSA-PSS with a 62-byte salt
        // (TPM 2.0 `PssEncode`).
        #[cfg(feature = "sha512")]
        {
            let sha512 = TpmtHa::Sha512(&[7; 64]);
            k.rsapss_sign(&mut rng, sha512, &mut sig).unwrap();
            assert_eq!(
                Rsa1024::rsapss_verify(k.as_public(), sha512, &sig),
                Ok(true)
            );
        }
    }

    /// RSA-PSS signatures with any salt length verify (TPM 2.0 `PssDecode`).
    #[test]
    fn pss_verification_accepts_any_salt_length() {
        let k = key(b"pss");
        let digest = [0x24u8; 32];
        for salt_len in [0, 1, 20, 32, 94] {
            let sig = k
                .key
                .sign_with_rng(
                    &mut test_rng(b"salt"),
                    rsa::Pss::new_with_salt::<sha2::Sha256>(salt_len),
                    &digest,
                )
                .unwrap();
            let sig: [u8; 128] = sig.try_into().unwrap();
            assert_eq!(
                Rsa1024::rsapss_verify(k.as_public(), TpmtHa::Sha256(&digest), &sig),
                Ok(true),
                "salt length {salt_len}"
            );
        }
    }

    #[test]
    fn encryption() {
        let k = key(b"encrypt");
        let public = k.as_public();
        let mut rng = CruxCryptoProvider::from_entropy().unwrap();
        let (mut ct, mut pt) = ([0u8; 128], [0u8; 128]);

        // OAEP: round trip, wrong label, corrupted ciphertext, oversized
        // message, non-UTF-8 label.
        let hash = TpmiAlgHash::Sha256;
        assert_eq!(
            Rsa1024::oaep_encrypt(public, &mut rng, hash, b"label\0", b"secret", &mut ct),
            Ok(Some(()))
        );
        assert_eq!(
            k.oaep_decrypt(&mut rng, hash, b"label\0", &ct, &mut pt),
            Ok(Some(6))
        );
        assert_eq!(&pt[..6], b"secret");
        assert_eq!(
            k.oaep_decrypt(&mut rng, hash, b"other\0", &ct, &mut pt),
            Ok(None)
        );
        assert_eq!(k.oaep_decrypt(&mut rng, hash, b"", &ct, &mut pt), Ok(None));
        ct[5] ^= 1;
        assert_eq!(
            k.oaep_decrypt(&mut rng, hash, b"label\0", &ct, &mut pt),
            Ok(None)
        );
        assert_eq!(
            Rsa1024::oaep_encrypt(public, &mut rng, hash, b"", &[0; 63], &mut ct),
            Ok(None)
        );
        assert_eq!(
            Rsa1024::oaep_encrypt(public, &mut rng, hash, &[0xff, 0], b"m", &mut ct),
            Ok(None)
        );
        assert_eq!(
            Rsa1024::oaep_encrypt(public, &mut rng, hash, b"", b"m", &mut ct),
            Ok(Some(()))
        );
        assert_eq!(
            k.oaep_decrypt(&mut rng, hash, b"", &ct, &mut pt),
            Ok(Some(1))
        );

        // RSAES-PKCS1-v1_5.
        assert_eq!(
            Rsa1024::rsaes_encrypt(public, &mut rng, b"pkcs", &mut ct),
            Ok(Some(()))
        );
        assert_eq!(k.rsaes_decrypt(&mut rng, &ct, &mut pt), Ok(Some(4)));
        assert_eq!(&pt[..4], b"pkcs");
        assert_eq!(
            Rsa1024::rsaes_encrypt(public, &mut rng, &[1; 118], &mut ct),
            Ok(None)
        );

        // Raw RSA: round trip, and a value not smaller than the modulus.
        let mut m = [0u8; 128];
        m[127] = 9;
        assert_eq!(Rsa1024::raw_encrypt(public, &m, &mut ct), Ok(Some(())));
        assert_eq!(k.raw_decrypt(&mut rng, &ct, &mut pt), Ok(Some(())));
        assert_eq!(pt, m);
        let mut n = [0u8; 128];
        Rsa1024::store_public(public, &mut n).unwrap();
        assert_eq!(Rsa1024::raw_encrypt(public, &n, &mut ct), Ok(None));
        assert_eq!(k.raw_decrypt(&mut rng, &n, &mut pt), Ok(None));
    }

    /// The dispatch layer (`RsaPrivateKey`/`RsaPublicKey`) drives this backend.
    #[test]
    fn dispatch() {
        use tpm2::crypto::{
            RsaEncryptScheme, RsaModulusBuffer, RsaPrivateKey, RsaPublicKey, SignatureBuffer,
        };
        use tpm2::{TpmiRsaKeyBits, TpmtSigScheme};
        let mut rng = test_rng(b"dispatch");
        let private =
            RsaPrivateKey::<CruxCryptoProvider>::generate(&mut rng, TpmiRsaKeyBits::Rsa2048, 0)
                .unwrap();
        assert_eq!(private.exponent(), 65537);
        let mut sig_buf: SignatureBuffer = [0; _];
        let digest = [9u8; 32];
        let sig = private
            .sign(
                &mut rng,
                TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256),
                &digest,
                &mut sig_buf,
            )
            .unwrap();
        let mut n_buf: RsaModulusBuffer = [0; _];
        let n = private.modulus(&mut n_buf).unwrap();
        let public = RsaPublicKey::<CruxCryptoProvider>::load(TpmiRsaKeyBits::Rsa2048, 0, n)
            .unwrap()
            .unwrap();
        assert_eq!(public.verify(&digest, sig), Ok(true));

        let mut ct_buf: RsaModulusBuffer = [0; _];
        let scheme = RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha256,
            label: Some(c"label"),
        };
        let ct = public
            .encrypt(&mut rng, scheme, b"hello", &mut ct_buf)
            .unwrap()
            .unwrap();
        let mut pt_buf: RsaModulusBuffer = [0; _];
        let pt = private
            .decrypt(&mut rng, scheme, ct.as_slice(), &mut pt_buf)
            .unwrap()
            .unwrap();
        assert_eq!(pt.as_ref(), b"hello");
    }
}
