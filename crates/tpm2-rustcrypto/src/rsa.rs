use alloc::vec::Vec;

use rsa::{
    BoxedUint, Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, PrivateKey as RsaPrivateKey, Pss,
    PublicKey as RsaPublicKey,
    hazmat::{rsa_decrypt_and_check, rsa_encrypt},
    traits::{PrivateKeyParts, PublicKeyParts},
};
use sha2::digest::Digest as _;
use tpm2::{
    TpmiAlgHash, TpmtHa,
    crypto::{
        CryptoError,
        backend::{PrivateKey, RsaKey},
    },
};

use crate::{ChaChaRng, RngWrapper};

/// RSA private key with a `MOD_SIZE`-byte modulus and `PRIME_SIZE`-byte primes.
pub struct RsaKeyPair<const MOD_SIZE: usize, const PRIME_SIZE: usize>(RsaPrivateKey);

macro_rules! with_digest {
    ($alg:expr, |$d:ident| $body:expr) => {
        match $alg {
            TpmiAlgHash::Sha1 => {
                type $d = sha1::Sha1;
                $body
            }
            TpmiAlgHash::Sha256 => {
                type $d = sha2::Sha256;
                $body
            }
            TpmiAlgHash::Sha384 => {
                type $d = sha2::Sha384;
                $body
            }
            TpmiAlgHash::Sha512 => {
                type $d = sha2::Sha512;
                $body
            }
            TpmiAlgHash::Sm3_256 => {
                type $d = sm3::Sm3;
                $body
            }
            TpmiAlgHash::Sha3_256 => {
                type $d = sha3::Sha3_256;
                $body
            }
            TpmiAlgHash::Sha3_384 => {
                type $d = sha3::Sha3_384;
                $body
            }
            TpmiAlgHash::Sha3_512 => {
                type $d = sha3::Sha3_512;
                $body
            }
        }
    };
}

/// DER `DigestInfo` prefix for `RSASSA-PKCS1-v1_5`, matching `MakeDerTag` in
/// the TPM 2.0 reference implementation.
fn digest_info_prefix(alg: TpmiAlgHash) -> &'static [u8] {
    match alg {
        TpmiAlgHash::Sha1 => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        TpmiAlgHash::Sha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        TpmiAlgHash::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        TpmiAlgHash::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        TpmiAlgHash::Sm3_256 => &[
            0x30, 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11,
            0x05, 0x00, 0x04, 0x20,
        ],
        TpmiAlgHash::Sha3_256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x08, 0x05, 0x00, 0x04, 0x20,
        ],
        TpmiAlgHash::Sha3_384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x09, 0x05, 0x00, 0x04, 0x30,
        ],
        TpmiAlgHash::Sha3_512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x0a, 0x05, 0x00, 0x04, 0x40,
        ],
    }
}

/// Builds the `rsa` crate's OAEP padding for `D` and the TPM label `L` (`label_bytes`).
fn oaep<D: sha2::digest::Digest + sha2::digest::FixedOutputReset>(label_bytes: &[u8]) -> Oaep<D> {
    if label_bytes.is_empty() {
        Oaep::<D>::new()
    } else {
        Oaep::<D>::new_with_label(label_bytes)
    }
}

/// Writes the big-endian `value` into `out`, left-padded with zeros.
fn write_be<const N: usize>(value: &BoxedUint, out: &mut [u8; N]) -> Result<(), CryptoError> {
    let bytes = value.to_be_bytes_trimmed_vartime();
    if bytes.len() > N {
        return Err(CryptoError::Internal);
    }
    out.fill(0);
    out[N - bytes.len()..].copy_from_slice(&bytes);
    Ok(())
}

/// Copies an `rsa` crate ciphertext into `out`, mapping a too-long message to
/// `Ok(None)`.
fn write_ct<const N: usize>(
    ct: rsa::Result<Vec<u8>>,
    out: &mut [u8; N],
) -> Result<Option<()>, CryptoError> {
    match ct {
        Ok(ct) if ct.len() == N => {
            out.copy_from_slice(&ct);
            Ok(Some(()))
        }
        Ok(_) => Err(CryptoError::Internal),
        Err(rsa::Error::MessageTooLong) => Ok(None),
        Err(_) => Err(CryptoError::Internal),
    }
}

/// Copies an `rsa` crate plaintext into `out`, mapping a decryption error to
/// `Ok(None)`.
fn write_pt<const N: usize>(
    pt: rsa::Result<Vec<u8>>,
    out: &mut [u8; N],
) -> Result<Option<usize>, CryptoError> {
    let Ok(pt) = pt else {
        return Ok(None);
    };
    let dst = out.get_mut(..pt.len()).ok_or(CryptoError::Internal)?;
    dst.copy_from_slice(&pt);
    Ok(Some(pt.len()))
}

/// Copies an `rsa` crate signature into `out`.
fn write_sig<const N: usize>(
    sig: rsa::Result<Vec<u8>>,
    out: &mut [u8; N],
) -> Result<(), CryptoError> {
    let sig = sig.map_err(|_| CryptoError::Internal)?;
    if sig.len() != N {
        return Err(CryptoError::Internal);
    }
    out.copy_from_slice(&sig);
    Ok(())
}

/// Builds the `RSASSA-PKCS1-v1_5` padding for `digest`.
fn pkcs1v15_sign(digest: TpmtHa<'_>) -> Pkcs1v15Sign {
    Pkcs1v15Sign {
        hash_len: Some(digest.digest().len()),
        prefix: digest_info_prefix(digest.hash_alg()).into(),
    }
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize>
    PrivateKey<MOD_SIZE, PRIME_SIZE, ChaChaRng, u32> for RsaKeyPair<MOD_SIZE, PRIME_SIZE>
{
    type PublicKey = RsaPublicKey;

    fn generate(rng: &mut ChaChaRng, exponent: u32) -> Result<Self, CryptoError> {
        let mut wrapper = RngWrapper(rng);
        RsaPrivateKey::new_with_exp(&mut wrapper, MOD_SIZE * 8, BoxedUint::from(exponent))
            .map(Self)
            .map_err(|_| CryptoError::Internal)
    }

    fn load_public(
        exponent: u32,
        modulus: &[u8; MOD_SIZE],
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        let n = BoxedUint::from_be_slice_vartime(modulus);
        let e = BoxedUint::from(exponent);
        Ok(RsaPublicKey::new(n, e).ok())
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; MOD_SIZE]) -> Result<(), CryptoError> {
        write_be(public.n(), out)
    }

    fn load(
        public: Self::PublicKey,
        prime_p: &[u8; PRIME_SIZE],
    ) -> Result<Option<Self>, CryptoError> {
        let p = BoxedUint::from_be_slice_vartime(prime_p);
        if p <= BoxedUint::one() {
            return Ok(None);
        }
        let Some(q) = public.n().checked_div(&p).into_option() else {
            return Ok(None);
        };
        if q <= BoxedUint::one()
            || q.checked_mul(&p).into_option().as_ref() != Some(public.n().as_ref())
        {
            return Ok(None);
        }
        let e = public.e().clone();

        Ok(RsaPrivateKey::from_p_q(p, q, e).ok().map(Self))
    }

    fn store(&self, out: &mut [u8; PRIME_SIZE]) -> Result<(), CryptoError> {
        let primes = self.0.primes();
        if primes.is_empty() {
            return Err(CryptoError::Internal);
        }
        write_be(&primes[0], out)
    }

    fn as_public(&self) -> &Self::PublicKey {
        self.0.as_ref()
    }
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> RsaKey<MOD_SIZE, PRIME_SIZE, ChaChaRng>
    for RsaKeyPair<MOD_SIZE, PRIME_SIZE>
{
    fn exponent(public: &Self::PublicKey) -> u32 {
        let bytes = public.e().to_le_bytes();
        let mut arr = [0u8; 4];
        for (i, &b) in bytes.iter().take(4).enumerate() {
            arr[i] = b;
        }
        u32::from_le_bytes(arr)
    }

    fn raw_encrypt(
        public: &Self::PublicKey,
        m: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let m = BoxedUint::from_be_slice_vartime(m);
        if m >= public.n().as_ref() {
            return Ok(None);
        }
        let c = rsa_encrypt(public, &m).map_err(|_| CryptoError::Internal)?;
        write_be(&c, out)?;
        Ok(Some(()))
    }

    fn raw_decrypt(
        &self,
        rng: &mut ChaChaRng,
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let Ok(c) = BoxedUint::from_be_slice(c, self.0.n_bits_precision()) else {
            return Ok(None);
        };
        if c >= self.0.n().as_ref() {
            return Ok(None);
        }
        let m = rsa_decrypt_and_check(&self.0, Some(&mut RngWrapper(rng)), &c)
            .map_err(|_| CryptoError::Internal)?;
        write_be(&m, out)?;
        Ok(Some(()))
    }

    fn oaep_encrypt(
        public: &Self::PublicKey,
        rng: &mut ChaChaRng,
        hash: TpmiAlgHash,
        label: &[u8],
        m: &[u8],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let mut wrapper = RngWrapper(rng);
        let ct = with_digest!(hash, |D| public.encrypt(&mut wrapper, oaep::<D>(label), m));
        write_ct(ct, out)
    }

    fn oaep_decrypt(
        &self,
        rng: &mut ChaChaRng,
        hash: TpmiAlgHash,
        label: &[u8],
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        let mut wrapper = RngWrapper(rng);
        let pt = with_digest!(hash, |D| {
            self.0.decrypt_blinded(&mut wrapper, oaep::<D>(label), c)
        });
        write_pt(pt, out)
    }

    fn rsaes_encrypt(
        public: &Self::PublicKey,
        rng: &mut ChaChaRng,
        m: &[u8],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let ct = public.encrypt(&mut RngWrapper(rng), Pkcs1v15Encrypt, m);
        write_ct(ct, out)
    }

    fn rsaes_decrypt(
        &self,
        rng: &mut ChaChaRng,
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        let pt = self
            .0
            .decrypt_blinded(&mut RngWrapper(rng), Pkcs1v15Encrypt, c);
        write_pt(pt, out)
    }

    fn rsassa_sign(
        &self,
        rng: &mut ChaChaRng,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError> {
        let sig =
            self.0
                .sign_with_rng(&mut RngWrapper(rng), pkcs1v15_sign(digest), digest.digest());
        write_sig(sig, out)
    }

    fn rsassa_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError> {
        Ok(public
            .verify(pkcs1v15_sign(digest), digest.digest(), sig)
            .is_ok())
    }

    fn rsapss_sign(
        &self,
        rng: &mut ChaChaRng,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError> {
        let mut wrapper = RngWrapper(rng);
        let hashed = digest.digest();
        // TPM 2.0 `PssEncode`: the largest salt up to the digest size.
        let em_len = (self.0.n().bit_width() as usize - 1).div_ceil(8);
        let max_salt = em_len.checked_sub(hashed.len() + 2);
        let salt_len = max_salt.ok_or(CryptoError::Unsupported)?.min(hashed.len());
        let sig = with_digest!(digest.hash_alg(), |D| {
            let padding = Pss::<D>::new_blinded_with_salt(salt_len);
            self.0.sign_with_rng(&mut wrapper, padding, hashed)
        });
        write_sig(sig, out)
    }

    fn rsapss_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError> {
        if BoxedUint::from_be_slice_vartime(sig) >= public.n().as_ref() {
            return Ok(false);
        }
        let res = with_digest!(digest.hash_alg(), |D| {
            let padding = Pss {
                blinded: false,
                digest: D::new(),
                salt_len: None,
            };
            public.verify(padding, digest.digest(), sig)
        });
        Ok(res.is_ok())
    }
}
