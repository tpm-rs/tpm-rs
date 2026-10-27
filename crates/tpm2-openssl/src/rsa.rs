use openssl::bn::{BigNum, BigNumContext, BigNumContextRef, BigNumRef};
use openssl::error::ErrorStack;
use openssl::md::{Md, MdRef};
use openssl::pkey::{PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding, Rsa as OsRsa};
use openssl::sign::RsaPssSaltlen;
use tpm2::{
    TpmiAlgHash, TpmtHa,
    crypto::{
        CryptoError, Rng,
        backend::{PrivateKey, Rsa, RsaKey},
    },
};

use crate::rng::OpensslRng;

/// `RSAES-PKCS1-v1_5` decryption padding mode which
/// reports invalid padding as an error, rather than OpenSSL's default implicit
/// rejection (returning a synthetic plaintext).
const RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING: libc::c_int = 8;

/// PSS salt length which recovers the salt length from the signature when
/// verifying.
const RSA_PSS_SALTLEN_AUTO: libc::c_int = -2;

/// Returns the OpenSSL digest for `alg`.
fn md(alg: TpmiAlgHash) -> &'static MdRef {
    match alg {
        TpmiAlgHash::Sha1 => Md::sha1(),
        TpmiAlgHash::Sha256 => Md::sha256(),
        TpmiAlgHash::Sha384 => Md::sha384(),
        TpmiAlgHash::Sha512 => Md::sha512(),
        TpmiAlgHash::Sm3_256 => Md::sm3(),
        TpmiAlgHash::Sha3_256 => Md::sha3_256(),
        TpmiAlgHash::Sha3_384 => Md::sha3_384(),
        TpmiAlgHash::Sha3_512 => Md::sha3_512(),
    }
}

/// Copies the result `res` of decrypting into `buf` to `out`, then zeroes
/// `buf`. Errors in `res` are `c >= n` or invalid padding.
fn decrypt_result<const MOD_SIZE: usize>(
    res: Result<usize, openssl::error::ErrorStack>,
    buf: &mut [u8],
    out: &mut [u8; MOD_SIZE],
) -> Result<Option<usize>, CryptoError> {
    let res = match res {
        Ok(len) if len <= MOD_SIZE => {
            out[..len].copy_from_slice(&buf[..len]);
            Ok(Some(len))
        }
        Ok(_) => Err(CryptoError::Internal),
        Err(_) => Ok(None),
    };
    buf.fill(0);
    res
}

/// Configures `pctx` (initialized for encryption or decryption) for
/// `RSAES-OAEP` with `hash` and `label`.
fn set_oaep<T>(pctx: &mut PkeyCtx<T>, hash: TpmiAlgHash, label: &[u8]) -> Result<(), CryptoError> {
    let md = md(hash);
    pctx.set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|_| CryptoError::Internal)?;
    pctx.set_rsa_oaep_md(md)
        .map_err(|_| CryptoError::Internal)?;
    pctx.set_rsa_mgf1_md(md)
        .map_err(|_| CryptoError::Internal)?;
    if !label.is_empty() {
        pctx.set_rsa_oaep_label(label)
            .map_err(|_| CryptoError::Internal)?;
    }
    Ok(())
}

fn internal(_: ErrorStack) -> CryptoError {
    CryptoError::Internal
}

/// Generates a `PRIME_SIZE`-byte prime `p` with `gcd(e, p - 1) == 1` from
/// `rng`: random candidates with their top two bits (so `p * q` has its top bit
/// set) and low bit set are drawn until one passes OpenSSL's primality test
/// (trial division and the default number of Miller-Rabin rounds).
fn generate_prime<const PRIME_SIZE: usize>(
    rng: &mut OpensslRng,
    e: &BigNumRef,
    ctx: &mut BigNumContextRef,
) -> Result<BigNum, CryptoError> {
    let one = BigNum::from_u32(1).map_err(internal)?;
    let (mut p1, mut gcd) = (
        BigNum::new().map_err(internal)?,
        BigNum::new().map_err(internal)?,
    );
    let mut bytes = [0u8; PRIME_SIZE];
    loop {
        rng.fill_bytes(&mut bytes)?;
        bytes[0] |= 0xc0;
        bytes[PRIME_SIZE - 1] |= 1;
        let p = BigNum::from_slice(&bytes).map_err(internal)?;
        if !p.is_prime_fasttest(0, ctx, true).map_err(internal)? {
            continue;
        }
        p1.checked_sub(&p, &one).map_err(internal)?;
        gcd.gcd(e, &p1, ctx).map_err(internal)?;
        if gcd == one {
            bytes.fill(0);
            return Ok(p);
        }
    }
}

/// Returns the RSA private key with primes `p` and `q` and public exponent `e`
/// (with `d = e^-1 mod lcm(p - 1, q - 1)`), or `None` if `e` or `q` isn't
/// invertible (mod `lcm(p - 1, q - 1)` and `p` respectively).
fn private_key_from_primes(
    p: BigNum,
    q: BigNum,
    e: BigNum,
    ctx: &mut BigNumContextRef,
) -> Result<Option<OsRsa<Private>>, CryptoError> {
    let one = BigNum::from_u32(1).map_err(internal)?;
    let new = || BigNum::new().map_err(internal);
    let (mut n, mut p1, mut q1, mut gcd, mut phi) = (new()?, new()?, new()?, new()?, new()?);
    let (mut lcm, mut d, mut dmp1, mut dmq1, mut iqmp) = (new()?, new()?, new()?, new()?, new()?);
    n.checked_mul(&p, &q, ctx).map_err(internal)?;
    p1.checked_sub(&p, &one).map_err(internal)?;
    q1.checked_sub(&q, &one).map_err(internal)?;
    gcd.gcd(&p1, &q1, ctx).map_err(internal)?;
    phi.checked_mul(&p1, &q1, ctx).map_err(internal)?;
    lcm.checked_div(&phi, &gcd, ctx).map_err(internal)?;
    if d.mod_inverse(&e, &lcm, ctx).is_err() || iqmp.mod_inverse(&q, &p, ctx).is_err() {
        return Ok(None);
    }
    dmp1.nnmod(&d, &p1, ctx).map_err(internal)?;
    dmq1.nnmod(&d, &q1, ctx).map_err(internal)?;
    let key = OsRsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp).map_err(internal)?;
    Ok(Some(key))
}

macro_rules! impl_rsa {
    ($name:ident, $mod_size:expr, $prime_size:expr) => {
        /// RSA private key with a
        #[doc = concat!(stringify!($mod_size), "-byte")]
        /// modulus.
        pub struct $name {
            pub priv_key: OsRsa<Private>,
            pub pub_key: OsRsa<Public>,
        }

        impl $name {
            /// Signs `digest` with `RSASSA-PKCS1-v1_5` or (if `pss`) `RSASSA-PSS`.
            fn sign_digest(
                &self,
                pss: bool,
                digest: TpmtHa<'_>,
                out: &mut [u8; $mod_size],
            ) -> Result<(), CryptoError> {
                let md = md(digest.hash_alg());
                let pkey =
                    PKey::from_rsa(self.priv_key.clone()).map_err(|_| CryptoError::Internal)?;
                let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
                pctx.sign_init().map_err(|_| CryptoError::Internal)?;
                if pss {
                    // TPM 2.0 PssEncode: the largest salt up to the digest size.
                    let Some(max_salt) = ($mod_size as usize).checked_sub(md.size() + 2) else {
                        return Err(CryptoError::Unsupported);
                    };
                    let salt_len = max_salt.min(md.size());
                    pctx.set_rsa_padding(Padding::PKCS1_PSS)
                        .map_err(|_| CryptoError::Internal)?;
                    pctx.set_rsa_mgf1_md(md)
                        .map_err(|_| CryptoError::Internal)?;
                    pctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_len as i32))
                        .map_err(|_| CryptoError::Internal)?;
                } else {
                    pctx.set_rsa_padding(Padding::PKCS1)
                        .map_err(|_| CryptoError::Internal)?;
                }
                pctx.set_signature_md(md)
                    .map_err(|_| CryptoError::Internal)?;
                let len = pctx
                    .sign(digest.digest(), Some(out))
                    .map_err(|_| CryptoError::Internal)?;
                if len != $mod_size {
                    return Err(CryptoError::Internal);
                }
                Ok(())
            }

            /// Verifies `sig` over `digest` under `public` with
            /// `RSASSA-PKCS1-v1_5` or (if `pss`) `RSASSA-PSS`.
            fn verify_digest(
                public: &OsRsa<Public>,
                pss: bool,
                digest: TpmtHa<'_>,
                sig: &[u8; $mod_size],
            ) -> Result<bool, CryptoError> {
                let md = md(digest.hash_alg());
                let pkey = PKey::from_rsa(public.clone()).map_err(|_| CryptoError::Internal)?;
                let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
                pctx.verify_init().map_err(|_| CryptoError::Internal)?;
                if pss {
                    // TPM 2.0 PssDecode: accept any salt length.
                    pctx.set_rsa_padding(Padding::PKCS1_PSS)
                        .map_err(|_| CryptoError::Internal)?;
                    pctx.set_rsa_mgf1_md(md)
                        .map_err(|_| CryptoError::Internal)?;
                    pctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(RSA_PSS_SALTLEN_AUTO))
                        .map_err(|_| CryptoError::Internal)?;
                } else {
                    pctx.set_rsa_padding(Padding::PKCS1)
                        .map_err(|_| CryptoError::Internal)?;
                }
                pctx.set_signature_md(md)
                    .map_err(|_| CryptoError::Internal)?;
                // Invalid signatures (including `sig >= n`) are errors.
                Ok(pctx.verify(digest.digest(), sig).unwrap_or(false))
            }
        }

        impl PrivateKey<$mod_size, $prime_size, OpensslRng, u32> for $name {
            type PublicKey = OsRsa<Public>;

            fn load_public(
                exponent: u32,
                modulus: &[u8; $mod_size],
            ) -> Result<Option<Self::PublicKey>, CryptoError> {
                // Per TPM 2.0 Part 1, the modulus has its top bit set and is odd.
                if modulus[0] & 0x80 == 0 || modulus[$mod_size - 1] & 1 == 0 {
                    return Ok(None);
                }
                let n = BigNum::from_slice(modulus).map_err(|_| CryptoError::Internal)?;
                let e = BigNum::from_u32(exponent).map_err(|_| CryptoError::Internal)?;
                Ok(OsRsa::from_public_components(n, e).ok())
            }

            fn store_public(
                public: &Self::PublicKey,
                out: &mut [u8; $mod_size],
            ) -> Result<(), CryptoError> {
                let n_bytes = public.n().to_vec();
                if n_bytes.len() > $mod_size {
                    return Err(CryptoError::Internal);
                }
                out.fill(0);
                out[$mod_size - n_bytes.len()..].copy_from_slice(&n_bytes);
                Ok(())
            }

            fn load(
                public: Self::PublicKey,
                prime_p: &[u8; $prime_size],
            ) -> Result<Option<Self>, CryptoError> {
                let mut ctx = BigNumContext::new().map_err(internal)?;
                let p = BigNum::from_slice(prime_p).map_err(internal)?;
                let e = public.e().to_owned().map_err(internal)?;
                let (mut q, mut rem) = (
                    BigNum::new().map_err(internal)?,
                    BigNum::new().map_err(internal)?,
                );
                q.div_rem(&mut rem, public.n(), &p, &mut ctx)
                    .map_err(internal)?;
                if rem.num_bits() != 0 {
                    return Ok(None);
                }
                let Some(priv_key) = private_key_from_primes(p, q, e, &mut ctx)? else {
                    return Ok(None);
                };

                if priv_key.check_key().is_err() {
                    return Ok(None);
                }

                Ok(Some($name {
                    priv_key,
                    pub_key: public,
                }))
            }

            fn generate(rng: &mut OpensslRng, exponent: u32) -> Result<Self, CryptoError> {
                let mut ctx = BigNumContext::new().map_err(internal)?;
                let e = BigNum::from_u32(exponent).map_err(internal)?;
                let p = generate_prime::<$prime_size>(rng, &e, &mut ctx)?;
                // FIPS 186-5, Appendix A.1.3: `|p - q| > 2^(nlen/2 - 100)`.
                let q = loop {
                    let q = generate_prime::<$prime_size>(rng, &e, &mut ctx)?;
                    let mut diff = BigNum::new().map_err(internal)?;
                    diff.checked_sub(&p, &q).map_err(internal)?;
                    if diff.num_bits() > $prime_size * 8 - 100 {
                        break q;
                    }
                };
                let priv_key =
                    private_key_from_primes(p, q, e, &mut ctx)?.ok_or(CryptoError::Internal)?;
                let n = priv_key.n().to_owned().map_err(internal)?;
                let e = priv_key.e().to_owned().map_err(internal)?;
                let pub_key = OsRsa::from_public_components(n, e).map_err(internal)?;
                Ok($name { priv_key, pub_key })
            }

            fn as_public(&self) -> &Self::PublicKey {
                &self.pub_key
            }

            fn store(&self, out: &mut [u8; $prime_size]) -> Result<(), CryptoError> {
                let p_bytes = self.priv_key.p().unwrap().to_vec();
                if p_bytes.len() > $prime_size {
                    return Err(CryptoError::Internal);
                }
                out.fill(0);
                out[$prime_size - p_bytes.len()..].copy_from_slice(&p_bytes);
                Ok(())
            }
        }

        impl RsaKey<$mod_size, $prime_size, OpensslRng> for $name {
            fn exponent(public: &Self::PublicKey) -> u32 {
                let e_bytes = public.e().to_vec();
                let mut e = 0u32;
                for &b in &e_bytes {
                    e = (e << 8) | (b as u32);
                }
                e
            }

            fn raw_encrypt(
                public: &Self::PublicKey,
                m: &[u8; $mod_size],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<()>, CryptoError> {
                match public.public_encrypt(m, out, Padding::NONE) {
                    Ok($mod_size) => Ok(Some(())),
                    Ok(_) => Err(CryptoError::Internal),
                    // `m >= n`
                    Err(_) => Ok(None),
                }
            }

            fn raw_decrypt(
                &self,
                _rng: &mut OpensslRng,
                c: &[u8; $mod_size],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<()>, CryptoError> {
                match self.priv_key.private_decrypt(c, out, Padding::NONE) {
                    Ok($mod_size) => Ok(Some(())),
                    Ok(_) => {
                        out.fill(0);
                        Err(CryptoError::Internal)
                    }
                    // `c >= n`
                    Err(_) => Ok(None),
                }
            }

            fn oaep_encrypt(
                public: &Self::PublicKey,
                _rng: &mut OpensslRng,
                hash: TpmiAlgHash,
                label: &[u8],
                m: &[u8],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<()>, CryptoError> {
                if m.len() + 2 * md(hash).size() + 2 > $mod_size {
                    return Ok(None);
                }
                let pkey = PKey::from_rsa(public.clone()).map_err(|_| CryptoError::Internal)?;
                let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
                pctx.encrypt_init().map_err(|_| CryptoError::Internal)?;
                set_oaep(&mut pctx, hash, label)?;
                let len = pctx
                    .encrypt(m, Some(out))
                    .map_err(|_| CryptoError::Internal)?;
                if len != $mod_size {
                    return Err(CryptoError::Internal);
                }
                Ok(Some(()))
            }

            fn oaep_decrypt(
                &self,
                _rng: &mut OpensslRng,
                hash: TpmiAlgHash,
                label: &[u8],
                c: &[u8; $mod_size],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<usize>, CryptoError> {
                let pkey =
                    PKey::from_rsa(self.priv_key.clone()).map_err(|_| CryptoError::Internal)?;
                let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
                pctx.decrypt_init().map_err(|_| CryptoError::Internal)?;
                set_oaep(&mut pctx, hash, label)?;
                let mut buf = vec![0u8; $mod_size];
                let res = pctx.decrypt(c, Some(&mut buf));
                decrypt_result(res, &mut buf, out)
            }

            fn rsaes_encrypt(
                public: &Self::PublicKey,
                _rng: &mut OpensslRng,
                m: &[u8],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<()>, CryptoError> {
                if m.len() > $mod_size - 11 {
                    return Ok(None);
                }
                let len = public
                    .public_encrypt(m, out, Padding::PKCS1)
                    .map_err(|_| CryptoError::Internal)?;
                if len != $mod_size {
                    return Err(CryptoError::Internal);
                }
                Ok(Some(()))
            }

            fn rsaes_decrypt(
                &self,
                _rng: &mut OpensslRng,
                c: &[u8; $mod_size],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<usize>, CryptoError> {
                let mut buf = vec![0u8; $mod_size];
                let res = self.priv_key.private_decrypt(
                    c,
                    &mut buf,
                    Padding::from_raw(RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING),
                );
                decrypt_result(res, &mut buf, out)
            }

            fn rsassa_sign(
                &self,
                _rng: &mut OpensslRng,
                digest: TpmtHa<'_>,
                out: &mut [u8; $mod_size],
            ) -> Result<(), CryptoError> {
                self.sign_digest(false, digest, out)
            }

            fn rsassa_verify(
                public: &Self::PublicKey,
                digest: TpmtHa<'_>,
                sig: &[u8; $mod_size],
            ) -> Result<bool, CryptoError> {
                Self::verify_digest(public, false, digest, sig)
            }

            fn rsapss_sign(
                &self,
                _rng: &mut OpensslRng,
                digest: TpmtHa<'_>,
                out: &mut [u8; $mod_size],
            ) -> Result<(), CryptoError> {
                self.sign_digest(true, digest, out)
            }

            fn rsapss_verify(
                public: &Self::PublicKey,
                digest: TpmtHa<'_>,
                sig: &[u8; $mod_size],
            ) -> Result<bool, CryptoError> {
                Self::verify_digest(public, true, digest, sig)
            }
        }
    };
}
impl_rsa!(Rsa1024, 128, 64);
impl_rsa!(Rsa2048, 256, 128);
impl_rsa!(Rsa3072, 384, 192);
impl_rsa!(Rsa4096, 512, 256);

impl Rsa for super::OpensslBackend {
    type Rsa1024 = Rsa1024;
    type Rsa2048 = Rsa2048;
    type Rsa3072 = Rsa3072;
    type Rsa4096 = Rsa4096;
}
