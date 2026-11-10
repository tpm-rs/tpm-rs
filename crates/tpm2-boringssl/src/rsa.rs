//! RSA (`RSA-1024`, `RSA-2048`, `RSA-3072`, `RSA-4096`) implementations backed
//! by BoringSSL's `RSA_*`, `EVP_PKEY_*` (for `RSAES-OAEP`), and `BN_*` APIs.

use core::{
    ffi::{c_int, c_uint},
    ptr,
};

use tpm2::{
    TpmiAlgHash, TpmtHa,
    crypto::{
        CryptoError, Rng,
        backend::{PrivateKey, Rsa, RsaKey},
    },
};

use crate::bssl_sys::{self, BN_CTX, EVP_MD, EVP_PKEY_CTX, RSA};
use crate::{
    BoringSsl, BoringSslRng,
    util::{Bn, Owned, Secret, bn_ctx, check},
};

/// Validated RSA public key backed by BoringSSL `RSA`.
#[derive(Clone)]
pub struct BoringSslRsaPublicKey<const MOD_SIZE: usize> {
    rsa: Owned<RSA>,
    exponent: u32,
    modulus: [u8; MOD_SIZE],
}

/// Validated RSA private key backed by BoringSSL `RSA`.
#[derive(Clone)]
pub struct BoringSslRsaPrivateKey<const MOD_SIZE: usize, const PRIME_SIZE: usize> {
    rsa: Owned<RSA>,
    public: BoringSslRsaPublicKey<MOD_SIZE>,
    prime_p: Secret<[u8; PRIME_SIZE]>,
}

impl<const MOD_SIZE: usize> BoringSslRsaPublicKey<MOD_SIZE> {
    /// Encrypts `input` with `RSA_encrypt` and `padding`, writing the
    /// `MOD_SIZE`-byte ciphertext into `out`.
    fn encrypt(
        &self,
        padding: c_int,
        input: &[u8],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError> {
        let mut out_len: usize = 0;
        check(unsafe {
            bssl_sys::RSA_encrypt(
                self.rsa.as_ptr(),
                &raw mut out_len,
                out.as_mut_ptr(),
                MOD_SIZE,
                input.as_ptr(),
                input.len(),
                padding,
            )
        })?;
        if out_len != MOD_SIZE {
            return Err(CryptoError::Internal);
        }
        Ok(())
    }
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> BoringSslRsaPrivateKey<MOD_SIZE, PRIME_SIZE> {
    /// Decrypts `c` (`< n`) with `RSA_decrypt` and `padding`, writing the
    /// recovered message into `out[..len]` and returning `Ok(Some(len))`, or
    /// `Ok(None)` if decryption fails (i.e. the padding is invalid).
    fn decrypt(
        &self,
        padding: c_int,
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        let mut out_len: usize = 0;
        let ok = unsafe {
            bssl_sys::RSA_decrypt(
                self.rsa.as_ptr(),
                &raw mut out_len,
                out.as_mut_ptr(),
                MOD_SIZE,
                c.as_ptr(),
                MOD_SIZE,
                padding,
            )
        };
        if ok != 1 {
            return Ok(None);
        }
        if out_len > MOD_SIZE {
            return Err(CryptoError::Internal);
        }
        Ok(Some(out_len))
    }
}

fn hash_alg_to_md(alg: TpmiAlgHash) -> Result<*const EVP_MD, CryptoError> {
    unsafe {
        Ok(match alg {
            TpmiAlgHash::Sha1 => bssl_sys::EVP_sha1(),
            TpmiAlgHash::Sha256 => bssl_sys::EVP_sha256(),
            TpmiAlgHash::Sha384 => bssl_sys::EVP_sha384(),
            TpmiAlgHash::Sha512 => bssl_sys::EVP_sha512(),
            _ => return Err(CryptoError::Unsupported),
        })
    }
}

/// Returns an `EVP_PKEY_CTX` for `RSAES-OAEP` encryption or decryption with
/// `rsa`, using `md` for both the OAEP digest and `MGF1`, and `label` as the
/// OAEP label `L` (no label if empty).
fn oaep_ctx(
    rsa: &Owned<RSA>,
    md: *const EVP_MD,
    label: &[u8],
    encrypt: bool,
) -> Result<Owned<EVP_PKEY_CTX>, CryptoError> {
    let pkey = Owned::new(unsafe { bssl_sys::EVP_PKEY_new() })?;
    check(unsafe { bssl_sys::EVP_PKEY_set1_RSA(pkey.as_ptr(), rsa.as_ptr()) })?;
    // `EVP_PKEY_CTX_new` takes its own reference to `pkey`.
    let ctx = Owned::new(unsafe { bssl_sys::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut()) })?;
    let c = ctx.as_ptr();
    unsafe {
        check(if encrypt {
            bssl_sys::EVP_PKEY_encrypt_init(c)
        } else {
            bssl_sys::EVP_PKEY_decrypt_init(c)
        })?;
        check(bssl_sys::EVP_PKEY_CTX_set_rsa_padding(
            c,
            bssl_sys::RSA_PKCS1_OAEP_PADDING,
        ))?;
        check(bssl_sys::EVP_PKEY_CTX_set_rsa_oaep_md(c, md))?;
        check(bssl_sys::EVP_PKEY_CTX_set_rsa_mgf1_md(c, md))?;
    }
    if !label.is_empty() {
        let copy = unsafe { bssl_sys::OPENSSL_memdup(label.as_ptr().cast(), label.len()) };
        if copy.is_null() {
            return Err(CryptoError::Internal);
        }
        // On success, `EVP_PKEY_CTX_set0_rsa_oaep_label` takes ownership of `copy`.
        if unsafe { bssl_sys::EVP_PKEY_CTX_set0_rsa_oaep_label(c, copy.cast(), label.len()) } != 1 {
            unsafe { bssl_sys::OPENSSL_free(copy) };
            return Err(CryptoError::Internal);
        }
    }
    Ok(ctx)
}

/// Generates a random prime `p` of `PRIME_SIZE` bytes from `rng` such that
/// `p` has its top two bits set, `gcd(p - 1, e) == 1`, and if `other` is
/// `Some(q)`, `|p - q| > 2^(prime_bits - 100)`.
#[inline(never)]
fn generate_prime<const PRIME_SIZE: usize>(
    rng: &mut impl Rng,
    e: &Bn,
    other: Option<&Bn>,
    ctx: *mut BN_CTX,
) -> Result<Bn, CryptoError> {
    let prime_bits = (PRIME_SIZE * 8) as c_uint;
    let p = Bn::zero()?;
    let (pm1, gcd, diff) = (Bn::zero()?, Bn::zero()?, Bn::zero()?);
    let (pm1, gcd, diff) = (pm1.as_ptr(), gcd.as_ptr(), diff.as_ptr());
    let mut buf = Secret([0u8; PRIME_SIZE]);
    for _ in 0..prime_bits * 16 {
        rng.fill_bytes(&mut buf.0)?;
        // Set top two bits (so p * q is guaranteed to have MOD_SIZE * 8 bits)
        // and bottom bit (odd), matching FIPS 186-5 Appendix A.1.3.
        buf.0[0] |= 0xc0;
        buf.0[PRIME_SIZE - 1] |= 0x01;
        unsafe {
            if bssl_sys::BN_bin2bn(buf.0.as_ptr(), PRIME_SIZE, p.as_ptr()).is_null() {
                return Err(CryptoError::Internal);
            }
            if let Some(q) = other {
                // `BN_num_bits` ignores the sign of `p - q`.
                check(bssl_sys::BN_sub(diff, p.as_ptr(), q.as_ptr()))?;
                if bssl_sys::BN_num_bits(diff) <= prime_bits - 100 {
                    continue;
                }
            }
            check(bssl_sys::BN_sub(pm1, p.as_ptr(), bssl_sys::BN_value_one()))?;
            check(bssl_sys::BN_gcd(gcd, pm1, e.as_ptr(), ctx))?;
            if bssl_sys::BN_is_one(gcd) != 1 {
                continue;
            }
        }
        if is_prime(p.as_ptr(), ctx)? {
            return Ok(p);
        }
    }
    Err(CryptoError::Internal)
}

/// Returns whether `bn` is prime.
fn is_prime(bn: *const bssl_sys::BIGNUM, ctx: *mut BN_CTX) -> Result<bool, CryptoError> {
    let mut is_prime: c_int = 0;
    check(unsafe {
        bssl_sys::BN_primality_test(
            &raw mut is_prime,
            bn,
            bssl_sys::BN_prime_checks_for_generation,
            ctx,
            0,
            ptr::null_mut(),
        )
    })?;
    Ok(is_prime == 1)
}

macro_rules! impl_rsa_key {
    ($mod_size:literal, $prime_size:literal) => {
        impl PrivateKey<$mod_size, $prime_size, BoringSslRng, u32>
            for BoringSslRsaPrivateKey<$mod_size, $prime_size>
        {
            type PublicKey = BoringSslRsaPublicKey<$mod_size>;

            #[inline(never)]
            fn generate(rng: &mut BoringSslRng, exponent: u32) -> Result<Self, CryptoError> {
                if exponent < 3 || exponent % 2 == 0 {
                    return Err(CryptoError::Unsupported);
                }
                let ctx = bn_ctx()?;
                let e = Bn::from_u32(exponent)?;
                let n = Bn::zero()?;
                for _ in 0..8 {
                    let p = generate_prime::<$prime_size>(rng, &e, None, ctx.as_ptr())?;
                    let q = generate_prime::<$prime_size>(rng, &e, Some(&p), ctx.as_ptr())?;
                    check(unsafe {
                        bssl_sys::BN_mul(n.as_ptr(), p.as_ptr(), q.as_ptr(), ctx.as_ptr())
                    })?;
                    // `p` and `q` have their top two bits set, so `n` has
                    // exactly `$mod_size` bytes.
                    let mut modulus = [0u8; $mod_size];
                    n.to_be_padded(&mut modulus)?;
                    let mut prime_p = Secret([0u8; $prime_size]);
                    p.to_be_padded(&mut prime_p.0)?;
                    if let Some(public) = Self::load_public(exponent, &modulus)?
                        && let Some(private) = Self::load(public, &prime_p.0)?
                    {
                        return Ok(private);
                    }
                }
                Err(CryptoError::Internal)
            }

            #[inline(never)]
            fn load(
                public: Self::PublicKey,
                prime_p: &[u8; $prime_size],
            ) -> Result<Option<Self>, CryptoError> {
                if (prime_p[0] & 0x80) == 0 || (prime_p[$prime_size - 1] & 0x01) == 0 {
                    return Ok(None);
                }
                let p = Bn::from_be(prime_p)?;
                let (q, rem, pm1, qm1) = (Bn::zero()?, Bn::zero()?, Bn::zero()?, Bn::zero()?);
                let (phi, d, dmp1, dmq1, iqmp) = (
                    Bn::zero()?,
                    Bn::zero()?,
                    Bn::zero()?,
                    Bn::zero()?,
                    Bn::zero()?,
                );
                let (p, q, rem, pm1, qm1) = (
                    p.as_ptr(),
                    q.as_ptr(),
                    rem.as_ptr(),
                    pm1.as_ptr(),
                    qm1.as_ptr(),
                );
                let (phi, d, dmp1, dmq1, iqmp) = (
                    phi.as_ptr(),
                    d.as_ptr(),
                    dmp1.as_ptr(),
                    dmq1.as_ptr(),
                    iqmp.as_ptr(),
                );
                let ctx = bn_ctx()?;
                let ctx = ctx.as_ptr();
                unsafe {
                    let n = bssl_sys::RSA_get0_n(public.rsa.as_ptr());
                    let e = bssl_sys::RSA_get0_e(public.rsa.as_ptr());
                    let one = bssl_sys::BN_value_one();

                    // `q = n / p` must be an odd `$prime_size`-byte integer.
                    check(bssl_sys::BN_div(q, rem, n, p, ctx))?;
                    if bssl_sys::BN_is_zero(rem) != 1
                        || bssl_sys::BN_num_bits(q) != ($prime_size * 8) as c_uint
                        || bssl_sys::BN_is_odd(q) != 1
                    {
                        return Ok(None);
                    }
                    // `RSA_new_private_key` doesn't check that `p` and `q` are prime.
                    if !is_prime(p, ctx)? || !is_prime(q, ctx)? {
                        return Ok(None);
                    }

                    // `RSA_check_key` accepts `d = e^-1 mod (p - 1)(q - 1)`, and
                    // the CRT values are the same as for `e^-1 mod lcm(p - 1, q - 1)`.
                    check(bssl_sys::BN_sub(pm1, p, one))?;
                    check(bssl_sys::BN_sub(qm1, q, one))?;
                    check(bssl_sys::BN_mul(phi, pm1, qm1, ctx))?;
                    if bssl_sys::BN_mod_inverse(d, e, phi, ctx).is_null() {
                        return Ok(None);
                    }
                    check(bssl_sys::BN_nnmod(dmp1, d, pm1, ctx))?;
                    check(bssl_sys::BN_nnmod(dmq1, d, qm1, ctx))?;
                    if bssl_sys::BN_mod_inverse(iqmp, q, p, ctx).is_null() {
                        return Ok(None);
                    }

                    let rsa = Owned::from_ptr(bssl_sys::RSA_new_private_key(
                        n, e, d, p, q, dmp1, dmq1, iqmp,
                    ));
                    Ok(rsa.map(|rsa| Self {
                        rsa,
                        public,
                        prime_p: Secret(*prime_p),
                    }))
                }
            }

            fn store(&self, out: &mut [u8; $prime_size]) -> Result<(), CryptoError> {
                *out = self.prime_p.0;
                Ok(())
            }

            fn as_public(&self) -> &Self::PublicKey {
                &self.public
            }

            #[inline(never)]
            fn load_public(
                exponent: u32,
                modulus: &[u8; $mod_size],
            ) -> Result<Option<Self::PublicKey>, CryptoError> {
                if exponent < 3 || exponent % 2 == 0 {
                    return Err(CryptoError::Unsupported);
                }
                if (modulus[0] & 0x80) == 0 || (modulus[$mod_size - 1] & 0x01) == 0 {
                    return Ok(None);
                }
                let n = Bn::from_be(modulus)?;
                let e = Bn::from_u32(exponent)?;
                let rsa = Owned::from_ptr(unsafe {
                    bssl_sys::RSA_new_public_key(n.as_ptr(), e.as_ptr())
                });
                Ok(rsa.map(|rsa| BoringSslRsaPublicKey {
                    rsa,
                    exponent,
                    modulus: *modulus,
                }))
            }

            fn store_public(
                public: &Self::PublicKey,
                out: &mut [u8; $mod_size],
            ) -> Result<(), CryptoError> {
                *out = public.modulus;
                Ok(())
            }
        }

        impl RsaKey<$mod_size, $prime_size, BoringSslRng>
            for BoringSslRsaPrivateKey<$mod_size, $prime_size>
        {
            fn exponent(public: &Self::PublicKey) -> u32 {
                public.exponent
            }

            #[inline(never)]
            fn raw_encrypt(
                public: &Self::PublicKey,
                m: &[u8; $mod_size],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<()>, CryptoError> {
                if m >= &public.modulus {
                    return Ok(None);
                }
                public.encrypt(bssl_sys::RSA_NO_PADDING, m, out).map(Some)
            }

            #[inline(never)]
            fn raw_decrypt(
                &self,
                _rng: &mut BoringSslRng,
                c: &[u8; $mod_size],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<()>, CryptoError> {
                if c >= &self.public.modulus {
                    return Ok(None);
                }
                // `c < n`, so raw decryption cannot fail.
                match self.decrypt(bssl_sys::RSA_NO_PADDING, c, out)? {
                    Some($mod_size) => Ok(Some(())),
                    _ => Err(CryptoError::Internal),
                }
            }

            #[inline(never)]
            fn oaep_encrypt(
                public: &Self::PublicKey,
                rng: &mut BoringSslRng,
                hash: TpmiAlgHash,
                label: &[u8],
                m: &[u8],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<()>, CryptoError> {
                let md = hash_alg_to_md(hash)?;
                // `RSAES-OAEP` requires `mLen <= k - 2 * hLen - 2`.
                let h_len = unsafe { bssl_sys::EVP_MD_size(md) };
                if m.len() + 2 * h_len + 2 > $mod_size {
                    return Ok(None);
                }
                // The OAEP seed comes from BoringSSL's system RNG.
                rng.check_system()?;
                let ctx = oaep_ctx(&public.rsa, md, label, true)?;
                let mut out_len: usize = $mod_size;
                check(unsafe {
                    bssl_sys::EVP_PKEY_encrypt(
                        ctx.as_ptr(),
                        out.as_mut_ptr(),
                        &raw mut out_len,
                        m.as_ptr(),
                        m.len(),
                    )
                })?;
                if out_len != $mod_size {
                    return Err(CryptoError::Internal);
                }
                Ok(Some(()))
            }

            #[inline(never)]
            fn oaep_decrypt(
                &self,
                _rng: &mut BoringSslRng,
                hash: TpmiAlgHash,
                label: &[u8],
                c: &[u8; $mod_size],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<usize>, CryptoError> {
                if c >= &self.public.modulus {
                    return Ok(None);
                }
                let md = hash_alg_to_md(hash)?;
                let ctx = oaep_ctx(&self.rsa, md, label, false)?;
                let mut out_len: usize = $mod_size;
                let ok = unsafe {
                    bssl_sys::EVP_PKEY_decrypt(
                        ctx.as_ptr(),
                        out.as_mut_ptr(),
                        &raw mut out_len,
                        c.as_ptr(),
                        $mod_size,
                    )
                };
                // `c < n`, so only invalid padding can fail.
                if ok != 1 {
                    return Ok(None);
                }
                if out_len > $mod_size {
                    return Err(CryptoError::Internal);
                }
                Ok(Some(out_len))
            }

            #[inline(never)]
            fn rsaes_encrypt(
                public: &Self::PublicKey,
                rng: &mut BoringSslRng,
                m: &[u8],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<()>, CryptoError> {
                // `RSAES-PKCS1-v1_5` requires at least 11 bytes of padding.
                if m.len() > $mod_size - 11 {
                    return Ok(None);
                }
                // The padding comes from BoringSSL's system RNG.
                rng.check_system()?;
                public
                    .encrypt(bssl_sys::RSA_PKCS1_PADDING, m, out)
                    .map(Some)
            }

            #[inline(never)]
            fn rsaes_decrypt(
                &self,
                _rng: &mut BoringSslRng,
                c: &[u8; $mod_size],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<usize>, CryptoError> {
                if c >= &self.public.modulus {
                    return Ok(None);
                }
                self.decrypt(bssl_sys::RSA_PKCS1_PADDING, c, out)
            }

            #[inline(never)]
            fn rsassa_sign(
                &self,
                _rng: &mut BoringSslRng,
                digest: TpmtHa<'_>,
                out: &mut [u8; $mod_size],
            ) -> Result<(), CryptoError> {
                let bytes = digest.digest();
                let nid = unsafe { bssl_sys::EVP_MD_type(hash_alg_to_md(digest.hash_alg())?) };
                let mut out_len: c_uint = 0;
                check(unsafe {
                    bssl_sys::RSA_sign(
                        nid,
                        bytes.as_ptr(),
                        bytes.len(),
                        out.as_mut_ptr(),
                        &raw mut out_len,
                        self.rsa.as_ptr(),
                    )
                })?;
                if out_len as usize != $mod_size {
                    return Err(CryptoError::Internal);
                }
                Ok(())
            }

            #[inline(never)]
            fn rsassa_verify(
                public: &Self::PublicKey,
                digest: TpmtHa<'_>,
                sig: &[u8; $mod_size],
            ) -> Result<bool, CryptoError> {
                let bytes = digest.digest();
                let nid = unsafe { bssl_sys::EVP_MD_type(hash_alg_to_md(digest.hash_alg())?) };
                let ok = unsafe {
                    bssl_sys::RSA_verify(
                        nid,
                        bytes.as_ptr(),
                        bytes.len(),
                        sig.as_ptr(),
                        $mod_size,
                        public.rsa.as_ptr(),
                    )
                };
                Ok(ok == 1)
            }

            #[inline(never)]
            fn rsapss_sign(
                &self,
                rng: &mut BoringSslRng,
                digest: TpmtHa<'_>,
                out: &mut [u8; $mod_size],
            ) -> Result<(), CryptoError> {
                let bytes = digest.digest();
                let md = hash_alg_to_md(digest.hash_alg())?;
                // The salt comes from BoringSSL's system RNG.
                rng.check_system()?;
                // TPM 2.0 `PssEncode`: the largest salt length up to the digest
                // size (`emLen - hLen - 2` for small keys).
                let salt_len = bytes.len().min($mod_size - bytes.len() - 2);
                let mut out_len: usize = 0;
                check(unsafe {
                    bssl_sys::RSA_sign_pss_mgf1(
                        self.rsa.as_ptr(),
                        &raw mut out_len,
                        out.as_mut_ptr(),
                        $mod_size,
                        bytes.as_ptr(),
                        bytes.len(),
                        md,
                        md,
                        salt_len as c_int,
                    )
                })?;
                if out_len != $mod_size {
                    return Err(CryptoError::Internal);
                }
                Ok(())
            }

            #[inline(never)]
            fn rsapss_verify(
                public: &Self::PublicKey,
                digest: TpmtHa<'_>,
                sig: &[u8; $mod_size],
            ) -> Result<bool, CryptoError> {
                let bytes = digest.digest();
                let md = hash_alg_to_md(digest.hash_alg())?;
                // TPM 2.0 `PssDecode`: accept any salt length.
                let ok = unsafe {
                    bssl_sys::RSA_verify_pss_mgf1(
                        public.rsa.as_ptr(),
                        bytes.as_ptr(),
                        bytes.len(),
                        md,
                        md,
                        bssl_sys::RSA_PSS_SALTLEN_AUTO,
                        sig.as_ptr(),
                        $mod_size,
                    )
                };
                Ok(ok == 1)
            }
        }
    };
}

impl_rsa_key!(128, 64);
impl_rsa_key!(256, 128);
impl_rsa_key!(384, 192);
impl_rsa_key!(512, 256);

impl Rsa for BoringSsl {
    type Rsa1024 = BoringSslRsaPrivateKey<128, 64>;
    type Rsa2048 = BoringSslRsaPrivateKey<256, 128>;
    type Rsa3072 = BoringSslRsaPrivateKey<384, 192>;
    type Rsa4096 = BoringSslRsaPrivateKey<512, 256>;
}
