//! RSA (`RSA-1024`, `RSA-2048`, `RSA-3072`, `RSA-4096`) implementations backed
//! by BoringSSL's FIPS-module `RSA_*`, `EVP_PKEY_*` (for `RSAES-OAEP`), and
//! `BN_*` APIs.

use core::ptr::{self, NonNull};

use tpm2::{
    TpmiAlgHash, TpmtHa,
    crypto::{
        CryptoError, Rng, RsaEncryptScheme,
        backend::{AsymmetricKey, Rsa, RsaKey, RsaSigScheme},
    },
};

use crate::{BoringSsl, bssl_sys};

pub(crate) struct BnPtr(NonNull<bssl_sys::BIGNUM>);

impl BnPtr {
    pub(crate) fn new() -> Result<Self, CryptoError> {
        NonNull::new(unsafe { bssl_sys::BN_new() })
            .map(Self)
            .ok_or(CryptoError::Internal)
    }

    pub(crate) fn from_be(bytes: &[u8]) -> Result<Self, CryptoError> {
        NonNull::new(unsafe { bssl_sys::BN_bin2bn(bytes.as_ptr(), bytes.len(), ptr::null_mut()) })
            .map(Self)
            .ok_or(CryptoError::Internal)
    }

    pub(crate) fn from_u32(val: u32) -> Result<Self, CryptoError> {
        let bn = Self::new()?;
        let ok = unsafe { bssl_sys::BN_set_word(bn.as_ptr(), u64::from(val)) };
        if ok != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(bn)
    }

    pub(crate) fn to_be_padded(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        let ok = unsafe { bssl_sys::BN_bn2bin_padded(out.as_mut_ptr(), out.len(), self.as_ptr()) };
        if ok != 1 {
            return Err(CryptoError::Internal);
        }
        Ok(())
    }

    #[inline]
    pub(crate) const fn as_ptr(&self) -> *mut bssl_sys::BIGNUM {
        self.0.as_ptr()
    }
}

impl Drop for BnPtr {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::BN_clear_free(self.0.as_ptr());
        }
    }
}

pub(crate) struct BnCtxPtr(NonNull<bssl_sys::BN_CTX>);

impl BnCtxPtr {
    pub(crate) fn new() -> Result<Self, CryptoError> {
        NonNull::new(unsafe { bssl_sys::BN_CTX_new() })
            .map(Self)
            .ok_or(CryptoError::Internal)
    }

    #[inline]
    pub(crate) const fn as_ptr(&self) -> *mut bssl_sys::BN_CTX {
        self.0.as_ptr()
    }
}

impl Drop for BnCtxPtr {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::BN_CTX_free(self.0.as_ptr());
        }
    }
}

/// Validated RSA public key backed by BoringSSL `RSA`.
pub struct BoringSslRsaPublicKey<const MOD_SIZE: usize> {
    rsa: NonNull<bssl_sys::RSA>,
    exponent: u32,
    modulus: [u8; MOD_SIZE],
}

// SAFETY: `bssl_sys::RSA` is reference-counted and internally synchronized via mutexes.
unsafe impl<const MOD_SIZE: usize> Send for BoringSslRsaPublicKey<MOD_SIZE> {}
unsafe impl<const MOD_SIZE: usize> Sync for BoringSslRsaPublicKey<MOD_SIZE> {}

impl<const MOD_SIZE: usize> Clone for BoringSslRsaPublicKey<MOD_SIZE> {
    fn clone(&self) -> Self {
        unsafe {
            bssl_sys::RSA_up_ref(self.rsa.as_ptr());
        }
        Self {
            rsa: self.rsa,
            exponent: self.exponent,
            modulus: self.modulus,
        }
    }
}

impl<const MOD_SIZE: usize> Drop for BoringSslRsaPublicKey<MOD_SIZE> {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::RSA_free(self.rsa.as_ptr());
        }
    }
}

/// Validated RSA private key backed by BoringSSL `RSA`.
pub struct BoringSslRsaPrivateKey<const MOD_SIZE: usize, const PRIME_SIZE: usize> {
    rsa: NonNull<bssl_sys::RSA>,
    public: BoringSslRsaPublicKey<MOD_SIZE>,
    prime_p: [u8; PRIME_SIZE],
}

// SAFETY: `bssl_sys::RSA` is reference-counted and internally synchronized via mutexes.
unsafe impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> Send
    for BoringSslRsaPrivateKey<MOD_SIZE, PRIME_SIZE>
{
}
unsafe impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> Sync
    for BoringSslRsaPrivateKey<MOD_SIZE, PRIME_SIZE>
{
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> Clone
    for BoringSslRsaPrivateKey<MOD_SIZE, PRIME_SIZE>
{
    fn clone(&self) -> Self {
        unsafe {
            bssl_sys::RSA_up_ref(self.rsa.as_ptr());
        }
        Self {
            rsa: self.rsa,
            public: self.public.clone(),
            prime_p: self.prime_p,
        }
    }
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> Drop
    for BoringSslRsaPrivateKey<MOD_SIZE, PRIME_SIZE>
{
    fn drop(&mut self) {
        unsafe {
            bssl_sys::RSA_free(self.rsa.as_ptr());
            bssl_sys::OPENSSL_cleanse(self.prime_p.as_mut_ptr().cast(), PRIME_SIZE);
        }
    }
}

/// Marker type implementing [`RsaKey<MOD_SIZE, PRIME_SIZE>`].
pub struct BoringSslRsa<const MOD_SIZE: usize, const PRIME_SIZE: usize>;

fn hash_alg_to_nid(alg: TpmiAlgHash) -> Option<core::ffi::c_int> {
    match alg {
        TpmiAlgHash::Sha1 => Some(bssl_sys::NID_sha1),
        TpmiAlgHash::Sha256 => Some(bssl_sys::NID_sha256),
        TpmiAlgHash::Sha384 => Some(bssl_sys::NID_sha384),
        TpmiAlgHash::Sha512 => Some(bssl_sys::NID_sha512),
        _ => None,
    }
}

fn hash_alg_to_md(alg: TpmiAlgHash) -> Result<*const bssl_sys::EVP_MD, CryptoError> {
    let md = unsafe {
        match alg {
            TpmiAlgHash::Sha1 => bssl_sys::EVP_sha1(),
            TpmiAlgHash::Sha256 => bssl_sys::EVP_sha256(),
            TpmiAlgHash::Sha384 => bssl_sys::EVP_sha384(),
            TpmiAlgHash::Sha512 => bssl_sys::EVP_sha512(),
            _ => return Err(CryptoError::Unsupported),
        }
    };
    if md.is_null() {
        Err(CryptoError::Internal)
    } else {
        Ok(md)
    }
}

/// `EVP_PKEY_CTX` configured for `RSAES-OAEP` encryption or decryption.
struct OaepCtxPtr(NonNull<bssl_sys::EVP_PKEY_CTX>);

impl OaepCtxPtr {
    /// Creates an `RSAES-OAEP` context for `rsa`, using `md` for both the OAEP
    /// digest and `MGF1`, and `label` as the OAEP label `L` (no label if empty).
    fn new(
        rsa: NonNull<bssl_sys::RSA>,
        md: *const bssl_sys::EVP_MD,
        label: &[u8],
        encrypt: bool,
    ) -> Result<Self, CryptoError> {
        let pkey =
            NonNull::new(unsafe { bssl_sys::EVP_PKEY_new() }).ok_or(CryptoError::Internal)?;
        let ctx = unsafe {
            if bssl_sys::EVP_PKEY_set1_RSA(pkey.as_ptr(), rsa.as_ptr()) == 1 {
                bssl_sys::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut())
            } else {
                ptr::null_mut()
            }
        };
        // `EVP_PKEY_CTX_new` holds its own reference to `pkey`.
        unsafe {
            bssl_sys::EVP_PKEY_free(pkey.as_ptr());
        }
        let Some(ctx) = NonNull::new(ctx) else {
            unsafe {
                bssl_sys::ERR_clear_error();
            }
            return Err(CryptoError::Internal);
        };
        let ctx = Self(ctx);

        let ok = unsafe {
            let init = if encrypt {
                bssl_sys::EVP_PKEY_encrypt_init(ctx.as_ptr())
            } else {
                bssl_sys::EVP_PKEY_decrypt_init(ctx.as_ptr())
            };
            init == 1
                && bssl_sys::EVP_PKEY_CTX_set_rsa_padding(
                    ctx.as_ptr(),
                    bssl_sys::RSA_PKCS1_OAEP_PADDING,
                ) == 1
                && bssl_sys::EVP_PKEY_CTX_set_rsa_oaep_md(ctx.as_ptr(), md) == 1
                && bssl_sys::EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.as_ptr(), md) == 1
        };
        if !ok {
            unsafe {
                bssl_sys::ERR_clear_error();
            }
            return Err(CryptoError::Internal);
        }

        if !label.is_empty() {
            let copy = unsafe { bssl_sys::OPENSSL_memdup(label.as_ptr().cast(), label.len()) };
            if copy.is_null() {
                return Err(CryptoError::Internal);
            }
            // On success, `EVP_PKEY_CTX_set0_rsa_oaep_label` takes ownership of `copy`.
            let ok = unsafe {
                bssl_sys::EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.as_ptr(), copy.cast(), label.len())
            };
            if ok != 1 {
                unsafe {
                    bssl_sys::OPENSSL_free(copy);
                    bssl_sys::ERR_clear_error();
                }
                return Err(CryptoError::Internal);
            }
        }
        Ok(ctx)
    }

    #[inline]
    const fn as_ptr(&self) -> *mut bssl_sys::EVP_PKEY_CTX {
        self.0.as_ptr()
    }
}

impl Drop for OaepCtxPtr {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::EVP_PKEY_CTX_free(self.0.as_ptr());
        }
    }
}

/// Generates a random prime `p` of `PRIME_SIZE` bytes from `rng` such that
/// `p` has its top two bits set, `gcd(p - 1, e) == 1`, and if `other_p` is
/// `Some(q)`, `|p - q| > 2^(prime_bits - 100)`.
#[inline(never)]
fn generate_prime_from_rng<const PRIME_SIZE: usize>(
    rng: &mut impl Rng,
    e: &BnPtr,
    other_p: Option<&BnPtr>,
    ctx: &BnCtxPtr,
) -> Result<([u8; PRIME_SIZE], BnPtr), CryptoError> {
    let prime_bits = (PRIME_SIZE * 8) as core::ffi::c_uint;
    let min_diff_bits = prime_bits.saturating_sub(100);
    let cand = BnPtr::new()?;
    let pm1 = BnPtr::new()?;
    let gcd = BnPtr::new()?;
    let diff = BnPtr::new()?;
    let mut buf = [0u8; PRIME_SIZE];

    let max_tries = (PRIME_SIZE * 8) * 16;
    for _ in 0..max_tries {
        rng.fill_bytes(&mut buf)?;
        // Set top two bits (so p * q is guaranteed to have MOD_SIZE * 8 bits)
        // and bottom bit (odd), matching FIPS 186-5 Appendix A.1.3.
        buf[0] |= 0xc0;
        buf[PRIME_SIZE - 1] |= 0x01;

        if unsafe { bssl_sys::BN_bin2bn(buf.as_ptr(), PRIME_SIZE, cand.as_ptr()) }.is_null() {
            buf.fill(0);
            return Err(CryptoError::Internal);
        }

        if let Some(p) = other_p {
            let ok = unsafe {
                if bssl_sys::BN_cmp(cand.as_ptr(), p.as_ptr()) >= 0 {
                    bssl_sys::BN_sub(diff.as_ptr(), cand.as_ptr(), p.as_ptr())
                } else {
                    bssl_sys::BN_sub(diff.as_ptr(), p.as_ptr(), cand.as_ptr())
                }
            };
            if ok != 1 {
                buf.fill(0);
                return Err(CryptoError::Internal);
            }
            if unsafe { bssl_sys::BN_num_bits(diff.as_ptr()) } <= min_diff_bits {
                continue;
            }
        }

        let ok = unsafe {
            !bssl_sys::BN_copy(pm1.as_ptr(), cand.as_ptr()).is_null()
                && bssl_sys::BN_sub_word(pm1.as_ptr(), 1) == 1
                && bssl_sys::BN_gcd(gcd.as_ptr(), pm1.as_ptr(), e.as_ptr(), ctx.as_ptr()) == 1
        };
        if !ok {
            buf.fill(0);
            return Err(CryptoError::Internal);
        }
        if unsafe { bssl_sys::BN_is_one(gcd.as_ptr()) } != 1 {
            continue;
        }

        let mut is_prime: core::ffi::c_int = 0;
        let ok = unsafe {
            bssl_sys::BN_primality_test(
                &raw mut is_prime,
                cand.as_ptr(),
                bssl_sys::BN_prime_checks_for_generation,
                ctx.as_ptr(),
                0,
                ptr::null_mut(),
            )
        };
        if ok != 1 {
            buf.fill(0);
            return Err(CryptoError::Internal);
        }
        if is_prime == 1 {
            return Ok((buf, cand));
        }
    }

    buf.fill(0);
    Err(CryptoError::Internal)
}

macro_rules! impl_rsa_key {
    ($mod_size:literal, $prime_size:literal) => {
        impl AsymmetricKey<$mod_size, $prime_size, u32> for BoringSslRsa<$mod_size, $prime_size> {
            type Public = BoringSslRsaPublicKey<$mod_size>;
            type Private = BoringSslRsaPrivateKey<$mod_size, $prime_size>;

            #[inline(never)]
            fn load_public(
                exponent: u32,
                modulus: &[u8; $mod_size],
            ) -> Result<Option<Self::Public>, CryptoError> {
                if exponent < 3 || exponent % 2 == 0 {
                    return Err(CryptoError::Unsupported);
                }
                if (modulus[0] & 0x80) == 0 || (modulus[$mod_size - 1] & 0x01) == 0 {
                    return Ok(None);
                }
                let n = BnPtr::from_be(modulus)?;
                let e = BnPtr::from_u32(exponent)?;
                let rsa_ptr = unsafe { bssl_sys::RSA_new_public_key(n.as_ptr(), e.as_ptr()) };
                let Some(rsa) = NonNull::new(rsa_ptr) else {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    return Ok(None);
                };
                Ok(Some(BoringSslRsaPublicKey {
                    rsa,
                    exponent,
                    modulus: *modulus,
                }))
            }

            fn store_public(
                public: &Self::Public,
                out: &mut [u8; $mod_size],
            ) -> Result<(), CryptoError> {
                out.copy_from_slice(&public.modulus);
                Ok(())
            }

            #[inline(never)]
            fn load_private(
                public: Self::Public,
                prime_p: &[u8; $prime_size],
            ) -> Result<Option<Self::Private>, CryptoError> {
                if (prime_p[0] & 0x80) == 0 || (prime_p[$prime_size - 1] & 0x01) == 0 {
                    return Ok(None);
                }

                let ctx = BnCtxPtr::new()?;
                let p = BnPtr::from_be(prime_p)?;
                let q = BnPtr::new()?;
                let rem = BnPtr::new()?;
                let pm1 = BnPtr::new()?;
                let qm1 = BnPtr::new()?;
                let gcd = BnPtr::new()?;
                let phi = BnPtr::new()?;
                let lcm = BnPtr::new()?;
                let d = BnPtr::new()?;
                let dmp1 = BnPtr::new()?;
                let dmq1 = BnPtr::new()?;
                let iqmp = BnPtr::new()?;

                let n_ptr = unsafe { bssl_sys::RSA_get0_n(public.rsa.as_ptr()) };
                let e_ptr = unsafe { bssl_sys::RSA_get0_e(public.rsa.as_ptr()) };
                if n_ptr.is_null() || e_ptr.is_null() {
                    return Err(CryptoError::Internal);
                }

                let div_ok = unsafe {
                    bssl_sys::BN_div(q.as_ptr(), rem.as_ptr(), n_ptr, p.as_ptr(), ctx.as_ptr())
                };
                if div_ok != 1 {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    return Ok(None);
                }

                let valid_q = unsafe {
                    bssl_sys::BN_is_zero(rem.as_ptr()) == 1
                        && bssl_sys::BN_num_bits(q.as_ptr())
                            == ($prime_size * 8) as core::ffi::c_uint
                        && bssl_sys::BN_is_odd(q.as_ptr()) == 1
                };
                if !valid_q {
                    return Ok(None);
                }

                // Verify p and q are prime so composite factors cannot slip through.
                let mut p_prime: core::ffi::c_int = 0;
                let mut q_prime: core::ffi::c_int = 0;
                let primality_ok = unsafe {
                    bssl_sys::BN_primality_test(
                        &raw mut p_prime,
                        p.as_ptr(),
                        bssl_sys::BN_prime_checks_for_generation,
                        ctx.as_ptr(),
                        0,
                        ptr::null_mut(),
                    ) == 1
                        && bssl_sys::BN_primality_test(
                            &raw mut q_prime,
                            q.as_ptr(),
                            bssl_sys::BN_prime_checks_for_generation,
                            ctx.as_ptr(),
                            0,
                            ptr::null_mut(),
                        ) == 1
                };
                if !primality_ok {
                    return Err(CryptoError::Internal);
                }
                if p_prime != 1 || q_prime != 1 {
                    return Ok(None);
                }

                let math_ok = unsafe {
                    !bssl_sys::BN_copy(pm1.as_ptr(), p.as_ptr()).is_null()
                        && bssl_sys::BN_sub_word(pm1.as_ptr(), 1) == 1
                        && !bssl_sys::BN_copy(qm1.as_ptr(), q.as_ptr()).is_null()
                        && bssl_sys::BN_sub_word(qm1.as_ptr(), 1) == 1
                        && bssl_sys::BN_mul(phi.as_ptr(), pm1.as_ptr(), qm1.as_ptr(), ctx.as_ptr())
                            == 1
                        && bssl_sys::BN_gcd(gcd.as_ptr(), pm1.as_ptr(), qm1.as_ptr(), ctx.as_ptr())
                            == 1
                        && bssl_sys::BN_div(
                            lcm.as_ptr(),
                            ptr::null_mut(),
                            phi.as_ptr(),
                            gcd.as_ptr(),
                            ctx.as_ptr(),
                        ) == 1
                };
                if !math_ok {
                    return Err(CryptoError::Internal);
                }

                let inv_ok = unsafe {
                    !bssl_sys::BN_mod_inverse(d.as_ptr(), e_ptr, lcm.as_ptr(), ctx.as_ptr())
                        .is_null()
                        && bssl_sys::BN_nnmod(dmp1.as_ptr(), d.as_ptr(), pm1.as_ptr(), ctx.as_ptr())
                            == 1
                        && bssl_sys::BN_nnmod(dmq1.as_ptr(), d.as_ptr(), qm1.as_ptr(), ctx.as_ptr())
                            == 1
                        && !bssl_sys::BN_mod_inverse(
                            iqmp.as_ptr(),
                            q.as_ptr(),
                            p.as_ptr(),
                            ctx.as_ptr(),
                        )
                        .is_null()
                };
                if !inv_ok {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    return Ok(None);
                }

                let rsa_ptr = unsafe {
                    bssl_sys::RSA_new_private_key(
                        n_ptr,
                        e_ptr,
                        d.as_ptr(),
                        p.as_ptr(),
                        q.as_ptr(),
                        dmp1.as_ptr(),
                        dmq1.as_ptr(),
                        iqmp.as_ptr(),
                    )
                };
                let Some(rsa) = NonNull::new(rsa_ptr) else {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    return Ok(None);
                };

                Ok(Some(BoringSslRsaPrivateKey {
                    rsa,
                    public,
                    prime_p: *prime_p,
                }))
            }

            #[inline(never)]
            fn generate(rng: &mut impl Rng, exponent: u32) -> Result<Self::Private, CryptoError> {
                if exponent < 3 || exponent % 2 == 0 {
                    return Err(CryptoError::Unsupported);
                }
                let ctx = BnCtxPtr::new()?;
                let e = BnPtr::from_u32(exponent)?;
                let n = BnPtr::new()?;

                for _ in 0..8 {
                    let (mut p_bytes, p) =
                        generate_prime_from_rng::<$prime_size>(rng, &e, None, &ctx)?;
                    let (mut q_bytes, q) =
                        generate_prime_from_rng::<$prime_size>(rng, &e, Some(&p), &ctx)?;
                    unsafe {
                        bssl_sys::OPENSSL_cleanse(q_bytes.as_mut_ptr().cast(), $prime_size);
                    }

                    let mul_ok = unsafe {
                        bssl_sys::BN_mul(n.as_ptr(), p.as_ptr(), q.as_ptr(), ctx.as_ptr())
                    };
                    if mul_ok != 1 {
                        unsafe {
                            bssl_sys::OPENSSL_cleanse(p_bytes.as_mut_ptr().cast(), $prime_size);
                        }
                        return Err(CryptoError::Internal);
                    }

                    let mut modulus = [0u8; $mod_size];
                    if n.to_be_padded(&mut modulus).is_err() {
                        unsafe {
                            bssl_sys::OPENSSL_cleanse(p_bytes.as_mut_ptr().cast(), $prime_size);
                        }
                        continue;
                    }

                    if let Some(pub_key) = Self::load_public(exponent, &modulus)? {
                        if let Some(priv_key) = Self::load_private(pub_key, &p_bytes)? {
                            unsafe {
                                bssl_sys::OPENSSL_cleanse(p_bytes.as_mut_ptr().cast(), $prime_size);
                            }
                            return Ok(priv_key);
                        }
                    }
                    unsafe {
                        bssl_sys::OPENSSL_cleanse(p_bytes.as_mut_ptr().cast(), $prime_size);
                    }
                }

                Err(CryptoError::Internal)
            }

            fn as_public(private: &Self::Private) -> &Self::Public {
                &private.public
            }

            fn store_private(
                private: &Self::Private,
                out: &mut [u8; $prime_size],
            ) -> Result<(), CryptoError> {
                out.copy_from_slice(&private.prime_p);
                Ok(())
            }
        }

        impl RsaKey<$mod_size, $prime_size> for BoringSslRsa<$mod_size, $prime_size> {
            fn exponent(public: &Self::Public) -> u32 {
                public.exponent
            }

            #[inline(never)]
            fn encrypt(
                _rng: &mut impl Rng,
                public: &Self::Public,
                scheme: RsaEncryptScheme<'_>,
                plaintext: &[u8],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<()>, CryptoError> {
                let mut out_len: usize = 0;
                let ok = match scheme {
                    RsaEncryptScheme::Raw => {
                        // `plaintext` is a big-endian integer which may be
                        // shorter than the modulus or have extra leading zeros.
                        let start = plaintext
                            .iter()
                            .position(|&b| b != 0)
                            .unwrap_or(plaintext.len());
                        let value = &plaintext[start..];
                        let Some(pad) = usize::checked_sub($mod_size, value.len()) else {
                            return Ok(None);
                        };
                        let mut input = [0u8; $mod_size];
                        input[pad..].copy_from_slice(value);
                        if input >= public.modulus {
                            return Ok(None);
                        }
                        unsafe {
                            bssl_sys::RSA_encrypt(
                                public.rsa.as_ptr(),
                                &raw mut out_len,
                                out.as_mut_ptr(),
                                $mod_size,
                                input.as_ptr(),
                                $mod_size,
                                bssl_sys::RSA_NO_PADDING,
                            )
                        }
                    }
                    RsaEncryptScheme::Rsaes => {
                        // `RSAES-PKCS1-v1_5` requires at least 11 bytes of padding.
                        if plaintext.len() > $mod_size - 11 {
                            return Ok(None);
                        }
                        unsafe {
                            bssl_sys::RSA_encrypt(
                                public.rsa.as_ptr(),
                                &raw mut out_len,
                                out.as_mut_ptr(),
                                $mod_size,
                                plaintext.as_ptr(),
                                plaintext.len(),
                                bssl_sys::RSA_PKCS1_PADDING,
                            )
                        }
                    }
                    RsaEncryptScheme::Oaep { hash, .. } => {
                        let md = hash_alg_to_md(hash)?;
                        // `RSAES-OAEP` requires `mLen <= k - 2 * hLen - 2`.
                        let h_len = unsafe { bssl_sys::EVP_MD_size(md) };
                        if plaintext.len() + 2 * h_len + 2 > $mod_size {
                            return Ok(None);
                        }
                        let ctx = OaepCtxPtr::new(public.rsa, md, scheme.label_bytes(), true)?;
                        out_len = $mod_size;
                        unsafe {
                            bssl_sys::EVP_PKEY_encrypt(
                                ctx.as_ptr(),
                                out.as_mut_ptr(),
                                &raw mut out_len,
                                plaintext.as_ptr(),
                                plaintext.len(),
                            )
                        }
                    }
                };
                if ok != 1 || out_len != $mod_size {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    return Err(CryptoError::Internal);
                }
                Ok(Some(()))
            }

            #[inline(never)]
            fn decrypt(
                _rng: &mut impl Rng,
                private: &Self::Private,
                scheme: RsaEncryptScheme<'_>,
                ciphertext: &[u8; $mod_size],
                out: &mut [u8; $mod_size],
            ) -> Result<Option<usize>, CryptoError> {
                if ciphertext >= &private.public.modulus {
                    return Ok(None);
                }
                let mut out_len: usize = 0;
                let ok = match scheme {
                    RsaEncryptScheme::Raw | RsaEncryptScheme::Rsaes => {
                        let padding = if scheme == RsaEncryptScheme::Raw {
                            bssl_sys::RSA_NO_PADDING
                        } else {
                            bssl_sys::RSA_PKCS1_PADDING
                        };
                        unsafe {
                            bssl_sys::RSA_decrypt(
                                private.rsa.as_ptr(),
                                &raw mut out_len,
                                out.as_mut_ptr(),
                                $mod_size,
                                ciphertext.as_ptr(),
                                $mod_size,
                                padding,
                            )
                        }
                    }
                    RsaEncryptScheme::Oaep { hash, .. } => {
                        let md = hash_alg_to_md(hash)?;
                        let ctx = OaepCtxPtr::new(private.rsa, md, scheme.label_bytes(), false)?;
                        out_len = $mod_size;
                        unsafe {
                            bssl_sys::EVP_PKEY_decrypt(
                                ctx.as_ptr(),
                                out.as_mut_ptr(),
                                &raw mut out_len,
                                ciphertext.as_ptr(),
                                $mod_size,
                            )
                        }
                    }
                };
                if ok != 1 {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    // `ciphertext < n`, so only invalid padding can fail.
                    return match scheme {
                        RsaEncryptScheme::Raw => Err(CryptoError::Internal),
                        _ => Ok(None),
                    };
                }
                if out_len > $mod_size || (scheme == RsaEncryptScheme::Raw && out_len != $mod_size)
                {
                    return Err(CryptoError::Internal);
                }
                Ok(Some(out_len))
            }

            #[inline(never)]
            fn sign(
                _rng: &mut impl Rng,
                private: &Self::Private,
                scheme: RsaSigScheme,
                digest: TpmtHa<'_>,
                out: &mut [u8; $mod_size],
            ) -> Result<(), CryptoError> {
                let bytes = digest.digest();
                match scheme {
                    RsaSigScheme::Rsassa => {
                        let Some(nid) = hash_alg_to_nid(digest.hash_alg()) else {
                            return Err(CryptoError::Unsupported);
                        };
                        let mut out_len: core::ffi::c_uint = 0;
                        let ok = unsafe {
                            bssl_sys::RSA_sign(
                                nid,
                                bytes.as_ptr(),
                                bytes.len(),
                                out.as_mut_ptr(),
                                &raw mut out_len,
                                private.rsa.as_ptr(),
                            )
                        };
                        if ok != 1 || out_len as usize != $mod_size {
                            unsafe {
                                bssl_sys::ERR_clear_error();
                            }
                            return Err(CryptoError::Internal);
                        }
                        Ok(())
                    }
                    RsaSigScheme::Rsapss => {
                        let md = hash_alg_to_md(digest.hash_alg())?;
                        // TPM 2.0 `PssEncode`: the largest salt length up to
                        // the digest size (`emLen - hLen - 2` for small keys).
                        let salt_len = bytes.len().min($mod_size - bytes.len() - 2);
                        let mut out_len: usize = 0;
                        let ok = unsafe {
                            bssl_sys::RSA_sign_pss_mgf1(
                                private.rsa.as_ptr(),
                                &raw mut out_len,
                                out.as_mut_ptr(),
                                $mod_size,
                                bytes.as_ptr(),
                                bytes.len(),
                                md,
                                md,
                                salt_len as core::ffi::c_int,
                            )
                        };
                        if ok != 1 || out_len != $mod_size {
                            unsafe {
                                bssl_sys::ERR_clear_error();
                            }
                            return Err(CryptoError::Internal);
                        }
                        Ok(())
                    }
                }
            }

            #[inline(never)]
            fn verify(
                public: &Self::Public,
                scheme: RsaSigScheme,
                digest: TpmtHa<'_>,
                sig: &[u8; $mod_size],
            ) -> Result<bool, CryptoError> {
                let bytes = digest.digest();
                let ok = match scheme {
                    RsaSigScheme::Rsassa => {
                        let Some(nid) = hash_alg_to_nid(digest.hash_alg()) else {
                            return Err(CryptoError::Unsupported);
                        };
                        unsafe {
                            bssl_sys::RSA_verify(
                                nid,
                                bytes.as_ptr(),
                                bytes.len(),
                                sig.as_ptr(),
                                $mod_size,
                                public.rsa.as_ptr(),
                            )
                        }
                    }
                    RsaSigScheme::Rsapss => {
                        let md = hash_alg_to_md(digest.hash_alg())?;
                        // TPM 2.0 `PssDecode`: accept any salt length.
                        unsafe {
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
                        }
                    }
                };
                if ok != 1 {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    return Ok(false);
                }
                Ok(true)
            }
        }
    };
}

impl_rsa_key!(128, 64);
impl_rsa_key!(256, 128);
impl_rsa_key!(384, 192);
impl_rsa_key!(512, 256);

impl Rsa for BoringSsl {
    type Rsa1024 = BoringSslRsa<128, 64>;
    type Rsa2048 = BoringSslRsa<256, 128>;
    type Rsa3072 = BoringSslRsa<384, 192>;
    type Rsa4096 = BoringSslRsa<512, 256>;
}
