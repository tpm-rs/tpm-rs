//! Non-FIPS Curve25519 (`Ed25519` and `X25519`) implementations backed by
//! BoringSSL's `curve25519.h` and internal `x25519_ge_*` APIs.
//!
//! Enabled by the `non-fips` Cargo feature.

use core::{mem::MaybeUninit, ptr};

use tpm2::crypto::{
    Crypto, CryptoError, Rng,
    backend::{AsymmetricKey, EdwardsCurve, HashState, MontgomeryCurve},
};

use crate::{
    BoringSsl, BoringSslHashState, bcm, bssl_sys,
    rsa::{BnCtxPtr, BnPtr},
};

/// Order `L = 2^252 + 27742317777372353535851937790883648493` of the Ed25519
/// prime-order subgroup in little-endian byte order.
const ED25519_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Stack threshold before falling back to multi-slice streaming Ed25519.
const STACK_MSG_BUF_LEN: usize = 4096;

/// Validated Ed25519 public key (RFC 8032 compressed Edwards point).
#[derive(Clone)]
pub struct BoringSslEd25519PublicKey {
    point: [u8; 32],
}

/// Validated Ed25519 private key (`seed || public_point` 64-byte keypair).
#[derive(Clone)]
pub struct BoringSslEd25519PrivateKey {
    keypair: [u8; 64],
    public: BoringSslEd25519PublicKey,
}

impl Drop for BoringSslEd25519PrivateKey {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::OPENSSL_cleanse(self.keypair.as_mut_ptr().cast(), self.keypair.len());
        }
    }
}

/// Marker type implementing [`EdwardsCurve<32>`] for Ed25519.
pub struct BoringSslEd25519;

impl BoringSslEd25519 {
    /// Derives a private key (and its public key) from the RFC 8032 secret
    /// seed `secret`.
    #[inline(never)]
    fn from_secret(secret: &[u8; 32]) -> Result<Option<BoringSslEd25519PrivateKey>, CryptoError> {
        let mut point = [0u8; 32];
        let mut keypair = [0u8; 64];
        unsafe {
            bssl_sys::ED25519_keypair_from_seed(
                point.as_mut_ptr(),
                keypair.as_mut_ptr(),
                secret.as_ptr(),
            );
        }
        Ok(Some(BoringSslEd25519PrivateKey {
            keypair,
            public: BoringSslEd25519PublicKey { point },
        }))
    }

    fn sign_streaming(
        private: &BoringSslEd25519PrivateKey,
        msg: &[&[u8]],
        out_r: &mut [u8; 32],
        out_s: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let mut az = [0u8; 64];
        BoringSslHashState::<64>::hash(&[&private.keypair[..32]], &mut az)?;
        az[0] &= 248;
        az[31] &= 63;
        az[31] |= 64;

        let mut st = BoringSslHashState::<64>::init()?;
        st.update(&az[32..64])?;
        for slice in msg {
            st.update(slice)?;
        }
        let mut nonce = [0u8; 64];
        st.finalize(&mut nonce)?;
        unsafe {
            bcm::bssl_x25519_sc_reduce(nonce.as_mut_ptr());
        }

        let mut r_p3 = MaybeUninit::<bcm::bssl_ge_p3>::uninit();
        unsafe {
            bcm::bssl_x25519_ge_scalarmult_base(r_p3.as_mut_ptr(), nonce.as_ptr());
        }
        let r_p3 = unsafe { r_p3.assume_init() };
        let r_p2 = bcm::bssl_ge_p2 {
            X: r_p3.X,
            Y: r_p3.Y,
            Z: r_p3.Z,
        };
        unsafe {
            bcm::bssl_x25519_ge_tobytes(out_r.as_mut_ptr(), &raw const r_p2);
        }

        let mut st = BoringSslHashState::<64>::init()?;
        st.update(out_r)?;
        st.update(&private.keypair[32..64])?;
        for slice in msg {
            st.update(slice)?;
        }
        let mut hram = [0u8; 64];
        st.finalize(&mut hram)?;
        unsafe {
            bcm::bssl_x25519_sc_reduce(hram.as_mut_ptr());
        }

        // out_s = (hram[..32] * az[..32] + nonce[..32]) mod L (in little-endian).
        let ctx = BnCtxPtr::new()?;
        let bn_l = BnPtr::new()?;
        let bn_h = BnPtr::new()?;
        let bn_a = BnPtr::new()?;
        let bn_n = BnPtr::new()?;
        let bn_s = BnPtr::new()?;
        let ok = unsafe {
            !bssl_sys::BN_le2bn(ED25519_ORDER_LE.as_ptr(), 32, bn_l.as_ptr()).is_null()
                && !bssl_sys::BN_le2bn(hram.as_ptr(), 32, bn_h.as_ptr()).is_null()
                && !bssl_sys::BN_le2bn(az.as_ptr(), 32, bn_a.as_ptr()).is_null()
                && !bssl_sys::BN_le2bn(nonce.as_ptr(), 32, bn_n.as_ptr()).is_null()
                && bssl_sys::BN_mod_mul(
                    bn_s.as_ptr(),
                    bn_h.as_ptr(),
                    bn_a.as_ptr(),
                    bn_l.as_ptr(),
                    ctx.as_ptr(),
                ) == 1
                && bssl_sys::BN_mod_add(
                    bn_s.as_ptr(),
                    bn_s.as_ptr(),
                    bn_n.as_ptr(),
                    bn_l.as_ptr(),
                    ctx.as_ptr(),
                ) == 1
                && bssl_sys::BN_bn2le_padded(out_s.as_mut_ptr(), 32, bn_s.as_ptr()) == 1
        };
        unsafe {
            bssl_sys::OPENSSL_cleanse(az.as_mut_ptr().cast(), az.len());
            bssl_sys::OPENSSL_cleanse(nonce.as_mut_ptr().cast(), nonce.len());
        }
        if !ok {
            return Err(CryptoError::Internal);
        }
        Ok(())
    }

    fn verify_streaming(
        public: &BoringSslEd25519PublicKey,
        msg: &[&[u8]],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        if (sig_s[31] & 224) != 0 {
            return Ok(false);
        }
        let bn_l = BnPtr::new()?;
        let bn_s = BnPtr::new()?;
        let s_valid = unsafe {
            !bssl_sys::BN_le2bn(ED25519_ORDER_LE.as_ptr(), 32, bn_l.as_ptr()).is_null()
                && !bssl_sys::BN_le2bn(sig_s.as_ptr(), 32, bn_s.as_ptr()).is_null()
                && bssl_sys::BN_cmp(bn_s.as_ptr(), bn_l.as_ptr()) < 0
        };
        if !s_valid {
            return Ok(false);
        }

        let mut a_p3 = MaybeUninit::<bcm::bssl_ge_p3>::uninit();
        let ok = unsafe {
            bcm::bssl_x25519_ge_frombytes_vartime(a_p3.as_mut_ptr(), public.point.as_ptr())
        };
        if ok != 1 {
            return Ok(false);
        }
        let a_p3 = unsafe { a_p3.assume_init() };

        let mut st = BoringSslHashState::<64>::init()?;
        st.update(sig_r)?;
        st.update(&public.point)?;
        for slice in msg {
            st.update(slice)?;
        }
        let mut h = [0u8; 64];
        st.finalize(&mut h)?;
        unsafe {
            bcm::bssl_x25519_sc_reduce(h.as_mut_ptr());
        }

        // Compute R = [s]B - [h]A.
        let mut ha_p2 = MaybeUninit::<bcm::bssl_ge_p2>::uninit();
        let mut ha_bytes = [0u8; 32];
        let mut ha_p3 = MaybeUninit::<bcm::bssl_ge_p3>::uninit();
        let mut ha_cached = MaybeUninit::<bcm::bssl_ge_cached>::uninit();
        let mut sb_p3 = MaybeUninit::<bcm::bssl_ge_p3>::uninit();
        let mut r_p1p1 = MaybeUninit::<bcm::bssl_ge_p1p1>::uninit();
        let mut r_p2 = MaybeUninit::<bcm::bssl_ge_p2>::uninit();
        let mut rcheck = [0u8; 32];
        unsafe {
            bcm::bssl_x25519_ge_scalarmult(ha_p2.as_mut_ptr(), h.as_ptr(), &raw const a_p3);
            bcm::bssl_x25519_ge_tobytes(ha_bytes.as_mut_ptr(), ha_p2.as_ptr());
            if bcm::bssl_x25519_ge_frombytes_vartime(ha_p3.as_mut_ptr(), ha_bytes.as_ptr()) != 1 {
                return Ok(false);
            }
            bcm::bssl_x25519_ge_p3_to_cached(ha_cached.as_mut_ptr(), ha_p3.as_ptr());
            bcm::bssl_x25519_ge_scalarmult_base(sb_p3.as_mut_ptr(), sig_s.as_ptr());
            bcm::bssl_x25519_ge_sub(r_p1p1.as_mut_ptr(), sb_p3.as_ptr(), ha_cached.as_ptr());
            bcm::bssl_x25519_ge_p1p1_to_p2(r_p2.as_mut_ptr(), r_p1p1.as_ptr());
            bcm::bssl_x25519_ge_tobytes(rcheck.as_mut_ptr(), r_p2.as_ptr());
        }
        Ok(BoringSsl::ct_eq(&rcheck, sig_r))
    }
}

impl AsymmetricKey<32, 32> for BoringSslEd25519 {
    type Public = BoringSslEd25519PublicKey;
    type Private = BoringSslEd25519PrivateKey;

    #[inline(never)]
    fn load_public(_: (), point: &[u8; 32]) -> Result<Option<Self::Public>, CryptoError> {
        let mut a = MaybeUninit::<bcm::bssl_ge_p3>::uninit();
        let ok = unsafe { bcm::bssl_x25519_ge_frombytes_vartime(a.as_mut_ptr(), point.as_ptr()) };
        if ok != 1 {
            return Ok(None);
        }
        let a = unsafe { a.assume_init() };
        let a_p2 = bcm::bssl_ge_p2 {
            X: a.X,
            Y: a.Y,
            Z: a.Z,
        };
        let mut canon = [0u8; 32];
        unsafe {
            bcm::bssl_x25519_ge_tobytes(canon.as_mut_ptr(), &raw const a_p2);
        }
        if !BoringSsl::ct_eq(&canon, point) {
            return Ok(None);
        }
        Ok(Some(BoringSslEd25519PublicKey { point: *point }))
    }

    fn store_public(public: &Self::Public, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        *out = public.point;
        Ok(())
    }

    #[inline(never)]
    fn load_private(
        public: Self::Public,
        secret: &[u8; 32],
    ) -> Result<Option<Self::Private>, CryptoError> {
        let Some(private) = Self::from_secret(secret)? else {
            return Ok(None);
        };
        // The secret seed must derive `public`.
        if !BoringSsl::ct_eq(&private.public.point, &public.point) {
            return Ok(None);
        }
        Ok(Some(private))
    }

    #[inline(never)]
    fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret)?;
        let res = Self::from_secret(&secret)?.ok_or(CryptoError::Internal);
        unsafe {
            bssl_sys::OPENSSL_cleanse(secret.as_mut_ptr().cast(), secret.len());
        }
        res
    }

    fn as_public(private: &Self::Private) -> &Self::Public {
        &private.public
    }

    fn store_private(private: &Self::Private, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(&private.keypair[..32]);
        Ok(())
    }
}

impl EdwardsCurve<32> for BoringSslEd25519 {
    #[inline(never)]
    fn sign_message(
        private: &Self::Private,
        msg: &[&[u8]],
        out_r: &mut [u8; 32],
        out_s: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let mut sig = [0u8; 64];
        match msg {
            [] => {
                let ok = unsafe {
                    bssl_sys::ED25519_sign(
                        sig.as_mut_ptr(),
                        ptr::null(),
                        0,
                        private.keypair.as_ptr(),
                    )
                };
                if ok != 1 {
                    return Err(CryptoError::Internal);
                }
            }
            [single] => {
                let ptr = if single.is_empty() {
                    ptr::null()
                } else {
                    single.as_ptr()
                };
                let ok = unsafe {
                    bssl_sys::ED25519_sign(
                        sig.as_mut_ptr(),
                        ptr,
                        single.len(),
                        private.keypair.as_ptr(),
                    )
                };
                if ok != 1 {
                    return Err(CryptoError::Internal);
                }
            }
            slices => {
                let total_len: usize = slices.iter().map(|s| s.len()).sum();
                if total_len <= STACK_MSG_BUF_LEN {
                    let mut buf = [0u8; STACK_MSG_BUF_LEN];
                    let mut pos = 0;
                    for s in slices {
                        buf[pos..pos + s.len()].copy_from_slice(s);
                        pos += s.len();
                    }
                    let ok = unsafe {
                        bssl_sys::ED25519_sign(
                            sig.as_mut_ptr(),
                            buf.as_ptr(),
                            total_len,
                            private.keypair.as_ptr(),
                        )
                    };
                    if ok != 1 {
                        return Err(CryptoError::Internal);
                    }
                } else {
                    return Self::sign_streaming(private, slices, out_r, out_s);
                }
            }
        }
        out_r.copy_from_slice(&sig[..32]);
        out_s.copy_from_slice(&sig[32..]);
        Ok(())
    }

    #[inline(never)]
    fn verify_message(
        public: &Self::Public,
        msg: &[&[u8]],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(sig_r);
        sig[32..].copy_from_slice(sig_s);
        match msg {
            [] => {
                let ok = unsafe {
                    bssl_sys::ED25519_verify(ptr::null(), 0, sig.as_ptr(), public.point.as_ptr())
                };
                Ok(ok == 1)
            }
            [single] => {
                let ptr = if single.is_empty() {
                    ptr::null()
                } else {
                    single.as_ptr()
                };
                let ok = unsafe {
                    bssl_sys::ED25519_verify(ptr, single.len(), sig.as_ptr(), public.point.as_ptr())
                };
                Ok(ok == 1)
            }
            slices => {
                let total_len: usize = slices.iter().map(|s| s.len()).sum();
                if total_len <= STACK_MSG_BUF_LEN {
                    let mut buf = [0u8; STACK_MSG_BUF_LEN];
                    let mut pos = 0;
                    for s in slices {
                        buf[pos..pos + s.len()].copy_from_slice(s);
                        pos += s.len();
                    }
                    let ok = unsafe {
                        bssl_sys::ED25519_verify(
                            buf.as_ptr(),
                            total_len,
                            sig.as_ptr(),
                            public.point.as_ptr(),
                        )
                    };
                    Ok(ok == 1)
                } else {
                    Self::verify_streaming(public, slices, sig_r, sig_s)
                }
            }
        }
    }

    #[inline(never)]
    fn sign_prehash(
        private: &Self::Private,
        prehash: &[u8; 64],
        out_r: &mut [u8; 32],
        out_s: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let mut sig = [0u8; 64];
        let ok = unsafe {
            bssl_sys::ED25519_sign_prehashed(
                sig.as_mut_ptr(),
                ptr::null(),
                0,
                prehash.as_ptr(),
                private.keypair.as_ptr(),
            )
        };
        if ok != 1 {
            return Err(CryptoError::Internal);
        }
        out_r.copy_from_slice(&sig[..32]);
        out_s.copy_from_slice(&sig[32..]);
        Ok(())
    }

    #[inline(never)]
    fn verify_prehash(
        public: &Self::Public,
        prehash: &[u8; 64],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(sig_r);
        sig[32..].copy_from_slice(sig_s);
        let ok = unsafe {
            bssl_sys::ED25519_verify_prehashed(
                ptr::null(),
                0,
                prehash.as_ptr(),
                sig.as_ptr(),
                public.point.as_ptr(),
            )
        };
        Ok(ok == 1)
    }
}

/// Validated X25519 public key (RFC 7748 32-byte little-endian `u`-coordinate).
#[derive(Clone)]
pub struct BoringSslX25519PublicKey {
    u: [u8; 32],
}

/// Validated X25519 private key (RFC 7748 32-byte scalar and public `u`-coordinate).
#[derive(Clone)]
pub struct BoringSslX25519PrivateKey {
    scalar: [u8; 32],
    public: BoringSslX25519PublicKey,
}

impl Drop for BoringSslX25519PrivateKey {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::OPENSSL_cleanse(self.scalar.as_mut_ptr().cast(), self.scalar.len());
        }
    }
}

/// Marker type implementing [`MontgomeryCurve<32>`] for X25519.
pub struct BoringSslX25519;

impl BoringSslX25519 {
    /// Derives a private key (and its public key) from the RFC 7748 scalar
    /// `scalar`.
    #[inline(never)]
    fn from_scalar(scalar: &[u8; 32]) -> Result<Option<BoringSslX25519PrivateKey>, CryptoError> {
        let mut u = [0u8; 32];
        unsafe {
            bssl_sys::X25519_public_from_private(u.as_mut_ptr(), scalar.as_ptr());
        }
        Ok(Some(BoringSslX25519PrivateKey {
            scalar: *scalar,
            public: BoringSslX25519PublicKey { u },
        }))
    }
}

impl AsymmetricKey<32, 32> for BoringSslX25519 {
    type Public = BoringSslX25519PublicKey;
    type Private = BoringSslX25519PrivateKey;

    fn load_public(_: (), u: &[u8; 32]) -> Result<Option<Self::Public>, CryptoError> {
        Ok(Some(BoringSslX25519PublicKey { u: *u }))
    }

    fn store_public(public: &Self::Public, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        *out = public.u;
        Ok(())
    }

    #[inline(never)]
    fn load_private(
        public: Self::Public,
        scalar: &[u8; 32],
    ) -> Result<Option<Self::Private>, CryptoError> {
        let Some(private) = Self::from_scalar(scalar)? else {
            return Ok(None);
        };
        // The scalar must derive `public`.
        if !BoringSsl::ct_eq(&private.public.u, &public.u) {
            return Ok(None);
        }
        Ok(Some(private))
    }

    #[inline(never)]
    fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
        let mut scalar = [0u8; 32];
        rng.fill_bytes(&mut scalar)?;
        let res = Self::from_scalar(&scalar)?.ok_or(CryptoError::Internal);
        unsafe {
            bssl_sys::OPENSSL_cleanse(scalar.as_mut_ptr().cast(), scalar.len());
        }
        res
    }

    fn as_public(private: &Self::Private) -> &Self::Public {
        &private.public
    }

    fn store_private(private: &Self::Private, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        *out = private.scalar;
        Ok(())
    }
}

impl MontgomeryCurve<32> for BoringSslX25519 {
    #[inline(never)]
    fn ecdh(
        private: &Self::Private,
        peer_public: &Self::Public,
        out_u: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        let ok = unsafe {
            bssl_sys::X25519(
                out_u.as_mut_ptr(),
                private.scalar.as_ptr(),
                peer_public.u.as_ptr(),
            )
        };
        if ok != 1 {
            return Ok(None);
        }
        Ok(Some(()))
    }
}
