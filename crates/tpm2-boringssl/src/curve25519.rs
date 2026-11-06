//! Curve25519 (`Ed25519` and `X25519`) implementations via BoringSSL's
//! `ED25519_*` and `X25519*` functions.

use tpm2::crypto::{
    Crypto, CryptoError, Rng,
    backend::{EdwardsCurve, MontgomeryCurve, PrivateKey},
};

use crate::{
    BoringSsl, BoringSslRng,
    rsa::{BnCtxPtr, BnPtr},
};

/// Maximum total length of a multi-slice `EdDSA` message, which BoringSSL needs
/// contiguous (copied into a stack buffer of this size).
const MAX_MSG_LEN: usize = 4096;

/// The field prime `p = 2^255 - 19`, big-endian.
const P: [u8; 32] = {
    let mut p = [0xff; 32];
    (p[0], p[31]) = (0x7f, 0xed);
    p
};
/// `(p - 1) / 2 = 2^254 - 10`, big-endian.
const P_MINUS_1_OVER_2: [u8; 32] = {
    let mut e = [0xff; 32];
    (e[0], e[31]) = (0x3f, 0xf6);
    e
};
/// The curve constant `d = -121665 / 121666 mod p`, big-endian.
const D: [u8; 32] = [
    0x52, 0x03, 0x6c, 0xee, 0x2b, 0x6f, 0xfe, 0x73, 0x8c, 0xc7, 0x40, 0x79, 0x77, 0x79, 0xe8, 0x98,
    0x00, 0x70, 0x0a, 0x4d, 0x41, 0x41, 0xd8, 0xab, 0x75, 0xeb, 0x4d, 0xca, 0x13, 0x59, 0x78, 0xa3,
];

/// Returns whether `point` is a valid RFC 8032 Ed25519 point encoding
/// (Section 5.1.3), which BoringSSL has no public function to check.
///
/// Decoding computes `x^2 = u / v` with `u = y^2 - 1` and `v = d y^2 + 1`
/// (never 0, as `-1/d` isn't a square). `u / v` is a square exactly when
/// `u v` is, so this checks `y < p` and that `t = u v` is 0 (then `x = 0`,
/// whose sign bit must be clear) or a square (Euler's criterion). The point is
/// public, so this doesn't need to be constant time.
fn is_valid_point(point: &[u8; 32]) -> Result<bool, CryptoError> {
    let sign = point[31] >> 7;
    let mut y_le = *point;
    y_le[31] &= 0x7f;
    let ctx = BnCtxPtr::new()?;
    let (p, d, e) = (
        BnPtr::from_be(&P)?,
        BnPtr::from_be(&D)?,
        BnPtr::from_be(&P_MINUS_1_OVER_2)?,
    );
    let (y, t, u) = (BnPtr::new()?, BnPtr::new()?, BnPtr::new()?);
    let (ctx, p, y, t, u) = (ctx.as_ptr(), p.as_ptr(), y.as_ptr(), t.as_ptr(), u.as_ptr());
    unsafe {
        let one = bssl_sys::BN_value_one();
        let ok = !bssl_sys::BN_le2bn(y_le.as_ptr(), y_le.len(), y).is_null()
            && bssl_sys::BN_mod_sqr(t, y, p, ctx) == 1 // t = y^2
            && bssl_sys::BN_mod_mul(u, d.as_ptr(), t, p, ctx) == 1 // u = d y^2
            && bssl_sys::BN_mod_add(u, u, one, p, ctx) == 1 // u = d y^2 + 1
            && bssl_sys::BN_mod_sub(t, t, one, p, ctx) == 1 // t = y^2 - 1
            && bssl_sys::BN_mod_mul(t, t, u, p, ctx) == 1 // t = (y^2 - 1)(d y^2 + 1)
            && bssl_sys::BN_mod_exp(u, t, e.as_ptr(), p, ctx) == 1; // u = t^((p - 1) / 2)
        if !ok {
            return Err(CryptoError::Internal);
        }
        Ok(if bssl_sys::BN_cmp(y, p) >= 0 {
            false
        } else if bssl_sys::BN_is_zero(t) == 1 {
            sign == 0
        } else {
            bssl_sys::BN_is_one(u) == 1
        })
    }
}

/// Calls `f` on the concatenation of `msg`, copying it into a stack buffer if
/// it has more than one slice.
///
/// Returns `Err(CryptoError::Unsupported)` if a multi-slice `msg` is longer
/// than [`MAX_MSG_LEN`].
fn with_contiguous<T>(msg: &[&[u8]], f: impl FnOnce(&[u8]) -> T) -> Result<T, CryptoError> {
    match msg {
        [] => Ok(f(&[])),
        [single] => Ok(f(single)),
        slices => {
            let mut buf = [0u8; MAX_MSG_LEN];
            let mut len = 0;
            for s in slices {
                let dst = buf.get_mut(len..len + s.len());
                dst.ok_or(CryptoError::Unsupported)?.copy_from_slice(s);
                len += s.len();
            }
            Ok(f(&buf[..len]))
        }
    }
}

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

impl BoringSslEd25519PrivateKey {
    /// Derives a private key (and its public key) from the RFC 8032 secret
    /// seed `secret`.
    fn from_secret(secret: &[u8; 32]) -> Self {
        let mut point = [0u8; 32];
        let mut keypair = [0u8; 64];
        unsafe {
            bssl_sys::ED25519_keypair_from_seed(
                point.as_mut_ptr(),
                keypair.as_mut_ptr(),
                secret.as_ptr(),
            );
        }
        Self {
            keypair,
            public: BoringSslEd25519PublicKey { point },
        }
    }
}

/// Splits a 64-byte RFC 8032 signature into `(R, S)`.
fn split_sig(sig: &[u8; 64], out_r: &mut [u8; 32], out_s: &mut [u8; 32]) {
    out_r.copy_from_slice(&sig[..32]);
    out_s.copy_from_slice(&sig[32..]);
}

/// Joins `(R, S)` into a 64-byte RFC 8032 signature.
fn join_sig(sig_r: &[u8; 32], sig_s: &[u8; 32]) -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(sig_r);
    sig[32..].copy_from_slice(sig_s);
    sig
}

impl PrivateKey<32, 32, BoringSslRng> for BoringSslEd25519PrivateKey {
    type PublicKey = BoringSslEd25519PublicKey;

    #[inline(never)]
    fn generate(rng: &mut BoringSslRng, _: ()) -> Result<Self, CryptoError> {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret)?;
        let private = Self::from_secret(&secret);
        unsafe {
            bssl_sys::OPENSSL_cleanse(secret.as_mut_ptr().cast(), secret.len());
        }
        Ok(private)
    }

    #[inline(never)]
    fn load(public: Self::PublicKey, secret: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
        let private = Self::from_secret(secret);
        // The secret seed must derive `public`.
        Ok(BoringSsl::ct_eq(&private.public.point, &public.point).then_some(private))
    }

    fn store(&self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(&self.keypair[..32]);
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }

    #[inline(never)]
    fn load_public(_: (), point: &[u8; 32]) -> Result<Option<Self::PublicKey>, CryptoError> {
        Ok(is_valid_point(point)?.then_some(BoringSslEd25519PublicKey { point: *point }))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        *out = public.point;
        Ok(())
    }
}

impl EdwardsCurve<32, BoringSslRng> for BoringSslEd25519PrivateKey {
    #[inline(never)]
    fn sign_message(
        &self,
        msg: &[&[u8]],
        out_r: &mut [u8; 32],
        out_s: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let mut sig = [0u8; 64];
        let ok = with_contiguous(msg, |m| unsafe {
            bssl_sys::ED25519_sign(sig.as_mut_ptr(), m.as_ptr(), m.len(), self.keypair.as_ptr())
        })?;
        if ok != 1 {
            return Err(CryptoError::Internal);
        }
        split_sig(&sig, out_r, out_s);
        Ok(())
    }

    #[inline(never)]
    fn verify_message(
        public: &Self::PublicKey,
        msg: &[&[u8]],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        let sig = join_sig(sig_r, sig_s);
        let ok = with_contiguous(msg, |m| unsafe {
            bssl_sys::ED25519_verify(m.as_ptr(), m.len(), sig.as_ptr(), public.point.as_ptr())
        })?;
        Ok(ok == 1)
    }

    #[inline(never)]
    fn sign_prehash(
        &self,
        prehash: &[u8; 64],
        out_r: &mut [u8; 32],
        out_s: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let mut sig = [0u8; 64];
        let ok = unsafe {
            bssl_sys::ED25519_sign_prehashed(
                sig.as_mut_ptr(),
                core::ptr::null(),
                0,
                prehash.as_ptr(),
                self.keypair.as_ptr(),
            )
        };
        if ok != 1 {
            return Err(CryptoError::Internal);
        }
        split_sig(&sig, out_r, out_s);
        Ok(())
    }

    #[inline(never)]
    fn verify_prehash(
        public: &Self::PublicKey,
        prehash: &[u8; 64],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        let sig = join_sig(sig_r, sig_s);
        let ok = unsafe {
            bssl_sys::ED25519_verify_prehashed(
                core::ptr::null(),
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

impl BoringSslX25519PrivateKey {
    /// Derives a private key (and its public key) from the RFC 7748 scalar
    /// `scalar`.
    #[inline(never)]
    fn from_scalar(scalar: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
        let mut u = [0u8; 32];
        unsafe {
            bssl_sys::X25519_public_from_private(u.as_mut_ptr(), scalar.as_ptr());
        }
        Ok(Some(Self {
            scalar: *scalar,
            public: BoringSslX25519PublicKey { u },
        }))
    }
}

impl PrivateKey<32, 32, BoringSslRng> for BoringSslX25519PrivateKey {
    type PublicKey = BoringSslX25519PublicKey;

    #[inline(never)]
    fn generate(rng: &mut BoringSslRng, _: ()) -> Result<Self, CryptoError> {
        let mut scalar = [0u8; 32];
        rng.fill_bytes(&mut scalar)?;
        let res = Self::from_scalar(&scalar)?.ok_or(CryptoError::Internal);
        unsafe {
            bssl_sys::OPENSSL_cleanse(scalar.as_mut_ptr().cast(), scalar.len());
        }
        res
    }

    #[inline(never)]
    fn load(public: Self::PublicKey, scalar: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
        let Some(private) = Self::from_scalar(scalar)? else {
            return Ok(None);
        };
        // The scalar must derive `public`.
        if !BoringSsl::ct_eq(&private.public.u, &public.u) {
            return Ok(None);
        }
        Ok(Some(private))
    }

    fn store(&self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        *out = self.scalar;
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }

    fn load_public(_: (), u: &[u8; 32]) -> Result<Option<Self::PublicKey>, CryptoError> {
        Ok(Some(BoringSslX25519PublicKey { u: *u }))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        *out = public.u;
        Ok(())
    }
}

impl MontgomeryCurve<32, BoringSslRng> for BoringSslX25519PrivateKey {
    #[inline(never)]
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_u: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        let ok = unsafe {
            bssl_sys::X25519(
                out_u.as_mut_ptr(),
                self.scalar.as_ptr(),
                peer_public.u.as_ptr(),
            )
        };
        if ok != 1 {
            return Ok(None);
        }
        Ok(Some(()))
    }
}
