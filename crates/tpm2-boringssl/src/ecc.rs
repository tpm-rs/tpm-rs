//! Weierstrass ECC (`NIST P-224`, `NIST P-256`, `NIST P-384`, `NIST P-521`)
//! implementations backed by BoringSSL's FIPS-module `EC_*`, `ECDSA_*`, and
//! `BN_*` APIs.
//!
//! Supports key validation, scalar derivation, deterministic RNG keypair
//! generation, ECDH (`Z = [d] * Q`), and `ECDSA` signatures.

use core::ptr::{self, NonNull};

use tpm2::crypto::{
    CryptoError, Rng,
    backend::{Ecc, EccCurve, PrivateKey},
};

use crate::bssl_sys;
use crate::{
    BoringSsl, BoringSslRng,
    rsa::{BnCtxPtr, BnPtr},
};

struct EcPointPtr(NonNull<bssl_sys::EC_POINT>);

impl EcPointPtr {
    fn new(group: *const bssl_sys::EC_GROUP) -> Result<Self, CryptoError> {
        NonNull::new(unsafe { bssl_sys::EC_POINT_new(group) })
            .map(Self)
            .ok_or(CryptoError::Internal)
    }

    #[inline]
    const fn as_ptr(&self) -> *mut bssl_sys::EC_POINT {
        self.0.as_ptr()
    }
}

impl Drop for EcPointPtr {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::EC_POINT_free(self.0.as_ptr());
        }
    }
}

fn curve_group<const COORD_SIZE: usize>() -> Result<*const bssl_sys::EC_GROUP, CryptoError> {
    let group = unsafe {
        match COORD_SIZE {
            28 => bssl_sys::EC_group_p224(),
            32 => bssl_sys::EC_group_p256(),
            48 => bssl_sys::EC_group_p384(),
            66 => bssl_sys::EC_group_p521(),
            _ => return Err(CryptoError::Unsupported),
        }
    };
    if group.is_null() {
        Err(CryptoError::Internal)
    } else {
        Ok(group)
    }
}

fn new_ec_key_for_group(
    group: *const bssl_sys::EC_GROUP,
) -> Result<NonNull<bssl_sys::EC_KEY>, CryptoError> {
    let key = NonNull::new(unsafe { bssl_sys::EC_KEY_new() }).ok_or(CryptoError::Internal)?;
    let ok = unsafe { bssl_sys::EC_KEY_set_group(key.as_ptr(), group) };
    if ok != 1 {
        unsafe {
            bssl_sys::EC_KEY_free(key.as_ptr());
            bssl_sys::ERR_clear_error();
        }
        return Err(CryptoError::Internal);
    }
    Ok(key)
}

/// Validated Weierstrass ECC public key backed by BoringSSL `EC_KEY`.
pub struct BoringSslEccPublicKey<const COORD_SIZE: usize> {
    ec_key: NonNull<bssl_sys::EC_KEY>,
}

// SAFETY: `bssl_sys::EC_KEY` is reference-counted and immutable after construction here.
unsafe impl<const COORD_SIZE: usize> Send for BoringSslEccPublicKey<COORD_SIZE> {}
unsafe impl<const COORD_SIZE: usize> Sync for BoringSslEccPublicKey<COORD_SIZE> {}

impl<const COORD_SIZE: usize> Clone for BoringSslEccPublicKey<COORD_SIZE> {
    fn clone(&self) -> Self {
        unsafe {
            bssl_sys::EC_KEY_up_ref(self.ec_key.as_ptr());
        }
        Self {
            ec_key: self.ec_key,
        }
    }
}

impl<const COORD_SIZE: usize> Drop for BoringSslEccPublicKey<COORD_SIZE> {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::EC_KEY_free(self.ec_key.as_ptr());
        }
    }
}

/// Validated Weierstrass ECC private key backed by BoringSSL `EC_KEY`.
pub struct BoringSslEccPrivateKey<const COORD_SIZE: usize> {
    ec_key: NonNull<bssl_sys::EC_KEY>,
    public: BoringSslEccPublicKey<COORD_SIZE>,
}

// SAFETY: `bssl_sys::EC_KEY` is reference-counted and immutable after construction here.
unsafe impl<const COORD_SIZE: usize> Send for BoringSslEccPrivateKey<COORD_SIZE> {}
unsafe impl<const COORD_SIZE: usize> Sync for BoringSslEccPrivateKey<COORD_SIZE> {}

impl<const COORD_SIZE: usize> Clone for BoringSslEccPrivateKey<COORD_SIZE> {
    fn clone(&self) -> Self {
        unsafe {
            bssl_sys::EC_KEY_up_ref(self.ec_key.as_ptr());
        }
        Self {
            ec_key: self.ec_key,
            public: self.public.clone(),
        }
    }
}

impl<const COORD_SIZE: usize> Drop for BoringSslEccPrivateKey<COORD_SIZE> {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::EC_KEY_free(self.ec_key.as_ptr());
        }
    }
}

macro_rules! impl_ecc_curve {
    ($coord_size:literal, $point_size:literal) => {
        impl BoringSslEccPrivateKey<$coord_size> {
            /// Derives a private key (and its public key) from `scalar`,
            /// returning `Ok(None)` if `scalar` is not in `[1, n - 1]`.
            #[inline(never)]
            fn from_scalar(scalar: &[u8; $coord_size]) -> Result<Option<Self>, CryptoError> {
                let group = curve_group::<$coord_size>()?;
                let ec_key = new_ec_key_for_group(group)?;
                let ok = unsafe {
                    bssl_sys::EC_KEY_oct2priv(ec_key.as_ptr(), scalar.as_ptr(), $coord_size)
                };
                if ok != 1 {
                    unsafe {
                        bssl_sys::EC_KEY_free(ec_key.as_ptr());
                        bssl_sys::ERR_clear_error();
                    }
                    return Ok(None);
                }

                let priv_bn = unsafe { bssl_sys::EC_KEY_get0_private_key(ec_key.as_ptr()) };
                let ctx = BnCtxPtr::new()?;
                let pub_pt = EcPointPtr::new(group)?;
                let mul_ok = unsafe {
                    bssl_sys::EC_POINT_mul(
                        group,
                        pub_pt.as_ptr(),
                        priv_bn,
                        ptr::null(),
                        ptr::null(),
                        ctx.as_ptr(),
                    ) == 1
                        && bssl_sys::EC_KEY_set_public_key(ec_key.as_ptr(), pub_pt.as_ptr()) == 1
                };
                if !mul_ok {
                    unsafe {
                        bssl_sys::EC_KEY_free(ec_key.as_ptr());
                        bssl_sys::ERR_clear_error();
                    }
                    return Err(CryptoError::Internal);
                }

                unsafe {
                    bssl_sys::EC_KEY_up_ref(ec_key.as_ptr());
                }
                let public = BoringSslEccPublicKey { ec_key };
                Ok(Some(Self { ec_key, public }))
            }
        }

        impl PrivateKey<$point_size, $coord_size, BoringSslRng>
            for BoringSslEccPrivateKey<$coord_size>
        {
            type PublicKey = BoringSslEccPublicKey<$coord_size>;

            #[inline(never)]
            fn generate(rng: &mut BoringSslRng, _: ()) -> Result<Self, CryptoError> {
                let mut buf = [0u8; $coord_size];
                for _ in 0..256 {
                    rng.fill_bytes(&mut buf)?;
                    if $coord_size == 66 {
                        // P-521 order is 521 bits; mask top 7 bits so rejection sampling succeeds.
                        buf[0] &= 0x01;
                    }
                    if let Some(priv_key) = Self::from_scalar(&buf)? {
                        unsafe {
                            bssl_sys::OPENSSL_cleanse(buf.as_mut_ptr().cast(), $coord_size);
                        }
                        return Ok(priv_key);
                    }
                }
                unsafe {
                    bssl_sys::OPENSSL_cleanse(buf.as_mut_ptr().cast(), $coord_size);
                }
                Err(CryptoError::Internal)
            }

            #[inline(never)]
            fn load(
                public: Self::PublicKey,
                scalar: &[u8; $coord_size],
            ) -> Result<Option<Self>, CryptoError> {
                let Some(private) = Self::from_scalar(scalar)? else {
                    return Ok(None);
                };
                // The private key must match `public` (`[d]G == Q`).
                let group = unsafe { bssl_sys::EC_KEY_get0_group(private.ec_key.as_ptr()) };
                let derived_pt =
                    unsafe { bssl_sys::EC_KEY_get0_public_key(private.ec_key.as_ptr()) };
                let pub_pt = unsafe { bssl_sys::EC_KEY_get0_public_key(public.ec_key.as_ptr()) };
                if group.is_null() || derived_pt.is_null() || pub_pt.is_null() {
                    return Err(CryptoError::Internal);
                }
                let ctx = BnCtxPtr::new()?;
                match unsafe { bssl_sys::EC_POINT_cmp(group, derived_pt, pub_pt, ctx.as_ptr()) } {
                    0 => Ok(Some(private)),
                    1 => Ok(None),
                    _ => {
                        unsafe {
                            bssl_sys::ERR_clear_error();
                        }
                        Err(CryptoError::Internal)
                    }
                }
            }

            fn store(&self, out: &mut [u8; $coord_size]) -> Result<(), CryptoError> {
                let written = unsafe {
                    bssl_sys::EC_KEY_priv2oct(self.ec_key.as_ptr(), out.as_mut_ptr(), $coord_size)
                };
                if written != $coord_size {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    return Err(CryptoError::Internal);
                }
                Ok(())
            }

            fn as_public(&self) -> &Self::PublicKey {
                &self.public
            }

            #[inline(never)]
            fn load_public(
                _: (),
                point: &[u8; $point_size],
            ) -> Result<Option<Self::PublicKey>, CryptoError> {
                let (x, y) = point.split_at($coord_size);
                let group = curve_group::<$coord_size>()?;
                let ec_key = new_ec_key_for_group(group)?;
                let bn_x = BnPtr::from_be(x)?;
                let bn_y = BnPtr::from_be(y)?;
                let ok = unsafe {
                    bssl_sys::EC_KEY_set_public_key_affine_coordinates(
                        ec_key.as_ptr(),
                        bn_x.as_ptr(),
                        bn_y.as_ptr(),
                    )
                };
                if ok != 1 {
                    unsafe {
                        bssl_sys::EC_KEY_free(ec_key.as_ptr());
                        bssl_sys::ERR_clear_error();
                    }
                    return Ok(None);
                }
                Ok(Some(BoringSslEccPublicKey { ec_key }))
            }

            fn store_public(
                public: &Self::PublicKey,
                out: &mut [u8; $point_size],
            ) -> Result<(), CryptoError> {
                let group = unsafe { bssl_sys::EC_KEY_get0_group(public.ec_key.as_ptr()) };
                let pub_pt = unsafe { bssl_sys::EC_KEY_get0_public_key(public.ec_key.as_ptr()) };
                if group.is_null() || pub_pt.is_null() {
                    return Err(CryptoError::Internal);
                }
                let ctx = BnCtxPtr::new()?;
                let bn_x = BnPtr::new()?;
                let bn_y = BnPtr::new()?;
                let ok = unsafe {
                    bssl_sys::EC_POINT_get_affine_coordinates_GFp(
                        group,
                        pub_pt,
                        bn_x.as_ptr(),
                        bn_y.as_ptr(),
                        ctx.as_ptr(),
                    )
                };
                if ok != 1 {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    return Err(CryptoError::Internal);
                }
                let (out_x, out_y) = out.split_at_mut($coord_size);
                bn_x.to_be_padded(out_x)?;
                bn_y.to_be_padded(out_y)?;
                Ok(())
            }
        }

        impl EccCurve<$coord_size, $point_size, BoringSslRng>
            for BoringSslEccPrivateKey<$coord_size>
        {
            #[inline(never)]
            fn ecdh(
                &self,
                peer_public: &Self::PublicKey,
                out_x: &mut [u8; $coord_size],
                out_y: &mut [u8; $coord_size],
            ) -> Result<Option<()>, CryptoError> {
                let group = unsafe { bssl_sys::EC_KEY_get0_group(self.ec_key.as_ptr()) };
                let priv_bn = unsafe { bssl_sys::EC_KEY_get0_private_key(self.ec_key.as_ptr()) };
                let peer_pt =
                    unsafe { bssl_sys::EC_KEY_get0_public_key(peer_public.ec_key.as_ptr()) };
                if group.is_null() || priv_bn.is_null() || peer_pt.is_null() {
                    return Err(CryptoError::Internal);
                }

                let ctx = BnCtxPtr::new()?;
                let shared_pt = EcPointPtr::new(group)?;
                let mul_ok = unsafe {
                    bssl_sys::EC_POINT_mul(
                        group,
                        shared_pt.as_ptr(),
                        ptr::null(),
                        peer_pt,
                        priv_bn,
                        ctx.as_ptr(),
                    )
                };
                if mul_ok != 1 {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    return Ok(None);
                }
                if unsafe { bssl_sys::EC_POINT_is_at_infinity(group, shared_pt.as_ptr()) } != 0 {
                    return Ok(None);
                }

                let bn_x = BnPtr::new()?;
                let bn_y = BnPtr::new()?;
                let ok = unsafe {
                    bssl_sys::EC_POINT_get_affine_coordinates_GFp(
                        group,
                        shared_pt.as_ptr(),
                        bn_x.as_ptr(),
                        bn_y.as_ptr(),
                        ctx.as_ptr(),
                    )
                };
                if ok != 1 {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    return Err(CryptoError::Internal);
                }
                bn_x.to_be_padded(out_x)?;
                bn_y.to_be_padded(out_y)?;
                Ok(Some(()))
            }

            #[inline(never)]
            fn sign(
                &self,
                rng: &mut BoringSslRng,
                digest: &[u8],
                out_r: &mut [u8; $coord_size],
                out_s: &mut [u8; $coord_size],
            ) -> Result<(), CryptoError> {
                // `ECDSA_sign_p1363` uses BoringSSL's system RNG.
                rng.check_system()?;
                let mut sig = [0u8; 2 * $coord_size];
                let mut sig_len: usize = 0;
                let ok = unsafe {
                    bssl_sys::ECDSA_sign_p1363(
                        digest.as_ptr(),
                        digest.len(),
                        sig.as_mut_ptr(),
                        &raw mut sig_len,
                        sig.len(),
                        self.ec_key.as_ptr(),
                    )
                };
                if ok != 1 || sig_len != 2 * $coord_size {
                    unsafe {
                        bssl_sys::ERR_clear_error();
                    }
                    return Err(CryptoError::Internal);
                }
                out_r.copy_from_slice(&sig[..$coord_size]);
                out_s.copy_from_slice(&sig[$coord_size..]);
                Ok(())
            }

            #[inline(never)]
            fn verify(
                public: &Self::PublicKey,
                digest: &[u8],
                sig_r: &[u8; $coord_size],
                sig_s: &[u8; $coord_size],
            ) -> Result<bool, CryptoError> {
                let mut sig = [0u8; 2 * $coord_size];
                sig[..$coord_size].copy_from_slice(sig_r);
                sig[$coord_size..].copy_from_slice(sig_s);
                let ok = unsafe {
                    bssl_sys::ECDSA_verify_p1363(
                        digest.as_ptr(),
                        digest.len(),
                        sig.as_ptr(),
                        sig.len(),
                        public.ec_key.as_ptr(),
                    )
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

impl_ecc_curve!(28, 56);
impl_ecc_curve!(32, 64);
impl_ecc_curve!(48, 96);
impl_ecc_curve!(66, 132);

impl Ecc for BoringSsl {
    type NistP192 = !;
    type NistP224 = BoringSslEccPrivateKey<28>;
    type NistP256 = BoringSslEccPrivateKey<32>;
    type NistP384 = BoringSslEccPrivateKey<48>;
    type NistP521 = BoringSslEccPrivateKey<66>;
    type BNP256 = !;
    type BNP638 = !;
    type SM2P256 = !;
    type BpP256R1 = !;
    type BpP384R1 = !;
    type BpP512R1 = !;
    type Ed25519 = crate::curve25519::BoringSslEd25519PrivateKey;
    type Ed448 = !;
    type X25519 = crate::curve25519::BoringSslX25519PrivateKey;
    type X448 = !;
}
