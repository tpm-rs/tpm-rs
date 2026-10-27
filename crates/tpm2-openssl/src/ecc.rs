use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{PKey, Private, Public},
    pkey_ctx::PkeyCtx,
};
use tpm2::{
    TpmtHa,
    crypto::{
        CryptoError, Rng,
        backend::{AsymmetricKey, Ecc, EccCurve, EccSigScheme, Hash},
    },
};

use foreign_types::ForeignType;
use std::ffi::CString;
use std::ptr;

#[repr(C)]
struct EVP_SIGNATURE {
    _private: [u8; 0],
}
unsafe extern "C" {
    fn EVP_SIGNATURE_fetch(
        ctx: *mut openssl_sys::OSSL_LIB_CTX,
        algorithm: *const libc::c_char,
        properties: *const libc::c_char,
    ) -> *mut EVP_SIGNATURE;
    fn EVP_SIGNATURE_free(signature: *mut EVP_SIGNATURE);
    fn EVP_PKEY_sign_init_ex2(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        signature: *mut EVP_SIGNATURE,
        params: *const openssl_sys::OSSL_PARAM,
    ) -> libc::c_int;
    fn EVP_PKEY_verify_init_ex2(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        signature: *mut EVP_SIGNATURE,
        params: *const openssl_sys::OSSL_PARAM,
    ) -> libc::c_int;
    fn EVP_PKEY_sign(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        sig: *mut libc::c_uchar,
        siglen: *mut libc::size_t,
        tbs: *const libc::c_uchar,
        tbslen: libc::size_t,
    ) -> libc::c_int;
    fn EVP_PKEY_verify(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        sig: *const libc::c_uchar,
        siglen: libc::size_t,
        tbs: *const libc::c_uchar,
        tbslen: libc::size_t,
    ) -> libc::c_int;
}

pub struct EccPriv {
    pub priv_key: EcKey<Private>,
    pub pub_key: EcKey<Public>,
}

macro_rules! impl_ecc {
    ($name:ident, $nid:ident, $coord_size:expr, $point_size:expr) => {
        pub struct $name;

        impl AsymmetricKey<$point_size, $coord_size> for $name {
            type Public = EcKey<Public>;
            type Private = EccPriv;

            fn load_public(
                _: (),
                public: &[u8; $point_size],
            ) -> Result<Option<Self::Public>, CryptoError> {
                let (x, y) = public.split_at($coord_size);
                let group =
                    EcGroup::from_curve_name(Nid::$nid).map_err(|_| CryptoError::Internal)?;
                let mut ctx = BigNumContext::new().map_err(|_| CryptoError::Internal)?;
                let bn_x = BigNum::from_slice(x).map_err(|_| CryptoError::Internal)?;
                let bn_y = BigNum::from_slice(y).map_err(|_| CryptoError::Internal)?;

                let mut point = match EcPoint::new(&group) {
                    Ok(p) => p,
                    Err(_) => return Err(CryptoError::Internal),
                };
                if point
                    .set_affine_coordinates_gfp(&group, &bn_x, &bn_y, &mut ctx)
                    .is_err()
                {
                    return Ok(None);
                }

                if point.is_on_curve(&group, &mut ctx).unwrap_or(false) {
                    let key = EcKey::from_public_key(&group, &point)
                        .map_err(|_| CryptoError::Internal)?;
                    Ok(Some(key))
                } else {
                    Ok(None)
                }
            }

            fn store_public(
                public: &Self::Public,
                out: &mut [u8; $point_size],
            ) -> Result<(), CryptoError> {
                let (out_x, out_y) = out.split_at_mut($coord_size);
                let group = public.group();
                let mut ctx = BigNumContext::new().map_err(|_| CryptoError::Internal)?;
                let mut x = BigNum::new().map_err(|_| CryptoError::Internal)?;
                let mut y = BigNum::new().map_err(|_| CryptoError::Internal)?;
                public
                    .public_key()
                    .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)
                    .map_err(|_| CryptoError::Internal)?;

                let x_bytes = x.to_vec();
                let y_bytes = y.to_vec();
                if x_bytes.len() > $coord_size || y_bytes.len() > $coord_size {
                    return Err(CryptoError::Internal);
                }
                out_x.fill(0);
                out_y.fill(0);
                out_x[$coord_size - x_bytes.len()..].copy_from_slice(&x_bytes);
                out_y[$coord_size - y_bytes.len()..].copy_from_slice(&y_bytes);
                Ok(())
            }

            fn load_private(
                public: Self::Public,
                scalar: &[u8; $coord_size],
            ) -> Result<Option<Self::Private>, CryptoError> {
                let group =
                    EcGroup::from_curve_name(Nid::$nid).map_err(|_| CryptoError::Internal)?;
                let mut ctx = BigNumContext::new().map_err(|_| CryptoError::Internal)?;
                let d = BigNum::from_slice(scalar).map_err(|_| CryptoError::Internal)?;

                let mut order = BigNum::new().map_err(|_| CryptoError::Internal)?;
                group
                    .order(&mut order, &mut ctx)
                    .map_err(|_| CryptoError::Internal)?;

                // Compare manually using ucmp since cmp isn't easily accessible without traits
                if d == BigNum::new().unwrap() {
                    return Ok(None);
                }

                // To check d >= order, we can check order - d. Wait, `d >= order`?
                // Just use d.ucmp(&order).
                // Actually `d.cmp(&order)` might be available. Or `d >= order` can be done by
                // checking `d.checked_sub(&order)`.
                // Better: BigNum implements Ord in rust-openssl!
                if d >= order {
                    return Ok(None);
                }

                // Generate public point
                let mut pub_pt = EcPoint::new(&group).map_err(|_| CryptoError::Internal)?;
                // Wait! To get [d]G, we can use EcPoint::mul with 3 args? No, `EcPoint::mul` is for
                // [m]P.
                // Does EcPoint have `mul_generator`? No.
                // We can just use EcKey::from_private_components which requires the public point,
                // but wait, `EcKey::from_private_components` requires the public point.
                // But `EcKey` doesn't have a way to generate public point from private!
                // Wait, OpenSSL `EC_POINT_mul` with null P multiplies the generator. But
                // rust-openssl doesn't bind that cleanly.
                // Let's just create an EcKey with private only? No, OpenSSL requires public point
                // for EcKey sometimes.
                // Actually, `EcKey::from_private_components` requires the public point.
                // Let's multiply the generator.
                let generator = group.generator_opt().unwrap();
                pub_pt
                    .mul2(&group, generator, &d, &mut ctx)
                    .map_err(|_| CryptoError::Internal)?;

                // The scalar must match `public`.
                if !pub_pt
                    .eq(&group, public.public_key(), &mut ctx)
                    .map_err(|_| CryptoError::Internal)?
                {
                    return Ok(None);
                }

                let priv_key = EcKey::from_private_components(&group, &d, &pub_pt)
                    .map_err(|_| CryptoError::Internal)?;
                let pub_key =
                    EcKey::from_public_key(&group, &pub_pt).map_err(|_| CryptoError::Internal)?;

                Ok(Some(EccPriv { priv_key, pub_key }))
            }

            fn generate(_rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
                let group =
                    EcGroup::from_curve_name(Nid::$nid).map_err(|_| CryptoError::Internal)?;
                let priv_key = EcKey::generate(&group).map_err(|_| CryptoError::Internal)?;
                let pub_key = EcKey::from_public_key(&group, priv_key.public_key())
                    .map_err(|_| CryptoError::Internal)?;
                Ok(EccPriv { priv_key, pub_key })
            }

            fn as_public(private: &Self::Private) -> &Self::Public {
                &private.pub_key
            }

            fn store_private(
                private: &Self::Private,
                out: &mut [u8; $coord_size],
            ) -> Result<(), CryptoError> {
                let d_bytes = private.priv_key.private_key().to_vec();
                if d_bytes.len() > $coord_size {
                    return Err(CryptoError::Internal);
                }
                out.fill(0);
                out[$coord_size - d_bytes.len()..].copy_from_slice(&d_bytes);
                Ok(())
            }
        }

        impl EccCurve<$coord_size, $point_size> for $name {
            fn ecdh(
                private: &Self::Private,
                peer_public: &Self::Public,
                out_x: &mut [u8; $coord_size],
                out_y: &mut [u8; $coord_size],
            ) -> Result<Option<()>, CryptoError> {
                let group = private.priv_key.group();
                let mut ctx = BigNumContext::new().map_err(|_| CryptoError::Internal)?;
                let mut res = EcPoint::new(group).map_err(|_| CryptoError::Internal)?;

                res.mul2(
                    group,
                    peer_public.public_key(),
                    private.priv_key.private_key(),
                    &mut ctx,
                )
                .map_err(|_| CryptoError::Internal)?;

                // If it's infinity, return None
                // OpenSSL doesn't have is_infinity bound, but affine_coordinates fails for
                // infinity!
                let mut x = BigNum::new().map_err(|_| CryptoError::Internal)?;
                let mut y = BigNum::new().map_err(|_| CryptoError::Internal)?;
                if res
                    .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)
                    .is_err()
                {
                    return Ok(None);
                }

                let x_bytes = x.to_vec();
                let y_bytes = y.to_vec();
                if x_bytes.len() > $coord_size || y_bytes.len() > $coord_size {
                    return Err(CryptoError::Internal);
                }
                out_x.fill(0);
                out_y.fill(0);
                out_x[$coord_size - x_bytes.len()..].copy_from_slice(&x_bytes);
                out_y[$coord_size - y_bytes.len()..].copy_from_slice(&y_bytes);

                Ok(Some(()))
            }

            fn sign<H: Hash>(
                _rng: &mut impl Rng,
                private: &Self::Private,
                scheme: EccSigScheme,
                digest: TpmtHa<'_>,
                out_r: &mut [u8; $coord_size],
                out_s: &mut [u8; $coord_size],
            ) -> Result<(), CryptoError> {
                let group = private.priv_key.group();
                let mut ctx = BigNumContext::new().map_err(|_| CryptoError::Internal)?;
                let mut order = BigNum::new().map_err(|_| CryptoError::Internal)?;
                group
                    .order(&mut order, &mut ctx)
                    .map_err(|_| CryptoError::Internal)?;
                let order_bytes = order.num_bytes() as usize;

                match scheme {
                    EccSigScheme::Ecdsa => {
                        let sig = EcdsaSig::sign(digest.digest(), &private.priv_key)
                            .map_err(|_| CryptoError::Internal)?;
                        let r_bytes = sig.r().to_vec();
                        let s_bytes = sig.s().to_vec();
                        if r_bytes.len() > $coord_size || s_bytes.len() > $coord_size {
                            return Err(CryptoError::Internal);
                        }
                        out_r.fill(0);
                        out_s.fill(0);
                        out_r[$coord_size - r_bytes.len()..].copy_from_slice(&r_bytes);
                        out_s[$coord_size - s_bytes.len()..].copy_from_slice(&s_bytes);
                        Ok(())
                    }
                    EccSigScheme::Sm2 => {
                        let pkey = PKey::from_ec_key(private.priv_key.clone())
                            .map_err(|_| CryptoError::Internal)?;
                        let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
                        pctx.sign_init().map_err(|_| CryptoError::Internal)?;
                        let mut sig_out = vec![];
                        pctx.sign_to_vec(digest.digest(), &mut sig_out)
                            .map_err(|_| CryptoError::Internal)?;
                        let sig =
                            EcdsaSig::from_der(&sig_out).map_err(|_| CryptoError::Internal)?;
                        let r_bytes = sig.r().to_vec();
                        let s_bytes = sig.s().to_vec();
                        if r_bytes.len() > $coord_size || s_bytes.len() > $coord_size {
                            return Err(CryptoError::Internal);
                        }
                        out_r.fill(0);
                        out_s.fill(0);
                        out_r[$coord_size - r_bytes.len()..].copy_from_slice(&r_bytes);
                        out_s[$coord_size - s_bytes.len()..].copy_from_slice(&s_bytes);
                        Ok(())
                    }
                    EccSigScheme::Ecschnorr => {
                        let zero = BigNum::new().map_err(|_| CryptoError::Internal)?;
                        let d = private.priv_key.private_key();

                        loop {
                            let mut k_bytes = vec![0u8; $coord_size];
                            let mut k = BigNum::new().map_err(|_| CryptoError::Internal)?;
                            while k <= zero || k >= order {
                                _rng.fill_bytes(&mut k_bytes)
                                    .map_err(|_| CryptoError::Internal)?;
                                k = BigNum::from_slice(&k_bytes)
                                    .map_err(|_| CryptoError::Internal)?;
                            }

                            let (r_out, s_out) = {
                                let mut e1 =
                                    EcPoint::new(group).map_err(|_| CryptoError::Internal)?;
                                e1.mul2(group, group.generator_opt().unwrap(), &k, &mut ctx)
                                    .map_err(|_| CryptoError::Internal)?;

                                let mut x_e = BigNum::new().map_err(|_| CryptoError::Internal)?;
                                let mut y_e = BigNum::new().map_err(|_| CryptoError::Internal)?;
                                if e1
                                    .affine_coordinates_gfp(group, &mut x_e, &mut y_e, &mut ctx)
                                    .is_err()
                                {
                                    continue;
                                }
                                let x_e_bytes = x_e.to_vec();
                                let mut fe2bs_x_e = vec![0u8; order_bytes];
                                if x_e_bytes.len() <= order_bytes {
                                    fe2bs_x_e[order_bytes - x_e_bytes.len()..]
                                        .copy_from_slice(&x_e_bytes);
                                } else {
                                    continue;
                                }
                                let mut hash_input = fe2bs_x_e;
                                hash_input.extend_from_slice(digest.digest());
                                let mut r_digest = vec![0u8; tpm2::TpmiAlgHash::MAX_DIGEST_BYTES];
                                let t_ha = tpm2::crypto::hash::<H>(
                                    digest.hash_alg(),
                                    &[&hash_input],
                                    &mut r_digest,
                                )
                                .map_err(|_| CryptoError::Internal)?;
                                let r_len_trunc = t_ha.digest().len().min(order_bytes);
                                let r_val = BigNum::from_slice(&t_ha.digest()[..r_len_trunc])
                                    .map_err(|_| CryptoError::Internal)?;

                                let mut s = BigNum::new().map_err(|_| CryptoError::Internal)?;
                                let mut rd = BigNum::new().map_err(|_| CryptoError::Internal)?;
                                rd.mod_mul(&r_val, d, &order, &mut ctx)
                                    .map_err(|_| CryptoError::Internal)?;
                                s.mod_add(&k, &rd, &order, &mut ctx)
                                    .map_err(|_| CryptoError::Internal)?;

                                if s == zero || s == k {
                                    continue;
                                }
                                (r_val, s)
                            };

                            let r_bytes = r_out.to_vec();
                            let s_bytes = s_out.to_vec();
                            if r_bytes.len() > $coord_size || s_bytes.len() > $coord_size {
                                return Err(CryptoError::Internal);
                            }
                            out_r.fill(0);
                            out_s.fill(0);
                            out_r[$coord_size - r_bytes.len()..].copy_from_slice(&r_bytes);
                            out_s[$coord_size - s_bytes.len()..].copy_from_slice(&s_bytes);
                            break;
                        }
                        Ok(())
                    }
                }
            }

            fn verify<H: Hash>(
                public: &Self::Public,
                scheme: EccSigScheme,
                digest: TpmtHa<'_>,
                sig_r: &[u8; $coord_size],
                sig_s: &[u8; $coord_size],
            ) -> Result<bool, CryptoError> {
                match scheme {
                    EccSigScheme::Ecdsa => {
                        let r = BigNum::from_slice(sig_r).map_err(|_| CryptoError::Internal)?;
                        let s = BigNum::from_slice(sig_s).map_err(|_| CryptoError::Internal)?;
                        let sig = EcdsaSig::from_private_components(r, s)
                            .map_err(|_| CryptoError::Internal)?;
                        Ok(sig.verify(digest.digest(), public).unwrap_or(false))
                    }
                    EccSigScheme::Sm2 => {
                        let r = BigNum::from_slice(sig_r).map_err(|_| CryptoError::Internal)?;
                        let s = BigNum::from_slice(sig_s).map_err(|_| CryptoError::Internal)?;
                        let sig = EcdsaSig::from_private_components(r, s)
                            .map_err(|_| CryptoError::Internal)?;
                        let sig_der = sig.to_der().map_err(|_| CryptoError::Internal)?;
                        let pkey =
                            PKey::from_ec_key(public.clone()).map_err(|_| CryptoError::Internal)?;
                        let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
                        pctx.verify_init().map_err(|_| CryptoError::Internal)?;
                        Ok(pctx.verify(digest.digest(), &sig_der).unwrap_or(false))
                    }
                    EccSigScheme::Ecschnorr => {
                        let group = public.group();
                        let mut ctx = BigNumContext::new().map_err(|_| CryptoError::Internal)?;
                        let mut order = BigNum::new().map_err(|_| CryptoError::Internal)?;
                        group
                            .order(&mut order, &mut ctx)
                            .map_err(|_| CryptoError::Internal)?;
                        let order_bytes = order.num_bytes() as usize;

                        let r = BigNum::from_slice(sig_r).map_err(|_| CryptoError::Internal)?;
                        let s = BigNum::from_slice(sig_s).map_err(|_| CryptoError::Internal)?;
                        let zero = BigNum::new().map_err(|_| CryptoError::Internal)?;
                        if r <= zero || r >= order {
                            return Ok(false);
                        }
                        if s <= zero || s >= order {
                            return Ok(false);
                        }

                        let mut r_mod = BigNum::new().map_err(|_| CryptoError::Internal)?;
                        let mut neg_r = BigNum::new().map_err(|_| CryptoError::Internal)?;
                        r_mod
                            .nnmod(&r, &order, &mut ctx)
                            .map_err(|_| CryptoError::Internal)?;
                        neg_r
                            .checked_sub(&order, &r_mod)
                            .map_err(|_| CryptoError::Internal)?;
                        let mut e1 = EcPoint::new(group).map_err(|_| CryptoError::Internal)?;
                        if e1
                            .mul2(group, group.generator_opt().unwrap(), &s, &mut ctx)
                            .is_err()
                        {
                            return Ok(false);
                        }
                        let mut e2 = EcPoint::new(group).map_err(|_| CryptoError::Internal)?;
                        if e2
                            .mul2(group, public.public_key(), &neg_r, &mut ctx)
                            .is_err()
                        {
                            return Ok(false);
                        }
                        let mut e = EcPoint::new(group).map_err(|_| CryptoError::Internal)?;
                        if e.add(group, &e1, &e2, &mut ctx).is_err() {
                            return Ok(false);
                        }

                        let mut x_e = BigNum::new().map_err(|_| CryptoError::Internal)?;
                        let mut y_e = BigNum::new().map_err(|_| CryptoError::Internal)?;
                        if e.affine_coordinates_gfp(group, &mut x_e, &mut y_e, &mut ctx)
                            .is_err()
                        {
                            return Ok(false);
                        }

                        let x_e_bytes = x_e.to_vec();
                        let mut fe2bs_x_e = vec![0u8; order_bytes];
                        if x_e_bytes.len() <= order_bytes {
                            fe2bs_x_e[order_bytes - x_e_bytes.len()..].copy_from_slice(&x_e_bytes);
                        } else {
                            return Ok(false);
                        }
                        let mut hash_input = fe2bs_x_e;
                        hash_input.extend_from_slice(digest.digest());
                        let mut r_digest = vec![0u8; tpm2::TpmiAlgHash::MAX_DIGEST_BYTES];
                        let t_ha = tpm2::crypto::hash::<H>(
                            digest.hash_alg(),
                            &[&hash_input],
                            &mut r_digest,
                        )
                        .map_err(|_| CryptoError::Internal)?;
                        let r_len_trunc = t_ha.digest().len().min(order_bytes);
                        let r_prime = BigNum::from_slice(&t_ha.digest()[..r_len_trunc])
                            .map_err(|_| CryptoError::Internal)?;
                        Ok(r_prime == r)
                    }
                }
            }
        }
    };
}
impl_ecc!(NistP192, X9_62_PRIME192V1, 24, 48);
impl_ecc!(NistP224, SECP224R1, 28, 56);
impl_ecc!(NistP256, X9_62_PRIME256V1, 32, 64);
impl_ecc!(NistP384, SECP384R1, 48, 96);
impl_ecc!(NistP521, SECP521R1, 66, 132);
impl_ecc!(SM2P256, SM2, 32, 64);
impl_ecc!(BpP256R1, BRAINPOOL_P256R1, 32, 64);
impl_ecc!(BpP384R1, BRAINPOOL_P384R1, 48, 96);
impl_ecc!(BpP512R1, BRAINPOOL_P512R1, 64, 128);

impl Ecc for super::OpensslBackend {
    type NistP192 = NistP192;
    type NistP224 = NistP224;
    type NistP256 = NistP256;
    type NistP384 = NistP384;
    type NistP521 = NistP521;
    type SM2P256 = SM2P256;
    type BpP256R1 = BpP256R1;
    type BpP384R1 = BpP384R1;
    type BpP512R1 = BpP512R1;
    type BNP256 = !;
    type BNP638 = !;
    type Ed25519 = Ed25519;
    type Ed448 = Ed448;
    type X25519 = X25519;
    type X448 = X448;
}

use openssl::pkey::Id;
use openssl::sign::Signer;
use tpm2::crypto::backend::{EdwardsCurve, MontgomeryCurve};

// Wrapper because PKey<Private> and PKey<Public> are separate types
pub struct EdPriv {
    pub priv_key: PKey<Private>,
    pub pub_key: PKey<Public>,
}

/// Returns whether the raw public keys of `a` and `b` are equal.
fn raw_public_eq(a: &PKey<Public>, b: &PKey<Public>) -> Result<bool, CryptoError> {
    let a = a.raw_public_key().map_err(|_| CryptoError::Internal)?;
    let b = b.raw_public_key().map_err(|_| CryptoError::Internal)?;
    Ok(a == b)
}

macro_rules! impl_edwards {
    ($name:ident, $id:ident, $key_size:expr) => {
        pub struct $name;

        impl $name {
            fn from_secret(secret: &[u8; $key_size]) -> Result<Option<EdPriv>, CryptoError> {
                let priv_key = match PKey::private_key_from_raw_bytes(secret, Id::$id) {
                    Ok(k) => k,
                    Err(_) => return Ok(None),
                };
                let pub_bytes = priv_key
                    .raw_public_key()
                    .map_err(|_| CryptoError::Internal)?;
                let pub_key = PKey::public_key_from_raw_bytes(&pub_bytes, Id::$id)
                    .map_err(|_| CryptoError::Internal)?;
                Ok(Some(EdPriv { priv_key, pub_key }))
            }
        }

        impl AsymmetricKey<$key_size, $key_size> for $name {
            type Public = PKey<Public>;
            type Private = EdPriv;

            fn load_public(
                _: (),
                point: &[u8; $key_size],
            ) -> Result<Option<Self::Public>, CryptoError> {
                PKey::public_key_from_raw_bytes(point, Id::$id)
                    .map(Some)
                    .or(Ok(None))
            }

            fn store_public(
                public: &Self::Public,
                out: &mut [u8; $key_size],
            ) -> Result<(), CryptoError> {
                let bytes = public.raw_public_key().map_err(|_| CryptoError::Internal)?;
                if bytes.len() != $key_size {
                    return Err(CryptoError::Internal);
                }
                out.copy_from_slice(&bytes);
                Ok(())
            }

            fn load_private(
                public: Self::Public,
                secret: &[u8; $key_size],
            ) -> Result<Option<Self::Private>, CryptoError> {
                let Some(private) = Self::from_secret(secret)? else {
                    return Ok(None);
                };
                // The secret must derive `public`.
                if !raw_public_eq(&private.pub_key, &public)? {
                    return Ok(None);
                }
                Ok(Some(private))
            }

            fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
                let mut secret = [0u8; $key_size];
                rng.fill_bytes(&mut secret)
                    .map_err(|_| CryptoError::Internal)?;
                Self::from_secret(&secret).and_then(|opt| opt.ok_or(CryptoError::Internal))
            }

            fn as_public(private: &Self::Private) -> &Self::Public {
                &private.pub_key
            }

            fn store_private(
                private: &Self::Private,
                out: &mut [u8; $key_size],
            ) -> Result<(), CryptoError> {
                let bytes = private
                    .priv_key
                    .raw_private_key()
                    .map_err(|_| CryptoError::Internal)?;
                if bytes.len() != $key_size {
                    return Err(CryptoError::Internal);
                }
                out.copy_from_slice(&bytes);
                Ok(())
            }
        }

        impl EdwardsCurve<$key_size> for $name {
            fn sign_message(
                private: &Self::Private,
                msg: &[&[u8]],
                out_r: &mut [u8; $key_size],
                out_s: &mut [u8; $key_size],
            ) -> Result<(), CryptoError> {
                let mut signer = Signer::new_without_digest(&private.priv_key)
                    .map_err(|_| CryptoError::Internal)?;
                // Collect msg into one slice for oneshot signing since Ed25519 requires it
                let mut full_msg = Vec::new();
                for m in msg {
                    full_msg.extend_from_slice(m);
                }
                let sig = signer
                    .sign_oneshot_to_vec(&full_msg)
                    .map_err(|_| CryptoError::Internal)?;
                if sig.len() != 2 * $key_size {
                    return Err(CryptoError::Internal);
                }
                out_r.copy_from_slice(&sig[..$key_size]);
                out_s.copy_from_slice(&sig[$key_size..]);
                Ok(())
            }

            fn sign_prehash(
                private: &Self::Private,
                prehash: &[u8; 64],
                out_r: &mut [u8; $key_size],
                out_s: &mut [u8; $key_size],
            ) -> Result<(), CryptoError> {
                unsafe {
                    let mut inst = String::from(stringify!($name));
                    inst.push_str("ph");
                    let instance_str = CString::new(inst).unwrap();
                    let sig_fetch =
                        EVP_SIGNATURE_fetch(ptr::null_mut(), instance_str.as_ptr(), ptr::null());
                    if sig_fetch.is_null() {
                        return Err(CryptoError::Unsupported);
                    }
                    let pctx =
                        openssl_sys::EVP_PKEY_CTX_new(private.priv_key.as_ptr(), ptr::null_mut());
                    if pctx.is_null() {
                        EVP_SIGNATURE_free(sig_fetch);
                        return Err(CryptoError::Internal);
                    }
                    if EVP_PKEY_sign_init_ex2(pctx, sig_fetch, ptr::null()) != 1 {
                        openssl_sys::EVP_PKEY_CTX_free(pctx);
                        EVP_SIGNATURE_free(sig_fetch);
                        return Err(CryptoError::Internal);
                    }
                    EVP_SIGNATURE_free(sig_fetch);

                    let mut sig_len = 2 * $key_size;
                    let mut sig = vec![0u8; sig_len];
                    if EVP_PKEY_sign(
                        pctx,
                        sig.as_mut_ptr(),
                        &mut sig_len,
                        prehash.as_ptr(),
                        prehash.len(),
                    ) != 1
                    {
                        openssl_sys::EVP_PKEY_CTX_free(pctx);
                        return Err(CryptoError::Internal);
                    }
                    openssl_sys::EVP_PKEY_CTX_free(pctx);
                    if sig_len != 2 * $key_size {
                        return Err(CryptoError::Internal);
                    }
                    out_r.copy_from_slice(&sig[..$key_size]);
                    out_s.copy_from_slice(&sig[$key_size..]);
                    Ok(())
                }
            }

            fn verify_message(
                public: &Self::Public,
                msg: &[&[u8]],
                sig_r: &[u8; $key_size],
                sig_s: &[u8; $key_size],
            ) -> Result<bool, CryptoError> {
                let mut verifier = openssl::sign::Verifier::new_without_digest(public)
                    .map_err(|_| CryptoError::Internal)?;
                let mut full_msg = Vec::new();
                for m in msg {
                    full_msg.extend_from_slice(m);
                }
                let mut sig = vec![0u8; 2 * $key_size];
                sig[..$key_size].copy_from_slice(sig_r);
                sig[$key_size..].copy_from_slice(sig_s);
                verifier
                    .verify_oneshot(&sig, &full_msg)
                    .map_err(|_| CryptoError::Internal)
            }

            fn verify_prehash(
                public: &Self::Public,
                prehash: &[u8; 64],
                sig_r: &[u8; $key_size],
                sig_s: &[u8; $key_size],
            ) -> Result<bool, CryptoError> {
                unsafe {
                    let mut inst = String::from(stringify!($name));
                    inst.push_str("ph");
                    let instance_str = CString::new(inst).unwrap();
                    let sig_fetch =
                        EVP_SIGNATURE_fetch(ptr::null_mut(), instance_str.as_ptr(), ptr::null());
                    if sig_fetch.is_null() {
                        return Err(CryptoError::Unsupported);
                    }
                    let pctx = openssl_sys::EVP_PKEY_CTX_new(public.as_ptr(), ptr::null_mut());
                    if pctx.is_null() {
                        EVP_SIGNATURE_free(sig_fetch);
                        return Err(CryptoError::Internal);
                    }
                    if EVP_PKEY_verify_init_ex2(pctx, sig_fetch, ptr::null()) != 1 {
                        openssl_sys::EVP_PKEY_CTX_free(pctx);
                        EVP_SIGNATURE_free(sig_fetch);
                        return Err(CryptoError::Internal);
                    }
                    EVP_SIGNATURE_free(sig_fetch);

                    let mut sig = Vec::with_capacity(2 * $key_size);
                    sig.extend_from_slice(sig_r);
                    sig.extend_from_slice(sig_s);
                    let res = EVP_PKEY_verify(
                        pctx,
                        sig.as_ptr(),
                        sig.len(),
                        prehash.as_ptr(),
                        prehash.len(),
                    );
                    openssl_sys::EVP_PKEY_CTX_free(pctx);
                    match res {
                        1 => Ok(true),
                        0 => Ok(false),
                        _ => Err(CryptoError::Internal),
                    }
                }
            }
        }
    };
}

impl_edwards!(Ed25519, ED25519, 32);
impl_edwards!(Ed448, ED448, 57);

macro_rules! impl_montgomery {
    ($name:ident, $id:ident, $key_size:expr) => {
        pub struct $name;

        impl $name {
            fn from_scalar(scalar: &[u8; $key_size]) -> Result<Option<EdPriv>, CryptoError> {
                let priv_key = match PKey::private_key_from_raw_bytes(scalar, Id::$id) {
                    Ok(k) => k,
                    Err(_) => return Ok(None),
                };
                let pub_bytes = priv_key
                    .raw_public_key()
                    .map_err(|_| CryptoError::Internal)?;
                let pub_key = PKey::public_key_from_raw_bytes(&pub_bytes, Id::$id)
                    .map_err(|_| CryptoError::Internal)?;
                Ok(Some(EdPriv { priv_key, pub_key }))
            }
        }

        impl AsymmetricKey<$key_size, $key_size> for $name {
            type Public = PKey<Public>;
            type Private = EdPriv;

            fn load_public(
                _: (),
                point: &[u8; $key_size],
            ) -> Result<Option<Self::Public>, CryptoError> {
                PKey::public_key_from_raw_bytes(point, Id::$id)
                    .map(Some)
                    .or(Ok(None))
            }

            fn store_public(
                public: &Self::Public,
                out_u: &mut [u8; $key_size],
            ) -> Result<(), CryptoError> {
                let bytes = public.raw_public_key().map_err(|_| CryptoError::Internal)?;
                if bytes.len() != $key_size {
                    return Err(CryptoError::Internal);
                }
                out_u.copy_from_slice(&bytes);
                Ok(())
            }

            fn load_private(
                public: Self::Public,
                scalar: &[u8; $key_size],
            ) -> Result<Option<Self::Private>, CryptoError> {
                let Some(private) = Self::from_scalar(scalar)? else {
                    return Ok(None);
                };
                // The scalar must derive `public`.
                if !raw_public_eq(&private.pub_key, &public)? {
                    return Ok(None);
                }
                Ok(Some(private))
            }

            fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
                let mut secret = [0u8; $key_size];
                rng.fill_bytes(&mut secret)
                    .map_err(|_| CryptoError::Internal)?;
                Self::from_scalar(&secret).and_then(|opt| opt.ok_or(CryptoError::Internal))
            }

            fn as_public(private: &Self::Private) -> &Self::Public {
                &private.pub_key
            }

            fn store_private(
                private: &Self::Private,
                out: &mut [u8; $key_size],
            ) -> Result<(), CryptoError> {
                let bytes = private
                    .priv_key
                    .raw_private_key()
                    .map_err(|_| CryptoError::Internal)?;
                if bytes.len() != $key_size {
                    return Err(CryptoError::Internal);
                }
                out.copy_from_slice(&bytes);
                Ok(())
            }
        }

        impl MontgomeryCurve<$key_size> for $name {
            fn ecdh(
                private: &Self::Private,
                public: &Self::Public,
                out_ss: &mut [u8; $key_size],
            ) -> Result<Option<()>, CryptoError> {
                let mut deriver = openssl::derive::Deriver::new(&private.priv_key)
                    .map_err(|_| CryptoError::Internal)?;
                deriver
                    .set_peer(public)
                    .map_err(|_| CryptoError::Internal)?;
                let ss = match deriver.derive_to_vec() {
                    Ok(ss) if ss.iter().any(|&b| b != 0) => ss,
                    _ => return Ok(None),
                };
                if ss.len() != $key_size {
                    return Err(CryptoError::Internal);
                }
                out_ss.copy_from_slice(&ss);
                Ok(Some(()))
            }
        }
    };
}

impl_montgomery!(X25519, X25519, 32);
impl_montgomery!(X448, X448, 56);
