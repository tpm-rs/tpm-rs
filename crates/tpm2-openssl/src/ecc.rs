use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{PKey, Private, Public},
    pkey_ctx::PkeyCtx,
};
use tpm2::crypto::{
    CryptoError, Rng,
    backend::{Ecc, EccCurve, PrivateKey},
};

use crate::rng::OpensslRng;

use foreign_types::ForeignType;
use std::ffi::CStr;

use core::ffi::c_int;
use openssl_sys::{
    self as ffi, EVP_PKEY_sign, EVP_PKEY_verify, EVP_SIGNATURE_fetch, EVP_SIGNATURE_free,
};

use crate::sys::{EVP_PKEY_sign_init_ex2, EVP_PKEY_verify_init_ex2};
use std::ptr;

/// Writes the big-endian `(r, s)` of `sig` into `out_r` and `out_s`.
fn store_sig<const COORD_SIZE: usize>(
    sig: &EcdsaSig,
    out_r: &mut [u8; COORD_SIZE],
    out_s: &mut [u8; COORD_SIZE],
) -> Result<(), CryptoError> {
    let r_bytes = sig.r().to_vec();
    let s_bytes = sig.s().to_vec();
    if r_bytes.len() > COORD_SIZE || s_bytes.len() > COORD_SIZE {
        return Err(CryptoError::Internal);
    }
    out_r.fill(0);
    out_s.fill(0);
    out_r[COORD_SIZE - r_bytes.len()..].copy_from_slice(&r_bytes);
    out_s[COORD_SIZE - s_bytes.len()..].copy_from_slice(&s_bytes);
    Ok(())
}

/// Returns the signature with big-endian `(r, s)`.
fn load_sig(sig_r: &[u8], sig_s: &[u8]) -> Result<EcdsaSig, CryptoError> {
    let r = BigNum::from_slice(sig_r).map_err(|_| CryptoError::Internal)?;
    let s = BigNum::from_slice(sig_s).map_err(|_| CryptoError::Internal)?;
    EcdsaSig::from_private_components(r, s).map_err(|_| CryptoError::Internal)
}

/// Weierstrass curve private key, on the curve with NID `NID`. `POINT_SIZE` is
/// `2 * COORD_SIZE`.
pub struct OpensslEccKey<const NID: c_int, const COORD_SIZE: usize, const POINT_SIZE: usize> {
    pub priv_key: EcKey<Private>,
    pub pub_key: EcKey<Public>,
}

impl<const NID: c_int, const COORD_SIZE: usize, const POINT_SIZE: usize>
    PrivateKey<POINT_SIZE, COORD_SIZE, OpensslRng> for OpensslEccKey<NID, COORD_SIZE, POINT_SIZE>
{
    type PublicKey = EcKey<Public>;

    fn load_public(
        _: (),
        public: &[u8; POINT_SIZE],
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        const { assert!(POINT_SIZE == 2 * COORD_SIZE) };
        let (x, y) = public.split_at(COORD_SIZE);
        let group =
            EcGroup::from_curve_name(Nid::from_raw(NID)).map_err(|_| CryptoError::Internal)?;
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
            let key = EcKey::from_public_key(&group, &point).map_err(|_| CryptoError::Internal)?;
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    fn store_public(
        public: &Self::PublicKey,
        out: &mut [u8; POINT_SIZE],
    ) -> Result<(), CryptoError> {
        let (out_x, out_y) = out.split_at_mut(COORD_SIZE);
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
        if x_bytes.len() > COORD_SIZE || y_bytes.len() > COORD_SIZE {
            return Err(CryptoError::Internal);
        }
        out_x.fill(0);
        out_y.fill(0);
        out_x[COORD_SIZE - x_bytes.len()..].copy_from_slice(&x_bytes);
        out_y[COORD_SIZE - y_bytes.len()..].copy_from_slice(&y_bytes);
        Ok(())
    }

    fn load(
        public: Self::PublicKey,
        scalar: &[u8; COORD_SIZE],
    ) -> Result<Option<Self>, CryptoError> {
        let group =
            EcGroup::from_curve_name(Nid::from_raw(NID)).map_err(|_| CryptoError::Internal)?;
        let mut ctx = BigNumContext::new().map_err(|_| CryptoError::Internal)?;
        let d = BigNum::from_slice(scalar).map_err(|_| CryptoError::Internal)?;

        let mut order = BigNum::new().map_err(|_| CryptoError::Internal)?;
        group
            .order(&mut order, &mut ctx)
            .map_err(|_| CryptoError::Internal)?;

        // `0 < d < n`
        if d == BigNum::new().unwrap() || d >= order {
            return Ok(None);
        }

        // Compute `[d]G`.
        let mut pub_pt = EcPoint::new(&group).map_err(|_| CryptoError::Internal)?;
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

        Ok(Some(Self {
            priv_key,
            pub_key: public,
        }))
    }

    /// Draws `d` from `rng` by rejection sampling: `COORD_SIZE` random
    /// big-endian bytes, with the bits above `bitlen(n)` cleared, are
    /// accepted iff `1 <= d < n`.
    fn generate(rng: &mut OpensslRng, _: ()) -> Result<Self, CryptoError> {
        const { assert!(POINT_SIZE == 2 * COORD_SIZE) };
        let internal = |_: openssl::error::ErrorStack| CryptoError::Internal;
        let group = EcGroup::from_curve_name(Nid::from_raw(NID)).map_err(internal)?;
        let mut ctx = BigNumContext::new().map_err(internal)?;
        let mut order = BigNum::new().map_err(internal)?;
        group.order(&mut order, &mut ctx).map_err(internal)?;
        let excess_bits = COORD_SIZE * 8 - group.order_bits() as usize;

        let mut bytes = [0u8; COORD_SIZE];
        let d = loop {
            rng.fill_bytes(&mut bytes)?;
            bytes[0] &= 0xff >> excess_bits;
            let d = BigNum::from_slice(&bytes).map_err(internal)?;
            if d.num_bits() > 0 && d < order {
                break d;
            }
        };
        bytes.fill(0);

        let mut point = EcPoint::new(&group).map_err(internal)?;
        point
            .mul_generator2(&group, &d, &mut ctx)
            .map_err(internal)?;
        let priv_key = EcKey::from_private_components(&group, &d, &point).map_err(internal)?;
        let pub_key = EcKey::from_public_key(&group, &point).map_err(internal)?;
        Ok(Self { priv_key, pub_key })
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.pub_key
    }

    fn store(&self, out: &mut [u8; COORD_SIZE]) -> Result<(), CryptoError> {
        let d_bytes = self.priv_key.private_key().to_vec();
        if d_bytes.len() > COORD_SIZE {
            return Err(CryptoError::Internal);
        }
        out.fill(0);
        out[COORD_SIZE - d_bytes.len()..].copy_from_slice(&d_bytes);
        Ok(())
    }
}

impl<const NID: c_int, const COORD_SIZE: usize, const POINT_SIZE: usize>
    EccCurve<COORD_SIZE, POINT_SIZE, OpensslRng> for OpensslEccKey<NID, COORD_SIZE, POINT_SIZE>
{
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_x: &mut [u8; COORD_SIZE],
        out_y: &mut [u8; COORD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let group = self.priv_key.group();
        let mut ctx = BigNumContext::new().map_err(|_| CryptoError::Internal)?;
        let mut res = EcPoint::new(group).map_err(|_| CryptoError::Internal)?;

        res.mul2(
            group,
            peer_public.public_key(),
            self.priv_key.private_key(),
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
        if x_bytes.len() > COORD_SIZE || y_bytes.len() > COORD_SIZE {
            return Err(CryptoError::Internal);
        }
        out_x.fill(0);
        out_y.fill(0);
        out_x[COORD_SIZE - x_bytes.len()..].copy_from_slice(&x_bytes);
        out_y[COORD_SIZE - y_bytes.len()..].copy_from_slice(&y_bytes);

        Ok(Some(()))
    }

    fn sign(
        &self,
        _rng: &mut OpensslRng,
        digest: &[u8],
        out_r: &mut [u8; COORD_SIZE],
        out_s: &mut [u8; COORD_SIZE],
    ) -> Result<(), CryptoError> {
        let sig = EcdsaSig::sign(digest, &self.priv_key).map_err(|_| CryptoError::Internal)?;
        store_sig(&sig, out_r, out_s)
    }

    fn verify(
        public: &Self::PublicKey,
        digest: &[u8],
        sig_r: &[u8; COORD_SIZE],
        sig_s: &[u8; COORD_SIZE],
    ) -> Result<bool, CryptoError> {
        let sig = load_sig(sig_r, sig_s)?;
        Ok(sig.verify(digest, public).unwrap_or(false))
    }

    // OpenSSL only implements `SM2` signatures on the `SM2` curve.
    fn sm2_sign(
        &self,
        _rng: &mut OpensslRng,
        e: &[u8],
        out_r: &mut [u8; COORD_SIZE],
        out_s: &mut [u8; COORD_SIZE],
    ) -> Result<(), CryptoError> {
        if NID != ffi::NID_sm2 {
            return Err(CryptoError::Unsupported);
        }
        let pkey = PKey::from_ec_key(self.priv_key.clone()).map_err(|_| CryptoError::Internal)?;
        let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
        pctx.sign_init().map_err(|_| CryptoError::Internal)?;
        let mut sig_out = vec![];
        pctx.sign_to_vec(e, &mut sig_out)
            .map_err(|_| CryptoError::Internal)?;
        let sig = EcdsaSig::from_der(&sig_out).map_err(|_| CryptoError::Internal)?;
        store_sig(&sig, out_r, out_s)
    }

    fn sm2_verify(
        public: &Self::PublicKey,
        e: &[u8],
        sig_r: &[u8; COORD_SIZE],
        sig_s: &[u8; COORD_SIZE],
    ) -> Result<bool, CryptoError> {
        if NID != ffi::NID_sm2 {
            return Err(CryptoError::Unsupported);
        }
        let sig = load_sig(sig_r, sig_s)?;
        let sig_der = sig.to_der().map_err(|_| CryptoError::Internal)?;
        let pkey = PKey::from_ec_key(public.clone()).map_err(|_| CryptoError::Internal)?;
        let mut pctx = PkeyCtx::new(&pkey).map_err(|_| CryptoError::Internal)?;
        pctx.verify_init().map_err(|_| CryptoError::Internal)?;
        Ok(pctx.verify(e, &sig_der).unwrap_or(false))
    }
}

impl Ecc for super::OpensslBackend {
    type NistP192 = OpensslEccKey<{ ffi::NID_X9_62_prime192v1 }, 24, 48>;
    type NistP224 = OpensslEccKey<{ ffi::NID_secp224r1 }, 28, 56>;
    type NistP256 = OpensslEccKey<{ ffi::NID_X9_62_prime256v1 }, 32, 64>;
    type NistP384 = OpensslEccKey<{ ffi::NID_secp384r1 }, 48, 96>;
    type NistP521 = OpensslEccKey<{ ffi::NID_secp521r1 }, 66, 132>;
    type SM2P256 = OpensslEccKey<{ ffi::NID_sm2 }, 32, 64>;
    type BpP256R1 = OpensslEccKey<{ ffi::NID_brainpoolP256r1 }, 32, 64>;
    type BpP384R1 = OpensslEccKey<{ ffi::NID_brainpoolP384r1 }, 48, 96>;
    type BpP512R1 = OpensslEccKey<{ ffi::NID_brainpoolP512r1 }, 64, 128>;
    type BNP256 = !;
    type BNP638 = !;
    type Ed25519 = OpensslEdwardsKey<{ ffi::EVP_PKEY_ED25519 }, 32>;
    type Ed448 = OpensslEdwardsKey<{ ffi::EVP_PKEY_ED448 }, 57>;
    type X25519 = OpensslMontgomeryKey<{ ffi::EVP_PKEY_X25519 }, 32>;
    type X448 = OpensslMontgomeryKey<{ ffi::EVP_PKEY_X448 }, 56>;
}

use openssl::pkey::Id;
use openssl::sign::Signer;
use tpm2::crypto::backend::{EdwardsCurve, MontgomeryCurve};

/// Returns whether the raw public keys of `a` and `b` are equal.
fn raw_public_eq(a: &PKey<Public>, b: &PKey<Public>) -> Result<bool, CryptoError> {
    let a = a.raw_public_key().map_err(|_| CryptoError::Internal)?;
    let b = b.raw_public_key().map_err(|_| CryptoError::Internal)?;
    Ok(a == b)
}

/// The field prime `p = 2^255 - 19` of Ed25519, little-endian.
const ED25519_P: [u8; 32] = {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};
/// The curve constant `d = -121665 / 121666 mod p` of Ed25519, little-endian.
const ED25519_D: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];
/// The field prime `p = 2^448 - 2^224 - 1` of Ed448, little-endian (57 bytes).
const ED448_P: [u8; 57] = {
    let mut p = [0xff; 57];
    p[28] = 0xfe;
    p[56] = 0;
    p
};
/// The curve constant `d = -39081 mod p` of Ed448, little-endian (57 bytes).
const ED448_D: [u8; 57] = {
    let mut d = ED448_P;
    (d[0], d[1]) = (0x56, 0x67);
    d
};

/// Returns whether `point` is a valid RFC 8032 point encoding (Sections 5.1.3
/// and 5.2.3) on the twisted Edwards curve `a x^2 + y^2 = 1 + d x^2 y^2` with
/// field prime `p` and `a = ±1` (`p` and `d` little-endian). OpenSSL doesn't
/// check this.
///
/// Decoding computes `x^2 = u / v` with `u = y^2 - 1` and `v = d y^2 - a`
/// (never 0, as `a / d` isn't a square). `u / v` is a square exactly when
/// `u v` is, so this checks `y < p` and that `t = u v` is 0 (then `x = 0`,
/// whose sign bit must be clear) or a square (Euler's criterion). The point is
/// public, so this doesn't need to be constant time.
fn is_valid_point(point: &[u8], p: &[u8], d: &[u8], a: i32) -> Result<bool, CryptoError> {
    let internal = |_: openssl::error::ErrorStack| CryptoError::Internal;
    let from_le = |le: &[u8]| {
        let be: Vec<u8> = le.iter().rev().copied().collect();
        BigNum::from_slice(&be).map_err(internal)
    };
    let bn = || BigNum::new().map_err(internal);
    let sign = point[point.len() - 1] >> 7;
    let mut y = point.to_vec();
    y[point.len() - 1] &= 0x7f;
    let (y, p, d) = (from_le(&y)?, from_le(p)?, from_le(d)?);
    if y >= p {
        return Ok(false);
    }
    let mut ctx = BigNumContext::new().map_err(internal)?;
    let one = BigNum::from_u32(1).map_err(internal)?;
    let (mut y2, mut dy2, mut u, mut v, mut t) = (bn()?, bn()?, bn()?, bn()?, bn()?);
    y2.mod_sqr(&y, &p, &mut ctx).map_err(internal)?; // y^2
    dy2.mod_mul(&d, &y2, &p, &mut ctx).map_err(internal)?; // d y^2
    u.mod_sub(&y2, &one, &p, &mut ctx).map_err(internal)?; // u = y^2 - 1
    match a {
        -1 => v.mod_add(&dy2, &one, &p, &mut ctx), // v = d y^2 + 1
        _ => v.mod_sub(&dy2, &one, &p, &mut ctx),  // v = d y^2 - 1
    }
    .map_err(internal)?;
    t.mod_mul(&u, &v, &p, &mut ctx).map_err(internal)?; // t = u v
    if t.num_bits() == 0 {
        return Ok(sign == 0);
    }
    let mut e = bn()?;
    e.rshift1(&p).map_err(internal)?; // (p - 1) / 2, as p is odd
    u.mod_exp(&t, &e, &p, &mut ctx).map_err(internal)?;
    Ok(u == one)
}

/// An Edwards curve's RFC 8032 parameters (see [`is_valid_point`]), and its
/// prehash (`HashEdDSA`) signature algorithm.
struct EdwardsParams {
    p: &'static [u8],
    d: &'static [u8],
    a: i32,
    prehash_alg: &'static CStr,
}

impl EdwardsParams {
    /// Returns the parameters of the Edwards curve with `EVP_PKEY` type `id`.
    fn new(id: c_int) -> Result<Self, CryptoError> {
        let (p, d, a, prehash_alg): (&[u8], &[u8], _, _) = match id {
            ffi::EVP_PKEY_ED25519 => (&ED25519_P, &ED25519_D, -1, c"Ed25519ph"),
            ffi::EVP_PKEY_ED448 => (&ED448_P, &ED448_D, 1, c"Ed448ph"),
            _ => return Err(CryptoError::Unsupported),
        };
        Ok(Self {
            p,
            d,
            a,
            prehash_alg,
        })
    }
}

/// Edwards curve private key, for the `EVP_PKEY` type `ID`.
pub struct OpensslEdwardsKey<const ID: c_int, const SIZE: usize> {
    pub priv_key: PKey<Private>,
    pub pub_key: PKey<Public>,
}

impl<const ID: c_int, const SIZE: usize> OpensslEdwardsKey<ID, SIZE> {
    fn from_secret(secret: &[u8; SIZE]) -> Result<Option<Self>, CryptoError> {
        let priv_key = match PKey::private_key_from_raw_bytes(secret, Id::from_raw(ID)) {
            Ok(k) => k,
            Err(_) => return Ok(None),
        };
        let pub_bytes = priv_key
            .raw_public_key()
            .map_err(|_| CryptoError::Internal)?;
        let pub_key = PKey::public_key_from_raw_bytes(&pub_bytes, Id::from_raw(ID))
            .map_err(|_| CryptoError::Internal)?;
        Ok(Some(Self { priv_key, pub_key }))
    }
}

impl<const ID: c_int, const SIZE: usize> PrivateKey<SIZE, SIZE, OpensslRng>
    for OpensslEdwardsKey<ID, SIZE>
{
    type PublicKey = PKey<Public>;

    fn load_public(_: (), point: &[u8; SIZE]) -> Result<Option<Self::PublicKey>, CryptoError> {
        let EdwardsParams { p, d, a, .. } = EdwardsParams::new(ID)?;
        if !is_valid_point(point, p, d, a)? {
            return Ok(None);
        }
        PKey::public_key_from_raw_bytes(point, Id::from_raw(ID))
            .map(Some)
            .or(Ok(None))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; SIZE]) -> Result<(), CryptoError> {
        let bytes = public.raw_public_key().map_err(|_| CryptoError::Internal)?;
        if bytes.len() != SIZE {
            return Err(CryptoError::Internal);
        }
        out.copy_from_slice(&bytes);
        Ok(())
    }

    fn load(public: Self::PublicKey, secret: &[u8; SIZE]) -> Result<Option<Self>, CryptoError> {
        let Some(private) = Self::from_secret(secret)? else {
            return Ok(None);
        };
        // The secret must derive `public`.
        if !raw_public_eq(&private.pub_key, &public)? {
            return Ok(None);
        }
        Ok(Some(private))
    }

    fn generate(rng: &mut OpensslRng, _: ()) -> Result<Self, CryptoError> {
        let mut secret = [0u8; SIZE];
        rng.fill_bytes(&mut secret)
            .map_err(|_| CryptoError::Internal)?;
        Self::from_secret(&secret).and_then(|opt| opt.ok_or(CryptoError::Internal))
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.pub_key
    }

    fn store(&self, out: &mut [u8; SIZE]) -> Result<(), CryptoError> {
        let bytes = self
            .priv_key
            .raw_private_key()
            .map_err(|_| CryptoError::Internal)?;
        if bytes.len() != SIZE {
            return Err(CryptoError::Internal);
        }
        out.copy_from_slice(&bytes);
        Ok(())
    }
}

impl<const ID: c_int, const SIZE: usize> EdwardsCurve<SIZE, OpensslRng>
    for OpensslEdwardsKey<ID, SIZE>
{
    fn sign_message(
        &self,
        msg: &[&[u8]],
        out_r: &mut [u8; SIZE],
        out_s: &mut [u8; SIZE],
    ) -> Result<(), CryptoError> {
        let mut signer =
            Signer::new_without_digest(&self.priv_key).map_err(|_| CryptoError::Internal)?;
        // Collect msg into one slice for oneshot signing since Ed25519 requires it
        let mut full_msg = Vec::new();
        for m in msg {
            full_msg.extend_from_slice(m);
        }
        let sig = signer
            .sign_oneshot_to_vec(&full_msg)
            .map_err(|_| CryptoError::Internal)?;
        if sig.len() != 2 * SIZE {
            return Err(CryptoError::Internal);
        }
        out_r.copy_from_slice(&sig[..SIZE]);
        out_s.copy_from_slice(&sig[SIZE..]);
        Ok(())
    }

    fn sign_prehash(
        &self,
        prehash: &[u8; 64],
        out_r: &mut [u8; SIZE],
        out_s: &mut [u8; SIZE],
    ) -> Result<(), CryptoError> {
        unsafe {
            let prehash_alg = EdwardsParams::new(ID)?.prehash_alg;
            let sig_fetch = EVP_SIGNATURE_fetch(ptr::null_mut(), prehash_alg.as_ptr(), ptr::null());
            if sig_fetch.is_null() {
                return Err(CryptoError::Unsupported);
            }
            let pctx = openssl_sys::EVP_PKEY_CTX_new(self.priv_key.as_ptr(), ptr::null_mut());
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

            let mut sig_len = 2 * SIZE;
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
            if sig_len != 2 * SIZE {
                return Err(CryptoError::Internal);
            }
            out_r.copy_from_slice(&sig[..SIZE]);
            out_s.copy_from_slice(&sig[SIZE..]);
            Ok(())
        }
    }

    fn verify_message(
        public: &Self::PublicKey,
        msg: &[&[u8]],
        sig_r: &[u8; SIZE],
        sig_s: &[u8; SIZE],
    ) -> Result<bool, CryptoError> {
        let mut verifier = openssl::sign::Verifier::new_without_digest(public)
            .map_err(|_| CryptoError::Internal)?;
        let mut full_msg = Vec::new();
        for m in msg {
            full_msg.extend_from_slice(m);
        }
        let mut sig = vec![0u8; 2 * SIZE];
        sig[..SIZE].copy_from_slice(sig_r);
        sig[SIZE..].copy_from_slice(sig_s);
        verifier
            .verify_oneshot(&sig, &full_msg)
            .map_err(|_| CryptoError::Internal)
    }

    fn verify_prehash(
        public: &Self::PublicKey,
        prehash: &[u8; 64],
        sig_r: &[u8; SIZE],
        sig_s: &[u8; SIZE],
    ) -> Result<bool, CryptoError> {
        unsafe {
            let prehash_alg = EdwardsParams::new(ID)?.prehash_alg;
            let sig_fetch = EVP_SIGNATURE_fetch(ptr::null_mut(), prehash_alg.as_ptr(), ptr::null());
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

            let mut sig = Vec::with_capacity(2 * SIZE);
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

/// Montgomery curve private key, for the `EVP_PKEY` type `ID`.
pub struct OpensslMontgomeryKey<const ID: c_int, const SIZE: usize> {
    pub priv_key: PKey<Private>,
    pub pub_key: PKey<Public>,
}

impl<const ID: c_int, const SIZE: usize> OpensslMontgomeryKey<ID, SIZE> {
    fn from_scalar(scalar: &[u8; SIZE]) -> Result<Option<Self>, CryptoError> {
        let priv_key = match PKey::private_key_from_raw_bytes(scalar, Id::from_raw(ID)) {
            Ok(k) => k,
            Err(_) => return Ok(None),
        };
        let pub_bytes = priv_key
            .raw_public_key()
            .map_err(|_| CryptoError::Internal)?;
        let pub_key = PKey::public_key_from_raw_bytes(&pub_bytes, Id::from_raw(ID))
            .map_err(|_| CryptoError::Internal)?;
        Ok(Some(Self { priv_key, pub_key }))
    }
}

impl<const ID: c_int, const SIZE: usize> PrivateKey<SIZE, SIZE, OpensslRng>
    for OpensslMontgomeryKey<ID, SIZE>
{
    type PublicKey = PKey<Public>;

    fn load_public(_: (), point: &[u8; SIZE]) -> Result<Option<Self::PublicKey>, CryptoError> {
        PKey::public_key_from_raw_bytes(point, Id::from_raw(ID))
            .map(Some)
            .or(Ok(None))
    }

    fn store_public(public: &Self::PublicKey, out_u: &mut [u8; SIZE]) -> Result<(), CryptoError> {
        let bytes = public.raw_public_key().map_err(|_| CryptoError::Internal)?;
        if bytes.len() != SIZE {
            return Err(CryptoError::Internal);
        }
        out_u.copy_from_slice(&bytes);
        Ok(())
    }

    fn load(public: Self::PublicKey, scalar: &[u8; SIZE]) -> Result<Option<Self>, CryptoError> {
        let Some(private) = Self::from_scalar(scalar)? else {
            return Ok(None);
        };
        // The scalar must derive `public`.
        if !raw_public_eq(&private.pub_key, &public)? {
            return Ok(None);
        }
        Ok(Some(private))
    }

    fn generate(rng: &mut OpensslRng, _: ()) -> Result<Self, CryptoError> {
        let mut secret = [0u8; SIZE];
        rng.fill_bytes(&mut secret)
            .map_err(|_| CryptoError::Internal)?;
        Self::from_scalar(&secret).and_then(|opt| opt.ok_or(CryptoError::Internal))
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.pub_key
    }

    fn store(&self, out: &mut [u8; SIZE]) -> Result<(), CryptoError> {
        let bytes = self
            .priv_key
            .raw_private_key()
            .map_err(|_| CryptoError::Internal)?;
        if bytes.len() != SIZE {
            return Err(CryptoError::Internal);
        }
        out.copy_from_slice(&bytes);
        Ok(())
    }
}

impl<const ID: c_int, const SIZE: usize> MontgomeryCurve<SIZE, OpensslRng>
    for OpensslMontgomeryKey<ID, SIZE>
{
    fn ecdh(
        &self,
        public: &Self::PublicKey,
        out_ss: &mut [u8; SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let mut deriver =
            openssl::derive::Deriver::new(&self.priv_key).map_err(|_| CryptoError::Internal)?;
        deriver
            .set_peer(public)
            .map_err(|_| CryptoError::Internal)?;
        let ss = match deriver.derive_to_vec() {
            Ok(ss) if ss.iter().any(|&b| b != 0) => ss,
            _ => return Ok(None),
        };
        if ss.len() != SIZE {
            return Err(CryptoError::Internal);
        }
        out_ss.copy_from_slice(&ss);
        Ok(Some(()))
    }
}
