//! Weierstrass ECC (`NIST P-224`, `NIST P-256`, `NIST P-384`, `NIST P-521`)
//! implementations backed by BoringSSL's `EC_*` and `ECDSA_*` APIs.
//!
//! Supports key validation, scalar derivation, deterministic RNG keypair
//! generation, ECDH (`Z = [d] * Q`), and `ECDSA` signatures.

use core::ptr;

use tpm2::crypto::{
    CryptoError, Rng,
    backend::{Ecc, EccCurve, PrivateKey},
};

use crate::bssl_sys::{self, EC_GROUP, EC_KEY, EC_POINT};
use crate::{
    BoringSsl, BoringSslRng,
    util::{Owned, Secret, check},
};

/// Largest X9.62 uncompressed point (`0x04 || x || y`, for P-521).
const MAX_ENCODED_POINT: usize = 1 + 2 * 66;

/// Writes the coordinates of `point` (`x || y`) to `out`.
fn encode_point(
    group: *const EC_GROUP,
    point: *const EC_POINT,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let mut buf = Secret([0u8; MAX_ENCODED_POINT]);
    let len = unsafe {
        bssl_sys::EC_POINT_point2oct(
            group,
            point,
            bssl_sys::point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
            buf.0.as_mut_ptr(),
            buf.0.len(),
            ptr::null_mut(),
        )
    };
    if len != 1 + out.len() {
        return Err(CryptoError::Internal);
    }
    out.copy_from_slice(&buf.0[1..len]);
    Ok(())
}

/// Validated Weierstrass ECC public key backed by BoringSSL `EC_KEY`.
#[derive(Clone)]
pub struct BoringSslEccPublicKey<const COORD_SIZE: usize>(Owned<EC_KEY>);

/// Validated Weierstrass ECC private key, whose BoringSSL `EC_KEY` also holds
/// its public key. `POINT_SIZE` is `2 * COORD_SIZE`.
#[derive(Clone)]
pub struct BoringSslEccPrivateKey<const COORD_SIZE: usize, const POINT_SIZE: usize>(
    BoringSslEccPublicKey<COORD_SIZE>,
);

impl<const COORD_SIZE: usize> BoringSslEccPublicKey<COORD_SIZE> {
    fn group(&self) -> *const EC_GROUP {
        unsafe { bssl_sys::EC_KEY_get0_group(self.0.as_ptr()) }
    }

    fn point(&self) -> *const EC_POINT {
        unsafe { bssl_sys::EC_KEY_get0_public_key(self.0.as_ptr()) }
    }
}

impl<const COORD_SIZE: usize, const POINT_SIZE: usize>
    BoringSslEccPrivateKey<COORD_SIZE, POINT_SIZE>
{
    fn new_key() -> Result<Owned<EC_KEY>, CryptoError> {
        const { assert!(POINT_SIZE == 2 * COORD_SIZE) };
        let nid = match COORD_SIZE {
            28 => bssl_sys::NID_secp224r1,
            32 => bssl_sys::NID_X9_62_prime256v1,
            48 => bssl_sys::NID_secp384r1,
            66 => bssl_sys::NID_secp521r1,
            _ => return Err(CryptoError::Unsupported),
        };
        Owned::new(unsafe { bssl_sys::EC_KEY_new_by_curve_name(nid) })
    }

    /// Derives a private key (and its public key) from `scalar`,
    /// returning `Ok(None)` if `scalar` is not in `[1, n - 1]`.
    #[inline(never)]
    fn from_scalar(scalar: &[u8; COORD_SIZE]) -> Result<Option<Self>, CryptoError> {
        let key = Self::new_key()?;
        let ok = unsafe { bssl_sys::EC_KEY_oct2priv(key.as_ptr(), scalar.as_ptr(), COORD_SIZE) };
        if ok != 1 {
            return Ok(None);
        }
        let group = unsafe { bssl_sys::EC_KEY_get0_group(key.as_ptr()) };
        let point = Owned::new(unsafe { bssl_sys::EC_POINT_new(group) })?;
        unsafe {
            check(bssl_sys::EC_POINT_mul(
                group,
                point.as_ptr(),
                bssl_sys::EC_KEY_get0_private_key(key.as_ptr()),
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
            ))?;
            check(bssl_sys::EC_KEY_set_public_key(
                key.as_ptr(),
                point.as_ptr(),
            ))?;
        }
        Ok(Some(Self(BoringSslEccPublicKey(key))))
    }
}

impl<const COORD_SIZE: usize, const POINT_SIZE: usize>
    PrivateKey<POINT_SIZE, COORD_SIZE, BoringSslRng>
    for BoringSslEccPrivateKey<COORD_SIZE, POINT_SIZE>
{
    type PublicKey = BoringSslEccPublicKey<COORD_SIZE>;

    #[inline(never)]
    fn generate(rng: &mut BoringSslRng, _: ()) -> Result<Self, CryptoError> {
        let mut buf = Secret([0u8; COORD_SIZE]);
        for _ in 0..256 {
            rng.fill_bytes(&mut buf.0)?;
            if COORD_SIZE == 66 {
                // P-521 order is 521 bits; mask top 7 bits so rejection sampling succeeds.
                buf.0[0] &= 0x01;
            }
            if let Some(private) = Self::from_scalar(&buf.0)? {
                return Ok(private);
            }
        }
        Err(CryptoError::Internal)
    }

    #[inline(never)]
    fn load(
        public: Self::PublicKey,
        scalar: &[u8; COORD_SIZE],
    ) -> Result<Option<Self>, CryptoError> {
        let Some(private) = Self::from_scalar(scalar)? else {
            return Ok(None);
        };
        // The private key must match `public` (`[d]G == Q`).
        let (derived, group) = (&private.0, public.group());
        match unsafe {
            bssl_sys::EC_POINT_cmp(group, derived.point(), public.point(), ptr::null_mut())
        } {
            0 => Ok(Some(private)),
            1 => Ok(None),
            _ => Err(CryptoError::Internal),
        }
    }

    fn store(&self, out: &mut [u8; COORD_SIZE]) -> Result<(), CryptoError> {
        let written =
            unsafe { bssl_sys::EC_KEY_priv2oct(self.0.0.as_ptr(), out.as_mut_ptr(), COORD_SIZE) };
        if written != COORD_SIZE {
            return Err(CryptoError::Internal);
        }
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.0
    }

    #[inline(never)]
    fn load_public(
        _: (),
        point: &[u8; POINT_SIZE],
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        // X9.62 uncompressed point: `0x04 || x || y`.
        let mut buf = [0x04; MAX_ENCODED_POINT];
        let buf = &mut buf[..1 + POINT_SIZE];
        buf[1..].copy_from_slice(point);
        let key = Self::new_key()?;
        let ok = unsafe {
            bssl_sys::EC_KEY_oct2key(key.as_ptr(), buf.as_ptr(), buf.len(), ptr::null_mut())
        };
        Ok((ok == 1).then_some(BoringSslEccPublicKey(key)))
    }

    fn store_public(
        public: &Self::PublicKey,
        out: &mut [u8; POINT_SIZE],
    ) -> Result<(), CryptoError> {
        encode_point(public.group(), public.point(), out)
    }
}

impl<const COORD_SIZE: usize, const POINT_SIZE: usize>
    EccCurve<COORD_SIZE, POINT_SIZE, BoringSslRng>
    for BoringSslEccPrivateKey<COORD_SIZE, POINT_SIZE>
{
    #[inline(never)]
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_x: &mut [u8; COORD_SIZE],
        out_y: &mut [u8; COORD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let group = self.0.group();
        let shared = Owned::new(unsafe { bssl_sys::EC_POINT_new(group) })?;
        let ok = unsafe {
            bssl_sys::EC_POINT_mul(
                group,
                shared.as_ptr(),
                ptr::null(),
                peer_public.point(),
                bssl_sys::EC_KEY_get0_private_key(self.0.0.as_ptr()),
                ptr::null_mut(),
            )
        };
        if ok != 1 || unsafe { bssl_sys::EC_POINT_is_at_infinity(group, shared.as_ptr()) } != 0 {
            return Ok(None);
        }
        let mut xy = Secret([0u8; POINT_SIZE]);
        encode_point(group, shared.as_ptr(), &mut xy.0)?;
        out_x.copy_from_slice(&xy.0[..COORD_SIZE]);
        out_y.copy_from_slice(&xy.0[COORD_SIZE..]);
        Ok(Some(()))
    }

    #[inline(never)]
    fn sign(
        &self,
        rng: &mut BoringSslRng,
        digest: &[u8],
        out_r: &mut [u8; COORD_SIZE],
        out_s: &mut [u8; COORD_SIZE],
    ) -> Result<(), CryptoError> {
        // `ECDSA_sign_p1363` uses BoringSSL's system RNG.
        rng.check_system()?;
        let mut sig = [0u8; POINT_SIZE];
        let mut sig_len: usize = 0;
        check(unsafe {
            bssl_sys::ECDSA_sign_p1363(
                digest.as_ptr(),
                digest.len(),
                sig.as_mut_ptr(),
                &raw mut sig_len,
                sig.len(),
                self.0.0.as_ptr(),
            )
        })?;
        if sig_len != sig.len() {
            return Err(CryptoError::Internal);
        }
        out_r.copy_from_slice(&sig[..COORD_SIZE]);
        out_s.copy_from_slice(&sig[COORD_SIZE..]);
        Ok(())
    }

    #[inline(never)]
    fn verify(
        public: &Self::PublicKey,
        digest: &[u8],
        sig_r: &[u8; COORD_SIZE],
        sig_s: &[u8; COORD_SIZE],
    ) -> Result<bool, CryptoError> {
        let mut sig = [0u8; POINT_SIZE];
        sig[..COORD_SIZE].copy_from_slice(sig_r);
        sig[COORD_SIZE..].copy_from_slice(sig_s);
        let ok = unsafe {
            bssl_sys::ECDSA_verify_p1363(
                digest.as_ptr(),
                digest.len(),
                sig.as_ptr(),
                sig.len(),
                public.0.as_ptr(),
            )
        };
        Ok(ok == 1)
    }
}

impl Ecc for BoringSsl {
    type NistP192 = !;
    type NistP224 = BoringSslEccPrivateKey<28, 56>;
    type NistP256 = BoringSslEccPrivateKey<32, 64>;
    type NistP384 = BoringSslEccPrivateKey<48, 96>;
    type NistP521 = BoringSslEccPrivateKey<66, 132>;
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
