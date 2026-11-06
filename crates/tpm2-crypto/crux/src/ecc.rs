//! [`Ecc`] for [`CruxCryptoProvider`].
//!
//! | Curve | Arithmetic | Schemes |
//! |-------|------------|---------|
//! | NIST P-256 | `libcrux-p256` | ECDSA, ECDH |
//! | NIST P-384, P-521 | RustCrypto `p384`, `p521` | ECDSA, ECDH |
//! | NIST P-192, P-224, BN P-256, BN P-638, SM2 P-256 | `tpm2-crypto-weierstrass` | ECDSA, SM2, ECDH |
//!
//! Every curve also implements the tpm-rs extensions
//! [`EccCurve::mul_generator`] and [`EccCurve::mul_point`]. ECDSA accepts a
//! digest of any length: it is truncated to its leftmost bytes or zero-padded
//! on the left to the size of the curve order (FIPS 186-5 `bits2int`, see
//! [`ecdsa_prehash`]). The Brainpool curves, Curve25519 and Curve448 are not
//! supported.

use core::marker::PhantomData;

use tpm2::crypto::backend::{Ecc, EccCurve, PrivateKey};
use tpm2::crypto::{Crypto as _, CryptoError, Rng as _};
use zeroize::Zeroize as _;

use crate::{CruxCryptoProvider, CruxRng};

impl Ecc for CruxCryptoProvider {
    type NistP192 = tpm2_crypto_weierstrass::NistP192;
    type NistP224 = tpm2_crypto_weierstrass::NistP224;
    type NistP256 = CruxEccKey<NistP256, 32, 64>;
    type NistP384 = CruxEccKey<NistP384, 48, 96>;
    type NistP521 = CruxEccKey<NistP521, 66, 132>;
    type BNP256 = tpm2_crypto_weierstrass::BnP256;
    type BNP638 = tpm2_crypto_weierstrass::BnP638;
    type SM2P256 = tpm2_crypto_weierstrass::Sm2P256;
    type BpP256R1 = !;
    type BpP384R1 = !;
    type BpP512R1 = !;
    type Ed25519 = !;
    type Ed448 = !;
    type X25519 = !;
    type X448 = !;
}

/// Normalizes an ECDSA `digest` to exactly `N` bytes, the byte length of the
/// curve order, as described by FIPS 186-5 section 6.4 (`bits2int`).
///
/// TPM 2.0 allows any hash algorithm to be combined with any ECDSA curve
/// (Part 1, section C.4 / `CryptEccSign`), so the digest length does not have
/// to match the curve size:
/// - A digest longer than the order is truncated to its leftmost `N` bytes.
///   For the byte-aligned orders used here (P-256 and P-384) this is exactly
///   the leftmost `bitlen(n)` bits.
/// - A shorter digest is left-padded with zeros, which preserves its integer
///   value.
///
/// This matches the BoringSSL and pure-Rust backends. It is also required to
/// avoid a panic in `libcrux_p256`, whose `*_without_hash` functions read
/// exactly 32 bytes from the message and index out of bounds on shorter input.
///
/// For P-521 (`N == 66`), every supported TPM digest (at most 64 bytes) is
/// shorter than the order, so only the zero-padding branch is ever taken.
pub fn ecdsa_prehash<const N: usize>(digest: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    if digest.len() >= N {
        out.copy_from_slice(&digest[..N]);
    } else {
        out[N - digest.len()..].copy_from_slice(digest);
    }
    out
}

/// The arithmetic of a curve of [`CruxEccKey`], with coordinates and scalars
/// of `COORD` bytes and points `x || y` of `POINT = 2 * COORD` bytes.
pub trait CurveOps<const COORD: usize, const POINT: usize> {
    /// Whether `point` is a point of the curve (not the point at infinity).
    fn validate(point: &[u8; POINT]) -> bool;

    /// Draws a secret scalar uniformly from `[1, n - 1]`.
    fn random_scalar(rng: &mut CruxRng) -> Result<[u8; COORD], CryptoError>;

    /// `[k]G`: `Ok(None)` if `k` is not in `[1, n - 1]`.
    fn mul_generator(k: &[u8; COORD]) -> Result<Option<[u8; POINT]>, CryptoError>;

    /// `[k]point` for a validated `point`: `Ok(None)` if `k` is not in
    /// `[1, n - 1]` or the result is the point at infinity.
    fn mul_point(point: &[u8; POINT], k: &[u8; COORD]) -> Result<Option<[u8; POINT]>, CryptoError>;

    /// ECDSA signature `r || s` of `digest` with the valid secret scalar `d`.
    fn ecdsa_sign(
        d: &[u8; COORD],
        rng: &mut CruxRng,
        digest: &[u8],
    ) -> Result<[u8; POINT], CryptoError>;

    /// Verifies the ECDSA signature `r || s` of `digest` under the validated
    /// `point`.
    fn ecdsa_verify(point: &[u8; POINT], digest: &[u8], sig: &[u8; POINT]) -> bool;
}

/// A validated public key (a point other than the point at infinity) of the
/// curve `C`, encoded `x || y` (`POINT` bytes).
pub struct CruxEccPublicKey<C, const POINT: usize> {
    point: [u8; POINT],
    curve: PhantomData<fn() -> C>,
}

impl<C, const POINT: usize> Clone for CruxEccPublicKey<C, POINT> {
    fn clone(&self) -> Self {
        Self {
            point: self.point,
            curve: PhantomData,
        }
    }
}

impl<C, const POINT: usize> core::fmt::Debug for CruxEccPublicKey<C, POINT> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CruxEccPublicKey")
            .field("point", &self.point)
            .finish()
    }
}

/// A validated private key of the curve `C` (a secret scalar `d` in
/// `[1, n - 1]` of `COORD` bytes and its public key `[d]G`). The secret scalar
/// is zeroized on drop.
pub struct CruxEccKey<C, const COORD: usize, const POINT: usize> {
    d: [u8; COORD],
    public: CruxEccPublicKey<C, POINT>,
}

impl<C, const COORD: usize, const POINT: usize> Drop for CruxEccKey<C, COORD, POINT> {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}

impl<C, const COORD: usize, const POINT: usize> core::fmt::Debug for CruxEccKey<C, COORD, POINT> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CruxEccKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl<C: CurveOps<COORD, POINT>, const COORD: usize, const POINT: usize>
    CruxEccKey<C, COORD, POINT>
{
    /// The key of the secret scalar `d`: `Ok(None)` if `d` is not in `[1, n - 1]`.
    fn from_scalar(d: &[u8; COORD]) -> Result<Option<Self>, CryptoError> {
        Ok(C::mul_generator(d)?.map(|point| Self {
            d: *d,
            public: CruxEccPublicKey {
                point,
                curve: PhantomData,
            },
        }))
    }
}

/// Splits `point` (`x || y`) into the coordinate outputs.
fn write_point<const COORD: usize, const POINT: usize>(
    point: Option<[u8; POINT]>,
    out_x: &mut [u8; COORD],
    out_y: &mut [u8; COORD],
) -> Option<()> {
    let point = point?;
    out_x.copy_from_slice(&point[..COORD]);
    out_y.copy_from_slice(&point[COORD..]);
    Some(())
}

impl<C: CurveOps<COORD, POINT>, const COORD: usize, const POINT: usize>
    PrivateKey<POINT, COORD, CruxRng> for CruxEccKey<C, COORD, POINT>
{
    type PublicKey = CruxEccPublicKey<C, POINT>;

    fn generate(rng: &mut CruxRng, _: ()) -> Result<Self, CryptoError> {
        let mut d = C::random_scalar(rng)?;
        let key = Self::from_scalar(&d);
        d.zeroize();
        key?.ok_or(CryptoError::Internal)
    }

    fn load(public: Self::PublicKey, private: &[u8; COORD]) -> Result<Option<Self>, CryptoError> {
        let Some(key) = Self::from_scalar(private)? else {
            return Ok(None);
        };
        Ok(CruxCryptoProvider::ct_eq(&key.public.point, &public.point).then_some(key))
    }

    fn store(&self, out: &mut [u8; COORD]) -> Result<(), CryptoError> {
        *out = self.d;
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }

    fn load_public(_: (), public: &[u8; POINT]) -> Result<Option<Self::PublicKey>, CryptoError> {
        Ok(C::validate(public).then_some(CruxEccPublicKey {
            point: *public,
            curve: PhantomData,
        }))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; POINT]) -> Result<(), CryptoError> {
        *out = public.point;
        Ok(())
    }
}

impl<C: CurveOps<COORD, POINT>, const COORD: usize, const POINT: usize>
    EccCurve<COORD, POINT, CruxRng> for CruxEccKey<C, COORD, POINT>
{
    /// The cofactor of the NIST curves is 1, so this is `[d]Q`.
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_x: &mut [u8; COORD],
        out_y: &mut [u8; COORD],
    ) -> Result<Option<()>, CryptoError> {
        Ok(write_point(
            C::mul_point(&peer_public.point, &self.d)?,
            out_x,
            out_y,
        ))
    }

    fn sign(
        &self,
        rng: &mut CruxRng,
        digest: &[u8],
        out_r: &mut [u8; COORD],
        out_s: &mut [u8; COORD],
    ) -> Result<(), CryptoError> {
        let sig = C::ecdsa_sign(&self.d, rng, digest)?;
        write_point(Some(sig), out_r, out_s).ok_or(CryptoError::Internal)
    }

    fn verify(
        public: &Self::PublicKey,
        digest: &[u8],
        sig_r: &[u8; COORD],
        sig_s: &[u8; COORD],
    ) -> Result<bool, CryptoError> {
        let mut sig = [0u8; POINT];
        sig[..COORD].copy_from_slice(sig_r);
        sig[COORD..].copy_from_slice(sig_s);
        Ok(C::ecdsa_verify(&public.point, digest, &sig))
    }

    fn mul_generator(
        k: &[u8; COORD],
        out_x: &mut [u8; COORD],
        out_y: &mut [u8; COORD],
    ) -> Result<Option<()>, CryptoError> {
        Ok(write_point(C::mul_generator(k)?, out_x, out_y))
    }

    fn mul_point(
        point: &Self::PublicKey,
        k: &[u8; COORD],
        out_x: &mut [u8; COORD],
        out_y: &mut [u8; COORD],
    ) -> Result<Option<()>, CryptoError> {
        Ok(write_point(C::mul_point(&point.point, k)?, out_x, out_y))
    }
}

/// NIST P-256 (`libcrux-p256`).
#[derive(Debug)]
pub enum NistP256 {}

impl NistP256 {
    /// Draws a valid scalar (in `[1, n - 1]`) from `rng`.
    fn scalar(rng: &mut CruxRng) -> Result<[u8; 32], CryptoError> {
        let mut k = [0u8; 32];
        // Each attempt succeeds with probability above `1 - 2^-32`.
        for _ in 0..100 {
            rng.fill_bytes(&mut k)?;
            if libcrux_p256::validate_private_key(&k) {
                return Ok(k);
            }
        }
        Err(CryptoError::Internal)
    }
}

impl CurveOps<32, 64> for NistP256 {
    fn validate(point: &[u8; 64]) -> bool {
        libcrux_p256::validate_public_key(point)
    }

    fn random_scalar(rng: &mut CruxRng) -> Result<[u8; 32], CryptoError> {
        Self::scalar(rng)
    }

    fn mul_generator(k: &[u8; 32]) -> Result<Option<[u8; 64]>, CryptoError> {
        let mut point = [0u8; 64];
        Ok(libcrux_p256::dh_initiator(&mut point, k).then_some(point))
    }

    fn mul_point(point: &[u8; 64], k: &[u8; 32]) -> Result<Option<[u8; 64]>, CryptoError> {
        let mut out = [0u8; 64];
        Ok(libcrux_p256::dh_responder(&mut out, point, k).then_some(out))
    }

    fn ecdsa_sign(d: &[u8; 32], rng: &mut CruxRng, digest: &[u8]) -> Result<[u8; 64], CryptoError> {
        let prehash = ecdsa_prehash::<32>(digest);
        let mut nonce = Self::scalar(rng)?;
        let mut sig = [0u8; 64];
        let signed = libcrux_p256::ecdsa_sign_p256_without_hash(&mut sig, 32, &prehash, d, &nonce);
        nonce.zeroize();
        if signed {
            Ok(sig)
        } else {
            Err(CryptoError::Internal)
        }
    }

    fn ecdsa_verify(point: &[u8; 64], digest: &[u8], sig: &[u8; 64]) -> bool {
        let prehash = ecdsa_prehash::<32>(digest);
        libcrux_p256::ecdsa_verif_without_hash(32, &prehash, point, &sig[..32], &sig[32..])
    }
}

/// Implements [`CurveOps`] for a RustCrypto `elliptic-curve` crate.
///
/// ECDSA signatures use deterministic nonces (RFC 6979), so `rng` is not used
/// for them.
macro_rules! rust_crypto_curve {
    ($(#[$doc:meta])* $name:ident, $krate:ident, $coord:literal, $point:literal) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub enum $name {}

        impl $name {
            /// The affine point `x || y` of `public`.
            fn encode(public: &$krate::PublicKey) -> Result<[u8; $point], CryptoError> {
                use $krate::elliptic_curve::sec1::ToEncodedPoint as _;
                let encoded = public.to_encoded_point(false);
                encoded
                    .as_bytes()
                    .get(1..)
                    .and_then(|xy| xy.try_into().ok())
                    .ok_or(CryptoError::Internal)
            }

            /// The validated public key of the point `x || y`.
            fn decode(point: &[u8; $point]) -> Option<$krate::PublicKey> {
                let mut sec1 = [0u8; $point + 1];
                sec1[0] = 0x04;
                sec1[1..].copy_from_slice(point);
                $krate::PublicKey::from_sec1_bytes(&sec1).ok()
            }
        }

        impl CurveOps<$coord, $point> for $name {
            fn validate(point: &[u8; $point]) -> bool {
                Self::decode(point).is_some()
            }

            fn random_scalar(rng: &mut CruxRng) -> Result<[u8; $coord], CryptoError> {
                let secret = $krate::SecretKey::random(rng);
                secret
                    .to_bytes()
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::Internal)
            }

            fn mul_generator(k: &[u8; $coord]) -> Result<Option<[u8; $point]>, CryptoError> {
                let Ok(secret) = $krate::SecretKey::from_slice(k) else {
                    return Ok(None);
                };
                Self::encode(&secret.public_key()).map(Some)
            }

            fn mul_point(
                point: &[u8; $point],
                k: &[u8; $coord],
            ) -> Result<Option<[u8; $point]>, CryptoError> {
                let Some(public) = Self::decode(point) else {
                    return Ok(None);
                };
                let Ok(secret) = $krate::SecretKey::from_slice(k) else {
                    return Ok(None);
                };
                let product = $krate::ProjectivePoint::from(*public.as_affine())
                    * secret.to_nonzero_scalar().as_ref();
                // The product is the point at infinity.
                let Ok(result) = $krate::PublicKey::from_affine(product.to_affine()) else {
                    return Ok(None);
                };
                Self::encode(&result).map(Some)
            }

            fn ecdsa_sign(
                d: &[u8; $coord],
                _rng: &mut CruxRng,
                digest: &[u8],
            ) -> Result<[u8; $point], CryptoError> {
                use $krate::ecdsa::signature::hazmat::PrehashSigner as _;
                let prehash = ecdsa_prehash::<$coord>(digest);
                let signing_key =
                    $krate::ecdsa::SigningKey::from_slice(d).map_err(|_| CryptoError::Internal)?;
                let sig: $krate::ecdsa::Signature = signing_key
                    .sign_prehash(&prehash)
                    .map_err(|_| CryptoError::Internal)?;
                sig.to_bytes()
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::Internal)
            }

            fn ecdsa_verify(point: &[u8; $point], digest: &[u8], sig: &[u8; $point]) -> bool {
                use $krate::ecdsa::signature::hazmat::PrehashVerifier as _;
                let prehash = ecdsa_prehash::<$coord>(digest);
                let mut sec1 = [0u8; $point + 1];
                sec1[0] = 0x04;
                sec1[1..].copy_from_slice(point);
                let Ok(verifying_key) = $krate::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else {
                    return false;
                };
                let Ok(sig) = $krate::ecdsa::Signature::from_slice(sig) else {
                    return false;
                };
                verifying_key.verify_prehash(&prehash, &sig).is_ok()
            }
        }
    };
}

rust_crypto_curve!(
    /// NIST P-384 (RustCrypto `p384`).
    NistP384,
    p384,
    48,
    96
);
rust_crypto_curve!(
    /// NIST P-521 (RustCrypto `p521`).
    NistP521,
    p521,
    66,
    132
);

#[cfg(test)]
mod tests;
