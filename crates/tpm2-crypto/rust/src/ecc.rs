//! Elliptic-curve cryptography: NIST P-256, P-384 and P-521 (`p256`, `p384`, `p521`), and the
//! curves of `tpm2-crypto-weierstrass` (NIST P-192, NIST P-224, BN P-256, BN P-638 and SM2 P-256).

use crate::{RngAdapter, RustCryptoProvider};
use tpm2::crypto::backend::Ecc;

/// Copies `digest` into `buf` as the ECDSA hash value of a curve with `field_len`-byte scalars:
/// a shorter digest is left-padded with zeros (the same integer), a longer one truncated to its
/// leftmost `field_len` bytes (FIPS 186-5 `bits2int`, as `bits(n) == 8 * field_len` for these
/// curves whenever a digest is longer). Returns the prehash `&buf[..field_len]`.
fn prepare_prehash<'a>(digest: &[u8], field_len: usize, buf: &'a mut [u8; 66]) -> &'a [u8] {
    let buf = &mut buf[..field_len];
    if digest.len() >= field_len {
        buf.copy_from_slice(&digest[..field_len]);
    } else {
        let offset = field_len - digest.len();
        buf[..offset].fill(0);
        buf[offset..].copy_from_slice(digest);
    }
    buf
}

/// Defines the key type of a NIST curve of the RustCrypto `elliptic-curve` family and implements
/// the [`EccCurve`](tpm2::crypto::backend::EccCurve) and
/// [`PrivateKey`](tpm2::crypto::backend::PrivateKey) traits for it, for any random number
/// generator.
macro_rules! nist_curve {
    ($(#[$m:meta])* $name:ident, $krate:ident, $coord:literal, $point:literal) => {
        $(#[$m])*
        ///
        /// The public key type is the validated `PublicKey` of the curve's crate (a point other
        /// than the point at infinity).
        #[derive(Clone)]
        pub struct $name {
            secret: $krate::SecretKey,
            public: $krate::PublicKey,
        }

        impl $name {
            /// Writes the affine coordinates of `public` into `out_x` and `out_y`.
            fn write_point(
                public: &$krate::PublicKey,
                out_x: &mut [u8; $coord],
                out_y: &mut [u8; $coord],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                use $krate::elliptic_curve::sec1::ToEncodedPoint as _;
                let encoded = public.to_encoded_point(false);
                let (Some(x), Some(y)) = (encoded.x(), encoded.y()) else {
                    return Err(tpm2::crypto::CryptoError::Internal);
                };
                out_x.copy_from_slice(x);
                out_y.copy_from_slice(y);
                Ok(())
            }

            /// Decodes the scalar `k`: `None` unless it is in `[1, n - 1]`.
            fn scalar(k: &[u8; $coord]) -> Option<$krate::SecretKey> {
                $krate::SecretKey::from_bytes($krate::FieldBytes::from_slice(k)).ok()
            }

            /// Decodes the signature `(r, s)`: `None` unless both are in `[1, n - 1]`.
            fn signature(r: &[u8; $coord], s: &[u8; $coord]) -> Option<$krate::ecdsa::Signature> {
                $krate::ecdsa::Signature::from_scalars(
                    *$krate::FieldBytes::from_slice(r),
                    *$krate::FieldBytes::from_slice(s),
                )
                .ok()
            }
        }

        impl<R: tpm2::crypto::Rng> tpm2::crypto::backend::PrivateKey<$point, $coord, R> for $name {
            type PublicKey = $krate::PublicKey;

            fn generate(rng: &mut R, _: ()) -> Result<Self, tpm2::crypto::CryptoError> {
                let mut rng = RngAdapter::new(rng);
                let secret = $krate::SecretKey::random(&mut rng);
                let public = secret.public_key();
                rng.finish(Self { secret, public })
            }

            fn load(
                public: Self::PublicKey,
                private: &[u8; $coord],
            ) -> Result<Option<Self>, tpm2::crypto::CryptoError> {
                Ok(Self::scalar(private)
                    .filter(|secret| secret.public_key() == public)
                    .map(|secret| Self { secret, public }))
            }

            fn store(&self, out: &mut [u8; $coord]) -> Result<(), tpm2::crypto::CryptoError> {
                out.copy_from_slice(&self.secret.to_bytes());
                Ok(())
            }

            fn as_public(&self) -> &Self::PublicKey {
                &self.public
            }

            fn load_public(
                _: (),
                public: &[u8; $point],
            ) -> Result<Option<Self::PublicKey>, tpm2::crypto::CryptoError> {
                let mut sec1 = [0x04; 1 + $point];
                sec1[1..].copy_from_slice(public);
                Ok($krate::PublicKey::from_sec1_bytes(&sec1).ok())
            }

            fn store_public(
                public: &Self::PublicKey,
                out: &mut [u8; $point],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                let (x, y) = out.split_at_mut($coord);
                Self::write_point(
                    public,
                    x.try_into().map_err(|_| tpm2::crypto::CryptoError::Internal)?,
                    y.try_into().map_err(|_| tpm2::crypto::CryptoError::Internal)?,
                )
            }
        }

        impl<R: tpm2::crypto::Rng> tpm2::crypto::backend::EccCurve<$coord, $point, R> for $name {
            /// The cofactor of the NIST curves is 1, so this is `[d]Q`.
            fn ecdh(
                &self,
                peer_public: &Self::PublicKey,
                out_x: &mut [u8; $coord],
                out_y: &mut [u8; $coord],
            ) -> Result<Option<()>, tpm2::crypto::CryptoError> {
                let product = peer_public.to_projective() * *self.secret.to_nonzero_scalar();
                let Ok(z) = $krate::PublicKey::from_affine(product.to_affine()) else {
                    return Ok(None);
                };
                Self::write_point(&z, out_x, out_y).map(Some)
            }

            /// ECDSA with the per-message secret of RFC 6979, with additional randomness from
            /// `rng` (`RandomizedPrehashSigner`).
            fn sign(
                &self,
                rng: &mut R,
                digest: &[u8],
                out_r: &mut [u8; $coord],
                out_s: &mut [u8; $coord],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                use $krate::ecdsa::signature::hazmat::RandomizedPrehashSigner as _;
                let signing_key = $krate::ecdsa::SigningKey::from_bytes(&self.secret.to_bytes())
                    .map_err(|_| tpm2::crypto::CryptoError::Internal)?;
                let mut buf = [0u8; 66];
                let prehash = prepare_prehash(digest, $coord, &mut buf);
                let mut rng = RngAdapter::new(rng);
                let signature: $krate::ecdsa::Signature = signing_key
                    .sign_prehash_with_rng(&mut rng, prehash)
                    .map_err(|_| tpm2::crypto::CryptoError::Internal)?;
                let signature = rng.finish(signature)?;
                let (r, s) = signature.split_bytes();
                out_r.copy_from_slice(&r);
                out_s.copy_from_slice(&s);
                Ok(())
            }

            fn verify(
                public: &Self::PublicKey,
                digest: &[u8],
                sig_r: &[u8; $coord],
                sig_s: &[u8; $coord],
            ) -> Result<bool, tpm2::crypto::CryptoError> {
                use $krate::ecdsa::signature::hazmat::PrehashVerifier as _;
                let Some(signature) = Self::signature(sig_r, sig_s) else {
                    return Ok(false);
                };
                let verifying_key = $krate::ecdsa::VerifyingKey::from_affine(*public.as_affine())
                    .map_err(|_| tpm2::crypto::CryptoError::Internal)?;
                let mut buf = [0u8; 66];
                let prehash = prepare_prehash(digest, $coord, &mut buf);
                Ok(verifying_key.verify_prehash(prehash, &signature).is_ok())
            }

            fn mul_generator(
                k: &[u8; $coord],
                out_x: &mut [u8; $coord],
                out_y: &mut [u8; $coord],
            ) -> Result<Option<()>, tpm2::crypto::CryptoError> {
                let Some(k) = Self::scalar(k) else {
                    return Ok(None);
                };
                Self::write_point(&k.public_key(), out_x, out_y).map(Some)
            }

            fn mul_point(
                point: &Self::PublicKey,
                k: &[u8; $coord],
                out_x: &mut [u8; $coord],
                out_y: &mut [u8; $coord],
            ) -> Result<Option<()>, tpm2::crypto::CryptoError> {
                let Some(k) = Self::scalar(k) else {
                    return Ok(None);
                };
                let product = point.to_projective() * *k.to_nonzero_scalar();
                let Ok(result) = $krate::PublicKey::from_affine(product.to_affine()) else {
                    return Ok(None);
                };
                Self::write_point(&result, out_x, out_y).map(Some)
            }
        }
    };
}

nist_curve!(
    /// NIST P-256 keys for `RustCryptoProvider` (`p256`).
    RustCryptoEccNistP256,
    p256,
    32,
    64
);
nist_curve!(
    /// NIST P-384 keys for `RustCryptoProvider` (`p384`).
    RustCryptoEccNistP384,
    p384,
    48,
    96
);
nist_curve!(
    /// NIST P-521 keys for `RustCryptoProvider` (`p521`).
    RustCryptoEccNistP521,
    p521,
    66,
    132
);

/// NIST P-256/384/521 with the RustCrypto curve crates; NIST P-192, NIST P-224, BN P-256,
/// BN P-638 and SM2 P-256 with the generic constant-time short-Weierstrass arithmetic of
/// `tpm2-crypto-weierstrass` (which also implements `SM2` signatures on them).
///
/// The Brainpool curves, Curve25519 and Curve448 are not supported (`!`).
impl Ecc for RustCryptoProvider {
    type NistP192 = tpm2_crypto_weierstrass::NistP192;
    type NistP224 = tpm2_crypto_weierstrass::NistP224;
    type NistP256 = RustCryptoEccNistP256;
    type NistP384 = RustCryptoEccNistP384;
    type NistP521 = RustCryptoEccNistP521;
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
