//! Digest signature generation and verification (`TPM2_Sign` and
//! `TPM2_VerifySignature`).

#[cfg(any(feature = "ecdsa", feature = "sm2", feature = "ecschnorr"))]
use super::left_pad_be;
use super::{Crypto, CryptoError, Rng};
#[cfg(feature = "ecc")]
use super::{EccPrivateKey, EccPublicKey};
#[cfg(feature = "rsa")]
use super::{RsaPrivateKey, RsaPublicKey};
#[cfg(any(feature = "ecdsa", feature = "sm2", feature = "ecschnorr"))]
use super::{
    backend::{EccCurve, EccSigScheme},
    match_ecc_curve,
};
#[cfg(any(feature = "rsassa", feature = "rsapss"))]
use super::{
    backend::{RsaKey, RsaSigScheme},
    match_rsa_bits,
};
#[cfg(feature = "rsa")]
use crate::TpmiRsaKeyBits;
#[cfg(any(feature = "ecdsa", feature = "sm2", feature = "ecschnorr"))]
use crate::{Tpm2bEccParameter, TpmsSignatureEcc};
#[cfg(any(feature = "rsassa", feature = "rsapss"))]
use crate::{Tpm2bPublicKeyRsa, TpmsSignatureRsa};
use crate::{TpmiAlgHash, TpmtHa, TpmtSigScheme, TpmtSignature};

/// Maximum byte length of the raw payload of any enabled digest-level
/// [`TpmtSignature`]:
/// - HMAC (`digest`): [`TpmiAlgHash::MAX_DIGEST_BYTES`]
/// - RSA (`sig`): [`TpmiRsaKeyBits::MAX_PUB_KEY_BYTES`]
/// - ECC (`r || s`): `2 * MAX_ECC_COORD_BYTES` (when `ecc` is enabled)
pub const MAX_SIGNATURE_BYTES: usize = max!(
    TpmiAlgHash::MAX_DIGEST_BYTES,
    #[cfg(feature = "rsa")]
    TpmiRsaKeyBits::MAX_PUB_KEY_BYTES,
    #[cfg(feature = "ecc")]
    2 * super::MAX_ECC_COORD_BYTES,
);

/// Scratch buffer large enough to hold the raw payload of any enabled
/// digest-level [`TpmtSignature`].
pub type SignatureBuffer = [u8; MAX_SIGNATURE_BYTES];

/// Borrowed private key handle for [`sign`].
pub enum SigningKey<'a, C: Crypto> {
    /// RSA private key (`RSASSA` or `RSAPSS`).
    #[cfg(feature = "rsa")]
    Rsa(&'a RsaPrivateKey<C>),
    /// Weierstrass ECC private key (`ECDSA`, `SM2`, or `ECSchnorr`).
    #[cfg(feature = "ecc")]
    Ecc(&'a EccPrivateKey<C>),
}

/// Borrowed public key handle for [`verify`].
pub enum VerifyingKey<'a, C: Crypto> {
    /// RSA public key (`RSASSA` or `RSAPSS`).
    #[cfg(feature = "rsa")]
    Rsa(&'a RsaPublicKey<C>),
    /// Weierstrass ECC public key (`ECDSA`, `SM2`, or `ECSchnorr`).
    #[cfg(feature = "ecc")]
    Ecc(&'a EccPublicKey<C>),
}

/// Signs `digest` with `key` and `scheme`, writing the signature payload into
/// `out` and returning a [`TpmtSignature`].
///
/// `HMAC` (use [`hmac`](super::hmac) instead), `ECDAA`, message-level schemes
/// (`EdDSA`, `HashEdDSA`, `ML-DSA`, `HashML-DSA`), and mismatched
/// `(key, scheme)` pairs return `Err(`[`CryptoError::Unsupported`]`)`.
/// Returns `Err(`[`CryptoError::Internal`]`)` if `digest.len()` does not match
/// `scheme`'s hash algorithm.
pub fn sign<'a, C: Crypto>(
    rng: &mut impl Rng,
    key: SigningKey<'_, C>,
    scheme: TpmtSigScheme,
    digest: &[u8],
    out: &'a mut SignatureBuffer,
) -> Result<TpmtSignature<'a>, CryptoError> {
    let _ = (&rng, &out);
    let hash = match scheme {
        #[cfg(feature = "rsassa")]
        TpmtSigScheme::Rsassa(h) => Some(h),
        #[cfg(feature = "rsapss")]
        TpmtSigScheme::Rsapss(h) => Some(h),
        #[cfg(feature = "ecdsa")]
        TpmtSigScheme::Ecdsa(h) => Some(h),
        #[cfg(feature = "sm2")]
        TpmtSigScheme::Sm2(h) => Some(h),
        #[cfg(feature = "ecschnorr")]
        TpmtSigScheme::Ecschnorr(h) => Some(h),
        // `HMAC`, `ECDAA`, and message-level schemes.
        _ => None,
    };
    let Some(hash) = hash else {
        return Err(CryptoError::Unsupported);
    };
    let digest = TpmtHa::new(hash, digest).ok_or(CryptoError::Internal)?;

    match (key, scheme) {
        #[cfg(feature = "rsassa")]
        (SigningKey::Rsa(k), TpmtSigScheme::Rsassa(_)) => {
            let sig = rsa_sign::<C>(rng, k, RsaSigScheme::Rsassa, digest, out)?;
            Ok(TpmtSignature::Rsassa(TpmsSignatureRsa { hash, sig }))
        }
        #[cfg(feature = "rsapss")]
        (SigningKey::Rsa(k), TpmtSigScheme::Rsapss(_)) => {
            let sig = rsa_sign::<C>(rng, k, RsaSigScheme::Rsapss, digest, out)?;
            Ok(TpmtSignature::Rsapss(TpmsSignatureRsa { hash, sig }))
        }
        #[cfg(feature = "ecdsa")]
        (SigningKey::Ecc(k), TpmtSigScheme::Ecdsa(_)) => {
            let (signature_r, signature_s) =
                ecc_sign::<C>(rng, k, EccSigScheme::Ecdsa, digest, out)?;
            Ok(TpmtSignature::Ecdsa(TpmsSignatureEcc {
                hash,
                signature_r,
                signature_s,
            }))
        }
        #[cfg(feature = "sm2")]
        (SigningKey::Ecc(k), TpmtSigScheme::Sm2(_)) => {
            let (signature_r, signature_s) = ecc_sign::<C>(rng, k, EccSigScheme::Sm2, digest, out)?;
            Ok(TpmtSignature::Sm2(TpmsSignatureEcc {
                hash,
                signature_r,
                signature_s,
            }))
        }
        #[cfg(feature = "ecschnorr")]
        (SigningKey::Ecc(k), TpmtSigScheme::Ecschnorr(_)) => {
            let (signature_r, signature_s) =
                ecc_sign::<C>(rng, k, EccSigScheme::Ecschnorr, digest, out)?;
            Ok(TpmtSignature::Ecschnorr(TpmsSignatureEcc {
                hash,
                signature_r,
                signature_s,
            }))
        }
        _ => {
            let _ = digest;
            Err(CryptoError::Unsupported)
        }
    }
}

/// Verifies `signature` over `digest` using `key`.
///
/// Returns `Ok(true)` if `signature` is valid, `Ok(false)` if `digest.len()`
/// does not match `signature`'s hash algorithm or cryptographic verification
/// fails, and `Err(`[`CryptoError::Unsupported`]`)` for unsupported schemes
/// (including `HMAC`, `TPM_ALG_ECDAA`, which TPM 2.0 `TPM2_VerifySignature`
/// does not support, and message-level schemes `EdDSA` / `ML-DSA`).
pub fn verify<C: Crypto>(
    key: VerifyingKey<'_, C>,
    digest: &[u8],
    signature: TpmtSignature<'_>,
) -> Result<bool, CryptoError> {
    let hash = match signature {
        #[cfg(feature = "rsassa")]
        TpmtSignature::Rsassa(s) => Some(s.hash),
        #[cfg(feature = "rsapss")]
        TpmtSignature::Rsapss(s) => Some(s.hash),
        #[cfg(feature = "ecdsa")]
        TpmtSignature::Ecdsa(s) => Some(s.hash),
        #[cfg(feature = "sm2")]
        TpmtSignature::Sm2(s) => Some(s.hash),
        #[cfg(feature = "ecschnorr")]
        TpmtSignature::Ecschnorr(s) => Some(s.hash),
        // `HMAC`, `ECDAA`, and message-level schemes.
        _ => None,
    };
    let Some(hash) = hash else {
        return Err(CryptoError::Unsupported);
    };
    let Some(digest) = TpmtHa::new(hash, digest) else {
        return Ok(false);
    };

    match (key, signature) {
        #[cfg(feature = "rsassa")]
        (VerifyingKey::Rsa(k), TpmtSignature::Rsassa(s)) => {
            rsa_verify::<C>(k, RsaSigScheme::Rsassa, digest, s.sig.as_slice())
        }
        #[cfg(feature = "rsapss")]
        (VerifyingKey::Rsa(k), TpmtSignature::Rsapss(s)) => {
            rsa_verify::<C>(k, RsaSigScheme::Rsapss, digest, s.sig.as_slice())
        }
        #[cfg(feature = "ecdsa")]
        (VerifyingKey::Ecc(k), TpmtSignature::Ecdsa(s)) => ecc_verify::<C>(
            k,
            EccSigScheme::Ecdsa,
            digest,
            s.signature_r.as_slice(),
            s.signature_s.as_slice(),
        ),
        #[cfg(feature = "sm2")]
        (VerifyingKey::Ecc(k), TpmtSignature::Sm2(s)) => ecc_verify::<C>(
            k,
            EccSigScheme::Sm2,
            digest,
            s.signature_r.as_slice(),
            s.signature_s.as_slice(),
        ),
        #[cfg(feature = "ecschnorr")]
        (VerifyingKey::Ecc(k), TpmtSignature::Ecschnorr(s)) => ecc_verify::<C>(
            k,
            EccSigScheme::Ecschnorr,
            digest,
            s.signature_r.as_slice(),
            s.signature_s.as_slice(),
        ),
        _ => {
            let _ = digest;
            Err(CryptoError::Unsupported)
        }
    }
}

#[cfg(any(feature = "rsassa", feature = "rsapss"))]
fn rsa_sign<'a, C: Crypto>(
    rng: &mut impl Rng,
    key: &RsaPrivateKey<C>,
    scheme: RsaSigScheme,
    digest: TpmtHa<'_>,
    out: &'a mut SignatureBuffer,
) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
    match_rsa_bits!(match key {
        RsaPrivateKey::$Alg(k) => {
            let Some(buf) = out.first_chunk_mut() else {
                return Err(CryptoError::Internal);
            };
            C::$Alg::sign(rng, k, scheme, digest, buf)?;
            Tpm2bPublicKeyRsa::new(buf).ok_or(CryptoError::Internal)
        },
    })
}

#[cfg(any(feature = "rsassa", feature = "rsapss"))]
fn rsa_verify<C: Crypto>(
    key: &RsaPublicKey<C>,
    scheme: RsaSigScheme,
    digest: TpmtHa<'_>,
    sig: &[u8],
) -> Result<bool, CryptoError> {
    match_rsa_bits!(match key {
        RsaPublicKey::$Alg(k) => {
            let Ok(sig) = sig.try_into() else {
                return Ok(false);
            };
            C::$Alg::verify(k, scheme, digest, sig)
        },
    })
}

#[cfg(any(feature = "ecdsa", feature = "sm2", feature = "ecschnorr"))]
fn ecc_sign<'a, C: Crypto>(
    rng: &mut impl Rng,
    key: &EccPrivateKey<C>,
    scheme: EccSigScheme,
    digest: TpmtHa<'_>,
    out: &'a mut SignatureBuffer,
) -> Result<(Tpm2bEccParameter<'a>, Tpm2bEccParameter<'a>), CryptoError> {
    match_ecc_curve!(match key {
        EccPrivateKey::$Alg(k) => {
            let Some((out_r, rest)) = out.split_first_chunk_mut() else {
                return Err(CryptoError::Internal);
            };
            let Some(out_s) = rest.first_chunk_mut() else {
                return Err(CryptoError::Internal);
            };
            C::$Alg::sign::<C>(rng, k, scheme, digest, out_r, out_s)?;
            Ok((
                Tpm2bEccParameter::new(out_r).ok_or(CryptoError::Internal)?,
                Tpm2bEccParameter::new(out_s).ok_or(CryptoError::Internal)?,
            ))
        },
    })
}

#[cfg(any(feature = "ecdsa", feature = "sm2", feature = "ecschnorr"))]
fn ecc_verify<C: Crypto>(
    key: &EccPublicKey<C>,
    scheme: EccSigScheme,
    digest: TpmtHa<'_>,
    sig_r: &[u8],
    sig_s: &[u8],
) -> Result<bool, CryptoError> {
    match_ecc_curve!(match key {
        EccPublicKey::$Alg(k) => {
            let (Some(r), Some(s)) = (left_pad_be(sig_r), left_pad_be(sig_s)) else {
                return Ok(false);
            };
            C::$Alg::verify::<C>(k, scheme, digest, &r, &s)
        },
    })
}
