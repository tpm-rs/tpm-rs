//! Digest and message signature generation and verification (`TPM2_Sign`,
//! `TPM2_SignDigest`, `TPM2_SignSequenceComplete`, `TPM2_VerifySignature`,
//! `TPM2_VerifyDigestSignature`, and `TPM2_VerifySequenceComplete`).

#[cfg(feature = "eddsa")]
use super::backend::EdwardsCurve;
#[cfg(any(feature = "ecdsa", feature = "sm2", feature = "ecschnorr"))]
use super::left_pad_be;
use super::{Crypto, CryptoError, Rng};
#[cfg(feature = "ecc")]
use super::{EccPrivateKey, EccPublicKey};
#[cfg(feature = "mldsa")]
use super::{MldsaPrivateKey, MldsaPublicKey, backend::MldsaKey, match_mldsa_parms};
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
#[cfg(feature = "eddsa")]
use crate::Tpm2bSignatureEddsa;
#[cfg(feature = "rsa")]
use crate::TpmiRsaKeyBits;
#[cfg(feature = "hash_mldsa")]
use crate::TpmsSignatureHashMldsa;
#[cfg(any(feature = "ecdsa", feature = "sm2", feature = "ecschnorr"))]
use crate::{Tpm2bEccParameter, TpmsSignatureEcc};
#[cfg(any(feature = "rsassa", feature = "rsapss"))]
use crate::{Tpm2bPublicKeyRsa, TpmsSignatureRsa};
#[cfg(feature = "mldsa")]
use crate::{Tpm2bSignatureMldsa, TpmiMldsaParms};
use crate::{TpmiAlgHash, TpmtHa, TpmtSigScheme, TpmtSignature};

/// Maximum byte length of the raw payload of any enabled [`TpmtSignature`]:
/// - HMAC (`digest`): [`TpmiAlgHash::MAX_DIGEST_BYTES`]
/// - RSA (`sig`): [`TpmiRsaKeyBits::MAX_PUB_KEY_BYTES`]
/// - ECC / EdDSA (`r || s`): `2 * MAX_ECC_COORD_BYTES` (when `ecc` is enabled)
/// - ML-DSA / HashML-DSA (`sig`): [`TpmiMldsaParms::MAX_SIG_BYTES`] (when
///   `mldsa` is enabled)
pub const MAX_SIGNATURE_BYTES: usize = max!(
    TpmiAlgHash::MAX_DIGEST_BYTES,
    #[cfg(feature = "rsa")]
    TpmiRsaKeyBits::MAX_PUB_KEY_BYTES,
    #[cfg(feature = "ecc")]
    2 * super::MAX_ECC_COORD_BYTES,
    #[cfg(feature = "mldsa")]
    TpmiMldsaParms::MAX_SIG_BYTES,
);

/// Scratch buffer large enough to hold the raw payload of any enabled
/// [`TpmtSignature`].
pub type SignatureBuffer = [u8; MAX_SIGNATURE_BYTES];

/// Borrowed private key handle for [`sign`] and [`sign_message`].
pub enum SigningKey<'a, C: Crypto> {
    /// RSA private key (`RSASSA` or `RSAPSS`).
    #[cfg(feature = "rsa")]
    Rsa(&'a RsaPrivateKey<C>),
    /// ECC private key (Weierstrass for `ECDSA`/`SM2`/`ECSchnorr`, or twisted
    /// Edwards for `EdDSA`/`HashEdDSA`).
    #[cfg(feature = "ecc")]
    Ecc(&'a EccPrivateKey<C>),
    /// ML-DSA private key paired with the context string (`ML-DSA` pure message
    /// signing with `0..=255`-byte `context`, or 64-byte external `µ` digest
    /// signing with empty `context`).
    #[cfg(feature = "mldsa")]
    Mldsa {
        key: &'a MldsaPrivateKey<C>,
        context: &'a [u8],
    },
    /// ML-DSA private key paired with the prehash digest algorithm and
    /// `0..=255`-byte context string (`HashML-DSA`).
    #[cfg(feature = "hash_mldsa")]
    HashMldsa {
        key: &'a MldsaPrivateKey<C>,
        hash: TpmiAlgHash,
        context: &'a [u8],
    },
}

/// Borrowed public key handle for [`verify`] and [`verify_message`].
pub enum VerifyingKey<'a, C: Crypto> {
    /// RSA public key (`RSASSA` or `RSAPSS`).
    #[cfg(feature = "rsa")]
    Rsa(&'a RsaPublicKey<C>),
    /// ECC public key (Weierstrass for `ECDSA`/`SM2`/`ECSchnorr`, or twisted
    /// Edwards for `EdDSA`/`HashEdDSA`).
    #[cfg(feature = "ecc")]
    Ecc(&'a EccPublicKey<C>),
    /// ML-DSA public key paired with the context string (`ML-DSA` pure message
    /// or `HashML-DSA` prehash verification with `0..=255`-byte `context`, or
    /// 64-byte external `µ` verification with empty `context`).
    #[cfg(feature = "mldsa")]
    Mldsa {
        key: &'a MldsaPublicKey<C>,
        context: &'a [u8],
    },
}

/// Signs `digest` with `key` and `scheme` (`TPM2_Sign` / `TPM2_SignDigest`),
/// writing the signature payload into `out` and returning a [`TpmtSignature`].
///
/// Supported digest-level schemes:
/// - `RSASSA`, `RSAPSS`, `ECDSA`, `SM2`, `ECSchnorr`: `digest` must match the
///   hash algorithm in `scheme`.
/// - `HashEdDSA` ([`TpmtSigScheme::HashEddsa`] with [`SigningKey::Ecc`] on
///   `Ed25519` or `Ed448`): `digest` must be the 64-byte prehash (`SHA-512` for
///   Ed25519ph, `SHAKE256-512` for Ed448ph).
/// - `ML-DSA` ([`TpmtSigScheme::Mldsa`] with [`SigningKey::Mldsa`]): `digest`
///   must be the 64-byte external `µ` ([`TpmiMldsaParms::MU_BYTES`]) and
///   `context` must be empty.
/// - `HashML-DSA` ([`TpmtSigScheme::HashMldsa`] with
///   [`SigningKey::HashMldsa`]): `digest` must match `hash` and
///   `context.len() <= 255` ([`TpmtSignature::MAX_CTX_BYTES`]).
///
/// `HMAC` (use [`hmac`](super::hmac) instead), `ECDAA`, pure `EdDSA`
/// ([`TpmtSigScheme::Eddsa`], which is message-only; see [`sign_message`]), and
/// mismatched `(key, scheme)` pairs return
/// `Err(`[`CryptoError::Unsupported`]`)`. Returns
/// `Err(`[`CryptoError::Internal`]`)` if `digest.len()` or `context.len()` does
/// not match the scheme's requirements.
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
        #[cfg(feature = "hash_eddsa")]
        TpmtSigScheme::HashEddsa => {
            #[allow(irrefutable_let_patterns)]
            let SigningKey::Ecc(k) = key else {
                return Err(CryptoError::Unsupported);
            };
            let Ok(prehash) = digest.try_into() else {
                return Err(CryptoError::Internal);
            };
            let sig = eddsa_sign_prehash::<C>(k, prehash, out)?;
            return Ok(TpmtSignature::HashEddsa(sig));
        }
        #[cfg(feature = "mldsa")]
        TpmtSigScheme::Mldsa => {
            #[allow(irrefutable_let_patterns)]
            let SigningKey::Mldsa { key: k, context } = key else {
                return Err(CryptoError::Unsupported);
            };
            if !context.is_empty() {
                return Err(CryptoError::Internal);
            }
            let Ok(mu) = digest.try_into() else {
                return Err(CryptoError::Internal);
            };
            let sig = mldsa_sign_mu::<C>(rng, k, mu, out)?;
            return Ok(TpmtSignature::Mldsa(sig));
        }
        #[cfg(feature = "hash_mldsa")]
        TpmtSigScheme::HashMldsa => {
            let SigningKey::HashMldsa {
                key: k,
                hash,
                context,
            } = key
            else {
                return Err(CryptoError::Unsupported);
            };
            if context.len() > TpmtSignature::MAX_CTX_BYTES {
                return Err(CryptoError::Internal);
            }
            let digest = TpmtHa::new(hash, digest).ok_or(CryptoError::Internal)?;
            let signature = mldsa_sign_prehash::<C>(rng, k, context, digest, out)?;
            return Ok(TpmtSignature::HashMldsa(TpmsSignatureHashMldsa {
                hash,
                signature,
            }));
        }
        // `HMAC`, `ECDAA`, and pure `EdDSA`.
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

/// Verifies `signature` over `digest` using `key` (`TPM2_VerifySignature` /
/// `TPM2_VerifyDigestSignature`).
///
/// Returns `Ok(true)` if `signature` is valid, `Ok(false)` if `digest.len()`,
/// `context.len()` (must be empty for external-`µ` `ML-DSA` and `<= 255` for
/// `HashML-DSA`), or signature component sizes do not match the scheme or
/// cryptographic verification fails, and `Err(`[`CryptoError::Unsupported`]`)`
/// for unsupported schemes (including `HMAC`, `TPM_ALG_ECDAA`, which TPM 2.0
/// `TPM2_VerifySignature` does not support, and pure `EdDSA`, which is
/// message-only; see [`verify_message`]).
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
        #[cfg(feature = "hash_eddsa")]
        TpmtSignature::HashEddsa(sig) => {
            #[allow(irrefutable_let_patterns)]
            let VerifyingKey::Ecc(k) = key else {
                return Err(CryptoError::Unsupported);
            };
            let Ok(prehash) = digest.try_into() else {
                return Ok(false);
            };
            return eddsa_verify_prehash::<C>(k, prehash, sig.as_slice());
        }
        #[cfg(feature = "mldsa")]
        TpmtSignature::Mldsa(sig) => {
            #[allow(irrefutable_let_patterns)]
            let VerifyingKey::Mldsa { key: k, context } = key else {
                return Err(CryptoError::Unsupported);
            };
            if !context.is_empty() {
                return Ok(false);
            }
            let Ok(mu) = digest.try_into() else {
                return Ok(false);
            };
            return mldsa_verify_mu::<C>(k, mu, sig.as_slice());
        }
        #[cfg(feature = "hash_mldsa")]
        TpmtSignature::HashMldsa(s) => {
            #[allow(irrefutable_let_patterns)]
            let VerifyingKey::Mldsa { key: k, context } = key else {
                return Err(CryptoError::Unsupported);
            };
            if context.len() > TpmtSignature::MAX_CTX_BYTES {
                return Ok(false);
            }
            let Some(digest) = TpmtHa::new(s.hash, digest) else {
                return Ok(false);
            };
            return mldsa_verify_prehash::<C>(k, context, digest, s.signature.as_slice());
        }
        // `HMAC`, `ECDAA`, and pure `EdDSA`.
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

/// Signs the concatenation of message slices `msg` with `key` and `scheme`
/// (`TPM2_SignSequenceComplete`), writing the signature payload into `out` and
/// returning a [`TpmtSignature`].
///
/// Only pure message-level schemes are supported here:
/// - `EdDSA` ([`TpmtSigScheme::Eddsa`] with [`SigningKey::Ecc`] on `Ed25519` or
///   `Ed448`)
/// - `ML-DSA` ([`TpmtSigScheme::Mldsa`] with [`SigningKey::Mldsa`], where
///   `context.len() <= 255` / [`TpmtSignature::MAX_CTX_BYTES`])
///
/// Digest and prehash schemes (`HashEdDSA`, `HashML-DSA`, `ECDSA`, `RSASSA`,
/// etc.) must use [`sign`] and return `Err(`[`CryptoError::Unsupported`]`)`
/// here. Returns `Err(`[`CryptoError::Internal`]`)` if `context.len() > 255`.
pub fn sign_message<'a, C: Crypto>(
    rng: &mut impl Rng,
    key: SigningKey<'_, C>,
    scheme: TpmtSigScheme,
    msg: &[&[u8]],
    out: &'a mut SignatureBuffer,
) -> Result<TpmtSignature<'a>, CryptoError> {
    let _ = (&rng, msg, &out);
    match (key, scheme) {
        #[cfg(feature = "eddsa")]
        (SigningKey::Ecc(k), TpmtSigScheme::Eddsa) => {
            let sig = eddsa_sign_message::<C>(k, msg, out)?;
            Ok(TpmtSignature::Eddsa(sig))
        }
        #[cfg(feature = "mldsa")]
        (SigningKey::Mldsa { key: k, context }, TpmtSigScheme::Mldsa) => {
            if context.len() > TpmtSignature::MAX_CTX_BYTES {
                return Err(CryptoError::Internal);
            }
            let sig = mldsa_sign_message::<C>(rng, k, context, msg, out)?;
            Ok(TpmtSignature::Mldsa(sig))
        }
        _ => Err(CryptoError::Unsupported),
    }
}

/// Verifies `signature` over the concatenation of message slices `msg` using
/// `key` (`TPM2_VerifySequenceComplete`).
///
/// Only pure message-level schemes (`EdDSA` and `ML-DSA`) are supported here;
/// digest and prehash schemes return `Err(`[`CryptoError::Unsupported`]`)`.
/// Returns `Ok(false)` if `context.len() > 255`
/// ([`TpmtSignature::MAX_CTX_BYTES`]), the signature size does not match the
/// key, or cryptographic verification fails.
pub fn verify_message<C: Crypto>(
    key: VerifyingKey<'_, C>,
    msg: &[&[u8]],
    signature: TpmtSignature<'_>,
) -> Result<bool, CryptoError> {
    let _ = msg;
    match (key, signature) {
        #[cfg(feature = "eddsa")]
        (VerifyingKey::Ecc(k), TpmtSignature::Eddsa(sig)) => {
            eddsa_verify_message::<C>(k, msg, sig.as_slice())
        }
        #[cfg(feature = "mldsa")]
        (VerifyingKey::Mldsa { key: k, context }, TpmtSignature::Mldsa(sig)) => {
            if context.len() > TpmtSignature::MAX_CTX_BYTES {
                return Ok(false);
            }
            mldsa_verify_message::<C>(k, context, msg, sig.as_slice())
        }
        _ => Err(CryptoError::Unsupported),
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
        #[allow(unreachable_patterns)]
        _ => Err(CryptoError::Unsupported),
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
        #[allow(unreachable_patterns)]
        _ => Err(CryptoError::Unsupported),
    })
}

#[cfg(feature = "eddsa")]
fn eddsa_sign_message<'a, C: Crypto>(
    key: &EccPrivateKey<C>,
    msg: &[&[u8]],
    out: &'a mut SignatureBuffer,
) -> Result<Tpm2bSignatureEddsa<'a>, CryptoError> {
    match key {
        #[cfg(feature = "curve25519")]
        EccPrivateKey::Ed25519(k) => {
            let Some(buf) = out.first_chunk_mut::<64>() else {
                return Err(CryptoError::Internal);
            };
            let (out_r, out_s) = buf.split_first_chunk_mut::<32>().unwrap();
            let out_s: &mut [u8; 32] = out_s.try_into().unwrap();
            C::Ed25519::sign_message(k, msg, out_r, out_s)?;
            Tpm2bSignatureEddsa::new(buf).ok_or(CryptoError::Internal)
        }
        #[cfg(feature = "curve448")]
        EccPrivateKey::Ed448(k) => {
            let Some(buf) = out.first_chunk_mut::<114>() else {
                return Err(CryptoError::Internal);
            };
            let (out_r, out_s) = buf.split_first_chunk_mut::<57>().unwrap();
            let out_s: &mut [u8; 57] = out_s.try_into().unwrap();
            C::Ed448::sign_message(k, msg, out_r, out_s)?;
            Tpm2bSignatureEddsa::new(buf).ok_or(CryptoError::Internal)
        }
        _ => Err(CryptoError::Unsupported),
    }
}

#[cfg(feature = "hash_eddsa")]
fn eddsa_sign_prehash<'a, C: Crypto>(
    key: &EccPrivateKey<C>,
    prehash: &[u8; 64],
    out: &'a mut SignatureBuffer,
) -> Result<Tpm2bSignatureEddsa<'a>, CryptoError> {
    match key {
        #[cfg(feature = "curve25519")]
        EccPrivateKey::Ed25519(k) => {
            let Some(buf) = out.first_chunk_mut::<64>() else {
                return Err(CryptoError::Internal);
            };
            let (out_r, out_s) = buf.split_first_chunk_mut::<32>().unwrap();
            let out_s: &mut [u8; 32] = out_s.try_into().unwrap();
            C::Ed25519::sign_prehash(k, prehash, out_r, out_s)?;
            Tpm2bSignatureEddsa::new(buf).ok_or(CryptoError::Internal)
        }
        #[cfg(feature = "curve448")]
        EccPrivateKey::Ed448(k) => {
            let Some(buf) = out.first_chunk_mut::<114>() else {
                return Err(CryptoError::Internal);
            };
            let (out_r, out_s) = buf.split_first_chunk_mut::<57>().unwrap();
            let out_s: &mut [u8; 57] = out_s.try_into().unwrap();
            C::Ed448::sign_prehash(k, prehash, out_r, out_s)?;
            Tpm2bSignatureEddsa::new(buf).ok_or(CryptoError::Internal)
        }
        _ => Err(CryptoError::Unsupported),
    }
}

#[cfg(feature = "eddsa")]
fn eddsa_verify_message<C: Crypto>(
    key: &EccPublicKey<C>,
    msg: &[&[u8]],
    sig: &[u8],
) -> Result<bool, CryptoError> {
    match key {
        #[cfg(feature = "curve25519")]
        EccPublicKey::Ed25519(k) => {
            let Ok(buf): Result<&[u8; 64], _> = sig.try_into() else {
                return Ok(false);
            };
            let (sig_r, sig_s) = buf.split_first_chunk::<32>().unwrap();
            let sig_s: &[u8; 32] = sig_s.try_into().unwrap();
            C::Ed25519::verify_message(k, msg, sig_r, sig_s)
        }
        #[cfg(feature = "curve448")]
        EccPublicKey::Ed448(k) => {
            let Ok(buf): Result<&[u8; 114], _> = sig.try_into() else {
                return Ok(false);
            };
            let (sig_r, sig_s) = buf.split_first_chunk::<57>().unwrap();
            let sig_s: &[u8; 57] = sig_s.try_into().unwrap();
            C::Ed448::verify_message(k, msg, sig_r, sig_s)
        }
        _ => Err(CryptoError::Unsupported),
    }
}

#[cfg(feature = "hash_eddsa")]
fn eddsa_verify_prehash<C: Crypto>(
    key: &EccPublicKey<C>,
    prehash: &[u8; 64],
    sig: &[u8],
) -> Result<bool, CryptoError> {
    match key {
        #[cfg(feature = "curve25519")]
        EccPublicKey::Ed25519(k) => {
            let Ok(buf): Result<&[u8; 64], _> = sig.try_into() else {
                return Ok(false);
            };
            let (sig_r, sig_s) = buf.split_first_chunk::<32>().unwrap();
            let sig_s: &[u8; 32] = sig_s.try_into().unwrap();
            C::Ed25519::verify_prehash(k, prehash, sig_r, sig_s)
        }
        #[cfg(feature = "curve448")]
        EccPublicKey::Ed448(k) => {
            let Ok(buf): Result<&[u8; 114], _> = sig.try_into() else {
                return Ok(false);
            };
            let (sig_r, sig_s) = buf.split_first_chunk::<57>().unwrap();
            let sig_s: &[u8; 57] = sig_s.try_into().unwrap();
            C::Ed448::verify_prehash(k, prehash, sig_r, sig_s)
        }
        _ => Err(CryptoError::Unsupported),
    }
}

#[cfg(feature = "mldsa")]
fn mldsa_sign_message<'a, C: Crypto>(
    rng: &mut impl Rng,
    key: &MldsaPrivateKey<C>,
    context: &[u8],
    msg: &[&[u8]],
    out: &'a mut SignatureBuffer,
) -> Result<Tpm2bSignatureMldsa<'a>, CryptoError> {
    match_mldsa_parms!(match key {
        MldsaPrivateKey::$Alg(k) => {
            let Some(buf) = out.first_chunk_mut() else {
                return Err(CryptoError::Internal);
            };
            C::$Alg::sign_message(rng, k, context, msg, buf)?;
            Tpm2bSignatureMldsa::new(buf).ok_or(CryptoError::Internal)
        },
    })
}

#[cfg(feature = "mldsa")]
fn mldsa_verify_message<C: Crypto>(
    key: &MldsaPublicKey<C>,
    context: &[u8],
    msg: &[&[u8]],
    sig: &[u8],
) -> Result<bool, CryptoError> {
    match_mldsa_parms!(match key {
        MldsaPublicKey::$Alg(k) => {
            let Ok(sig) = sig.try_into() else {
                return Ok(false);
            };
            C::$Alg::verify_message(k, context, msg, sig)
        },
    })
}

#[cfg(feature = "mldsa")]
fn mldsa_sign_mu<'a, C: Crypto>(
    rng: &mut impl Rng,
    key: &MldsaPrivateKey<C>,
    mu: &[u8; 64],
    out: &'a mut SignatureBuffer,
) -> Result<Tpm2bSignatureMldsa<'a>, CryptoError> {
    match_mldsa_parms!(match key {
        MldsaPrivateKey::$Alg(k) => {
            let Some(buf) = out.first_chunk_mut() else {
                return Err(CryptoError::Internal);
            };
            C::$Alg::sign_mu(rng, k, mu, buf)?;
            Tpm2bSignatureMldsa::new(buf).ok_or(CryptoError::Internal)
        },
    })
}

#[cfg(feature = "mldsa")]
fn mldsa_verify_mu<C: Crypto>(
    key: &MldsaPublicKey<C>,
    mu: &[u8; 64],
    sig: &[u8],
) -> Result<bool, CryptoError> {
    match_mldsa_parms!(match key {
        MldsaPublicKey::$Alg(k) => {
            let Ok(sig) = sig.try_into() else {
                return Ok(false);
            };
            C::$Alg::verify_mu(k, mu, sig)
        },
    })
}

#[cfg(feature = "hash_mldsa")]
fn mldsa_sign_prehash<'a, C: Crypto>(
    rng: &mut impl Rng,
    key: &MldsaPrivateKey<C>,
    context: &[u8],
    digest: TpmtHa<'_>,
    out: &'a mut SignatureBuffer,
) -> Result<Tpm2bSignatureMldsa<'a>, CryptoError> {
    match_mldsa_parms!(match key {
        MldsaPrivateKey::$Alg(k) => {
            let Some(buf) = out.first_chunk_mut() else {
                return Err(CryptoError::Internal);
            };
            C::$Alg::sign_prehash(rng, k, context, digest, buf)?;
            Tpm2bSignatureMldsa::new(buf).ok_or(CryptoError::Internal)
        },
    })
}

#[cfg(feature = "hash_mldsa")]
fn mldsa_verify_prehash<C: Crypto>(
    key: &MldsaPublicKey<C>,
    context: &[u8],
    digest: TpmtHa<'_>,
    sig: &[u8],
) -> Result<bool, CryptoError> {
    match_mldsa_parms!(match key {
        MldsaPublicKey::$Alg(k) => {
            let Ok(sig) = sig.try_into() else {
                return Ok(false);
            };
            C::$Alg::verify_prehash(k, context, digest, sig)
        },
    })
}
