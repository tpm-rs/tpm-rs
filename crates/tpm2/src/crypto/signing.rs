use super::{ConstantTimeEq, CryptoError, Ecc, Hmac, Rsa, digest_eq, hmac};
use crate::{
    Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmEccCurve, TpmiAlgHash, TpmiRsaKeyBits,
    TpmsSignatureEcc, TpmsSignatureRsa, TpmtHa, TpmtSigScheme, TpmtSignature,
};

/// Scratch buffer large enough to hold the raw bytes of any [`TpmtSignature`]:
/// - RSA (`sig`): [`TpmiRsaKeyBits::MAX_PUB_KEY_BYTES`] (`512` bytes)
/// - ECC (`r || s`): `2 *` [`TpmEccCurve::MAX_ECC_KEY_BYTES`] (`160` bytes)
/// - HMAC (`digest`): [`TpmiAlgHash::MAX_DIGEST_BYTES`] (`64` bytes)
pub type SignatureBuffer = [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];

const _: () = assert!(TpmiRsaKeyBits::MAX_PUB_KEY_BYTES >= 2 * TpmEccCurve::MAX_ECC_KEY_BYTES);
const _: () = assert!(TpmiRsaKeyBits::MAX_PUB_KEY_BYTES >= TpmiAlgHash::MAX_DIGEST_BYTES);

/// RSA signature schemes (`RSASSA-PKCS1-v1_5` and `RSASSA-PSS`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RsaSigScheme {
    Rsassa,
    Rsapss,
}

/// ECC signature schemes (`ECDSA`, `ECDAA`, `SM2`, and `ECSchnorr`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EccSigScheme {
    Ecdsa,
    Ecdaa(u16),
    Sm2,
    Ecschnorr,
}

/// Borrowed private or symmetric key handle for [`sign`].
pub enum SigningKey<'a, C: Rsa + Ecc> {
    Hmac(&'a [u8]),
    Rsa(&'a <C as Rsa>::PrivateKey),
    Ecc(&'a <C as Ecc>::PrivateKey),
}

/// Borrowed public or symmetric key handle for [`verify`].
pub enum VerifyingKey<'a, C: Rsa + Ecc> {
    Hmac(&'a [u8]),
    Rsa(&'a <C as Rsa>::PublicKey),
    Ecc(&'a <C as Ecc>::PublicKey),
}

/// Trait implemented by a cryptographic backend to provide signature generation and verification.
#[allow(unused_variables)]
pub trait Signing: Rsa + Ecc + Hmac + ConstantTimeEq {
    /// Signs `digest` using an RSA private key and `scheme` (`RSASSA` or `RSAPSS`).
    fn rsa_sign<'a>(
        &self,
        rng: &mut Self::Rng,
        key: &<Self as Rsa>::PrivateKey,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Verifies an RSA signature over `digest`. Returns `Ok(true)` if valid, `Ok(false)` if invalid.
    fn rsa_verify(
        &self,
        key: &<Self as Rsa>::PublicKey,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        sig: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Signs `digest` using an ECC private key and `scheme` (`ECDSA`, `ECDAA`, `SM2`, `ECSCHNORR`).
    fn ecc_sign<'a>(
        &self,
        rng: &mut Self::Rng,
        key: &<Self as Ecc>::PrivateKey,
        scheme: EccSigScheme,
        digest: TpmtHa<'_>,
        out_r: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_s: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<(Tpm2bEccParameter<'a>, Tpm2bEccParameter<'a>), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Verifies an ECC `(r, s)` signature over `digest`. Returns `Ok(true)` if valid, `Ok(false)` if invalid.
    fn ecc_verify(
        &self,
        key: &<Self as Ecc>::PublicKey,
        scheme: EccSigScheme,
        digest: TpmtHa<'_>,
        sig_r: &[u8],
        sig_s: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// Signs `digest` with `key` and `scheme`, writing the signature payload to `out` and returning a [`TpmtSignature`].
pub fn sign<'a, C: Signing>(
    crypto: &C,
    rng: &mut C::Rng,
    key: SigningKey<'_, C>,
    scheme: TpmtSigScheme,
    digest: &[u8],
    out: &'a mut SignatureBuffer,
) -> Result<TpmtSignature<'a>, CryptoError> {
    let hash = match scheme {
        TpmtSigScheme::Hmac(h)
        | TpmtSigScheme::Rsassa(h)
        | TpmtSigScheme::Rsapss(h)
        | TpmtSigScheme::Ecdsa(h)
        | TpmtSigScheme::Sm2(h)
        | TpmtSigScheme::Ecschnorr(h) => h,
        TpmtSigScheme::Ecdaa(s) => s.hash_alg,
    };
    let digest = TpmtHa::from_slice(hash, digest).ok_or(CryptoError::Unsupported)?;

    match (key, scheme) {
        (SigningKey::Hmac(k), TpmtSigScheme::Hmac(hash)) => {
            let out_digest = out.first_chunk_mut().unwrap();
            let tag = hmac(crypto, hash, k, digest.digest(), out_digest)?;
            Ok(TpmtSignature::Hmac(tag))
        }
        (SigningKey::Rsa(k), TpmtSigScheme::Rsassa(_)) => {
            let sig = crypto.rsa_sign(rng, k, RsaSigScheme::Rsassa, digest, out)?;
            Ok(TpmtSignature::Rsassa(TpmsSignatureRsa { hash, sig }))
        }
        (SigningKey::Rsa(k), TpmtSigScheme::Rsapss(_)) => {
            let sig = crypto.rsa_sign(rng, k, RsaSigScheme::Rsapss, digest, out)?;
            Ok(TpmtSignature::Rsapss(TpmsSignatureRsa { hash, sig }))
        }
        (SigningKey::Ecc(k), TpmtSigScheme::Ecdsa(_)) => {
            let (out_r, rest) = out.split_first_chunk_mut().unwrap();
            let out_s = rest.first_chunk_mut().unwrap();
            let (signature_r, signature_s) =
                crypto.ecc_sign(rng, k, EccSigScheme::Ecdsa, digest, out_r, out_s)?;
            Ok(TpmtSignature::Ecdsa(TpmsSignatureEcc {
                hash,
                signature_r,
                signature_s,
            }))
        }
        (SigningKey::Ecc(k), TpmtSigScheme::Ecdaa(s)) => {
            let (out_r, rest) = out.split_first_chunk_mut().unwrap();
            let out_s = rest.first_chunk_mut().unwrap();
            let (signature_r, signature_s) =
                crypto.ecc_sign(rng, k, EccSigScheme::Ecdaa(s.count), digest, out_r, out_s)?;
            Ok(TpmtSignature::Ecdaa(TpmsSignatureEcc {
                hash,
                signature_r,
                signature_s,
            }))
        }
        (SigningKey::Ecc(k), TpmtSigScheme::Sm2(_)) => {
            let (out_r, rest) = out.split_first_chunk_mut().unwrap();
            let out_s = rest.first_chunk_mut().unwrap();
            let (signature_r, signature_s) =
                crypto.ecc_sign(rng, k, EccSigScheme::Sm2, digest, out_r, out_s)?;
            Ok(TpmtSignature::Sm2(TpmsSignatureEcc {
                hash,
                signature_r,
                signature_s,
            }))
        }
        (SigningKey::Ecc(k), TpmtSigScheme::Ecschnorr(_)) => {
            let (out_r, rest) = out.split_first_chunk_mut().unwrap();
            let out_s = rest.first_chunk_mut().unwrap();
            let (signature_r, signature_s) =
                crypto.ecc_sign(rng, k, EccSigScheme::Ecschnorr, digest, out_r, out_s)?;
            Ok(TpmtSignature::Ecschnorr(TpmsSignatureEcc {
                hash,
                signature_r,
                signature_s,
            }))
        }
        _ => Err(CryptoError::Unsupported),
    }
}

/// Verifies `signature` over `digest` using `key`.
pub fn verify<C: Signing>(
    crypto: &C,
    key: VerifyingKey<'_, C>,
    digest: &[u8],
    signature: TpmtSignature<'_>,
) -> Result<bool, CryptoError> {
    let hash = match signature {
        TpmtSignature::Hmac(t) => t.hash_alg(),
        TpmtSignature::Rsassa(s) | TpmtSignature::Rsapss(s) => s.hash,
        TpmtSignature::Ecdsa(s)
        | TpmtSignature::Ecdaa(s)
        | TpmtSignature::Sm2(s)
        | TpmtSignature::Ecschnorr(s) => s.hash,
    };
    let Some(digest) = TpmtHa::from_slice(hash, digest) else {
        return Ok(false);
    };

    match (key, signature) {
        (VerifyingKey::Hmac(k), TpmtSignature::Hmac(expected)) => {
            let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
            let actual = hmac(crypto, hash, k, digest.digest(), &mut buf)?;
            Ok(digest_eq(crypto, actual, expected))
        }
        (VerifyingKey::Rsa(k), TpmtSignature::Rsassa(s)) => {
            crypto.rsa_verify(k, RsaSigScheme::Rsassa, digest, s.sig.as_slice())
        }
        (VerifyingKey::Rsa(k), TpmtSignature::Rsapss(s)) => {
            crypto.rsa_verify(k, RsaSigScheme::Rsapss, digest, s.sig.as_slice())
        }
        (VerifyingKey::Ecc(k), TpmtSignature::Ecdsa(s)) => crypto.ecc_verify(
            k,
            EccSigScheme::Ecdsa,
            digest,
            s.signature_r.as_slice(),
            s.signature_s.as_slice(),
        ),
        (VerifyingKey::Ecc(k), TpmtSignature::Ecdaa(s)) => crypto.ecc_verify(
            k,
            EccSigScheme::Ecdaa(0),
            digest,
            s.signature_r.as_slice(),
            s.signature_s.as_slice(),
        ),
        (VerifyingKey::Ecc(k), TpmtSignature::Sm2(s)) => crypto.ecc_verify(
            k,
            EccSigScheme::Sm2,
            digest,
            s.signature_r.as_slice(),
            s.signature_s.as_slice(),
        ),
        (VerifyingKey::Ecc(k), TpmtSignature::Ecschnorr(s)) => crypto.ecc_verify(
            k,
            EccSigScheme::Ecschnorr,
            digest,
            s.signature_r.as_slice(),
            s.signature_s.as_slice(),
        ),
        _ => Err(CryptoError::Unsupported),
    }
}
