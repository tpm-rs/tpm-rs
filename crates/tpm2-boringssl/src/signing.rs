//! [`Signing`] implementation: RSASSA-PKCS1-v1_5, RSASSA-PSS, and ECDSA (P-256,
//! P-384, P-521) using BoringSSL.

use tpm2::crypto::{CryptoError, EccSigScheme, RsaSigScheme, Signing};
use tpm2::{Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmEccCurve, TpmiRsaKeyBits, TpmtHa};

use crate::ecc::write_param;
use crate::{
    BoringSsl, ChaChaRng, EccPrivateKey, EccPublicKey, RsaPrivateKey, RsaPublicKey, bssl, pad_into,
};

/// Returns the big-endian `value` without its leading zeros.
fn trim_zeros(value: &[u8]) -> &[u8] {
    let zeros = value.iter().take_while(|&&byte| byte == 0).count();
    value.get(zeros..).unwrap_or_default()
}

impl Signing for BoringSsl {
    fn rsa_sign<'a>(
        &self,
        _rng: &mut ChaChaRng,
        key: &RsaPrivateKey,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        let len = match scheme {
            RsaSigScheme::Rsassa => {
                key.key
                    .sign_pkcs1v15(digest.hash_alg(), digest.digest(), out)?
            }
            RsaSigScheme::Rsapss => key.key.sign_pss(digest.hash_alg(), digest.digest(), out)?,
        };
        Tpm2bPublicKeyRsa::new(&out[..len]).ok_or(CryptoError::Internal)
    }

    fn rsa_verify(
        &self,
        key: &RsaPublicKey,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        sig: &[u8],
    ) -> Result<bool, CryptoError> {
        match scheme {
            RsaSigScheme::Rsassa => {
                key.key
                    .verify_pkcs1v15(digest.hash_alg(), digest.digest(), sig)
            }
            RsaSigScheme::Rsapss => key.key.verify_pss(digest.hash_alg(), digest.digest(), sig),
        }
    }

    fn ecc_sign<'a>(
        &self,
        _rng: &mut ChaChaRng,
        key: &EccPrivateKey,
        scheme: EccSigScheme,
        digest: TpmtHa<'_>,
        out_r: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_s: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<(Tpm2bEccParameter<'a>, Tpm2bEccParameter<'a>), CryptoError> {
        if scheme != EccSigScheme::Ecdsa {
            return Err(CryptoError::Unsupported);
        }
        let group = key.public.group;
        let len = group.coord_len();
        let mut sig = [0u8; 2 * TpmEccCurve::MAX_ECC_KEY_BYTES];
        bssl::ecdsa_sign(
            group,
            &key.scalar[..len],
            digest.digest(),
            &mut sig[..2 * len],
        )?;
        let (r, s) = sig[..2 * len].split_at(len);
        Ok((write_param(r, out_r)?, write_param(s, out_s)?))
    }

    fn ecc_verify(
        &self,
        key: &EccPublicKey,
        scheme: EccSigScheme,
        digest: TpmtHa<'_>,
        sig_r: &[u8],
        sig_s: &[u8],
    ) -> Result<bool, CryptoError> {
        if scheme != EccSigScheme::Ecdsa {
            return Err(CryptoError::Unsupported);
        }
        let group = key.group;
        let len = group.coord_len();
        let mut sig = [0u8; 2 * TpmEccCurve::MAX_ECC_KEY_BYTES];
        let (out_r, out_s) = sig[..2 * len].split_at_mut(len);
        if pad_into(trim_zeros(sig_r), out_r).is_none()
            || pad_into(trim_zeros(sig_s), out_s).is_none()
        {
            return Ok(false);
        }
        let mut pub_xy = [0u8; 2 * TpmEccCurve::MAX_ECC_KEY_BYTES];
        pub_xy[..len].copy_from_slice(&key.x[..len]);
        pub_xy[len..2 * len].copy_from_slice(&key.y[..len]);
        Ok(bssl::ecdsa_verify(group, &pub_xy[..2 * len], digest.digest(), &sig[..2 * len]).is_ok())
    }
}
