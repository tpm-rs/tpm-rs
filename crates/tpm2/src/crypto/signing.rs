//! Signature buffers shared by the signing key types.
//!
//! Signing and verification (`TPM2_Sign`, `TPM2_SignDigest`,
//! `TPM2_SignSequenceComplete`, `TPM2_VerifySignature`,
//! `TPM2_VerifyDigestSignature`, and `TPM2_VerifySequenceComplete`) are
//! methods on the key types: [`RsaPrivateKey::sign`](super::RsaPrivateKey::sign)
//! / [`RsaPublicKey::verify`](super::RsaPublicKey::verify),
//! [`EccPrivateKey::sign`](super::EccPrivateKey::sign) /
//! [`EccPublicKey::verify`](super::EccPublicKey::verify) (plus `sign_message` /
//! `verify_message` for `EdDSA`), and
//! [`MldsaPrivateKey`](super::MldsaPrivateKey) /
//! [`MldsaPublicKey`](super::MldsaPublicKey).

use crate::TpmiAlgHash;

/// Maximum byte length of the raw payload of any enabled
/// [`TpmtSignature`](crate::TpmtSignature):
/// - HMAC (`digest`): [`TpmiAlgHash::MAX_DIGEST_BYTES`]
/// - RSA (`sig`):
///   [`TpmiRsaKeyBits::MAX_PUB_KEY_BYTES`](crate::TpmiRsaKeyBits::MAX_PUB_KEY_BYTES)
/// - ECC / EdDSA (`r || s`): `2 * MAX_ECC_COORD_BYTES` (when `ecc` is enabled)
/// - ML-DSA / HashML-DSA (`sig`):
///   [`TpmiMldsaParms::MAX_SIG_BYTES`](crate::TpmiMldsaParms::MAX_SIG_BYTES)
///   (when `mldsa` is enabled)
pub const MAX_SIGNATURE_BYTES: usize = max!(
    TpmiAlgHash::MAX_DIGEST_BYTES,
    #[cfg(feature = "rsa")]
    crate::TpmiRsaKeyBits::MAX_PUB_KEY_BYTES,
    #[cfg(feature = "ecc")]
    2 * super::MAX_ECC_COORD_BYTES,
    #[cfg(feature = "mldsa")]
    crate::TpmiMldsaParms::MAX_SIG_BYTES,
);

/// Scratch buffer large enough to hold the raw payload of any enabled
/// [`TpmtSignature`](crate::TpmtSignature).
pub type SignatureBuffer = [u8; MAX_SIGNATURE_BYTES];
