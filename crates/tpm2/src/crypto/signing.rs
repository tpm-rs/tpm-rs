//! Signature buffers shared by the signing key types.
//!
//! Signing and verification (`TPM2_Sign` and `TPM2_VerifySignature`) are
//! methods on the key types: [`RsaPrivateKey::sign`](super::RsaPrivateKey::sign)
//! / [`RsaPublicKey::verify`](super::RsaPublicKey::verify) and
//! [`EccPrivateKey::sign`](super::EccPrivateKey::sign) /
//! [`EccPublicKey::verify`](super::EccPublicKey::verify).

use crate::TpmiAlgHash;

/// Maximum byte length of the raw payload of any enabled digest-level
/// [`TpmtSignature`](crate::TpmtSignature):
/// - HMAC (`digest`): [`TpmiAlgHash::MAX_DIGEST_BYTES`]
/// - RSA (`sig`):
///   [`TpmiRsaKeyBits::MAX_PUB_KEY_BYTES`](crate::TpmiRsaKeyBits::MAX_PUB_KEY_BYTES)
/// - ECC (`r || s`): `2 * MAX_ECC_COORD_BYTES` (when `ecc` is enabled)
pub const MAX_SIGNATURE_BYTES: usize = max!(
    TpmiAlgHash::MAX_DIGEST_BYTES,
    #[cfg(feature = "rsa")]
    crate::TpmiRsaKeyBits::MAX_PUB_KEY_BYTES,
    #[cfg(feature = "ecc")]
    2 * super::MAX_ECC_COORD_BYTES,
);

/// Scratch buffer large enough to hold the raw payload of any enabled
/// digest-level [`TpmtSignature`](crate::TpmtSignature).
pub type SignatureBuffer = [u8; MAX_SIGNATURE_BYTES];
