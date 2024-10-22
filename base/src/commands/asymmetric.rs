//! [TPM2.0 1.83] 14 Asymmetric Primitives

/// [TPM2.0 1.83] 14.2 TPM2_RSA_Encrypt (Command)
pub struct RsaEncryptCmd {}

/// [TPM2.0 1.83] 14.3 TPM2_RSA_Decrypt (Command)
pub struct RsaDecryptCmd {}

/// [TPM2.0 1.83] 14.4 TPM2_ECDH_KeyGen (Command)
pub struct EcdhKeyGenCmd {}

/// [TPM2.0 1.83] 14.5 TPM2_ECDH_ZGen (Command)
pub struct EcdhZGenCmd {}

/// [TPM2.0 1.83] 14.6 TPM2_ECC_Parameters (Command)
pub struct EccParametersCmd {}

/// [TPM2.0 1.83] 14.7 TPM2_ZGen_2Phase (Command)
pub struct ZGen2PhaseCmd {}

/// [TPM2.0 1.83] 14.8 TPM2_ECC_Encrypt (Command)
pub struct EccEncryptCmd {}

/// [TPM2.0 1.83] 14.9 TPM2_ECC_Decrypt (Command)
pub struct EccDecryptCmd {}
