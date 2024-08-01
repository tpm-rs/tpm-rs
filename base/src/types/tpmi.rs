// =============================================================================
// USES
// =============================================================================

use crate::types::{TPM2AlgID, TPM2ECCCurve, TPM2ST};
use open_enum::open_enum;
use tpm2_rs_marshal::Marshal;

// =============================================================================
// MODULES
// =============================================================================

mod rh_nv_index;
pub use rh_nv_index::*;
mod sh_auth_session;
pub use sh_auth_session::*;

// =============================================================================
// TYPES
// =============================================================================

/// The number of bits in an AES key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiAesKeyBits(pub u16);

/// TpmiAlgAsymScheme represents all the scheme types for any asymmetric algortihm (TPMI_ALG_ASYM_SCHEME).
/// See definition in Part 2: Structures, section 11.2.3.4.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgAsymScheme{
    SM2 = TPM2AlgID::SM2.0,
    ECDH = TPM2AlgID::ECDH.0,
    ECMQV = TPM2AlgID::ECMQV.0,
    RSAPSS = TPM2AlgID::RSAPSS.0,
    RSASSA = TPM2AlgID::RSASSA.0,
    ECDSA = TPM2AlgID::ECDSA.0,
    ECDAA = TPM2AlgID::ECDAA.0,
    ECSchnorr = TPM2AlgID::ECSchnorr.0,
    RSAES = TPM2AlgID::RSAES.0,
    OAEP = TPM2AlgID::OAEP.0,
}

/// TpmiAlgEccScheme represents values that may appear in the scheme parameter of a TpmtEccScheme (TPMI_ALG_ECC_SCHEME).
/// See definition in Part 2: Structures, section 11.2.5.4.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgEccScheme{
    RSAPSS = TPM2AlgID::RSAPSS.0,
    RSASSA = TPM2AlgID::RSASSA.0,
    ECDSA = TPM2AlgID::ECDSA.0,
    ECDAA = TPM2AlgID::ECDAA.0,
    SM2 = TPM2AlgID::SM2.0,
    ECSchnorr = TPM2AlgID::ECSchnorr.0,
    ECDH = TPM2AlgID::ECDH.0,
    ECMQV = TPM2AlgID::ECMQV.0,
}

/// TpmiAlgHash represents all of the hash algorithms (TPMI_ALG_HASH).
/// See definition in Part 2: Structures, section 9.27.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
pub enum TpmiAlgHash {
    SHA1 = TPM2AlgID::SHA1.0,
    SHA256  = TPM2AlgID::SHA256.0,
    SHA384   = TPM2AlgID::SHA384.0,
    SHA512 = TPM2AlgID::SHA512.0,
    SM3256 = TPM2AlgID::SM3256.0,
    SHA3256 = TPM2AlgID::SHA3256.0,
    SHA3384 = TPM2AlgID::SHA3384.0,
    SHA3512 = TPM2AlgID::SHA3512.0,
}

/// TpmiAlgKdf represents all of key derivation functions (TPMI_ALG_KDF).
/// See definition in Part 2: Structures, section 9.32.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
pub enum TpmiAlgKdf {
    MGF1 = TPM2AlgID::MGF1.0,
    KDF1SP80056A = TPM2AlgID::KDF1SP80056A.0,
    KDF2 = TPM2AlgID::KDF2.0,
    KDF1SP800108 = TPM2AlgID::KDF1SP800108.0,
}

/// TpmiAlgKeyedhashScheme represents values that may appear in a keyed_hash as the scheme parameter (TPMI_ALG_KEYEDHASH_SCHEME).
/// See definition in Part 2: Structures, section 11.1.19.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgKeyedhashScheme{
    HMAC = TPM2AlgID::HMAC.0,
    XOR = TPM2AlgID::XOR.0,
}

/// TpmiAlgPublic represents all object types (TPMI_ALG_PUBLIC).
/// See definition in Part 2: Structures, section 12.2.2.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgPublic{
    RSA = TPM2AlgID::RSA.0,
    KeyedHash = TPM2AlgID::KeyedHash.0,
    ECC = TPM2AlgID::ECC.0,
    SymCipher = TPM2AlgID::SymCipher.0,
}

/// TpmiAlgRsaScheme represents values that may appear in the scheme parameter of a TpmsRsaParms (TPMI_ALG_RSA_SCHEME).
/// See definition in Part 2: Structures, section 11.2.4.1.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgRsaScheme{
    RSAPSS = TPM2AlgID::RSAPSS.0,
    RSASSA = TPM2AlgID::RSASSA.0,
    ECDSA = TPM2AlgID::ECDSA.0,
    ECDAA = TPM2AlgID::ECDAA.0,
    SM2 = TPM2AlgID::SM2.0,
    ECSchnorr = TPM2AlgID::ECSchnorr.0,
    RSAES = TPM2AlgID::RSAES.0,
    OAEP = TPM2AlgID::OAEP.0,
}

/// TpmiAlgSymMode represents all of block-cipher modes of operation (TPMI_ALG_SYM_MODE).
/// See definition in Part 2: Structures, section 9.31.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgSymMode{
    CMAC = TPM2AlgID::CMAC.0,
    CTR = TPM2AlgID::CTR.0,
    OFB = TPM2AlgID::OFB.0,
    CBC = TPM2AlgID::CBC.0,
    CFB = TPM2AlgID::CFB.0,
    ECB = TPM2AlgID::ECB.0,
}

/// TpmiAlgSymObject represents all of the symmetric algorithms that may be used as a companion encryption algortihm for an asymmetric object (TPMI_ALG_SYM_OBJECT).
/// See definition in Part 2: Structures, section 9.30.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
#[allow(clippy::upper_case_acronyms)]
pub enum TpmiAlgSymObject{
    TDES = TPM2AlgID::TDES.0,
    AES = TPM2AlgID::AES.0,
    SM4 = TPM2AlgID::SM4.0,
    Camellia = TPM2AlgID::Camellia.0,
}

/// The number of bits in a Camellia key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiCamelliaKeyBits(pub u16);

/// TpmiEccCurve represents an implemented ECC curve (TPMI_ECC_SCHEME).
/// See definition in Part 2: Structures, section 11.2.5.5.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiEccCurve(pub TPM2ECCCurve);

/// The number of bits in an RSA key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiRsaKeyBits(pub u16);

/// The number of bits in an SM4 key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmiSm4KeyBits(pub u16);

/// TpmiStAttest represents an attestation structure type (TPMI_ST_ATTEST).
/// See definition in Part 2: Structures, section 10.12.10.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
pub enum TpmiStAttest {
    AttestCertify = TPM2ST::AttestCertify.0,
    AttestQuote = TPM2ST::AttestQuote.0,
    AttestSessionAudit = TPM2ST::AttestSessionAudit.0,
    AttestCommandAudit = TPM2ST::AttestCommandAudit.0,
    AttestTime = TPM2ST::AttestTime.0,
    AttestCreation = TPM2ST::AttestCreation.0,
    AttestNV = TPM2ST::AttestNV.0,
    AttestNVDigest = TPM2ST::AttestNVDigest.0,
}

/// TpmiStCommandTag defines the command tags (TPMI_ST_COMMAND_TAG).
/// See definition in Part 2: Structures, section 9.35.
#[open_enum]
#[repr(u16)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
pub enum TpmiStCommandTag{
    NoSessions = TPM2ST::NoSessions.0,
    Sessions = TPM2ST::Sessions.0,
}

/// TpmiYesNo is used in place of a boolean.
/// See TPMI_YES_NO definition in Part 2: Structures, section 9.2.
#[open_enum]
#[repr(u8)]
#[rustfmt::skip] #[derive(Debug)] // Keep debug derivation separate for open_enum override.
#[derive(Copy, Clone, PartialEq, Default, Marshal)]
pub enum TpmiYesNo {
    NO = 0,
    YES = 1,
}
