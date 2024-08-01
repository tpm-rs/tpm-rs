// =============================================================================
// USES
// =============================================================================

use crate::types::*;
use tpm2_rs_marshal::Marshal;

// =============================================================================
// MODULES
// =============================================================================

mod ha;
pub use ha::*;
mod public;
pub use public::*;
mod sensitive;
pub use sensitive::*;

// =============================================================================
// TYPES
// =============================================================================

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtAsymScheme {
    Ecdh(TpmsKeySchemeEcdh) = TPM2AlgID::ECDH.0,
    Ecmqv(TpmsKeySchemeEcmqv) = TPM2AlgID::ECMQV.0,
    Sm2(TpmsSigSchemeSm2) = TPM2AlgID::SM2.0,
    Rsapss(TpmsSigSchemeRsapss) = TPM2AlgID::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TPM2AlgID::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2AlgID::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2AlgID::ECDAA.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2AlgID::ECSchnorr.0,
    Rsaes(TpmsEncSchemeRsaes) = TPM2AlgID::RSAES.0,
    Oaep(TpmsEncSchemeOaep) = TPM2AlgID::OAEP.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtEccScheme {
    Rsapss(TpmsSigSchemeRsapss) = TPM2AlgID::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TPM2AlgID::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2AlgID::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2AlgID::ECDAA.0,
    Sm2(TpmsSigSchemeSm2) = TPM2AlgID::SM2.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2AlgID::ECSchnorr.0,
    Ecdh(TpmsKeySchemeEcdh) = TPM2AlgID::ECDH.0,
    Ecmqv(TpmsKeySchemeEcmqv) = TPM2AlgID::ECMQV.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtKdfScheme {
    Mgf1(TpmsSchemeMgf1) = TPM2AlgID::MGF1.0,
    Kdf1Sp800_56a(TpmsSchemeKdf1Sp800_56a) = TPM2AlgID::KDF1SP80056A.0,
    Kdf2(TpmsSchemeKdf2) = TPM2AlgID::KDF2.0,
    Kdf1Sp800_108(TpmsSchemeKdf1Sp800_108) = TPM2AlgID::KDF1SP800108.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtKeyedHashScheme {
    Hmac(TpmsSchemeHmac) = TPM2AlgID::HMAC.0,
    ExclusiveOr(TpmsSchemeXor) = TPM2AlgID::XOR.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtRsaScheme {
    Rsapss(TpmsSigSchemeRsapss) = TPM2AlgID::RSAPSS.0,
    Rsassa(TpmsSigSchemeRsassa) = TPM2AlgID::RSASSA.0,
    Ecdsa(TpmsSigSchemeEcdsa) = TPM2AlgID::ECDSA.0,
    Ecdaa(TpmsSigSchemeEcdaa) = TPM2AlgID::ECDAA.0,
    Sm2(TpmsSigSchemeSm2) = TPM2AlgID::SM2.0,
    Ecschnorr(TpmsSigSchemeEcschnorr) = TPM2AlgID::ECSchnorr.0,
    Rsaes(TpmsEncSchemeRsaes) = TPM2AlgID::RSAES.0,
    Oaep(TpmsEncSchemeOaep) = TPM2AlgID::OAEP.0,
    Null(TpmsEmpty) = TPM2AlgID::Null.0,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmtSymDefObject {
    Aes(TpmiAesKeyBits, TpmiAlgSymMode) = TPM2AlgID::AES.0,
    Sm4(TpmiSm4KeyBits, TpmiAlgSymMode) = TPM2AlgID::SM4.0,
    Camellia(TpmiCamelliaKeyBits, TpmiAlgSymMode) = TPM2AlgID::Camellia.0,
    ExclusiveOr(TpmiAlgHash, TpmsEmpty) = TPM2AlgID::XOR.0,
    Null(TpmsEmpty, TpmsEmpty) = TPM2AlgID::Null.0,
}
