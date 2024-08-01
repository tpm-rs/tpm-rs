// =============================================================================
// USES
// =============================================================================

use crate::{constants::*, types::*};
use core::mem::size_of;
use tpm2_rs_marshal::Marshal;
use tpm2_rs_unionify::UnionSize;

// =============================================================================
// TYPES
// =============================================================================

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub enum TpmuAttest {
    Certify(TpmsCertifyInfo) = TPM2ST::AttestCertify.0,
    Creation(TpmsCreationInfo) = TPM2ST::AttestCreation.0,
    Quote(TpmsQuoteInfo) = TPM2ST::AttestQuote.0,
    CommandAudit(TpmsCommandAuditInfo) = TPM2ST::AttestCommandAudit.0,
    SessionAudit(TpmsSessionAuditInfo) = TPM2ST::AttestSessionAudit.0,
    Time(TpmsTimeAttestInfo) = TPM2ST::AttestTime.0,
    Nv(TpmsNvCertifyInfo) = TPM2ST::AttestNV.0,
}

#[derive(UnionSize)]
#[repr(C, u16)]
pub enum TpmuEncryptedSecret {
    Ecc([u8; size_of::<TpmsEccPoint>()]),
    Rsa([u8; TPM2_MAX_RSA_KEY_BYTES as usize]),
    Symmetric([u8; size_of::<Tpm2bDigest>()]),
    KeyedHash([u8; size_of::<Tpm2bDigest>()]),
}

#[derive(UnionSize)]
#[repr(C, u16)]
pub enum TpmuName {
    Digest(TpmtHa),
    Handle(TPM2Handle),
}

#[repr(C)]
union TpmuPublicId {
    pub keyed_hash: Tpm2bDigest,
    pub sym: Tpm2bDigest,
    pub rsa: Tpm2bPublicKeyRsa,
    pub ecc: TpmsEccPoint,
    pub derive: TpmsDerive,
}

#[repr(C, u16)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmuSensitiveComposite {
    Rsa(Tpm2bPrivateKeyRsa) = TPM2AlgID::RSA.0,
    Ecc(Tpm2bEccParameter) = TPM2AlgID::ECC.0,
    Bits(Tpm2bSensitiveData) = TPM2AlgID::KeyedHash.0,
    Sym(Tpm2bSymKey) = TPM2AlgID::SymCipher.0,
    /* For size purposes only */
    Any(Tpm2bPrivateVendorSpecific) = TPM2AlgID::Null.0,
}

#[derive(UnionSize)]
#[repr(C, u16)]
pub enum TpmuSensitiveCreate {
    Create([u8; TPM2_MAX_SYM_DATA as usize]),
    Derive(TpmsDerive),
}
