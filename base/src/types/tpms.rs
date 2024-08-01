// =============================================================================
// USES
// =============================================================================

use crate::{constants::*, types::*};
use tpm2_rs_marshal::Marshal;

// =============================================================================
// MODULES
// =============================================================================

mod attest;
pub use attest::*;

// =============================================================================
// TYPES
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Debug, Marshal)]
pub struct TpmsAlgProperty {
    pub alg: TPM2AlgID,
    pub alg_properties: TpmaAlgorithm,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsAsymParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtAsymScheme,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Debug, Marshal)]
pub struct TpmsAuthCommand {
    pub session_handle: TpmiShAuthSession,
    pub nonce: Tpm2bNonce,
    pub session_attributes: TpmaSession,
    pub hmac: Tpm2bAuth,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Debug, Marshal)]
pub struct TpmsAuthResponse {
    pub nonce: Tpm2bNonce,
    pub session_attributes: TpmaSession,
    pub hmac: Tpm2bData,
}

#[repr(C, u32)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub enum TpmsCapabilityData {
    Algorithms(TpmlAlgProperty) = TPM2Cap::Algs.0,
    Handles(TpmlHandle) = TPM2Cap::Handles.0,
    Command(TpmlCca) = TPM2Cap::Commands.0,
    PpCommands(TpmlCc) = TPM2Cap::PPCommands.0,
    AuditCommands(TpmlCc) = TPM2Cap::AuditCommands.0,
    AssignedPcr(TpmlPcrSelection) = TPM2Cap::PCRs.0,
    TpmProperties(TpmlTaggedTpmProperty) = TPM2Cap::TPMProperties.0,
    PcrProperties(TpmlTaggedPcrProperty) = TPM2Cap::PCRProperties.0,
    EccCurves(TpmlEccCurve) = TPM2Cap::ECCCurves.0,
    AuthPolicies(TpmlTaggedPolicy) = TPM2Cap::AuthPolicies.0,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsCertifyInfo {
    pub name: Tpm2bName,
    pub qualified_name: Tpm2bName,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: TpmiYesNo,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct TpmsCommandAuditInfo {
    pub audit_counter: u64,
    pub digest_alg: u16,
    pub audit_digest: Tpm2bDigest,
    pub command_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsContextData {
    pub integrity: Tpm2bDigest,
    pub encrypted: Tpm2bContextSensitive,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsCreationData {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
    pub locality: TpmaLocality,
    pub parent_name_alg: TPM2AlgID,
    pub parent_name: Tpm2bName,
    pub parent_qualified_name: Tpm2bName,
    pub outside_info: Tpm2bData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsCreationInfo {
    pub object_name: Tpm2bName,
    pub creation_hash: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsDerive {
    pub label: Tpm2bLabel,
    pub context: Tpm2bLabel,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsEccParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtEccScheme,
    pub curve_id: TpmiEccCurve,
    pub kdf: TpmtKdfScheme,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsEccPoint {
    pub x: Tpm2bEccParameter,
    pub y: Tpm2bEccParameter,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsEmpty;

pub type TpmsEncSchemeOaep = TpmsSchemeHash;

pub type TpmsEncSchemeRsaes = TpmsEmpty;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsIdObject {
    pub integrity_hmac: Tpm2bDigest,
    pub enc_identity: Tpm2bDigest,
}

pub type TpmsKeySchemeEcdh = TpmsSchemeHash;

pub type TpmsKeySchemeEcmqv = TpmsSchemeHash;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsKeyedHashParms {
    pub scheme: TpmtKeyedHashScheme,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsNvCertifyInfo {
    pub index_name: Tpm2bName,
    pub offset: u16,
    pub nv_contents: Tpm2bMaxNvBuffer,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsNvPublic {
    pub nv_index: TpmiRhNvIndex,
    pub name_alg: TpmiAlgHash,
    pub attributes: TpmaNv,
    pub auth_policy: Tpm2bDigest,
    pub data_size: u16,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
pub struct TpmsPcrSelection {
    pub hash: TpmiAlgHash,
    pub sizeof_select: u8,
    #[marshal(length=sizeof_select)]
    pub pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsQuoteInfo {
    pub pcr_select: TpmlPcrSelection,
    pub pcr_digest: Tpm2bDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsRsaParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtRsaScheme,
    pub key_bits: TpmiRsaKeyBits,
    pub exponent: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSchemeHash {
    pub hash_alg: TpmiAlgHash,
}

pub type TpmsSchemeHmac = TpmsSchemeHash;

pub type TpmsSchemeKdf1Sp800_108 = TpmsSchemeHash;

pub type TpmsSchemeKdf1Sp800_56a = TpmsSchemeHash;

pub type TpmsSchemeKdf2 = TpmsSchemeHash;

pub type TpmsSchemeMgf1 = TpmsSchemeHash;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSchemeXor {
    pub hash_alg: TpmiAlgHash,
    pub kdf: TpmiAlgKdf,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2bAuth,
    pub data: Tpm2bSensitiveData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSessionAuditInfo {
    pub exclusive_session: TpmiYesNo,
    pub session_digest: Tpm2bDigest,
}

pub type TpmsSigSchemeEcdaa = TpmsSchemeHash;

pub type TpmsSigSchemeEcdsa = TpmsSchemeHash;

pub type TpmsSigSchemeEcschnorr = TpmsSchemeHash;

pub type TpmsSigSchemeRsapss = TpmsSchemeHash;

pub type TpmsSigSchemeRsassa = TpmsSchemeHash;

pub type TpmsSigSchemeSm2 = TpmsSchemeHash;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsSymCipherParms {
    pub sym: TpmtSymDefObject,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Debug, Marshal)]
pub struct TpmsTaggedPcrSelect {
    tag: TPM2PTPCR,
    size_of_select: u8,
    #[marshal(length=size_of_select)]
    pcr_select: [u8; TPM2_PCR_SELECT_MAX as usize],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal, Default)]
pub struct TpmsTaggedPolicy {
    handle: TPM2Handle,
    policy_hash: TpmtHa,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Default, Debug, Marshal)]
pub struct TpmsTaggedProperty {
    pub property: TPM2PT,
    pub value: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsTimeAttestInfo {
    pub time: TpmsTimeInfo,
    pub firmware_version: u64,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct TpmsTimeInfo {
    pub time: u64,
    pub clock_info: TpmsClockInfo,
}
