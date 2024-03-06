use crate::constants::{TPM2Cap, TPM2CC, TPM2PT, TPM2SU};
use crate::{
    Marshal, Marshalable, TPM2Handle, Tpm2bCreationData, Tpm2bData, Tpm2bDigest, Tpm2bName,
    Tpm2bPublic, Tpm2bSensitiveCreate, TpmiRhHierarchy, TpmtTkCreation, UnmarshalBuf,
};
use crate::{TpmiYesNo, TpmlDigest, TpmlPcrSelection, TpmsCapabilityData};

/// Trait for a TPM command transaction.
pub trait TpmCommand: Marshalable {
    /// The command code.
    const CMD_CODE: TPM2CC;
    /// The command handles type.
    type Handles: Marshalable + Default;
    /// The response parameters type.
    type RespT: Marshalable;
    /// The reponse handles type.
    type RespHandles: Marshalable;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct StartupCmd {
    pub startup_type: TPM2SU,
}
impl TpmCommand for StartupCmd {
    const CMD_CODE: TPM2CC = TPM2CC::Startup;
    type Handles = ();
    type RespT = ();
    type RespHandles = ();
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct GetCapabilityCmd {
    pub capability: TPM2Cap,
    pub property: TPM2PT,
    pub property_count: u32,
}
impl TpmCommand for GetCapabilityCmd {
    const CMD_CODE: TPM2CC = TPM2CC::GetCapability;
    type Handles = ();
    type RespT = GetCapabilityResp;
    type RespHandles = ();
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct GetCapabilityResp {
    pub more_data: TpmiYesNo,
    pub capability_data: TpmsCapabilityData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct PcrReadCmd {
    pcr_selection_in: TpmlPcrSelection,
}
impl TpmCommand for PcrReadCmd {
    const CMD_CODE: TPM2CC = TPM2CC::PCRRead;
    type Handles = ();
    type RespT = PcrReadResp;
    type RespHandles = ();
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct PcrReadResp {
    pcr_update_counter: u32,
    pcr_selection_out: TpmlPcrSelection,
    pcr_values: TpmlDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct CreatePrimaryCmd {
    pub in_sensitive: Tpm2bSensitiveCreate,
    pub in_public: Tpm2bPublic,
    pub outside_info: Tpm2bData,
    pub creation_pcr: TpmlPcrSelection,
}
impl TpmCommand for CreatePrimaryCmd {
    const CMD_CODE: TPM2CC = TPM2CC::CreatePrimary;
    type Handles = TpmiRhHierarchy;
    type RespT = CreatePrimaryResp;
    type RespHandles = TPM2Handle;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct CreatePrimaryResp {
    pub out_public: Tpm2bPublic,
    pub creation_data: Tpm2bCreationData,
    pub creation_hash: Tpm2bDigest,
    pub creation_ticket: TpmtTkCreation,
    pub name: Tpm2bName,
}
