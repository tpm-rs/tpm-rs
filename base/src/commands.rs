use crate::constants::{TPM2Cap, TPM2CC, TPM2PT, TPM2SU};
use crate::errors::TpmResult;
use crate::{Marshal, Marshalable, UnmarshalBuf};
use crate::{TpmiYesNo, TpmlDigest, TpmlPcrSelection, TpmsCapabilityData};

pub trait TpmCommand: Marshalable {
    const CMD_CODE: TPM2CC;
    type RespT: Marshalable;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct StartupCmd {
    pub startup_type: TPM2SU,
}
impl TpmCommand for StartupCmd {
    const CMD_CODE: TPM2CC = TPM2CC::Startup;
    type RespT = ();
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
    type RespT = GetCapabilityResp;
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
    type RespT = PcrReadResp;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct PcrReadResp {
    pcr_update_counter: u32,
    pcr_selection_out: TpmlPcrSelection,
    pcr_values: TpmlDigest,
}
