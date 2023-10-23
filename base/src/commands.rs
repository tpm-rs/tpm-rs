use crate::constants::{TPM2Cap, TPM2CC};
use crate::errors::TpmResult;
use crate::{Marshal, Marshalable, UnmarshalBuf};
use crate::{TpmiYesNo, TpmlDigest, TpmlPcrSelection, TpmsCapabilityData};
use zerocopy::byteorder::big_endian::*;

// Provides a const way to turn a u32 into a U32.
pub const fn to_be_u32(val: u32) -> U32 {
    U32::from_bytes(val.to_be_bytes())
}

pub trait TpmCommand: Marshalable {
    const CMD_CODE: TPM2CC;
    type RespT: Marshalable;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct GetCapabilityCmd {
    capability: TPM2Cap,
    property: U32,
    property_count: U32,
}
impl TpmCommand for GetCapabilityCmd {
    const CMD_CODE: TPM2CC = TPM2CC::GetCapability;
    type RespT = GetCapabilityResp;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct GetCapabilityResp {
    more_data: TpmiYesNo,
    capability_data: TpmsCapabilityData,
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
    pcr_update_counter: U32,
    pcr_selection_out: TpmlPcrSelection,
    pcr_values: TpmlDigest,
}
