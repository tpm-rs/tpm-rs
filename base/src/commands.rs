use crate::constants::TPM2CC;
use crate::errors::TpmResult;
use crate::{Marshalable, UnmarshalBuf};
use crate::{TpmiYesNo, TpmlDigest, TpmlPcrSelection, TpmsCapabilityData};
use marshal_derive::Marshal;
use zerocopy::byteorder::big_endian::*;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

// Provides a const way to turn a u32 into a U32.
pub const fn to_be_u32(val: u32) -> U32 {
    U32::from_bytes(val.to_be_bytes())
}

// Provides a const way to turn a u16 into a U16.
pub const fn to_be_u16(val: u16) -> U16 {
    U16::from_bytes(val.to_be_bytes())
}

pub trait TpmCommand: Marshalable {
    const CMD_CODE: TPM2CC;
    type RespT: Marshalable;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, AsBytes, FromBytes, FromZeroes)]
pub struct GetCapabilityCmd {
    pub capability: U32,
    pub property: U32,
    pub property_count: U32,
}
impl TpmCommand for GetCapabilityCmd {
    const CMD_CODE: TPM2CC = TPM2CC::GetCapability;
    type RespT = GetCapabilityResp;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
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
    pcr_update_counter: U32,
    pcr_selection_out: TpmlPcrSelection,
    pcr_values: TpmlDigest,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, AsBytes, FromBytes, FromZeroes)]
pub struct StartupCmd {
    pub startup_type: U16,
}
impl TpmCommand for StartupCmd {
    const CMD_CODE: TPM2CC = TPM2CC::Startup;
    type RespT = ();
}
