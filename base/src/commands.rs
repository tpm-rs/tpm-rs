use crate::errors::TpmResult;
use crate::{Marshalable, UnmarshalBuf};
use crate::{TpmCap, TpmCc, TpmiYesNo, TpmlDigest, TpmlPcrSelection, TpmsCapabilityData};
use marshal_derive::Marshal;
use zerocopy::byteorder::big_endian::*;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

// Provides a const way to turn a u32 into a U32.
pub const fn to_be(val: u32) -> U32 {
    U32::from_bytes(val.to_be_bytes())
}

pub trait TpmCommand: Marshalable {
    const CMD_CODE: TpmCc;
    type RespT: Marshalable;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct GetCapabilityCmd {
    capability: TpmCap,
    property: U32,
    property_count: U32,
}
impl TpmCommand for GetCapabilityCmd {
    const CMD_CODE: TpmCc = to_be(0x0000017A);
    type RespT = GetCapabilityResp;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
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
    const CMD_CODE: TpmCc = to_be(0x0000017E);
    type RespT = PcrReadResp;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct PcrReadResp {
    pcr_update_counter: U32,
    pcr_selection_out: TpmlPcrSelection,
    pcr_values: TpmlDigest,
}
