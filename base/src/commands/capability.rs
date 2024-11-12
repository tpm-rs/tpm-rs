//! [TPM2.0 1.83] 30 Capability Commands

use crate::commands::{Marshalable, TpmCommandProps};
use crate::constants::{TpmCap, TpmCc, TpmPt};
use crate::{TpmiYesNo, TpmsCapabilityData};

/// [TPM2.0 1.83] 30.2 TPM2_GetCapability (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct GetCapabilityCmd {
    pub capability: TpmCap,
    pub property: TpmPt,
    pub property_count: u32,
}
impl TpmCommandProps for GetCapabilityCmd {
    const CMD_CODE: TpmCc = TpmCc::GetCapability;
    type Handles = ();
    type RespT = GetCapabilityResp;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 30.2 TPM2_GetCapability (Response)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct GetCapabilityResp {
    pub more_data: TpmiYesNo,
    pub capability_data: TpmsCapabilityData,
}

/// [TPM2.0 1.83] 30.3 TPM2_TestParms (Command)
pub struct TestParmsCmd {}

/// [TPM2.0 1.83] 30.4 TPM2_SetCapability (Command)
pub struct SetCapabilityCmd {}
