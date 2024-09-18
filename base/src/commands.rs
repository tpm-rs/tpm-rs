use crate::constants::{TpmCap, TpmCc, TpmPt, TpmSu};
use crate::Marshalable;
use crate::{TpmiYesNo, TpmlDigest, TpmlPcrSelection, TpmsCapabilityData};

/// Trait for a TPM command transaction.
pub trait TpmCommand: Marshalable {
    /// The command code.
    const CMD_CODE: TpmCc;
    /// The command handles type.
    type Handles: Marshalable + Default;
    /// The response parameters type.
    type RespT: Marshalable;
    /// The reponse handles type.
    type RespHandles: Marshalable;
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct StartupCmd {
    pub startup_type: TpmSu,
}
impl TpmCommand for StartupCmd {
    const CMD_CODE: TpmCc = TpmCc::Startup;
    type Handles = ();
    type RespT = ();
    type RespHandles = ();
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct GetCapabilityCmd {
    pub capability: TpmCap,
    pub property: TpmPt,
    pub property_count: u32,
}
impl TpmCommand for GetCapabilityCmd {
    const CMD_CODE: TpmCc = TpmCc::GetCapability;
    type Handles = ();
    type RespT = GetCapabilityResp;
    type RespHandles = ();
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct GetCapabilityResp {
    pub more_data: TpmiYesNo,
    pub capability_data: TpmsCapabilityData,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct PcrReadCmd {
    pcr_selection_in: TpmlPcrSelection,
}
impl TpmCommand for PcrReadCmd {
    const CMD_CODE: TpmCc = TpmCc::PCRRead;
    type Handles = ();
    type RespT = PcrReadResp;
    type RespHandles = ();
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct PcrReadResp {
    pcr_update_counter: u32,
    pcr_selection_out: TpmlPcrSelection,
    pcr_values: TpmlDigest,
}
