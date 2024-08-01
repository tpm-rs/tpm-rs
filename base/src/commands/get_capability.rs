// =============================================================================
// USES
// =============================================================================

use crate::{commands::TpmCommand, types::*};
use tpm2_rs_marshal::Marshal;

// =============================================================================
// TYPES
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct GetCapabilityCmd {
    pub capability: TPM2Cap,
    pub property: TPM2PT,
    pub property_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct GetCapabilityResp {
    pub more_data: TpmiYesNo,
    pub capability_data: TpmsCapabilityData,
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

impl TpmCommand for GetCapabilityCmd {
    const CMD_CODE: TPM2CC = TPM2CC::GetCapability;
    type Handles = ();
    type RespT = GetCapabilityResp;
    type RespHandles = ();
}
