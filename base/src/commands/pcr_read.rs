// =============================================================================
// USES
// =============================================================================

use crate::{commands::TpmCommand, types::*};
use tpm2_rs_marshal::Marshal;

// =============================================================================
// TYPES
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct PcrReadCmd {
    pcr_selection_in: TpmlPcrSelection,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshal)]
pub struct PcrReadResp {
    pcr_update_counter: u32,
    pcr_selection_out: TpmlPcrSelection,
    pcr_values: TpmlDigest,
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

impl TpmCommand for PcrReadCmd {
    const CMD_CODE: TPM2CC = TPM2CC::PCRRead;
    type Handles = ();
    type RespT = PcrReadResp;
    type RespHandles = ();
}
