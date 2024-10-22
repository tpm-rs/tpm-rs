//! [TPM2.0 1.83] 22 Integrity Collection (PCR)

use crate::commands::{Marshalable, TpmCommand};
use crate::constants::TpmCc;
use crate::{TpmlDigest, TpmlPcrSelection};

/// [TPM2.0 1.83] 22.2 TPM2_PCR_Extend (Command)
pub struct PcrExtendCmd {}

/// [TPM2.0 1.83] 22.3 TPM2_PCR_Event (Command)
pub struct PcrEventCmd {}

/// [TPM2.0 1.83] 22.4 TPM2_PCR_Read (Command)
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
/// [TPM2.0 1.83] 22.4 TPM2_PCR_Read (Response)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct PcrReadResp {
    pcr_update_counter: u32,
    pcr_selection_out: TpmlPcrSelection,
    pcr_values: TpmlDigest,
}

/// [TPM2.0 1.83] 22.5 TPM2_PCR_Allocate (Command)
pub struct PcrAllocateCmd {}

/// [TPM2.0 1.83] 22.6 TPM2_PCR_SetAuthPolicy (Command)
pub struct PcrSetAuthPolicyCmd {}

/// [TPM2.0 1.83] 22.7 TPM2_PCR_SetAuthValue (Command)
pub struct PcrSetAuthValueCmd {}

/// [TPM2.0 1.83] 22.8 TPM2_PCR_Reset (Command)
pub struct PcrResetCmd {}

/// [TPM2.0 1.83] 22.9 _TPM_Hash_Start
pub struct HashStartCmd {}

/// [TPM2.0 1.83] 22.10 _TPM_Hash_Data
pub struct HashStartData {}

/// [TPM2.0 1.83] 22.11 _TPM_Hash_End
pub struct HashStartEnd {}
