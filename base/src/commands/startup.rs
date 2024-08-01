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
pub struct StartupCmd {
    pub startup_type: TPM2SU,
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

impl TpmCommand for StartupCmd {
    const CMD_CODE: TPM2CC = TPM2CC::Startup;
    type Handles = ();
    type RespT = ();
    type RespHandles = ();
}
