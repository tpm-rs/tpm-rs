//! [TPM2.0 1.83] 9 Start-up
use crate::commands::{Marshalable, TpmCommandProps};
use crate::constants::{TpmCc, TpmSu};

/// [TPM2.0 1.83] 9.2 _TPM_Init
pub struct InitCmd {}

/// [TPM2.0 1.83] 9.3 TPM2_Startup (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct StartupCmd {
    pub startup_type: TpmSu,
}
impl TpmCommandProps for StartupCmd {
    const CMD_CODE: TpmCc = TpmCc::Startup;
    type Handles = ();
    type RespT = ();
    type RespHandles = ();
}

/// [TPM2.0 1.83] 9.4 TPM2_Shutdown (Command)
pub struct ShutdownCmd {}
