//! [TPM2.0 1.83] 16 Random Number Generator

use crate::commands::{Marshalable, TpmCommand};
use crate::constants::TpmCc;
use crate::Tpm2bDigest;

/// [TPM2.0 1.83] 16.1 TPM2_GetRandom (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct GetRandomCmd {
    pub bytes_requested: u16,
}
impl TpmCommand for GetRandomCmd {
    const CMD_CODE: TpmCc = TpmCc::GetRandom;
    type Handles = ();
    type RespT = GetRandomResp;
    type RespHandles = ();
}
/// [TPM2.0 1.83] 16.1 TPM2_GetRandom (Response)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct GetRandomResp {
    pub random_bytes: Tpm2bDigest,
}

/// [TPM2.0 1.83] 16.2 TPM2_StirRandom (Command)
pub struct StirRandomCmd {}
