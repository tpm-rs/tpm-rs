//! [TPM2.0 1.83] 11 Session Commands

use crate::commands::{Marshalable, TpmCommand};
use crate::constants::{TpmCc, TpmSe};
use crate::{
    Tpm2bEncryptedSecret, Tpm2bNonce, TpmiAlgHash, TpmiDhEntity, TpmiDhObject, TpmiShAuthSession,
    TpmtSymDefObject,
};

/// [TPM2.0 1.83] 11.1 TPM2_StartAuthSession (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct StartAuthSessionCmd {
    pub nonce_caller: Tpm2bNonce,
    pub encrypted_salt: Tpm2bEncryptedSecret,
    pub session_type: TpmSe,
    pub symmetric: TpmtSymDefObject,
    pub auth_hash: TpmiAlgHash,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Marshalable)]
pub struct StartAuthSessionHandles {
    pub tpm_key: TpmiDhObject,
    pub bind: TpmiDhEntity,
}

impl TpmCommand for StartAuthSessionCmd {
    const CMD_CODE: TpmCc = TpmCc::StartAuthSession;

    type Handles = StartAuthSessionHandles;
    type RespT = StartAuthSessionResp;
    type RespHandles = TpmiShAuthSession;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Marshalable)]
pub struct StartAuthSessionResp {
    pub nonce_tpm: Tpm2bNonce,
}

/// [TPM2.0 1.83] 11.2 TPM2_PolicyRestart (Command)
pub struct PolicyRestartCmd {}
