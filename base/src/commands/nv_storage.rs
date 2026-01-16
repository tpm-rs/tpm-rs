//! [TPM2.0 1.83] 31 Non-volatile Storage
use crate::commands::TpmCommand;
use crate::constants::*;
use crate::Marshalable;
use crate::{
    Tpm2bMaxNvBuffer, Tpm2bName, Tpm2bNvPublic, Tpm2bNvPublic2, TpmiRhNvAuth, TpmiRhNvIndex,
    TpmiRhPlatform, TpmiRhNvDefinedIndex, Tpm2bAuth, TpmiRhProvision, TpmsNvPublic
};

/// [TPM2.0 1.83] 31.3 TPM2_NV_DefineSpace (Command)
#[derive(Clone, Copy, Debug, Marshalable)]
pub struct NvDefineSpaceCmd {
    pub auth: Tpm2bAuth,
    pub public_info: Tpm2bNvPublic,
}

impl TpmCommand for NvDefineSpaceCmd {
    const CMD_CODE: TpmCc = TpmCc::NVDefineSpace;
    type Handles = TpmiRhProvision;
    type RespT = ();
    type RespHandles = ();
}

/// [TPM2.0 1.83] 31.4 TPM2_NV_UndefineSpace (Command)
#[derive(Clone, Copy, Debug, Marshalable)]
pub struct NvUndefineSpaceCmd {}

#[derive(Clone, Copy, Debug, Default, Marshalable)]
pub struct NvUndefineSpaceHandles {
    pub auth: TpmiRhProvision,
    pub nv_index: TpmiRhNvDefinedIndex,
}

impl TpmCommand for NvUndefineSpaceCmd {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpace;
    type Handles = NvUndefineSpaceHandles;
    type RespT = ();
    type RespHandles = ();
}

/// [TPM2.0 1.83] 31.5 TPM2_NV_UndefineSpaceSpecial (Command)
#[derive(Clone, Copy, Debug, Marshalable)]
pub struct NvUndefineSpaceSpecialCmd {}

#[derive(Clone, Copy, Debug, Default, Marshalable)]
pub struct NvUndefineSpaceSpecialHandles {
    pub nv_index: TpmiRhNvDefinedIndex,
    pub platform: TpmiRhPlatform,
}

impl TpmCommand for NvUndefineSpaceSpecialCmd {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
    type Handles = NvUndefineSpaceSpecialHandles;
    type RespT = ();
    type RespHandles = ();
}

/// [TPM2.0 1.83] 31.6 TPM2_NV_ReadPublic (Command)
#[derive(Clone, Copy, Debug, Marshalable)]
pub struct NvReadPublicCmd {
    pub nv_index: TpmiRhNvIndex,
}

/// [TPM2.0 1.83] 31.6 TPM2_NV_ReadPublic (Response)
#[derive(Clone, Copy, Debug, Marshalable)]
pub struct NvReadPublicResp {
    pub nv_public: Tpm2bNvPublic,
    pub nv_name: Tpm2bName,
}

impl TpmCommand for NvReadPublicCmd {
    const CMD_CODE: TpmCc = TpmCc::NVReadPublic;
    type Handles = ();
    type RespT = NvReadPublicResp;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 31.7 TPM2_NV_Write (Command)
#[derive(Clone, Copy, Debug, Marshalable)]
pub struct NvWriteCmd {
    pub data: Tpm2bMaxNvBuffer,
    pub offset: u16,
}

#[derive(Clone, Copy, Debug, Default, Marshalable)]
pub struct NvWriteHandles {
    pub auth: TpmiRhNvAuth,
    pub nv_index: TpmiRhNvIndex,
}

impl TpmCommand for NvWriteCmd {
    const CMD_CODE: TpmCc = TpmCc::NVWrite;
    type Handles = NvWriteHandles;
    type RespT = ();
    type RespHandles = ();
}

/// [TPM2.0 1.83] 31.8 TPM2_NV_Increment (Command)
pub struct NvIncrementCmd {}

/// [TPM2.0 1.83] 31.9 TPM2_NV_Extend (Command)
pub struct NvExtendCmd {}

/// [TPM2.0 1.83] 31.10 TPM2_NV_SetBits (Command)
pub struct NvSetBitsCmd {}

/// [TPM2.0 1.83] 31.11 TPM2_NV_WriteLock (Command)
pub struct NvWriteLockCmd {}

/// [TPM2.0 1.83] 31.12 TPM2_NV_GlobalWriteLock (Command)
pub struct NvGlobalWriteLockCmd {}

/// [TPM2.0 1.83] 31.13 TPM2_NV_Read (Command)
#[derive(Clone, Copy, Debug, Marshalable)]
pub struct NvReadCmd {
    pub nv_index: TpmiRhNvIndex,
    pub size: u16,
    pub offset: u16,
}

/// [TPM2.0 1.83] 31.13 TPM2_NV_Read (Response)
#[derive(Clone, Copy, Debug, Marshalable)]
pub struct NvReadResp {
    pub data: Tpm2bMaxNvBuffer,
}

impl TpmCommand for NvReadCmd {
    const CMD_CODE: TpmCc = TpmCc::NVRead;
    type Handles = TpmiRhNvAuth;
    type RespT = NvReadResp;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 31.14 TPM2_NV_ReadLock (Command)
pub struct NvReadLockCmd {}

/// [TPM2.0 1.83] 31.15 TPM2_NV_ChangeAuth (Command)
pub struct NvChangeAuthCmd {}

/// [TPM2.0 1.83] 31.16 TPM2_NV_Certify (Command)
pub struct NvCertifyCmd {}

/// [TPM2.0 1.83] 31.17 TPM2_NV_DefineSpace2 (Command)
pub struct NvDefineSpace2Cmd {}

/// [TPM2.0 1.83] 31.18 TPM2_NV_ReadPublic2 (Command)
#[derive(Clone, Copy, Debug, Marshalable)]
pub struct NvReadPublic2Cmd {
    pub nv_index: TpmiRhNvIndex,
}

/// [TPM2.0 1.83] 31.18 TPM2_NV_ReadPublic2 (Response)
#[derive(Clone, Copy, Debug, Marshalable)]
pub struct NvReadPublic2Resp {
    pub nv_public: Tpm2bNvPublic2,
    pub nv_name: Tpm2bName,
}

impl TpmCommand for NvReadPublic2Cmd {
    const CMD_CODE: TpmCc = TpmCc::NVReadPublic2;
    type Handles = ();
    type RespT = NvReadPublic2Resp;
    type RespHandles = ();
}
