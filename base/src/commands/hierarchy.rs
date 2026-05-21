//! [TPM2.0 1.83] 24 Hierarchy Commands

use crate::commands::{Marshalable, TpmCommand};
use crate::constants::{TpmCc, TpmHandle};
use crate::{
    Tpm2bCreationData, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bPublic, Tpm2bSensitiveCreate,
    TpmiRhHierarchy, TpmlPcrSelection, TpmtTkCreation,
};

/// [TPM2.0 1.83] 24.1 TPM2_CreatePrimary (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct CreatePrimaryCmd {
    pub in_sensitive: Tpm2bSensitiveCreate,
    pub in_public: Tpm2bPublic,
    pub outside_info: Tpm2bData,
    pub creation_pcr: TpmlPcrSelection,
}

impl TpmCommand for CreatePrimaryCmd {
    const CMD_CODE: TpmCc = TpmCc::CreatePrimary;

    type Handles = TpmiRhHierarchy;
    type RespT = CreatePrimaryResp;
    // Object handle of type TPM_HT_TRANSIENT.
    type RespHandles = TpmHandle;
}

/// [TPM2.0 1.83] 24.1 TPM2_CreatePrimary (Response)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug, Marshalable)]
pub struct CreatePrimaryResp {
    pub out_public: Tpm2bPublic,
    pub creation_data: Tpm2bCreationData,
    pub creation_hash: Tpm2bDigest,
    pub creation_ticket: TpmtTkCreation,
    pub name: Tpm2bName,
}

/// [TPM2.0 1.83] 24.2 TPM2_HierarchyControl (Command)
pub struct HierarchyControlCmd {}

/// [TPM2.0 1.83] 24.3 TPM2_SetPrimaryPolicy (Command)
pub struct SetPrimaryPolicyCmd {}

/// [TPM2.0 1.83] 24.4 TPM2_ChangePPS (Command)
pub struct ChangePpsCmd {}

/// [TPM2.0 1.83] 24.5 TPM2_ChangeEPS (Command)
pub struct ChangeEpsCmd {}

/// [TPM2.0 1.83] 24.6 TPM2_Clear (Command)
pub struct ClearCmd {}

/// [TPM2.0 1.83] 24.7 TPM2_ClearControl (Command)
pub struct ClearControlCmd {}

/// [TPM2.0 1.83] 24.8 TPM2_HierarchyChangeAuth (Command)
pub struct HierarchyChangeAuthCmd {}
