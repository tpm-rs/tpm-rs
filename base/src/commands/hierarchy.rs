//! [TPM2.0 1.83] 24 Hierarchy Commands

use crate::{commands::*, *};

// Defined by TCG EK Credential Profile 2.0.
// This is the PolicyOR of PolicyA and PolicyC.
// PolicyA is empty digest | PolicySecret | endorsement hierarchy.
// PolicyC is empty digest | PolicyAuthorizeNV | Name of index I-1
// Index I-1 is 0x01C07F01 with name alg SHA256, auth policy PolicyASha256,
// and attributes NV_POLICYWRITE | NV_WRITEALL | NV_PPREAD | NV_OWNERREAD
// | NV_AUTHREAD | NV_POLICYREAD | NV_NODA | NV_WRITTEN
const POLICY_B_SHA256: [u8; 32] = [
    0xca, 0x3d, 0x0a, 0x99, 0xa2, 0xb9, 0x39, 0x06, 0xf7, 0xa3, 0x34, 0x24, 0x14, 0xef, 0xcf, 0xb3,
    0xa3, 0x85, 0xd4, 0x4c, 0xd1, 0xfd, 0x45, 0x90, 0x89, 0xd1, 0x9b, 0x50, 0x71, 0xc0, 0xb7, 0xa0,
];

/// [TPM2.0 1.83] 24.1 TPM2_CreatePrimary (Command)
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct CreatePrimaryCmd {
    pub primary_handle: TpmHandle,
    pub sensitive: TpmsSensitiveCreate,
    pub public: TpmtPublic,
    pub outside_data: Tpm2bData,
    pub creation_pcr: TpmlPcrSelection,
}

/// [TPM2.0 1.83] 24.1 TPM2_CreatePrimary (Response)
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct CreatePrimaryResp {
    pub public: TpmtPublic,
    pub creation_data: TpmsCreationData,
    pub creation_hash: Tpm2bDigest,
    pub creation_ticket: TpmtTkCreation,
    pub creation_name: Tpm2bName,
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

impl Default for CreatePrimaryCmd {
    fn default() -> Self {
        // Default CreatePrimary is for the most common endorsement key template, which is
        // in the EK Credential Profile 2.0 for Default EK template H-1.
        CreatePrimaryCmd {
            primary_handle: TpmHandle::RHEndorsement,
            sensitive: TpmsSensitiveCreate::default(),
            public: TpmtPublic {
                name_alg: TpmiAlgHash::SHA256,
                object_attributes: TpmaObject::FIXED_TPM
                    | TpmaObject::FIXED_PARENT
                    | TpmaObject::SENSITIVE_DATA_ORIGIN
                    | TpmaObject::USER_WITH_AUTH
                    | TpmaObject::ADMIN_WITH_POLICY
                    | TpmaObject::RESTRICTED
                    | TpmaObject::DECRYPT,
                auth_policy: Tpm2bDigest {
                    size: 32,
                    buffer: {
                        let mut buffer = [0u8; 64];
                        buffer.copy_from_slice(&POLICY_B_SHA256[..]);
                        buffer
                    },
                },
                parms_and_id: PublicParmsAndId::Rsa(
                    TpmsRsaParms {
                        symmetric: TpmtSymDefObject::Aes(TpmiAesKeyBits(128), TpmiAlgSymMode::CFB),
                        scheme: TpmtRsaScheme::Null(TpmsEmpty {}),
                        key_bits: TpmiRsaKeyBits(2048),
                        exponent: 0,
                    },
                    Tpm2bPublicKeyRsa {
                        size: 256,
                        buffer: [0; 512],
                    },
                ),
            },
            outside_data: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        }
    }
}

impl TpmCommand for CreatePrimaryCmd {
    const CMD_CODE: TpmCc = TpmCc::CreatePrimary;
    type Handles = CreatePrimaryCmd;
    type RespT = CreatePrimaryResp;
    type RespHandles = TpmHandle;
}
