//! [TPM2.0 1.83] 24 Hierarchy Commands

use crate::{*, commands::*};

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
	CreatePrimaryCmd {
	    primary_handle: TpmHandle::RHEndorsement,
	    sensitive: TpmsSensitiveCreate::default(),
	    public: TpmtPublic{
		name_alg: TpmiAlgHash::SHA256,
		object_attributes: TpmaObject(0x300b2),
		auth_policy: Tpm2bDigest{
		    size: 32,
		    buffer: {
			let mut base = [0; 64];
			base.copy_from_slice(&[
			    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5,
			    0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b,
			    0x33, 0x14, 0x69, 0xaa,
			]);
			base}},
		parms_and_id: PublicParmsAndId::Rsa(TpmsRsaParms{
		    symmetric: TpmtSymDefObject::Aes(TpmiAesKeyBits(128), TpmiAlgSymMode::CFB),
		    scheme: TpmtRsaScheme::Null(TpmsEmpty{}),
		    key_bits: TpmiRsaKeyBits(2048),
		    exponent: 0,
		}, Tpm2bPublicKeyRsa{size: 256, buffer: [0; 512]}),
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
