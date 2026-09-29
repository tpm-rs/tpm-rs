//! TPM 2.0 Object Commands
//!
//! This module implements the "Object Commands" defined in
//! **Section 12** of the TPM 2.0 Specification.
//!
//! These commands support creating, loading, clearing, and describing
//! TPM cryptographic keys and objects.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct CreateHandles {
    pub parent_handle: Handle,
}
impl Marshal for CreateHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.parent_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for CreateHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            parent_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 12.1 TPM2_Create (Command)
#[doc(alias = "TPM2_Create")]
#[doc(alias = "Create_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct Create<'a> {
    pub in_sensitive: crate::Tpm2bSensitiveCreate<'a>,
    pub in_public: crate::Tpm2bPublic<'a>,
    pub outside_info: crate::Tpm2bData<'a>,
    pub creation_pcr: crate::TpmlPcrSelection,
}
impl Marshal for Create<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bSensitiveCreate>::MAX_SIZE
        + <crate::Tpm2bPublic>::MAX_SIZE
        + <crate::Tpm2bData>::MAX_SIZE
        + <crate::TpmlPcrSelection>::MAX_SIZE;
    type MaxBuffer = [u8; Create::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_sensitive, dst, 0);
        let count = marshal_helper(&self.in_public, dst, count);
        let count = marshal_helper(&self.outside_info, dst, count);
        marshal_helper(&self.creation_pcr, dst, count)
    }
}

impl<'a> Unmarshal<'a> for Create<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            in_sensitive: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_public: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            outside_info: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            creation_pcr: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

/// [TPM2.0 1.83] 12.1 TPM2_Create (Response)
#[doc(alias = "Create_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CreateRsp<'a> {
    pub out_private: crate::Tpm2bPrivate<'a>,
    pub out_public: crate::Tpm2bPublic<'a>,
    pub creation_data: crate::Tpm2bCreationData<'a>,
    pub creation_hash: crate::Tpm2bDigest<'a>,
    pub creation_ticket: crate::TpmtTkCreation<'a>,
}
impl Marshal for CreateRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bPrivate>::MAX_SIZE
        + <crate::Tpm2bPublic>::MAX_SIZE
        + <crate::Tpm2bCreationData>::MAX_SIZE
        + <crate::Tpm2bDigest>::MAX_SIZE
        + <crate::TpmtTkCreation>::MAX_SIZE;
    type MaxBuffer = [u8; CreateRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_private, dst, 0);
        let count = marshal_helper(&self.out_public, dst, count);
        let count = marshal_helper(&self.creation_data, dst, count);
        let count = marshal_helper(&self.creation_hash, dst, count);
        marshal_helper(&self.creation_ticket, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CreateRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_private: Unmarshal::unmarshal(src)?,
            out_public: Unmarshal::unmarshal(src)?,
            creation_data: Unmarshal::unmarshal(src)?,
            creation_hash: Unmarshal::unmarshal(src)?,
            creation_ticket: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for Create<'_> {
    const CMD_CODE: TpmCc = TpmCc::Create;
    type Handles = CreateHandles;
    type Response<'a> = CreateRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct LoadHandles {
    pub parent_handle: Handle,
}
impl Marshal for LoadHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.parent_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for LoadHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            parent_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 12.2 TPM2_Load (Command)
#[doc(alias = "TPM2_Load")]
#[doc(alias = "Load_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct Load<'a> {
    pub in_private: crate::Tpm2bPrivate<'a>,
    pub in_public: crate::Tpm2bPublic<'a>,
}
impl Marshal for Load<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bPrivate>::MAX_SIZE + <crate::Tpm2bPublic>::MAX_SIZE;
    type MaxBuffer = [u8; Load::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_private, dst, 0);
        marshal_helper(&self.in_public, dst, count)
    }
}

impl<'a> Unmarshal<'a> for Load<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            in_private: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_public: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct LoadRespHandles {
    pub object_handle: Handle,
}
impl Marshal for LoadRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.object_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for LoadRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: TpmiDhObject::<false>::unmarshal(src)?.0,
        })
    }
}

/// [TPM2.0 1.83] 12.2 TPM2_Load (Response)
#[doc(alias = "Load_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct LoadRsp<'a> {
    pub name: crate::Tpm2bName<'a>,
}
impl Marshal for LoadRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bName>::MAX_SIZE;
    type MaxBuffer = [u8; LoadRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.name.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for LoadRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            name: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for Load<'_> {
    const CMD_CODE: TpmCc = TpmCc::Load;
    type Handles = LoadHandles;
    type Response<'a> = LoadRsp<'a>;
    type RespHandles = LoadRespHandles;
}

/// [TPM2.0 1.83] 12.3 TPM2_LoadExternal (Command)
#[doc(alias = "TPM2_LoadExternal")]
#[doc(alias = "LoadExternal_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct LoadExternal<'a> {
    pub in_private: Option<crate::Tpm2bSensitive<'a>>,
    pub in_public: crate::Tpm2bPublic<'a>,
    pub hierarchy: Handle,
}
impl Marshal for LoadExternal<'_> {
    const MAX_SIZE: usize = <Option<crate::Tpm2bSensitive>>::MAX_SIZE
        + <crate::Tpm2bPublic>::MAX_SIZE
        + Handle::MAX_SIZE;
    type MaxBuffer = [u8; LoadExternal::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_private, dst, 0);
        let count = marshal_helper(&self.in_public, dst, count);
        marshal_helper(&self.hierarchy, dst, count)
    }
}

impl<'a> Unmarshal<'a> for LoadExternal<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            in_private: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_public: crate::Tpm2bPublic::unmarshal_nullable(src)
                .map_err(|e| e.in_parameter(2))?,
            hierarchy: TpmiRhHierarchy::unmarshal(src)
                .map_err(|e| e.in_parameter(3))?
                .0,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct LoadExternalRespHandles {
    pub object_handle: Handle,
}
impl Marshal for LoadExternalRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.object_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for LoadExternalRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: TpmiDhObject::<false>::unmarshal(src)?.0,
        })
    }
}

/// [TPM2.0 1.83] 12.3 TPM2_LoadExternal (Response)
#[doc(alias = "LoadExternal_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct LoadExternalRsp<'a> {
    pub name: crate::Tpm2bName<'a>,
}
impl Marshal for LoadExternalRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bName>::MAX_SIZE;
    type MaxBuffer = [u8; LoadExternalRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.name.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for LoadExternalRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            name: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for LoadExternal<'_> {
    const CMD_CODE: TpmCc = TpmCc::LoadExternal;
    type Handles = ();
    type Response<'a> = LoadExternalRsp<'a>;
    type RespHandles = LoadExternalRespHandles;
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ReadPublicHandles {
    pub object_handle: Handle,
}
impl Marshal for ReadPublicHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.object_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ReadPublicHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 12.4 TPM2_ReadPublic (Command)
#[doc(alias = "TPM2_ReadPublic")]
#[doc(alias = "ReadPublic_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ReadPublic {}
impl Marshal for ReadPublic {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for ReadPublic {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

/// [TPM2.0 1.83] 12.4 TPM2_ReadPublic (Response)
#[doc(alias = "ReadPublic_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ReadPublicRsp<'a> {
    pub out_public: crate::Tpm2bPublic<'a>,
    pub name: crate::Tpm2bName<'a>,
    pub qualified_name: crate::Tpm2bName<'a>,
}
impl Marshal for ReadPublicRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bPublic>::MAX_SIZE
        + <crate::Tpm2bName>::MAX_SIZE
        + <crate::Tpm2bName>::MAX_SIZE;
    type MaxBuffer = [u8; ReadPublicRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_public, dst, 0);
        let count = marshal_helper(&self.name, dst, count);
        marshal_helper(&self.qualified_name, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ReadPublicRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_public: crate::Tpm2bPublic::unmarshal_nullable(src)?,
            name: Unmarshal::unmarshal(src)?,
            qualified_name: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ReadPublic {
    const CMD_CODE: TpmCc = TpmCc::ReadPublic;
    type Handles = ReadPublicHandles;
    type Response<'a> = ReadPublicRsp<'a>;
    type RespHandles = ();
}

///
/// Handles for TPM2_ActivateCredential command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ActivateCredentialHandles {
    /// Handle of the object associated with the credential (typically an AK).
    pub activate_handle: Handle,
    /// Handle of the key (typically an endorsement key or storage parent key) used to decrypt the credential.
    pub key_handle: Handle,
}
impl Marshal for ActivateCredentialHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.activate_handle, dst, 0);
        marshal_helper(&self.key_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ActivateCredentialHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            activate_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 12.5 TPM2_ActivateCredential (Command)
#[doc(alias = "TPM2_ActivateCredential")]
#[doc(alias = "ActivateCredential_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ActivateCredential<'a> {
    /// The credential block. Contains the wrapped (encrypted) credential information.
    pub credential_blob: crate::Tpm2bIdObject<'a>,
    /// The encrypted secret used to decrypt the credential blob.
    pub secret: crate::Tpm2bEncryptedSecret<'a>,
}
impl Marshal for ActivateCredential<'_> {
    const MAX_SIZE: usize =
        <crate::Tpm2bIdObject>::MAX_SIZE + <crate::Tpm2bEncryptedSecret>::MAX_SIZE;
    type MaxBuffer = [u8; ActivateCredential::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.credential_blob, dst, 0);
        marshal_helper(&self.secret, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ActivateCredential<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            credential_blob: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            secret: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

/// [TPM2.0 1.83] 12.5 TPM2_ActivateCredential (Response)
#[doc(alias = "ActivateCredential_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ActivateCredentialRsp<'a> {
    /// The decrypted credential data (typically a symmetric key or a direct challenge/response).
    pub cert_info: crate::Tpm2bDigest<'a>,
}
impl Marshal for ActivateCredentialRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bDigest>::MAX_SIZE;
    type MaxBuffer = [u8; ActivateCredentialRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.cert_info.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ActivateCredentialRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            cert_info: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ActivateCredential<'_> {
    const CMD_CODE: TpmCc = TpmCc::ActivateCredential;
    type Handles = ActivateCredentialHandles;
    type Response<'a> = ActivateCredentialRsp<'a>;
    type RespHandles = ();
}

///
/// Handles for TPM2_MakeCredential command.
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct MakeCredentialHandles {
    /// Handle of the key (protector key, e.g., EK) used to encrypt the credential.
    pub handle: Handle,
}
impl Marshal for MakeCredentialHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for MakeCredentialHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 12.6 TPM2_MakeCredential (Command)
#[doc(alias = "TPM2_MakeCredential")]
#[doc(alias = "MakeCredential_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct MakeCredential<'a> {
    /// The credential information to be encrypted.
    pub credential: crate::Tpm2bDigest<'a>,
    /// The name of the target object for which the credential is created.
    pub object_name: crate::Tpm2bName<'a>,
}
impl Marshal for MakeCredential<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bDigest>::MAX_SIZE + <crate::Tpm2bName>::MAX_SIZE;
    type MaxBuffer = [u8; MakeCredential::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.credential, dst, 0);
        marshal_helper(&self.object_name, dst, count)
    }
}

impl<'a> Unmarshal<'a> for MakeCredential<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            credential: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            object_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

/// [TPM2.0 1.83] 12.6 TPM2_MakeCredential (Response)
#[doc(alias = "MakeCredential_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct MakeCredentialRsp<'a> {
    /// The encrypted credential block (contains the encrypted credential).
    pub credential_blob: crate::Tpm2bIdObject<'a>,
    /// The encrypted secret key (seed) that is used to derive the credential decryption key.
    pub secret: crate::Tpm2bEncryptedSecret<'a>,
}
impl Marshal for MakeCredentialRsp<'_> {
    const MAX_SIZE: usize =
        <crate::Tpm2bIdObject>::MAX_SIZE + <crate::Tpm2bEncryptedSecret>::MAX_SIZE;
    type MaxBuffer = [u8; MakeCredentialRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.credential_blob, dst, 0);
        marshal_helper(&self.secret, dst, count)
    }
}

impl<'a> Unmarshal<'a> for MakeCredentialRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            credential_blob: Unmarshal::unmarshal(src)?,
            secret: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for MakeCredential<'_> {
    const CMD_CODE: TpmCc = TpmCc::MakeCredential;
    type Handles = MakeCredentialHandles;
    type Response<'a> = MakeCredentialRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct UnsealHandles {
    pub item_handle: Handle,
}
impl Marshal for UnsealHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.item_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for UnsealHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            item_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 12.7 TPM2_Unseal (Command)
#[doc(alias = "TPM2_Unseal")]
#[doc(alias = "Unseal_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct Unseal {}
impl Marshal for Unseal {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for Unseal {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for Unseal {
    const CMD_CODE: TpmCc = TpmCc::Unseal;
    type Handles = UnsealHandles;
    type Response<'a> = UnsealRsp<'a>;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 12.7 TPM2_Unseal (Response)
#[doc(alias = "Unseal_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct UnsealRsp<'a> {
    pub out_data: crate::Tpm2bSensitiveData<'a>,
}
impl Marshal for UnsealRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bSensitiveData>::MAX_SIZE;
    type MaxBuffer = [u8; UnsealRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_data.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for UnsealRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_data: Unmarshal::unmarshal(src)?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ObjectChangeAuthHandles {
    pub object_handle: Handle,
    pub parent_handle: Handle,
}
impl Marshal for ObjectChangeAuthHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.object_handle, dst, 0);
        marshal_helper(&self.parent_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ObjectChangeAuthHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            parent_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 12.8 TPM2_ObjectChangeAuth (Command)
#[doc(alias = "TPM2_ObjectChangeAuth")]
#[doc(alias = "ObjectChangeAuth_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ObjectChangeAuth<'a> {
    pub new_auth: crate::Tpm2bAuth<'a>,
}
impl Marshal for ObjectChangeAuth<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bAuth>::MAX_SIZE;
    type MaxBuffer = [u8; ObjectChangeAuth::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.new_auth.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ObjectChangeAuth<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            new_auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 12.8 TPM2_ObjectChangeAuth (Response)
#[doc(alias = "ObjectChangeAuth_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ObjectChangeAuthRsp<'a> {
    pub out_private: crate::Tpm2bPrivate<'a>,
}
impl Marshal for ObjectChangeAuthRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bPrivate>::MAX_SIZE;
    type MaxBuffer = [u8; ObjectChangeAuthRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_private.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ObjectChangeAuthRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_private: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ObjectChangeAuth<'_> {
    const CMD_CODE: TpmCc = TpmCc::ObjectChangeAuth;
    type Handles = ObjectChangeAuthHandles;
    type Response<'a> = ObjectChangeAuthRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CreateLoadedHandles {
    pub parent_handle: Handle,
}
impl Marshal for CreateLoadedHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.parent_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for CreateLoadedHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            parent_handle: TpmiDhParent::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 12.9 TPM2_CreateLoaded (Command)
#[doc(alias = "TPM2_CreateLoaded")]
#[doc(alias = "CreateLoaded_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CreateLoaded<'a> {
    pub in_sensitive: crate::Tpm2bSensitiveCreate<'a>,
    pub in_public: crate::Tpm2bTemplate<'a>,
}
impl Marshal for CreateLoaded<'_> {
    const MAX_SIZE: usize =
        <crate::Tpm2bSensitiveCreate>::MAX_SIZE + <crate::Tpm2bTemplate>::MAX_SIZE;
    type MaxBuffer = [u8; CreateLoaded::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_sensitive, dst, 0);
        marshal_helper(&self.in_public, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CreateLoaded<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            in_sensitive: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_public: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CreateLoadedRespHandles {
    pub object_handle: Handle,
}
impl Marshal for CreateLoadedRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.object_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for CreateLoadedRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: TpmiDhObject::<false>::unmarshal(src)?.0,
        })
    }
}

/// [TPM2.0 1.83] 12.9 TPM2_CreateLoaded (Response)
#[doc(alias = "CreateLoaded_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CreateLoadedRsp<'a> {
    pub out_private: crate::Tpm2bPrivate<'a>,
    pub out_public: crate::Tpm2bPublic<'a>,
    pub name: crate::Tpm2bName<'a>,
}
impl Marshal for CreateLoadedRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bPrivate>::MAX_SIZE
        + <crate::Tpm2bPublic>::MAX_SIZE
        + <crate::Tpm2bName>::MAX_SIZE;
    type MaxBuffer = [u8; CreateLoadedRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_private, dst, 0);
        let count = marshal_helper(&self.out_public, dst, count);
        marshal_helper(&self.name, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CreateLoadedRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_private: Unmarshal::unmarshal(src)?,
            out_public: Unmarshal::unmarshal(src)?,
            name: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for CreateLoaded<'_> {
    const CMD_CODE: TpmCc = TpmCc::CreateLoaded;
    type Handles = CreateLoadedHandles;
    type Response<'a> = CreateLoadedRsp<'a>;
    type RespHandles = CreateLoadedRespHandles;
}
