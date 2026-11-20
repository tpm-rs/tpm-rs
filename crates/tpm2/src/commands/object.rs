//! TPM 2.0 Object Commands
//!
//! This module implements the "Object Commands" commands defined in
//! **Section 12** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_Create (Command)
#[doc(alias = "TPM2_Create")]
#[doc(alias = "Create_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Create<'a> {
    pub parent_handle: NamedHandle<'a>,
    pub in_sensitive: Tpm2bSensitiveCreate<'a>,
    pub in_public: Tpm2bPublic<'a>,
    pub outside_info: Tpm2bData<'a>,
    pub creation_pcr: TpmlPcrSelection,
}
/// TPM2_Create (Response)
#[doc(alias = "Create_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct CreateRsp<'a> {
    pub out_private: Tpm2bPrivate<'a>,
    pub out_public: Tpm2bPublic<'a>,
    pub creation_data: Tpm2bCreationData<'a>,
    pub creation_hash: Tpm2bDigest<'a>,
    pub creation_ticket: TpmtTkCreation<'a>,
}

impl Command for Create<'_> {
    const CMD_CODE: TpmCc = TpmCc::Create;
    type Response<'a> = CreateRsp<'a>;
}
impl Message for Create<'_> {
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.parent_handle]
    }
}
impl Marshal for Create<'_> {
    const MAX_SIZE: usize = Tpm2bSensitiveCreate::MAX_SIZE
        + Tpm2bPublic::MAX_SIZE
        + Tpm2bData::MAX_SIZE
        + TpmlPcrSelection::MAX_SIZE;
    type MaxBuffer = [u8; Create::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_sensitive, dst, 0);
        let count = marshal_helper(&self.in_public, dst, count);
        let count = marshal_helper(&self.outside_info, dst, count);
        marshal_helper(&self.creation_pcr, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for Create<'a> {
    fn unmarshal_with_handles(
        [parent_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            parent_handle,
            in_sensitive: Unmarshal::unmarshal(src)?,
            in_public: Unmarshal::unmarshal(src)?,
            outside_info: Unmarshal::unmarshal(src)?,
            creation_pcr: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for CreateRsp<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for CreateRsp<'_> {
    const MAX_SIZE: usize = Tpm2bPrivate::MAX_SIZE
        + Tpm2bPublic::MAX_SIZE
        + Tpm2bCreationData::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + TpmtTkCreation::MAX_SIZE;
    type MaxBuffer = [u8; CreateRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_private, dst, 0);
        let count = marshal_helper(&self.out_public, dst, count);
        let count = marshal_helper(&self.creation_data, dst, count);
        let count = marshal_helper(&self.creation_hash, dst, count);
        marshal_helper(&self.creation_ticket, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for CreateRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_private: Unmarshal::unmarshal(src)?,
            out_public: Unmarshal::unmarshal(src)?,
            creation_data: Unmarshal::unmarshal(src)?,
            creation_hash: Unmarshal::unmarshal(src)?,
            creation_ticket: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_Load (Command)
#[doc(alias = "TPM2_Load")]
#[doc(alias = "Load_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Load<'a> {
    pub parent_handle: NamedHandle<'a>,
    pub in_private: Tpm2bPrivate<'a>,
    pub in_public: Tpm2bPublic<'a>,
}
/// TPM2_Load (Response)
#[doc(alias = "Load_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct LoadRsp<'a> {
    pub object_handle: Handle,
    pub name: Tpm2bName<'a>,
}

impl<'a> LoadRsp<'a> {
    /// Returns the loaded object's [`NamedHandle`].
    pub const fn named_handle(&self) -> NamedHandle<'a> {
        NamedHandle::new(self.object_handle, self.name)
    }
}

impl Command for Load<'_> {
    const CMD_CODE: TpmCc = TpmCc::Load;
    type Response<'a> = LoadRsp<'a>;
}
impl Message for Load<'_> {
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.parent_handle]
    }
}
impl Marshal for Load<'_> {
    const MAX_SIZE: usize = Tpm2bPrivate::MAX_SIZE + Tpm2bPublic::MAX_SIZE;
    type MaxBuffer = [u8; Load::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_private, dst, 0);
        marshal_helper(&self.in_public, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for Load<'a> {
    fn unmarshal_with_handles(
        [parent_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            parent_handle,
            in_private: Unmarshal::unmarshal(src)?,
            in_public: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for LoadRsp<'_> {
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.object_handle.into()]
    }
}
impl Marshal for LoadRsp<'_> {
    const MAX_SIZE: usize = Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; LoadRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.name.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for LoadRsp<'a> {
    fn unmarshal_with_handles(
        [object_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: object_handle.handle,
            name: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ReadPublic (Command)
#[doc(alias = "TPM2_ReadPublic")]
#[doc(alias = "ReadPublic_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ReadPublic<'a> {
    pub object_handle: NamedHandle<'a>,
}
/// TPM2_ReadPublic (Response)
#[doc(alias = "ReadPublic_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ReadPublicRsp<'a> {
    pub out_public: Tpm2bPublic<'a>,
    pub name: Tpm2bName<'a>,
    pub qualified_name: Tpm2bName<'a>,
}

impl Command for ReadPublic<'_> {
    const CMD_CODE: TpmCc = TpmCc::ReadPublic;
    type Response<'a> = ReadPublicRsp<'a>;
}
impl Message for ReadPublic<'_> {
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.object_handle]
    }
}
impl Marshal for ReadPublic<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for ReadPublic<'a> {
    fn unmarshal_with_handles(
        [object_handle]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { object_handle })
    }
}

impl Message for ReadPublicRsp<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for ReadPublicRsp<'_> {
    const MAX_SIZE: usize = Tpm2bPublic::MAX_SIZE + Tpm2bName::MAX_SIZE + Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; ReadPublicRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_public, dst, 0);
        let count = marshal_helper(&self.name, dst, count);
        marshal_helper(&self.qualified_name, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for ReadPublicRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_public: Unmarshal::unmarshal(src)?,
            name: Unmarshal::unmarshal(src)?,
            qualified_name: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ActivateCredential (Command)
#[doc(alias = "TPM2_ActivateCredential")]
#[doc(alias = "ActivateCredential_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ActivateCredential<'a> {
    pub activate_handle: NamedHandle<'a>,
    pub key_handle: NamedHandle<'a>,
    pub credential_blob: Tpm2bIdObject<'a>,
    pub secret: Tpm2bEncryptedSecret<'a>,
}
/// TPM2_ActivateCredential (Response)
#[doc(alias = "ActivateCredential_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ActivateCredentialRsp<'a> {
    pub cert_info: Tpm2bDigest<'a>,
}

impl Command for ActivateCredential<'_> {
    const CMD_CODE: TpmCc = TpmCc::ActivateCredential;
    type Response<'a> = ActivateCredentialRsp<'a>;
}
impl Message for ActivateCredential<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.activate_handle, self.key_handle]
    }
}
impl Marshal for ActivateCredential<'_> {
    const MAX_SIZE: usize = Tpm2bIdObject::MAX_SIZE + Tpm2bEncryptedSecret::MAX_SIZE;
    type MaxBuffer = [u8; ActivateCredential::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.credential_blob, dst, 0);
        marshal_helper(&self.secret, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for ActivateCredential<'a> {
    fn unmarshal_with_handles(
        [activate_handle, key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            activate_handle,
            key_handle,
            credential_blob: Unmarshal::unmarshal(src)?,
            secret: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for ActivateCredentialRsp<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for ActivateCredentialRsp<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; ActivateCredentialRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.cert_info.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ActivateCredentialRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            cert_info: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_MakeCredential (Command)
#[doc(alias = "TPM2_MakeCredential")]
#[doc(alias = "MakeCredential_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct MakeCredential<'a> {
    pub handle: NamedHandle<'a>,
    pub credential: Tpm2bDigest<'a>,
    pub object_name: Tpm2bName<'a>,
}
/// TPM2_MakeCredential (Response)
#[doc(alias = "MakeCredential_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct MakeCredentialRsp<'a> {
    pub credential_blob: Tpm2bIdObject<'a>,
    pub secret: Tpm2bEncryptedSecret<'a>,
}

impl Command for MakeCredential<'_> {
    const CMD_CODE: TpmCc = TpmCc::MakeCredential;
    type Response<'a> = MakeCredentialRsp<'a>;
}
impl Message for MakeCredential<'_> {
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.handle]
    }
}
impl Marshal for MakeCredential<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; MakeCredential::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.credential, dst, 0);
        marshal_helper(&self.object_name, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for MakeCredential<'a> {
    fn unmarshal_with_handles(
        [handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            handle,
            credential: Unmarshal::unmarshal(src)?,
            object_name: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for MakeCredentialRsp<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for MakeCredentialRsp<'_> {
    const MAX_SIZE: usize = Tpm2bIdObject::MAX_SIZE + Tpm2bEncryptedSecret::MAX_SIZE;
    type MaxBuffer = [u8; MakeCredentialRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.credential_blob, dst, 0);
        marshal_helper(&self.secret, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for MakeCredentialRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            credential_blob: Unmarshal::unmarshal(src)?,
            secret: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_Unseal (Command)
#[doc(alias = "TPM2_Unseal")]
#[doc(alias = "Unseal_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Unseal<'a> {
    pub item_handle: NamedHandle<'a>,
}
/// TPM2_Unseal (Response)
#[doc(alias = "Unseal_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct UnsealRsp<'a> {
    pub out_data: Tpm2bSensitiveData<'a>,
}

impl Command for Unseal<'_> {
    const CMD_CODE: TpmCc = TpmCc::Unseal;
    type Response<'a> = UnsealRsp<'a>;
}
impl Message for Unseal<'_> {
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.item_handle]
    }
}
impl Marshal for Unseal<'_> {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for Unseal<'a> {
    fn unmarshal_with_handles(
        [item_handle]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { item_handle })
    }
}

impl Message for UnsealRsp<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for UnsealRsp<'_> {
    const MAX_SIZE: usize = Tpm2bSensitiveData::MAX_SIZE;
    type MaxBuffer = [u8; UnsealRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_data.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for UnsealRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_data: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ObjectChangeAuth (Command)
#[doc(alias = "TPM2_ObjectChangeAuth")]
#[doc(alias = "ObjectChangeAuth_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ObjectChangeAuth<'a> {
    pub object_handle: NamedHandle<'a>,
    pub parent_handle: NamedHandle<'a>,
    pub new_auth: Tpm2bAuth<'a>,
}
/// TPM2_ObjectChangeAuth (Response)
#[doc(alias = "ObjectChangeAuth_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ObjectChangeAuthRsp<'a> {
    pub out_private: Tpm2bPrivate<'a>,
}

impl Command for ObjectChangeAuth<'_> {
    const CMD_CODE: TpmCc = TpmCc::ObjectChangeAuth;
    type Response<'a> = ObjectChangeAuthRsp<'a>;
}
impl Message for ObjectChangeAuth<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.object_handle, self.parent_handle]
    }
}
impl Marshal for ObjectChangeAuth<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE;
    type MaxBuffer = [u8; ObjectChangeAuth::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.new_auth.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ObjectChangeAuth<'a> {
    fn unmarshal_with_handles(
        [object_handle, parent_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle,
            parent_handle,
            new_auth: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for ObjectChangeAuthRsp<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for ObjectChangeAuthRsp<'_> {
    const MAX_SIZE: usize = Tpm2bPrivate::MAX_SIZE;
    type MaxBuffer = [u8; ObjectChangeAuthRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_private.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ObjectChangeAuthRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_private: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_LoadExternal (Command)
#[doc(alias = "TPM2_LoadExternal")]
#[doc(alias = "LoadExternal_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct LoadExternal<'a> {
    pub in_private: Option<Tpm2bSensitive<'a>>,
    pub in_public: Tpm2bPublic<'a>,
    pub hierarchy: Handle,
}
/// TPM2_LoadExternal (Response)
#[doc(alias = "LoadExternal_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct LoadExternalRsp<'a> {
    pub object_handle: Handle,
    pub name: Tpm2bName<'a>,
}

impl<'a> LoadExternalRsp<'a> {
    /// Returns the loaded external object's [`NamedHandle`].
    pub const fn named_handle(&self) -> NamedHandle<'a> {
        NamedHandle::new(self.object_handle, self.name)
    }
}

impl Command for LoadExternal<'_> {
    const CMD_CODE: TpmCc = TpmCc::LoadExternal;
    type Response<'a> = LoadExternalRsp<'a>;
}
impl Message for LoadExternal<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for LoadExternal<'_> {
    const MAX_SIZE: usize =
        <Option<Tpm2bSensitive>>::MAX_SIZE + Tpm2bPublic::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; LoadExternal::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_private, dst, 0);
        let count = marshal_helper(&self.in_public, dst, count);
        marshal_helper(&self.hierarchy, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for LoadExternal<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            in_private: Unmarshal::unmarshal(src)?,
            in_public: Unmarshal::unmarshal(src)?,
            hierarchy: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for LoadExternalRsp<'_> {
    const NUM_HANDLES: usize = 1;
    type Handles<'a>
        = [NamedHandle<'a>; 1]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.object_handle.into()]
    }
}
impl Marshal for LoadExternalRsp<'_> {
    const MAX_SIZE: usize = Tpm2bName::MAX_SIZE;
    type MaxBuffer = [u8; LoadExternalRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.name.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for LoadExternalRsp<'a> {
    fn unmarshal_with_handles(
        [object_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: object_handle.handle,
            name: Unmarshal::unmarshal(src)?,
        })
    }
}
