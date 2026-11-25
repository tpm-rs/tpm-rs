//! TPM 2.0 Hierarchy Commands
//!
//! This module implements the "Hierarchy Commands" commands defined in
//! **Section 24** of the TPM 2.0 Specification.
use super::{Command, Response, UnmarshalCommand, UnmarshalResponse};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_CreatePrimary (Command)
#[doc(alias = "TPM2_CreatePrimary")]
#[doc(alias = "CreatePrimary_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct CreatePrimary<'a> {
    pub primary_handle: Handle,
    pub in_sensitive: Tpm2bSensitiveCreate<'a>,
    pub in_public: Tpm2bPublic<'a>,
    pub outside_info: Tpm2bData<'a>,
    pub creation_pcr: TpmlPcrSelection,
}
/// TPM2_CreatePrimary (Response)
#[doc(alias = "CreatePrimary_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct CreatePrimaryRsp<'a> {
    pub object_handle: Handle,
    pub out_public: Tpm2bPublic<'a>,
    pub creation_data: Tpm2bCreationData<'a>,
    pub creation_hash: Tpm2bDigest<'a>,
    pub creation_ticket: TpmtTkCreation<'a>,
    pub name: Name<'a>,
}

impl Command for CreatePrimary<'_> {
    const CMD_CODE: TpmCc = TpmCc::CreatePrimary;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = CreatePrimaryRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.primary_handle)]
    }
}
impl Marshal for CreatePrimary<'_> {
    const MAX_SIZE: usize = Tpm2bSensitiveCreate::MAX_SIZE
        + Tpm2bPublic::MAX_SIZE
        + Tpm2bData::MAX_SIZE
        + TpmlPcrSelection::MAX_SIZE;
    type MaxBuffer = [u8; CreatePrimary::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_sensitive, dst, 0);
        let count = marshal_helper(&self.in_public, dst, count);
        let count = marshal_helper(&self.outside_info, dst, count);
        marshal_helper(&self.creation_pcr, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for CreatePrimary<'a> {
    fn unmarshal_with_handles(
        [primary_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            primary_handle: primary_handle.try_into()?,
            in_sensitive: Unmarshal::unmarshal(src)?,
            in_public: Unmarshal::unmarshal(src)?,
            outside_info: Unmarshal::unmarshal(src)?,
            creation_pcr: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for CreatePrimaryRsp<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.object_handle]
    }
}
impl Marshal for CreatePrimaryRsp<'_> {
    const MAX_SIZE: usize = Tpm2bPublic::MAX_SIZE
        + Tpm2bCreationData::MAX_SIZE
        + Tpm2bDigest::MAX_SIZE
        + TpmtTkCreation::MAX_SIZE
        + Name::MAX_SIZE;
    type MaxBuffer = [u8; CreatePrimaryRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_public, dst, 0);
        let count = marshal_helper(&self.creation_data, dst, count);
        let count = marshal_helper(&self.creation_hash, dst, count);
        let count = marshal_helper(&self.creation_ticket, dst, count);
        marshal_helper(&self.name, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for CreatePrimaryRsp<'a> {
    fn unmarshal_with_handles(
        [object_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle,
            out_public: Unmarshal::unmarshal(src)?,
            creation_data: Unmarshal::unmarshal(src)?,
            creation_hash: Unmarshal::unmarshal(src)?,
            creation_ticket: Unmarshal::unmarshal(src)?,
            name: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_HierarchyControl (Command)
#[doc(alias = "TPM2_HierarchyControl")]
#[doc(alias = "HierarchyControl_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct HierarchyControl {
    pub auth_handle: Handle,
    pub enable: Handle,
    pub state: bool,
}

impl Command for HierarchyControl {
    const CMD_CODE: TpmCc = TpmCc::HierarchyControl;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.auth_handle)]
    }
}
impl Marshal for HierarchyControl {
    const MAX_SIZE: usize = Handle::MAX_SIZE + bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.enable, dst, 0);
        marshal_helper(&self.state, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for HierarchyControl {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: auth_handle.try_into()?,
            enable: Unmarshal::unmarshal(src)?,
            state: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_SetPrimaryPolicy (Command)
#[doc(alias = "TPM2_SetPrimaryPolicy")]
#[doc(alias = "SetPrimaryPolicy_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct SetPrimaryPolicy<'a> {
    pub auth_handle: Handle,
    pub auth_policy: Tpm2bDigest<'a>,
    pub hash_alg: Option<TpmiAlgHash>,
}

impl Command for SetPrimaryPolicy<'_> {
    const CMD_CODE: TpmCc = TpmCc::SetPrimaryPolicy;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.auth_handle)]
    }
}
impl Marshal for SetPrimaryPolicy<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; SetPrimaryPolicy::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_policy, dst, 0);
        marshal_helper(&self.hash_alg, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for SetPrimaryPolicy<'a> {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: auth_handle.try_into()?,
            auth_policy: Unmarshal::unmarshal(src)?,
            hash_alg: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ChangePPS (Command)
#[doc(alias = "TPM2_ChangePPS")]
#[doc(alias = "ChangePPS_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ChangePPS {
    pub auth_handle: Handle,
}

impl Command for ChangePPS {
    const CMD_CODE: TpmCc = TpmCc::ChangePPS;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.auth_handle)]
    }
}
impl Marshal for ChangePPS {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for ChangePPS {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: auth_handle.try_into()?,
        })
    }
}

/// TPM2_ChangeEPS (Command)
#[doc(alias = "TPM2_ChangeEPS")]
#[doc(alias = "ChangeEPS_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ChangeEPS {
    pub auth_handle: Handle,
}

impl Command for ChangeEPS {
    const CMD_CODE: TpmCc = TpmCc::ChangeEPS;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.auth_handle)]
    }
}
impl Marshal for ChangeEPS {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for ChangeEPS {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: auth_handle.try_into()?,
        })
    }
}

/// TPM2_Clear (Command)
#[doc(alias = "TPM2_Clear")]
#[doc(alias = "Clear_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Clear {
    pub auth_handle: Handle,
}

impl Command for Clear {
    const CMD_CODE: TpmCc = TpmCc::Clear;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.auth_handle)]
    }
}
impl Marshal for Clear {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for Clear {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: auth_handle.try_into()?,
        })
    }
}

/// TPM2_ClearControl (Command)
#[doc(alias = "TPM2_ClearControl")]
#[doc(alias = "ClearControl_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ClearControl {
    pub auth: Handle,
    pub disable: bool,
}

impl Command for ClearControl {
    const CMD_CODE: TpmCc = TpmCc::ClearControl;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.auth)]
    }
}
impl Marshal for ClearControl {
    const MAX_SIZE: usize = bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.disable.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for ClearControl {
    fn unmarshal_with_handles(
        [auth]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: auth.try_into()?,
            disable: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_HierarchyChangeAuth (Command)
#[doc(alias = "TPM2_HierarchyChangeAuth")]
#[doc(alias = "HierarchyChangeAuth_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct HierarchyChangeAuth<'a> {
    pub auth_handle: Handle,
    pub new_auth: Tpm2bAuth<'a>,
}

impl Command for HierarchyChangeAuth<'_> {
    const CMD_CODE: TpmCc = TpmCc::HierarchyChangeAuth;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.auth_handle)]
    }
}
impl Marshal for HierarchyChangeAuth<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE;
    type MaxBuffer = [u8; HierarchyChangeAuth::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.new_auth.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for HierarchyChangeAuth<'a> {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: auth_handle.try_into()?,
            new_auth: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ReadOnlyControl (Command)
#[doc(alias = "TPM2_ReadOnlyControl")]
#[doc(alias = "ReadOnlyControl_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ReadOnlyControl {
    pub auth_handle: Handle,
    pub state: bool,
}

impl Command for ReadOnlyControl {
    const CMD_CODE: TpmCc = TpmCc::ReadOnlyControl;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.auth_handle)]
    }
}
impl Marshal for ReadOnlyControl {
    const MAX_SIZE: usize = bool::MAX_SIZE;
    type MaxBuffer = [u8; ReadOnlyControl::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.state.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for ReadOnlyControl {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: auth_handle.try_into()?,
            state: Unmarshal::unmarshal(src)?,
        })
    }
}
