//! TPM 2.0 Hierarchy Commands
//!
//! This module implements the "Hierarchy Commands" defined in
//! **Section 24** of the TPM 2.0 Specification.
//!
//! These commands manage TPM authorization hierarchies (Owner, Platform, Endorsement, Null)
//! and support creating primary objects within them.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CreatePrimaryHandles {
    pub primary_handle: Handle,
}
impl Marshal for CreatePrimaryHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.primary_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for CreatePrimaryHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            primary_handle: TpmiRhHierarchy::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 24.1 TPM2_CreatePrimary (Command)
#[doc(alias = "TPM2_CreatePrimary")]
#[doc(alias = "CreatePrimary_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CreatePrimary<'a> {
    pub in_sensitive: crate::Tpm2bSensitiveCreate<'a>,
    pub in_public: crate::Tpm2bPublic<'a>,
    pub outside_info: crate::Tpm2bData<'a>,
    pub creation_pcr: crate::TpmlPcrSelection,
}
impl Marshal for CreatePrimary<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bSensitiveCreate>::MAX_SIZE
        + <crate::Tpm2bPublic>::MAX_SIZE
        + <crate::Tpm2bData>::MAX_SIZE
        + <crate::TpmlPcrSelection>::MAX_SIZE;
    type MaxBuffer = [u8; CreatePrimary::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.in_sensitive, dst, 0);
        let count = marshal_helper(&self.in_public, dst, count);
        let count = marshal_helper(&self.outside_info, dst, count);
        marshal_helper(&self.creation_pcr, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CreatePrimary<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            in_sensitive: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_public: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            outside_info: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            creation_pcr: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CreatePrimaryRespHandles {
    pub object_handle: Handle,
}
impl Marshal for CreatePrimaryRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.object_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for CreatePrimaryRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_handle: TpmiDhObject::<false>::unmarshal(src)?.0,
        })
    }
}

/// [TPM2.0 1.83] 24.1 TPM2_CreatePrimary (Response)
#[doc(alias = "CreatePrimary_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CreatePrimaryRsp<'a> {
    pub out_public: crate::Tpm2bPublic<'a>,
    pub creation_data: crate::Tpm2bCreationData<'a>,
    pub creation_hash: crate::Tpm2bDigest<'a>,
    pub creation_ticket: crate::TpmtTkCreation<'a>,
    pub name: crate::Tpm2bName<'a>,
}
impl Marshal for CreatePrimaryRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bPublic>::MAX_SIZE
        + <crate::Tpm2bCreationData>::MAX_SIZE
        + <crate::Tpm2bDigest>::MAX_SIZE
        + <crate::TpmtTkCreation>::MAX_SIZE
        + <crate::Tpm2bName>::MAX_SIZE;
    type MaxBuffer = [u8; CreatePrimaryRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_public, dst, 0);
        let count = marshal_helper(&self.creation_data, dst, count);
        let count = marshal_helper(&self.creation_hash, dst, count);
        let count = marshal_helper(&self.creation_ticket, dst, count);
        marshal_helper(&self.name, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CreatePrimaryRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_public: Unmarshal::unmarshal(src)?,
            creation_data: Unmarshal::unmarshal(src)?,
            creation_hash: Unmarshal::unmarshal(src)?,
            creation_ticket: Unmarshal::unmarshal(src)?,
            name: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for CreatePrimary<'_> {
    const CMD_CODE: TpmCc = TpmCc::CreatePrimary;
    type Handles = CreatePrimaryHandles;
    type Response<'a> = CreatePrimaryRsp<'a>;
    type RespHandles = CreatePrimaryRespHandles;
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HierarchyControlHandles {
    pub auth_handle: Handle,
}
impl Marshal for HierarchyControlHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for HierarchyControlHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhBaseHierarchy::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 24.2 TPM2_HierarchyControl (Command)
#[doc(alias = "TPM2_HierarchyControl")]
#[doc(alias = "HierarchyControl_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HierarchyControl {
    pub enable: Handle,
    pub state: bool,
}
impl Marshal for HierarchyControl {
    const MAX_SIZE: usize = Handle::MAX_SIZE + bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.enable, dst, 0);
        marshal_helper(&self.state, dst, count)
    }
}

impl<'a> Unmarshal<'a> for HierarchyControl {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let enable = TpmiRhEnables::<false>::unmarshal(src)
            .map_err(|e| e.in_parameter(1))?
            .0;
        let state: bool = Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?;
        Ok(Self { enable, state })
    }
}

impl Command for HierarchyControl {
    const CMD_CODE: TpmCc = TpmCc::HierarchyControl;
    type Handles = HierarchyControlHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SetPrimaryPolicyHandles {
    pub auth_handle: Handle,
}
impl Marshal for SetPrimaryPolicyHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SetPrimaryPolicyHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhHierarchyPolicy::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 24.3 TPM2_SetPrimaryPolicy (Command)
#[doc(alias = "TPM2_SetPrimaryPolicy")]
#[doc(alias = "SetPrimaryPolicy_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct SetPrimaryPolicy<'a> {
    pub auth_policy: crate::Tpm2bDigest<'a>,
    pub hash_alg: Option<crate::TpmiAlgHash>,
}
impl Marshal for SetPrimaryPolicy<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bDigest>::MAX_SIZE + <Option<crate::TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; SetPrimaryPolicy::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_policy, dst, 0);
        marshal_helper(&self.hash_alg, dst, count)
    }
}

impl<'a> Unmarshal<'a> for SetPrimaryPolicy<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_policy: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            hash_alg: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Command for SetPrimaryPolicy<'_> {
    const CMD_CODE: TpmCc = TpmCc::SetPrimaryPolicy;
    type Handles = SetPrimaryPolicyHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ChangePPSHandles {
    pub auth_handle: Handle,
}
impl Marshal for ChangePPSHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ChangePPSHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhPlatform::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 24.4 TPM2_ChangePPS (Command)
#[doc(alias = "TPM2_ChangePPS")]
#[doc(alias = "ChangePPS_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ChangePPS {}
impl Marshal for ChangePPS {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for ChangePPS {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for ChangePPS {
    const CMD_CODE: TpmCc = TpmCc::ChangePPS;
    type Handles = ChangePPSHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ChangeEPSHandles {
    pub auth_handle: Handle,
}
impl Marshal for ChangeEPSHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ChangeEPSHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhPlatform::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 24.5 TPM2_ChangeEPS (Command)
#[doc(alias = "TPM2_ChangeEPS")]
#[doc(alias = "ChangeEPS_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ChangeEPS {}
impl Marshal for ChangeEPS {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for ChangeEPS {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for ChangeEPS {
    const CMD_CODE: TpmCc = TpmCc::ChangeEPS;
    type Handles = ChangeEPSHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ClearHandles {
    pub auth_handle: Handle,
}
impl Marshal for ClearHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ClearHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhClear::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 24.6 TPM2_Clear (Command)
#[doc(alias = "TPM2_Clear")]
#[doc(alias = "Clear_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct Clear {}
impl Marshal for Clear {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for Clear {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for Clear {
    const CMD_CODE: TpmCc = TpmCc::Clear;
    type Handles = ClearHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ClearControlHandles {
    pub auth: Handle,
}
impl Marshal for ClearControlHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ClearControlHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: TpmiRhClear::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 24.7 TPM2_ClearControl (Command)
#[doc(alias = "TPM2_ClearControl")]
#[doc(alias = "ClearControl_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ClearControl {
    pub disable: bool,
}
impl Marshal for ClearControl {
    const MAX_SIZE: usize = bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.disable.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ClearControl {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let disable: bool = Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?;
        Ok(Self { disable })
    }
}

impl Command for ClearControl {
    const CMD_CODE: TpmCc = TpmCc::ClearControl;
    type Handles = ClearControlHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct HierarchyChangeAuthHandles {
    pub auth_handle: Handle,
}
impl Marshal for HierarchyChangeAuthHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for HierarchyChangeAuthHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhHierarchyAuth::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 24.8 TPM2_HierarchyChangeAuth (Command)
#[doc(alias = "TPM2_HierarchyChangeAuth")]
#[doc(alias = "HierarchyChangeAuth_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct HierarchyChangeAuth<'a> {
    pub new_auth: crate::Tpm2bAuth<'a>,
}
impl Marshal for HierarchyChangeAuth<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bAuth>::MAX_SIZE;
    type MaxBuffer = [u8; HierarchyChangeAuth::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.new_auth.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for HierarchyChangeAuth<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            new_auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for HierarchyChangeAuth<'_> {
    const CMD_CODE: TpmCc = TpmCc::HierarchyChangeAuth;
    type Handles = HierarchyChangeAuthHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ReadOnlyControlHandles {
    pub auth_handle: Handle,
}

impl Marshal for ReadOnlyControlHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ReadOnlyControlHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhPlatform::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 24.9 TPM2_ReadOnlyControl (Command)
#[doc(alias = "TPM2_ReadOnlyControl")]
#[doc(alias = "ReadOnlyControl_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ReadOnlyControl {
    pub state: bool,
}

impl Marshal for ReadOnlyControl {
    const MAX_SIZE: usize = bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.state.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ReadOnlyControl {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            state: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for ReadOnlyControl {
    const CMD_CODE: TpmCc = TpmCc::ReadOnlyControl;
    type Handles = ReadOnlyControlHandles;
    type Response<'a> = ();
    type RespHandles = ();
}
