//! TPM 2.0 Capability Commands
//!
//! This module implements the "Capability Commands" defined in
//! **Section 30** of the TPM 2.0 Specification.
//!
//! These commands provide queries for TPM configuration, supported algorithms,
//! commands, attributes, and property values.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// [TPM2.0 1.83] 30.2 TPM2_GetCapability (Command)
#[doc(alias = "TPM2_GetCapability")]
#[doc(alias = "GetCapability_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetCapability {
    pub capability: TpmCap,
    pub property: u32,
    pub property_count: u32,
}
impl Command for GetCapability {
    const CMD_CODE: TpmCc = TpmCc::GetCapability;
    type Handles = ();
    type Response<'a> = GetCapabilityRsp<'a>;
    type RespHandles = ();
}
impl Marshal for GetCapability {
    const MAX_SIZE: usize = TpmCap::MAX_SIZE + u32::MAX_SIZE + u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.capability, dst, 0);
        let count = marshal_helper(&self.property, dst, count);
        marshal_helper(&self.property_count, dst, count)
    }
}

impl<'a> Unmarshal<'a> for GetCapability {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            capability: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            property: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            property_count: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

/// [TPM2.0 1.83] 30.2 TPM2_GetCapability (Response)
#[doc(alias = "GetCapability_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetCapabilityRsp<'a> {
    pub more_data: bool,
    pub capability_data: TpmsCapabilityData<'a>,
}

impl<'a> Marshal for GetCapabilityRsp<'a> {
    const MAX_SIZE: usize = bool::MAX_SIZE + TpmsCapabilityData::MAX_SIZE;
    type MaxBuffer = [u8; GetCapabilityRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.more_data, dst, 0);
        marshal_helper(&self.capability_data, dst, count)
    }
}

impl<'a> Unmarshal<'a> for GetCapabilityRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            more_data: Unmarshal::unmarshal(src)?,
            capability_data: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 30.3 TPM2_TestParms (Command)
#[doc(alias = "TPM2_TestParms")]
#[doc(alias = "TestParms_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct TestParms {
    pub parameters: crate::structures::TpmtPublicParms,
}
impl Command for TestParms {
    const CMD_CODE: TpmCc = TpmCc::TestParms;
    type Handles = ();
    type Response<'a> = ();
    type RespHandles = ();
}
impl Marshal for TestParms {
    const MAX_SIZE: usize = <crate::structures::TpmtPublicParms>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.parameters.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TestParms {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            parameters: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SetCapabilityHandles {
    pub auth_handle: Handle,
}

impl Marshal for SetCapabilityHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SetCapabilityHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhHierarchyAuth::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 30.4 TPM2_SetCapability (Command)
#[doc(alias = "TPM2_SetCapability")]
#[doc(alias = "SetCapability_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SetCapability<'a> {
    pub set_capability_data: Tpm2bSetCapabilityData<'a>,
}

impl<'a> Marshal for SetCapability<'a> {
    const MAX_SIZE: usize = Tpm2bSetCapabilityData::MAX_SIZE;
    type MaxBuffer = [u8; SetCapability::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.set_capability_data.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SetCapability<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            set_capability_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl<'a> Command for SetCapability<'a> {
    const CMD_CODE: TpmCc = TpmCc::SetCapability;
    type Handles = SetCapabilityHandles;
    type Response<'b> = ();
    type RespHandles = ();
}
