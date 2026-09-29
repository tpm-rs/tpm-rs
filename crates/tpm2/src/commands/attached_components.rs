//! TPM 2.0 Attached Components Commands
//!
//! This module implements the "Attached Components" commands defined in
//! **Section 32** of the TPM 2.0 Specification.
//!
//! These commands provide:
//! - Retrieval of capabilities of attached components
//! - Sending commands to attached components
//! - Restricting attached component policies
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and `TpmCommand` trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ACGetCapabilityHandles {
    pub ac: Handle,
}

impl Marshal for ACGetCapabilityHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.ac.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ACGetCapabilityHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            ac: TpmiRhAc::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 32.2 TPM2_AC_GetCapability (Command)
#[doc(alias = "TPM2_AC_GetCapability")]
#[doc(alias = "AC_GetCapability_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ACGetCapability {
    pub capability: TpmAt,
    pub count: u32,
}

impl Marshal for ACGetCapability {
    const MAX_SIZE: usize = TpmAt::MAX_SIZE + u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.capability, dst, 0);
        marshal_helper(&self.count, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ACGetCapability {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            capability: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            count: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

/// [TPM2.0 1.83] 32.2 TPM2_AC_GetCapability (Response)
#[doc(alias = "AC_GetCapability_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct ACGetCapabilityRsp {
    pub more_data: bool,
    pub capabilities_data: TpmlAcCapabilities,
}

impl Marshal for ACGetCapabilityRsp {
    const MAX_SIZE: usize = bool::MAX_SIZE + TpmlAcCapabilities::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.more_data, dst, 0);
        marshal_helper(&self.capabilities_data, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ACGetCapabilityRsp {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            more_data: Unmarshal::unmarshal(src)?,
            capabilities_data: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ACGetCapability {
    const CMD_CODE: TpmCc = TpmCc::ACGetCapability;
    type Handles = ACGetCapabilityHandles;
    type Response<'a> = ACGetCapabilityRsp;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ACSendHandles {
    pub send_object: Handle,
    pub auth_handle: Handle,
    pub ac: Handle,
}

impl Marshal for ACSendHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.send_object, dst, 0);
        let count = marshal_helper(&self.auth_handle, dst, count);
        marshal_helper(&self.ac, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ACSendHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            send_object: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            auth_handle: TpmiRhNvAuth::unmarshal(src).map_err(|e| e.in_handle(2))?.0,
            ac: TpmiRhAc::unmarshal(src).map_err(|e| e.in_handle(3))?.0,
        })
    }
}

/// [TPM2.0 1.83] 32.3 TPM2_AC_Send (Command)
#[doc(alias = "TPM2_AC_Send")]
#[doc(alias = "AC_Send_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ACSend<'a> {
    pub ac_in: Tpm2bMaxBuffer<'a>,
}

impl Marshal for ACSend<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; ACSend::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.ac_in.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ACSend<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            ac_in: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 32.3 TPM2_AC_Send (Response)
#[doc(alias = "AC_Send_Out")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct ACSendRsp {
    pub ac_out: TpmsAcOutput,
}

impl Marshal for ACSendRsp {
    const MAX_SIZE: usize = TpmsAcOutput::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.ac_out.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ACSendRsp {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            ac_out: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ACSend<'_> {
    const CMD_CODE: TpmCc = TpmCc::ACSend;
    type Handles = ACSendHandles;
    type Response<'a> = ACSendRsp;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyACSendSelectHandles {
    pub policy_session: Handle,
}

impl Marshal for PolicyACSendSelectHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.policy_session.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyACSendSelectHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 32.4 TPM2_Policy_AC_SendSelect (Command)
#[doc(alias = "TPM2_Policy_AC_SendSelect")]
#[doc(alias = "Policy_AC_SendSelect_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct PolicyACSendSelect<'a> {
    pub object_name: Tpm2bName<'a>,
    pub auth_object_name: Tpm2bName<'a>,
    pub ac_name: Tpm2bName<'a>,
    pub include_object: bool,
}

impl Marshal for PolicyACSendSelect<'_> {
    const MAX_SIZE: usize =
        Tpm2bName::MAX_SIZE + Tpm2bName::MAX_SIZE + Tpm2bName::MAX_SIZE + bool::MAX_SIZE;
    type MaxBuffer = [u8; PolicyACSendSelect::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.object_name, dst, 0);
        let count = marshal_helper(&self.auth_object_name, dst, count);
        let count = marshal_helper(&self.ac_name, dst, count);
        marshal_helper(&self.include_object, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PolicyACSendSelect<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            object_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            auth_object_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            ac_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            include_object: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}

impl Command for PolicyACSendSelect<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyACSendSelect;
    type Handles = PolicyACSendSelectHandles;
    type Response<'a> = ();
    type RespHandles = ();
}
