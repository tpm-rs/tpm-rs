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
//! response parameters, and [`Command`] trait implementation.
//!
//! The "Attached Components" commands are deprecated in v184 of the
//! specification. Following the policy described in the
//! [`commands`](crate::commands) module docs, the command and response types in
//! this module are therefore annotated with Rust's `#[deprecated]` attribute.
#![allow(deprecated)] // So we can define the now-deprecated Commands / impls.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// [TPM2.0 1.83] 32.2 TPM2_AC_GetCapability (Command)
#[doc(alias = "TPM2_AC_GetCapability")]
#[doc(alias = "AC_GetCapability_In")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ACGetCapability {
    /// Handle indicating the Attached Component (`TPMI_RH_AC`).
    pub ac: Handle,
    /// Starting info type.
    pub capability: TpmAt,
    /// Maximum number of values to return.
    pub count: u32,
}
/// [TPM2.0 1.83] 32.2 TPM2_AC_GetCapability (Response)
#[doc(alias = "AC_GetCapability_Out")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ACGetCapabilityRsp {
    /// Flag to indicate whether there are more values.
    pub more_data: bool,
    /// List of capabilities.
    pub capabilities_data: TpmlAcCapabilities,
}

impl Command for ACGetCapability {
    const CMD_CODE: TpmCc = TpmCc::ACGetCapability;
    type Response<'a> = ACGetCapabilityRsp;
}
impl Message for ACGetCapability {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.ac]
    }
}
impl Marshal for ACGetCapability {
    const MAX_SIZE: usize = TpmAt::MAX_SIZE + u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.capability, dst, 0);
        marshal_helper(&self.count, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for ACGetCapability {
    fn unmarshal_with_handles(
        [ac]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            ac,
            capability: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            count: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Message for ACGetCapabilityRsp {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ACGetCapabilityRsp {
    const MAX_SIZE: usize = bool::MAX_SIZE + TpmlAcCapabilities::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.more_data, dst, 0);
        marshal_helper(&self.capabilities_data, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for ACGetCapabilityRsp {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            more_data: Unmarshal::unmarshal(src)?,
            capabilities_data: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 32.3 TPM2_AC_Send (Command)
#[doc(alias = "TPM2_AC_Send")]
#[doc(alias = "AC_Send_In")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ACSend<'a> {
    /// Handle of the object being sent to the AC (`TPMI_DH_OBJECT`).
    pub send_object: Handle,
    /// The handle indicating the source of the authorization value
    /// (`TPMI_RH_NV_AUTH`).
    pub auth_handle: Handle,
    /// Handle indicating the AC that is to receive the object (`TPMI_RH_AC`).
    pub ac: Handle,
    /// Optional non-sensitive information related to the object.
    pub ac_in: Tpm2bMaxBuffer<'a>,
}
/// [TPM2.0 1.83] 32.3 TPM2_AC_Send (Response)
#[doc(alias = "AC_Send_Out")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ACSendRsp {
    /// May include AC specific data or information about an error.
    pub ac_out: TpmsAcOutput,
}

impl Command for ACSend<'_> {
    const CMD_CODE: TpmCc = TpmCc::ACSend;
    type Response<'a> = ACSendRsp;
}
impl Message for ACSend<'_> {
    type Handles = [Handle; 3];
    fn handles(&self) -> Self::Handles {
        [self.send_object, self.auth_handle, self.ac]
    }
}
impl Marshal for ACSend<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; ACSend::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.ac_in.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ACSend<'a> {
    fn unmarshal_with_handles(
        [send_object, auth_handle, ac]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            send_object,
            auth_handle,
            ac,
            ac_in: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Message for ACSendRsp {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ACSendRsp {
    const MAX_SIZE: usize = TpmsAcOutput::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.ac_out.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ACSendRsp {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            ac_out: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 32.4 TPM2_Policy_AC_SendSelect (Command)
#[doc(alias = "TPM2_Policy_AC_SendSelect")]
#[doc(alias = "Policy_AC_SendSelect_In")]
#[deprecated]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyACSendSelect<'a> {
    /// Handle for the policy session being extended (`TPMI_SH_POLICY`).
    pub policy_session: Handle,
    /// The Name of the Object to be sent.
    pub object_name: Tpm2bName<'a>,
    /// The Name associated with `authHandle` used in the `TPM2_AC_Send` command.
    pub auth_object_name: Tpm2bName<'a>,
    /// The Name of the Attached Component to which the Object will be sent.
    pub ac_name: Tpm2bName<'a>,
    /// If SET, `object_name` will be included in the value in
    /// `policySession->policyDigest`.
    pub include_object: bool,
}

impl Command for PolicyACSendSelect<'_> {
    const CMD_CODE: TpmCc = TpmCc::PolicyACSendSelect;
    type Response<'a> = ();
}
impl Message for PolicyACSendSelect<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
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
impl<'a> UnmarshalMessage<'a> for PolicyACSendSelect<'a> {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            policy_session,
            object_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            auth_object_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            ac_name: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            include_object: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
        })
    }
}
