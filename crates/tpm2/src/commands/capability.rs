//! TPM 2.0 Capability Commands
//!
//! This module implements the "Capability Commands" commands defined in
//! **Section 30** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage, param};
use crate::{errors::TpmRc, marshal::marshal_helper, *};

/// TPM2_GetCapability (Command)
#[doc(alias = "TPM2_GetCapability")]
#[doc(alias = "GetCapability_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetCapability {
    pub capability: TpmCap,
    pub property: u32,
    pub property_count: u32,
}
/// TPM2_GetCapability (Response)
#[doc(alias = "GetCapability_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetCapabilityRsp<'a> {
    pub more_data: bool,
    pub capability_data: TpmsCapabilityData<'a>,
}

impl Command for GetCapability {
    const CMD_CODE: TpmCc = TpmCc::GetCapability;
    type Response<'a> = GetCapabilityRsp<'a>;
}
impl Message for GetCapability {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
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
impl<'a> UnmarshalMessage<'a> for GetCapability {
    fn unmarshal_with_handles([]: Self::Handles, src: &mut &'a [u8]) -> Result<Self, TpmRc> {
        Ok(Self {
            capability: param(src, 1)?,
            property: param(src, 2)?,
            property_count: param(src, 3)?,
        })
    }
}

impl Message for GetCapabilityRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for GetCapabilityRsp<'_> {
    const MAX_SIZE: usize = bool::MAX_SIZE + TpmsCapabilityData::MAX_SIZE;
    type MaxBuffer = [u8; GetCapabilityRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.more_data, dst, 0);
        marshal_helper(&self.capability_data, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for GetCapabilityRsp<'a> {
    fn unmarshal_with_handles([]: Self::Handles, src: &mut &'a [u8]) -> Result<Self, TpmRc> {
        Ok(Self {
            more_data: param(src, 1)?,
            capability_data: param(src, 2)?,
        })
    }
}

/// TPM2_TestParms (Command)
#[doc(alias = "TPM2_TestParms")]
#[doc(alias = "TestParms_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct TestParms {
    pub parameters: TpmtPublicParms,
}

impl Command for TestParms {
    const CMD_CODE: TpmCc = TpmCc::TestParms;
    type Response<'a> = ();
}
impl Message for TestParms {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for TestParms {
    const MAX_SIZE: usize = TpmtPublicParms::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.parameters.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for TestParms {
    fn unmarshal_with_handles([]: Self::Handles, src: &mut &'a [u8]) -> Result<Self, TpmRc> {
        Ok(Self {
            parameters: param(src, 1)?,
        })
    }
}
