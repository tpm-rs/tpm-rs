//! TPM 2.0 Integrity Collection (PCR) Commands
//!
//! This module implements the "Integrity Collection (PCR)" commands defined in
//! **Section 22** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_PCR_Extend (Command)
#[doc(alias = "TPM2_PCR_Extend")]
#[doc(alias = "PCR_Extend_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCRExtend<'a> {
    pub pcr_handle: Handle,
    pub digests: TpmlDigestValues<'a>,
}

impl Command for PCRExtend<'_> {
    const CMD_CODE: TpmCc = TpmCc::PCRExtend;
    type Response<'a> = ();
}
impl Message for PCRExtend<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.pcr_handle]
    }
}
impl Marshal for PCRExtend<'_> {
    const MAX_SIZE: usize = TpmlDigestValues::MAX_SIZE;
    type MaxBuffer = [u8; PCRExtend::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.digests.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PCRExtend<'a> {
    fn unmarshal_with_handles(
        [pcr_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pcr_handle,
            digests: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PCR_Event (Command)
#[doc(alias = "TPM2_PCR_Event")]
#[doc(alias = "PCR_Event_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCREvent<'a> {
    pub pcr_handle: Handle,
    pub event_data: Tpm2bEvent<'a>,
}
/// TPM2_PCR_Event (Response)
#[doc(alias = "PCR_Event_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCREventRsp<'a> {
    pub digests: TpmlDigestValues<'a>,
}

impl Command for PCREvent<'_> {
    const CMD_CODE: TpmCc = TpmCc::PCREvent;
    type Response<'a> = PCREventRsp<'a>;
}
impl Message for PCREvent<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.pcr_handle]
    }
}
impl Marshal for PCREvent<'_> {
    const MAX_SIZE: usize = Tpm2bEvent::MAX_SIZE;
    type MaxBuffer = [u8; PCREvent::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.event_data.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PCREvent<'a> {
    fn unmarshal_with_handles(
        [pcr_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pcr_handle,
            event_data: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for PCREventRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for PCREventRsp<'_> {
    const MAX_SIZE: usize = TpmlDigestValues::MAX_SIZE;
    type MaxBuffer = [u8; PCREventRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.digests.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PCREventRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            digests: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PCR_Read (Command)
#[doc(alias = "TPM2_PCR_Read")]
#[doc(alias = "PCR_Read_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCRRead {
    pub pcr_selection_in: TpmlPcrSelection,
}
/// TPM2_PCR_Read (Response)
#[doc(alias = "PCR_Read_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCRReadRsp<'a> {
    pub pcr_update_counter: u32,
    pub pcr_selection_out: TpmlPcrSelection,
    pub pcr_values: TpmlDigest<'a>,
}

impl Command for PCRRead {
    const CMD_CODE: TpmCc = TpmCc::PCRRead;
    type Response<'a> = PCRReadRsp<'a>;
}
impl Message for PCRRead {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for PCRRead {
    const MAX_SIZE: usize = TpmlPcrSelection::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.pcr_selection_in.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PCRRead {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pcr_selection_in: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for PCRReadRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for PCRReadRsp<'_> {
    const MAX_SIZE: usize = u32::MAX_SIZE + TpmlPcrSelection::MAX_SIZE + TpmlDigest::MAX_SIZE;
    type MaxBuffer = [u8; PCRReadRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.pcr_update_counter, dst, 0);
        let count = marshal_helper(&self.pcr_selection_out, dst, count);
        marshal_helper(&self.pcr_values, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PCRReadRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pcr_update_counter: Unmarshal::unmarshal(src)?,
            pcr_selection_out: Unmarshal::unmarshal(src)?,
            pcr_values: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PCR_Allocate (Command)
#[doc(alias = "TPM2_PCR_Allocate")]
#[doc(alias = "PCR_Allocate_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCRAllocate {
    pub auth_handle: Handle,
    pub pcr_allocation: TpmlPcrSelection,
}
/// TPM2_PCR_Allocate (Response)
#[doc(alias = "PCR_Allocate_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCRAllocateRsp {
    pub allocation_success: bool,
    pub max_pcr: u32,
    pub size_needed: u32,
    pub size_available: u32,
}

impl Command for PCRAllocate {
    const CMD_CODE: TpmCc = TpmCc::PCRAllocate;
    type Response<'a> = PCRAllocateRsp;
}
impl Message for PCRAllocate {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle]
    }
}
impl Marshal for PCRAllocate {
    const MAX_SIZE: usize = TpmlPcrSelection::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.pcr_allocation.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PCRAllocate {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            pcr_allocation: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for PCRAllocateRsp {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for PCRAllocateRsp {
    const MAX_SIZE: usize = bool::MAX_SIZE + u32::MAX_SIZE + u32::MAX_SIZE + u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.allocation_success, dst, 0);
        let count = marshal_helper(&self.max_pcr, dst, count);
        let count = marshal_helper(&self.size_needed, dst, count);
        marshal_helper(&self.size_available, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PCRAllocateRsp {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            allocation_success: Unmarshal::unmarshal(src)?,
            max_pcr: Unmarshal::unmarshal(src)?,
            size_needed: Unmarshal::unmarshal(src)?,
            size_available: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PCR_SetAuthPolicy (Command)
#[doc(alias = "TPM2_PCR_SetAuthPolicy")]
#[doc(alias = "PCR_SetAuthPolicy_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCRSetAuthPolicy<'a> {
    pub auth_handle: Handle,
    pub auth_policy: Tpm2bDigest<'a>,
    pub hash_alg: Option<TpmiAlgHash>,
    pub pcr_num: Handle,
}

impl Command for PCRSetAuthPolicy<'_> {
    const CMD_CODE: TpmCc = TpmCc::PCRSetAuthPolicy;
    type Response<'a> = ();
}
impl Message for PCRSetAuthPolicy<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle]
    }
}
impl Marshal for PCRSetAuthPolicy<'_> {
    const MAX_SIZE: usize =
        Tpm2bDigest::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; PCRSetAuthPolicy::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth_policy, dst, 0);
        let count = marshal_helper(&self.hash_alg, dst, count);
        marshal_helper(&self.pcr_num, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PCRSetAuthPolicy<'a> {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            auth_policy: Unmarshal::unmarshal(src)?,
            hash_alg: Unmarshal::unmarshal(src)?,
            pcr_num: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PCR_SetAuthValue (Command)
#[doc(alias = "TPM2_PCR_SetAuthValue")]
#[doc(alias = "PCR_SetAuthValue_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCRSetAuthValue<'a> {
    pub pcr_handle: Handle,
    pub auth: Tpm2bDigest<'a>,
}

impl Command for PCRSetAuthValue<'_> {
    const CMD_CODE: TpmCc = TpmCc::PCRSetAuthValue;
    type Response<'a> = ();
}
impl Message for PCRSetAuthValue<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.pcr_handle]
    }
}
impl Marshal for PCRSetAuthValue<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; PCRSetAuthValue::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for PCRSetAuthValue<'a> {
    fn unmarshal_with_handles(
        [pcr_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pcr_handle,
            auth: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PCR_Reset (Command)
#[doc(alias = "TPM2_PCR_Reset")]
#[doc(alias = "PCR_Reset_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCRReset {
    pub pcr_handle: Handle,
}

impl Command for PCRReset {
    const CMD_CODE: TpmCc = TpmCc::PCRReset;
    type Response<'a> = ();
}
impl Message for PCRReset {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.pcr_handle]
    }
}
impl Marshal for PCRReset {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for PCRReset {
    fn unmarshal_with_handles(
        [pcr_handle]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { pcr_handle })
    }
}
