//! TPM 2.0 Integrity Collection (PCR) Commands
//!
//! This module implements the "Integrity Collection (PCR)" commands defined in
//! **Section 22** of the TPM 2.0 Specification.
//!
//! These commands support reading, extending, resetting, or allocating
//! Platform Configuration Registers (PCRs).
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// [TPM2.0 1.83] 22.2 TPM2_PCR_Extend (Command)
#[doc(alias = "TPM2_PCR_Extend")]
#[doc(alias = "PCR_Extend_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PCRExtend<'a> {
    /// PCR handle to extend.
    pub pcr_handle: Handle,
    /// List of tagged digests to extend.
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
            digests: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 22.3 TPM2_PCR_Event (Command)
#[doc(alias = "TPM2_PCR_Event")]
#[doc(alias = "PCR_Event_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCREvent<'a> {
    /// PCR handle to record the event to.
    pub pcr_handle: Handle,
    /// Data of the event.
    pub event_data: Tpm2bEvent<'a>,
}
/// [TPM2.0 1.83] 22.3 TPM2_PCR_Event (Response)
#[doc(alias = "PCR_Event_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCREventRsp<'a> {
    /// Tagged digests recorded for the event.
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
            event_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
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

/// [TPM2.0 1.83] 22.4 TPM2_PCR_Read (Command)
#[doc(alias = "TPM2_PCR_Read")]
#[doc(alias = "PCR_Read_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCRRead {
    /// PCR selection to read.
    pub pcr_selection_in: TpmlPcrSelection,
}
/// [TPM2.0 1.83] 22.4 TPM2_PCR_Read (Response)
#[doc(alias = "PCR_Read_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCRReadRsp<'a> {
    /// PCR update counter value.
    pub pcr_update_counter: u32,
    /// PCR selection that was actually read.
    pub pcr_selection_out: TpmlPcrSelection,
    /// PCR values read.
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
            pcr_selection_in: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
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

/// [TPM2.0 1.83] 22.5 TPM2_PCR_Allocate (Command)
#[doc(alias = "TPM2_PCR_Allocate")]
#[doc(alias = "PCR_Allocate_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PCRAllocate {
    /// Auth handle (`TPMI_RH_PLATFORM`).
    pub auth_handle: Handle,
    /// Requested PCR allocation.
    pub pcr_allocation: TpmlPcrSelection,
}
/// [TPM2.0 1.83] 22.5 TPM2_PCR_Allocate (Response)
#[doc(alias = "PCR_Allocate_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PCRAllocateRsp {
    /// YES if the allocation succeeded.
    pub allocation_success: bool,
    /// Maximum number of PCR that may be in a bank.
    pub max_pcr: u32,
    /// Number of octets required to satisfy the request.
    pub size_needed: u32,
    /// Number of octets available. Computed before the allocation.
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
            pcr_allocation: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
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

/// [TPM2.0 1.83] 22.6 TPM2_PCR_SetAuthPolicy (Command)
#[doc(alias = "TPM2_PCR_SetAuthPolicy")]
#[doc(alias = "PCR_SetAuthPolicy_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
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
            auth_policy: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            hash_alg: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            // `pcrNum` is a `TPMI_DH_PCR` command parameter (not a handle), so its
            // range is validated here.
            pcr_num: TpmiDhPcr::<false>::unmarshal(src)
                .map_err(|e| e.in_parameter(3))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 22.7 TPM2_PCR_SetAuthValue (Command)
#[doc(alias = "TPM2_PCR_SetAuthValue")]
#[doc(alias = "PCR_SetAuthValue_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
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
            auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 22.8 TPM2_PCR_Reset (Command)
#[doc(alias = "TPM2_PCR_Reset")]
#[doc(alias = "PCR_Reset_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PCRReset {
    /// PCR handle to reset.
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

/// [TPM2.0 1.83] 22.9 _TPM_Hash_Start
///
/// Hardware indication / architectural platform signal sent by the platform
/// to indicate the start of an event hash sequence (typically for CRTM / H-CRTM measurement).
/// Not transmitted as an over-the-wire command.
pub struct HashStart {}

/// [TPM2.0 1.83] 22.10 _TPM_Hash_Data
///
/// Hardware indication / architectural platform signal sent by the platform
/// to provide data to be hashed in an active H-CRTM sequence. Not transmitted as an over-the-wire command.
pub struct HashData {}

/// [TPM2.0 1.83] 22.11 _TPM_Hash_End
///
/// Hardware indication / architectural platform signal sent by the platform
/// to complete an active H-CRTM event hash sequence. Not transmitted as an over-the-wire command.
pub struct HashEnd {}
