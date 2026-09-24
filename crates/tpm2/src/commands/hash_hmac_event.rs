//! TPM 2.0 Hash/HMAC/Event Sequences Commands
//!
//! This module implements the "Hash/HMAC/Event Sequences" commands defined in
//! **Section 17** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_HMAC_Start (Command)
#[doc(alias = "TPM2_HMAC_Start")]
#[doc(alias = "HMAC_Start_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct HMACStart<'a> {
    pub handle: Handle,
    pub auth: Tpm2bAuth<'a>,
    pub hash_alg: Option<TpmiAlgHash>,
}
/// TPM2_HMAC_Start (Response)
#[doc(alias = "HMAC_Start_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct HMACStartRsp {
    pub sequence_handle: Handle,
}

impl Command for HMACStart<'_> {
    const CMD_CODE: TpmCc = TpmCc::HMACStart;
    type Response<'a> = HMACStartRsp;
}
impl Message for HMACStart<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.handle]
    }
}
impl Marshal for HMACStart<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; HMACStart::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        marshal_helper(&self.hash_alg, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for HMACStart<'a> {
    fn unmarshal_with_handles(
        [handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            handle,
            auth: Unmarshal::unmarshal(src)?,
            hash_alg: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for HMACStartRsp {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.sequence_handle]
    }
}
impl Marshal for HMACStartRsp {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for HMACStartRsp {
    fn unmarshal_with_handles(
        [sequence_handle]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { sequence_handle })
    }
}

/// TPM2_HashSequenceStart (Command)
#[doc(alias = "TPM2_HashSequenceStart")]
#[doc(alias = "HashSequenceStart_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct HashSequenceStart<'a> {
    pub auth: Tpm2bAuth<'a>,
    pub hash_alg: Option<TpmiAlgHash>,
}
/// TPM2_HashSequenceStart (Response)
#[doc(alias = "HashSequenceStart_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct HashSequenceStartRsp {
    pub sequence_handle: Handle,
}

impl Command for HashSequenceStart<'_> {
    const CMD_CODE: TpmCc = TpmCc::HashSequenceStart;
    type Response<'a> = HashSequenceStartRsp;
}
impl Message for HashSequenceStart<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for HashSequenceStart<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; HashSequenceStart::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        marshal_helper(&self.hash_alg, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for HashSequenceStart<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: Unmarshal::unmarshal(src)?,
            hash_alg: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for HashSequenceStartRsp {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.sequence_handle]
    }
}
impl Marshal for HashSequenceStartRsp {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for HashSequenceStartRsp {
    fn unmarshal_with_handles(
        [sequence_handle]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { sequence_handle })
    }
}

/// TPM2_SequenceUpdate (Command)
#[doc(alias = "TPM2_SequenceUpdate")]
#[doc(alias = "SequenceUpdate_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct SequenceUpdate<'a> {
    pub sequence_handle: Handle,
    pub buffer: Tpm2bMaxBuffer<'a>,
}

impl Command for SequenceUpdate<'_> {
    const CMD_CODE: TpmCc = TpmCc::SequenceUpdate;
    type Response<'a> = ();
}
impl Message for SequenceUpdate<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.sequence_handle]
    }
}
impl Marshal for SequenceUpdate<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; SequenceUpdate::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.buffer.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for SequenceUpdate<'a> {
    fn unmarshal_with_handles(
        [sequence_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle,
            buffer: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_SequenceComplete (Command)
#[doc(alias = "TPM2_SequenceComplete")]
#[doc(alias = "SequenceComplete_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct SequenceComplete<'a> {
    pub sequence_handle: Handle,
    pub buffer: Tpm2bMaxBuffer<'a>,
    pub hierarchy: Handle,
}
/// TPM2_SequenceComplete (Response)
#[doc(alias = "SequenceComplete_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct SequenceCompleteRsp<'a> {
    pub result: Tpm2bDigest<'a>,
    pub validation: TpmtTkHashcheck<'a>,
}

impl Command for SequenceComplete<'_> {
    const CMD_CODE: TpmCc = TpmCc::SequenceComplete;
    type Response<'a> = SequenceCompleteRsp<'a>;
}
impl Message for SequenceComplete<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.sequence_handle]
    }
}
impl Marshal for SequenceComplete<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; SequenceComplete::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.buffer, dst, 0);
        marshal_helper(&self.hierarchy, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for SequenceComplete<'a> {
    fn unmarshal_with_handles(
        [sequence_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle,
            buffer: Unmarshal::unmarshal(src)?,
            hierarchy: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for SequenceCompleteRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for SequenceCompleteRsp<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + TpmtTkHashcheck::MAX_SIZE;
    type MaxBuffer = [u8; SequenceCompleteRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.result, dst, 0);
        marshal_helper(&self.validation, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for SequenceCompleteRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            result: Unmarshal::unmarshal(src)?,
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_EventSequenceComplete (Command)
#[doc(alias = "TPM2_EventSequenceComplete")]
#[doc(alias = "EventSequenceComplete_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct EventSequenceComplete<'a> {
    pub pcr_handle: Handle,
    pub sequence_handle: Handle,
    pub buffer: Tpm2bMaxBuffer<'a>,
}
/// TPM2_EventSequenceComplete (Response)
#[doc(alias = "EventSequenceComplete_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct EventSequenceCompleteRsp<'a> {
    pub results: TpmlDigestValues<'a>,
}

impl Command for EventSequenceComplete<'_> {
    const CMD_CODE: TpmCc = TpmCc::EventSequenceComplete;
    type Response<'a> = EventSequenceCompleteRsp<'a>;
}
impl Message for EventSequenceComplete<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.pcr_handle, self.sequence_handle]
    }
}
impl Marshal for EventSequenceComplete<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; EventSequenceComplete::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.buffer.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for EventSequenceComplete<'a> {
    fn unmarshal_with_handles(
        [pcr_handle, sequence_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pcr_handle,
            sequence_handle,
            buffer: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for EventSequenceCompleteRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for EventSequenceCompleteRsp<'_> {
    const MAX_SIZE: usize = TpmlDigestValues::MAX_SIZE;
    type MaxBuffer = [u8; EventSequenceCompleteRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.results.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for EventSequenceCompleteRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            results: Unmarshal::unmarshal(src)?,
        })
    }
}
