//! TPM 2.0 Hash, HMAC, and Event Sequences Commands
//!
//! This module implements the "Hash/HMAC/Event Sequences" commands defined in
//! **Section 17** of the TPM 2.0 Specification.
//!
//! These commands support streaming operations for hashing, HMAC calculation,
//! or adding events to a PCR bank.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HmacStartHandles {
    pub handle: Handle,
}
impl Marshal for HmacStartHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for HmacStartHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 17.2 TPM2_HMAC_Start (Command)
#[doc(alias = "TPM2_HMAC_Start")]
#[doc(alias = "HMAC_Start_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HmacStart<'a> {
    pub auth: Tpm2bAuth<'a>,
    pub hash_alg: Option<TpmiAlgHash>,
}
impl Marshal for HmacStart<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; HmacStart::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; HmacStart::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        marshal_helper(&self.hash_alg, dst, count)
    }
}

impl<'a> Unmarshal<'a> for HmacStart<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            hash_alg: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HmacStartRespHandles {
    pub sequence_handle: Handle,
}
impl Marshal for HmacStartRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sequence_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for HmacStartRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle: TpmiDhObject::<false>::unmarshal(src)?.0,
        })
    }
}

impl Command for HmacStart<'_> {
    const CMD_CODE: TpmCc = TpmCc::HmacStart;
    type Handles = HmacStartHandles;
    type Response<'a> = ();
    type RespHandles = HmacStartRespHandles;
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct MACStartHandles {
    pub handle: Handle,
}
impl Marshal for MACStartHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for MACStartHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 17.3 TPM2_MAC_Start (Command)
#[doc(alias = "TPM2_MAC_Start")]
#[doc(alias = "MAC_Start_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct MACStart<'a> {
    pub auth: Tpm2bAuth<'a>,
    pub in_scheme: Option<TpmiAlgMacScheme>,
}
impl Marshal for MACStart<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + <Option<TpmiAlgMacScheme>>::MAX_SIZE;
    type MaxBuffer = [u8; MACStart::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; MACStart::MAX_SIZE]) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        marshal_helper(&self.in_scheme, dst, count)
    }
}

impl<'a> Unmarshal<'a> for MACStart<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            in_scheme: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct MACStartRespHandles {
    pub sequence_handle: Handle,
}
impl Marshal for MACStartRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sequence_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for MACStartRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle: TpmiDhObject::<false>::unmarshal(src)?.0,
        })
    }
}

impl Command for MACStart<'_> {
    const CMD_CODE: TpmCc = TpmCc::MACStart;
    type Handles = MACStartHandles;
    type Response<'a> = ();
    type RespHandles = MACStartRespHandles;
}

/// [TPM2.0 1.83] 17.4 TPM2_HashSequenceStart (Command)
#[doc(alias = "TPM2_HashSequenceStart")]
#[doc(alias = "HashSequenceStart_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HashSequenceStart<'a> {
    pub auth: Tpm2bAuth<'a>,
    pub hash_alg: Option<TpmiAlgHash>,
}
impl Marshal for HashSequenceStart<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; HashSequenceStart::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        marshal_helper(&self.hash_alg, dst, count)
    }
}

impl<'a> Unmarshal<'a> for HashSequenceStart<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            hash_alg: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct HashSequenceStartRespHandles {
    pub sequence_handle: Handle,
}
pub type HashSequenceStartHandles = HashSequenceStartRespHandles;

impl Marshal for HashSequenceStartRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sequence_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for HashSequenceStartRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle: TpmiDhObject::<false>::unmarshal(src)?.0,
        })
    }
}

impl Command for HashSequenceStart<'_> {
    const CMD_CODE: TpmCc = TpmCc::HashSequenceStart;
    type Handles = ();
    type Response<'a> = ();
    type RespHandles = HashSequenceStartRespHandles;
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SignSequenceStartHandles {
    pub key_handle: Handle,
}
impl Marshal for SignSequenceStartHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SignSequenceStartHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 17.5 TPM2_SignSequenceStart (Command)
#[doc(alias = "TPM2_SignSequenceStart")]
#[doc(alias = "SignSequenceStart_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SignSequenceStart<'a> {
    pub auth: Tpm2bAuth<'a>,
    pub context: Tpm2bSignatureCtx<'a>,
}
impl Marshal for SignSequenceStart<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + Tpm2bSignatureCtx::MAX_SIZE;
    type MaxBuffer = [u8; SignSequenceStart::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        marshal_helper(&self.context, dst, count)
    }
}

impl<'a> Unmarshal<'a> for SignSequenceStart<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            context: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SignSequenceStartRespHandles {
    pub sequence_handle: Handle,
}
impl Marshal for SignSequenceStartRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sequence_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SignSequenceStartRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle: TpmiDhObject::<false>::unmarshal(src)?.0,
        })
    }
}

impl Command for SignSequenceStart<'_> {
    const CMD_CODE: TpmCc = TpmCc::SignSequenceStart;
    type Handles = SignSequenceStartHandles;
    type Response<'a> = ();
    type RespHandles = SignSequenceStartRespHandles;
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct VerifySequenceStartHandles {
    pub key_handle: Handle,
}
impl Marshal for VerifySequenceStartHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.key_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for VerifySequenceStartHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 17.6 TPM2_VerifySequenceStart (Command)
#[doc(alias = "TPM2_VerifySequenceStart")]
#[doc(alias = "VerifySequenceStart_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct VerifySequenceStart<'a> {
    pub auth: Tpm2bAuth<'a>,
    pub hint: Tpm2bSignatureHint<'a>,
    pub context: Tpm2bSignatureCtx<'a>,
}
impl Marshal for VerifySequenceStart<'_> {
    const MAX_SIZE: usize =
        Tpm2bAuth::MAX_SIZE + Tpm2bSignatureHint::MAX_SIZE + Tpm2bSignatureCtx::MAX_SIZE;
    type MaxBuffer = [u8; VerifySequenceStart::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        let count = marshal_helper(&self.hint, dst, count);
        marshal_helper(&self.context, dst, count)
    }
}

impl<'a> Unmarshal<'a> for VerifySequenceStart<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            hint: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            context: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct VerifySequenceStartRespHandles {
    pub sequence_handle: Handle,
}
impl Marshal for VerifySequenceStartRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sequence_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for VerifySequenceStartRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle: TpmiDhObject::<false>::unmarshal(src)?.0,
        })
    }
}

impl Command for VerifySequenceStart<'_> {
    const CMD_CODE: TpmCc = TpmCc::VerifySequenceStart;
    type Handles = VerifySequenceStartHandles;
    type Response<'a> = ();
    type RespHandles = VerifySequenceStartRespHandles;
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SequenceUpdateHandles {
    pub sequence_handle: Handle,
}
impl Marshal for SequenceUpdateHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sequence_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SequenceUpdateHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 17.7 TPM2_SequenceUpdate (Command)
#[doc(alias = "TPM2_SequenceUpdate")]
#[doc(alias = "SequenceUpdate_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SequenceUpdate<'a> {
    pub buffer: Tpm2bMaxBuffer<'a>,
}

impl Marshal for SequenceUpdate<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; SequenceUpdate::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.buffer.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SequenceUpdate<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            buffer: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for SequenceUpdate<'_> {
    const CMD_CODE: TpmCc = TpmCc::SequenceUpdate;
    type Handles = SequenceUpdateHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SequenceCompleteHandles {
    pub sequence_handle: Handle,
}
impl Marshal for SequenceCompleteHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sequence_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SequenceCompleteHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 17.8 TPM2_SequenceComplete (Command)
#[doc(alias = "TPM2_SequenceComplete")]
#[doc(alias = "SequenceComplete_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SequenceComplete<'a> {
    pub buffer: Tpm2bMaxBuffer<'a>,
    pub hierarchy: Handle,
}

impl Marshal for SequenceComplete<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; SequenceComplete::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.buffer, dst, 0);
        marshal_helper(&self.hierarchy, dst, count)
    }
}

impl<'a> Unmarshal<'a> for SequenceComplete<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            buffer: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            hierarchy: TpmiRhHierarchy::unmarshal(src)
                .map_err(|e| e.in_parameter(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 17.8 TPM2_SequenceComplete (Response)
#[doc(alias = "SequenceComplete_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct SequenceCompleteRsp<'a> {
    pub result: Tpm2bDigest<'a>,
    pub validation: TpmtTkHashcheck<'a>,
}
impl Marshal for SequenceCompleteRsp<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + TpmtTkHashcheck::MAX_SIZE;
    type MaxBuffer = [u8; SequenceCompleteRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.result, dst, 0);
        marshal_helper(&self.validation, dst, count)
    }
}

impl<'a> Unmarshal<'a> for SequenceCompleteRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            result: Unmarshal::unmarshal(src)?,
            validation: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for SequenceComplete<'_> {
    const CMD_CODE: TpmCc = TpmCc::SequenceComplete;
    type Handles = SequenceCompleteHandles;
    type Response<'a> = SequenceCompleteRsp<'a>;
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EventSequenceCompleteHandles {
    pub pcr_handle: Handle,
    pub sequence_handle: Handle,
}
impl Marshal for EventSequenceCompleteHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.pcr_handle, dst, 0);
        marshal_helper(&self.sequence_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for EventSequenceCompleteHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            pcr_handle: TpmiDhPcr::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            sequence_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 17.9 TPM2_EventSequenceComplete (Command)
#[doc(alias = "TPM2_EventSequenceComplete")]
#[doc(alias = "EventSequenceComplete_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EventSequenceComplete<'a> {
    pub buffer: Tpm2bMaxBuffer<'a>,
}

impl Marshal for EventSequenceComplete<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; EventSequenceComplete::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.buffer.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for EventSequenceComplete<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            buffer: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 17.9 TPM2_EventSequenceComplete (Response)
#[doc(alias = "EventSequenceComplete_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct EventSequenceCompleteRsp<'a> {
    pub results: TpmlDigestValues<'a>,
}

impl<'a> Marshal for EventSequenceCompleteRsp<'a> {
    const MAX_SIZE: usize = TpmlDigestValues::MAX_SIZE;
    type MaxBuffer = [u8; EventSequenceCompleteRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.results.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for EventSequenceCompleteRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            results: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for EventSequenceComplete<'_> {
    const CMD_CODE: TpmCc = TpmCc::EventSequenceComplete;
    type Handles = EventSequenceCompleteHandles;
    type Response<'a> = EventSequenceCompleteRsp<'a>;
    type RespHandles = ();
}
