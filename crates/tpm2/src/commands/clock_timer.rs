//! TPM 2.0 Clocks and Timers Commands
//!
//! This module implements the "Clocks and Timers" commands defined in
//! **Section 29** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, *};

/// TPM2_ReadClock (Command)
#[doc(alias = "TPM2_ReadClock")]
#[doc(alias = "ReadClock_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ReadClock;
/// TPM2_ReadClock (Response)
#[doc(alias = "ReadClock_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ReadClockRsp {
    pub current_time: TpmsTimeInfo,
}

impl Command for ReadClock {
    const CMD_CODE: TpmCc = TpmCc::ReadClock;
    type Response<'a> = ReadClockRsp;
}
impl Message for ReadClock {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ReadClock {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for ReadClock {
    fn unmarshal_with_handles([]: Self::Handles, _: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self)
    }
}

impl Message for ReadClockRsp {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ReadClockRsp {
    const MAX_SIZE: usize = TpmsTimeInfo::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.current_time.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ReadClockRsp {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            current_time: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ClockSet (Command)
#[doc(alias = "TPM2_ClockSet")]
#[doc(alias = "ClockSet_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ClockSet {
    pub auth: Handle,
    pub new_time: u64,
}

impl Command for ClockSet {
    const CMD_CODE: TpmCc = TpmCc::ClockSet;
    type Response<'a> = ();
}
impl Message for ClockSet {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.auth]
    }
}
impl Marshal for ClockSet {
    const MAX_SIZE: usize = u64::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.new_time.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ClockSet {
    fn unmarshal_with_handles(
        [auth]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth,
            new_time: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ClockRateAdjust (Command)
#[doc(alias = "TPM2_ClockRateAdjust")]
#[doc(alias = "ClockRateAdjust_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ClockRateAdjust {
    pub auth: Handle,
    pub rate_adjust: TpmClockAdjust,
}

impl Command for ClockRateAdjust {
    const CMD_CODE: TpmCc = TpmCc::ClockRateAdjust;
    type Response<'a> = ();
}
impl Message for ClockRateAdjust {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.auth]
    }
}
impl Marshal for ClockRateAdjust {
    const MAX_SIZE: usize = TpmClockAdjust::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.rate_adjust.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ClockRateAdjust {
    fn unmarshal_with_handles(
        [auth]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth,
            rate_adjust: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ACT_SetTimeout (Command)
#[doc(alias = "TPM2_ACT_SetTimeout")]
#[doc(alias = "ACT_SetTimeout_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ACTSetTimeout {
    pub act_handle: Handle,
    pub start_timeout: u32,
}

impl Command for ACTSetTimeout {
    const CMD_CODE: TpmCc = TpmCc::ACTSetTimeout;
    type Response<'a> = ();
}
impl Message for ACTSetTimeout {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.act_handle]
    }
}
impl Marshal for ACTSetTimeout {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; ACTSetTimeout::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.start_timeout.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ACTSetTimeout {
    fn unmarshal_with_handles(
        [act_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            act_handle,
            start_timeout: Unmarshal::unmarshal(src)?,
        })
    }
}
