//! TPM 2.0 Clocks and Timers Commands
//!
//! This module implements the "Clocks and Timers" commands defined in
//! **Section 29** of the TPM 2.0 Specification.
use super::{Command, Response, UnmarshalCommand, UnmarshalResponse};
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
    type Handles<'a>
        = [EntityHandle<'a>; 0]
    where
        Self: 'a;
    type Response<'a> = ReadClockRsp;
    fn handles(&self) -> Self::Handles<'_> {
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
impl<'a> UnmarshalCommand<'a> for ReadClock {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self)
    }
}

impl Response for ReadClockRsp {
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
impl<'a> UnmarshalResponse<'a> for ReadClockRsp {
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
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.auth)]
    }
}
impl Marshal for ClockSet {
    const MAX_SIZE: usize = u64::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.new_time.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for ClockSet {
    fn unmarshal_with_handles(
        [auth]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: auth.try_into()?,
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
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.auth)]
    }
}
impl Marshal for ClockRateAdjust {
    const MAX_SIZE: usize = TpmClockAdjust::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.rate_adjust.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for ClockRateAdjust {
    fn unmarshal_with_handles(
        [auth]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: auth.try_into()?,
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
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.act_handle)]
    }
}
impl Marshal for ACTSetTimeout {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; ACTSetTimeout::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.start_timeout.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for ACTSetTimeout {
    fn unmarshal_with_handles(
        [act_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            act_handle: act_handle.try_into()?,
            start_timeout: Unmarshal::unmarshal(src)?,
        })
    }
}
