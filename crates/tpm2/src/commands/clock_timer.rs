//! TPM 2.0 Clocks and Timers Commands
//!
//! This module implements the "Clocks and Timers" and "Authenticated Countdown Timer"
//! commands defined in **Section 29** and **Section 33** of the TPM 2.0 Specification.
//!
//! These commands provide:
//! - Reading the current clock/timer value ([`ReadClock`])
//! - Advancing or adjusting the clock and timer values
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, *};

/// [TPM2.0 1.83] 29.1 TPM2_ReadClock (Command)
#[doc(alias = "TPM2_ReadClock")]
#[doc(alias = "ReadClock_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ReadClock {}

impl Command for ReadClock {
    const CMD_CODE: TpmCc = TpmCc::ReadClock;
    type Handles = ();
    type Response<'a> = ReadClockRsp;
    type RespHandles = ();
}

impl Marshal for ReadClock {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for ReadClock {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

/// [TPM2.0 1.83] 29.1 TPM2_ReadClock (Response)
#[doc(alias = "ReadClock_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ReadClockRsp {
    pub current_time: TpmsTimeInfo,
}

impl Marshal for ReadClockRsp {
    const MAX_SIZE: usize = TpmsTimeInfo::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.current_time.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ReadClockRsp {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            current_time: Unmarshal::unmarshal(src)?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ClockSetHandles {
    pub auth: Handle,
}

impl Marshal for ClockSetHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ClockSetHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: TpmiRhProvision::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 29.2 TPM2_ClockSet (Command)
#[doc(alias = "TPM2_ClockSet")]
#[doc(alias = "ClockSet_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ClockSet {
    pub new_time: u64,
}

impl Command for ClockSet {
    const CMD_CODE: TpmCc = TpmCc::ClockSet;
    type Handles = ClockSetHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

impl Marshal for ClockSet {
    const MAX_SIZE: usize = u64::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.new_time.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ClockSet {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            new_time: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ClockRateAdjustHandles {
    pub auth: Handle,
}

impl Marshal for ClockRateAdjustHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ClockRateAdjustHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: TpmiRhProvision::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 29.3 TPM2_ClockRateAdjust (Command)
#[doc(alias = "TPM2_ClockRateAdjust")]
#[doc(alias = "ClockRateAdjust_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ClockRateAdjust {
    pub rate_adjust: TpmClockAdjust,
}

impl Command for ClockRateAdjust {
    const CMD_CODE: TpmCc = TpmCc::ClockRateAdjust;
    type Handles = ClockRateAdjustHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

impl Marshal for ClockRateAdjust {
    const MAX_SIZE: usize = TpmClockAdjust::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.rate_adjust.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ClockRateAdjust {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let rate_adjust: TpmClockAdjust =
            Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?;
        Ok(Self { rate_adjust })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ACTSetTimeoutHandles {
    pub act_handle: Handle,
}

impl Marshal for ACTSetTimeoutHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.act_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ACTSetTimeoutHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            act_handle: TpmiRhAct::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 33.2 TPM2_ACT_SetTimeout (Command)
#[doc(alias = "TPM2_ACT_SetTimeout")]
#[doc(alias = "ACT_SetTimeout_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ACTSetTimeout {
    pub start_timeout: u32,
}

impl Marshal for ACTSetTimeout {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.start_timeout.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ACTSetTimeout {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            start_timeout: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for ACTSetTimeout {
    const CMD_CODE: TpmCc = TpmCc::ACTSetTimeout;
    type Handles = ACTSetTimeoutHandles;
    type Response<'a> = ();
    type RespHandles = ();
}
