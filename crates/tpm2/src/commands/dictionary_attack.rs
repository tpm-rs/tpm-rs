//! TPM 2.0 Dictionary Attack Functions Commands
//!
//! This module implements the "Dictionary Attack Functions" commands defined in
//! **Section 25** of the TPM 2.0 Specification.
//!
//! These commands provide protection against brute-force attacks on authorization values
//! by resetting dictionary attack locks and configuring security parameters.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct DictionaryAttackLockResetHandles {
    pub lock_handle: Handle,
}
impl Marshal for DictionaryAttackLockResetHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.lock_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for DictionaryAttackLockResetHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            lock_handle: TpmiRhLockout::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 25.2 TPM2_DictionaryAttackLockReset (Command)
#[doc(alias = "TPM2_DictionaryAttackLockReset")]
#[doc(alias = "DictionaryAttackLockReset_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct DictionaryAttackLockReset {}
impl Marshal for DictionaryAttackLockReset {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for DictionaryAttackLockReset {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for DictionaryAttackLockReset {
    const CMD_CODE: TpmCc = TpmCc::DictionaryAttackLockReset;
    type Handles = DictionaryAttackLockResetHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct DictionaryAttackParametersHandles {
    pub lock_handle: Handle,
}
impl Marshal for DictionaryAttackParametersHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.lock_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for DictionaryAttackParametersHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            lock_handle: TpmiRhLockout::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 25.3 TPM2_DictionaryAttackParameters (Command)
#[doc(alias = "TPM2_DictionaryAttackParameters")]
#[doc(alias = "DictionaryAttackParameters_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct DictionaryAttackParameters {
    pub new_max_tries: u32,
    pub new_recovery_time: u32,
    pub lockout_recovery: u32,
}
impl Marshal for DictionaryAttackParameters {
    const MAX_SIZE: usize = u32::MAX_SIZE + u32::MAX_SIZE + u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.new_max_tries, dst, 0);
        let count = marshal_helper(&self.new_recovery_time, dst, count);
        marshal_helper(&self.lockout_recovery, dst, count)
    }
}

impl<'a> Unmarshal<'a> for DictionaryAttackParameters {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            new_max_tries: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            new_recovery_time: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            lockout_recovery: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

impl Command for DictionaryAttackParameters {
    const CMD_CODE: TpmCc = TpmCc::DictionaryAttackParameters;
    type Handles = DictionaryAttackParametersHandles;
    type Response<'a> = ();
    type RespHandles = ();
}
