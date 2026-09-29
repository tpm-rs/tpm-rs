//! TPM 2.0 Miscellaneous Management Functions Commands
//!
//! This module implements the "Miscellaneous Management Functions" commands defined in
//! **Section 26** of the TPM 2.0 Specification.
//!
//! These commands provide administrative operations such as controlling physical presence
//! commands and setting algorithm sets.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and `TpmCommand` trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PPCommandsHandles {
    pub auth: Handle,
}

impl Marshal for PPCommandsHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PPCommandsHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: TpmiRhPlatform::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 26.2 TPM2_PP_Commands (Command)
#[doc(alias = "TPM2_PP_Commands")]
#[doc(alias = "PP_Commands_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PPCommands {
    pub set_list: TpmlCc,
    pub clear_list: TpmlCc,
}

impl Marshal for PPCommands {
    const MAX_SIZE: usize = TpmlCc::MAX_SIZE + TpmlCc::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.set_list, dst, 0);
        marshal_helper(&self.clear_list, dst, count)
    }
}

impl<'a> Unmarshal<'a> for PPCommands {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            set_list: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            clear_list: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl Command for PPCommands {
    const CMD_CODE: TpmCc = TpmCc::PPCommands;
    type Handles = PPCommandsHandles;
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SetAlgorithmSetHandles {
    pub auth_handle: Handle,
}

impl Marshal for SetAlgorithmSetHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SetAlgorithmSetHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle: TpmiRhPlatform::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 26.3 TPM2_SetAlgorithmSet (Command)
#[doc(alias = "TPM2_SetAlgorithmSet")]
#[doc(alias = "SetAlgorithmSet_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SetAlgorithmSet {
    pub algorithm_set: u32,
}

impl Marshal for SetAlgorithmSet {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.algorithm_set.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SetAlgorithmSet {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            algorithm_set: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

impl Command for SetAlgorithmSet {
    const CMD_CODE: TpmCc = TpmCc::SetAlgorithmSet;
    type Handles = SetAlgorithmSetHandles;
    type Response<'a> = ();
    type RespHandles = ();
}
