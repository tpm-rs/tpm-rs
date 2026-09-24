//! TPM 2.0 Miscellaneous Management Functions Commands
//!
//! This module implements the "Miscellaneous Management Functions" commands defined in
//! **Section 26** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_PP_Commands (Command)
#[doc(alias = "TPM2_PP_Commands")]
#[doc(alias = "PP_Commands_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PPCommands {
    pub auth: Handle,
    pub set_list: TpmlCc,
    pub clear_list: TpmlCc,
}

impl Command for PPCommands {
    const CMD_CODE: TpmCc = TpmCc::PPCommands;
    type Response<'a> = ();
}
impl Message for PPCommands {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.auth]
    }
}
impl Marshal for PPCommands {
    const MAX_SIZE: usize = TpmlCc::MAX_SIZE + TpmlCc::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.set_list, dst, 0);
        marshal_helper(&self.clear_list, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for PPCommands {
    fn unmarshal_with_handles(
        [auth]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth,
            set_list: Unmarshal::unmarshal(src)?,
            clear_list: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_SetAlgorithmSet (Command)
#[doc(alias = "TPM2_SetAlgorithmSet")]
#[doc(alias = "SetAlgorithmSet_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct SetAlgorithmSet {
    pub auth_handle: Handle,
    pub algorithm_set: u32,
}

impl Command for SetAlgorithmSet {
    const CMD_CODE: TpmCc = TpmCc::SetAlgorithmSet;
    type Response<'a> = ();
}
impl Message for SetAlgorithmSet {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.auth_handle]
    }
}
impl Marshal for SetAlgorithmSet {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.algorithm_set.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for SetAlgorithmSet {
    fn unmarshal_with_handles(
        [auth_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth_handle,
            algorithm_set: Unmarshal::unmarshal(src)?,
        })
    }
}
