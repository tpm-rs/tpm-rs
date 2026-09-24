//! TPM 2.0 Start-up Commands
//!
//! This module implements the "Start-up" commands defined in
//! **Section 9** of the TPM 2.0 Specification.
//!
//! These commands manage the TPM initialization state, startup types (Clear vs State),
//! and ordered shutdown processes.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, *};

/// TPM2_Startup (Command)
#[doc(alias = "TPM2_Startup")]
#[doc(alias = "Startup_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Startup {
    pub startup_type: TpmSu,
}
impl Command for Startup {
    const CMD_CODE: TpmCc = TpmCc::Startup;
    type Response<'a> = ();
}
impl Message for Startup {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for Startup {
    const MAX_SIZE: usize = TpmSu::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.startup_type.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for Startup {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            startup_type: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_Shutdown (Command)
#[doc(alias = "TPM2_Shutdown")]
#[doc(alias = "Shutdown_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct Shutdown {
    pub shutdown_type: TpmSu,
}

impl Command for Shutdown {
    const CMD_CODE: TpmCc = TpmCc::Shutdown;
    type Response<'a> = ();
}
impl Message for Shutdown {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for Shutdown {
    const MAX_SIZE: usize = TpmSu::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.shutdown_type.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for Shutdown {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            shutdown_type: Unmarshal::unmarshal(src)?,
        })
    }
}
