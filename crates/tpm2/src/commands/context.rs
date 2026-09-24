//! TPM 2.0 Context Management Commands
//!
//! This module implements the "Context Management" commands defined in
//! **Section 28** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, *};

/// TPM2_ContextSave (Command)
#[doc(alias = "TPM2_ContextSave")]
#[doc(alias = "ContextSave_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ContextSave {
    pub save_handle: Handle,
}
/// TPM2_ContextSave (Response)
#[doc(alias = "ContextSave_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ContextSaveRsp<'a> {
    pub context: TpmsContext<'a>,
}

impl Command for ContextSave {
    const CMD_CODE: TpmCc = TpmCc::ContextSave;
    type Response<'a> = ContextSaveRsp<'a>;
}
impl Message for ContextSave {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.save_handle]
    }
}
impl Marshal for ContextSave {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for ContextSave {
    fn unmarshal_with_handles(
        [save_handle]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { save_handle })
    }
}

impl Message for ContextSaveRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ContextSaveRsp<'_> {
    const MAX_SIZE: usize = TpmsContext::MAX_SIZE;
    type MaxBuffer = [u8; ContextSaveRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.context.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ContextSaveRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            context: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_ContextLoad (Command)
#[doc(alias = "TPM2_ContextLoad")]
#[doc(alias = "ContextLoad_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ContextLoad<'a> {
    pub context: TpmsContext<'a>,
}
/// TPM2_ContextLoad (Response)
#[doc(alias = "ContextLoad_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ContextLoadRsp {
    pub loaded_handle: Handle,
}

impl Command for ContextLoad<'_> {
    const CMD_CODE: TpmCc = TpmCc::ContextLoad;
    type Response<'a> = ContextLoadRsp;
}
impl Message for ContextLoad<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ContextLoad<'_> {
    const MAX_SIZE: usize = TpmsContext::MAX_SIZE;
    type MaxBuffer = [u8; ContextLoad::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.context.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for ContextLoad<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            context: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for ContextLoadRsp {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.loaded_handle]
    }
}
impl Marshal for ContextLoadRsp {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for ContextLoadRsp {
    fn unmarshal_with_handles(
        [loaded_handle]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { loaded_handle })
    }
}

/// TPM2_FlushContext (Command)
#[doc(alias = "TPM2_FlushContext")]
#[doc(alias = "FlushContext_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct FlushContext {
    pub flush_handle: Handle,
}

impl Command for FlushContext {
    const CMD_CODE: TpmCc = TpmCc::FlushContext;
    type Response<'a> = ();
}
impl Message for FlushContext {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for FlushContext {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.flush_handle.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for FlushContext {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            flush_handle: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_EvictControl (Command)
#[doc(alias = "TPM2_EvictControl")]
#[doc(alias = "EvictControl_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct EvictControl {
    pub auth: Handle,
    pub object_handle: Handle,
    pub persistent_handle: Handle,
}

impl Command for EvictControl {
    const CMD_CODE: TpmCc = TpmCc::EvictControl;
    type Response<'a> = ();
}
impl Message for EvictControl {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.auth, self.object_handle]
    }
}
impl Marshal for EvictControl {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.persistent_handle.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for EvictControl {
    fn unmarshal_with_handles(
        [auth, object_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth,
            object_handle,
            persistent_handle: Unmarshal::unmarshal(src)?,
        })
    }
}
