//! TPM 2.0 Context Management Commands
//!
//! This module implements the "Context Management" commands defined in
//! **Section 28** of the TPM 2.0 Specification.
//!
//! These commands provide a mechanism for managing internal TPM session resources
//! by swapping objects, sessions, and sequence contexts in and out of the TPM memory.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ContextSaveHandles {
    pub save_handle: Handle,
}
impl Marshal for ContextSaveHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.save_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ContextSaveHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            save_handle: TpmiDhContext::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 28.2 TPM2_ContextSave (Command)
#[doc(alias = "TPM2_ContextSave")]
#[doc(alias = "ContextSave_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ContextSave {}

/// [TPM2.0 1.83] 28.2 TPM2_ContextSave (Response)
#[doc(alias = "ContextSave_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ContextSaveRsp<'a> {
    pub context: crate::TpmsContext<'a>,
}

impl Marshal for ContextSave {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for ContextSave {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Marshal for ContextSaveRsp<'_> {
    const MAX_SIZE: usize = <crate::TpmsContext>::MAX_SIZE;
    type MaxBuffer = [u8; ContextSaveRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.context.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ContextSaveRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            context: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ContextSave {
    const CMD_CODE: TpmCc = TpmCc::ContextSave;
    type Handles = ContextSaveHandles;
    type Response<'a> = ContextSaveRsp<'a>;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 28.3 TPM2_ContextLoad (Command)
#[doc(alias = "TPM2_ContextLoad")]
#[doc(alias = "ContextLoad_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ContextLoad<'a> {
    pub context: crate::TpmsContext<'a>,
}
impl Marshal for ContextLoad<'_> {
    const MAX_SIZE: usize = <crate::TpmsContext>::MAX_SIZE;
    type MaxBuffer = [u8; ContextLoad::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.context.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ContextLoad<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            context: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct ContextLoadRespHandles {
    pub loaded_handle: Handle,
}
impl Marshal for ContextLoadRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.loaded_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ContextLoadRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            loaded_handle: TpmiDhContext::unmarshal(src)?.0,
        })
    }
}

impl Command for ContextLoad<'_> {
    const CMD_CODE: TpmCc = TpmCc::ContextLoad;
    type Handles = ();
    type Response<'a> = ();
    type RespHandles = ContextLoadRespHandles;
}

/// [TPM2.0 1.83] 28.4 TPM2_FlushContext (Command)
///
/// Causes all context associated with a loaded object, sequence object, or
/// authorization session to be removed from TPM memory.
///
/// Per TPM 2.0 Part 3, Section 28.4 Note, `flush_handle` is transmitted in the
/// **command parameter area** (`cHandles = 0`) rather than the command handle area so
/// the TPM does not perform standard handle-area entity presence validation when
/// flushing a saved session context that is not currently resident in TPM RAM.
#[doc(alias = "TPM2_FlushContext")]
#[doc(alias = "FlushContext_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct FlushContext {
    /// The handle of the transient object, sequence object, or authorization session to flush (`TPMI_DH_CONTEXT`).
    pub flush_handle: Handle,
}

impl Marshal for FlushContext {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.flush_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for FlushContext {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            flush_handle: TpmiDhContext::unmarshal(src)
                .map_err(|e| e.in_parameter(1))?
                .0,
        })
    }
}

impl Command for FlushContext {
    const CMD_CODE: TpmCc = TpmCc::FlushContext;
    type Handles = ();
    type Response<'a> = ();
    type RespHandles = ();
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EvictControlHandles {
    pub auth: Handle,
    pub object_handle: Handle,
}
impl Marshal for EvictControlHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.auth, dst, 0);
        marshal_helper(&self.object_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for EvictControlHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: TpmiRhProvision::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            object_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 28.5 TPM2_EvictControl (Command)
#[doc(alias = "TPM2_EvictControl")]
#[doc(alias = "EvictControl_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct EvictControl {
    pub persistent_handle: Handle,
}
impl Marshal for EvictControl {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.persistent_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for EvictControl {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            persistent_handle: TpmiDhPersistent::unmarshal(src)
                .map_err(|e| e.in_parameter(1))?
                .0,
        })
    }
}

impl Command for EvictControl {
    const CMD_CODE: TpmCc = TpmCc::EvictControl;
    type Handles = EvictControlHandles;
    type Response<'a> = ();
    type RespHandles = ();
}
