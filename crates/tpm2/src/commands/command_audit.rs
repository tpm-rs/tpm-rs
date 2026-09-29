//! TPM 2.0 Command Audit Commands
//!
//! This module implements the "Command Audit" commands defined in
//! **Section 21** of the TPM 2.0 Specification.
//!
//! These commands provide a mechanism for configuring the audit status
//! for individual command codes.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and `TpmCommand` trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SetCommandCodeAuditStatusHandles {
    pub auth: Handle,
}

impl Marshal for SetCommandCodeAuditStatusHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.auth.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SetCommandCodeAuditStatusHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            auth: TpmiRhProvision::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 21.2 TPM2_SetCommandCodeAuditStatus (Command)
#[doc(alias = "TPM2_SetCommandCodeAuditStatus")]
#[doc(alias = "SetCommandCodeAuditStatus_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SetCommandCodeAuditStatus {
    pub audit_alg: Option<TpmiAlgHash>,
    pub set_list: TpmlCc,
    pub clear_list: TpmlCc,
}

impl Marshal for SetCommandCodeAuditStatus {
    const MAX_SIZE: usize = <Option<TpmiAlgHash>>::MAX_SIZE + TpmlCc::MAX_SIZE + TpmlCc::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.audit_alg, dst, 0);
        let count = marshal_helper(&self.set_list, dst, count);
        marshal_helper(&self.clear_list, dst, count)
    }
}

impl<'a> Unmarshal<'a> for SetCommandCodeAuditStatus {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            audit_alg: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            set_list: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            clear_list: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

impl Command for SetCommandCodeAuditStatus {
    const CMD_CODE: TpmCc = TpmCc::SetCommandCodeAuditStatus;
    type Handles = SetCommandCodeAuditStatusHandles;
    type Response<'a> = ();
    type RespHandles = ();
}
