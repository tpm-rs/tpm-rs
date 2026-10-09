//! TPM 2.0 Command Audit Commands
//!
//! This module implements the "Command Audit" commands defined in
//! **Section 21** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage, param};
use crate::{errors::TpmRc, marshal::marshal_helper, *};

/// TPM2_SetCommandCodeAuditStatus (Command)
#[doc(alias = "TPM2_SetCommandCodeAuditStatus")]
#[doc(alias = "SetCommandCodeAuditStatus_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct SetCommandCodeAuditStatus {
    pub auth: Handle,
    pub audit_alg: Option<TpmiAlgHash>,
    pub set_list: TpmlCc,
    pub clear_list: TpmlCc,
}

impl Command for SetCommandCodeAuditStatus {
    const CMD_CODE: TpmCc = TpmCc::SetCommandCodeAuditStatus;
    type Response<'a> = ();
}
impl Message for SetCommandCodeAuditStatus {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.auth]
    }
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
impl<'a> UnmarshalMessage<'a> for SetCommandCodeAuditStatus {
    fn unmarshal_with_handles([auth]: Self::Handles, src: &mut &'a [u8]) -> Result<Self, TpmRc> {
        Ok(Self {
            auth,
            audit_alg: param(src, 1)?,
            set_list: param(src, 2)?,
            clear_list: param(src, 3)?,
        })
    }
}
