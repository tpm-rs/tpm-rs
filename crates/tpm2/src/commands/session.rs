//! TPM 2.0 Session Commands
//!
//! This module implements the "Session Commands" commands defined in
//! **Section 11** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_StartAuthSession (Command)
#[doc(alias = "TPM2_StartAuthSession")]
#[doc(alias = "StartAuthSession_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct StartAuthSession<'a> {
    pub tpm_key: Handle,
    pub bind: Handle,
    pub nonce_caller: Tpm2bNonce<'a>,
    pub encrypted_salt: Tpm2bEncryptedSecret<'a>,
    pub session_type: TpmSe,
    pub symmetric: Option<TpmtSymDef>,
    pub auth_hash: TpmiAlgHash,
}
/// TPM2_StartAuthSession (Response)
#[doc(alias = "StartAuthSession_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct StartAuthSessionRsp<'a> {
    pub session_handle: Handle,
    pub nonce_tpm: Tpm2bNonce<'a>,
}

impl Command for StartAuthSession<'_> {
    const CMD_CODE: TpmCc = TpmCc::StartAuthSession;
    type Response<'a> = StartAuthSessionRsp<'a>;
}
impl Message for StartAuthSession<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.tpm_key, self.bind]
    }
}
impl Marshal for StartAuthSession<'_> {
    const MAX_SIZE: usize = Tpm2bNonce::MAX_SIZE
        + Tpm2bEncryptedSecret::MAX_SIZE
        + TpmSe::MAX_SIZE
        + <Option<TpmtSymDef>>::MAX_SIZE
        + TpmiAlgHash::MAX_SIZE;
    type MaxBuffer = [u8; StartAuthSession::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.nonce_caller, dst, 0);
        let count = marshal_helper(&self.encrypted_salt, dst, count);
        let count = marshal_helper(&self.session_type, dst, count);
        let count = marshal_helper(&self.symmetric, dst, count);
        marshal_helper(&self.auth_hash, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for StartAuthSession<'a> {
    fn unmarshal_with_handles(
        [tpm_key, bind]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            tpm_key,
            bind,
            nonce_caller: Unmarshal::unmarshal(src)?,
            encrypted_salt: Unmarshal::unmarshal(src)?,
            session_type: Unmarshal::unmarshal(src)?,
            symmetric: Unmarshal::unmarshal(src)?,
            auth_hash: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for StartAuthSessionRsp<'_> {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.session_handle]
    }
}
impl Marshal for StartAuthSessionRsp<'_> {
    const MAX_SIZE: usize = Tpm2bNonce::MAX_SIZE;
    type MaxBuffer = [u8; StartAuthSessionRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.nonce_tpm.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for StartAuthSessionRsp<'a> {
    fn unmarshal_with_handles(
        [session_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            session_handle,
            nonce_tpm: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_PolicyRestart (Command)
#[doc(alias = "TPM2_PolicyRestart")]
#[doc(alias = "PolicyRestart_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct PolicyRestart {
    pub session_handle: Handle,
}

impl Command for PolicyRestart {
    const CMD_CODE: TpmCc = TpmCc::PolicyRestart;
    type Response<'a> = ();
}
impl Message for PolicyRestart {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.session_handle]
    }
}
impl Marshal for PolicyRestart {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for PolicyRestart {
    fn unmarshal_with_handles(
        [session_handle]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { session_handle })
    }
}
