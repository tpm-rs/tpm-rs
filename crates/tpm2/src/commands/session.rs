//! TPM 2.0 Session Commands
//!
//! This module implements the "Session Commands" commands defined in
//! **Section 11** of the TPM 2.0 Specification.
use super::{Command, Response, UnmarshalCommand, UnmarshalResponse};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_StartAuthSession (Command)
#[doc(alias = "TPM2_StartAuthSession")]
#[doc(alias = "StartAuthSession_In")]
#[derive(Clone, Copy)]
pub struct StartAuthSession<'a> {
    pub tpm_key: EntityHandle<'a>,
    pub bind: EntityHandle<'a>,
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
    type Handles<'a>
        = [EntityHandle<'a>; 2]
    where
        Self: 'a;
    type Response<'a> = StartAuthSessionRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
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
impl<'a> UnmarshalCommand<'a> for StartAuthSession<'a> {
    fn unmarshal_with_handles(
        [tpm_key, bind]: Self::Handles<'a>,
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

impl Response for StartAuthSessionRsp<'_> {
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
impl<'a> UnmarshalResponse<'a> for StartAuthSessionRsp<'a> {
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
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        [EntityHandle::Handle(self.session_handle)]
    }
}
impl Marshal for PolicyRestart {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for PolicyRestart {
    fn unmarshal_with_handles(
        [session_handle]: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            session_handle: session_handle.try_into()?,
        })
    }
}
