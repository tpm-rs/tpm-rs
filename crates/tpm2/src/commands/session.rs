//! TPM 2.0 Session Commands
//!
//! This module implements the "Session Commands" defined in
//! **Section 11** of the TPM 2.0 Specification.
//!
//! These commands support starting authorization, policy, or trial sessions,
//! enabling secure communication and access control.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct StartAuthSessionHandles {
    pub tpm_key: Handle,
    pub bind: Handle,
}
impl Marshal for StartAuthSessionHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.tpm_key, dst, 0);
        marshal_helper(&self.bind, dst, count)
    }
}

impl<'a> Unmarshal<'a> for StartAuthSessionHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            tpm_key: TpmiDhObject::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            bind: TpmiDhEntity::<true>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 11.1 TPM2_StartAuthSession (Command)
#[doc(alias = "TPM2_StartAuthSession")]
#[doc(alias = "StartAuthSession_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct StartAuthSession<'a> {
    pub nonce_caller: Tpm2bNonce<'a>,
    pub encrypted_salt: Tpm2bEncryptedSecret<'a>,
    pub session_type: TpmSe,
    pub symmetric: Option<TpmtSymDef>,
    pub auth_hash: TpmiAlgHash,
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

impl<'a> Unmarshal<'a> for StartAuthSession<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nonce_caller: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            encrypted_salt: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            session_type: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
            symmetric: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(4))?,
            auth_hash: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(5))?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct StartAuthSessionRespHandles {
    pub session_handle: Handle,
}
impl Marshal for StartAuthSessionRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.session_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for StartAuthSessionRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            session_handle: TpmiShAuthSession::<false>::unmarshal(src)?.0,
        })
    }
}

/// [TPM2.0 1.83] 11.1 TPM2_StartAuthSession (Response)
#[doc(alias = "StartAuthSession_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct StartAuthSessionRsp<'a> {
    pub nonce_tpm: Tpm2bNonce<'a>,
}
impl Marshal for StartAuthSessionRsp<'_> {
    const MAX_SIZE: usize = Tpm2bNonce::MAX_SIZE;
    type MaxBuffer = [u8; StartAuthSessionRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.nonce_tpm.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for StartAuthSessionRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            nonce_tpm: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for StartAuthSession<'_> {
    const CMD_CODE: TpmCc = TpmCc::StartAuthSession;
    type Handles = StartAuthSessionHandles;
    type Response<'a> = StartAuthSessionRsp<'a>;
    type RespHandles = StartAuthSessionRespHandles;
}

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyRestartHandles {
    pub session_handle: Handle,
}
impl Marshal for PolicyRestartHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.session_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for PolicyRestartHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            session_handle: TpmiShPolicy::unmarshal(src).map_err(|e| e.in_handle(1))?.0,
        })
    }
}

/// [TPM2.0 1.83] 11.2 TPM2_PolicyRestart (Command)
#[doc(alias = "TPM2_PolicyRestart")]
#[doc(alias = "PolicyRestart_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct PolicyRestart {}
impl Marshal for PolicyRestart {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for PolicyRestart {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

impl Command for PolicyRestart {
    const CMD_CODE: TpmCc = TpmCc::PolicyRestart;
    type Handles = PolicyRestartHandles;
    type Response<'a> = ();
    type RespHandles = ();
}
