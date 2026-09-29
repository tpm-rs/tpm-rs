//! TPM 2.0 Ephemeral EC Keys Commands
//!
//! This module implements the "Ephemeral EC Keys" commands defined in
//! **Section 19** of the TPM 2.0 Specification.
//!
//! These commands allow generating ephemeral EC keys that exist only for the duration
//! of a single protocol transaction.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CommitHandles {
    pub sign_handle: Handle,
}
impl Marshal for CommitHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sign_handle.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for CommitHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sign_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 19.2 TPM2_Commit (Command)
#[doc(alias = "TPM2_Commit")]
#[doc(alias = "Commit_In")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct Commit<'a> {
    pub p1: crate::Tpm2bEccPoint<'a>,
    pub s2: crate::Tpm2bSensitiveData<'a>,
    pub y2: crate::Tpm2bEccParameter<'a>,
}
impl Marshal for Commit<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bEccPoint>::MAX_SIZE
        + <crate::Tpm2bSensitiveData>::MAX_SIZE
        + <crate::Tpm2bEccParameter>::MAX_SIZE;
    type MaxBuffer = [u8; Commit::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.p1, dst, 0);
        let count = marshal_helper(&self.s2, dst, count);
        marshal_helper(&self.y2, dst, count)
    }
}

impl<'a> Unmarshal<'a> for Commit<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            p1: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            s2: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
            y2: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(3))?,
        })
    }
}

/// [TPM2.0 1.83] 19.2 TPM2_Commit (Response)
#[doc(alias = "Commit_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct CommitRsp<'a> {
    pub k: crate::Tpm2bEccPoint<'a>,
    pub l: crate::Tpm2bEccPoint<'a>,
    pub e: crate::Tpm2bEccPoint<'a>,
    pub counter: u16,
}
impl Marshal for CommitRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bEccPoint>::MAX_SIZE
        + <crate::Tpm2bEccPoint>::MAX_SIZE
        + <crate::Tpm2bEccPoint>::MAX_SIZE
        + u16::MAX_SIZE;
    type MaxBuffer = [u8; CommitRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.k, dst, 0);
        let count = marshal_helper(&self.l, dst, count);
        let count = marshal_helper(&self.e, dst, count);
        marshal_helper(&self.counter, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CommitRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            k: Unmarshal::unmarshal(src)?,
            l: Unmarshal::unmarshal(src)?,
            e: Unmarshal::unmarshal(src)?,
            counter: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for Commit<'_> {
    const CMD_CODE: TpmCc = TpmCc::Commit;
    type Handles = CommitHandles;
    type Response<'a> = CommitRsp<'a>;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 19.3 TPM2_EC_Ephemeral (Command)
#[doc(alias = "TPM2_EC_Ephemeral")]
#[doc(alias = "EC_Ephemeral_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECEphemeral {
    pub curve_id: crate::TpmEccCurve,
}

impl Marshal for ECEphemeral {
    const MAX_SIZE: usize = <crate::TpmEccCurve>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.curve_id.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for ECEphemeral {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            curve_id: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 19.3 TPM2_EC_Ephemeral (Response)
#[doc(alias = "EC_Ephemeral_Out")]
#[derive(Clone, PartialEq, Debug, Default, Eq)]
pub struct ECEphemeralRsp<'a> {
    pub q: crate::Tpm2bEccPoint<'a>,
    pub counter: u16,
}

impl Marshal for ECEphemeralRsp<'_> {
    const MAX_SIZE: usize = <crate::Tpm2bEccPoint>::MAX_SIZE + u16::MAX_SIZE;
    type MaxBuffer = [u8; ECEphemeralRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.q, dst, 0);
        marshal_helper(&self.counter, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ECEphemeralRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            q: Unmarshal::unmarshal(src)?,
            counter: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for ECEphemeral {
    const CMD_CODE: TpmCc = TpmCc::ECEphemeral;
    type Handles = ();
    type Response<'a> = ECEphemeralRsp<'a>;
    type RespHandles = ();
}
