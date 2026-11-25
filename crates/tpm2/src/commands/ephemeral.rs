//! TPM 2.0 Ephemeral EC Keys Commands
//!
//! This module implements the "Ephemeral EC Keys" commands defined in
//! **Section 19** of the TPM 2.0 Specification.
use super::{Command, Response, UnmarshalCommand, UnmarshalResponse};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_Commit (Command)
#[doc(alias = "TPM2_Commit")]
#[doc(alias = "Commit_In")]
#[derive(Clone, Copy)]
pub struct Commit<'a> {
    pub sign_handle: ObjectHandle<'a>,
    pub p1: Tpm2bEccPoint<'a>,
    pub s2: Tpm2bSensitiveData<'a>,
    pub y2: Tpm2bEccParameter<'a>,
}
/// TPM2_Commit (Response)
#[doc(alias = "Commit_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct CommitRsp<'a> {
    pub k: Tpm2bEccPoint<'a>,
    pub l: Tpm2bEccPoint<'a>,
    pub e: Tpm2bEccPoint<'a>,
    pub counter: u16,
}

impl Command for Commit<'_> {
    const CMD_CODE: TpmCc = TpmCc::Commit;
    type Handles<'a>
        = [EntityHandle<'a>; 1]
    where
        Self: 'a;
    type Response<'a> = CommitRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        [self.sign_handle.into()]
    }
}
impl Marshal for Commit<'_> {
    const MAX_SIZE: usize =
        Tpm2bEccPoint::MAX_SIZE + Tpm2bSensitiveData::MAX_SIZE + Tpm2bEccParameter::MAX_SIZE;
    type MaxBuffer = [u8; Commit::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.p1, dst, 0);
        let count = marshal_helper(&self.s2, dst, count);
        marshal_helper(&self.y2, dst, count)
    }
}
impl<'a> UnmarshalCommand<'a> for Commit<'a> {
    fn unmarshal_with_handles(
        [sign_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sign_handle: sign_handle.try_into()?,
            p1: Unmarshal::unmarshal(src)?,
            s2: Unmarshal::unmarshal(src)?,
            y2: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for CommitRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for CommitRsp<'_> {
    const MAX_SIZE: usize =
        Tpm2bEccPoint::MAX_SIZE + Tpm2bEccPoint::MAX_SIZE + Tpm2bEccPoint::MAX_SIZE + u16::MAX_SIZE;
    type MaxBuffer = [u8; CommitRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.k, dst, 0);
        let count = marshal_helper(&self.l, dst, count);
        let count = marshal_helper(&self.e, dst, count);
        marshal_helper(&self.counter, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for CommitRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            k: Unmarshal::unmarshal(src)?,
            l: Unmarshal::unmarshal(src)?,
            e: Unmarshal::unmarshal(src)?,
            counter: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_EC_Ephemeral (Command)
#[doc(alias = "TPM2_EC_Ephemeral")]
#[doc(alias = "EC_Ephemeral_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECEphemeral {
    pub curve_id: TpmEccCurve,
}
/// TPM2_EC_Ephemeral (Response)
#[doc(alias = "EC_Ephemeral_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct ECEphemeralRsp<'a> {
    pub q: Tpm2bEccPoint<'a>,
    pub counter: u16,
}

impl Command for ECEphemeral {
    const CMD_CODE: TpmCc = TpmCc::ECEphemeral;
    type Handles<'a>
        = [EntityHandle<'a>; 0]
    where
        Self: 'a;
    type Response<'a> = ECEphemeralRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for ECEphemeral {
    const MAX_SIZE: usize = TpmEccCurve::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.curve_id.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for ECEphemeral {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            curve_id: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for ECEphemeralRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for ECEphemeralRsp<'_> {
    const MAX_SIZE: usize = Tpm2bEccPoint::MAX_SIZE + u16::MAX_SIZE;
    type MaxBuffer = [u8; ECEphemeralRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.q, dst, 0);
        marshal_helper(&self.counter, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for ECEphemeralRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            q: Unmarshal::unmarshal(src)?,
            counter: Unmarshal::unmarshal(src)?,
        })
    }
}
