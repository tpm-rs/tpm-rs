//! TPM 2.0 Testing Commands
//!
//! This module implements the "Testing" commands defined in
//! **Section 10** of the TPM 2.0 Specification.
use super::{Command, Response, UnmarshalCommand, UnmarshalResponse};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_SelfTest (Command)
#[doc(alias = "TPM2_SelfTest")]
#[doc(alias = "SelfTest_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct SelfTest {
    pub full_test: bool,
}

impl Command for SelfTest {
    const CMD_CODE: TpmCc = TpmCc::SelfTest;
    type Handles<'a>
        = [EntityHandle<'a>; 0]
    where
        Self: 'a;
    type Response<'a> = ();
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for SelfTest {
    const MAX_SIZE: usize = bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.full_test.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for SelfTest {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            full_test: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_IncrementalSelfTest (Command)
#[doc(alias = "TPM2_IncrementalSelfTest")]
#[doc(alias = "IncrementalSelfTest_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct IncrementalSelfTest {
    pub to_test: TpmlAlg,
}
/// TPM2_IncrementalSelfTest (Response)
#[doc(alias = "IncrementalSelfTest_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct IncrementalSelfTestRsp {
    pub to_do_list: TpmlAlg,
}

impl Command for IncrementalSelfTest {
    const CMD_CODE: TpmCc = TpmCc::IncrementalSelfTest;
    type Handles<'a>
        = [EntityHandle<'a>; 0]
    where
        Self: 'a;
    type Response<'a> = IncrementalSelfTestRsp;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for IncrementalSelfTest {
    const MAX_SIZE: usize = TpmlAlg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.to_test.marshal(dst)
    }
}
impl<'a> UnmarshalCommand<'a> for IncrementalSelfTest {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            to_test: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Response for IncrementalSelfTestRsp {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for IncrementalSelfTestRsp {
    const MAX_SIZE: usize = TpmlAlg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.to_do_list.marshal(dst)
    }
}
impl<'a> UnmarshalResponse<'a> for IncrementalSelfTestRsp {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            to_do_list: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_GetTestResult (Command)
#[doc(alias = "TPM2_GetTestResult")]
#[doc(alias = "GetTestResult_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetTestResult;
/// TPM2_GetTestResult (Response)
#[doc(alias = "GetTestResult_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetTestResultRsp<'a> {
    pub out_data: Tpm2bMaxBuffer<'a>,
    pub test_result: Result<(), errors::TpmRc>,
}

impl Command for GetTestResult {
    const CMD_CODE: TpmCc = TpmCc::GetTestResult;
    type Handles<'a>
        = [EntityHandle<'a>; 0]
    where
        Self: 'a;
    type Response<'a> = GetTestResultRsp<'a>;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for GetTestResult {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalCommand<'a> for GetTestResult {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self)
    }
}

impl Response for GetTestResultRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for GetTestResultRsp<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + <Result<(), errors::TpmRc>>::MAX_SIZE;
    type MaxBuffer = [u8; GetTestResultRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.out_data, dst, 0);
        marshal_helper(&self.test_result, dst, count)
    }
}
impl<'a> UnmarshalResponse<'a> for GetTestResultRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_data: Unmarshal::unmarshal(src)?,
            test_result: Unmarshal::unmarshal(src)?,
        })
    }
}
