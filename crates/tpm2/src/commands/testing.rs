//! TPM 2.0 Testing Commands
//!
//! This module implements the "Testing" commands defined in
//! **Section 10** of the TPM 2.0 Specification.
//!
//! These commands trigger and query the results of the TPM's internal cryptographic
//! self-tests.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`](super::Command) trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// [TPM2.0 1.83] 10.2 TPM2_SelfTest (Command)
#[doc(alias = "TPM2_SelfTest")]
#[doc(alias = "SelfTest_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct SelfTest {
    pub full_test: bool,
}
impl Command for SelfTest {
    const CMD_CODE: TpmCc = TpmCc::SelfTest;
    type Handles = ();
    type Response<'a> = ();
    type RespHandles = ();
}
impl Marshal for SelfTest {
    const MAX_SIZE: usize = bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.full_test.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for SelfTest {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            full_test: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 10.3 TPM2_IncrementalSelfTest (Command)
#[doc(alias = "TPM2_IncrementalSelfTest")]
#[doc(alias = "IncrementalSelfTest_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct IncrementalSelfTest {
    pub to_test: TpmlAlg,
}
impl Command for IncrementalSelfTest {
    const CMD_CODE: TpmCc = TpmCc::IncrementalSelfTest;
    type Handles = ();
    type Response<'a> = IncrementalSelfTestRsp;
    type RespHandles = ();
}
impl Marshal for IncrementalSelfTest {
    const MAX_SIZE: usize = TpmlAlg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.to_test.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for IncrementalSelfTest {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            to_test: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 10.3 TPM2_IncrementalSelfTest (Response)
#[doc(alias = "IncrementalSelfTest_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct IncrementalSelfTestRsp {
    pub to_do_list: TpmlAlg,
}
impl Marshal for IncrementalSelfTestRsp {
    const MAX_SIZE: usize = TpmlAlg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.to_do_list.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for IncrementalSelfTestRsp {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            to_do_list: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 10.4 TPM2_GetTestResult (Command)
#[doc(alias = "TPM2_GetTestResult")]
#[doc(alias = "GetTestResult_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct GetTestResult {}
impl Command for GetTestResult {
    const CMD_CODE: TpmCc = TpmCc::GetTestResult;
    type Handles = ();
    type Response<'a> = GetTestResultRsp<'a>;
    type RespHandles = ();
}
impl Marshal for GetTestResult {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];

    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl<'a> Unmarshal<'a> for GetTestResult {
    fn unmarshal(_src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {})
    }
}

/// [TPM2.0 1.83] 10.4 TPM2_GetTestResult (Response)
#[doc(alias = "GetTestResult_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetTestResultRsp<'a> {
    pub out_data: Tpm2bMaxBuffer<'a>,
    pub test_result: Result<(), errors::TpmRc>,
}
impl Default for GetTestResultRsp<'_> {
    fn default() -> Self {
        Self {
            out_data: Tpm2bMaxBuffer::default(),
            test_result: Ok(()),
        }
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

impl<'a> Unmarshal<'a> for GetTestResultRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            out_data: Unmarshal::unmarshal(src)?,
            test_result: Unmarshal::unmarshal(src)?,
        })
    }
}
