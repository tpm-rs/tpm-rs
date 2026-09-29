//! TPM 2.0 Vendor Specific Commands
//!
//! This module implements the "Vendor Specific" commands defined in
//! **Section 34** of the TPM 2.0 Specification.
//!
//! These commands provide placeholders for vendor-defined extensions and tests.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and `TpmCommand` trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, *};

/// [TPM2.0 1.83] 34.2 TPM2_Vendor_TCG_Test (Command)
#[doc(alias = "TPM2_Vendor_TCG_Test")]
#[doc(alias = "Vendor_TCG_Test_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct VendorTcgTest<'a> {
    pub input_data: Tpm2bData<'a>,
}

impl Marshal for VendorTcgTest<'_> {
    const MAX_SIZE: usize = Tpm2bData::MAX_SIZE;
    type MaxBuffer = [u8; VendorTcgTest::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.input_data.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for VendorTcgTest<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            input_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 34.2 TPM2_Vendor_TCG_Test (Response)
#[doc(alias = "Vendor_TCG_Test_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct VendorTcgTestRsp<'a> {
    pub output_data: Tpm2bData<'a>,
}

impl Marshal for VendorTcgTestRsp<'_> {
    const MAX_SIZE: usize = Tpm2bData::MAX_SIZE;
    type MaxBuffer = [u8; VendorTcgTestRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.output_data.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for VendorTcgTestRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            output_data: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for VendorTcgTest<'_> {
    const CMD_CODE: TpmCc = TpmCc::VendorTcgTest;
    type Handles = ();
    type Response<'a> = VendorTcgTestRsp<'a>;
    type RespHandles = ();
}
