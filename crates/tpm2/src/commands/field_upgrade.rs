//! TPM 2.0 Field Upgrade Commands
//!
//! This module implements the "Field Upgrade" commands defined in
//! **Section 27** of the TPM 2.0 Specification.
//!
//! These commands provide a mechanism to safely upgrade TPM firmware
//! and retrieve testing/firmware parameters.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and `TpmCommand` trait implementation.

use super::Command;
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct FieldUpgradeStartHandles {
    pub authorization: Handle,
    pub key_handle: Handle,
}

impl Marshal for FieldUpgradeStartHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE + Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.authorization, dst, 0);
        marshal_helper(&self.key_handle, dst, count)
    }
}

impl<'a> Unmarshal<'a> for FieldUpgradeStartHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            authorization: TpmiRhPlatform::unmarshal(src)
                .map_err(|e| e.in_handle(1))?
                .0,
            key_handle: TpmiDhObject::<false>::unmarshal(src)
                .map_err(|e| e.in_handle(2))?
                .0,
        })
    }
}

/// [TPM2.0 1.83] 27.2 TPM2_FieldUpgradeStart (Command)
#[doc(alias = "TPM2_FieldUpgradeStart")]
#[doc(alias = "FieldUpgradeStart_In")]
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct FieldUpgradeStart<'a> {
    pub fu_digest: Tpm2bDigest<'a>,
    pub manifest_signature: TpmtSignature<'a>,
}

impl<'a> Marshal for FieldUpgradeStart<'a> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + <TpmtSignature>::MAX_SIZE;
    type MaxBuffer = [u8; FieldUpgradeStart::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.fu_digest, dst, 0);
        marshal_helper(&self.manifest_signature, dst, count)
    }
}

impl<'a> Unmarshal<'a> for FieldUpgradeStart<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            fu_digest: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
            manifest_signature: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(2))?,
        })
    }
}

impl<'a> Command for FieldUpgradeStart<'a> {
    const CMD_CODE: TpmCc = TpmCc::FieldUpgradeStart;
    type Handles = FieldUpgradeStartHandles;
    type Response<'b> = ();
    type RespHandles = ();
}

/// [TPM2.0 1.83] 27.3 TPM2_FieldUpgradeData (Command)
#[doc(alias = "TPM2_FieldUpgradeData")]
#[doc(alias = "FieldUpgradeData_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct FieldUpgradeData<'a> {
    pub fu_data: Tpm2bMaxBuffer<'a>,
}

impl Marshal for FieldUpgradeData<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; FieldUpgradeData::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.fu_data.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for FieldUpgradeData<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            fu_data: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 27.3 TPM2_FieldUpgradeData (Response)
#[doc(alias = "FieldUpgradeData_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct FieldUpgradeDataRsp<'a> {
    pub next_digest: Option<TpmtHa<'a>>,
    pub first_digest: TpmtHa<'a>,
}

impl Marshal for FieldUpgradeDataRsp<'_> {
    const MAX_SIZE: usize = <Option<TpmtHa>>::MAX_SIZE + TpmtHa::MAX_SIZE;
    type MaxBuffer = [u8; FieldUpgradeDataRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.next_digest, dst, 0);
        marshal_helper(&self.first_digest, dst, count)
    }
}

impl<'a> Unmarshal<'a> for FieldUpgradeDataRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            next_digest: Unmarshal::unmarshal(src)?,
            first_digest: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for FieldUpgradeData<'_> {
    const CMD_CODE: TpmCc = TpmCc::FieldUpgradeData;
    type Handles = ();
    type Response<'a> = FieldUpgradeDataRsp<'a>;
    type RespHandles = ();
}

/// [TPM2.0 1.83] 27.4 TPM2_FirmwareRead (Command)
#[doc(alias = "TPM2_FirmwareRead")]
#[doc(alias = "FirmwareRead_In")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct FirmwareRead {
    pub sequence_number: u32,
}

impl Marshal for FirmwareRead {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sequence_number.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for FirmwareRead {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_number: Unmarshal::unmarshal(src).map_err(|e| e.in_parameter(1))?,
        })
    }
}

/// [TPM2.0 1.83] 27.4 TPM2_FirmwareRead (Response)
#[doc(alias = "FirmwareRead_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Default, Eq)]
pub struct FirmwareReadRsp<'a> {
    pub fu_data: Tpm2bMaxBuffer<'a>,
}

impl Marshal for FirmwareReadRsp<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; FirmwareReadRsp::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.fu_data.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for FirmwareReadRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            fu_data: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Command for FirmwareRead {
    const CMD_CODE: TpmCc = TpmCc::FirmwareRead;
    type Handles = ();
    type Response<'a> = FirmwareReadRsp<'a>;
    type RespHandles = ();
}
