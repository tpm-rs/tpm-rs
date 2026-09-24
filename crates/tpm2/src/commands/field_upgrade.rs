//! TPM 2.0 Field Upgrade Commands
//!
//! This module implements the "Field Upgrade" commands defined in
//! **Section 27** of the TPM 2.0 Specification.
use super::{Command, Message, UnmarshalMessage};
use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

/// TPM2_FieldUpgradeStart (Command)
#[doc(alias = "TPM2_FieldUpgradeStart")]
#[doc(alias = "FieldUpgradeStart_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct FieldUpgradeStart<'a> {
    pub authorization: Handle,
    pub key_handle: Handle,
    pub fu_digest: Tpm2bDigest<'a>,
    pub manifest_signature: TpmtSignature<'a>,
}

impl Command for FieldUpgradeStart<'_> {
    const CMD_CODE: TpmCc = TpmCc::FieldUpgradeStart;
    type Response<'a> = ();
}
impl Message for FieldUpgradeStart<'_> {
    type Handles = [Handle; 2];
    fn handles(&self) -> Self::Handles {
        [self.authorization, self.key_handle]
    }
}
impl Marshal for FieldUpgradeStart<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE + TpmtSignature::MAX_SIZE;
    type MaxBuffer = [u8; FieldUpgradeStart::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.fu_digest, dst, 0);
        marshal_helper(&self.manifest_signature, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for FieldUpgradeStart<'a> {
    fn unmarshal_with_handles(
        [authorization, key_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            authorization,
            key_handle,
            fu_digest: Unmarshal::unmarshal(src)?,
            manifest_signature: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_FirmwareRead (Command)
#[doc(alias = "TPM2_FirmwareRead")]
#[doc(alias = "FirmwareRead_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct FirmwareRead {
    pub sequence_number: u32,
}
/// TPM2_FirmwareRead (Response)
#[doc(alias = "FirmwareRead_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct FirmwareReadRsp<'a> {
    pub fu_data: Tpm2bMaxBuffer<'a>,
}

impl Command for FirmwareRead {
    const CMD_CODE: TpmCc = TpmCc::FirmwareRead;
    type Response<'a> = FirmwareReadRsp<'a>;
}
impl Message for FirmwareRead {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for FirmwareRead {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sequence_number.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for FirmwareRead {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_number: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for FirmwareReadRsp<'_> {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for FirmwareReadRsp<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; FirmwareReadRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.fu_data.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for FirmwareReadRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            fu_data: Unmarshal::unmarshal(src)?,
        })
    }
}
