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
    pub key_handle: NamedHandle<'a>,
    pub fu_digest: Tpm2bDigest<'a>,
    pub manifest_signature: TpmtSignature<'a>,
}

impl Command for FieldUpgradeStart<'_> {
    const CMD_CODE: TpmCc = TpmCc::FieldUpgradeStart;
    type Response<'a> = ();
}
impl Message for FieldUpgradeStart<'_> {
    const NUM_HANDLES: usize = 2;
    type Handles<'a>
        = [NamedHandle<'a>; 2]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        [self.authorization.into(), self.key_handle]
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
        [authorization, key_handle]: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            authorization: authorization.handle,
            key_handle,
            fu_digest: Unmarshal::unmarshal(src)?,
            manifest_signature: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM2_FieldUpgradeData (Command)
#[doc(alias = "TPM2_FieldUpgradeData")]
#[doc(alias = "FieldUpgradeData_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct FieldUpgradeData<'a> {
    pub fu_data: Tpm2bMaxBuffer<'a>,
}
/// TPM2_FieldUpgradeData (Response)
#[doc(alias = "FieldUpgradeData_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct FieldUpgradeDataRsp<'a> {
    pub next_digest: Option<TpmtHa<'a>>,
    pub first_digest: TpmtHa<'a>,
}

impl Command for FieldUpgradeData<'_> {
    const CMD_CODE: TpmCc = TpmCc::FieldUpgradeData;
    type Response<'a> = FieldUpgradeDataRsp<'a>;
}
impl Message for FieldUpgradeData<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for FieldUpgradeData<'_> {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE;
    type MaxBuffer = [u8; FieldUpgradeData::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.fu_data.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for FieldUpgradeData<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            fu_data: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for FieldUpgradeDataRsp<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
        []
    }
}
impl Marshal for FieldUpgradeDataRsp<'_> {
    const MAX_SIZE: usize = <Option<TpmtHa>>::MAX_SIZE + TpmtHa::MAX_SIZE;
    type MaxBuffer = [u8; FieldUpgradeDataRsp::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.next_digest, dst, 0);
        marshal_helper(&self.first_digest, dst, count)
    }
}
impl<'a> UnmarshalMessage<'a> for FieldUpgradeDataRsp<'a> {
    fn unmarshal_with_handles(
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            next_digest: Unmarshal::unmarshal(src)?,
            first_digest: Unmarshal::unmarshal(src)?,
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
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
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
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            sequence_number: Unmarshal::unmarshal(src)?,
        })
    }
}

impl Message for FirmwareReadRsp<'_> {
    const NUM_HANDLES: usize = 0;
    type Handles<'a>
        = [NamedHandle<'a>; 0]
    where
        Self: 'a;
    fn handles(&self) -> Self::Handles<'_> {
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
        []: Self::Handles<'a>,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self {
            fu_data: Unmarshal::unmarshal(src)?,
        })
    }
}
